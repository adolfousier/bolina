#!/usr/bin/env python3
"""fuzz_diff.py - differential fuzz oracle orchestrator (BE-SURF-04, D-056).

Drives one bounded differential run:

  1. emit a deterministic corpus with the Zig harness
       zig build fuzz-corpus -Dcorpus-budget=N -- CORPUS
  2. replay the SAME corpus file through the Zig production parsers
       zig build fuzz-diff -Dcoverage -- CORPUS
  3. replay the SAME corpus file through tools/refparse.py, the independent
     Python reference parser written from the SPEC field tables alone
  4. compare the two verdict streams record by record

Any divergence is a genuine parser defect (that is the oracle working).
Divergent records are saved under the work dir for audit, one .bin with the
raw bytes and one .txt with both verdicts, and the orchestrator exits
non-zero. The receipt block follows the SPEC section 11.6 shape: coverage of
the parsing code reached plus the seed corpus description.

Usage:
  python3 tools/fuzz_diff.py [--budget N] [--corpus PATH] [--workdir DIR]
                             [--zig PATH]

Exit codes: 0 clean run, zero divergences; 1 divergences found; 2
infrastructure failure (build error, missing corpus, broken framing).
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import refparse  # noqa: E402

TAG_NAMES = {
    0x01: "envelope", 0x02: "intent", 0x03: "grant",
    0x04: "span", 0x05: "effect", 0x06: "claim",
    0x07: "refusal", 0x08: "control_genesis", 0x09: "control",
    0x0A: "handshake_initiation", 0x0B: "handshake_response",
    0x0C: "cookie_reply", 0x0D: "data_packet_header",
    0x0E: "relay_route", 0x0F: "relay_registration",
    0x10: "fragment_header", 0x11: "lookup_request",
    0x12: "lookup_response", 0x13: "cert",
    0x14: "binding_message", 0x15: "sync_request",
    0x16: "sync_response",
}

# The Zig replay reads the whole corpus under .limited64(4 GiB) and allocates a
# tag byte and a verdict bool per three corpus bytes on top, so the corpus size
# is the binding constraint on --budget, not the record count itself. 1274.6
# bytes/record is measured, not estimated: 255,004,304 bytes for 200,068 records
# and 6,379,201,306 for 5,000,068 agree to four figures (D-074).
REPLAY_BYTE_CAP = 4 * 1024 * 1024 * 1024
BYTES_PER_RECORD = 1274.6

CORPUS_DESCRIPTION = (
    "22 seeds, one per parse entry point (envelope, intent, grant, span, "
    "effect, claim, refusal from test/vectors.json; cert synthesized with a "
    "two-signature CA list; binding built from the real vectors cert; "
    "genesis, control, handshake initiation/response, cookie reply, "
    "data header, relay route/registration, fragment header, lookup "
    "request/response, sync request/response synthesized from their SPEC "
    "field tables), 5 mutation operators (bit flip, byte overwrite, "
    "truncate, saturate, extend), 40% mutated-seed / 60% fully-random, 4096-byte "
    "input cap, deterministic PRNG seed (configurable via --seed, default "
    "0x626f6c696e61 'bolina'), tags 0x01-0x16, "
    "record framing u8 tag || u16 BE len || bytes, plus 4 boundary seeds "
    "(bind cert_len=0, data payload 1385, cert scope_count 9, cert "
    "descending CA keys) each emitted verbatim then as a 16-record mutated "
    "lineage to reach the length/ordering-field exits generic mutation "
    "cannot"
)


def run(cmd, capture_stdout=False):
    """Run a command in the repo root; return (rc, stdout, stderr)."""
    p = subprocess.run(cmd, cwd=REPO,
                       stdout=subprocess.PIPE if capture_stdout else None,
                       stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout or "", p.stderr or ""


def emit_corpus(zig, budget, corpus_path, seed):
    cmd = [zig, "build", "fuzz-corpus",
                      "-Dcorpus-budget=%d" % budget]
    if seed is not None:
        cmd.append("-Dfuzz-seed=%d" % seed)
    cmd += ["--", corpus_path]
    rc, _, err = run(cmd)
    if rc != 0:
        sys.stderr.write(err)
        return False
    m = re.search(r"CORPUS EMITTED: (\d+) records", err)
    if not m or int(m.group(1)) < budget:
        sys.stderr.write("fuzz-corpus emitted wrong record count\n")
        return False
    return True


def zig_diff(zig, corpus_path):
    """Run the Zig diff binary with coverage on; return (ok, verdicts, stderr)."""
    rc, out, err = run([zig, "build", "fuzz-diff", "-Dcoverage",
                        "--", corpus_path], capture_stdout=True)
    if rc != 0:
        sys.stderr.write(err)
        return False, [], err
    verdicts = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] == "REC":
            verdicts.append((int(parts[1]), int(parts[3], 16), parts[4]))
    return True, verdicts, err


def save_divergence(workdir, idx, tag, payload, py_verdict, zig_verdict):
    ddir = os.path.join(workdir, "divergences")
    os.makedirs(ddir, exist_ok=True)
    name = "rec_%06d_tag_0x%02x_%s" % (idx, tag, TAG_NAMES.get(tag, "unknown"))
    with open(os.path.join(ddir, name + ".bin"), "wb") as f:
        f.write(payload)
    with open(os.path.join(ddir, name + ".txt"), "w") as f:
        f.write("record: %d\n" % idx)
        f.write("tag: 0x%02x (%s)\n" % (tag, TAG_NAMES.get(tag, "unknown")))
        f.write("length: %d bytes\n" % len(payload))
        f.write("python reference: %s\n" % py_verdict)
        f.write("zig production: %s\n" % ("accept" if zig_verdict == "A"
                                          else "reject"))
        f.write("payload_hex:\n%s\n" % payload.hex())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--budget", type=int, default=20000,
                    help="corpus record count (default 20000)")
    ap.add_argument("--seed", type=int, default=None,
                    help="PRNG seed for corpus emit (default 0x626f6c696e61 'bolina'); different seeds expand coverage without repeating records")
    ap.add_argument("--corpus", default=None, help="corpus file path")
    ap.add_argument("--workdir", default=None,
                    help="work directory (default .fuzz-diff under repo)")
    ap.add_argument("--zig", default=os.environ.get("ZIG", "zig"),
                    help="zig binary (default $ZIG or PATH)")
    args = ap.parse_args()

    workdir = args.workdir or os.path.join(REPO, ".fuzz-diff")
    os.makedirs(workdir, exist_ok=True)
    corpus_path = args.corpus or os.path.join(workdir, "corpus.bin")

    print("== BE-SURF-04 differential fuzz oracle (D-056) ==")
    print("budget: %d records" % args.budget)
    if args.seed is not None:
        print("seed: 0x%x" % args.seed)

    # 1. corpus emit (Zig)
    if not emit_corpus(args.zig, args.budget, corpus_path, args.seed):
        print("FAIL: corpus emit", file=sys.stderr)
        return 2
    corpus_bytes = os.path.getsize(corpus_path)
    print("corpus: %s (%d bytes)" % (corpus_path, corpus_bytes))
    if corpus_bytes > REPLAY_BYTE_CAP:
        # The Zig replay reads the corpus whole under a .limited64(4 GiB) cap
        # (src/fuzz.zig runDiff), so an oversized budget dies there as a bare
        # "error: StreamTooLong" with no statement of what was too long. Refuse
        # here instead, naming the budget that caused it (D-074).
        print("FAIL: corpus %d bytes exceeds the %d-byte replay cap; "
              "--budget %d is above the ~%d-record ceiling (measured %.1f "
              "bytes/record)"
              % (corpus_bytes, REPLAY_BYTE_CAP, args.budget,
                 REPLAY_BYTE_CAP // BYTES_PER_RECORD, BYTES_PER_RECORD),
              file=sys.stderr)
        return 2

    # 2. Zig diff replay (production parsers, coverage on)
    ok, zig_verdicts, zig_err = zig_diff(args.zig, corpus_path)
    if not ok:
        print("FAIL: zig diff replay", file=sys.stderr)
        return 2
    done = re.search(r"DIFF DONE: (\d+) records, (\d+) accepted, (\d+) rejected",
                     zig_err)
    if not done:
        print("FAIL: zig diff produced no DIFF DONE line", file=sys.stderr)
        return 2

    # 3. Python reference replay. The corpus carries a deterministic
    # boundary-seed prefix beyond the random budget, so integrity is checked
    # against the actual corpus framing count, not against --budget.
    with open(corpus_path, "rb") as f:
        data = f.read()
    py_results, framing_ok = refparse.replay_corpus(data)
    if not framing_ok:
        print("FAIL: corpus framing broken", file=sys.stderr)
        return 2
    n_records = len(py_results)
    if int(done.group(1)) != n_records:
        print("FAIL: zig replay count %s != corpus record count %d" %
              (done.group(1), n_records), file=sys.stderr)
        return 2
    if n_records != len(zig_verdicts):
        print("FAIL: zig verdict lines %d != corpus record count %d" %
              (len(zig_verdicts), n_records), file=sys.stderr)
        return 2

    # 4. compare verdict streams, record by record
    # Re-walk the corpus to keep each divergent record's raw bytes.
    records = []
    pos = 0
    for idx, tag, _ in py_results:
        length = int.from_bytes(data[pos + 1:pos + 3], "big")
        records.append((idx, tag, data[pos + 3:pos + 3 + length]))
        pos += 3 + length

    divergences = 0
    py_accepted = sum(1 for _, _, v in py_results if v.ok)
    for (idx, tag, py_v), (z_idx, z_tag, z_verdict) in zip(py_results,
                                                           zig_verdicts):
        if idx != z_idx or tag != z_tag:
            print("FAIL: record stream desync at %d" % idx, file=sys.stderr)
            return 2
        py_verdict = "A" if py_v.ok else "R"
        if py_verdict != z_verdict:
            divergences += 1
            save_divergence(workdir, idx, tag, records[idx][2],
                            str(py_v), z_verdict)
            print("DIVERGENCE rec=%d tag=0x%02x (%s): python=%s zig=%s" %
                  (idx, tag, TAG_NAMES.get(tag, "?"),
                   py_v, z_verdict))

    # 5. receipt (SPEC section 11.6 shape)
    cov = re.search(r"COVERAGE: (\d+)/(\d+) exit points reached", zig_err)
    print()
    print("== receipt ==")
    print("records: %d (budget %d)" % (len(py_results), args.budget))
    print("zig production: %s accepted, %s rejected" %
          (done.group(2), done.group(3)))
    print("python reference: %d accepted, %d rejected" %
          (py_accepted, len(py_results) - py_accepted))
    print("divergences: %d" % divergences)
    if cov:
        print("coverage: %s/%s parser exit points reached" %
              (cov.group(1), cov.group(2)))
    else:
        print("coverage: NOT REPORTED (diff binary built without -Dcoverage?)")
    print("corpus: %s" % CORPUS_DESCRIPTION)

    if divergences:
        print()
        print("VERDICT: FAIL - %d divergence(s) saved under %s/divergences" %
              (divergences, workdir))
        return 1
    print()
    print("VERDICT: PASS - production parser and reference parser agree on "
          "every record")
    return 0


if __name__ == "__main__":
    sys.exit(main())
