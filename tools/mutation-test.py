#!/usr/bin/env python3
# mutation-test.py
#
# Manual mutation harness for the Grant verifier (LANGUAGE.md section 4 metric;
# SPEC section 11.2 feasibility). cargo-mutants does not exist for Zig, so this
# applies one mutant at a time to src/verify.zig, rebuilds and runs the full test
# suite, and records whether the suite kills it. The mutant set targets every
# distinct check the slice models, so a 100% kill rate is evidence that the
# verifier's logic is covered, not just its happy path.
#
# Each mutant keeps the module compilable (mutated code still references its
# locals); a non-zero `zig build test` exit means a test caught the mutant.

import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFY = ROOT / "src" / "verify.zig"
ZIG = pathlib.Path.home() / "srv/zig/toolchain/zig-aarch64-macos-0.16.0/zig"

ORIGINAL = VERIFY.read_text()

# (name, anchor, replacement). Each disables exactly one BE-GRANT-03 check.
MUTANTS = [
    ("M1 version (BE-GRANT-03 c0)",
     "if (grant.version != 2) return error.BadVersion;",
     "if (false) return error.BadVersion; // MUTANT"),
    ("M2 sender==approver (c1)",
     "if (!std.mem.eql(u8, env.sender, grant.approver)) return error.BadEnvelopeBinding;",
     "if (false) return error.BadEnvelopeBinding; // MUTANT"),
    ("M3 executor (c5)",
     "if (!std.mem.eql(u8, grant.executor, ctx.own_pubkey)) return error.WrongExecutor;",
     "if (false) return error.WrongExecutor; // MUTANT"),
    ("M4 action digest (BE-GRANT-02 c9)",
     "if (!std.mem.eql(u8, &digest, grant.action_digest)) return error.ActionDigestMismatch;",
     "if (!std.mem.eql(u8, &digest, &digest)) return error.ActionDigestMismatch; // MUTANT"),
    ("M5 expiry (BE-GRANT-05 c10)",
     "try checkExpiry(grant.not_after, ctx.now_ms, ctx.first_receipt_ms, ctx.t_max_s, ctx.t_recv_s);",
     "// MUTANT: expiry skipped"),
]


def run_suite():
    p = subprocess.run(
        [str(ZIG), "build", "test", "--summary", "all"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return p.returncode, p.stdout + p.stderr


def main():
    killed = 0
    results = []
    try:
        for name, find, replace in MUTANTS:
            if find not in ORIGINAL:
                print(f"SKIP   {name}: anchor not found (verify.zig changed?)")
                continue
            VERIFY.write_text(ORIGINAL.replace(find, replace, 1))
            rc, _ = run_suite()
            is_killed = rc != 0
            killed += int(is_killed)
            results.append(is_killed)
            print(f"{'KILLED' if is_killed else 'SURVIVED'}  {name}")
    finally:
        VERIFY.write_text(ORIGINAL)  # always restore the source

    total = len(results)
    print(f"\nmutation score: {killed}/{total} killed")
    return 0 if total > 0 and killed == total else 1


if __name__ == "__main__":
    sys.exit(main())
