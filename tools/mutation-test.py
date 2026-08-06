#!/usr/bin/env python3
# mutation-test.py
#
# Mutation harness v3 for the Grant verifier (LANGUAGE.md section 4 metric;
# SPEC.md section 11.2). cargo-mutants does not exist for Zig, so this applies
# one mutant at a time to src/verify.zig, rebuilds, runs the full test suite,
# and records whether the suite kills it.
#
# v3 change (Daniel, round 4, B3): the denominator is no longer stated by this
# script. It is DERIVED from SPEC.md at run time:
#   - the BE-GRANT-03 enumerated checks (the 0-11 list) are counted from SPEC
#   - the modelled subset is parsed from SPEC's conformance-status sentence
#     ("models checks 0, 1, 2, 5, 9, 10 and 11 inside the single routine")
#   - the BE-GRANT-03c seal is modelled iff SPEC states the requirement
# The gate then fails unless a killed mutant attacks EVERY modelled check and
# the seal. A denominator the gate controls is a denominator the gate can game;
# this one traces to SPEC, so dropping a mutant to hide a gap is impossible
# without also editing the SPEC line it is anchored to (CONTRIBUTING.md gate
# rule).
#
# v2 (kept) replaced check-absence mutants with check-CORRECTNESS mutants: a
# wrong operator, field, constant, boundary, or inverted condition. A
# check-absence mutant only proves a check exists; a check-correctness mutant
# proves the check is RIGHT. Every mutant keeps the module compiling, so a
# non-zero `zig build test` exit means a test caught the mutant by asserting
# the correct behaviour.

import re
import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFY = ROOT / "src" / "verify.zig"
SPEC = ROOT / "SPEC.md"
ZIG = pathlib.Path.home() / "srv/zig/toolchain/zig-aarch64-macos-0.16.0/zig"

ORIGINAL = VERIFY.read_text()


# --- denominator, derived from SPEC.md (the only source of truth) ----------

def enumerated_checks_from_spec():
    """The full BE-GRANT-03 check list (0-11), counted from SPEC's numbered
    list, not from this script."""
    text = SPEC.read_text()
    start = text.index("**BE-GRANT-03 (no bypass edge)**")
    rest = text[start:]
    nxt = rest.find("\n**BE-GRANT-03b")
    block = rest[:nxt] if nxt != -1 else rest
    nums = re.findall(r"^(\d+)\. ", block, re.MULTILINE)
    return [int(n) for n in nums]


def modelled_checks_from_spec():
    """The subset the slice models, parsed from SPEC's conformance-status
    sentence. This is the authority for 'which checks must be attacked'."""
    text = SPEC.read_text()
    m = re.search(r"models checks (.+?) inside the single routine", text, re.DOTALL)
    if not m:
        sys.exit("FATAL: cannot parse modelled-check set from SPEC "
                 "(conformance sentence changed?)")
    return [int(n) for n in re.findall(r"\d+", m.group(1))]


def seal_modeled_in_spec():
    return "**BE-GRANT-03c" in SPEC.read_text()


# --- mutants --------------------------------------------------------------
# Each mutant: (class, check, name, anchor, replacement). `check` is the SPEC
# BE-GRANT-03 number (0-11) the mutant attacks, or "03c" for the seal. The gate
# requires every modelled check and the seal to be covered by a KILLED mutant,
# and forbids any mutant attacking a check SPEC does not list as modelled.

MUTANTS = [
    ("WRONG-CONSTANT", 0,
     "check 0 version constant (version != 2 -> != 3)",
     "if (grant.version != 2) return error.BadVersion;",
     "if (grant.version != 3) return error.BadVersion; // MUTANT"),
    ("WRONG-CONSTANT", 2,
     "check 2 grant domain tag (DOMAIN_GRANT -> DOMAIN_ENVELOPE)",
     "try verifySigned(parser.DOMAIN_GRANT, grant.tbs, grant.sig, grant.approver);",
     "try verifySigned(parser.DOMAIN_ENVELOPE, grant.tbs, grant.sig, grant.approver); // MUTANT"),
    ("WRONG-FIELD", 1,
     "check 1 binding compares sender to subject not approver",
     "if (!std.mem.eql(u8, env.sender, grant.approver)) return error.BadEnvelopeBinding;",
     "if (!std.mem.eql(u8, env.sender, grant.subject)) return error.BadEnvelopeBinding; // MUTANT"),
    ("WRONG-FIELD", 5,
     "check 5 executor compares executor to approver not own key",
     "if (!std.mem.eql(u8, grant.executor, ctx.own_pubkey)) return error.WrongExecutor;",
     "if (!std.mem.eql(u8, grant.executor, grant.approver)) return error.WrongExecutor; // MUTANT"),
    ("WRONG-FIELD", 9,
     "check 9 digest hashed over grant_id not the intent action",
     "const digest = actionDigest(ctx.intent_action);",
     "const digest = actionDigest(grant.grant_id); // MUTANT"),
    ("WRONG-OPERATOR", 10,
     "check 10a not_after bound (>= -> >) weakens the deny",
     "if (now_ms >= not_after) return error.Expired;",
     "if (now_ms > not_after) return error.Expired; // MUTANT"),
    ("WRONG-OPERATOR", 10,
     "check 10b T_max bound (> -> >=) over-refuses at equality",
     "if (not_after > first_receipt_ms + t_max_ms) return error.Expired;",
     "if (not_after >= first_receipt_ms + t_max_ms) return error.Expired; // MUTANT"),
    ("WRONG-OPERATOR", 10,
     "check 10c T_recv bound (> -> >=) over-refuses at equality",
     "if (now_ms > first_receipt_ms + t_recv_ms) return error.Expired;",
     "if (now_ms >= first_receipt_ms + t_recv_ms) return error.Expired; // MUTANT"),
    ("WRONG-LOGIC", 11,
     "check 11 ledger condition inverted (consumed -> !consumed)",
     "if (ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed;",
     "if (!ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed; // MUTANT"),
    # BE-GRANT-03c seal: two mutants on grantOf, both killed by the TOCTOU test
    # that tampers slot.wire after verification and expects error.Tampered.
    ("SEAL-ABSENCE", "03c",
     "seal-check-absence: grantOf computes the digest but never compares it",
     "    if (!std.crypto.timing_safe.eql([32]u8, recomputed, slot.seal)) return error.Tampered;",
     "    _ = recomputed; // MUTANT seal-check-absence: MAC never compared"),
    ("SEAL-BYPASS", "03c",
     "tamper-passes: grantOf returns re-parsed data without checking the seal",
     "    const recomputed = sealOver(slot.wire);\n    if (!std.crypto.timing_safe.eql([32]u8, recomputed, slot.seal)) return error.Tampered;",
     "    // MUTANT tamper-passes: grantOf returns re-parsed data without the seal check"),
]


def run_suite():
    p = subprocess.run(
        [str(ZIG), "build", "test", "--summary", "all"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return p.returncode, p.stdout + p.stderr


def main():
    # 1. derive the denominator from SPEC
    enumerated = enumerated_checks_from_spec()
    modelled = set(modelled_checks_from_spec())
    seal = seal_modeled_in_spec()
    if not enumerated:
        sys.exit("FATAL: no enumerated BE-GRANT-03 checks found in SPEC")
    if not modelled.issubset(set(enumerated)):
        sys.exit(f"FATAL: modelled set {sorted(modelled)} not a subset of "
                 f"enumerated {enumerated} (SPEC/conformance drift)")
    print("denominator derived from SPEC.md (not self-counted):")
    print(f"  BE-GRANT-03 enumerated checks: {enumerated} ({len(enumerated)})")
    print(f"  modelled by this slice:        {sorted(modelled)} ({len(modelled)})")
    print(f"  BE-GRANT-03c seal:             {'modelled' if seal else 'NOT modelled'}")
    print()

    # scope check: no mutant may attack a check SPEC does not list as modelled
    for klass, check, name, _, _ in MUTANTS:
        if check != "03c" and check not in modelled:
            sys.exit(f"FATAL: mutant '{name}' attacks check {check}, which SPEC "
                     "does not list as modelled (scope lie)")

    # 2. run mutants
    results = []  # dict per mutant
    try:
        for klass, check, name, find, replace in MUTANTS:
            if find not in ORIGINAL:
                print(f"SKIP   [{klass}] {name}: anchor not found (verify.zig changed?)")
                results.append({"klass": klass, "check": check, "name": name,
                                "killed": False, "skipped": True})
                continue
            VERIFY.write_text(ORIGINAL.replace(find, replace, 1))
            rc, _ = run_suite()
            is_killed = rc != 0
            results.append({"klass": klass, "check": check, "name": name,
                            "killed": is_killed, "skipped": False})
            print(f"{'KILLED  ' if is_killed else 'SURVIVED'} [{klass}] {name}")
    finally:
        VERIFY.write_text(ORIGINAL)

    # 3. gate against the externally-derived denominator
    run = [r for r in results if not r["skipped"]]
    killed = sum(1 for r in run if r["killed"])
    survivors = [r["name"] for r in run if not r["killed"]]
    covered = {r["check"] for r in run if r["killed"] and r["check"] != "03c"}
    seal_killed = any(r["killed"] for r in run if r["check"] == "03c")
    uncovered = sorted(modelled - covered)

    print()
    print(f"mutation score: {len(covered)}/{len(modelled)} modelled "
          f"BE-GRANT-03 checks + {'1' if seal_killed else '0'}/1 seal "
          f"covered by killed mutants (denominator from SPEC.md)")
    print(f"  {killed}/{len(run)} mutants killed, "
          f"{len(survivors)} survived")
    if survivors:
        print(f"  SURVIVORS: {survivors}")
    if uncovered:
        print(f"  UNCOVERED modelled checks: {uncovered}")
    if not seal_killed:
        print("  UNCOVERED: BE-GRANT-03c seal")

    ok = (not survivors) and (not uncovered) and seal_killed and seal
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
