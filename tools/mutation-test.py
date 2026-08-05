#!/usr/bin/env python3
# mutation-test.py
#
# Mutation harness v2 for the Grant verifier (LANGUAGE.md section 4 metric;
# SPEC.md section 11.2). cargo-mutants does not exist for Zig, so this applies
# one mutant at a time to src/verify.zig, rebuilds, runs the full test suite,
# and records whether the suite kills it.
#
# v2 replaces the v1 check-absence mutants (which skipped a check with
# `if (false)`) with check-CORRECTNESS mutants: a wrong operator, a wrong
# field, a wrong constant, a wrong boundary, or an inverted condition. A
# check-absence mutant only proves a check exists; a check-correctness mutant
# proves the check is RIGHT. Every mutant below must keep the module compiling
# (mutated code still references its locals), so a non-zero `zig build test`
# exit means a test caught the mutant by asserting the correct behaviour.
#
# Denominator, stated honestly: this harness covers the SEVEN checks the slice
# models (0 version, 1 envelope binding, 2 grant sig, 5 executor, 9 action
# digest, 10 expiry, 11 consumed-ledger). Checks 3, 4 (certificate validity),
# 6, 7, 8 (pending-intent matching) are not modelled here; they need a
# certificate store and the executor's pending-intent table, which the slice
# defers. So a 100% kill rate means "every check the slice claims to enforce is
# enforced correctly", not "the whole BE-GRANT-03 chain is mutation-clean".

import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFY = ROOT / "src" / "verify.zig"
ZIG = pathlib.Path.home() / "srv/zig/toolchain/zig-aarch64-macos-0.16.0/zig"

ORIGINAL = VERIFY.read_text()

# (class, name, anchor, replacement). Each mutant mutates exactly one check's
# CORRECTNESS, not its presence.
MUTANTS = [
    # WRONG-CONSTANT: the compared value or domain tag is wrong.
    ("WRONG-CONSTANT", "check 0 version constant (version != 2 -> != 3)",
     "if (grant.version != 2) return error.BadVersion;",
     "if (grant.version != 3) return error.BadVersion; // MUTANT"),
    ("WRONG-CONSTANT", "check 2 grant domain tag (DOMAIN_GRANT -> DOMAIN_ENVELOPE)",
     "try verifySigned(parser.DOMAIN_GRANT, grant.tbs, grant.sig, grant.approver);",
     "try verifySigned(parser.DOMAIN_ENVELOPE, grant.tbs, grant.sig, grant.approver); // MUTANT"),
    # WRONG-FIELD: a comparison reads the wrong field of the grant/envelope.
    ("WRONG-FIELD", "check 1 binding compares sender to subject not approver",
     "if (!std.mem.eql(u8, env.sender, grant.approver)) return error.BadEnvelopeBinding;",
     "if (!std.mem.eql(u8, env.sender, grant.subject)) return error.BadEnvelopeBinding; // MUTANT"),
    ("WRONG-FIELD", "check 5 executor compares executor to approver not own key",
     "if (!std.mem.eql(u8, grant.executor, ctx.own_pubkey)) return error.WrongExecutor;",
     "if (!std.mem.eql(u8, grant.executor, grant.approver)) return error.WrongExecutor; // MUTANT"),
    ("WRONG-FIELD", "check 9 digest hashed over grant_id not the intent action",
     "const digest = actionDigest(ctx.intent_action);",
     "const digest = actionDigest(grant.grant_id); // MUTANT"),
    # WRONG-OPERATOR / BOUNDARY: a comparison operator is flipped. The three
    # expiry conditions are strict on two sides and non-strict on not_after;
    # each mutant weakens or tightens one boundary by one step.
    ("WRONG-OPERATOR", "check 10a not_after bound (>= -> >) weakens the deny",
     "if (now_ms >= not_after) return error.Expired;",
     "if (now_ms > not_after) return error.Expired; // MUTANT"),
    ("WRONG-OPERATOR", "check 10b T_max bound (> -> >=) over-refuses at equality",
     "if (not_after > first_receipt_ms + t_max_ms) return error.Expired;",
     "if (not_after >= first_receipt_ms + t_max_ms) return error.Expired; // MUTANT"),
    ("WRONG-OPERATOR", "check 10c T_recv bound (> -> >=) over-refuses at equality",
     "if (now_ms > first_receipt_ms + t_recv_ms) return error.Expired;",
     "if (now_ms >= first_receipt_ms + t_recv_ms) return error.Expired; // MUTANT"),
    # WRONG-LOGIC: the consumed-ledger condition is inverted (still runs, just
    # backwards), proving the check tests the right polarity.
    ("WRONG-LOGIC", "check 11 ledger condition inverted (consumed -> !consumed)",
     "if (ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed;",
     "if (!ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed; // MUTANT"),
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
        for klass, name, find, replace in MUTANTS:
            if find not in ORIGINAL:
                print(f"SKIP   [{klass}] {name}: anchor not found (verify.zig changed?)")
                continue
            VERIFY.write_text(ORIGINAL.replace(find, replace, 1))
            rc, _ = run_suite()
            is_killed = rc != 0
            killed += int(is_killed)
            results.append((klass, name, is_killed))
            print(f"{'KILLED  ' if is_killed else 'SURVIVED'} [{klass}] {name}")
    finally:
        VERIFY.write_text(ORIGINAL)  # always restore the source

    total = len(results)
    print()
    print(f"mutation score: {killed}/{total} mutants killed")
    print("denominator: 9 check-correctness mutants over the 7 modelled BE-GRANT-03 "
          "checks (0,1,2,5,9,10,11); checks 3,4,6,7,8 are unmodelled "
          "(no cert store / pending-intent table in this slice)")
    return 0 if total > 0 and killed == total else 1


if __name__ == "__main__":
    sys.exit(main())
