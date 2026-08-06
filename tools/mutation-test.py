#!/usr/bin/env python3
# mutation-test.py
#
# Mutation harness v6 for the Grant verifier, the attestation layer, AND the
# transport DoS gate (LANGUAGE.md section 4 metric; SPEC.md section 11.2).
# cargo-mutants does not exist for Zig, so this applies one mutant at a time to
# a source file, rebuilds, runs the full test suite, and records whether the
# suite kills it.
#
# v7 (round-4 review): the transport domain keys ALL FOUR section-4 markers,
# not just the two the symbolic tests could kill. D-026 excluded WINDOW_BITS
# and MAX_MESSAGE because their tests referenced the constant under test and so
# could never kill a mutant on it; the fix is to stop writing tests that way
# (CONTRIBUTING.md: a test MUST NOT reference the constant it verifies), key
# the properties anyway, and let the survivors show what the symbolic tests
# were hiding. The survivors are the finding.
# v6 (round 4, transport lands): the mac1/cookie DoS gate now has code
# (src/mac.zig), so it gets its own mutant class alongside Grant and Evidence.
# The check set for ALL THREE domains is DERIVED from SPEC.md at run time,
# never stated by this script (the denominator law, CONTRIBUTING.md):
#   - Grant domain: the modelled subset of BE-GRANT-03 (parsed from SPEC's
#     conformance sentence) plus the BE-GRANT-03b callback property.
#   - Evidence domain: the section-7 properties the slice implements, each
#     detected from a table or a BE-EVID marker in section 7 (ceiling integers,
#     the method_id->class table, BE-EVID-02/03/05/05a/09/09b).
#   - Transport domain: the section-4 properties the slice implements, one key
#     per bold BE-TR marker (mac1-label, cookie-rotate, window-bits,
#     max-message). All four are keyed regardless of whether the current tests
#     can kill a mutant on them: max-message is killable (its test cross-checks
#     a separate constant), window-bits is NOT yet killable (its test walks the
#     constant symbolically), and that survivor is the finding, not a gap to
#     route the denominator around.
# A killed mutant must cover every modelled grant check, the callback property,
# AND every detected evidence and transport property; a mutant attacking a
# property SPEC does not list is a scope lie and aborts. Dropping a rule from
# SPEC removes its key from the denominator, so hiding a gap means editing the
# SPEC line it traces to.
#
# v4 (kept) removed the BE-GRANT-03c seal mutants when the storable capability
# was deleted, replacing them with the CALLBACK class proving the effect runs
# only after every check (and the ledger commit) passes.
#
# v3 (kept) stopped stating the denominator: it is parsed from SPEC.
#
# v2 (kept) replaced check-absence mutants with check-CORRECTNESS mutants: a
# wrong operator, field, constant, boundary, or inverted condition. A
# check-absence mutant only proves a check exists; a check-correctness mutant
# proves the check is RIGHT. Every mutant keeps the module compiling, so a
# non-zero `zig build test` exit means a test caught the mutant by asserting the
# correct behaviour.

import re
import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
SPEC = ROOT / "SPEC.md"
ZIG = pathlib.Path.home() / "srv/zig/toolchain/zig-aarch64-macos-0.16.0/zig"

# Target files are mutated in place and restored from these snapshots, so the
# harness leaves the tree byte-identical on every exit path (try/finally).
TARGETS = {
    "verify.zig": SRC / "verify.zig",
    "evidence.zig": SRC / "evidence.zig",
    "dag.zig": SRC / "dag.zig",
    "mac.zig": SRC / "mac.zig",
    "replay.zig": SRC / "replay.zig",
    "reassembly.zig": SRC / "reassembly.zig",
}
ORIGINALS = {name: path.read_text() for name, path in TARGETS.items()}


# --- grant denominator, derived from SPEC.md section 8 --------------------

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


# --- evidence denominator, derived from SPEC.md section 7 -----------------
#
# Each property is DETECTED from a table or a BE-EVID marker in section 7. The
# denominator is the set of detected properties; nothing here is a literal. A
# mutant covers a property iff it is killed while attacking it.

EVIDENCE_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("ceiling-q8", "the normative Q8 ceiling integers (table 7.2/7.4)",
     r"DirectObservation.*?\*\*242\*\*.*?\*\*165\*\*"),
    ("class-table", "the method_id -> class derivation table (7.4)",
     r"\| `method_id` \| Observation mechanism \| Class \|"),
    ("min-recompute", "BE-EVID-02 receiver recomputes min(stated, ceiling)",
     r"BE-EVID-02 \(the receiver recomputes"),
    ("subject-match", "BE-EVID-03 resource_id == subject",
     r"\*\*BE-EVID-03\*\*"),
    ("supersession", "BE-EVID-05 superseded volatile span stops supporting",
     r"BE-EVID-05 \(superseded evidence stops supporting"),
    ("supersession-strict", "BE-EVID-05a supersession is strict descent",
     r"BE-EVID-05a \(supersession is strict descent"),
    ("three-state", "BE-EVID-09 three resolution states",
     r"BE-EVID-09 \(three states, not two"),
    ("origin-effect", "BE-EVID-09b origin must resolve to an Effect",
     r"BE-EVID-09b \(origin must resolve to an Effect"),
    # R3-inverse (round-4 review item 4): every cited span is attributed, never
    # silently dropped. resolveClaim is a verdict routine, so R3 applies to it:
    # a span that fails a check is COUNTED into a terminal bucket, and the count
    # is what a silent-drop mutant shifts.
    ("resolution-record", "R3-inverse: every cited span is attributed, not dropped",
     r"Every failure records a cause, not just a verdict"),
]


def evidence_properties_from_spec():
    """The set of section-7 properties the slice must prove, each detected from
    a SPEC marker. Removing a rule from SPEC removes its key here, so the gate
    cannot hide an untested property without editing SPEC."""
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in EVIDENCE_MARKERS:
        if re.search(pattern, text, re.DOTALL):
            props.add(key)
    return props


# --- transport denominator, derived from SPEC.md section 4 -----------------
#
# Each property is DETECTED from a bold BE-TR marker in section 4, one key per
# marker. D-026 keyed only the markers whose tests could kill a mutant on the
# constant. D-027 reverses that: key all four markers regardless. A test that
# references the constant under test (replay_test.zig walks replay.WINDOW_BITS)
# scales with the mutant and cannot kill it, so the window-bits mutant SURVIVES
# by construction. That survivor IS the finding: it shows the symbolic test was
# hiding an unverified property. The fix is to stop writing tests that way
# (CONTRIBUTING.md: a test MUST NOT reference the constant it verifies) and
# assert literal values instead, done in the following commit. max-message is
# already killable because reassembly_test.zig cross-checks a SEPARATE constant
# (MEMORY_PER_PEER) against bytesInUse(), so halving MAX_MESSAGE breaks the
# cross-check. A survivor is a finding, not a gate failure to route around.

TRANSPORT_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("mac1-label", "BE-TR-04 mac1 keying (the derivation label feeds the KAT)",
     r"\*\*BE-TR-04"),
    ("cookie-rotate", "BE-TR-04a cookie secret rotation (the 120s boundary)",
     r"\*\*BE-TR-04a"),
    ("window-bits", "BE-TR-03 anti-replay sliding window (the 1024-bit floor)",
     r"\*\*BE-TR-03"),
    ("max-message", "BE-TR-05 memory bounds (the 1 MiB per-message ceiling)",
     r"\*\*BE-TR-05"),
]


def transport_properties_from_spec():
    """The set of section-4 transport properties the slice must prove, each
    detected from a bold BE-TR marker. Removing a rule from SPEC removes its
    key here, so the gate cannot hide an untested property without editing SPEC."""
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in TRANSPORT_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- mutants --------------------------------------------------------------
# Each mutant: (domain, target, class, key, name, find, replace).
#   domain: "grant" or "evidence" - which derived denominator it gates against.
#   target: the filename in TARGETS to mutate.
#   key:    grant -> a BE-GRANT-03 number or "03b"; evidence -> a section-7
#           property key. The killed set is gated against the derived keys.
#   Every mutant keeps the file compiling; a non-zero `zig build test` exit means
#   a test caught it by asserting the correct behaviour.

MUTANTS = [
    # --- grant domain: the BE-GRANT-03 checks the slice models (src/verify.zig)
    ("grant", "verify.zig", "WRONG-CONSTANT", 0,
     "check 0 version constant (version != 2 -> != 3)",
     "if (grant.version != 2) return error.BadVersion;",
     "if (grant.version != 3) return error.BadVersion; // MUTANT"),
    ("grant", "verify.zig", "WRONG-CONSTANT", 2,
     "check 2 grant domain tag (DOMAIN_GRANT -> DOMAIN_ENVELOPE)",
     "try verifySigned(parser.DOMAIN_GRANT, grant.tbs, grant.sig, grant.approver);",
     "try verifySigned(parser.DOMAIN_ENVELOPE, grant.tbs, grant.sig, grant.approver); // MUTANT"),
    ("grant", "verify.zig", "WRONG-FIELD", 1,
     "check 1 binding compares sender to subject not approver",
     "if (!std.mem.eql(u8, env.sender, grant.approver)) return error.BadEnvelopeBinding;",
     "if (!std.mem.eql(u8, env.sender, grant.subject)) return error.BadEnvelopeBinding; // MUTANT"),
    ("grant", "verify.zig", "WRONG-FIELD", 5,
     "check 5 executor compares executor to approver not own key",
     "if (!std.mem.eql(u8, grant.executor, ctx.own_pubkey)) return error.WrongExecutor;",
     "if (!std.mem.eql(u8, grant.executor, grant.approver)) return error.WrongExecutor; // MUTANT"),
    ("grant", "verify.zig", "WRONG-FIELD", 9,
     "check 9 digest hashed over grant_id not the intent action",
     "const digest = actionDigest(ctx.intent_action);",
     "const digest = actionDigest(grant.grant_id); // MUTANT"),
    ("grant", "verify.zig", "WRONG-OPERATOR", 10,
     "check 10a not_after bound (>= -> >) weakens the deny",
     "if (now_ms >= not_after) return error.Expired;",
     "if (now_ms > not_after) return error.Expired; // MUTANT"),
    ("grant", "verify.zig", "WRONG-OPERATOR", 10,
     "check 10b T_max bound (> -> >=) over-refuses at equality",
     "if (not_after > first_receipt_ms + t_max_ms) return error.Expired;",
     "if (not_after >= first_receipt_ms + t_max_ms) return error.Expired; // MUTANT"),
    ("grant", "verify.zig", "WRONG-OPERATOR", 10,
     "check 10c T_recv bound (> -> >=) over-refuses at equality",
     "if (now_ms > first_receipt_ms + t_recv_ms) return error.Expired;",
     "if (now_ms >= first_receipt_ms + t_recv_ms) return error.Expired; // MUTANT"),
    ("grant", "verify.zig", "WRONG-LOGIC", 11,
     "check 11 ledger condition inverted (consumed -> !consumed)",
     "if (ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed;",
     "if (!ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed; // MUTANT"),
    # BE-GRANT-03b callback: the effect MUST NOT run before a check passes.
    ("grant", "verify.zig", "CALLBACK-ABSENCE", "03b",
     "effect never invoked despite a valid grant",
     "execute(grant);",
     "// MUTANT: effect call removed"),
    ("grant", "verify.zig", "CALLBACK-BEFORE-EXPIRY", 10,
     "callback invoked before the expiry check runs",
     "try checkExpiry(grant.not_after, ctx.now_ms, ctx.first_receipt_ms, ctx.t_max_s, ctx.t_recv_s);",
     "execute(grant); // MUTANT callback before expiry\n    try checkExpiry(grant.not_after, ctx.now_ms, ctx.first_receipt_ms, ctx.t_max_s, ctx.t_recv_s);"),
    ("grant", "verify.zig", "CALLBACK-BEFORE-LEDGER", 11,
     "callback invoked before the ledger check",
     "if (ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed;",
     "execute(grant); // MUTANT callback before ledger\n    if (ctx.already_consumed(grant.grant_id)) return error.AlreadyConsumed;"),

    # --- evidence domain: the attestation layer (src/evidence.zig, src/dag.zig)
    # Ceiling integers (table 7.2/7.4). BE_EVID_02/15 assert the exact Q8 value;
    # raising it one bit changes the recomputed confidence and the unit assert.
    ("evidence", "evidence.zig", "WRONG-CONSTANT", "ceiling-q8",
     "DirectObservation ceiling (242 -> 243)",
     ".direct_observation => 242,",
     ".direct_observation => 243, // MUTANT"),
    # Class derivation table (7.4): method_id 1 dropping out of DirectObservation
    # falls to the Inference floor. BE_EVID_15 asserts classOf(1) directly.
    ("evidence", "evidence.zig", "WRONG-CONSTANT", "class-table",
     "method 1 drops out of DirectObservation (1,2,3,4 -> 2,3,4)",
     "1, 2, 3, 4 => .direct_observation,",
     "2, 3, 4 => .direct_observation, // MUTANT"),
    # BE-EVID-02: receiver recomputes min(stated, ceiling). @min -> @max lets a
    # sender's number above the ceiling through. BE_EVID_02 kills it at 200/242.
    ("evidence", "evidence.zig", "WRONG-OPERATOR", "min-recompute",
     "effective = min(stated, ceiling) -> max",
     "return @min(stated_q8, strongest_ceiling_q8);",
     "return @max(stated_q8, strongest_ceiling_q8); // MUTANT"),
    # BE-EVID-03: resource_id == subject. Inverting the guard makes a matching
    # span NOT raise the ceiling. BE_EVID_03 (and almost every other test) kills it.
    ("evidence", "evidence.zig", "WRONG-LOGIC", "subject-match",
     "subject match guard inverted (skip matching spans)",
     "if (!std.mem.eql(u8, span.resource_id, claim.subject)) continue;",
     "if (std.mem.eql(u8, span.resource_id, claim.subject)) continue; // MUTANT"),
    # BE-EVID-05: a superseded volatile span stops supporting. Dropping the
    # is_superseded conjunct makes every volatile span count as superseded.
    # BE_EVID_05 (volatile, not superseded, expects supported) kills it.
    ("evidence", "evidence.zig", "WRONG-LOGIC", "supersession",
     "supersession conjunct dropped (volatile always superseded)",
     "if (isVolatile(span.volatility) and ctx.is_superseded(span.resource_id, span.origin, claim_envelope)) {",
     "if (isVolatile(span.volatility)) { // MUTANT"),
    # BE-EVID-05a: supersession is strict descent. The DAG operator's `and`
    # turned to `or` admits a sibling (descendant of origin, not ancestor of
    # claim). The dag sibling and strict-self tests kill it.
    ("evidence", "dag.zig", "WRONG-OPERATOR", "supersession-strict",
     "supersedes operator and -> or (admits a sibling)",
     "return self.isAncestor(origin, effect) and self.isAncestor(effect, claim);",
     "return self.isAncestor(origin, effect) or self.isAncestor(effect, claim); // MUTANT"),
    # BE-EVID-09: three resolution states. Swapping the Unresolved/Unsupported
    # tail makes an absent origin render as 0.00. BE_EVID_02b/09 kill it.
    ("evidence", "evidence.zig", "WRONG-LOGIC", "three-state",
     "unresolved/unsupported tail swapped",
     "    if (has_unresolved) return .{ .unresolved = rec };\n    return .{ .unsupported = rec };",
     "    if (has_unresolved) return .{ .unsupported = rec }; // MUTANT\n    return .{ .unresolved = rec }; // MUTANT"),
    # BE-EVID-09b: a non-Effect origin drops out of both states. Treating it as
    # Unresolved (set the flag instead of continue) renders it pending.
    # BE_EVID_09b (sole non-Effect span, expects unsupported) kills it.
    ("evidence", "evidence.zig", "WRONG-LOGIC", "origin-effect",
     "non-Effect origin treated as unresolved (continue -> flag)",
     "                rec.non_effect += 1; // BE-EVID-09b: counted, drops out of both states\n                continue;",
     "                rec.non_effect += 1; // BE-EVID-09b: counted, drops out of both states\n                has_unresolved = true; // MUTANT"),

    # --- R3-inverse: silent-drop class (round-4 review item 4). Before the
    # resolution record a span that failed a check was discarded with a bare
    # `continue` and no test could see it. Now each failure lands in a count,
    # and these mutants drop the increment: the state and number stay correct
    # (fail-closed), but a count the BE_EVID_16 assertions pin shifts, killing
    # the mutant. One per finding F1/F2/F3.
    # F2: a cited span not carried inline must still be counted as cited.
    ("evidence", "evidence.zig", "DROP-COUNT", "resolution-record",
     "cited-but-not-inline span silently dropped (cited count not incremented)",
     "        rec.cited += 1;",
     "        rec.cited += 0; // MUTANT"),
    # F3: a non-Effect origin must still be counted as non_effect.
    ("evidence", "evidence.zig", "DROP-COUNT", "resolution-record",
     "non-Effect origin span silently dropped (non_effect count not incremented)",
     "                rec.non_effect += 1; // BE-EVID-09b: counted, drops out of both states",
     "                rec.non_effect += 0; // MUTANT"),
    # F1: an unresolved span must still be counted as unresolved.
    ("evidence", "evidence.zig", "DROP-COUNT", "resolution-record",
     "unresolved span silently dropped (unresolved count not incremented)",
     "                rec.unresolved += 1; // BE-EVID-02b: origin pending",
     "                rec.unresolved += 0; // MUTANT"),

    # --- transport domain: the mac1/cookie DoS gate (src/mac.zig)
    # BE-TR-04 mac1 keying: the derivation label feeds the unkeyed->keyed
    # BLAKE2s chain. A wrong label yields a wrong mac1 digest. The BE_TR_04 KAT
    # in mac_test.zig asserts the exact expected_mac1 bytes from an independent
    # Python hashlib.blake2s run, so a relabelled key kills it on mismatch.
    ("transport", "mac.zig", "WRONG-CONSTANT", "mac1-label",
     "mac1 derivation label changed (bolina-mac1-v2 -> v3)",
     'pub const MAC1_LABEL: []const u8 = "bolina-mac1-v2";',
     'pub const MAC1_LABEL: []const u8 = "bolina-mac1-v3"; // MUTANT'),
    # BE-TR-04a cookie rotation: the 120s boundary. Bumping it one ms makes
    # needsRotate(121_000) return false (the test expects true) while leaving
    # needsRotate(120_999) false; the boundary tests in mac_test.zig kill it.
    ("transport", "mac.zig", "WRONG-CONSTANT", "cookie-rotate",
     "cookie rotation interval (120000 -> 120001) shifts the boundary",
     "pub const COOKIE_ROTATE_MS: u64 = 120_000;",
     "pub const COOKIE_ROTATE_MS: u64 = 120_001; // MUTANT"),
    # BE-TR-03 sliding window: SPEC 4.3 declares a window of at least 1024.
    # Halving it violates the floor. EXPECTED TO SURVIVE: every assertion in
    # replay_test.zig references replay.WINDOW_BITS symbolically (the walk runs
    # WINDOW_BITS/2 iterations over offsets mod WINDOW_BITS), so halving the
    # constant scales both sides of every check and no test catches the shrink.
    # This is the documented survivor that exposes the symbolic-test weakness;
    # the following commit rewrites those assertions to literal values (512
    # offsets mod 1024) so the mutant becomes killable. A grow mutant (1025)
    # would remain SPEC-compliant (the bound is a floor), so the shrink
    # direction is the one that attacks the declared property.
    ("transport", "replay.zig", "WRONG-CONSTANT", "window-bits",
     "replay window halved (1024 -> 512) violates the SPEC floor",
     "pub const WINDOW_BITS: usize = 1024;",
     "pub const WINDOW_BITS: usize = 512; // MUTANT"),
    # BE-TR-05 per-message ceiling: the 1 MiB cap. Halving it makes the memory
    # test's LITERAL 1048576-byte fragment exceed the cap, so ingest returns
    # message_dropped where the test asserts partial, and bytesInUse never
    # reaches the literal 8388608; both assertions kill it.
    ("transport", "reassembly.zig", "WRONG-CONSTANT", "max-message",
     "per-message ceiling halved (1 MiB -> 512 KiB)",
     "pub const MAX_MESSAGE: usize = 1 << 20; // 1 MiB: the ceiling every size derives from",
     "pub const MAX_MESSAGE: usize = 1 << 19; // MUTANT"),
]


def run_suite():
    p = subprocess.run(
        [str(ZIG), "build", "test", "--summary", "all"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return p.returncode, p.stdout + p.stderr


def main():
    # 1. derive BOTH denominators from SPEC
    enumerated = enumerated_checks_from_spec()
    modelled = set(modelled_checks_from_spec())
    if not enumerated:
        sys.exit("FATAL: no enumerated BE-GRANT-03 checks found in SPEC")
    if not modelled.issubset(set(enumerated)):
        sys.exit(f"FATAL: grant modelled set {sorted(modelled)} not a subset of "
                 f"enumerated {enumerated} (SPEC/conformance drift)")
    evidence_props = evidence_properties_from_spec()
    if not evidence_props:
        sys.exit("FATAL: no evidence properties detected in section 7 of SPEC")
    transport_props = transport_properties_from_spec()
    if not transport_props:
        sys.exit("FATAL: no transport properties detected in section 4 of SPEC")

    print("denominators derived from SPEC.md (not self-counted):")
    print(f"  BE-GRANT-03 enumerated checks: {enumerated} ({len(enumerated)})")
    print(f"  grant modelled by this slice:  {sorted(modelled)} ({len(modelled)})")
    print(f"  BE-GRANT-03b callback:         call-boundary property modelled")
    print(f"  section-7 evidence properties: {sorted(evidence_props)} ({len(evidence_props)})")
    print(f"  section-4 transport properties: {sorted(transport_props)} ({len(transport_props)})")
    print()

    # 2. scope check: no mutant may attack a key its domain's SPEC does not list
    for domain, _target, _klass, key, name, _f, _r in MUTANTS:
        if domain == "grant":
            if key != "03b" and key not in modelled:
                sys.exit(f"FATAL: grant mutant '{name}' attacks check {key}, which "
                         "SPEC does not list as modelled (scope lie)")
        elif domain == "evidence":
            if key not in evidence_props:
                sys.exit(f"FATAL: evidence mutant '{name}' attacks '{key}', which "
                         "section 7 of SPEC does not declare (scope lie)")
        else:  # transport
            if key not in transport_props:
                sys.exit(f"FATAL: transport mutant '{name}' attacks '{key}', which "
                         "section 4 of SPEC does not declare (scope lie)")

    # 3. run mutants
    results = []
    try:
        for domain, target, klass, key, name, find, replace in MUTANTS:
            if find not in ORIGINALS[target]:
                print(f"SKIP   [{domain}/{klass}] {name}: anchor not found ({target} changed?)")
                results.append({"domain": domain, "klass": klass, "key": key,
                                "name": name, "killed": False, "skipped": True})
                continue
            # Restore EVERY target to its clean original before applying this
            # mutant. A previous iteration mutated a different file and left it
            # live; without this reset the suite would fail for the wrong
            # reason (a false KILLED from an accumulated mutant, not from the
            # one under test). Each mutant is evaluated in isolation, period.
            for _n, _p in TARGETS.items():
                _p.write_text(ORIGINALS[_n])
            path = TARGETS[target]
            path.write_text(ORIGINALS[target].replace(find, replace, 1))
            rc, _ = run_suite()
            is_killed = rc != 0
            results.append({"domain": domain, "klass": klass, "key": key,
                            "name": name, "killed": is_killed, "skipped": False})
            print(f"{'KILLED  ' if is_killed else 'SURVIVED'} [{domain}/{klass}] {name}")
    finally:
        for name, path in TARGETS.items():
            path.write_text(ORIGINALS[name])

    # 4. gate each domain against its externally-derived denominator
    def gate_domain(dom, keys, callback_key=None):
        run = [r for r in results if r["domain"] == dom and not r["skipped"]]
        killed_keys = {r["key"] for r in run if r["killed"]}
        survivors = [r["name"] for r in run if not r["killed"]]
        uncovered = sorted(set(keys) - killed_keys)
        cb = callback_key in killed_keys if callback_key is not None else True
        return run, survivors, uncovered, cb

    print()
    g_run, g_surv, g_uncov, g_cb = gate_domain("grant", modelled, "03b")
    g_cov = {r["key"] for r in g_run if r["killed"] and r["key"] != "03b"}
    print(f"grant:   {len(g_cov)}/{len(modelled)} modelled BE-GRANT-03 checks + "
          f"{'1' if g_cb else '0'}/1 callback covered")
    e_run, e_surv, e_uncov, _ = gate_domain("evidence", evidence_props)
    e_cov = {r["key"] for r in e_run if r["killed"]}
    print(f"evidence: {len(e_cov)}/{len(evidence_props)} section-7 properties "
          f"covered by killed mutants")
    t_run, t_surv, t_uncov, _ = gate_domain("transport", transport_props)
    t_cov = {r["key"] for r in t_run if r["killed"]}
    print(f"transport: {len(t_cov)}/{len(transport_props)} section-4 properties "
          f"covered by killed mutants")
    total_run = [r for r in results if not r["skipped"]]
    total_killed = sum(1 for r in total_run if r["killed"])
    print(f"total:   {total_killed}/{len(total_run)} mutants killed, "
          f"{len(g_surv) + len(e_surv) + len(t_surv)} survived")
    if g_surv:
        print(f"  grant SURVIVORS: {g_surv}")
    if e_surv:
        print(f"  evidence SURVIVORS: {e_surv}")
    if t_surv:
        print(f"  transport SURVIVORS: {t_surv}")
    if g_uncov:
        print(f"  UNCOVERED grant checks: {g_uncov}")
    if e_uncov:
        print(f"  UNCOVERED evidence properties: {e_uncov}")
    if t_uncov:
        print(f"  UNCOVERED transport properties: {t_uncov}")
    if not g_cb:
        print("  UNCOVERED: BE-GRANT-03b callback property")

    ok = ((not g_surv) and (not e_surv) and (not t_surv) and (not g_uncov)
          and (not e_uncov) and (not t_uncov) and g_cb)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
