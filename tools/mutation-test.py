#!/usr/bin/env python3
# mutation-test.py
#
# Mutation harness v9 for the Grant verifier, the attestation layer, the
# transport DoS gate, the session phase, the channel layer AND the mesh
# identity boundary (LANGUAGE.md section 4 metric; SPEC.md section 11.2).
# cargo-mutants does not exist for Zig, so this applies one mutant at a time to
# a source file, rebuilds, runs the full test suite, and records whether the
# suite kills it.
#
# v9 (bolina mandate task 12): the channel and mesh domains. Tasks 10 and 11
# shipped verify code with unit tests but nothing trying to break it, so those
# two layers carried no mutation evidence at all. Both denominators are
# detected from SPEC markers like every other domain, never stated here:
#   channel <- section 6 BE-CHAN / BE-GEN / BE-CTRL markers
#   mesh    <- section 5 BE-MESH markers
# Deliberately not keyed, each for a stated reason rather than convenience:
# BE-CHAN-03's acceptance half is the same requireMember code already keyed
# under chan-01/chan-02 and its error priority is not normative in SPEC, so
# pinning an order would invent a requirement (the D-014 sin); BE-MESH-02 and
# BE-MESH-03 are relay obligations with no relay in this slice (D-037); and
# BE-MESH-07 is satisfied by placement, since the lookup parsers live in the
# post-authentication unit.
#
# v8 (bolina mandate task 8): the session domain. Five properties the session
# phase declares in SPEC section 4 get keys detected from their normative
# sentences, so deleting a sentence deletes its key (the denominator law):
#   key-schedule   <- the pinned protocol name (Noise_IK over BLAKE2s HKDF)
#   mac1-first     <- BE-TR-04's "before any X25519 operation"
#   nonce-counter  <- the [0x00 x4] || counter nonce layout and 2^48 bound
#   rekey-bound    <- BE-TR-02's earlier-of 120s/2^48 replacement
#   rekey-zero     <- BE-TR-02's old keys zeroed on replacement
#   binding-sig    <- BE-TR-01's signature over the handshake hash h
# Two test defects fixed in the preceding commit before these mutants could be
# honest (D-027, a test MUST NOT reference the constant it verifies):
# noise_test.zig hashed the module's own PROTOCOL_NAME and cross-checked the
# HKDF a-vs-b (every KDF mutant scales with both), and session_test.zig walked
# REKEY_AFTER_MESSAGES / REKEY_AFTER_MS symbolically. All now assert literal
# bytes and values from an independent Python run. One mutant class needed a
# new witness shape: a delayed mac1 check still returns Mac1Failed on a healthy
# ephemeral, so the ordering test feeds an identity-point ephemeral, where the
# first DH errors IdentityPoint and only a mac1-first ordering surfaces
# Mac1Failed. The key-schedule KATs are what make the split-swap mutant
# killable at all: both sides of the round trip split identically, so a swap is
# invisible to key-agreement assertions and only fixed bytes catch it.
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
import os

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
    "noise.zig": SRC / "noise.zig",
    "session.zig": SRC / "session.zig",
    "binding.zig": SRC / "binding.zig",
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


# --- session denominator, derived from SPEC.md section 4 ------------------
#
# The session phase (Noise_IK key schedule, session lifetime, binding). Each
# key is detected from the normative sentence it protects; removing the
# sentence from SPEC removes the key and the mutants that trace to it. The
# rekey rule yields two keys because it makes two independent promises (the
# replacement bound and the zeroization of replaced keys), exactly as BE-TR-04
# feeds both the mac1 label (transport domain) and the mac1 ordering (here).

SESSION_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("key-schedule", "the pinned Noise_IK protocol name seeding the BLAKE2s HKDF",
     r"\*\*`Noise_IK_25519_ChaChaPoly_BLAKE2s`\*\*"),
    ("mac1-first", "BE-TR-04 mac1 verified before any X25519 operation",
     r"verify `mac1` \*\*before any X25519 operation\*\*"),
    ("nonce-counter", "the [0x00 x4] || big-endian counter nonce within 2^48",
     r"\[0x00 x 4\] \|\| counter"),
    ("rekey-bound", "BE-TR-02 replace at the earlier of 120 s or 2^48 messages",
     r"after the earlier of 120 seconds or 2\u2074\u2078 messages"),
    ("rekey-zero", "BE-TR-02 old keys zeroed on replacement",
     r"Old keys MUST be zeroed on replacement"),
    ("binding-sig", "BE-TR-01 binding signature verified against the handshake hash h",
     r"that signature verifies against `h`"),
]


def session_properties_from_spec():
    """The set of session-phase properties the slice must prove, each detected
    from its normative sentence in SPEC section 4. Removing a sentence removes
    its key here, so the gate cannot hide an untested property without editing
    SPEC."""
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in SESSION_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- channel denominator, derived from SPEC.md section 6 ------------------
#
# The channel control verify layer (BE-CHAN/BE-GEN/BE-CTRL, tasks 10-11 era).
# Each key is detected from its bold marker in SPEC section 6; removing a rule
# from SPEC removes its key here. BE-CHAN-03 is deliberately NOT keyed: its
# acceptance half is modelled by the same requireMember code keyed under
# chan-01/chan-02, and its fan-out half has no caller in this slice. That
# exclusion is named in D-038 rather than dropped, the D-037-decision-5 shape.

CHANNEL_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("chan-01", "BE-CHAN-01 membership granted by the CA, cert carries member_group",
     r"\*\*BE-CHAN-01"),
    ("chan-02", "BE-CHAN-02 removal is monotonic, grow-only revoked set",
     r"\*\*BE-CHAN-02"),
    ("gen-01", "BE-GEN-01 exactly one genesis envelope per channel",
     r"\*\*BE-GEN-01"),
    ("gen-03", "BE-GEN-03 genesis signed by admin_group cert, channel_id derived",
     r"\*\*BE-GEN-03"),
    ("gen-04", "BE-GEN-04 match_rule fixed at byte equality",
     r"\*\*BE-GEN-04"),
    ("ctrl-01", "BE-CTRL-01 action_type outside {1, 2} rejected",
     r"\*\*BE-CTRL-01"),
    ("ctrl-02", "BE-CTRL-02 Revoke requires admin_group",
     r"\*\*BE-CTRL-02"),
]


def channel_properties_from_spec():
    """The set of section-6 channel properties the slice must prove, each
    detected from its bold marker in SPEC section 6."""
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in CHANNEL_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- mesh denominator, derived from SPEC.md section 5 ----------------------
#
# The lighthouse-served certificate verifier (BE-MESH-01/04/05/06). Keyed from
# the bold markers in SPEC section 5. BE-MESH-02/03 are relay obligations with
# no relay in this slice and BE-MESH-07 is satisfied by placement; all three
# are excluded here and named in D-037 decision 5, not silently dropped.

MESH_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("mesh-01", "BE-MESH-01 a lighthouse is availability, never authority",
     r"\*\*BE-MESH-01"),
    ("mesh-04", "BE-MESH-04 served cert verified under BE-ID-01 through BE-ID-04",
     r"\*\*BE-MESH-04"),
    ("mesh-05", "BE-MESH-05 served cert opens the session and confers nothing",
     r"\*\*BE-MESH-05"),
    ("mesh-06", "BE-MESH-06 windows and revocation re-verified at every use",
     r"\*\*BE-MESH-06"),
]


def mesh_properties_from_spec():
    """The set of section-5 mesh properties the slice must prove, each detected
    from its bold marker in SPEC section 5."""
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in MESH_MARKERS:
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
     "try verifySigned(parser.channel.DOMAIN_GRANT, grant.tbs, grant.sig, grant.approver);",
     "try verifySigned(parser.channel.DOMAIN_ENVELOPE, grant.tbs, grant.sig, grant.approver); // MUTANT"),
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

    # --- session domain: Noise_IK key schedule, lifetime, binding ----------
    # key-schedule: the pinned protocol name. The init-state test asserts the
    # LITERAL BLAKE2s of the name (independent Python run), so a renamed
    # protocol hashes to a different h0 and dies there. The old test hashed the
    # module's own PROTOCOL_NAME and scaled with this mutant; that was the
    # D-027 defect fixed in the preceding commit.
    ("session", "noise.zig", "WRONG-CONSTANT", "key-schedule",
     "protocol name BLAKE2s -> BLAKE2b changes the seed of the whole schedule",
     'pub const PROTOCOL_NAME: []const u8 = "Noise_IK_25519_ChaChaPoly_BLAKE2s";',
     'pub const PROTOCOL_NAME: []const u8 = "Noise_IK_25519_ChaChaPoly_BLAKE2b"; // MUTANT'),
    # key-schedule: the HKDF counter byte. First occurrence is hkdf2 (used by
    # mixKey and split); the literal mixKey KATs kill a wrong o1. An a-vs-b
    # cross-check could never kill this mutant because both states run the same
    # wrong KDF; fixed bytes from the independent Python run can.
    ("session", "noise.zig", "WRONG-CONSTANT", "key-schedule",
     "hkdf2 o1 counter byte 0x01 -> 0x02 corrupts every derived key",
     "    HmacBlake2s256.create(&o1, &[_]u8{1}, &temp_key);",
     "    HmacBlake2s256.create(&o1, &[_]u8{2}, &temp_key); // MUTANT"),
    # key-schedule: split halves swapped. Invisible to the round trip because
    # initiator and responder split identically; the literal split KATs kill it.
    ("session", "noise.zig", "WRONG-FIELD", "key-schedule",
     "split halves swapped (c1 <-> c2) silently cross-wires directions",
     "        return .{ .c1 = out.o1, .c2 = out.o2 };",
     "        return .{ .c1 = out.o2, .c2 = out.o1 }; // MUTANT"),
    # mac1-first: the check removed. Both tampered-mac1 tests expect
    # Mac1Failed; without the check a tampered mac1 byte never touches the
    # transcript, readInitiation succeeds, and the suite dies.
    ("session", "noise.zig", "CHECK-ABSENCE", "mac1-first",
     "responder never verifies mac1 (floods reach the curve)",
     "        const m1_in: [mac.MAC_BYTES]u8 = field(mac.MAC_BYTES, msg1, OFF1_MAC1);\n        if (!mac.verifyMac1(responder_sig_pubkey, msg1[0..MSG1_BEFORE_MAC1], m1_in)) return Error.Mac1Failed;",
     "        // MUTANT: mac1 never verified"),
    # mac1-first: the check DELAYED past the first DH. Behaviorally identical
    # on a healthy ephemeral (the existing tampered-mac1 tests still pass), so
    # the ordering witness feeds an identity-point ephemeral: the first DH then
    # errors IdentityPoint, and only a mac1-first ordering surfaces Mac1Failed.
    ("session", "noise.zig", "WRONG-ORDER", "mac1-first",
     "mac1 check delayed past the first X25519 (curve work before proof)",
     "        // BE-TR-04: mac1 before any X25519.\n        const m1_in: [mac.MAC_BYTES]u8 = field(mac.MAC_BYTES, msg1, OFF1_MAC1);\n        if (!mac.verifyMac1(responder_sig_pubkey, msg1[0..MSG1_BEFORE_MAC1], m1_in)) return Error.Mac1Failed;\n\n        // e: initiator ephemeral, hashed; captured for es/ee.\n        const eph_i = field(DHLEN, msg1, OFF1_EPHEMERAL);\n        self.re = eph_i;\n        self.sym.mixHash(&eph_i);\n\n        // es: DH(s_R, e_I).\n        self.sym.mixKey(try dh(self.static_kp, self.re));",
     "        // e: initiator ephemeral, hashed; captured for es/ee.\n        const eph_i = field(DHLEN, msg1, OFF1_EPHEMERAL);\n        self.re = eph_i;\n        self.sym.mixHash(&eph_i);\n\n        // es: DH(s_R, e_I).\n        self.sym.mixKey(try dh(self.static_kp, self.re)); // MUTANT: DH runs first\n\n        // MUTANT: mac1 check delayed past the first X25519.\n        const m1_in: [mac.MAC_BYTES]u8 = field(mac.MAC_BYTES, msg1, OFF1_MAC1);\n        if (!mac.verifyMac1(responder_sig_pubkey, msg1[0..MSG1_BEFORE_MAC1], m1_in)) return Error.Mac1Failed;"),
    # nonce-counter: little-endian counter. The nonce test asserts literal byte
    # positions (0x01 at index 11 for counter 1, 0x01 at index 4 for the big
    # counter), which an endian flip violates.
    ("session", "noise.zig", "WRONG-ENDIAN", "nonce-counter",
     "transport nonce counter written little-endian",
     "    std.mem.writeInt(u64, nb[4..], counter, .big);",
     "    std.mem.writeInt(u64, nb[4..], counter, .little); // MUTANT"),
    # nonce-counter: the 2^48 message ceiling halved. The test sets the counter
    # to the literal 2^48 - 1 and expects one more legal seal; under a 2^47
    # ceiling that seal refuses, killing the mutant. The old test walked
    # session.REKEY_AFTER_MESSAGES symbolically and scaled with it.
    ("session", "session.zig", "WRONG-CONSTANT", "nonce-counter",
     "message ceiling halved (2^48 -> 2^47) rekeys sessions twice as early",
     "pub const REKEY_AFTER_MESSAGES: u64 = 1 << 48;",
     "pub const REKEY_AFTER_MESSAGES: u64 = 1 << 47; // MUTANT"),
    # rekey-bound: the 120 s time bound shifted one ms. The literal boundary
    # test expects due at epoch + 120_000 exactly; 120_001 is not due there.
    ("session", "session.zig", "WRONG-CONSTANT", "rekey-bound",
     "time bound 120_000 -> 120_001 shifts the rekey deadline",
     "pub const REKEY_AFTER_MS: u64 = 120_000;",
     "pub const REKEY_AFTER_MS: u64 = 120_001; // MUTANT"),
    # rekey-zero: the send zeroization dropped. The rotate test advances the
    # send counter under the old key and asserts it is 0 after rotation; the
    # counter reset lives inside zero(), so the witness catches the drop.
    ("session", "session.zig", "DROP-ZERO", "rekey-zero",
     "rotate never zeroes the old send state",
     "    pub fn rotate(s: *Session, result: noise.HandshakeResult, now_ms: u64) void {\n        s.send.zero();\n        s.recv.zero();",
     "    pub fn rotate(s: *Session, result: noise.HandshakeResult, now_ms: u64) void {\n        // MUTANT: old send state never zeroed\n        s.recv.zero();"),
    # rekey-zero: the recv zeroization dropped. The rotate test dirties the
    # recv window before rotation and asserts a fresh (uninitialized) window
    # after; the fresh window comes from zero().
    ("session", "session.zig", "DROP-ZERO", "rekey-zero",
     "rotate never zeroes the old recv state",
     "    pub fn rotate(s: *Session, result: noise.HandshakeResult, now_ms: u64) void {\n        s.send.zero();\n        s.recv.zero();",
     "    pub fn rotate(s: *Session, result: noise.HandshakeResult, now_ms: u64) void {\n        s.send.zero();\n        // MUTANT: old recv state never zeroed"),
    # binding-sig: the signature never verified. The tampered-signature test
    # expects BadBindingSig; without the check bindSession succeeds and the
    # suite dies. Unused parameters are legal in Zig, so the file compiles.
    ("session", "binding.zig", "CHECK-ABSENCE", "binding-sig",
     "bindSession never verifies the signature over h",
     "    verifySig(DOMAIN_BINDING, handshake_hash, binding_sig, cert.sig_pubkey) catch |e| switch (e) {\n        error.MalformedKey => return error.MalformedKey,\n        error.SignatureRejected => return error.BadBindingSig,\n    };",
     "    // MUTANT: the binding signature is never verified"),

    # --- channel domain: control verification (src/verify.zig, SPEC 6.1a-c)
    # chan-01: membership inverted. The BE_CHAN_01 test expects NotMember for a
    # cert without member_group; under the inversion it is accepted.
    ("channel", "verify.zig", "WRONG-LOGIC", "chan-01",
     "membership check inverted (non-members accepted, members refused)",
     "    if (!certCarriesGroup(sender_cert, genesis.member_group)) return error.NotMember;",
     "    if (certCarriesGroup(sender_cert, genesis.member_group)) return error.NotMember; // MUTANT"),
    # chan-02: revocation inverted. The BE_CHAN_02 test expects SubjectRevoked
    # for a revoked subject; under the inversion only unrevoked subjects fail.
    ("channel", "verify.zig", "WRONG-LOGIC", "chan-02",
     "revocation check inverted (revoked subjects accepted)",
     "    if (ctx.is_revoked(sender_cert.sig_pubkey)) return error.SubjectRevoked;",
     "    if (!ctx.is_revoked(sender_cert.sig_pubkey)) return error.SubjectRevoked; // MUTANT"),
    # gen-01: duplicate-genesis check inverted. The BE_GEN_01 test expects
     # DuplicateGenesis when the ledger hook says the channel exists.
    ("channel", "verify.zig", "WRONG-LOGIC", "gen-01",
     "duplicate genesis check inverted (second genesis accepted)",
     "    if (ctx.genesis_exists(channel_id)) return error.DuplicateGenesis;",
     "    if (!ctx.genesis_exists(channel_id)) return error.DuplicateGenesis; // MUTANT"),
    # gen-03 (authority half): admin-group check dropped. The BE_GEN_03
    # non-admin test expects GenesisNotAdmin.
    ("channel", "verify.zig", "CHECK-ABSENCE", "gen-03",
     "genesis admin-group authority never checked",
     "    if (!certCarriesGroup(admin_cert, genesis.admin_group)) return error.GenesisNotAdmin;",
     "    // MUTANT: admin group never checked"),
    # gen-03 (derivation half): channel_id comparison dropped. The BE_GEN_03
    # mismatched-id test expects BadChannelId.
    ("channel", "verify.zig", "CHECK-ABSENCE", "gen-03",
     "channel_id never compared against BLAKE2s(name || ca_key_0)",
     "    if (!std.mem.eql(u8, channel_id, &derived)) return error.BadChannelId;",
     "    // MUTANT: channel_id never compared"),
    # gen-04: match_rule constant shifted. The BE_GEN_04 test refuses
    # match_rule 2; under != 2 the value 2 passes and the refusal disappears.
    ("channel", "verify.zig", "WRONG-CONSTANT", "gen-04",
     "match_rule byte-equality value shifted (1 -> 2)",
     "    if (genesis.match_rule != 1) return error.BadMatchRule;",
     "    if (genesis.match_rule != 2) return error.BadMatchRule; // MUTANT"),
    # ctrl-01: the Revoke arm removed from the accept set. The BE_CTRL_02 test
    # drives action_type 2 and expects RevokeNotAdmin; under {1, 3} it hits
    # BadActionType instead, and the grant-arm action 3 becomes legal.
    ("channel", "verify.zig", "WRONG-CONSTANT", "ctrl-01",
     "action_type accept set shifted ({1, 2} -> {1, 3})",
     "        1, 2 => {},",
     "        1, 3 => {}, // MUTANT"),
    # ctrl-02: the admin requirement inverted. The BE_CTRL_02 test expects
    # RevokeNotAdmin for a non-admin sender; under the inversion non-admins
    # pass and admins are refused.
    ("channel", "verify.zig", "WRONG-LOGIC", "ctrl-02",
     "revoke admin requirement inverted (non-admins accepted)",
     "    if (control.action_type == 2 and !certCarriesGroup(sender_cert, genesis.admin_group))",
     "    if (control.action_type == 2 and certCarriesGroup(sender_cert, genesis.admin_group)) // MUTANT"),

    # --- mesh domain: served-certificate verification (src/verify.zig, SPEC 5)
    # mesh-01: identity taken from the wrong key. The overlay address derives
    # from sig_pubkey (BE-ID-01); deriving it from kex_pubkey makes every
    # honest lookup mismatch, so the happy-path tests kill it.
    ("mesh", "verify.zig", "WRONG-FIELD", "mesh-01",
     "overlay address derived from kex_pubkey instead of sig_pubkey",
     "    const derived = binding.deriveOverlayAddr(served.sig_pubkey);",
     "    const derived = binding.deriveOverlayAddr(served.kex_pubkey); // MUTANT"),
    # mesh-04 (substitution half): the address comparison dropped. The
    # BE_MESH_04 mismatch and BE_MESH_01 substitution tests both expect
    # AddressMismatch with open_calls still zero.
    ("mesh", "verify.zig", "CHECK-ABSENCE", "mesh-04",
     "served identity substitution never checked",
     "    const derived = binding.deriveOverlayAddr(served.sig_pubkey);\n    if (!std.mem.eql(u8, &derived, requested_addr)) return error.AddressMismatch;",
     "    _ = requested_addr; // MUTANT: substitution never checked"),
    # mesh-04 (chain half): validateCert dropped. The untrusted-CA test and the
    # BE_MESH_06 window test both expect ServedCertInvalid.
    ("mesh", "verify.zig", "CHECK-ABSENCE", "mesh-04",
     "served certificate chain never validated (BE-ID-02..04 skipped)",
     "    binding.validateCert(served, ctx.trusted_ca_keys, ctx.now_ms) catch return error.ServedCertInvalid;",
     "    // MUTANT: served certificate chain never validated"),
    # mesh-04 call boundary: the continuation never invoked despite a valid
    # cert. The happy-path tests assert open_calls == 1.
    ("mesh", "verify.zig", "CALLBACK-ABSENCE", "mesh-04",
     "session never opened despite a fully verified served cert",
     "    open_session(.{ .sig_pubkey = served.sig_pubkey, .kex_pubkey = served.kex_pubkey });",
     "    _ = open_session; // MUTANT: session never opened"),
    # mesh-05: the boundary wired wrong. The continuation must carry exactly
    # the two keys the handshake needs; feeding sig_pubkey twice is caught by
    # the happy-path assertion that opened_kex equals the cert's kex_pubkey.
    # The field-set reflection test (BE_MESH_05) guards the type's shape; this
    # mutant guards what crosses it.
    ("mesh", "verify.zig", "WRONG-FIELD", "mesh-05",
     "kex half of the boundary carries sig_pubkey (key material crossed)",
     "    open_session(.{ .sig_pubkey = served.sig_pubkey, .kex_pubkey = served.kex_pubkey });",
     "    open_session(.{ .sig_pubkey = served.sig_pubkey, .kex_pubkey = served.sig_pubkey }); // MUTANT"),
    # mesh-06: revocation at use dropped. The BE_MESH_06 revocation test
    # accepts while unrevoked, then expects ServedCertRevoked on reuse.
    ("mesh", "verify.zig", "CHECK-ABSENCE", "mesh-06",
     "revocation never consulted at use (cached verdict carried forward)",
     "    if (ctx.is_revoked(served.sig_pubkey)) return error.ServedCertRevoked;",
     "    // MUTANT: revocation never consulted at use"),
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
    session_props = session_properties_from_spec()
    if not session_props:
        sys.exit("FATAL: no session properties detected in section 4 of SPEC")
    channel_props = channel_properties_from_spec()
    if not channel_props:
        sys.exit("FATAL: no channel properties detected in section 6 of SPEC")
    mesh_props = mesh_properties_from_spec()
    if not mesh_props:
        sys.exit("FATAL: no mesh properties detected in section 5 of SPEC")

    print("denominators derived from SPEC.md (not self-counted):")
    print(f"  BE-GRANT-03 enumerated checks: {enumerated} ({len(enumerated)})")
    print(f"  grant modelled by this slice:  {sorted(modelled)} ({len(modelled)})")
    print(f"  BE-GRANT-03b callback:         call-boundary property modelled")
    print(f"  section-7 evidence properties: {sorted(evidence_props)} ({len(evidence_props)})")
    print(f"  section-4 transport properties: {sorted(transport_props)} ({len(transport_props)})")
    print(f"  session-phase properties:        {sorted(session_props)} ({len(session_props)})")
    print(f"  section-6 channel properties:    {sorted(channel_props)} ({len(channel_props)})")
    print(f"  section-5 mesh properties:       {sorted(mesh_props)} ({len(mesh_props)})")
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
        elif domain == "transport":
            if key not in transport_props:
                sys.exit(f"FATAL: transport mutant '{name}' attacks '{key}', which "
                         "section 4 of SPEC does not declare (scope lie)")
        elif domain == "session":
            if key not in session_props:
                sys.exit(f"FATAL: session mutant '{name}' attacks '{key}', which "
                         "SPEC does not declare (scope lie)")
        elif domain == "channel":
            if key not in channel_props:
                sys.exit(f"FATAL: channel mutant '{name}' attacks '{key}', which "
                         "section 6 of SPEC does not declare (scope lie)")
        elif domain == "mesh":
            if key not in mesh_props:
                sys.exit(f"FATAL: mesh mutant '{name}' attacks '{key}', which "
                         "section 5 of SPEC does not declare (scope lie)")
        else:
            sys.exit(f"FATAL: mutant '{name}' in unknown domain '{domain}'")

    # 3. run mutants
    # Optional domain filter (MUTATION_DOMAIN env var) so a chunked run stays
    # under the tool-timeout ceiling. A SIGKILL mid-run bypasses the finally
    # block below and leaves a live mutant in the tree; each domain fits
    # comfortably under the ceiling on its own, so filtering avoids that path.
    _domain_filter = os.environ.get("MUTATION_DOMAIN")
    run_mutants = ([m for m in MUTANTS if m[0] == _domain_filter]
                   if _domain_filter else MUTANTS)
    results = []
    try:
        for domain, target, klass, key, name, find, replace in run_mutants:
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
    #
    # A chunked run (MUTATION_DOMAIN set, D-035) executes one domain only. The
    # gate used to evaluate all six regardless, so every chunk reported the
    # five unrun domains as 0/N covered and returned 1. That made the exit code
    # decorative in the only mode the timeout ceiling permits: the pass signal
    # had to be read by eye off one printed row. Out-of-scope domains are now
    # reported as not run and excluded from the ok condition, so each chunk
    # returns 0 exactly when the domain it ran is fully covered with no
    # survivors. An unfiltered run still gates all six.
    def in_scope(dom):
        return _domain_filter is None or dom == _domain_filter

    def gate_domain(dom, keys, callback_key=None):
        if not in_scope(dom):
            return [], [], [], True
        run = [r for r in results if r["domain"] == dom and not r["skipped"]]
        killed_keys = {r["key"] for r in run if r["killed"]}
        survivors = [r["name"] for r in run if not r["killed"]]
        uncovered = sorted(set(keys) - killed_keys)
        cb = callback_key in killed_keys if callback_key is not None else True
        return run, survivors, uncovered, cb

    print()
    if _domain_filter:
        print(f"chunked run: MUTATION_DOMAIN={_domain_filter}, other domains "
              f"not run and not gated (D-035)")
    g_run, g_surv, g_uncov, g_cb = gate_domain("grant", modelled, "03b")
    if in_scope("grant"):
        g_cov = {r["key"] for r in g_run if r["killed"] and r["key"] != "03b"}
        print(f"grant:   {len(g_cov)}/{len(modelled)} modelled BE-GRANT-03 "
              f"checks + {'1' if g_cb else '0'}/1 callback covered")
    e_run, e_surv, e_uncov, _ = gate_domain("evidence", evidence_props)
    if in_scope("evidence"):
        e_cov = {r["key"] for r in e_run if r["killed"]}
        print(f"evidence: {len(e_cov)}/{len(evidence_props)} section-7 "
              f"properties covered by killed mutants")
    t_run, t_surv, t_uncov, _ = gate_domain("transport", transport_props)
    if in_scope("transport"):
        t_cov = {r["key"] for r in t_run if r["killed"]}
        print(f"transport: {len(t_cov)}/{len(transport_props)} section-4 "
              f"properties covered by killed mutants")
    s_run, s_surv, s_uncov, _ = gate_domain("session", session_props)
    if in_scope("session"):
        s_cov = {r["key"] for r in s_run if r["killed"]}
        print(f"session:  {len(s_cov)}/{len(session_props)} session-phase "
              f"properties covered by killed mutants")
    c_run, c_surv, c_uncov, _ = gate_domain("channel", channel_props)
    if in_scope("channel"):
        c_cov = {r["key"] for r in c_run if r["killed"]}
        print(f"channel:  {len(c_cov)}/{len(channel_props)} section-6 "
              f"properties covered by killed mutants")
    m_run, m_surv, m_uncov, _ = gate_domain("mesh", mesh_props)
    if in_scope("mesh"):
        m_cov = {r["key"] for r in m_run if r["killed"]}
        print(f"mesh:     {len(m_cov)}/{len(mesh_props)} section-5 "
              f"properties covered by killed mutants")
    total_run = [r for r in results if not r["skipped"]]
    total_killed = sum(1 for r in total_run if r["killed"])
    print(f"total:   {total_killed}/{len(total_run)} mutants killed, "
          f"{len(g_surv) + len(e_surv) + len(t_surv) + len(s_surv) + len(c_surv) + len(m_surv)}"
          f" survived")
    if g_surv:
        print(f"  grant SURVIVORS: {g_surv}")
    if e_surv:
        print(f"  evidence SURVIVORS: {e_surv}")
    if t_surv:
        print(f"  transport SURVIVORS: {t_surv}")
    if s_surv:
        print(f"  session SURVIVORS: {s_surv}")
    if c_surv:
        print(f"  channel SURVIVORS: {c_surv}")
    if m_surv:
        print(f"  mesh SURVIVORS: {m_surv}")
    if g_uncov:
        print(f"  UNCOVERED grant checks: {g_uncov}")
    if e_uncov:
        print(f"  UNCOVERED evidence properties: {e_uncov}")
    if t_uncov:
        print(f"  UNCOVERED transport properties: {t_uncov}")
    if s_uncov:
        print(f"  UNCOVERED session properties: {s_uncov}")
    if c_uncov:
        print(f"  UNCOVERED channel properties: {c_uncov}")
    if m_uncov:
        print(f"  UNCOVERED mesh properties: {m_uncov}")
    if not g_cb:
        print("  UNCOVERED: BE-GRANT-03b callback property")

    ok = ((not g_surv) and (not e_surv) and (not t_surv) and (not s_surv)
          and (not c_surv) and (not m_surv)
          and (not g_uncov) and (not e_uncov) and (not t_uncov)
          and (not s_uncov) and (not c_uncov) and (not m_uncov) and g_cb)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())