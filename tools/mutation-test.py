#!/usr/bin/env python3
# mutation-test.py
#
# Mutation harness v20 for the Grant verifier, the attestation layer, the
# transport DoS gate, the session phase, the channel layer, the mesh identity
# boundary, the relay surface, the ledger/history surface, the
# pending-intent/refusal surface, the resolver/render surface, the
# backfill/sync surface AND the durable grant-ledger/crash-recovery surface
# (LANGUAGE.md section 4 metric; SPEC.md section 11.2).
# cargo-mutants does not exist for Zig, so this applies one mutant at a time to
# a source file, rebuilds, runs the full test suite, and records whether the
# suite kills it.
#
# v15 (sync slice): the sync domain, and the version ledger catches up: v13
# added the resolver domain (BE-RES-01..06, src/resolver.zig) and v14 the
# render domain (BE-GRANT-07/07a, src/render.zig) without header notes; this
# note records all three rounds. BE-SYNC-01..05 shipped as the parser/sync.zig
# surface sub-unit plus the non-surface src/sync.zig engine (D-054); the
# denominator is detected from SPEC §6.4 markers like every other domain.
# Twelve mutants: the session and membership preconditions removed; the
# 64-envelope ceiling off by one; the 1 MiB cap doubled; the truncated flag
# pinned to zero; the have-set bound flipped at the ceiling; the depth and
# total walk comparisons flipped; retry-on-exhaustion reintroduced; the rate
# budget widened at the count and at the window edge; verify-before-adopt
# skipped.
# v12 (pending-intent slice): two domains. src/intent.zig shipped the
# pending-intent state machine (D-052, SPEC section 8.2) and verify.zig
# shipped verifyRefusalThen (SPEC 8.5), so both get their own denominator
# detected from SPEC markers like every other domain:
#   intent  <- §8.2 BE-GRANT-04/06/06a/06b/09/10 markers
#   refusal <- §8.5 the 0x06 domain tag + approver-role map + BE-GRANT-09 apply
# Six intent keys: restart collapse, resource exclusivity, T_pending sweep,
# intent_id dedupe, the refusal state transition, and REJECTED terminality.
# Three refusal keys: the 0x06 domain tag, the approver role, and the
# applyRefusal hook. BE-GRANT-09 splits across both domains on purpose: its
# state-machine half (PENDING -> REJECTED) is keyed under intent, its
# verification half (sig + approver + apply) under refusal. No key is omitted.
#
# v11 (ledger slice): the ledger domain. BE-LEDGER-01/02/03, BE-HIST-02/03/04
# and BE-ENV-03/04/05 shipped as src/ledger.zig plus src/historical.zig and
# the verify.zig admission path (D-045/D-046), so the §9 obligations get their
# own denominator, detected from SPEC markers like every other domain:
#   ledger <- §9.1 BE-LEDGER markers, §9.2 BE-HIST markers, §3 BE-ENV-03/04/05
# Nine keys: unknown-parent rejection, the hash-only store, Grant/Effect
# recording, the body_type/role map, the sliding seq window, equivocation
# surfacing, anchor-before-first-use, the causal-interval validity check, and
# revocation's causal position. Deliberately not keyed, for a stated reason
# rather than convenience: BE-HIST-01's audit clock exemption. Its vehicle
# validateCertNoClock is a documented stub pending the binding.zig refactor,
# so no test exercises it and no mutant of it could be killed; the key enters
# this denominator when the stub lands. The f8ee78e regression (five scan
# loops stepped by two, skipping odd-index entries) is covered by the
# second-signer/second-pubkey witnesses the fix added.
#
# v10 (relay slice): the relay domain. BE-MESH-02 shipped as src/relay.zig
# (D-043/D-044), so the mesh obligations the v9 note excluded for lack of a
# relay now get their own denominator, detected from SPEC markers like every
# other domain:
#   relay <- §5.2a wire formats, §5.2 BE-MESH-02, and the BE-SIG-01 0x07 row
# Eight keys: the two wire formats, the forward invariant, unknown-recipient
# drop, the 4096-entry table bound, the 300s skew, expiry pruning, and the
# 0x07 domain tag. Two keys attack code the slice defers rather than omits
# silently: the domain tag is pinned by a constant-vs-literal test (the
# verification path that consumes it is D-043-deferred) and the sig boundary
# is pinned through the tbs slice the future verifier will sign. Preceding
# commit hardened relay_test.zig to literal expectations (D-027): the
# table-full test walked relay.MAX_RELAY_TABLE symbolically, and the skew,
# tbs, and tag boundaries had no witness at all.
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
# pinning an order would invent a requirement (the D-014 sin); BE-MESH-03
# stays deferred (store-and-forward is a MAY, D-043) and BE-MESH-07 is
# satisfied by placement, since the lookup parsers live in the
# post-authentication unit. BE-MESH-02 moved to the relay domain in v10.
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
    "relay.zig": SRC / "relay.zig",
    "relay_store.zig": SRC / "relay_store.zig",
    "dispatch.zig": SRC / "dispatch.zig",
    "grant_ledger.zig": SRC / "grant_ledger.zig",
    "listener.zig": SRC / "listener.zig",
    "handshake.zig": SRC / "handshake.zig",
    "relay_serve.zig": SRC / "relay_serve.zig",
    "ledger.zig": SRC / "ledger.zig",
    "historical.zig": SRC / "historical.zig",
    "intent.zig": SRC / "intent.zig",
    "resolver.zig": SRC / "resolver.zig",
    "render.zig": SRC / "render.zig",
    "sync.zig": SRC / "sync.zig",
    "parser/sync.zig": SRC / "parser" / "sync.zig",
}
ORIGINALS = {name: path.read_text() for name, path in TARGETS.items()}

# A snapshot taken over residue from a killed run poisons every subsequent
# result: the mutant under test is applied on top of an already-broken
# baseline, the suite fails for the wrong reason, and every mutant is reported
# KILLED trivially. The run looks perfect and means nothing. Refuse to start.
_POISONED = sorted(n for n, t in ORIGINALS.items() if "MUTANT" in t)
if _POISONED:
    sys.stderr.write(
        "refusing to run: mutant residue in the baseline snapshot: "
        + ", ".join(_POISONED)
        + "\nrestore the tree first (git checkout HEAD -- src/), then re-run.\n"
    )
    sys.exit(2)

# Any argument is a mistake, and a silent one: this harness never parsed argv,
# so `--help` used to start a full in-place mutation run whose output went to a
# pipe nobody was reading. That is how residue got into the tree.
if len(sys.argv) > 1:
    sys.stderr.write(
        "refusing to run: this harness takes no arguments (got: "
        + " ".join(sys.argv[1:])
        + ").\nconfigure it through the environment (MUTATION_DOMAIN=<domain>).\n"
    )
    sys.exit(2)


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
# The lighthouse-served certificate verifier (BE-MESH-01/04/05/06) plus
# store-and-forward (BE-MESH-03). Keyed from the bold markers in SPEC
# section 5. BE-MESH-02 is keyed under the relay domain below (v10).
# BE-MESH-03, deferred as a MAY at v10, was bound after Daniel's 2026-08-11
# ruling (keep going, follow the spec) and enters the denominator with its
# mutants in harness v16 (D-051 closed, D-058 ruling). BE-MESH-07 stays
# satisfied by placement; it is excluded here and named in D-037 decision 5,
# not silently dropped.

MESH_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("mesh-01", "BE-MESH-01 a lighthouse is availability, never authority",
     r"\*\*BE-MESH-01"),
    ("mesh-03", "BE-MESH-03 relay MAY store forwarded ciphertext for offline recipients",
     r"\*\*BE-MESH-03"),
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


# --- daemon denominator, derived from SPEC.md section 0.4 ------------------

DAEMON_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("daemon-exec-02", "BE-EXEC-02 one listener per endpoint",
     r"\*\*BE-EXEC-02"),
    ("daemon-exec-03", "BE-EXEC-03 single address family",
     r"\*\*BE-EXEC-03"),
    ("daemon-sess-02", "BE-SESS-02 no half-session",
     r"\*\*BE-SESS-02"),
]


def daemon_properties_from_spec():
    """The set of section-0.4 daemon properties the slice must prove, each
    detected from its bold marker in SPEC section 0.4."""
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in DAEMON_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- dispatch denominator, derived from the D-059 ruling -------------------
#
# The dispatch seam (src/dispatch.zig) is daemon-milestone code: it carries
# no SPEC markers, so its denominator keys derive from the D-059 ruling's
# recorded decisions, hardcoded here with the ruling as the cited text. The
# law still holds: every property needs a killed mutant keyed to it, and
# removing a ruling decision removes its key here.

DISPATCH_PROPS = [
    # (denominator key, what D-059 records)
    ("dispatch-routing", "D-059 decision 2: body_type routes to its machine; "
     "intent/grant/refusal run their full machines, utterance passes "
     "through, control/effect routing-verified"),
    ("dispatch-envelope-gate", "D-059 decision 1 (corrected): the dispatch "
     "entry gate is verifyEnvelope, the BE-ENV-02 envelope signature check"),
    ("dispatch-subject-seam", "D-059 correction: the subject cert belongs to "
     "the intent sender and rides the cert_for_sender seam"),
    ("dispatch-executing-transition", "D-059 decision 4: the EXECUTING "
     "transition lands after a successful grant verify frame"),
    ("dispatch-consumed-commit", "D-059 decision 3: the consumed-grant hook "
     "is a check-and-set registry; first sight commits the grant_id"),
]


def dispatch_properties():
    """The set of phase-A dispatch properties the slice must prove, each
    derived from a recorded D-059 decision (daemon-milestone code carries no
    SPEC markers)."""
    return {key for key, _what in DISPATCH_PROPS}


# --- relay_serve denominator, derived from SPEC §0.4 BE-EXEC-04 (D-060) -----
#
# The serve-loop (src/relay_serve.zig) is phase-C daemon-milestone code. The
# single bold marker BE-EXEC-04 declares five sub-obligations; the denominator
# keys are those sub-obligations as recorded in the D-060 ruling, hardcoded
# here with the marker's normative text as the citation. The law holds: every
# property needs a killed mutant keyed to it, and removing a sub-obligation
# from the marker removes its key here.

RELAY_SERVE_PROPS = [
    # (denominator key, what BE-EXEC-04 declares)
    ("relay-serve-classify", "BE-EXEC-04: the leading type byte routes the "
     "datagram; any other value is dropped with no service"),
    ("relay-serve-sender-gate", "BE-EXEC-04: a type-5 route MUST NOT be "
     "forwarded unless sender_index is an established session at the relay"),
    ("relay-serve-decision", "BE-EXEC-04 + section 5.2a decision table: live "
     "delivery when the recipient endpoint is known, deferred storage when the "
     "registration is known but the endpoint is not, no service otherwise"),
    ("relay-serve-drain", "BE-EXEC-04: a type-6 registration accepted for a "
     "recipient with stored packets MUST drain the queue in store order, "
     "rewriting recipient_index to the fresh client_index"),
    ("relay-serve-opacity", "BE-EXEC-04 + BE-MESH-02: the Noise ciphertext body "
     "MUST pass byte-for-byte unchanged through the serve path"),
]


def relay_serve_properties():
    """The set of phase-C serve-loop properties the slice must prove, each
    derived from a BE-EXEC-04 sub-obligation recorded in the D-060 ruling."""
    return {key for key, _what in RELAY_SERVE_PROPS}


# --- grant_ledger denominator, derived from SPEC BE-GRANT-01/01a, BE-GRANT-04,
# BE-REV-02, BE-EXEC-01 (D-061). The durable consumed-grant + revocation
# append log (src/grant_ledger.zig, non-surface). Hardcoded keys with the
# normative citation; the law holds: every property needs a killed mutant
# keyed to it.

GRANT_LEDGER_PROPS = [
    # (denominator key, what the SPEC declares)
    ("grant-ledger-commit", "BE-GRANT-01: the consumed-grant commit row is "
     "appended and fsynced before the effect may run (durable before effect)"),
    ("grant-ledger-single-shot", "BE-GRANT-01: a spent grant_id is refused on "
     "replay (isConsumed is the single-shot gate)"),
    ("grant-ledger-orphan", "BE-GRANT-01a: a committed grant whose published "
     "tombstone never landed surfaces as exactly one orphan at recovery"),
    ("grant-ledger-at-least-once", "BE-GRANT-01a: an un-tombstoned orphan "
     "re-emits on every recovery until tombstoned (fail-safe at-least-once)"),
    ("grant-ledger-revoke", "BE-REV-02: a CA-signed revocation is durable and "
     "survives restart"),
    ("grant-ledger-prune", "BE-EXEC-01: pruneExpired drops consumed grants "
     "past their validity window, keeping live ones (bounded live set)"),
    ("grant-ledger-partial", "robustness: a partial trailing record (crash "
     "mid-write before fsync) is discarded, never read as a grant"),
]


def grant_ledger_properties():
    """The set of durable-ledger properties the slice must prove, each derived
    from a SPEC obligation recorded in the D-061 ruling."""
    return {key for key, _what in GRANT_LEDGER_PROPS}


# --- grant_revocation denominator, derived from the D-064 ruling ------------
#
# The F4 wiring (RED-TEAM-10): revocation consulted at the grant checkpoint,
# checks 3-4 of verifyGrantThen backed by dispatch.isRevokedHook over the
# durable grant_ledger revocation set (BE-REV-02 enforced at the capability->
# effect seam, not merely stored). The seam code carries no new SPEC marker
# (D-064: no M1 changes), so its denominator keys derive from the recorded
# D-064 rulings, hardcoded here with the ruling as the cited text. The law
# still holds: every property needs a killed mutant keyed to it.

GRANT_REVOCATION_PROPS = [
    # (denominator key, what D-064 records)
    ("f4-approver-check", "D-064 fix (3): check 3 consults "
     "is_revoked(approver_cert.sig_pubkey) -> ApproverRevoked at the "
     "capability->effect checkpoint (verify.zig 'as of this use')"),
    ("f4-subject-check", "D-064 fix (4): check 4 consults "
     "is_revoked(subject_cert.sig_pubkey) -> SubjectRevoked, declared fresh "
     "in VerifyError (ruling 2)"),
    ("f4-failsafe", "D-064 ruling 1: isRevokedHook returns true (refuse) when "
     "no durable ledger is initialized; the revocation set is part of the "
     "durable authority state, so without it loaded no grant may turn into "
     "an effect"),
]


def grant_revocation_properties():
    """The set of F4-seam properties the slice must prove, each derived from a
    ruling recorded in the D-064 decision entry."""
    return {key for key, _what in GRANT_REVOCATION_PROPS}


# --- relay denominator, derived from SPEC.md §5.2/§5.2a/BE-SIG-01 -----------
#
# The relay surface (src/relay.zig): BE-MESH-02 forwarding under D-043's
# BE-MESH-02-only scope. Keys are detected from the §5.2a wire-format
# definitions, the normative sentences they cite, and the BE-SIG-01 0x07 row;
# removing a sentence from SPEC removes its key here (the denominator law).
# Two keys name obligations the slice pins but does not yet consume: the 0x07
# domain tag (signature verification is deferred with the session state it
# needs) and the tbs boundary (the bytes the deferred verifier will sign).
# Pinning them keeps the wire commitment honest instead of quietly dropping
# the key until the verifier lands.

RELAY_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("relay-route-format", "§5.2a type 5 route header, 20 fixed bytes",
     r"Type5RelayRoute :="),
    ("relay-reg-format", "§5.2a type 6 registration, 124 fixed bytes",
     r"Type6RelayRegistration :="),
    ("relay-forward", "BE-MESH-02 forward unchanged, no key material",
     r"\*\*BE-MESH-02"),
    ("relay-unknown-dst", "MUST NOT forward type 5 to unknown recipient_index",
     r"MUST NOT forward type 5 packets to unknown"),
    ("relay-table-bound", "registration table bounded to 4096 entries",
     r"bounded to 4096 entries"),
    ("relay-skew", "|now - timestamp| > 300 seconds silently dropped",
     r"\|now - timestamp\| > 300"),
    ("relay-expiry", "registration entries expire at expiry and are pruned",
     r"Registration entries expire"),
    ("relay-domain-tag", "BE-SIG-01 domain tag 0x07 for RelayRegistration",
     r"0x07.*RelayRegistration"),
]


def relay_properties_from_spec():
    """The set of relay properties the slice must prove, each detected from
    its marker in SPEC §5.2/§5.2a or the BE-SIG-01 table."""
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in RELAY_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- ledger denominator, derived from SPEC.md §9.1/§9.2 and BE-ENV-03/04/05 -
# BE-HIST-01 is deliberately absent: validateCertNoClock is a documented stub
# pending the binding.zig refactor, no test exercises it, and a mutant of it
# could not be killed. Its key enters here when the stub lands (v11 note).
LEDGER_MARKERS = [
    # (denominator key, what SPEC says, marker text that must be present)
    ("ledger-unknown-parents",
     "an envelope naming unknown parent hashes is rejected within a bounded fetch",
     r"reject an envelope whose `parents` reference unknown hashes"),
    ("ledger-hash-only",
     "the ledger stores hashes, never plaintext",
     r"The ledger stores hashes, never plaintext"),
    ("ledger-grant-effect",
     "every Grant and every Effect appears in the ledger",
     r"Every `Grant` and every `Effect` MUST appear in the ledger"),
    ("env-role-map",
     "an envelope is rejected when its sender certificate lacks the body_type role",
     r"reject an envelope whose sender certificate lacks the role"),
    ("env-seq-window",
     "a per-(sender, channel) sliding acceptance window over seq",
     r"sliding acceptance window over"),
    ("env-equivocation",
     "a second envelope at one (sender, channel, seq) raises a divergence, never dropped",
     r"raise a divergence event with both hashes"),
    ("hist-anchor-first-use",
     "a signer's certificate is anchored in the channel before its first use",
     r"A signer's certificate MUST be anchored in the"),
    ("hist-causal-interval",
     "historical validity is causal descent from the anchor, outside any revocation",
     r"An envelope is historically valid if it is a causal"),
    ("hist-revocation-causal",
     "revocation is immediate for admission and causal-positioned for audit",
     r"A revocation takes effect for admission immediately on"),
]


def ledger_properties_from_spec():
    """The set of ledger/history properties the slice must prove, each detected
    from its marker in SPEC §9.1/§9.2 or the BE-ENV-03/04/05 rows."""
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in LEDGER_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- intent denominator, derived from SPEC.md section 8 -------------------
#
# The pending-intent state machine (src/intent.zig), non-surface. Each property
# is detected from a bold BE-GRANT marker in section 8, exactly as the other
# denominators. BE-GRANT-09 splits across two domains: its state-machine half
# (PENDING -> REJECTED) lives here; its verification half (sig + role) is the
# refusal domain below. Both detect the same SPEC sentence, by design.

INTENT_MARKERS = [
    ("intent-restart-collapse",
     "BE-GRANT-04 restart collapses every PENDING to EXPIRED (memory-only)",
     r"\*\*BE-GRANT-04 \(fail-closed on restart\)\*\*"),
    ("intent-exclusivity",
     "BE-GRANT-06 resource exclusivity (one holder, no queue)",
     r"\*\*BE-GRANT-06 \(resource exclusivity\)\*\*"),
    ("intent-tpending",
     "BE-GRANT-06a T_pending timeout transitions PENDING to EXPIRED",
     r"\*\*BE-GRANT-06a \(pending timeout\)\*\*"),
    ("intent-dedupe",
     "BE-GRANT-06b intent_id uniqueness at admission",
     r"\*\*BE-GRANT-06b \(intent_id uniqueness\)\*\*"),
    ("intent-refusal-transition",
     "BE-GRANT-09 a matched Refusal transitions PENDING to REJECTED",
     r"\*\*BE-GRANT-09 \(refusal semantics\)\*\*"),
    ("intent-terminal-rejected",
     "BE-GRANT-10 REJECTED is terminal, no transition out",
     r"\*\*BE-GRANT-10 \(refusal is terminal\)\*\*"),
]


def intent_properties_from_spec():
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in INTENT_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- refusal denominator, derived from SPEC.md section 8.5 + 8.1 ----------
#
# The Refusal verification half (verify.zig verifyRefusalThen): the signature
# domain tag, the approver-role gate, and the pending-intent transition hook.
# The sig tag 0x06 is a BE-SIG-01 row; the role is the body_type/role map; the
# transition is BE-GRANT-09's verify half (its state half is the intent domain).

REFUSAL_MARKERS = [
    ("refusal-domain-tag",
     "BE-SIG-01 the Refusal signature uses domain tag 0x06",
     r"domain tag 0x06 \(BE-SIG-01\)"),
    ("refusal-approver-role",
     "a Refusal requires the approver role (body_type/role map)",
     r"`Grant` and `Refusal` require `approver`"),
    ("refusal-apply-hook",
     "BE-GRANT-09 a verified Refusal transitions the pending intent",
     r"\*\*BE-GRANT-09 \(refusal semantics\)\*\*"),
]


def refusal_properties_from_spec():
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in REFUSAL_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- resolver denominator, derived from SPEC.md section 8.4 ----------------
#
# Canonical resource resolution (src/resolver.zig): the executor-side
# canonicalizer, alias collapse, own-fingerprint gate, and the signed
# resource-set publication state (D-053). Six markers, six properties.

RESOLVER_MARKERS = [
    ("resolver-canonical",
     "BE-RES-01 the executor canonicalizes, never the requester",
     r"\*\*BE-RES-01 \(the executor canonicalizes, never the requester\)\*\*"),
    ("resolver-unknown-refuse",
     "BE-RES-02 unknown or ambiguous resolves to refusal",
     r"\*\*BE-RES-02 \(unknown resolves to refusal\)\*\*"),
    ("resolver-alias-collapse",
     "BE-RES-03 aliases collapse into the lock",
     r"\*\*BE-RES-03 \(aliases collapse into the lock\)\*\*"),
    ("resolver-own-executor",
     "BE-RES-04 one resource, one executor (own fingerprint gate)",
     r"\*\*BE-RES-04 \(one resource, one executor\)\*\*"),
    ("resolver-signed-set",
     "BE-RES-05 the resource set publishes as signed state",
     r"\*\*BE-RES-05 \(granularity is declared, not emergent\)\*\*"),
    ("resolver-fp-blake2s",
     "BE-RES-06 executor_fp is BLAKE2s-256(sig_pubkey)[0..8], 16 lowercase hex",
     r"\*\*BE-RES-06 \(the sig_pubkey fingerprint is BLAKE2s-256\)\*\*"),
]


def resolver_properties_from_spec():
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in RESOLVER_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- render denominator, derived from SPEC.md section 8.3 -------------------
# What the human sees: the approving interface renders canonical resource_id,
# full action bytes, and a recomputed digest (BE-GRANT-07), with any
# displayed rationale marked untrusted and subordinate (BE-GRANT-07a).

RENDER_MARKERS = [
    ("render-approve-bytes",
     "BE-GRANT-07 approving interface renders canonical id, full action, recomputed digest",
     r"\*\*BE-GRANT-07\*\*"),
    ("render-rationale-untrusted",
     "BE-GRANT-07a displayed rationale marked untrusted, subordinate, never alone",
     r"\*\*BE-GRANT-07a\*\*"),
]


def render_properties_from_spec():
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in RENDER_MARKERS:
        if re.search(pattern, text):
            props.add(key)
    return props


# --- sync denominator, derived from SPEC.md section 6.4 --------------------
#
# Backfill surface: the parser/sync.zig wire parsers (third post-auth
# sub-unit, D-054) and the non-surface src/sync.zig engine. Admission,
# response bounds, walk budget, rate budget, verify-before-adopt. Five
# markers, five properties.

SYNC_MARKERS = [
    ("sync-admission",
     "BE-SYNC-01 authenticated peers only (session, member, not revoked)",
     r"\*\*BE-SYNC-01 \(authenticated peers only\)\*\*"),
    ("sync-bounds",
     "BE-SYNC-02 hard response bounds (min(max_envelopes,64), 1 MiB, truncated)",
     r"\*\*BE-SYNC-02 \(hard response bounds\)\*\*"),
    ("sync-walk",
     "BE-SYNC-03 walk budget (depth 128, total 4096, stop and surface)",
     r"\*\*BE-SYNC-03 \(walk budget\)\*\*"),
    ("sync-rate",
     "BE-SYNC-04 rate budget (serve 8, issue 4, per peer per 10 s)",
     r"\*\*BE-SYNC-04 \(rate\)\*\*"),
    ("sync-adopt",
     "BE-SYNC-05 verify before adopt",
     r"\*\*BE-SYNC-05 \(verify before adopt\)\*\*"),
]


def sync_properties_from_spec():
    text = SPEC.read_text()
    props = set()
    for key, _what, pattern in SYNC_MARKERS:
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
    # Checks 3, 4, 6, 7 and 8 folded into the routine when GrantContext gained
    # the certificate store and the pending-intent fields. SPEC's conformance
    # sentence records the repayment, so the derived denominator now demands
    # these five be attacked like every other modelled check.
    ("grant", "verify.zig", "CHECK-ABSENCE", 3,
     "check 3 approver role constraint never enforced",
     "if ((ctx.approver_cert.role_bits & binding.ROLE_APPROVER) == 0) return error.BadApproverCert;",
     "// MUTANT: approver role constraint removed"),
    ("grant", "verify.zig", "CHECK-ABSENCE", 4,
     "check 4 subject role constraint never enforced",
     "if ((ctx.subject_cert.role_bits & binding.ROLE_AGENT) == 0) return error.BadSubjectCert;",
     "// MUTANT: subject role constraint removed"),
    ("grant", "verify.zig", "CHECK-ABSENCE", 6,
     "check 6 subject never matched against the pending intent's sender",
     "if (!std.mem.eql(u8, grant.subject, ctx.intent_sender)) return error.WrongSubject;",
     "// MUTANT: pending-intent sender match removed"),
    ("grant", "verify.zig", "CHECK-ABSENCE", 7,
     "check 7 intent_id never matched against the pending intent",
     "if (!std.mem.eql(u8, grant.intent_id, ctx.pending_intent_id)) return error.NoMatchingIntent;",
     "// MUTANT: intent_id match removed"),
    ("grant", "verify.zig", "CHECK-ABSENCE", 8,
     "check 8 resource_id never matched against the pending intent",
     "if (!std.mem.eql(u8, grant.resource_id, ctx.pending_resource_id)) return error.WrongResource;",
     "// MUTANT: resource_id match removed"),
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
     "if (ctx.already_consumed(grant.grant_id, grant.not_after, ctx.now_ms)) return error.AlreadyConsumed;",
     "if (!ctx.already_consumed(grant.grant_id, grant.not_after, ctx.now_ms)) return error.AlreadyConsumed; // MUTANT"),
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
     "if (ctx.already_consumed(grant.grant_id, grant.not_after, ctx.now_ms)) return error.AlreadyConsumed;",
     "execute(grant); // MUTANT callback before ledger\n    if (ctx.already_consumed(grant.grant_id, grant.not_after, ctx.now_ms)) return error.AlreadyConsumed;"),

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
    # dispatch seam (src/dispatch.zig): the D-059 ruling's recorded
    # decisions, each attacked by a mutant keyed to its property. The seam
    # tests, grant tests, and refusal tests in dispatch_test.zig kill them.
    ("dispatch", "dispatch.zig", "WRONG-VALUE", "dispatch-routing",
     "intent body_type routed to the utterance pass-through",
     "            channel.BODY_INTENT => self.dispatchIntent(env, now_ms),",
     "            channel.BODY_INTENT => Outcome.utterance, // MUTANT: intent never admitted"),
    ("dispatch", "dispatch.zig", "WRONG-VALUE", "dispatch-routing",
     "control body_type routed to the utterance pass-through",
     "            channel.BODY_CONTROL => Outcome.control,",
     "            channel.BODY_CONTROL => Outcome.utterance, // MUTANT: control misrouted"),
    ("dispatch", "dispatch.zig", "CHECK-ABSENCE", "dispatch-envelope-gate",
     "envelope signature gate skipped",
     "        verify.verifyEnvelope(env) catch return error.BadEnvelope;",
     "        // MUTANT: envelope signature gate skipped"),
    ("dispatch", "dispatch.zig", "WRONG-SOURCE", "dispatch-subject-seam",
     "subject cert taken from the approver, not the intent sender seam",
     "        const subject_cert = hooks.cert_for_sender(&rec.sender) orelse return error.UnknownSender;",
     "        const subject_cert = approver_cert; // MUTANT: subject cert taken from the approver"),
    ("dispatch", "dispatch.zig", "CHECK-ABSENCE", "dispatch-executing-transition",
     "EXECUTING transition skipped after the grant frame",
     "        try self.intents.beginExecuting(idx);",
     "        // MUTANT: EXECUTING transition skipped"),
    ("dispatch", "dispatch.zig", "CHECK-ABSENCE", "dispatch-consumed-commit",
     "grant_id never durably committed to the consumed ledger (D-062 seam)",
     "    lg.commitConsumed(gid, not_after_ms, now_ms) catch return true;",
     "    // MUTANT: grant_id never durably committed (commit skipped)"),
    # --- grant_ledger domain: the durable consumed-grant + revocation append
    # log (src/grant_ledger.zig, D-061). Each mutant attacks one SPEC
    # obligation (BE-GRANT-01/01a, BE-REV-02, BE-EXEC-01) and is killed by a
    # literal binding test in grant_ledger_test.zig. Anchors are the exact
    # source text; the runner restores every target before each mutant.
    ("grant_ledger", "grant_ledger.zig", "CHECK-ABSENCE", "grant-ledger-commit",
     "BE-GRANT-01: commit row never appended (no durable commit before effect)",
     "        try self.appendSync(&row);\n        @memcpy(&self.consumed[self.consumed_len], &grant_id);\n        self.consumed_len += 1;",
     "        // MUTANT: commit row never appended (no durable commit before effect)\n        @memcpy(&self.consumed[self.consumed_len], &grant_id);\n        self.consumed_len += 1;"),
    ("grant_ledger", "grant_ledger.zig", "WRONG-VALUE", "grant-ledger-single-shot",
     "BE-GRANT-01: isConsumed always false (single-shot replay gate disabled)",
     "        return self.consumedIndex(grant_id) != null;",
     "        return false; // MUTANT: single-shot replay gate disabled"),
    ("grant_ledger", "grant_ledger.zig", "WRONG-LOGIC", "grant-ledger-orphan",
     "BE-GRANT-01a: orphan detection inverted (orphans never surfaced)",
     "            if (!seen_pub) {",
     "            if (seen_pub) { // MUTANT: orphan detection inverted"),
    ("grant_ledger", "grant_ledger.zig", "CHECK-ABSENCE", "grant-ledger-at-least-once",
     "BE-GRANT-01a: orphan_len not reset, orphans do not re-emit correctly",
     "        self.published_len = 0;\n        self.orphan_len = 0;",
     "        self.published_len = 0;\n        // MUTANT: orphan_len not reset, orphans accumulate across recovers"),
    ("grant_ledger", "grant_ledger.zig", "CHECK-ABSENCE", "grant-ledger-revoke",
     "BE-REV-02: revoke row never appended (revocation not durable)",
     "        try self.appendSync(&row);\n        @memcpy(&self.revoked[self.revoked_len], &sig_pubkey);\n        self.revoked_len += 1;",
     "        // MUTANT: revoke row never appended (revocation not durable)\n        @memcpy(&self.revoked[self.revoked_len], &sig_pubkey);\n        self.revoked_len += 1;"),
    ("grant_ledger", "grant_ledger.zig", "WRONG-VALUE", "grant-ledger-prune",
     "BE-EXEC-01: expired consumed grants never pruned (all kept live)",
     "                if (expiry >= now_ms) {",
     "                if (true) { // MUTANT: expired grants never pruned"),
    ("grant_ledger", "grant_ledger.zig", "WRONG-VALUE", "grant-ledger-partial",
     "partial trailing commit row accepted as a full grant (length guard dropped)",
     "            if (tag == TAG_COMMIT and i + COMMIT_LEN <= n) {",
     "            if (tag == TAG_COMMIT) { // MUTANT: partial commit rows accepted (length guard dropped)"),
    # --- grant_revocation domain: the F4 seam (verify.zig checks 3-4 +
    # dispatch.isRevokedHook, D-064, RED-TEAM-10). Revocation consulted at the
    # grant checkpoint, where capability turns into effect. Each mutant attacks
    # one D-064 ruling and is killed by a literal binding test in
    # dispatch_test.zig (the F4 regression guard, the F4 subject guard, and the
    # F4 fail-safe test). Anchors are the exact source text.
    ("grant_revocation", "verify.zig", "CHECK-ABSENCE", "f4-approver-check",
     "F4 check 3 removed: approver revocation never consulted at the grant checkpoint",
     "    if (ctx.is_revoked(ctx.approver_cert.sig_pubkey)) return error.ApproverRevoked;",
     "    // MUTANT: F4 check 3 removed, approver revocation never consulted at the grant checkpoint"),
    ("grant_revocation", "verify.zig", "WRONG-LOGIC", "f4-approver-check",
     "F4 check 3 inverted: unrevoked approvers refused, revoked approvers accepted",
     "    if (ctx.is_revoked(ctx.approver_cert.sig_pubkey)) return error.ApproverRevoked;",
     "    if (!ctx.is_revoked(ctx.approver_cert.sig_pubkey)) return error.ApproverRevoked; // MUTANT: check 3 inverted"),
    ("grant_revocation", "verify.zig", "CHECK-ABSENCE", "f4-subject-check",
     "F4 check 4 removed: subject revocation never consulted at the grant checkpoint",
     "    if (ctx.is_revoked(ctx.subject_cert.sig_pubkey)) return error.SubjectRevoked;",
     "    // MUTANT: F4 check 4 removed, subject revocation never consulted at the grant checkpoint"),
    ("grant_revocation", "dispatch.zig", "WRONG-VALUE", "f4-failsafe",
     "F4 fail-safe flipped: no durable ledger treated as unrevoked (grants pass checks 3-4)",
     "fn isRevokedHook(sig_pubkey: []const u8) bool {\n    var lg = &(durable_ledger orelse return true);",
     "fn isRevokedHook(sig_pubkey: []const u8) bool {\n    var lg = &(durable_ledger orelse return false); // MUTANT: fail-safe flipped"),
    # --- mesh-03: store-and-forward (relay_store.zig + relay.zig wiring,
    # SPEC 5.2a clause, D-058). Quota, body cap, TTL, storage order, opacity,
    # drain rewrite, and BE-MESH-04-extended no-service for unknown indexes.
    # mesh-03 quota: the per-recipient packet bound removed. The 65th-packet
    # refusal test in relay_store_test.zig kills this.
    ("mesh", "relay_store.zig", "CHECK-ABSENCE", "mesh-03",
     "per-recipient packet quota never enforced",
     "        if (recip_count >= MAX_PER_RECIPIENT or recip_bytes + body.len > MAX_BYTES_PER_RECIPIENT) {",
     "        if (false) { // MUTANT: per-recipient quota never enforced"),
    # mesh-03 body cap: the declared 2048-byte bound removed. The oversized
    # body test kills this (the slot copy panics on the out-of-range slice).
    ("mesh", "relay_store.zig", "CHECK-ABSENCE", "mesh-03",
     "declared body cap never enforced",
     "        if (body.len > MAX_BODY) return error.BodyTooLarge;",
     "        // MUTANT: body cap never enforced"),
    # mesh-03 TTL: expiry never fires. The lazy-purge test at TTL+0 kills it.
    ("mesh", "relay_store.zig", "CHECK-ABSENCE", "mesh-03",
     "TTL purge never expires stored packets",
     "            if (now_ms >= p.stored_at_ms and now_ms - p.stored_at_ms >= TTL_MS) {",
     "            if (false) { // MUTANT: TTL never expires"),
    # mesh-03 order: drain returns newest first. The storage-order test that
    # expects the older-clock packet first kills this.
    ("mesh", "relay_store.zig", "WRONG-VALUE", "mesh-03",
     "drain serves newest first instead of storage order",
     "                if (p.stored_at_ms > self.packets[b].stored_at_ms) continue;",
     "                if (p.stored_at_ms < self.packets[b].stored_at_ms) continue; // MUTANT: newest first"),
    # mesh-03 opacity: drained body truncated. The byte-for-byte witness
    # (BE-MESH-02 opacity) kills this.
    ("mesh", "relay_store.zig", "WRONG-VALUE", "mesh-03",
     "drained body truncated (opacity broken)",
     "        const out = DrainedPacket{ .sender_index = p.sender_index, .body = p.body[0..p.body_len] };",
     "        const out = DrainedPacket{ .sender_index = p.sender_index, .body = p.body[0 .. p.body_len / 2] }; // MUTANT: body truncated"),
    # mesh-03 rewrite: drainFor stamps recipient_index with zero instead of
    # the fresh client_index. The round-trip test expecting 42 kills this.
    ("mesh", "relay.zig", "WRONG-FIELD", "mesh-03",
     "drain rewrite removed (recipient_index stamped zero)",
     "            .recipient_index = new_client_index,",
     "            .recipient_index = 0, // MUTANT: rewrite removed"),
    # mesh-03 no-service: unknown indexes silently accepted for storage,
    # breaking BE-MESH-04 extended to storage by D-058. The unknown-index
    # test expecting UnknownRecipient kills this.
    ("mesh", "relay.zig", "CHECK-ABSENCE", "mesh-03",
     "unknown indexes silently accepted for storage",
     "    return StoreDeferredError.UnknownRecipient;",
     "    // MUTANT: unknown recipients silently accepted"),

    # --- relay domain: the relay surface (src/relay.zig, SPEC §5.2a)
    # relay-route-format: field order swapped. The happy-path test asserts the
    # LITERAL sender_index 1 and recipient_index 2 from the fixed ROUTE_HEX,
    # so swapped reads fail both assertions.
    ("relay", "relay.zig", "WRONG-FIELD", "relay-route-format",
     "route sender/recipient indices read in swapped order",
     "    const sender_index = try c.u32be();\n    const recipient_index = try c.u32be();",
     "    const recipient_index = try c.u32be(); // MUTANT: field order swapped\n    const sender_index = try c.u32be(); // MUTANT"),
    # relay-route-format: timestamp endianness. The happy-path test asserts
    # the LITERAL timestamp 1000; a little-endian read of the big-endian wire
    # bytes yields a huge value and dies there.
    ("relay", "relay.zig", "WRONG-ENDIAN", "relay-route-format",
     "route timestamp read little-endian instead of big-endian",
     "    const recipient_index = try c.u32be();\n    const timestamp = try c.u64be();",
     "    const recipient_index = try c.u32be();\n    const timestamp = try c.u64le(); // MUTANT"),
    # relay-route-format: reserved check dropped. The non-zero-reserved test
    # expects Malformed; without the check the buffer parses.
    ("relay", "relay.zig", "CHECK-ABSENCE", "relay-route-format",
     "route reserved bytes never checked",
     "    if (reserved[0] != 0 or reserved[1] != 0 or reserved[2] != 0)\n        return coverage.reject(.relay_route_reserved);",
     "    _ = reserved; // MUTANT: route reserved bytes never checked"),
    # relay-reg-format: reserved check dropped. The registration
    # non-zero-reserved test expects Malformed; without the check it parses.
    ("relay", "relay.zig", "CHECK-ABSENCE", "relay-reg-format",
     "registration reserved bytes never checked",
     "    if (reserved[0] != 0 or reserved[1] != 0 or reserved[2] != 0)\n        return coverage.reject(.relay_reg_reserved);",
     "    _ = reserved; // MUTANT: registration reserved bytes never checked"),
    # relay-reg-format (sig-skip half): the tbs boundary shrunk one byte. The
    # signature covers type..expiry (44 bytes); excluding the expiry byte
    # changes what the deferred verifier would sign. The tbs test asserts the
    # LITERAL 44-byte prefix of REG_BYTES.
    ("relay", "relay.zig", "WRONG-BOUNDARY", "relay-reg-format",
     "tbs shrunk one byte (expiry excluded from the signed span)",
     "    const tbs = buf[0..(LEN_RELAY_REGISTRATION - LEN_SIG - LEN_PADDING)];",
     "    const tbs = buf[0..(LEN_RELAY_REGISTRATION - LEN_SIG - LEN_PADDING - 1)]; // MUTANT"),
    # relay-domain-tag (tag-mismatch half): the tag shifted to 0x06, which
    # BE-SIG-01 already assigns. The verification path that consumes the tag
    # is deferred (D-043), so the pin test asserts the constant against the
    # LITERAL 0x07 from the BE-SIG-01 row, the same shape vectors_test uses
    # for every domain tag.
    ("relay", "relay.zig", "WRONG-CONSTANT", "relay-domain-tag",
     "registration domain tag shifted (0x07 -> 0x06, colliding)",
     "pub const DOMAIN_RELAY_REGISTRATION: u8 = 0x07;",
     "pub const DOMAIN_RELAY_REGISTRATION: u8 = 0x06; // MUTANT"),
    # relay-unknown-dst: the recipient lookup dropped entirely. The
    # unknown-recipient test expects UnknownRecipient; without the lookup
    # every packet forwards.
    ("relay", "relay.zig", "CHECK-ABSENCE", "relay-unknown-dst",
     "recipient never looked up (every packet forwards)",
     "    for (table.entries[0..table.count]) |e| {\n        if (e.client_index == route.recipient_index) {\n            // Forward the packet unchanged. The caller sends it to the\n            // recipient's UDP endpoint (obtained from the session table).\n            return packet;\n        }\n    }\n    return ForwardError.UnknownRecipient;",
     "    _ = table; // MUTANT: recipient never looked up\n    return packet;"),
    # relay-skew: the bound shifted one second. The boundary tests forward at
    # LITERAL now-300 and expect StaleRoute at LITERAL now-301; under a 299s
    # bound the now-300 route is stale and the forward test dies.
    ("relay", "relay.zig", "WRONG-CONSTANT", "relay-skew",
     "timestamp skew bound shifted (300 -> 299)",
     "pub const TIMESTAMP_SKEW: u64 = 300; // seconds, relay-local (D-044)",
     "pub const TIMESTAMP_SKEW: u64 = 299; // MUTANT"),
    # relay-table-bound: the bound raised one entry. The table-full test
    # inserts LITERAL 4096 entries and expects the next insert refused; under
    # 4097 the 4097th insert succeeds and the refusal assertion dies.
    ("relay", "relay.zig", "WRONG-CONSTANT", "relay-table-bound",
     "table bound raised one entry (4096 -> 4097)",
     "pub const MAX_RELAY_TABLE: usize = 4096; // bounded registration table (D-044)",
     "pub const MAX_RELAY_TABLE: usize = 4097; // MUTANT"),
    # relay-expiry: the prune comparison inverted. The prune test expects the
    # expiry-100 entry gone and the expiry-200 entry present at now 150; the
    # inversion prunes the live entry instead and the lookup assertions die.
    ("relay", "relay.zig", "WRONG-LOGIC", "relay-expiry",
     "prune comparison inverted (live entries pruned, expired kept)",
     "            if (self.entries[i].expiry <= now) {",
     "            if (self.entries[i].expiry > now) { // MUTANT"),
    # relay-forward: the forwarded packet mutated. BE-MESH-02's guarantee is
    # forward-unchanged; returning a tail slice changes length and bytes, and
    # the happy-path test's LITERAL expectEqualSlices dies.
    ("relay", "relay.zig", "WRONG-LOGIC", "relay-forward",
     "forwarded packet mutated (leading byte stripped)",
     "            return packet;\n        }\n    }\n    return ForwardError.UnknownRecipient;",
     "            return packet[1..]; // MUTANT: forwarded packet mutated\n        }\n    }\n    return ForwardError.UnknownRecipient;"),
    # --- ledger domain: the ledger/history surface (src/ledger.zig,
    # src/historical.zig, src/verify.zig admission; SPEC §9, BE-ENV-03/04/05)
    # ledger-unknown-parents: the parent-resolution refusal dropped. The
    # unknown-parents test expects allParentsPresent false for hashes never
    # inserted; with the refusal gone every parent set resolves.
    ("ledger", "ledger.zig", "CHECK-ABSENCE", "ledger-unknown-parents",
     "unknown parents never rejected (resolution always succeeds)",
     "            if (!found) return false;",
     "            _ = found; // MUTANT: unknown parents never rejected"),
    # ledger-hash-only: the stored commitment zeroed. The store keeps a hash
    # that commits to nothing; the known-parents test inserts a parent and
    # resolves it by its LITERAL BLAKE2s hash, which no longer matches.
    ("ledger", "ledger.zig", "WRONG-VALUE", "ledger-hash-only",
     "stored commitment zeroed (the hash kept is not the envelope's)",
     "        if (self.envelope_count >= MAX_ENVELOPES) return error.StoreFull;\n        self.envelopes[self.envelope_count] = entry;",
     "        if (self.envelope_count >= MAX_ENVELOPES) return error.StoreFull;\n        var blank = entry;\n        blank.hash = [_]u8{0} ** HASH_BYTES; // MUTANT: stored commitment zeroed\n        self.envelopes[self.envelope_count] = blank;"),
    # ledger-grant-effect: the record is written but the count never advances.
    # Every Grant/Effect acceptance reads as an empty ledger; the recording
    # tests expect envelope_count 1 after one insert and die at 0.
    ("ledger", "ledger.zig", "WRONG-LOGIC", "ledger-grant-effect",
     "record written but the count never advances (ledger reads empty)",
     "        self.envelopes[self.envelope_count] = entry;\n        self.envelope_count += 1;",
     "        self.envelopes[self.envelope_count] = entry;\n        // MUTANT: record written but the count never advances"),
    # env-equivocation (absorb half): the second copy at one triple is
    # absorbed as a routine duplicate, exactly the behaviour BE-ENV-05
    # forbids. The divergence test expects error.Divergence and dies at void.
    ("ledger", "ledger.zig", "CHECK-ABSENCE", "env-equivocation",
     "equivocation absorbed as a routine duplicate (divergence never raised)",
     "                if (std.mem.eql(u8, &e.hash, &entry.hash)) {\n                    return; // idempotent: same hash already stored\n                } else {\n                    return error.Divergence; // different hash: equivocation\n                }",
     "                return; // MUTANT: second copy absorbed, divergence never raised"),
    # env-equivocation (inversion half): the hash comparison flipped, so an
    # identical duplicate raises Divergence and a different one is absorbed.
    # The idempotency test re-inserts the SAME entry and dies at Divergence.
    ("ledger", "ledger.zig", "WRONG-LOGIC", "env-equivocation",
     "hash comparison inverted (identical copy treated as equivocation)",
     "                if (std.mem.eql(u8, &e.hash, &entry.hash)) {",
     "                if (!std.mem.eql(u8, &e.hash, &entry.hash)) { // MUTANT: identical hash treated as equivocation"),
    # env-seq-window (accept-all half): the window verdict discarded. Every
     # seq is accepted: the duplicate and below-window tests expect
    # WindowStale and die at void.
    ("ledger", "ledger.zig", "CHECK-ABSENCE", "env-seq-window",
     "window verdict discarded (stale and duplicate seq never rejected)",
     "                const accepted = self.seq_windows[i].window.check(seq);\n                if (!accepted) return error.WindowStale; // replay or below window",
     "                _ = self.seq_windows[i].window.check(seq); // MUTANT: stale and duplicate seq never rejected"),
    # env-seq-window (strict-maximum half): the sliding window replaced by the
    # strict "greater than the highest accepted" rule BE-ENV-04 forbids. The
    # reordered-seq test accepts LITERAL 99 after 100 and dies at WindowStale.
    ("ledger", "ledger.zig", "WRONG-LOGIC", "env-seq-window",
     "sliding window replaced by the forbidden strict maximum",
     "                const accepted = self.seq_windows[i].window.check(seq);",
     "                const accepted = seq > self.seq_windows[i].window.largest; // MUTANT: strict maximum, forbidden by BE-ENV-04"),
    # hist-anchor-first-use (reposition half): a second setAnchor with a
    # different hash moves the anchor instead of diverging. BE-HIST-02 pins
    # ONE anchor per signer; the mismatch test expects Divergence, dies at
    # void.
    ("ledger", "ledger.zig", "WRONG-LOGIC", "hist-anchor-first-use",
     "anchor repositioned after first use (second hash silently adopted)",
     "                if (!std.mem.eql(u8, &self.anchors[i].anchor_hash, &anchor_hash)) {\n                    // BE-HIST-02 requires ONE anchor per pubkey; mismatch is fatal.\n                    return error.Divergence;\n                }\n                return; // idempotent",
     "                // MUTANT: the anchor follows the latest envelope, not the first.\n                self.anchors[i].anchor_hash = anchor_hash;\n                return;"),
    # hist-anchor-first-use (lookup half): getAnchor returns the first stored
    # anchor regardless of signer. The second-signer regression test stores
    # two anchors and expects each lookup to return its OWN hash; it gets the
    # index-0 hash for both and dies on the slice comparison.
    ("ledger", "ledger.zig", "WRONG-LOGIC", "hist-anchor-first-use",
     "anchor lookup ignores the signer (any anchor satisfies any pubkey)",
     "    pub fn getAnchor(self: *const Ledger, pubkey: [LEN_SIG_PUBKEY]u8) ?[HASH_BYTES]u8 {\n        var i: usize = 0;\n        while (i < self.anchor_count) : (i += 1) {\n            if (std.mem.eql(u8, &self.anchors[i].pubkey, &pubkey)) {\n                return self.anchors[i].anchor_hash;\n            }\n        }\n        return null;\n    }",
     "    pub fn getAnchor(self: *const Ledger, pubkey: [LEN_SIG_PUBKEY]u8) ?[HASH_BYTES]u8 {\n        _ = pubkey; // MUTANT: any anchored signer satisfies any lookup\n        if (self.anchor_count > 0) return self.anchors[0].anchor_hash;\n        return null;\n    }"),
    # hist-revocation-causal (reposition half): a second setRevocation with a
    # different hash moves the revocation instead of diverging. The mismatch
    # test expects Divergence and dies at void.
    ("ledger", "ledger.zig", "WRONG-LOGIC", "hist-revocation-causal",
     "revocation repositioned after the fact (second hash silently adopted)",
     "                if (!std.mem.eql(u8, &self.revocations[i].revoke_hash, &revoke_hash)) {\n                    // Inconsistent revocation: divergence.\n                    return error.Divergence;\n                }\n                return;",
     "                // MUTANT: the revocation follows the latest envelope, not the first.\n                self.revocations[i].revoke_hash = revoke_hash;\n                return;"),
    # hist-revocation-causal (reads-live half): isRevoked returns false for a
    # revoked pubkey. The revocation test dies directly; the BE-HIST-03
    # descendant-of-revocation audit test dies too, because historicalValidity
    # never reaches its DescendantOfRevocation branch.
    ("ledger", "ledger.zig", "WRONG-LOGIC", "hist-revocation-causal",
     "revoked pubkey reads live (isRevoked false on a match)",
     "            if (std.mem.eql(u8, &self.revocations[i].pubkey, &pubkey)) {\n                return true;\n            }",
     "            if (std.mem.eql(u8, &self.revocations[i].pubkey, &pubkey)) {\n                return false; // MUTANT: revoked pubkey reads live\n            }"),
    # hist-causal-interval: the descent-from-anchor check dropped in the audit
    # path. The not-descendant test stores an anchor with NO dag edge and
    # expects NotDescendantOfAnchor; without the check the audit passes it.
    ("ledger", "historical.zig", "CHECK-ABSENCE", "hist-causal-interval",
     "causal descent from the anchor never checked on audit",
     "    const anchor_hash = ctx.ledger.getAnchor(sender) orelse return error.AnchorNotFound;\n    if (!ctx.dag.isAncestor(anchor_hash, env_hash)) {\n        return error.NotDescendantOfAnchor;\n    }",
     "    if (ctx.ledger.getAnchor(sender) == null) return error.AnchorNotFound;\n    // MUTANT: causal descent from the anchor never checked"),
    # env-role-map: Grant and Refusal gated on the agent role instead of
    # approver. The Grant test calls bodyTypeAllowed with the LITERAL approver
    # role bits and dies at false.
    ("ledger", "verify.zig", "WRONG-LOGIC", "env-role-map",
     "Grant and Refusal gated on agent instead of approver",
     "        parser.channel.BODY_GRANT, parser.channel.BODY_REFUSAL => is_approver,",
     "        parser.channel.BODY_GRANT, parser.channel.BODY_REFUSAL => is_agent, // MUTANT: Grant and Refusal need agent"),

    # --- intent domain: pending-intent state machine (src/intent.zig, SPEC 8.2)
    # intent-restart-collapse (BE-GRANT-04): a fresh Table after a crash holds
    # no PENDING/EXECUTING (memory-only dead-man's switch). The restart test
    # constructs a new Table and asserts len == 0; seeding len=1 breaks it.
    ("intent", "intent.zig", "WRONG-CONSTANT", "intent-restart-collapse",
     "fresh table starts non-empty (len seeded to 1)",
     "    len: usize = 0,",
     "    len: usize = 1, // MUTANT: fresh table starts non-empty"),
    # intent-exclusivity (BE-GRANT-06): a second PENDING on a held resource is
    # refused. Removing the held-resource lookup admits a second holder.
    ("intent", "intent.zig", "CHECK-ABSENCE", "intent-exclusivity",
     "resource exclusivity dropped (second holder admitted)",
     "        if (self.findHeldByResource(intent.resource_id) != null) return error.ResourceHeld;",
     "        // MUTANT: resource exclusivity check removed"),
    # intent-tpending (BE-GRANT-06a): a PENDING older than T_pending expires.
    # Flipping >= to < inverts the sweep so nothing ever expires.
    ("intent", "intent.zig", "WRONG-LOGIC", "intent-tpending",
     "T_pending comparison inverted (nothing expires)",
     "            if (e.state == .pending and now_ms >= e.admitted_ms + T_PENDING_MS) {",
     "            if (e.state == .pending and now_ms < e.admitted_ms + T_PENDING_MS) { // MUTANT"),
    # intent-dedupe (BE-GRANT-06b): a duplicate intent_id is refused. Removing
    # the lookup admits the duplicate.
    ("intent", "intent.zig", "CHECK-ABSENCE", "intent-dedupe",
     "intent_id dedupe dropped (duplicate admitted)",
     "        if (self.findPendingByIntentId(intent.intent_id) != null) return error.DuplicateIntentId;",
     "        // MUTANT: intent_id dedupe check removed"),
    # intent-refusal-transition (BE-GRANT-09 state half): a matched Refusal
    # moves PENDING to REJECTED. Dropping the transition returns no_match, so
    # the intent_test GRANT-09 case (expects .rejected) dies.
    ("intent", "intent.zig", "WRONG-VALUE", "intent-refusal-transition",
     "refusal transition dropped (always returns no_match)",
     "        self.entries[idx].state = .rejected;\n        return .rejected;",
     "        _ = idx;\n        return .no_match; // MUTANT: transition removed"),
    # intent-terminal-rejected (BE-GRANT-10): REJECTED is terminal, so a later
    # match on the same intent_id finds nothing. Widening findPendingByIntentId
    # to also match REJECTED breaks terminality.
    ("intent", "intent.zig", "WRONG-LOGIC", "intent-terminal-rejected",
     "terminality broken (REJECTED entries still match)",
     "            if (e.state == .pending and std.mem.eql(u8, e.intent_id[0..], intent_id)) return i;",
     "            if ((e.state == .pending or e.state == .rejected) and std.mem.eql(u8, e.intent_id[0..], intent_id)) return i; // MUTANT"),

    # --- refusal domain: refusal verification (src/verify.zig, SPEC 8.5/8.1)
    # refusal-domain-tag (BE-SIG-01): the Refusal signature uses domain tag
    # 0x06. Swapping DOMAIN_REFUSAL to DOMAIN_GRANT breaks signature verify.
    ("refusal", "verify.zig", "WRONG-CONSTANT", "refusal-domain-tag",
     "refusal domain tag swapped (DOMAIN_REFUSAL -> DOMAIN_GRANT)",
     "    try verifySigned(parser.channel.DOMAIN_REFUSAL, refusal.tbs, refusal.sig, env.sender);",
     "    try verifySigned(parser.channel.DOMAIN_GRANT, refusal.tbs, refusal.sig, env.sender); // MUTANT"),
    # refusal-approver-role (BE-ID-04): a Refusal needs the approver role.
    # Swapping ROLE_APPROVER to ROLE_AGENT admits a non-approver.
    ("refusal", "verify.zig", "WRONG-CONSTANT", "refusal-approver-role",
     "approver role swapped (ROLE_APPROVER -> ROLE_AGENT)",
     "    if ((ctx.approver_cert.role_bits & binding.ROLE_APPROVER) == 0) return error.BadApproverCert;",
     "    if ((ctx.approver_cert.role_bits & binding.ROLE_AGENT) == 0) return error.BadApproverCert; // MUTANT"),
    # refusal-apply-hook (BE-GRANT-09 verify half): applyRefusal runs the state
    # transition; skipping it leaves the intent PENDING so on_rejected never
    # fires and the verify_test GRANT-09 case dies.
    ("refusal", "verify.zig", "WRONG-LOGIC", "refusal-apply-hook",
     "applyRefusal hook skipped (intent never transitions)",
     "    if (ctx.intent_table.applyRefusal(refusal) == .rejected) {\n        on_rejected(refusal.intent_id);\n    }",
     "    _ = ctx.intent_table; // MUTANT: applyRefusal + on_rejected skipped"),

    # --- resolver domain: canonical resource resolution (src/resolver.zig, SPEC 8.4)
    # resolver-fp-window (BE-RES-06): the fingerprint is the FIRST 8 bytes of
    # the BLAKE2s-256 digest. Shifting the window by one byte changes every
    # hex char and dies on the known-vector test.
    ("resolver", "resolver.zig", "WRONG-CONSTANT", "resolver-fp-blake2s",
     "fingerprint digest window shifted by one byte",
     "    for (digest[0..FP_BYTES], 0..) |b, i| {",
     "    for (digest[1 .. FP_BYTES + 1], 0..) |b, i| { // MUTANT: window shifted"),
    # resolver-fp-hex (BE-RES-06): the fingerprint renders as 16 LOWERCASE hex
    # chars. Uppercasing the table breaks the vector and the class check.
    ("resolver", "resolver.zig", "WRONG-CONSTANT", "resolver-fp-blake2s",
     "fingerprint rendered uppercase",
     "    const hex = \"0123456789abcdef\";",
     "    const hex = \"0123456789ABCDEF\"; // MUTANT: uppercase hex rendering"),
    # resolver-grammar-dots (section 8.4 grammar, canonical form for
    # BE-RES-01): path segments "." and ".." are forbidden. Dropping the dot
    # rule admits the malformed declarations the grammar test refuses.
    ("resolver", "resolver.zig", "WRONG-LOGIC", "resolver-canonical",
     "dot segments accepted in the path grammar",
     "fn segLenInvalid(seg_len: usize, dots: usize) bool {\n    return seg_len == 0 or (dots == seg_len and seg_len <= 2);\n}",
     "fn segLenInvalid(seg_len: usize, dots: usize) bool {\n    _ = dots;\n    return seg_len == 0; // MUTANT: dot segments accepted\n}"),
    # resolver-return-proposal (BE-RES-01): resolve must return the executor's
    # canonical form. Returning the requester's proposal defeats every
    # downstream consumer (lock, Grant, rendering, ledger).
    ("resolver", "resolver.zig", "WRONG-VALUE", "resolver-canonical",
     "resolve returns the proposed spelling, not the canonical",
     "        return c;\n    }",
     "        return proposed; // MUTANT: requester's spelling, not the canonical\n    }"),
    # resolver-unknown-first (BE-RES-02): zero matches refuse. Resolving to
    # the first entry instead creates the create-on-first-use path the marker
    # forbids.
    ("resolver", "resolver.zig", "WRONG-LOGIC", "resolver-unknown-refuse",
     "unknown resource resolves to the first entry instead of refusing",
     "        const idx = found orelse return error.UnknownResource;",
     "        const idx = found orelse 0; // MUTANT: unknown resolves to first entry"),
    # resolver-ambiguity-dropped (BE-RES-02): ambiguous matches refuse.
    # Removing the distinct-entry check lets one spelling reach two resources.
    ("resolver", "resolver.zig", "CHECK-ABSENCE", "resolver-unknown-refuse",
     "ambiguity check removed (first match wins)",
     "                if (found) |f| if (f != i) return error.AmbiguousResource;",
     "                // MUTANT: ambiguity check removed, first match wins"),
    # resolver-foreign-fp (BE-RES-04): an executor refuses any canonical that
    # does not carry its own fingerprint. Removing the gate admits foreign
    # namespaces.
    ("resolver", "resolver.zig", "CHECK-ABSENCE", "resolver-own-executor",
     "foreign-fingerprint gate removed",
     "        if (!std.mem.eql(u8, c[4 .. 4 + FP_HEX_LEN], &self.own_fp)) return error.ForeignExecutor;",
     "        // MUTANT: foreign-fingerprint check removed"),
    # resolver-alias-entry (BE-RES-03): an alias maps to exactly one canonical
    # entry. Inverting the entry match sends aliases to the wrong resource,
    # breaking collapse into the lock.
    ("resolver", "resolver.zig", "WRONG-LOGIC", "resolver-alias-collapse",
     "alias matched against the wrong entry",
     "            if (a.entry == entry_idx and a.len == proposed.len and",
     "            if (a.entry != entry_idx and a.len == proposed.len and // MUTANT"),
    # resolver-verify-skipped (BE-RES-05): the published set's signature must
    # verify. Accepting any signature defeats the signed-state obligation.
    ("resolver", "resolver.zig", "CHECK-ABSENCE", "resolver-signed-set",
     "signature accepted without verification",
     "        const signature = Ed.Signature.fromBytes(sig);\n        var v = signature.verifier(pubkey) catch return false;\n        v.update(scratch[0 .. 1 + n]);\n        v.verify() catch return false;\n        return true;",
     "        const signature = Ed.Signature.fromBytes(sig);\n        _ = signature;\n        _ = pubkey;\n        _ = n;\n        return true; // MUTANT: signature accepted without verification"),
    # resolver-encoding-endian (BE-RES-05, SPEC v0.3.2-draft encoding clause):
    # the serialization's u16 lengths are big-endian, the repo convention.
    # Little-endian breaks the literal encoding witness.
    ("resolver", "resolver.zig", "WRONG-CONSTANT", "resolver-signed-set",
     "canonical length written little-endian",
     "            std.mem.writeInt(u16, out[pos..][0..2], @intCast(e.len), .big);",
     "            std.mem.writeInt(u16, out[pos..][0..2], @intCast(e.len), .little); // MUTANT: little-endian length"),
    # render-digest-source (BE-GRANT-07): the view's digest must be
    # recomputed from exactly the action bytes displayed. Digesting the
    # resource id instead breaks the grant-binding agreement witness.
    ("render", "render.zig", "WRONG-VALUE", "render-approve-bytes",
     "digest computed from the resource id, not the action",
     "        .action_digest = verify.actionDigest(action),",
     "        .action_digest = verify.actionDigest(canonical_resource_id), // MUTANT: digest of the id, not the action"),
    # render-digest-zero (BE-GRANT-07): pinning the digest to zero skips
    # recomputation entirely; the literal digest witness fails.
    ("render", "render.zig", "WRONG-VALUE", "render-approve-bytes",
     "digest pinned to zero, never recomputed",
     "        .action_digest = verify.actionDigest(action),",
     "        .action_digest = [_]u8{0} ** 32, // MUTANT: zero digest, never recomputed"),
    # render-action-truncated (BE-GRANT-07): the view must carry the FULL
    # action bytes; truncation is a summary, forbidden by the marker.
    ("render", "render.zig", "WRONG-VALUE", "render-approve-bytes",
     "action truncated to half (a summary, not the full bytes)",
     "        .action = action,",
     "        .action = action[0 .. action.len / 2], // MUTANT: truncated action"),
    # render-label-trusted (BE-GRANT-07a): displayed rationale must carry
    # the untrusted label; flipping it to trusted defeats the marking.
    ("render", "render.zig", "WRONG-VALUE", "render-rationale-untrusted",
     "rationale label flipped to trusted",
     "    untrusted_label: []const u8 = RATIONALE_UNTRUSTED_LABEL,",
     "    untrusted_label: []const u8 = \"trusted, verified\", // MUTANT: rationale marked trusted"),
    # render-rationale-first (BE-GRANT-07a): rationale must stay visually
    # subordinate; moving it ahead of the primary content breaks the order
    # witness.
    ("render", "render.zig", "WRONG-LOGIC", "render-rationale-untrusted",
     "rationale field moved before the primary content",
     "pub const ApprovalView = struct {\n    resource_id: []const u8, // canonical form, resolved by the executor (section 8.4)\n    action: []const u8, // full action bytes, never a summary\n    action_digest: [channel.LEN_ACTION_DIGEST]u8, // recomputed over `action`\n    rationale: ?Rationale = null, // null = not displayed at all\n};",
     "pub const ApprovalView = struct {\n    rationale: ?Rationale = null, // MUTANT: rationale first, dominant\n    resource_id: []const u8,\n    action: []const u8,\n    action_digest: [channel.LEN_ACTION_DIGEST]u8,\n};"),
    # render-primary-optional (BE-GRANT-07a): primary content must never be
    # optional, or rationale could stand alone on screen.
    ("render", "render.zig", "CHECK-ABSENCE", "render-rationale-untrusted",
     "primary content made optional (rationale can stand alone)",
     "    resource_id: []const u8, // canonical form, resolved by the executor (section 8.4)",
     "    resource_id: ?[]const u8 = null, // MUTANT: primary content optional"),

    # --- sync domain: backfill surface (SPEC 6.4, BE-SYNC-01..05, D-054) ---
    # sync-admission (BE-SYNC-01): SyncRequest is refused outside an
    # established session. Dropping the precondition admits unauthenticated
    # peers; the literal test's NoSession witness dies.
    ("sync", "sync.zig", "CHECK-ABSENCE", "sync-admission",
     "session precondition removed (SyncRequest admitted with no session)",
     "    if (!session_established) return SyncError.NoSession;",
     "    _ = session_established; // MUTANT: session precondition removed"),
    # sync-admission (BE-SYNC-01): the peer must carry the channel's member
    # group and must not be revoked. Removing requireMember admits outsiders
    # and revoked peers alike; both refusal witnesses die.
    ("sync", "sync.zig", "CHECK-ABSENCE", "sync-admission",
     "membership precondition removed (outsiders and revoked peers admitted)",
     "    verify.requireMember(sender_cert, genesis, ctx) catch |err| switch (err) {\n        error.SubjectRevoked => return SyncError.Revoked,\n        error.NotMember => return SyncError.NotMember,\n        // requireMember's error set is ChannelError but its body returns only\n        // these two; the remaining arms are unreachable by construction.\n        else => return SyncError.NotMember,\n    };",
     "    _ = sender_cert;\n    _ = genesis;\n    _ = ctx; // MUTANT: membership precondition removed"),
    # sync-bounds (BE-SYNC-02): the responder ceiling is 64 envelopes.
    # Off-by-one serves a 65th; the count-cap witness dies.
    ("sync", "sync.zig", "WRONG-CONSTANT", "sync-bounds",
     "responder ceiling off by one (64 -> 65)",
     "pub const MAX_RESPONSE_ENVELOPES: usize = 64; // BE-SYNC-02 responder ceiling",
     "pub const MAX_RESPONSE_ENVELOPES: usize = 65; // MUTANT: ceiling off by one"),
    # sync-bounds (BE-SYNC-02): a response is capped at 1 MiB. Doubling the
    # cap admits the 16th 65536-byte envelope; the byte-cap witness dies.
    ("sync", "sync.zig", "WRONG-CONSTANT", "sync-bounds",
     "byte cap doubled (1 MiB -> 2 MiB)",
     "pub const MAX_RESPONSE_BYTES: usize = 1 << 20; // BE-SYNC-02: 1 MiB per response",
     "pub const MAX_RESPONSE_BYTES: usize = 1 << 21; // MUTANT: byte cap doubled"),
    # sync-bounds (BE-SYNC-02): the truncated flag is serialized from the
    # builder's verdict. Pinning it to zero hides every continuation; the
    # wire-byte witnesses die.
    ("sync", "sync.zig", "WRONG-VALUE", "sync-bounds",
     "truncated flag pinned to zero on the wire",
     "    out[pos] = @intFromBool(truncated);",
     "    out[pos] = 0; // MUTANT: truncated pinned to zero"),
    # sync-bounds (BE-SYNC-02, §6.4 grammar): have_hashes carries at most 64
    # entries; the ceiling itself parses. Flipping > to >= refuses a full
    # have set; the ceiling witness dies.
    ("sync", "parser/sync.zig", "WRONG-LOGIC", "sync-bounds",
     "have-set bound flipped at the ceiling (64 refused)",
     "    if (have_count > MAX_HAVE) return coverage.reject(.sync_req_have_oversize);",
     "    if (have_count >= MAX_HAVE) return coverage.reject(.sync_req_have_oversize); // MUTANT: ceiling refused"),
    # sync-walk (BE-SYNC-03): the queue depth is capped at 128. Flipping the
    # comparison admits a 129th pending hash; the depth witness dies.
    ("sync", "sync.zig", "WRONG-LOGIC", "sync-walk",
     "depth comparison flipped (129 pending admitted)",
     "        if (self.depth >= WALK_MAX_DEPTH) {",
     "        if (self.depth > WALK_MAX_DEPTH) { // MUTANT: depth bound off by one"),
    # sync-walk (BE-SYNC-03): the walk examines at most 4096 envelopes.
    # Flipping the comparison admits a 4097th; the total witness dies.
    ("sync", "sync.zig", "WRONG-LOGIC", "sync-walk",
     "total comparison flipped (4097 examinations admitted)",
     "        if (self.examined >= WALK_MAX_TOTAL) {",
     "        if (self.examined > WALK_MAX_TOTAL) { // MUTANT: total bound off by one"),
    # sync-walk (BE-SYNC-03): on exhaustion the walk stops; nothing drains,
    # nothing retries. Removing the pop guard lets the exhausted queue keep
    # handing out hashes; the stop witness dies.
    ("sync", "sync.zig", "CHECK-ABSENCE", "sync-walk",
     "retry-on-exhaustion reintroduced (exhausted queue keeps draining)",
     "        if (self.exhausted or self.depth == 0) return null;",
     "        if (self.depth == 0) return null; // MUTANT: exhausted walk keeps draining"),
    # sync-rate (BE-SYNC-04): a peer's budget admits exactly `budget` events
    # per window. Widening the comparison admits one extra; the 9th-serve
    # witness dies.
    ("sync", "sync.zig", "WRONG-LOGIC", "sync-rate",
     "rate budget admits one extra (8 -> 9 serves)",
     "        if (inside >= self.budget) return false;",
     "        if (inside > self.budget) return false; // MUTANT: budget admits one extra"),
    # sync-rate (BE-SYNC-04): the sliding window is half-open; an event
    # exactly window_ms old has expired. Making the edge inclusive freezes
    # the window; the slide witness dies.
    ("sync", "sync.zig", "WRONG-LOGIC", "sync-rate",
     "window edge made inclusive (the window never slides)",
     "            if (s != 0 and now_ms >= s and now_ms - s < window_ms) inside += 1;",
     "            if (s != 0 and now_ms >= s and now_ms - s <= window_ms) inside += 1; // MUTANT: window edge inclusive"),
    # sync-adopt (BE-SYNC-05): a backfilled envelope passes the live
    # signature check before ledger entry. Skipping verifyEnvelope admits any
    # signature; the tampered-sig witness dies.
    ("sync", "sync.zig", "CHECK-ABSENCE", "sync-adopt",
     "verify-before-adopt skipped (any signature admitted)",
     "    verify.verifyEnvelope(env) catch return SyncError.BadEnvelope;",
     "    _ = env; // MUTANT: signature verification skipped"),
    # --- daemon domain: the listener + handshake surface (src/listener.zig,
    # src/handshake.zig, SPEC §0.4) ---
    # daemon-exec-02 (BE-EXEC-02): registry ownership check removed. The
    # registry test expecting EndpointBusy on the second claim kills this.
    ("daemon", "listener.zig", "CHECK-ABSENCE", "daemon-exec-02",
     "endpoint ownership never checked (double claim accepted)",
     "        if (self.owns(addr, port)) return error.EndpointBusy;",
     "        // MUTANT: endpoint ownership never checked"),
    # daemon-exec-02: OS bind refusal ignored. The OS-level duplicate-bind
    # test expecting BindRefused kills this.
    ("daemon", "listener.zig", "CHECK-ABSENCE", "daemon-exec-02",
     "OS bind refusal ignored (duplicate endpoint silently bound)",
     "        if (libc.bind(self.fd, &sa, sa_len) != 0) {",
     "        if (false) { // MUTANT: OS bind refusal ignored"),
    # daemon-exec-03 (BE-EXEC-03): family length gate removed. The
    # wrong-family test expecting FamilyMismatch kills this.
    ("daemon", "listener.zig", "CHECK-ABSENCE", "daemon-exec-03",
     "address family length gate removed",
     "        if (addr.len != want_len) return error.FamilyMismatch;",
     "        // MUTANT: address family length gate removed"),
    # daemon-exec-03: the socket in open() is created with the ipv6 family
    # for an ipv4 listener. The getsockname family witness (the created
    # socket must carry exactly the declared family) kills this. The
    # sockaddr family byte in makeSockaddr is not the target: macOS bind
    # ignores it, which makes it an equivalent mutant.
    ("daemon", "listener.zig", "WRONG-VALUE", "daemon-exec-03",
     "ipv4 listener socket created with the ipv6 address family",
     "            .ipv4 => AF_INET,",
     "            .ipv4 => AF_INET6, // MUTANT: wrong address family"),
    # daemon-sess-02 (BE-SESS-02): the type/size gate removed. Truncated and
    # wrong-type datagrams then reach the Noise layer; both witnesses die.
    ("daemon", "handshake.zig", "CHECK-ABSENCE", "daemon-sess-02",
     "initiation type/size gate removed",
     "        if (datagram.len < noise.MSG1_SIZE or datagram[0] != 1) return error.NotInitiation;",
     "        // MUTANT: initiation type/size gate removed"),
    # daemon-sess-02: handshake failure swallowed, processing continues with
    # broken state. The tampered-mac1 test expecting Refused kills this.
    ("daemon", "handshake.zig", "CHECK-ABSENCE", "daemon-sess-02",
     "handshake failure swallowed (half-session proceeds)",
     "        responder.readInitiation(datagram[0..noise.MSG1_SIZE], self.responder_sig_pubkey) catch return error.Refused;",
     "        responder.readInitiation(datagram[0..noise.MSG1_SIZE], self.responder_sig_pubkey) catch {}; // MUTANT: failure swallowed"),
    # daemon-sess-02: committed session swaps send/recv keys. The success
    # test asserting the key-agreement direction kills this.
    ("daemon", "handshake.zig", "WRONG-FIELD", "daemon-sess-02",
     "committed session swaps send and recv keys",
     "            .send_key = result.send_key,",
     "            .send_key = result.recv_key, // MUTANT: send/recv swapped"),
    # --- relay_serve domain: the serve-loop (src/relay_serve.zig, SPEC
    # section 0.4 BE-EXEC-04, D-060). Six mutants over the five BE-EXEC-04
    # sub-obligations; the decision-table split gets two (forward + store).
    # relay-serve-classify (BE-EXEC-04): the default arm drops unknown type
    # bytes with no service. The classifier test sending a junk type and
    # asserting .dropped kills this.
    ("relay_serve", "relay_serve.zig", "CHECK-ABSENCE", "relay-serve-classify",
     "unknown type byte served instead of dropped",
     "            else => self.drop(),",
     "            else => return .forwarded, // MUTANT: unknown type served"),
    # relay-serve-sender-gate (BE-EXEC-04): the sender_index session gate
     # removed. The sender-gate test forwarding without an established
     # session and asserting .dropped kills this.
    ("relay_serve", "relay_serve.zig", "CHECK-ABSENCE", "relay-serve-sender-gate",
     "sender session gate removed (type 5 forwarded without a session)",
     "        if (route.sender_index >= self.sessions.session_count) return self.drop();",
     "        // MUTANT: sender session gate removed"),
    # relay-serve-decision (BE-EXEC-04 + section 5.2a): live delivery arm
     # removed, so a registered endpoint's packet is stored instead of
     # forwarded. The T1 forward-live test asserting .forwarded kills this.
    ("relay_serve", "relay_serve.zig", "CHECK-ABSENCE", "relay-serve-decision",
     "live delivery arm removed (known endpoint stored instead of forwarded)",
     "        if (self.endpoints.get(route.recipient_index)) |ep| {",
     "        if (false) { // MUTANT: live delivery arm removed"),
    # relay-serve-decision (BE-EXEC-04 + section 5.2a): deferred storage
     # removed, so a known-but-offline recipient gets no service instead of
     # storage. The T2 store half asserting .stored kills this.
    ("relay_serve", "relay_serve.zig", "CHECK-ABSENCE", "relay-serve-decision",
     "deferred storage removed (offline recipient gets no service)",
     "        relay.storeDeferred(self.table, self.store, route, dgram[relay.LEN_RELAY_ROUTE..], now_ms) catch return self.drop();",
     "        return self.drop(); // MUTANT: deferred storage removed"),
    # relay-serve-drain (BE-EXEC-04): the registration drain zeroed, so
     # stored packets are never delivered at late registration. The T2 drain
     # half asserting .drained kills this.
    ("relay_serve", "relay_serve.zig", "WRONG-VALUE", "relay-serve-drain",
     "registration drain zeroed (stored packets never delivered)",
     "        const n = relay.drainFor(self.store, derived, reg.client_index, now_ms, &out);",
     "        const n: usize = 0; // MUTANT: drain zeroed"),
    # relay-serve-opacity (BE-EXEC-04 + BE-MESH-02): the forwarded body
     # truncated by one byte. The T1 forward-live test asserting the body
     # arrives byte-for-byte kills this.
    ("relay_serve", "relay_serve.zig", "WRONG-VALUE", "relay-serve-opacity",
     "forwarded ciphertext body truncated by one byte",
     "            if (sendto(self.fd, dgram.ptr, dgram.len, 0, &ep.sa, ep.sa_len) != want) return self.drop();",
     "            if (sendto(self.fd, dgram.ptr, dgram.len - 1, 0, &ep.sa, ep.sa_len) != want) return self.drop(); // MUTANT: body truncated"),
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
    relay_props = relay_properties_from_spec()
    if not relay_props:
        sys.exit("FATAL: no relay properties detected in SPEC §5.2a/BE-SIG-01")
    ledger_props = ledger_properties_from_spec()
    if not ledger_props:
        sys.exit("FATAL: no ledger properties detected in SPEC §9/BE-ENV-03/04/05")
    intent_props = intent_properties_from_spec()
    if not intent_props:
        sys.exit("FATAL: no intent properties detected in SPEC section 8")
    refusal_props = refusal_properties_from_spec()
    if not refusal_props:
        sys.exit("FATAL: no refusal properties detected in SPEC section 8.5/8.1")
    resolver_props = resolver_properties_from_spec()
    if not resolver_props:
        sys.exit("FATAL: no resolver properties detected in SPEC section 8.4")

    render_props = render_properties_from_spec()
    if not render_props:
        sys.exit("FATAL: no render properties detected in SPEC section 8.3")
    sync_props = sync_properties_from_spec()
    if not sync_props:
        sys.exit("FATAL: no sync properties detected in SPEC section 6.4")
    dispatch_props = dispatch_properties()
    if not dispatch_props:
        sys.exit("FATAL: no dispatch properties detected (D-059 missing?)")
    daemon_props = daemon_properties_from_spec()
    if not daemon_props:
        sys.exit("FATAL: no daemon properties detected (SPEC section 0.4 missing?)")
    relay_serve_props = relay_serve_properties()
    if not relay_serve_props:
        sys.exit("FATAL: no relay_serve properties detected (D-060 missing?)")
    grant_ledger_props = grant_ledger_properties()
    if not grant_ledger_props:
        sys.exit("FATAL: no grant_ledger properties detected (D-061 missing?)")
    grant_revocation_props = grant_revocation_properties()
    if not grant_revocation_props:
        sys.exit("FATAL: no grant_revocation properties detected (D-064 missing?)")

    print("denominators derived from SPEC.md (not self-counted):")
    print(f"  BE-GRANT-03 enumerated checks: {enumerated} ({len(enumerated)})")
    print(f"  grant modelled by this slice:  {sorted(modelled)} ({len(modelled)})")
    print(f"  BE-GRANT-03b callback:         call-boundary property modelled")
    print(f"  section-7 evidence properties: {sorted(evidence_props)} ({len(evidence_props)})")
    print(f"  section-4 transport properties: {sorted(transport_props)} ({len(transport_props)})")
    print(f"  session-phase properties:        {sorted(session_props)} ({len(session_props)})")
    print(f"  section-6 channel properties:    {sorted(channel_props)} ({len(channel_props)})")
    print(f"  section-5 mesh properties:       {sorted(mesh_props)} ({len(mesh_props)})")
    print(f"  relay properties (§5.2a):        {sorted(relay_props)} ({len(relay_props)})")
    print(f"  ledger properties (§9):          {sorted(ledger_props)} ({len(ledger_props)})")
    print(f"  intent properties (§8.2):        {sorted(intent_props)} ({len(intent_props)})")
    print(f"  refusal properties (§8.5):       {sorted(refusal_props)} ({len(refusal_props)})")
    print(f"  resolver properties (§8.4):      {sorted(resolver_props)} ({len(resolver_props)})")
    print(f"  daemon properties (§0.4):        {sorted(daemon_props)} ({len(daemon_props)})")
    print(f"  relay_serve properties (BE-EXEC-04): {sorted(relay_serve_props)} ({len(relay_serve_props)})")
    print(f"  dispatch properties (D-059):     {sorted(dispatch_props)} ({len(dispatch_props)})")
    print(f"  grant_ledger properties (D-061): {sorted(grant_ledger_props)} ({len(grant_ledger_props)})")
    print(f"  grant_revocation properties (D-064): {sorted(grant_revocation_props)} ({len(grant_revocation_props)})")
    print(f"  render properties (§8.3):        {sorted(render_props)} ({len(render_props)})")
    print(f"  sync properties (§6.4):          {sorted(sync_props)} ({len(sync_props)})")
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
        elif domain == "relay_serve":
            if key not in relay_serve_props:
                sys.exit(f"FATAL: relay_serve mutant '{name}' attacks '{key}', which "
                         "BE-EXEC-04 (section 0.4) does not declare (scope lie)")
        elif domain == "dispatch":
            if key not in dispatch_props:
                sys.exit(f"FATAL: dispatch mutant '{name}' attacks '{key}', which "
                         "the D-059 ruling does not record (scope lie)")
        elif domain == "grant_ledger":
            if key not in grant_ledger_props:
                sys.exit(f"FATAL: grant_ledger mutant '{name}' attacks '{key}', which "
                         "the D-061 ruling does not record (scope lie)")
        elif domain == "grant_revocation":
            if key not in grant_revocation_props:
                sys.exit(f"FATAL: grant_revocation mutant '{name}' attacks '{key}', which "
                         "the D-064 ruling does not record (scope lie)")
        elif domain == "daemon":
            if key not in daemon_props:
                sys.exit(f"FATAL: daemon mutant '{name}' attacks '{key}', which "
                         "section 0.4 of SPEC does not declare (scope lie)")
        elif domain == "relay":
            if key not in relay_props:
                sys.exit(f"FATAL: relay mutant '{name}' attacks '{key}', which "
                         "SPEC §5.2a/BE-SIG-01 does not declare (scope lie)")
        elif domain == "ledger":
            if key not in ledger_props:
                sys.exit(f"FATAL: ledger mutant '{name}' attacks '{key}', which "
                         "SPEC §9/BE-ENV-03/04/05 does not declare (scope lie)")
        elif domain == "intent":
            if key not in intent_props:
                sys.exit(f"FATAL: intent mutant '{name}' attacks '{key}', which "
                         "SPEC section 8 does not declare (scope lie)")
        elif domain == "refusal":
            if key not in refusal_props:
                sys.exit(f"FATAL: refusal mutant '{name}' attacks '{key}', which "
                         "SPEC section 8.5/8.1 does not declare (scope lie)")
        elif domain == "resolver":
            if key not in resolver_props:
                sys.exit(f"FATAL: resolver mutant '{name}' attacks '{key}', which "
                         "SPEC section 8.4 does not declare (scope lie)")
        elif domain == "render":
            if key not in render_props:
                sys.exit(f"FATAL: render mutant '{name}' attacks '{key}', which "
                         "SPEC section 8.3 does not declare (scope lie)")
        elif domain == "sync":
            if key not in sync_props:
                sys.exit(f"FATAL: sync mutant '{name}' attacks '{key}', which "
                         "SPEC section 6.4 does not declare (scope lie)")
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
    dp_run, dp_surv, dp_uncov, _ = gate_domain("dispatch", dispatch_props)
    if in_scope("dispatch"):
        dp_cov = {r["key"] for r in dp_run if r["killed"]}
        print(f"dispatch: {len(dp_cov)}/{len(dispatch_props)} D-059 "
              f"properties covered by killed mutants")
    dmn_run, dmn_surv, dmn_uncov, _ = gate_domain("daemon", daemon_props)
    if in_scope("daemon"):
        dmn_cov = {r["key"] for r in dmn_run if r["killed"]}
        print(f"daemon:   {len(dmn_cov)}/{len(daemon_props)} §0.4 "
              f"properties covered by killed mutants")
    rs_run, rs_surv, rs_uncov, _ = gate_domain("relay_serve", relay_serve_props)
    if in_scope("relay_serve"):
        rs_cov = {r["key"] for r in rs_run if r["killed"]}
        print(f"relay_serve: {len(rs_cov)}/{len(relay_serve_props)} BE-EXEC-04 "
              f"properties covered by killed mutants")
    gl_run, gl_surv, gl_uncov, _ = gate_domain("grant_ledger", grant_ledger_props)
    if in_scope("grant_ledger"):
        gl_cov = {r["key"] for r in gl_run if r["killed"]}
        print(f"grant_ledger: {len(gl_cov)}/{len(grant_ledger_props)} D-061 "
              f"properties covered by killed mutants")
    gr_run, gr_surv, gr_uncov, _ = gate_domain("grant_revocation", grant_revocation_props)
    if in_scope("grant_revocation"):
        gr_cov = {r["key"] for r in gr_run if r["killed"]}
        print(f"grant_revocation: {len(gr_cov)}/{len(grant_revocation_props)} D-064 "
              f"properties covered by killed mutants")
    r_run, r_surv, r_uncov, _ = gate_domain("relay", relay_props)
    if in_scope("relay"):
        r_cov = {r["key"] for r in r_run if r["killed"]}
        print(f"relay:    {len(r_cov)}/{len(relay_props)} §5.2a "
              f"properties covered by killed mutants")
    l_run, l_surv, l_uncov, _ = gate_domain("ledger", ledger_props)
    if in_scope("ledger"):
        l_cov = {r["key"] for r in l_run if r["killed"]}
        print(f"ledger:   {len(l_cov)}/{len(ledger_props)} §9/BE-ENV "
              f"properties covered by killed mutants")
    i_run, i_surv, i_uncov, _ = gate_domain("intent", intent_props)
    if in_scope("intent"):
        i_cov = {r["key"] for r in i_run if r["killed"]}
        print(f"intent:   {len(i_cov)}/{len(intent_props)} §8.2 "
              f"properties covered by killed mutants")
    f_run, f_surv, f_uncov, _ = gate_domain("refusal", refusal_props)
    if in_scope("refusal"):
        f_cov = {r["key"] for r in f_run if r["killed"]}
        print(f"refusal:  {len(f_cov)}/{len(refusal_props)} §8.5 "
              f"properties covered by killed mutants")
    v_run, v_surv, v_uncov, _ = gate_domain("resolver", resolver_props)
    if in_scope("resolver"):
        v_cov = {r["key"] for r in v_run if r["killed"]}
        print(f"resolver: {len(v_cov)}/{len(resolver_props)} §8.4 "
              f"properties covered by killed mutants")
    w_run, w_surv, w_uncov, _ = gate_domain("render", render_props)
    if in_scope("render"):
        w_cov = {r["key"] for r in w_run if r["killed"]}
        print(f"render:   {len(w_cov)}/{len(render_props)} §8.3 "
              f"properties covered by killed mutants")
    x_run, x_surv, x_uncov, _ = gate_domain("sync", sync_props)
    if in_scope("sync"):
        x_cov = {r["key"] for r in x_run if r["killed"]}
        print(f"sync:     {len(x_cov)}/{len(sync_props)} §6.4 "
              f"properties covered by killed mutants")
    total_run = [r for r in results if not r["skipped"]]
    total_killed = sum(1 for r in total_run if r["killed"])
    print(f"total:   {total_killed}/{len(total_run)} mutants killed, "
          f"{len(g_surv) + len(e_surv) + len(t_surv) + len(s_surv) + len(c_surv) + len(m_surv) + len(r_surv) + len(l_surv) + len(i_surv) + len(f_surv) + len(v_surv) + len(w_surv) + len(dp_surv) + len(dmn_surv) + len(rs_surv) + len(gr_surv)}"
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
    if r_surv:
        print(f"  relay SURVIVORS: {r_surv}")
    if l_surv:
        print(f"  ledger SURVIVORS: {l_surv}")
    if i_surv:
        print(f"  intent SURVIVORS: {i_surv}")
    if f_surv:
        print(f"  refusal SURVIVORS: {f_surv}")
    if v_surv:
        print(f"  resolver SURVIVORS: {v_surv}")
    if w_surv:
        print(f"  render SURVIVORS: {w_surv}")
    if x_surv:
        print(f"  sync SURVIVORS: {x_surv}")
    if dp_surv:
        print(f"  dispatch SURVIVORS: {dp_surv}")
    if dmn_surv:
        print(f"  daemon SURVIVORS: {dmn_surv}")
    if rs_surv:
        print(f"  relay_serve SURVIVORS: {rs_surv}")
    if gr_surv:
        print(f"  grant_revocation SURVIVORS: {gr_surv}")
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
    if r_uncov:
        print(f"  UNCOVERED relay properties: {r_uncov}")
    if l_uncov:
        print(f"  UNCOVERED ledger properties: {l_uncov}")
    if i_uncov:
        print(f"  UNCOVERED intent properties: {i_uncov}")
    if f_uncov:
        print(f"  UNCOVERED refusal properties: {f_uncov}")
    if v_uncov:
        print(f"  UNCOVERED resolver properties: {v_uncov}")
    if w_uncov:
        print(f"  UNCOVERED render properties: {w_uncov}")
    if x_uncov:
        print(f"  UNCOVERED sync properties: {x_uncov}")
    if dp_uncov:
        print(f"  UNCOVERED dispatch properties: {dp_uncov}")
    if dmn_uncov:
        print(f"  UNCOVERED daemon properties: {dmn_uncov}")
    if rs_uncov:
        print(f"  UNCOVERED relay_serve properties: {rs_uncov}")
    if gl_uncov:
        print(f"  UNCOVERED grant_ledger properties: {gl_uncov}")
    if gr_uncov:
        print(f"  UNCOVERED grant_revocation properties: {gr_uncov}")
    if not g_cb:
        print("  UNCOVERED: BE-GRANT-03b callback property")

    ok = ((not g_surv) and (not e_surv) and (not t_surv) and (not s_surv)
          and (not c_surv) and (not m_surv) and (not r_surv) and (not l_surv)
          and (not i_surv) and (not f_surv) and (not v_surv) and (not w_surv)
          and (not x_surv)
          and (not g_uncov) and (not e_uncov) and (not t_uncov)
          and (not s_uncov) and (not c_uncov) and (not m_uncov)
          and (not r_uncov) and (not l_uncov)
          and (not i_uncov) and (not f_uncov) and (not v_uncov)
          and (not w_uncov) and (not x_uncov)
          and (not dp_surv) and (not dp_uncov)
          and (not dmn_surv) and (not dmn_uncov) and (not rs_surv) and (not rs_uncov)
          and (not gl_surv) and (not gl_uncov)
          and (not gr_surv) and (not gr_uncov) and g_cb)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())


