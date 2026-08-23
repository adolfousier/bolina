# M1 Keying Audit - the 62 unbound BE markers

State at audit: `main` = `1a7de0f`. `tools/prumo-verify` reports
DECL = 110, BOUND = 48, MISSING = 62, ORPHANS = 0. High water = 48.

This document classifies every one of the 62 unbound markers into one of six
buckets so the keying sprint (task #3) can attack them in the right order:
key what exists this slice, and map what does not for the milestone that owns
it. No marker is hand-waved.

The M1 binding mechanism (from `tools/prumo-verify` lines 87-115) is a
**bijection**: DECL markers are extracted from SPEC paragraph openings
(`^\*\*BE-CLASS-NN[a-z]?`), BOUND markers are those whose name appears as a
Zig test (`test "BE_CLASS_NN..."`), and the high water is a **ratchet** that
can only rise. A test binds a marker by its name alone - the harness does not
read the test body. §11.1 of SPEC makes the bijection the conformance
property: no BE without a test, no orphan test.

### How to read each row

- **Requirement** - what SPEC demands, in one line.
- **Evidence** - where the code lives today, or that it does not.
- **Bucket** - one of KEY-NOW, GATE-BOUND, NEEDS-CODE, OUT-OF-SLICE, SUPERSEDED.
- **Binding** (KEY-NOW only) - the test that will bind it.

---

## Bucket A - KEY-NOW (code exists, bind by name)

These are the cheap wins. The behaviour is implemented in the shipped slice;
it just is not advertised under its own marker name. The keying pass renames
or adds a focused test so prumo sees the bijection close.

### A1. Role and identity checks already enforced

| Marker | Requirement | Evidence | Binding |
|--------|-------------|----------|---------|
| BE-ROLE-01 | Cert MUST NOT carry both `agent` and `approver` | `binding.zig:122` returns `error.RoleAgentApprover` inside `checkRoleConstraints` (comment cites BE-ROLE-01) | Rename the relevant `BE_ID_03` cases to `BE_ROLE_01` |
| BE-ROLE-02 | Cert MUST NOT carry both `agent` and `executor` | `binding.zig:123` returns `error.RoleAgentExecutor` | `BE_ROLE_02` |
| BE-ROLE-04 | Cert MUST NOT carry both `approver` and `executor` | `binding.zig:124` returns `error.RoleApproverExecutor` | `BE_ROLE_04` |
| BE-CA-01 | Approver bit on an issued cert MUST require >= 2 distinct CA keys | `binding.zig` checks `cert.ca_sig_count < APPROVER_QUORUM` with `APPROVER_QUORUM = 2` | Rename `BE_ID_04` (one-sig approver refused, two accepted) to `BE_CA_01` |
| BE-REV-02 (refuse half) | Node holding a valid CA-signed revocation MUST refuse that subject's envelopes | `verify.zig:267` `is_revoked` callback consulted at use; covered by `BE_CHAN_02` and `BE_MESH_06` | Confirm refusal is reachable on the envelope path and bind `BE_REV_02` |

BE-ROLE-03 (approver private keys unreadable by the agent process, SHOULD hold
in hardware) is NOT here - it is a process-isolation / hardware obligation with
no runtime test in this slice. See Bucket D.

### A2. Wire, signing, and digest properties

| Marker | Requirement | Evidence | Binding |
|--------|-------------|----------|---------|
| BE-SIG-01 | Every Ed25519 signature covers `domain_tag \|\| tbs`; verify MUST reject a mismatched tag | `verify.zig:74` `verifySigned(tag, tbs, ...)`; tags 0x01-0x06 declared in `binding.zig:31`; vectors file records `sig_input_hex = tag \|\| tbs` | Focused test: one `tbs`, two tags, signature for tag A rejected under tag B. `BE_SIG_01` |
| BE-WIRE-03 | Signing and hashing are over wire bytes exactly as transmitted; no re-encoding | `verify.zig` hashes parsed wire bytes; `actionDigest` (line ~101) hashes action bytes directly | Test that the digest input is the wire bytes, not a re-serialised copy. `BE_WIRE_03` |
| BE-BODY-02 | Action digest is always recomputed, never carried on the wire | `verify.zig:101` `actionDigest()` recomputes; no `action_digest` field in any parser | Already exercised by `BE_GRANT_02` (digest must match byte for byte); rename/add `BE_BODY_02` |
| BE-BODY-03 | `Intent.rationale` is untrusted input that MUST NOT influence authorisation | `parser/channel.zig:130` treats the action body as opaque; verify never consults rationale | Absence test proving rationale bytes do not change the verify result. `BE_BODY_03` |
| BE-EFF-01 (wire half) | `ok=false` means the mechanism did not run; a non-zero exit code is `ok=true` with `exit_code` | Parser round-trips `ok` and `exit_code` fields of the Effect body | Round-trip test of the two Effect shapes. `BE_EFF_01`. (Executor half is Bucket D.) |
| BE-ENV-01 | Envelope `ts` MUST NOT be input to any security decision | `parser/channel.zig:99` parses `ts`; no verify check reads it; expiry uses the grant's `not_after`, not envelope `ts` | Absence test: mutate `ts`, assert verify result is unchanged. `BE_ENV_01` |

### A3. Grant verification properties

| Marker | Requirement | Evidence | Binding |
|--------|-------------|----------|---------|
| BE-GRANT-01 (consumed half) | A `grant_id` already committed with no Effect MUST be treated as consumed on restart | `verify.zig` Grant check 11 exposes `AlreadyConsumed` as a caller hook | Already exercised by `BE_GRANT_01` (already-consumed grant refused). Confirm name binds; restart handler is Bucket D. |
| BE-GRANT-03a | Intent lifecycle frozen from verify start to EXECUTING (single critical section) | `verify.zig:182` `verifyGrantThen` runs the execute callback inside one verification frame | Test that the effect callback runs inside the verify frame with no re-entry gap. `BE_GRANT_03a` |
| BE-GEN-02 | Genesis parameters are immutable; no message changes them | `verify.zig:285` `verifyControlGenesis` only creates; no update path exists | Absence/structural test: no mutation entry point for genesis fields. `BE_GEN_02` |
| BE-CHAN-03 (accept half) | Node MUST NOT accept channel messages from a non-member; revoked treated as non-member | `verify.zig:330` `requireMember` over `member_group`; revocation via `is_revoked` | Covered by `BE_CHAN_01`/`BE_CHAN_02`; bind the non-member+revoked acceptance under `BE_CHAN_03`. (Fan-out half is Bucket D.) |

### A4. Handshake and transport (confirm-then-key)

| Marker | Requirement | Evidence | Binding |
|--------|-------------|----------|---------|
| BE-TR-07 | Handshake messages MUST carry no application payload (Noise_IK message-1 is replayable) | `noise.zig` handshake messages have a zero-length payload field; `parser.zig` reads handshake structures with no body field | Structural test asserting the handshake message has no payload field. `BE_TR_07` |
| BE-TR-06 | Exactly one code path marks an envelope delivered, and it requires a bound session (BE-TR-01) | `session.zig` (10 KB) holds the delivery state machine; single `delivered` flag gated on the bound flag in `binding.zig:180` | **Confirm-then-key**: read `session.zig` delivery paths during the keying pass, assert single delivery site + bound-session gate. `BE_TR_06` |
| BE-EVID-12 | An Intent MUST NOT name, hint at, or constrain the observation method | `parser/channel.zig` Intent body has no method field | Absence test proving the Intent body carries no method selector. `BE_EVID_12` |
| BE-MESH-07 | LookupRequest / LookupResponse MUST travel inside an established session | `parser/channel.zig` parses lookups as a post-auth unit (placement) | Structural test that the lookup units are only reachable post-auth. `BE_MESH_07` |

**A4 count check:** BE-TR-06 is the one marker in this audit where the code
path is known to exist (`session.zig`) but not yet read line-by-line. The
keying pass reads it first and binds it or, if the single-delivery-site
property does not hold cleanly, escalates it to task #2.

---

## Bucket B - GATE-BOUND (enforced by a prumo gate, not a runtime test)

These are properties the build/size gates already prove. Binding them to a
runtime test would be theatre. D-041 decides the binding convention: either
prumo gains a `gate-bound` annotation that satisfies the bijection without a
runtime test, or each gets one minimal structural test. Recommendation: one
minimal structural test each, because the bijection is the stated conformance
property and a gate is invisible to the DECL/TESTED intersection.

| Marker | Requirement | What already enforces it | Proposed structural test |
|--------|-------------|--------------------------|--------------------------|
| BE-SURF-01 | Exactly two structures parsed from unauthenticated input (Noise handshake + cookie reply); a third is a protocol-version change | M5 file-list gate: only `parser.zig` handles pre-auth | Test that the pre-auth parser surface is exactly the handshake + cookie units. `BE_SURF_01` |
| BE-SURF-02 | Every index/length/offset/count MUST use checked arithmetic, error on overflow | All parsers route through `Cursor.need()` / `c.u64be()` / `c.take()`, which return errors | Feed an overflow-length field, assert `error.Refused`. `BE_SURF_02` |
| BE-SURF-03 | Surface budgets split along the auth line | M5/M11 prumo gates | Re-state as a `BE_SURF_03` test that the post-auth parser set is the M11-counted set (or gate-annotate) |
| BE-DEP-01 | No library outside stdlib required to build; vendored primitives pinned by hash | M6 offline-build gate | Build-graph structural test, or gate-annotate |
| BE-DEP-02 | Daemon MUST NOT contain a recursive parser; all structures flat, fixed-order, length-prefixed | All parsers are flat streaming, no recursion | Structural scan test asserting no parser recurses. `BE_DEP_02` |

BE-SURF-04 (continuous fuzzing MUST be differential: production parser vs an
independent reference parser) is NOT gate-bound. `src/fuzz.zig` is a
bounds-check chaos fuzzer (mutated-valid + random streams through
`Cursor.need()`), with no second, independent reference implementation. So
SURF-04 is **NEEDS-CODE** - see Bucket C.

### Resolution (M1 keying pass, commit pending)

| Marker | Verdict | Reason |
|--------|---------|--------|
| BE-SURF-01 | **BOUND** (`BE_SURF_01`) | `@hasDecl` proves the pre-auth surface is the closed two-structure inventory (handshake + cookie + routing header); every authenticated-structure parser is absent from `parser.zig` and present only in the post-auth sub-namespaces. |
| BE-SURF-02 | **BOUND** (`BE_SURF_02`) | Behavioural: `Cursor.u32be()` on a short buffer returns `error.Truncated`; `Cursor.field16`/`field32` over a declared max return `error.Oversize`. The arithmetic errors, it never panics. |
| BE-SURF-03 | **GATE-BOUND, unbound** | The 1500-line budget IS the M5/M11 prumo gate. A runtime line-count test would restate the constant (D-027) and is theatre; the gate is the enforcement. |
| BE-DEP-01 | **GATE-BOUND, unbound** | "No external library" is a build-graph property enforced by the M6 offline-build gate. A runtime test cannot see the build graph. |
| BE-DEP-02 | **BOUND** (`BE_DEP_02`) | `Intent.action` is a flat `[]const u8` the parser slices and never interprets; no `parseAction`/interpreter decl exists in any parser module. The arbitrary field is opaque, so nothing recurses. |
| BE-WIRE-03 | **COVERED, unbound** | `verifySigned` feeds `tag \|\| tbs` straight to the streaming Ed25519 Verifier (no intermediate buffer, no re-encode); `actionDigest` hashes raw bytes. Forcing a separate test would restate a constant (D-027). Existing wire-byte tests (BE-ENV-02 et al.) already exercise the path. |
| BE-TR-06 | **NEEDS-CODE, unbound** | The `bound` flag exists (`session.zig`) and `bindSession` is the sole authoriser, but the delivery-gate ("deliver requires bound session") is daemon-layer. `main.zig` is a 13-line stub; no dispatch path in `src/` checks `session.bound` before delivery. Genuinely out of this slice. |

---

## Bucket C - NEEDS-CODE (feature not implemented this slice)

The feature itself is absent. Binding it would require writing the feature,
which belongs to a later milestone, not the keying sprint. These are mapped
for the milestone that owns them and left UNBOUND in M1 (high water does not
move for them).

### C1. Mesh relay (BE-MESH-02 landed in the relay slice; store-and-forward remains M2)

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-MESH-02 | Relay forwards Noise transport packets, holds no key material, cannot decrypt | **BOUND** (`BE_MESH_02`) - implemented in `src/relay.zig` (relay sub-unit 183/510, D-043): opaque type-5 forwarding through a bounded 4096-entry table, one-shot signed registration (domain tag 0x07), no key material in the relay unit. 17 tests bind the marker by name; 11 relay mutants killed (harness v10). M1 high water moved 67 to 68. |
| BE-MESH-03 | Relay MAY store forwarded ciphertext for an offline recipient under quota + TTL | No relay code. M2. |

### C2. Sync / backfill (LANDED in the sync slice)

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-SYNC-01 | SyncRequest MUST be refused outside an established session | **BOUND** (`BE_SYNC_01`) - implemented in `src/sync.zig` (non-surface, D-054): admission reuses `verify.requireMember` behind the session-established check, so a request outside an established session, from a non-member, or from a revoked peer refuses. One literal test binds the marker by name; 2 admission mutants killed (harness v15). M1 high water moved 102 to 103. |
| BE-SYNC-02 | Responder returns at most `min(max_envelopes, 64)`, max 1 MiB | **BOUND** (`BE_SYNC_02`) - implemented in `src/sync.zig`: stateless response builder binds at `min(max_envelopes, 64)` and 1 MiB, sets the truncated flag exactly when unserved candidates remain, and retains no state between responses; `max_envelopes` is parsed and carried by `src/parser/sync.zig` (sync sub-unit 77/100), never rejected at the wire. One literal test binds the marker by name; 4 bounds mutants killed (harness v15). M1 high water moved 103 to 104. |
| BE-SYNC-03 | Walk budget: max depth 128, max 4096 envelopes | **BOUND** (`BE_SYNC_03`) - implemented in `src/sync.zig`: explicit walk queue, depth 128 and total 4096, stop + surface + no retry path exists (a recursive walk cannot compile past the explicit queue shape, BE-DEP-02). One literal test binds the marker by name; 3 walk mutants killed (harness v15). M1 high water moved 104 to 105. |
| BE-SYNC-04 | Rate-limit both requests served and issued | **BOUND** (`BE_SYNC_04`) - implemented in `src/sync.zig`: sliding-window rate limiter, serve 8 and issue 4 per peer per 10 s (budgets declared by D-054's SPEC edit), fail closed. One literal test binds the marker by name; 2 rate mutants killed (harness v15). M1 high water moved 105 to 106. |
| BE-SYNC-05 | Every backfilled envelope passes the same verification as a live one | **BOUND** (`BE_SYNC_05`) - implemented in `src/sync.zig`: `adoptVerify` runs `parseEnvelope` + `verify.verifyEnvelope` before any ledger entry, so a backfilled envelope meets the same signature, role, membership, and parent-hash checks as a live one. One literal test binds the marker by name; 1 adopt mutant killed (harness v15). M1 high water moved 106 to 107. |

### C3. Ledger, DAG, history (LANDED in the ledger slice)

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-LEDGER-01 | Member MUST reject an envelope whose `parents` reference unknown hashes within a bounded fetch, and surface a divergence | **BOUND** (`BE_LEDGER_01`, ledger slice) — `src/ledger.zig` checkParents rejects unknown parents within a bounded fetch budget and surfaces a divergence; two literal tests. |
| BE-LEDGER-02 | Ledger stores hashes, never plaintext; a head hash MAY be published externally | **BOUND** (`BE_LEDGER_02`) — hash-only store: envelopes are stored by hash, plaintext never retained; the construction that keeps the module off the parse surface (D-045). |
| BE-LEDGER-03 | Every Grant and Effect MUST appear in the ledger | **BOUND** (`BE_LEDGER_03`) — Grant and Effect envelopes recorded in the hash store on acceptance; two tests. |
| BE-HIST-01 | The BE-ID-02 clock check governs admission, not audit; an expired cert cannot authorise new things but can prove what it signed | **BOUND** (`BE_HIST_01`) — `src/historical.zig` validateCertNoClock: the audit path does not recheck the clock on certs. Stub shape, deliberately unkeyed in the mutation denominator (v11 note); the M1 test binds by name. |
| BE-HIST-02 | A signer's cert MUST be anchored in the channel before first use, by a Control envelope | **BOUND** (`BE_HIST_02`) — self-anchoring per D-046 (the Control enum stays closed): the first envelope accepted from a signer IS its anchoring record; four tests including idempotence and divergence. |
| BE-HIST-03 | An envelope is historically valid iff it is a causal descendant of the anchoring envelope and NOT a descendant of a revocation | **BOUND** (`BE_HIST_03`) — audit checks causal descent from the anchor and refuses descent from a revocation; three tests. |
| BE-HIST-04 | Revocation takes effect for admission immediately, for audit at its causal position | **BOUND** (`BE_HIST_04`) — revocation recorded immediately when a Revoke is accepted, read at its causal position on audit; four tests. |

### C4. Envelope equivocation + replay (LANDED in the ledger slice)

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-ENV-05 | A second envelope with a different hash at the same `(sender, channel, seq)` MUST raise a divergence event, never be dropped as a routine duplicate | **BOUND** (`BE_ENV_05`, ledger slice) — hash-compare dedup in `src/ledger.zig`: a different hash at the same triple raises Divergence; a same-hash duplicate stays idempotent. Two tests. |
| BE-ENV-04 | Per-`(sender, channel)` sliding acceptance window over `seq`, same shape as BE-TR-03 | **BOUND** (`BE_ENV_04`, ledger slice) — per-(sender, channel) sliding window over seq at the envelope admission layer (`verifyEnvelopeAdmission` in `verify.zig`, windows in `ledger.zig`); five tests including the reordered-seq witness that forbids the strict maximum. |
| BE-ENV-03 | Receiver MUST reject an envelope whose sender cert lacks the role for its `body_type` | **BOUND** (`BE_ENV_03`, ledger slice) — body_type to role map enforced at admission: Intent/agent, Grant/approver, Effect/executor; four tests. |

### C5. Grant lifecycle that needs a pending table or refusal handler

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-GRANT-06 | Executor MUST refuse a second Intent whose `resource_id` is already PENDING or EXECUTING | Needs a pending-intent / resource-lock table; verify exposes it as a hook only. |
| BE-GRANT-06b | Executor MUST refuse an Intent whose `intent_id` equals one already PENDING | Needs the pending-intent table. |
| BE-GRANT-09 | Refusal semantics: `body_type=6`, `Refusal.sig` verifies, sender has approver role, `intent_id` names a pending intent | Refusal is parsed but not verified in this slice. Needs a refusal verifier. |
| BE-REV-01 (duration half) | Approver/executor certs MUST have `not_after - not_before <= 30 days` | **BOUND** (`BE_REV_01`, ad3a3e7) — `binding.zig` validateCert caps approver/executor certs at 2,592,000,000 ms (D-048/D-049); four literal tests: cap boundary accepted, 1 ms over refused, executor accepted, agent exempt. Fixtures split onto a PRIVILEGED_* 30-day window for the approver cert; agent fixtures keep the wide window. |
| BE-RES-06 | `executor_fp = BLAKE2s-256(sig_pubkey)[0..8]`, 16 hex chars | No `executor_fp` / `fingerprint` code exists in `src/*.zig` (grep empty). `BE_ID_01` tests overlay-address derivation (`fd` prefix over BLAKE2s of `sig_pubkey`), which is similar but not the 8-byte fingerprint. NEEDS-CODE. |

---

## Bucket D - OUT-OF-SLICE (executor / process / UI / hardware obligation)

No test is possible without the executor, the approving UI, or hardware key
isolation. These are real requirements but they bind to a component that does
not exist in this slice. They are mapped and left UNBOUND in M1.

### D1. Process and hardware isolation

- BE-ROLE-03 - Approver private keys MUST NOT be readable by the agent process; SHOULD hold in hardware. (Process / hardware.)
- BE-EVID-11 - `method_id` MUST be a compile-time constant; no interface accepts `method_id` / `evidence_class` / `confidence` as an argument. (Executor. Partially enforceable as a structural absence test - task #2 decides KEY-NOW vs OUT-OF-SLICE.)
- BE-EVID-14 - A DirectObservation span is emitted only if output was captured; its digest is the hash of that output; no synthetic digest. (Executor.)

### D2. Grant lifecycle owned by the executor / restart handler

- BE-GRANT-01a (restart half) - On restart, a `grant_id` committed with no Effect MUST be published as `ok=false interrupted`. (Executor restart handler.)
- BE-GRANT-04 - Pending state MUST live in process memory only; restart collapses PENDING to EXPIRED. (Executor restart handler.)
- BE-GRANT-06a - Intent MUST transition PENDING -> EXPIRED after `T_pending = 900s`. (Executor timer.)
- BE-GRANT-07 - Approving interface MUST render canonical `resource_id`, full action bytes, and recompute `action_digest`. (Approving UI.)
- BE-GRANT-07a - If `Intent.rationale` is displayed, it MUST be marked untrusted and visually subordinate. (Approving UI.)
- BE-GRANT-08 - Grant MUST be signed by a key a human controls directly; no server-side signing. (Executor / key custody.)
- BE-GRANT-10 - REJECTED is terminal; no transition out; a Grant naming a REJECTED intent is dropped. (Executor state machine.)

### D3. Resource canonicalisation owned by the executor

- BE-RES-01 - Executor canonicalises `resource_id`, never the requester.
- BE-RES-02 - Unknown resource resolves to a refusal.
- BE-RES-03 - Aliases collapse into the lock.
- BE-RES-04 - One resource, one executor; `executor_fp` is part of the identifier.
- BE-RES-05 - Granularity is declared, not emergent.

### D4. Channel fan-out owned by the executor

- BE-CHAN-03 (fan-out half) - Node MUST NOT fan a channel message out to a non-member. (No fan-out caller in this slice.)

---

## Bucket E - SUPERSEDED

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-GRANT-03c | Seal by content / capability lifetime | SPEC line 1297 still declares it with the text `SUPERSEDED BY REMOVAL (round 4 review)`. The author kept it as a historical note explaining why the seal was deleted. prumo's DECL extractor still counts it, so it appears in MISSING. |

**This is the D-041 trigger.** Three honest options, decided in task #2:

1. **Exclusion list.** Give `prumo-verify` an explicit `superseded` allowlist
   (e.g. `tools/m1-superseded`) of markers that stay in SPEC for history but
   are removed from the DECL denominator. DECL becomes 109, high water is
   unaffected. Keeps the historical note. **Recommended.**
2. **Inline annotation.** Mark the SPEC paragraph so the DECL extractor skips
   it (e.g. a leading sigil). Riskier - couples SPEC prose to the tool.
3. **Delete the paragraph.** Loses the "why it was removed" note. Rejected.

The principle: a marker the SPEC itself says is removed must not be forced
into the bijection by a fake test, and must not be deleted from the spec. An
exclusion list is the cleanest way to honour both.

---

## Summary counts

| Bucket | Count | High water moves? |
|--------|-------|-------------------|
| A - KEY-NOW (code exists, bind by name) | ~21 | Yes (this is the sprint) |
| B - GATE-BOUND (one structural test or gate-annotate) | 5 | Yes, by structural tests |
| C - NEEDS-CODE (feature absent, later milestone) | ~19 | No |
| D - OUT-OF-SLICE (executor / UI / hardware) | ~16 | No |
| E - SUPERSEDED (exclusion list, D-041) | 1 | No (excluded) |

A + B are the keying surface this sprint. The exact A/B split for the
confirm-then-key markers (BE-TR-06, BE-ENV-03, BE-ENV-04, BE-REV-01 duration,
BE-EVID-11) is settled in task #2 and then executed in task #3.

### Confirm-then-key resolution (M1 keying pass)

All five confirm-then-key markers were read against the code. At the keying
pass all five resolved to **NEEDS-CODE**; the ledger slice then landed code
for three of them (ENV-03, ENV-04, REV-01), which are now **BOUND** by
literal tests. Two (TR-06, EVID-11) remain **NEEDS-CODE** -- the property's
code path still does not exist, so no honest runtime test can bind it (D-027
forbids a vacuous structural test that passes only because the feature is
absent).

| Marker | Requirement | What the code has | Verdict |
|--------|-------------|-------------------|---------|
| BE-TR-06 | Single delivery site requires a bound session | `bound` flag + sole authoriser exist; no dispatch path checks it | NEEDS-CODE (see Bucket B resolution; `main.zig` is a stub) |
| BE-ENV-03 | Receiver rejects an envelope whose sender cert lacks the role for its body_type | `verifyEnvelopeAdmission` enforces the body_type -> role map (Intent/agent, Grant/approver, Effect/executor) | **BOUND** (ledger slice, `BE_ENV_03`) |
| BE-ENV-04 | Per-(sender,channel) sliding window over `seq` at the envelope layer | `verifyEnvelopeAdmission` runs a per-(sender, channel) sliding window over seq (`ledger.zig` windows) | **BOUND** (ledger slice, `BE_ENV_04`) |
| BE-REV-01 | Approver/executor cert duration `not_after - not_before <= 30 days` | `validateCert` caps approver/executor certs at 2,592,000,000 ms (ad3a3e7) | **BOUND** (ledger slice, `BE_REV_01`) |
| BE-EVID-11 | `method_id` is a compile-time constant of the executor; no executor interface accepts it | SPEC's own text: "verified by reading the executor's source once, statically". No executor module exists; `classOf(method_id)` is receiver code (BE-EVID-13/15, already bound), not an executor interface | NEEDS-CODE |

**Numbers do not sum to 62 yet** because five markers straddle a bucket line
and are settled by the task #2 mechanism decisions, not by this audit. The
audit's job is to name every marker and its evidence; the mechanism decisions
then pin the final count.

---

## Keying-pass order (task #3)

1. **Role/identity renames** (A1) - pure renames, lowest risk, biggest cluster
   drop. Five markers (ROLE-01/02/04, CA-01, REV-02) collapse out of `BE_ID_03`
   / `BE_ID_04` aliases.
2. **Confirm-then-key** (A4 + C4 straddlers) - read `session.zig` (TR-06),
   check envelope replay window (ENV-04), check body_type -> role (ENV-03),
   check 30-day duration (REV-01), check method_id constancy (EVID-11).
   Reclassify each to KEY-NOW or NEEDS-CODE on evidence.
3. **Wire/signing/digest focused tests** (A2) - new focused tests, not renames.
4. **Grant property tests** (A3) - one new test each.
5. **Structural tests for the gate-bound set** (B) - if D-041 picks tests over
   gate-annotation.
6. Bump `tools/m1-high-water`, run the full gauntlet, hold the 57/57 mutation
   baseline and the 77/77 vector set.

Every test is read against its SPEC paragraph before it is named, and no test
references the constant it verifies (D-027 - literals only).

---

## Resolution - sprint outcome (2026-08-07)

The keying pass bound nineteen markers. `tools/m1-high-water` rose 48 -> 67;
the live gate reads `67/109 bound, high water 67, missing 42`. Every marker
named in this audit now carries a final verdict:

- **BOUND (19)** - one real behavioural test each, across eight atomic
  commits (`5062364` through `e435166`): ROLE-01/02/04, CA-01, SIG-01,
  EFF-01, TR-07, EVID-12, BODY-02/03, ENV-01, CHAN-03, REV-02, GEN-02,
  GRANT-03a, MESH-07, SURF-01/02, DEP-02.
- **GATE-BOUND, unbound (3)** - SURF-03 (M5/M11 line budget), DEP-01 (M6
  offline-build graph), WIRE-03 (covered by streaming `verifySigned`; D-027
  forbids a redundant test). A runtime test for a build-time property would
  be theatre; the gate is the proof.
- **NEEDS-CODE (the relay round's worklist)** - TR-06 (dispatch must check
  `session.bound`; `main.zig` is a stub), ENV-03 (body_type -> role map),
  ENV-04 (envelope-layer seq replay), REV-01 (30-day duration cap), EVID-11
  (executor method_id interface). Each is traced to live source with the
  absent line named.
- **OUT-OF-SLICE** - the executor, restart handler, approving UI, and
  hardware key-isolation markers. Declared and MISSING until their milestone
  lands (D-041 decision 3).

Full gauntlet after the pass: `zig fmt --check` clean; `zig build test`
213/213; em-dash scan clean over `src/` and `tools/`; `verify-vectors`
PASSED 77 FAILED 0; mutation 57/57 killed, 0 survived (chunked, one writer
per domain; D-035/D-040). The mechanism decisions behind these verdicts are
D-041 (denominator law) and D-042 (keying-pass verdicts).

---

## Relay round addendum (branch relay-slice, measured 2026-08-08)

BE-MESH-02 moves out of bucket C1. `src/relay.zig` landed under the D-043
tripwire at 183/510 relay sub-unit lines; the handshake sub-unit is
ratcheted at 990/990 with zero growth. M1 ratchet reads 68/109 bound, high
water 68 (DECL 109 excludes BE-GRANT-03c per its SUPERSEDED BY REMOVAL
clause, D-041).

Full gauntlet at `fc4317c` plus two documentation commits: `zig fmt --check`
clean; `zig build test` green, 234 test declarations; em-dash scan clean
over `src/` and `tools/`; `verify-vectors` PASSED 77 FAILED 0; prumo-verify
0 failing (M5 pre-authentication 1173/1500, M11 1493/1500, M9 denominator
64 exit points); mutation harness v10 68/68 killed, 0 survived across seven
domains (grant 17, evidence 11, session 11, channel 8, mesh 6, transport 4,
relay 11), single writer per run (D-035). Fuzz coverage re-measured the same
day: 17/64 exit points reached over 4,000,000 inputs (24,000,000 parser
calls), 0 panics; the eight relay exits join the unreached set until
`src/fuzz.zig` grows relay entry points and `test/vectors.json` grows relay
seeds.

BE-MESH-03 stays in this bucket: store-and-forward is a SPEC MAY, deferred
by D-043. That is scope, not debt.

---

## Ledger round addendum (branch ledger-slice, measured 2026-08-08)

Buckets C3 and C4 empty out. `src/ledger.zig` (290 lines) and
`src/historical.zig` (109 lines) landed under the D-045 placement,
non-budgeted and off the parse surface, with the BE-SURF-03 list repair
logged as D-047. BE-LEDGER-01/02/03 and BE-HIST-01..04 move to BOUND in
C3, BE-ENV-03/04/05 move to BOUND in C4, and BE-REV-01's duration half
lands in C5 at `ad3a3e7`. BE-HIST-01 is bound by name but deliberately
unkeyed in the mutation denominator: `validateCertNoClock` is a stub shape
until the `binding.zig` refactor (v11 note). The REV-01 fixture collision
resolved per D-049: approver and executor fixtures moved to a
PRIVILEGED_CERT 30-day window, agent fixtures kept the wide window. M1
ratchet reads 79/109 bound, high water 79 (DECL 109 still excludes
BE-GRANT-03c per its SUPERSEDED BY REMOVAL clause, D-041).

Full gauntlet at `da9356e` plus two documentation commits: `zig fmt --check`
clean; `zig build test` green, 266 test declarations; em-dash scan clean
over `src/` and `tools/`; `verify-vectors` PASSED 77 FAILED 0; prumo-verify
0 failing (M5 pre-authentication 1173/1500 with the handshake sub-unit
ratcheted at 990/990 and relay 183/510, M11 post-authentication 1497/1500
with `binding.zig` 193 after REV-01's four lines, M9 denominator 64 exit
points); mutation harness v11 81/81 killed, 0 survived across eight domains
(grant 17, evidence 11, session 11, channel 8, mesh 6, transport 4, relay
11, ledger 13), single writer per run (D-035).

The round's one mutation incident, caught by the full re-run, not by a
chunk: the first re-run read 80/81 because BE-REV-01's new cap rejected the
check-4 role-swapped subject fixture before the role check ran, making the
grant role mutant unfalsifiable on that witness. The fixture moved to the
PRIVILEGED_CERT window (`98cf577`) and the clean re-run killed all 81
(`mutation_final.log`, same tree).

The remaining NEEDS-CODE rows stand: C5's pending-intent table and refusal
verifier (BE-GRANT-06/06b/09), BE-RES-06's executor fingerprint, and the
confirm-then-key pair BE-TR-06 and BE-EVID-11. The ledger slice closed the
divergence surface that BE-ENV-05 and BE-LEDGER-01 both named.

---

## Pending-intent slice addendum (branch post-auth-slice, measured 2026-08-09)

Buckets C5 and D2 empty out. `src/intent.zig` (190 lines) landed as the
non-surface pending-intent state machine under the D-052 placement: states
PENDING / EXECUTING / EXPIRED / REJECTED, a per-resource exclusivity lock,
intent_id dedupe, the T_pending = 900s timeout sweep, restart collapse
(memory-only per BE-GRANT-04), lock release on every exit path, and REJECTED
terminality. The refusal verifier landed in `src/verify.zig`
(`verifyRefusalThen`): the 0x06 DOMAIN_REFUSAL tag, the approver-role check,
and the applyRefusal hook that transitions a matched pending intent to
REJECTED. The wire parser half is `parseRefusal` in `parser/channel.zig`
(body_type 6: intent_id, note, sig).

Seven markers move to BOUND, each by a literal behavioural test named per
D-027:

- BE-GRANT-01a (interrupted effect leaves grant_id spent, never retried):
  `verify_test.zig`.
- BE-GRANT-04 (fresh table holds no pending state; restart collapse):
  `intent_test.zig`.
- BE-GRANT-06 (second intent on a held resource refused; exclusivity):
  `intent_test.zig`.
- BE-GRANT-06a (T_pending timeout expires pending and releases the lock):
  `intent_test.zig`.
- BE-GRANT-06b (duplicate intent_id refused at admission):
  `intent_test.zig`.
- BE-GRANT-09 (canonical refusal verifies and rejects the pending intent;
  wrong body_type / bad sig / wrong domain tag / non-approver each refused;
  a refusal matching no pending intent is dropped): six cases in
  `verify_test.zig` plus the no-match drop in `intent_test.zig`.
- BE-GRANT-10 (a rejected intent cannot re-enter EXECUTING):
  `intent_test.zig`.

These were the D2/C5 rows the audit had parked on the executor. The
resolution matches the session and relay rounds: the state machine that
enforces each property exists in `src/` now and is the unit the executor will
wire, so the property is testable today; the daemon dispatch (`main.zig` is
still a 13-line stub) is a later milestone and does not unbind a property the
state machine already enforces.

M1 ratchet reads 94/109 bound, high water 94 (DECL 109 still excludes
BE-GRANT-03c per its SUPERSEDED BY REMOVAL clause, D-041). The seven GRANT
markers raised the high water 87 to 94.

Full gauntlet at `ebafcfa` plus the docs/ratchet commit: `zig fmt --check`
clean; `zig build test` green; em-dash scan clean over `src/` and `tools/`;
`verify-vectors` PASSED 77 FAILED 0; prumo-verify 0 failing (M5
pre-authentication 1173/1500 with handshake 990/990 and relay 183/510, M11
post-authentication 1400/1500 subdivided per D-052 into wire-parser 652/723
and session-state 748/748, M9 denominator 66 exit points); mutation harness
v12 90/90 killed, 0 survived across ten domains (grant 17, evidence 11,
session 11, channel 8, mesh 6, transport 4, relay 11, ledger 13, intent 6,
refusal 3), single writer per run (D-035).

The remaining 15 missing markers span the executor and approving-UI
obligations, the confirm-then-key pair (BE-TR-06, BE-EVID-11), BE-RES-06's
executor fingerprint, and the sync set: all NEEDS-CODE or OUT-OF-SLICE, none
addressable by a runtime test against code that does not yet exist (D-027).

## Resolver round addendum (branch post-auth-slice, measured 2026-08-10)

The resolver round binds the six BE-RES markers (SPEC section 8.4) over
non-surface `src/resolver.zig` (322 lines, placed by D-052 ahead of creation,
zero M11 line cost): `executorFp` renders BLAKE2s-256(sig_pubkey)[0..8] as 16
lowercase hex chars (BE-RES-06), `validateCanonical` walks the
bol:fp/namespace/path grammar refusing dot and dotdot segments and the length
bounds, `resolve` refuses zero matches and more than one distinct canonical
(BE-RES-02, BE-RES-03), the own-fingerprint gate refuses canonical ids that
carry another executor's fp (BE-RES-04), and `resolveAndAdmit` threads the
canonical into the intent lock table so every downstream consumer keys on the
executor's form, never the requester's (BE-RES-01).

BE-RES-05 binds as signed executor-side state per D-053: the operator-declared
set serializes deterministically in declaration order (u16 big-endian lengths)
and signs Ed25519 under the new domain tag 0x08, declared by the SPEC
v0.3.2-draft edit committed ahead of the code (D-029 pre-flag). The channel
publication vehicle is undeclared in SPEC (body_type enum closed 1-6,
BE-CTRL-01 action_type closed {1, 2} with no extension path), so publication
waits on the daemon milestone: the same resolution as the pending-intent
addendum, the unit enforcing the property exists in src/ and is testable now.
Aliases are operator-declared entries per D-053 (granularity is declared, not
emergent, per BE-RES-05's own text); no fuzzy or prefix matching; resolution
counts distinct canonical entries reached, so two spellings of one resource
collapse onto one lock and any real ambiguity refuses.

Ratchet 94 to 100 of 109, high water committed with the tests (c54d34f).
Mutation harness v13 adds the resolver domain: 10 SPEC-keyed mutants, 6/6
section-8.4 properties covered by killed mutants. Full suite 100/100 on a
clean tree, receipt `mutation_resolver_clean.log`. The first full run started
on residue from a killed launch (a grant-domain mutant left un-restored in
`src/verify.zig`), which skipped that mutant and masked one resolver survivor;
root cause named, tree restored, clean re-run killed all 100 including both.
Lesson recorded in LANGUAGE.md: the harness restores from launch-time
snapshots, so verify zero residue before launching.

The remaining markers now number nine: BE-GRANT-07/07a (approving render),
BE-SURF-04 (fuzz oracle), BE-SYNC-01..05 (backfill/sync surface), and the
deferred MAY BE-MESH-03 (D-051). This supersedes the 15-marker count in the
pending-intent addendum's closing paragraph.


## Render round addendum (branch main, measured 2026-08-10)

The render slice binds BE-GRANT-07 and BE-GRANT-07a (SPEC section 8.3) over
non-surface `src/render.zig` (56 lines, D-052 placement, zero M11 cost).
`renderApproval` has no digest parameter, so a wire-sourced digest has no
path into the view (BE-GRANT-07); the view's action_digest is recomputed
from exactly the bytes the view carries, via the same primitive the Grant
binds (verify.actionDigest, check 9), so display and signature agree by
construction, witnessed against the grant fixture literal pair (action
"apt-get install -y sqlite3", digest
61a0be1fa7039021e3a6d10a38e41e21873abd4668419d6b45dfcd56686d60c3).
Rationale handling (BE-GRANT-07a) is typed: any displayed rationale carries
the untrusted label as part of its type, sits after the action bytes in
field order, and the primary content is non-optional, so rationale can
never be the sole element on screen. M1 ratchet 100 to 102 of 109
(committed with the tests, 3e7592a). Mutation harness v14 adds the render
domain: six SPEC-keyed mutants, 2/2 section-8.3 properties covered; full
suite 106/106 on a clean tree, zero residue after the run
(mutation_render_full.log). The remaining markers now number 7:
BE-SURF-04 (fuzz oracle), BE-SYNC-01..05 (backfill surface), and the
deferred MAY BE-MESH-03 (D-051). This supersedes the 9-marker count in the
resolver round addendum.


## Sync round addendum (branch main, measured 2026-08-11)

The sync slice binds BE-SYNC-01..05 (SPEC section 6.4, Backfill). D-054
ruled the budget before any code: the post-authentication unit is
subdivided into three sub-units (wire-parser, session-state, sync), the
wire-parser cap ratchets DOWN from 723 to its measured floor 652, the sync
sub-unit is declared at cap 100 over `src/parser/sync.zig` (77 measured),
and the cap sum stays 1500 - nothing raised, per BE-SURF-03 (the
estimate's renegotiation recommendation was the error the ruling
corrects). `src/sync.zig` (289 lines, non-surface per D-054) carries the
SyncEngine: admission reuses `verify.requireMember` (BE-SYNC-01), the
response builder binds at min(max_envelopes, 64) and 1 MiB with the exact
truncated flag and no retained state (BE-SYNC-02), the walk queue is
explicit at depth 128 and total 4096 with stop + surface + no retry
(BE-SYNC-03), the sliding-window rate limiter serves 8 and issues 4 per
peer per 10 s, budgets declared in the same SPEC edit (BE-SYNC-04, D-054),
and `adoptVerify` runs `parseEnvelope` + `verify.verifyEnvelope` before
any ledger entry (BE-SYNC-05). Five literal tests bind the markers by name
(D-027); ratchet 102 to 107 of 109, high water committed with the tests
(c43990d). Mutation harness v15 adds the sync domain: twelve SPEC-keyed
mutants (eleven over `src/sync.zig`, one over `src/parser/sync.zig`), 5/5
section-6.4 properties covered by killed mutants; chunked sync run 12/12
killed, full suite 118/118 on a clean tree, zero residue before launch and
after the run (mutation_sync_chunk.log, mutation_sync_full.log).
LANGUAGE.md's exit-point cell carries a denominator repair in the same
commit: the Branch enum grew 66 to 72 with the six sync exits (the two
refusal exits added since the 2026-08-08 measurement went unlogged), so
the cell reads 17 of 72 reached and 55 unreached, no new measurement
claimed. The
remaining markers now number 2: BE-SURF-04 (fuzz oracle, next per §13
lineage) and the deferred MAY BE-MESH-03 (D-051). This supersedes the
7-marker count in the render round addendum.

## BE-SURF-04 round addendum (branch main, measured 2026-08-11)

The fuzz oracle slice binds BE-SURF-04 (SPEC section 11.6, differential
fuzzing; D-056 rules the design, D-057 rules the expansion to every parse
entry point and the two findings it produced). One literal test binds the
marker by name (D-027): `test "BE_SURF_04 differential replay flags an
injected divergence and agrees on honest verdicts"` in `src/fuzz_test.zig`
exercises the replay-and-compare machinery inside the suite (corpus
framing, tagged routing to the parse entry points, positional verdict
comparison), flags exactly one divergence on a doctored reference stream,
flags zero on an honest one, and fails loudly on framing defects rather
than emitting silent verdicts; ratchet 107 to 108 of 109, high water
committed with the tests (3a8b0a3). The reference parser lives outside
the Zig tree by construction (`tools/refparse.py`, written from the SPEC
field tables alone and silent wherever the SPEC is silent, D-056 decision
1: a reference transcribed from the code would agree by construction and
gate nothing); `src/fuzz.zig` carries corpus-emit and diff-replay modes,
and `tools/fuzz_diff.py` runs the bounded differential campaign, enforced
at M4 by `tools/prumo-verify` (zero divergences required; the row prints
coverage and corpus every run). D-057 wired all 22 parse entry points
(the count is grep-derived from the source and corrects the plan's stale
20), added the `extend` mutation operator because the four shrinking
operators cannot reach trailing-byte exits, and raised the merge-gate
budget to 20000 records (about 8 seconds). The expansion produced two
findings, both closed in the specification rather than the code: SPEC 4.5
gained the fragment header bound (`total` at least 1, `index` strictly
less than `total`) that the parser enforced while the specification was
silent, and the reference's misplacement of BE-CTRL-01's action-type
check at the parse layer was corrected (the check lives whole at the
verifier, `src/verify.zig`). The M4 corpus reaches 69 of the 72 exit
points with three unreached exits named on the gate row every run
(`data_payload_oversize`, `cert_ca_count_oversize`, `bind_cert_len_zero`,
each a shape the corpus never constructs rather than a path that does not
exist); the separate chaos-mode re-measure in LANGUAGE.md reads 71 of 72
at 4,000,000 inputs. Mutation: no `TARGETS` file in `tools/mutation-test.py`
was touched by this slice (`src/fuzz.zig` is instrumentation, excluded
from the mutant population), so 118/118 killed at sync-slice HEAD
`8055801` (harness v15, mutation_sync_full.log) remains the standing
measurement and no mutation re-run was made. The
remaining markers now number 1: the deferred MAY BE-MESH-03 (D-051).
This supersedes the 2-marker count in the sync round addendum.

## Store-and-forward round addendum (branch main, measured 2026-08-11)

The mesh slice binds BE-MESH-03 (SPEC section 5.2a store-and-forward clause,
normativized by the v0.3.4-draft edit): a relay MAY store forwarded ciphertext
for offline recipients under declared bounds. Daniel's 2026-08-11 rulings
("keep going, follow the spec"; "you are in charge of the decisions") closed
the D-051 deferral: option 1, build and bind. D-058 supplies the mechanics
warrant: storage keys by overlay_addr because session-scoped client indexes
die with the session; drain rewrites the relay-layer recipient_index at
registration time and never touches the ciphertext body (BE-MESH-02 opacity);
BE-MESH-04's no-service rule for unknown indexes extends to storage. Declared
bounds: 64 packets and 4 MiB per recipient (the byte bound is
defense-in-depth, dominated by 64 times 2048), 2048-byte body cap, 120-second
TTL (one rekey interval, BE-TR-02) on the caller clock, 1024 global slots; quota exhaustion counts and never
blocks live forwarding.

Implementation: src/relay_store.zig 139 lines (non-surface per D-058, zero
budget cost); src/relay.zig 183 to 256 lines (storeDeferred, drainFor,
writeRelayRoute; M9 held clean via named error sets); relay sub-unit 256/510,
pre-authentication unit 1246/1500. M1 ratchet 108 to 109 of 109, committed
with the binding tests (758c92d): every marker the SPEC declares is now bound
by code and literal tests. Mutation harness v16 adds mesh-03 to the
denominator with seven mutants over relay_store.zig and relay.zig; the full
suite reads 125/125 killed, zero survivors, mesh 5/5 section-5 properties
covered, zero residue after the run (logs/mutation_mesh_full_v16.log). The
remaining markers now number zero. This supersedes the 1-marker count in the
BE-SURF-04 round addendum. M1 is complete; the daemon milestone (main.zig,
13-line stub) is the next declared territory, estimate first
(DAEMON-ESTIMATE.md).

## Daemon milestone addendum (branch main, measured 2026-08-11..12)

The mesh-03 addendum closed with "M1 is complete; the daemon milestone is the
next declared territory". The daemon milestone (phases B, C, D) declared and
bound five further markers, ratcheting M1 from 109 to 114 of 114, high water
committed with the binding tests at each phase:

| Phase | Markers bound | Ratchet | Estimate / decision |
|---|---|---|---|
| B (listener + handshake) | BE-EXEC-02, BE-EXEC-03, BE-SESS-02 | 109 -> 112 | PHASE-B-ESTIMATE.md |
| C (relay serving on live traffic) | BE-EXEC-04 | 112 -> 113 | PHASE-C-ESTIMATE.md, D-060 |
| D (daemon lifecycle + durable ledger) | BE-EXEC-01 | 113 -> 114 | PHASE-D-ESTIMATE.md, D-061 |

Phase D implemented the durable consumed-grant ledger (`src/grant_ledger.zig`,
non-surface per D-061): a hand-rolled two-phase append log over `std.fs` with
fsync barrier, committing a consumed grant before the effect and surfacing a
committed-but-unpublished grant as an `interrupted` Effect on restart
(BE-GRANT-01/01a, idempotent); revocation persists (BE-REV-02). The dispatch
check-11 seam was widened to commit before the effect (D-062). The DAG hash
ledger `src/ledger.zig` (BE-LEDGER-02/03) is untouched and distinct.

The differential oracle (BE-SURF-04 differential half, section 11.6) was
strengthened past the 69-of-72 state recorded in the BE-SURF-04 round
addendum. Four boundary seeds now drive all 72 parser exit points to coverage
at any corpus size (`bind_cert_len_zero`, `data_payload_oversize`,
`cert_group_oversize`, `cert_ca_order`), each a length- or ordering-field exit
uniform mutation cannot construct. The enforced M4 gate reads 0 divergences
over 20068 records, 72/72 exit points. An extended 1,000,000-record run held
at 0 divergences after the four findings it surfaced were fixed: three
reference-parser bound omissions (ControlGenesis `ca_count=0` 60191ca, binding
`cert_len=0` 08595d3, control-body oversize 224ab6b) and one production
crash-safety defect — `pruneExpired` rewrote the consumed log in place and a
crash mid-rewrite could empty it, un-spending a committed grant (BE-GRANT-01);
now crash-safe by atomic rename, D-063, becc23d. The crash-injection test that
found it was predicted by the model-checking brief issued for section 11.4.

Mutation harness v20 adds the grant_ledger domain (seven mutants) and
re-anchors three mutants the widened check-11 seam rewrote; the full suite
reads 151/151 killed, zero survivors, seventeen domains, zero residue
(logs/mutation_phase_d_full.log).

Honest state at this closeout. M1 is 114 of 114 declared markers bound, high
water 114. The differential component of BE-SURF-04 is evidenced at scale.
Three conformance items remain unsealed and are not described otherwise: the
continuous 24-hour soak of section 11.6 is deferred for want of dedicated
compute (owner workstations and production servers are out of scope by owner
ruling; the path is a dedicated runner or GitHub Actions, which the public
repo qualifies for at no cost); section 11.4 model checking is in progress
with an external contributor (brief issued); section 11.5 adversarial
evaluation against a real model has not been run. Per section 11.8 the draft
is closed, not sealed, and these three items are the gap between the two.

## RED-TEAM-10 round addendum (2026-08-13)

RED-TEAM-10 was an adversarial review of the implementation, cross-validated
across two independent lanes, run after the Phase D closeout seal. It is a
review of the code as built, distinct from the §11.5 adversarial evaluation
against a real model, which remains un-run.

The review's differential half extended the oracle from the 20,068-record
merge gate to 1,000,000 records and surfaced the four findings already
recorded in the Phase D addendum (three reference-parser bound omissions,
60191ca / 08595d3 / 224ab6b, and one production crash-safety defect in
`pruneExpired`, D-063, becc23d). The review's implementation half adjudicated
one new finding the Phase D closeout did not carry:

The review's composition half adjudicated three runtime guarantees that sit
on the un-wired side of the daemon milestone (`main.zig` is a 13-line stub,
so no live transport loop calls any of them): F1, the 120-second rekey
trigger is a dead gate (`dueForRekey` and `rotate` in `session.zig` have no
non-test caller, BE-TR-02 unenforced in any running binary); F2, mac2/cookie
verification is inactive on the live path (`handshake.zig` answers every
initiation with a zero cookie, so BE-TR-04a's spoofed-source-flood defence
is absent until the phase-C under-load wiring); F3, `bindSession` never
asserts `participant_static == cert.kex_pubkey`, leaving the cert's kex key
decorative on the responder path (identity binding holds by transitivity;
this is a hardening, not a hole). All three are wiring deferrals, not crypto
defects: the units compose correctly, are unit-tested, and each needs a live
caller (the daemon transport loop for F1, the under-load cookie path for F2,
one assertion when `bindSession` is wired for F3). This round closes F4
first as the most security-relevant of the four; F1-F3 ride their own
milestones.

**F4 — revocation was dead code at the effect checkpoint (GAP, not
layering).** `GrantContext` had no `is_revoked` seam while `ChannelContext`
and `MeshContext` both did; the durable revocation set built in Phase D was
never consulted on the grant path, the one checkpoint where capability turns
into effect. This inverts the principle verify.zig already states ("as of this
use, not of cache fill"). Fixed by D-064: `is_revoked` added to `GrantContext`
and consulted at checks 3-4 (`ApproverRevoked`/`SubjectRevoked`, both declared
fresh in `VerifyError` per ruling 2), backed by `dispatch.isRevokedHook` over
the durable ledger with the same fail-safe shape as `consumedHook` (no ledger
-> refuse). Regression guard c64cd02, wiring d9cff4e.

Two witnesses landed after the wiring (dd55d1c): the F4 subject guard (durably
revoked subject refused at check 4, effect never fired) and the F4 fail-safe
test (no durable ledger -> grant refused with `ApproverRevoked` before check
11, pinning D-064 ruling 1 and ruling 3 ordering together). Before these, the
subject-revoked and no-ledger paths had zero test coverage.

Mutation harness v21 (bd00e6d, D-065) keys the seam: the `grant_revocation`
domain derives three properties from the D-064 rulings (f4-approver-check,
f4-subject-check, f4-failsafe) and attacks them with four mutants over
`src/verify.zig` and `src/dispatch.zig`. The denominator reads 155 mutants
over eighteen domains; the full suite at HEAD bd00e6d reads 155/155 killed,
zero survivors, zero residue (receipt `logs/mutation_f4_full.log`).

No M1 marker changes this round: BE-REV-02 was already declared (114/114, high
water 114) and is now mechanically defended at the effect checkpoint rather
than merely implemented. The three unsealed conformance items from the Phase D
closeout are unchanged: the 24-hour soak is deferred for want of dedicated
compute, §11.4 model checking is in progress with an external contributor, and
§11.5 adversarial evaluation against a real model has not been run.

## D-086 scope mutation addendum (2026-08-19)

The D-085 resource-scope work (cert v3, checks 3a/4a) adds five mutants to
the grant domain, bringing the total from 155 to 160 across eighteen domains.
The five new mutants target `src/verify.zig`:

| ID | Type | Check | Anchor |
|----|------|-------|--------|
| grant/3a | CHECK-ABSENCE | 3a approver scope never enforced | `if (ctx.approver_cert.version >= 3 and !scopeCoversResource(...))` |
| grant/3a | WRONG-OPERATOR | 3a version gate `>=3` -> `>3` | same line |
| grant/4a | CHECK-ABSENCE | 4a subject scope never enforced | `if (ctx.subject_cert.version >= 3 and !scopeCoversResource(...))` |
| grant/4a | WRONG-OPERATOR | 4a version gate `>=3` -> `>3` | same line |
| grant/3a | WRONG-LOGIC | `scopeCoversResource` match inverted | `if (certCarriesScope(cert, hash[0..8])) return true;` |

The mutation harness regex in `modelled_checks_from_spec()` was also fixed:
`\d+` collapsed "3a"/"4a" into 3/4, making the scope checks invisible to the
denominator. Updated to `\d+[a-z]?` so the conformance sentence "models checks
0, 1, 2, 3, 3a, 4, 4a, 5, 6, 7, 8, 9, 10 and 11" parses to 14 modelled
checks (was 12). Three `sorted()` calls fixed for mixed int/string keys.

Grant domain run: 22/22 killed (17 existing + 5 new scope mutants), zero
survivors. The three scope tests in `verify_test.zig` (positive scope accepted,
approver non-covering scope refused, subject non-covering scope refused) kill
all five. Receipt: `logs/mutation_grant_scope.log` (inline output captured
2026-08-19, HEAD a02aa0f).

No M1 marker changes: the scope checks are covered by the existing BE-GRANT-03
marker (114/114, high water 114). M2 reads 160/160 killed.

## First nightly soak addendum (2026-08-15)

The §11.6 soak schedule activated by D-070 fired for the first time at 03:44
UTC on 2026-08-15 (GitHub Actions run 31862614634, HEAD `6dfebcb`). This
addendum records what that run actually evidences, because the run's own
verdict overstates it: all five matrix jobs concluded success, and the
differential half of all five failed.

**Chaos half: real evidence, first night.** Every seed (bolina, s42, s1337,
s999999, deadbeef) reports `FUZZ DONE: 14400000000 inputs (316800000000 parser
calls), 0 panics` and `COVERAGE: 72/72 exit points reached`, with no unreached
exit points. Job durations were 2h48m for four seeds and 3h03m for s1337,
about 14.6 hours of accumulated chaos fuzzing in one night against the §11.6
">= 24 hours" figure, which per D-070 ruling 2 accumulates across seeds and
nights rather than running uninterrupted.

**Differential half: zero nightly evidence to date.** Every seed died in the
Zig replay with `error: StreamTooLong`, and the orchestrator exited 2
(`FAIL: zig diff replay`). The 5,000,000-record default emitted a 6,379,201,306
byte corpus against the replay's 4 GiB read cap, so the differential never ran
on any seed on any night. The failure was invisible because the step piped into
`tee` without `pipefail`, so bash reported `tee`'s status. Both defects are
fixed under D-074: `pipefail` on the step, the budget lowered to a measured
1,000,000 records (verified end to end at 1,000,068 records, 0 divergences,
72/72 coverage before the change was committed), and an explicit oversize
refusal in `tools/fuzz_diff.py` that names the cap and the offending budget
instead of surfacing a bare `StreamTooLong`.

**Marker state is unchanged.** M1 reads 114 of 114 declared markers bound, high
water 114, missing 0. BE-SURF-04's differential component remains evidenced at
the scale RED-TEAM-10 established (1,000,000 records, 0 divergences), not by
the nightly, which has contributed nothing on that half yet. §11.6 stays
unsealed. The soak-deferred language in the Phase D and RED-TEAM-10 closeouts
above is left as written: it was accurate at those closeouts and is superseded
here, not rewritten.

## Second nightly soak addendum (2026-08-16): section 11.6 sealed

The second nightly soak (GitHub Actions run 31925289374, HEAD `2f310b0`,
03:52 UTC on 2026-08-16) is the first run in which both halves produced
evidence: the D-074 fixes (pipefail on the differential step, the measured
1,000,000-record budget) were active, all five matrix jobs concluded success,
and every receipt below was read from the job logs, not inferred from the green.

**Chaos half, every seed.** All five seeds (bolina, s42, s1337, s999999,
deadbeef) report `FUZZ DONE: 14400000000 inputs (316800000000 parser calls),
0 panics` and `COVERAGE: 72/72 exit points reached`. Job walls: 2h47m15s
(deadbeef), 2h48m43s (s999999), 3h06m46s (s1337), 2h47m36s (bolina), 2h10m21s
(s42), about 13h41m accumulated this night.

**Differential half, every seed.** All five seeds report 1,000,068 records
against the 1,000,000 budget, `divergences: 0`, `coverage: 72/72 parser exit
points reached`, and `VERDICT: PASS - production parser and reference parser
agree on every record`. The bolina seed's full receipt reads 173,741 accepted
and 826,327 rejected on both sides over a 1,276,006,998-byte corpus. Because
D-074 ruling 1 put the differential step under `pipefail`, a divergence would
have failed the job; the green is the verdict, not a `tee` exit status.

**The accumulation arithmetic (D-070 ruling 2).** The ">= 24 hours" figure is
met by accumulating five seeds per night across nights, not by one
uninterrupted run. Night one contributed about 14.6 hours of chaos fuzzing
(first addendum above; 14h15m on a strict job-wall reading). Night two
contributes 13h41m. The conservative sum is 27h56m, the first addendum's own
figure gives about 28.3h; both readings exceed 24 hours with margin. The
zero-allocation clause holds structurally per D-056 ruling 5 in
DECISION-LOG.md (no parse function takes an allocator; the fuzz arena covers
setup only), so it is not re-polled here.

**One tree, two nights.** `git diff 6dfebcb..2f310b0` touches no `src/` file:
only `.github/workflows/soak.yml`, `DECISION-LOG.md`, `M1-AUDIT.md`, and
`tools/fuzz_diff.py` differ between the two heads. The parser both nights
measured is byte-identical; the differential harness differs only by the
D-074 oversize refusal.

**Section 11.6 is sealed** under the CONTRIBUTING.md vocabulary: the evidence
for the claim exists and is recorded. Every clause of the claim now has a
receipt: elapsed hours (accumulated per D-070 ruling 2), zero crashes and zero
panics (both nights, all seeds, ReleaseSafe), zero out-of-bounds reads (a
clean ReleaseSafe exit over N inputs is N inputs with no OOB access), zero
allocations (structural ruling above), coverage and corpus reported per run
(R1), and differential fuzzing per BE-SURF-04 (night two, five seeds, plus
the per-push M4 gate and the RED-TEAM-10 standalone run). The unsealed
conformance items drop from three to two: section 11.4 model checking is in
progress with an external contributor, and section 11.5 adversarial
evaluation against a real model has not been run. The first addendum's
"§11.6 stays unsealed" stands as written and is superseded here, not
rewritten. No M1 marker changes, no surface changes, no production code
changes this round. What would reopen the seal: any future nightly reporting
a panic or a differential divergence (that night's evidence is a counter-
example and the item returns to unsealed), or the owner requiring literal
continuity, which per D-070 ruling 2 needs a dedicated long-lived runner and
a separate ruling.

## D-087 F13 verify-owns-state addendum (2026-08-21)

Crypto-review finding F13 (recorded in DECISION-LOG.md D-087): GrantContext
checks 6-9 previously compared against caller-assembled fields; verify now
fetches the pending intent and sender record itself through `intent_table`
and `sender_table` references. Declared bounds correction carried by the
same ruling: the sender record's action copy is executor storage policy at
512 bytes (refused above by `ActionTooLarge` at admission), never the
256 KiB wire ceiling of `parser.channel.MAX_ACTION`; the half-landed version
of F13 sized the record from the wire ceiling, which put roughly 64 MiB
inline in the `Dispatch` value and segfaulted every by-value construction.
A regression test pins the bound (`dispatch_test.zig`, "F13: sender-record
Entry uses the executor storage bound, not the wire ceiling"). No M1 marker
changes and no new surface files (verify.zig and dispatch.zig are non-surface
per D-052/D-059/D-062/D-064); the one surface-budget change this round is
D-087 ruling 4: the F1 binding fix grew `src/binding.zig` 179 to 190, so
SPEC v0.5.1 re-floors the session-state sub-unit cap 748 to 759 and
rebalances the sync sub-unit 100 to 89 (sub-cap sum stays 1500; measured
post-authentication total 1488 of 1500). Dispatch's public refusal taxonomy
is unchanged (a grant naming no PENDING intent still refuses
`NoPendingIntent` at the seam). The 120-second store-and-forward TTL from
the F7 fix stands as written above. Mutation receipt: the full suite
re-runs at this HEAD at closeout; the receipt bump follows its clean finish.

## v0.5.2 daemon-closeout addendum (2026-08-22)

The closeout promised by the D-087 addendum above is delivered. The daemon
milestone closed under D-089: `src/keys.zig` (node key material, D-018
zeroed-key violation dead), `src/daemon.zig` (node core: type 1/4/5/6
routing, BE-TR-01 binding frame pushed inside the encrypted session both
directions, fail-closed drop on every failure path), `src/main.zig`
(env-only boot, EADDRINUSE fatal), and a two-node conformance pilot over
real loopback UDP (`pilot_test.zig`: handshake, mutual binding, Intent,
Grant, ledger commit, effect, restart orphan recovery; wrong-kex and
intent-replay rejected). No M1 marker changes (114/114, high water 114).
Surface budget unchanged: keys/daemon/main join the BE-SURF-03 non-surface
list per D-089; pre-authentication measured 1458/1500, post-authentication
1488/1500.

Mutation receipt bumped at HEAD `7fcc336` after a full non-chunked run:
162/162 non-equivalent mutants killed, 0 survived, 1 documented equivalent
(D-088), 163 evaluated. The `d089` CHECK-ABSENCE family joins the
population (MD3 flock removal, MD4 compaction removal, MD5 dedup removal;
all three killed). The run surfaced one real test gap before the clean
finish: the intent WRONG-LOGIC terminality mutant survived while MD4's
eager compaction kept REJECTED corpses beyond every lookup's reach;
`intent_test.zig` now pins the terminality filter with hand-set corpses
(`31c7a1b`) and the F4 first-receipt restart-survival property gained its
own ledger test (`7fcc336`). Suite at seal: 397 passed, 7 skipped,
0 failed. prumo-verify: all enforced gates PASS, M6 informational only.

## Post-seal addendum: D-090 closeout (2026-08-23)

The D-090 slice (BE-HIST-01 real chain validation without clock, BE-HIST-04
causal revocation via `getRevokeHash` + DAG ancestry, BE-CTRL-03
subject-expiry Revoke body) landed as five commits on 2026-08-22 with the
d090 mutation domain chunk-killed 6/6, but its closeout was interrupted
before the docs sync, the receipt bump, and the gate re-run. The continuity
watchdog converged it:

- Full non-chunked suite at the closeout HEAD: **168/168 non-equivalent
  mutants killed, 0 survived, 1 documented equivalent (169 evaluated)**,
  log `logs/mutation_final_d090.log`, receipt `tools/m2-mutation-receipt`.
  This discharges the "ONE full-suite run at final HEAD" the D-090 record
  left pending. Suite: 403 passed, 7 skipped, 0 failed.
- The closeout gauntlet caught what the interrupted session never measured:
  `zig fmt --check` flagged `listener.zig`, `daemon.zig`, and `relay.zig`
  (drift carried on main since the D-089 pilot commits), and prumo-verify
  FAILED M5/M11: the D-090 chain split had grown `binding.zig` 190 to 220,
  putting session-state at 789/759 and the post-authentication unit at
  1518/1500, and the fmt canonicalization reflowed `relay.zig` to 259/256.
- Reconciliation (D-091): fmt canonicalized (semantics untouched), then a
  comment-only compaction restored `binding.zig` to its D-087 floor of 190
  and brought `relay.zig` to 255 (stale 510-line tripwire comment replaced
  by the v0.3.5 cap sentence). No sub-unit cap moved, no file changed list,
  no SPEC text: pre-authentication reads 1460/1500 (handshake 961/990,
  relay 255/256, listener 244/250), post-authentication 1488/1500
  (wire-parser 652/652, session-state 759/759, sync 77/89), M5 and M11
  PASS, tests 403/410 identical before and after the compaction.
- M1: 114/116 bound, high water 114 held. The two missing keyed tests are
  BE-CTRL-03 (declared by D-090, literal Revoke-body fixture still owed)
  and BE-TR-01a (declared by D-089, binding-message layout fixture owed);
  both are worklist items for the next slice, not regressions.
