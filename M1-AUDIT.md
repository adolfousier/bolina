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

### C1. Mesh relay (M2 mesh slice)

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-MESH-02 | Relay forwards Noise transport packets, holds no key material, cannot decrypt | No relay code. M2. |
| BE-MESH-03 | Relay MAY store forwarded ciphertext for an offline recipient under quota + TTL | No relay code. M2. |

### C2. Sync / backfill (sync slice)

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-SYNC-01 | SyncRequest MUST be refused outside an established session | No sync code. |
| BE-SYNC-02 | Responder returns at most `min(max_envelopes, 64)`, max 1 MiB | No sync code. |
| BE-SYNC-03 | Walk budget: max depth 128, max 4096 envelopes | No sync code. |
| BE-SYNC-04 | Rate-limit both requests served and issued | No sync code. |
| BE-SYNC-05 | Every backfilled envelope passes the same verification as a live one | No sync code. |

### C3. Ledger, DAG, history (ledger slice)

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-LEDGER-01 | Member MUST reject an envelope whose `parents` reference unknown hashes within a bounded fetch, and surface a divergence | `dag.zig:insert` just interns unknown parents (creates them); there is no fetch boundary and no divergence event. Needs the ledger store. |
| BE-LEDGER-02 | Ledger stores hashes, never plaintext; a head hash MAY be published externally | No persistent ledger; `dag.zig` is an in-memory causal graph. |
| BE-LEDGER-03 | Every Grant and Effect MUST appear in the ledger | No persistent ledger. |
| BE-HIST-01 | The BE-ID-02 clock check governs admission, not audit; an expired cert cannot authorise new things but can prove what it signed | No separate audit path. |
| BE-HIST-02 | A signer's cert MUST be anchored in the channel before first use, by a Control envelope | No channel state storage. |
| BE-HIST-03 | An envelope is historically valid iff it is a causal descendant of the anchoring envelope and NOT a descendant of a revocation | `dag.zig` has `isAncestor`/`supersedes` BFS but no revocation integration. |
| BE-HIST-04 | Revocation takes effect for admission immediately, for audit at its causal position | No revocation + causal integration. |

### C4. Envelope equivocation + replay (needs the divergence surface)

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-ENV-05 | A second envelope with a different hash at the same `(sender, channel, seq)` MUST raise a divergence event, never be dropped as a routine duplicate | Depends on the same divergence surface as BE-LEDGER-01 (SPEC cross-references it). A same-hash duplicate is dropped silently; a different-hash one never is. Needs the divergence event + hash-compare dedup. Ledger slice. |
| BE-ENV-04 | Per-`(sender, channel)` sliding acceptance window over `seq`, same shape as BE-TR-03 | `replay.zig` implements the transport window (`BE_TR_03`). **Confirm during keying** whether the same window is applied at the envelope layer; if yes, reclassify KEY-NOW; if not, NEEDS-CODE. |
| BE-ENV-03 | Receiver MUST reject an envelope whose sender cert lacks the role for its `body_type` | Role checks happen at cert validation (`binding.zig`) but a `body_type` -> role map may not be enforced. **Confirm during keying**; reclassify KEY-NOW if present, else NEEDS-CODE. |

### C5. Grant lifecycle that needs a pending table or refusal handler

| Marker | Requirement | Status |
|--------|-------------|--------|
| BE-GRANT-06 | Executor MUST refuse a second Intent whose `resource_id` is already PENDING or EXECUTING | Needs a pending-intent / resource-lock table; verify exposes it as a hook only. |
| BE-GRANT-06b | Executor MUST refuse an Intent whose `intent_id` equals one already PENDING | Needs the pending-intent table. |
| BE-GRANT-09 | Refusal semantics: `body_type=6`, `Refusal.sig` verifies, sender has approver role, `intent_id` names a pending intent | Refusal is parsed but not verified in this slice. Needs a refusal verifier. |
| BE-REV-01 (duration half) | Approver/executor certs MUST have `not_after - not_before <= 30 days` | `binding.zig:148` checks the validity window but not the 30-day duration cap separately. Small code addition; could be a keying-pass micro-fix or a NEEDS-CODE marker. Decision in task #2. |
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
