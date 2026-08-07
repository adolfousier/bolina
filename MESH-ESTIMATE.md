# Mesh Verification Layer Line-Cost Estimate

**Date:** 2026-08-07 (Round 5, mesh phase, task 11)
**Status:** VERDICT — FITS. The 7-line post-authentication wall flagged in
`CHANNEL-ESTIMATE.md` §7 and D-036 **does not fire for this task**, for a
reason that invalidates the prediction rather than escaping it. See §3.
**Precondition satisfied:** this estimate precedes all mesh verification code,
per the task acceptance "estimate precedes code."

## 1. The question

D-036 closed with a standing warning: task 11 (mesh) "faces the same wall and
will need a real SPEC decision (split the post-auth unit, or raise the cap with
a justified re-baseline), not another comment harvest." M11 stands at 1493/1500
with **7 lines of headroom**, measured live this round. If mesh adds post-auth
surface, the round cannot ship without a spec-level decision.

So the question is not "how many lines does mesh cost." It is: **does mesh add
post-authentication surface at all?**

## 2. Budget state (measured, not assumed)

| Quantity | Value | Source |
|---|---|---|
| BE-SURF-03 post-auth cap | 1500 lines | SPEC.md §2.3, normative; "MUST NOT be raised" |
| Current post-auth count | **1493** | `tools/prumo-verify` M11, this round, 0 failing gates |
| Remaining headroom | **7** | 1500 − 1493 |
| Post-auth unit files | `binding.zig` 189, `parser/channel.zig` 430, `parser/session.zig` 290, `reassembly.zig` 247, `replay.zig` 114, `session.zig` 223 | M11, list parsed from SPEC BE-SURF-03 |
| `src/verify.zig` classification | **Non-surface** | SPEC.md line 247: "`src/dag.zig`, `src/evidence.zig`, `src/verify.zig` — state over parsed values" |

`verify.zig` (337 lines) appears in neither the M5 nor the M11 file list. It is
not unbudgeted by oversight; BE-SURF-03 classifies it out explicitly.

## 3. Why the predicted wall does not fire

Two measured facts, either of which alone settles it:

**(a) The mesh wire parsers already exist and are already counted.**
`parseLookupRequest`, `parseLookupResponse` and `parseFragmentHeader` are in
`src/parser/session.zig` today, with their exit points already in the M9
denominator (`lookup_req_trailing`, `lookup_req_accepted`,
`lookup_resp_trailing`, `lookup_resp_accepted`, `frag_*`). Their cost is inside
the 1493 already measured. Task 11 adds **no new parse code**.

**(b) The remaining mesh obligations are checks over parsed values.**
BE-MESH-04/05/06 compare an already-parsed certificate against an
already-parsed address, run an already-existing signature chain, and consult a
caller-supplied revocation hook. That is the textbook D-018 non-surface
description, and it lands in `verify.zig`.

D-036's warning was written from the channels round, where the new work *was*
bytes-to-values in a budgeted file. It generalised that shape to mesh without
checking mesh's parser inventory. The generalisation was wrong. Recording that
plainly is cheaper than a spec decision taken on a false premise.

**The boundary is load-bearing in the other direction, and it constrains the
design.** The obvious API for BE-MESH-04 is "hand the verifier
`LookupResponse.cert` (raw bytes) and let it parse." That is rejected: it would
move bytes-to-values work into an unbudgeted file, which is precisely the D-018
gaming direction ("moving parsing OUT of the module to flatter M5/M11"). The
verifier therefore takes an already-parsed `Cert` and the requested
`overlay_addr`, matching every other verifier in the module. The caller runs
`parser.session.parseCert`, whose failure is an unavoidable error union, so the
"discard on parse failure" half of BE-MESH-04 is enforced by the type system at
the call site rather than by a duplicated parse.

## 4. Rule-by-rule scope (all seven, including what gets no code)

| Rule | Obligation | This task |
|---|---|---|
| BE-MESH-01 | Lighthouse is availability, never authority; verify the peer cert regardless of which lighthouse suggested it | **Code + test.** Enforced structurally: the verifier takes no lighthouse identity parameter, so it cannot condition acceptance on the suggester |
| BE-MESH-04 | Verify served cert under BE-ID-01..04 before use, discard on any failure | **Code + test.** The core of this task |
| BE-MESH-05 | Served cert opens the session and confers nothing | **Code + test.** The continuation receives only `{sig_pubkey, kex_pubkey}`; no role bits, groups or name cross the boundary, and a reflection test fails if a field is added |
| BE-MESH-06 | MAY cache; MUST re-verify validity window and revocation on every use, not at cache-fill time | **Code + test.** Verification is a call, not a value: `now_ms` and the revocation hook are parameters of the use, so no cacheable "verified" value exists |
| BE-MESH-07 | Lookups travel inside an established session, never parsed from unauthenticated input | **No code.** Already satisfied by placement: the lookup parsers live in the post-auth unit, and the pre-auth unit (`mac.zig`, `noise.zig`, `parser.zig`) does not reach them. Not re-asserted here |
| BE-MESH-02 | Relay forwards Noise transport, holds no key material | **Out of scope.** No relay exists in this slice |
| BE-MESH-03 | Relay MAY store ciphertext under quota and TTL | **Out of scope.** No relay exists in this slice |

Three of seven rules get no code this task. Two are unimplementable without a
relay that does not exist; one is already satisfied by file placement. Stating
that is the point: "mesh done" would be false, and the M1 bijection would have
caught the lie at the next ratchet anyway.

## 5. Line cost

| Item | File | Est. lines | Counts against M11? |
|---|---|---|---|
| `MeshError` (3 members) | `verify.zig` | ~5 | No (non-surface) |
| `MeshContext` (trusted set, now_ms, revocation hook) | `verify.zig` | ~6 | No |
| `SessionKeys` (2 fields) | `verify.zig` | ~4 | No |
| `verifyServedCertThen` body + comment block | `verify.zig` | ~30 | No |
| Tests | `verify_test.zig` | ~90 | No (tests never counted) |
| **Total** | | **~45** | **0 against M11** |

Post-auth count after this task: **1493, unchanged.** Headroom: **7, unchanged.**

## 6. Gate interactions checked before writing code

1. **M10 (call-graph wall)** is a raw token grep for `execute\(` with a
   denominator of exactly 1, resolved at run time. This task adds a *second*
   continuation-passing verifier to `verify.zig`. Naming its callback `execute`
   would fail M10 on the first run. It is named `open_session`, which is also
   the honest name: a session-open continuation is not a grant effect and
   confers no authority (BE-MESH-05), so M10's guarantee is untouched.
   **Observation, not fixed here:** because M10 matches a token and not a
   function identity, a future grant-effect callback named anything but
   `execute` would evade it. That weakness pre-exists this task but this task is
   the first to make it reachable. Tightening M10 to a scoped check is a SPEC
   decision, logged in D-037, not smuggled into a mesh commit.
2. **M9 (coverage denominator)** counts parser exit points. No parser changes,
   so M9 stays at 56 and `coverage.zig` is untouched.
3. **M1 (BE ↔ test bijection ratchet)** stands at 44/110, high water 44. New
   tests named `BE_MESH_01/04/05/06` advance the ratchet; the high-water file
   must be advanced in the same round or M1 under-reports.
4. **M8 (no pointer-minting builtins)** — the continuation is a plain function
   pointer, no `@ptrCast`/`@ptrFromInt`. Unchanged at 0.
5. **D-027 (a test MUST NOT reference the constant it verifies)** — the address
   tests recompute BLAKE2s independently rather than calling
   `binding.deriveOverlayAddr`, matching the existing `BE_ID_01` test's pattern.

## 7. What would invalidate this estimate

1. A mesh obligation turns out to need a wire structure not already parsed
   (would land in `parser/session.zig` and hit the 7-line wall immediately, at
   which point the D-036 spec decision fires for real).
2. Revocation at session-open time requires a state structure rather than a
   caller hook — that is `evidence.zig`/ledger work, still non-surface, but a
   larger design than this estimate covers.
3. `verify.zig` is reclassified into the post-auth unit by a spec revision, at
   which point every number here is void and the whole file (337 lines) blows
   the cap on its own.

## 8. Pre-close checks

1. **Read against other sections:** BE-SURF-01 (no new pre-auth structure ✓);
   BE-SURF-03 (no post-auth line added ✓); D-018 (parse stays in the surface
   module, §3 ✓); BE-ID-01..04 (reused, not reimplemented ✓).
2. **Who picked the denominator:** 1500 ← SPEC BE-SURF-03. 1493 ← M11's own
   measurement under the spec's counting rule. The non-surface classification ←
   SPEC.md line 247, not author choice. No denominator here is self-selected.
3. **Does the thing being checked need to exist:** the four in-scope rules are
   spec-mandated; the three out-of-scope ones are named rather than quietly
   dropped.

## 9. Verdict

**FITS, with zero post-authentication cost.** The mesh verification layer is
non-surface work in a non-surface file; M11 stays at 1493/1500 and the 7-line
wall is not touched. D-036's prediction of a task-11 wall was drawn from the
channels round's shape and is withdrawn here on measurement, not argued around.
Four of seven BE-MESH rules ship with code and tests; three are named as
out-of-scope with reasons.
