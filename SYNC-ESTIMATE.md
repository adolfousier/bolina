# SYNC-ESTIMATE.md — backfill slice (BE-SYNC-01..05), 2026-08-10

Estimate-first per §13 of POSTAUTH-ESTIMATE.md: the sync surface touches the
M11 post-authentication line budget, so budget and placement are measured and
decided BEFORE any code. Status: PROPOSED, awaiting D-055 ruling.

## 1. Scope

Five markers, SPEC §6.4 (Backfill):

- BE-SYNC-01: SyncRequest refused outside an established session (BE-TR-01)
  whose peer is a member of channel_id and not revoked.
- BE-SYNC-02: response bounded by min(max_envelopes, 64) and 1 MiB, truncated
  flag set on stop, responder stateless between responses.
- BE-SYNC-03: unknown-parent resolution via explicit work queue, depth ≤ 128,
  total envelopes examined ≤ 4096, stop + surface + no auto-retry on
  exhaustion (BE-DEP-02 forbids the recursive walk).
- BE-SYNC-04: per-peer rate limiting in both directions with a DECLARED
  budget (the numbers are owed to SPEC, see §5).
- BE-SYNC-05: every backfilled envelope passes the same verification as a
  live one (verifyEnvelope: BE-ENV-02 signature, BE-ENV-03 role, BE-CHAN-03
  membership, parent-hash consistency) before entering the local ledger.

## 2. What SPEC already declares (no wire edits owed)

SyncRequest/SyncResponse shapes are fully declared in §6.4:

    SyncRequest  := u8 version ; [32] channel_id ; u8 have_count ; [32]* have_hashes (≤ 64)
                    u16 max_envelopes (≤ 64)
    SyncResponse := u8 version ; [32] channel_id ; u8 envelope_count ; (u32 len, bytes)*
                    u8 truncated

They are SESSION messages, not channel messages: no parents, never in the
ledger, never fanned out. No body_type change, no BE-SURF-01 edit.

## 3. Budget arithmetic (the wall)

Measured now at main HEAD 5ae9d96 (prumo-verify):

- M11 post-auth unit: 1400/1500 total cap.
- wire-parser sub-unit: 652/723.
- session-state sub-unit: 748/748 (zero headroom by D-052 ratchet).
- Remaining surface headroom: 1500 - 1400 = 100 lines, TOTAL.

The sync wire parser is surface by nature (it reads attacker-controlled
bytes). Everything else (work queue walk, rate limiter, response builder,
verify-before-adopt glue) is state over parsed values and goes non-surface.

Parser size prediction: SyncRequest ~35-45 lines, SyncResponse ~45-55 lines,
bounds checks included: 80-100 lines. It fits the remaining 100 measured
lines with zero to twenty lines of slack. This is the tightest budget of any
slice so far.

Enforcement mechanics, verified from tools/prumo-verify (lines 221, 273-280):
the unit total binds on MEASURED lines (POST_AUTH_LINES ≤ 1500); each
sub-unit binds its own measured lines against its declared cap; M5
additionally enforces handshake-cap + relay-cap ≤ unit-cap, and M11 has no
equivalent cap-sum check today.

Decision owed (D-055): declare the sync sub-unit and rule on cap-sum
consistency (see §5.1). If measured overruns 100, the slice STOPS and
renegotiates via a new decision with justification. Caps never rise quietly.

## 4. Placement

- src/parser/sync.zig (surface, new sync sub-unit, cap 100): parse functions
  for SyncRequest and SyncResponse only.
- src/sync.zig (non-surface, pre-placed via BE-SURF-03 edit): SyncEngine with
  the work queue (depth/total budget counters), per-peer rate limiter,
  response builder (min(max_envelopes,64) and 1 MiB binding, truncated flag),
  and the adopt path that calls verify.verifyEnvelope before ledger entry.
  Prediction 250-350 lines, zero M11 cost.
- Reuse, never re-implement: verify.verifyEnvelope (line 100) for BE-SYNC-05,
  verify.requireMember (line 401) plus the session-established check for
  BE-SYNC-01, ledger revocation ordering for the not-revoked clause.

## 5. Owed SPEC edits (D-029 pre-flag, own commit before code)

1. BE-SURF-03: declare the sync sub-unit. Two constraints interact:
   (a) Measured, binding either way: parser ≤ 100 measured lines
   (1400 + parser ≤ 1500).
   (b) Cap-sum precedent: M5 enforces sub-unit caps summing to at most the
   unit cap; applying the same discipline to M11 caps sync at 1500 - 723 -
   748 = 29 lines, below any realistic parser. D-055 rules between: enforce
   cap-sum consistency and renegotiate the M11 total cap under D-030 rules
   (proposal: 1500 to 1600, justified by the declared sync surface), or
   declare sync at cap 29 and fail by construction. Recommendation:
   justified renegotiation, never a quiet raise. No code before the ruling.
2. BE-SURF-03 non-surface list: add src/sync.zig.
3. §6.4 BE-SYNC-04: declare the rate budget numbers. Proposal: serve ≤ 8
   requests per peer per 10 s, issue ≤ 4 requests per peer per 10 s (worst
   case 8 serves x 64 envelopes x 1 MiB per 10 s per peer stays inside the
   response bounds; numbers adjustable only by decision).

## 6. Binding plan per marker

- BE-SYNC-01: literal test, request outside session / non-member / revoked
  peer refuses; session + member + unrevoked admits.
- BE-SYNC-02: literal test, response at min(max_envelopes,64), at 1 MiB,
  truncated set exactly when either binds; responder retains no state.
- BE-SYNC-03: literal test, walk stops at depth 128 and at total 4096,
  surfaces unresolved-history, never retries (a recursion attempt cannot
  compile past the explicit queue shape).
- BE-SYNC-04: literal test, the 9th served request inside the window
  refuses; the window slides; issue side symmetric.
- BE-SYNC-05: literal test, a backfilled envelope with a bad signature /
  wrong role / non-member sender / bad parent hash is refused exactly as
  the live path refuses it (same verifyEnvelope error).

## 7. Mutation plan

harness v15: sync domain, ~10 mutants keyed to the five markers (bounds
off-by-one on 64 and 1 MiB, truncated flag pinned, depth/total budget
comparisons flipped, retry-on-exhaustion reintroduced, rate window widened,
verify-before-adopt skipped, session/membership precondition removed).
Chunked run first (D-035), zero-residue check (the 2026-08-10 lesson), then
the full suite.

## 8. Slice order

D-055 ruling → SPEC edits (one D-029 commit) → sync.zig engine + parser +
literal tests → ratchet 102→107 with the tests → harness sync domain →
chunked + full suite → docs sync → push → closeout.

## 9. Risks

- The §5.1 conflict is the dominant risk: 29 lines is likely unachievable
  for two bounded wire parsers; D-055 must choose between an engineering
  squeeze and a justified total-cap renegotiation BEFORE any code.
- Zero-slack tripwires are fragile: any unrelated post-auth surface work
  after this slice has no room until the next renegotiation.
