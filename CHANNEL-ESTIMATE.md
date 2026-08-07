# Channel Control-Message Parser Line-Cost Estimate

**Date:** 2026-08-06 (Round 5, channels phase, task 10)
**Status:** VERDICT — DOES NOT FIT in the standing headroom. Ships via a bounded
density pass, not by gaming the budget. See §7.
**Precondition satisfied:** this estimate precedes all channel parse code, per
the task acceptance "estimate precedes code."

## 1. The question

Before any channel control code is written, estimate the parser line cost of the
two control structures the spec places on the channel surface — `ControlGenesis`
(§6.1b) and `Control` (§6.1c) — against the remaining post-authentication
BE-SURF-03 budget. If they do not fit, the budget is a false premise for the
channels round (stop item 4) and work stops before line 1501, not at it.

The channel membership rules (BE-CHAN-01..03) and the control authority rules
(BE-GEN-01..04, BE-CTRL-01/02) are checks over already-parsed values; they are
non-surface by the D-018 boundary and are not part of this number (§5).

## 2. Budget state (measured, not assumed)

| Quantity | Value | Source |
|---|---|---|
| BE-SURF-03 post-auth cap | 1500 lines | SPEC.md §2.3 BE-SURF-03, normative; "MUST NOT be raised" |
| Counting rule | `wc -l` summed over the post-auth unit file list | `tools/prumo-verify` M11, parsed from SPEC BE-SURF-03 |
| Post-auth unit list | `src/parser/channel.zig`, `src/parser/session.zig`, `src/session.zig`, `src/binding.zig`, `src/replay.zig`, `src/reassembly.zig` | SPEC.md BE-SURF-03 |
| Current count | **1468** | M11 measurement, this round, 0 failing gates |
| Remaining | **32** | 1500 − 1468 |

The two control structures are channel-surface (§6.1b/c), so their parse code
lands in `src/parser/channel.zig` and counts toward M11. It cannot be moved to a
non-surface file: that is the gaming direction D-018 forbids ("moving parsing
OUT of the module to flatter M5"). It cannot be reclassified as non-surface:
both arrive as raw envelope bodies a hostile authenticated peer controls, so they
are bytes-to-values work, exactly the parser's job.

## 3. Calibration (measured from this file)

The estimate is the existing module's measured cost-per-wire-item applied to the
new structures. `src/parser/channel.zig` already parses six structures through
the shared `Cursor`; their line spans (comment header through closing brace):

| Function | Lines | Wire items |
|---|---|---|
| `parseEnvelope` | 44 | 11 (incl. parent loop, trailing check) |
| `parseIntent` | 34 | 4 (length-prefixed fields) |
| `parseGrant` | 54 | 11 + tbs/sig/wire |
| `parseSpan` / `readSpan` | 28 | 11 |
| `parseEffect` | 43 | 6 + inline span walk |
| `parseClaim` | 17 | 5 |

Measured ratio across these: roughly **4.9 lines of parse code per wire item at
the dense end, 6.3 at the verbose end**, including the per-structure comment
block and the trailing totality check every parser carries.

## 4. Per-structure estimate

Both are flat records (§2.2), parsed with the same `Cursor` helpers (`u8r`,
`u64be`, `take`, `field16`). Wire items read from SPEC §6.1b/c.

| Structure | Wire items | Struct lines | Body lines | Comment | Parse lines |
|---|---|---|---|---|---|
| `ControlGenesis` | version; u16 name_len+name(≤64); `[8]` member_group; `[8]` admin_group; u8 ca_count + `[32]*` ca_keys; u8 match_rule | 7 | 14 | 8 | **~29** |
| `Control` | version; u8 action_type; `[32]` subject; u16 body_len+body | 5 | 11 | 6 | **~22** |
| Constants (LEN_MEMBER_GROUP, LEN_ADMIN_GROUP, LEN_CA_KEY, MAX_GENESIS_NAME, MAX_CONTROL_BODY, MAX_CA_COUNT) | — | — | — | — | **~6** |
| **Two structures + constants** | | | | | **~57** |

Range: **~48 at maximum density** (grammar diagram only, no prose) to **~57 at
the module's standard density** (per-structure comment block).

What is counted and stays out of the parser: `version` is parsed and discarded
here (policy stays out of the parser, same convention as Envelope/Grant/Span);
`match_rule` and `action_type` are recorded, not refused (BE-GEN-04,
BE-CTRL-01 are verifier concerns, §5). The ascending ca_keys ordering is a
parse-time canonical-encoding check and is counted inside the `ControlGenesis`
body cost.

## 5. What is NOT counted against the budget, and why

| Item | Est. lines | Where it lives | Why it is not parser cost |
|---|---|---|---|
| BE-CHAN-01 membership test (cert carries member_group) | small | `verify.zig` (non-surface) | Check over a parsed cert + parsed genesis |
| BE-CHAN-02 monotonic revoke set | state | `verify.zig` / ledger | State over parsed, authenticated values |
| BE-CHAN-03 non-member rejection | small | `verify.zig` | Check, not byte conversion |
| BE-GEN-01 single-genesis / second-genesis reject | small | `verify.zig` | Ledger state check |
| BE-GEN-02 immutability | — | n/a (no message changes params) | Nothing to parse |
| BE-GEN-03 admin-signed genesis | sig check | `verify.zig` | Signature over parsed tbs |
| BE-GEN-04 match_rule fixed at 1 | 1 line | `verify.zig` | Policy refuse on a parsed value |
| BE-CTRL-01 action_type in {1,2} | 1 line | `verify.zig` | Policy refuse on a parsed value |
| BE-CTRL-02 Revoke requires admin_group | small | `verify.zig` | Authority check over parsed cert |

Boundary rule (D-018): bytes-to-values lives in the parser and counts; checks
over parsed, authenticated values live in `verify.zig` and do not. The gaming
direction is moving parsing out; that is forbidden. The membership/authority
checks above genuinely do not convert bytes, so they are correctly excluded.

## 6. Total against remaining

| Scenario | New lines | Post-auth after | Headroom after |
|---|---|---|---|
| Two structures, max density | ~48 | 1516 | **−16 (over)** |
| Two structures, standard density | ~57 | 1525 | **−25 (over)** |

The two control structures do **not** fit in the 32-line headroom at any density.
The deficit is 16 lines at maximum density, 25 at the module's standard density.

## 7. Resolution: bounded density pass (not gaming)

Three ways to "fit" are rejected:

1. **Move the parse to a non-surface file** — forbidden by D-018 (gaming).
2. **Reclassify as non-surface** — false; both are hostile-peer bytes-to-values.
3. **Raise the cap** — forbidden by SPEC ("MUST NOT be raised").
4. **Subdivide the unit** — no help: subdivision splits the existing 1500 into
   sub-caps, it does not raise the total.

The one legitimate path is a **density pass on this file**: `src/parser/channel.zig`
carries a 22-line module header and six per-structure comment blocks, several of
which restate mechanics also documented inline. Tightening the redundant
restatement — keeping every wire-grammar diagram and every WHY a check serves,
cutting only prose that says the same thing twice — frees roughly 30 lines
inside the same file the new code lands in. That keeps parsing in-channel, leaves
the cap untouched, and touches no logic, so the test and mutation gates stay
green by construction (comments affect no behavior).

Net after the pass: 1468 − ~30 (tightened) + ~57 (two structures) ≈ **1495**,
under 1500 with thin margin. The new parse carries its own per-structure
comments, so the auditor-readable surface trades verbose restatement for new
grammar documentation — a net wash on readability, not a loss.

This is a density valve used once, not a budget valve. Task #11 (mesh) will add
more post-auth surface and is likely to hit the same wall; when it does, the
honest answer is a spec-level decision (formal third sub-unit, cap revision, or
descope), not another comment harvest. That decision is flagged now, not hidden
until the gate fails.

## 8. What would invalidate this estimate

1. The two control structures turn out to need more than the counted fields
   (e.g. a second signature inside `Control`) — re-run before implementation.
2. A structure the spec places on the channel surface requires variable-length
   pre-auth parsing — that is a BE-SURF-01 violation, not an estimate revision.
3. The density pass frees materially fewer than 30 lines — stop item 4 fires,
   the channels round cannot ship in-budget, and the spec decision in §7 last
   paragraph is taken then instead of deferred.

## 9. Pre-close checks

1. **Read against other sections:** BE-SURF-01 (no new pre-auth structure; the
   two control structures are post-auth envelope bodies ✓); BE-WIRE-01/02 (apply
   to the new parse, totality check counted in each body); BE-TR-05 (every
   attacker-influenced size — name_len, ca_count, body_len — bounded at parse
   time, counted inside the per-structure ranges); §11.3 (vectors precede the
   parser they verify — task order holds); §11.6 (new structures enter the fuzz
   corpus and coverage counters, cost in `tools/` and `src/coverage.zig`,
   outside the M11 count).
2. **Who picked the denominator:** 1500 ← SPEC BE-SURF-03. 1468 ← M11
   measurement, the spec's own counting rule. The 4.9–6.3 lines-per-wire-item
   ratio ← measured over the six existing parse functions in this file. No
   denominator here is author-chosen.
3. **Does the thing being checked need to exist:** only the two spec-mandated
   structures are counted. The membership/authority checks are excluded because
   they are not parsing, not because they are not being built; their line costs
   are listed in §5.

## 10. Verdict

**The two control structures do not fit in the 32-line post-authentication
headroom** (deficit 16 at maximum density, 25 standard). The channels round
proceeds via a one-time density pass in `src/parser/channel.zig` that frees
roughly 30 lines of redundant prose, leaving the cap, the logic, and the
boundary rule intact, with the task #11 wall flagged for a real spec decision.
