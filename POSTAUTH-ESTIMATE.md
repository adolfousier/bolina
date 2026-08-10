# POSTAUTH-ESTIMATE.md

## 1. The question

The M1 ratchet stands at 87/109. The 22 missing markers are 21 NEEDS-CODE plus
one deferred MAY (MESH-03, Daniel's call per D-051). Every one of the 21 sits
behind the M11 wall: the post-authentication unit measures 1497/1500 lines,
three lines of headroom. KEYING-AUDIT.md projected that "a D-030 budget
subdivision, exactly like the relay round got (D-043)" unblocks them. This
estimate costs the 21 markers against the cap, tests that projection against
the arithmetic, and names the levers that actually exist. Estimate before line
one of code, per the standing rule.

## 2. Budget state

Measured this session at `c0b385e` (main == origin/main), `PRUMO=1 tools/prumo-verify`:

| File | Lines |
|---|---|
| binding.zig | 193 |
| parser/channel.zig | 430 |
| parser/session.zig | 290 |
| reassembly.zig | 247 |
| replay.zig | 114 |
| session.zig | 223 |
| **Total** | **1497 / 1500, headroom 3** |

M11 counts `wc -l` per file (tools/prumo-verify `surf_unit_lines`), physical
lines. Denominator 1500 parsed from SPEC BE-SURF-03; lists and cap are
normative, moving a file between lists is a D-029-flagged spec change.

## 3. Placement analysis (the hinge)

BE-SURF-03's own rationale draws the line: the post-auth unit is "everything
an auditor must read to verify what a hostile authenticated peer's bytes can
reach"; the non-surface list is "state over parsed values (D-018), not reached
by attacker bytes directly". verify.zig, ledger.zig, historical.zig sit
non-surface while being driven by hostile-peer envelopes, because they consume
parsed, bounds-checked structures. That precedent (D-045/D-047) classifies all
21 markers:

| Work | Layer | Placement | Counts vs M11 |
|---|---|---|---|
| Refusal wire parser (body_type 6) | bytes to values | parser/channel.zig | YES, 20-35 |
| SyncRequest/SyncResponse parsers | bytes to values | parser/session.zig | YES, 45-70 |
| Pending-intent state machine (table, transitions, locks, restart collapse) | values to decisions | non-surface (ledger.zig class) | NO |
| Refusal verification (sig tag 0x06, approver role, pending match) | values to decisions | verify.zig | NO |
| Resource resolver (grammar, canonical form, executor_fp, alias collapse) | values to decisions | non-surface | NO |
| Approving-interface render contract | values to decisions | non-surface | NO |
| Sync walker (queue, budgets, rate, verify-before-adopt) | values to decisions | non-surface | NO |
| Differential fuzz oracle + reference parser | harness | fuzz.zig | NO |

Consequence: M11 owes only the three new wire parsers, 65-105 lines median 85,
against 3 lines of headroom. The other 16 markers cost zero surface lines.

## 4. Itemized estimate

Calibration from RELAY-ESTIMATE section 3: parser items estimate accurately
(bounded by fixed wire formats), non-parser items ran 1.9-3.5x over raw
estimates (median 2.7x). The ranges below are already widened by that history;
density references are this repo's actuals (ledger.zig 236 lines for 10
markers, verify.zig 182, evidence.zig 258).

| Group | Markers | Placement | Lines | Basis |
|---|---|---|---|---|
| Pending-intent state machine | GRANT-01a, 04, 06, 06a, 06b, 09 (parse half excluded), 10 | non-surface intent.zig | 150-260 | ledger density 236/10 markers; states PENDING/EXECUTING/EXPIRED/REJECTED, resource lock, intent_id dedupe, T_pending 900s timer, restart collapse, lock release on every exit |
| Refusal verification | GRANT-09 (verify half) | verify.zig grows | 25-45 | verifyGrant template exists; sig tag 0x06 (DOMAIN_REFUSAL already declared), approver-role check, pending-match hook |
| Refusal wire parser | GRANT-09 (parse half) | parser/channel.zig grows | 20-35 | fixed fields [16] intent_id, u16 note_len + note <=1 KiB, [64] sig; same shape as parseClaim (bounded, one totality check, 2-3 new coverage arms) |
| Resource resolver | RES-01..06 | non-surface resolver.zig | 90-140 | grammar walk over [a-z0-9-._/] with segment rules (50-80), executor_fp = BLAKE2s-256(sig_pubkey)[0..8] (10), alias collapse into the lock (20-30), canonical emit (10-20); pure functions, zero allocation |
| Render contract | GRANT-07, 07a | non-surface render.zig | 40-80 | pure function over verified Intent: canonical resource_id + full action bytes + digest recomputed from displayed bytes; rationale marked untrusted and subordinate |
| Sync parsers | SYNC-01..05 (parse half) | parser/session.zig grows | 45-70 | SyncRequest fixed+bounded (have_count <=64, max_envelopes <=64): 20-30; SyncResponse with (u32 len, bytes)* walk and truncated flag: 25-40 |
| Sync walker | SYNC-01..05 (state half) | non-surface | 130-230 | work queue depth <=128 total <=4096, both-direction rate limits, verify-before-adopt wiring into the existing verify path |
| Differential fuzz oracle | SURF-04 | harness fuzz.zig | 200-400 | independent minimal reference parser over the post-auth wire shapes plus divergence glue; M4 moves PENDING to PASS |
| Binding tests | all 21 | harness *_test.zig | 400-800 | 2-3 literal-value tests per marker (D-027), the bijection binds by name |

Surface debt total: 65-105 (median 85). Non-surface new code: 635-1155.
Harness: 600-1200. Only the surface column touches M11.

## 5. Slim potential audit (measured, not vibed)

All six files were read line by line this session. Findings:

- No dead code, no duplicated logic. Cursor, ParseError, and the limits are
  shared through parser.zig; every parser is distinct wire grammar.
- Comments: 493 of the 1497 lines. They are SPEC citations and crypto decision
  rationale (session.zig's two "a round-trip test cannot tell the wrong choice
  from the right one" decisions, replay.zig's RFC 6479 construction notes).
  They are the auditor's reading of the unit. Deleting them would trade the
  budget number against the unit's stated purpose. Not a lever.
- Genuine code slim: approximately zero without behavior loss. The one
  defensive "unreachable" return (session.zig admit) is deliberate.

The one real lever is FORMATTING DENSITY, measured file by file:

| Lever | Where | Lines |
|---|---|---|
| Multi-line struct initializers compacted to <=100-col lines (parseEnvelope, parseGrant, readSpan, parseEffect, parseCert, parseLookupResponse, parseFragmentHeader, SessionTable admit/init) | parser files + session.zig | ~48-58 |
| Dash banner separator lines removed, headings kept | channel 16, parser/session ~12, binding ~14, reassembly ~4 | ~46 |
| **Total** | | **~94** |

Honest classification: compaction changes physical lines, not tokens and not
complexity. M11 measures wc -l as a proxy for audit load; compaction does not
shrink audit load. It is a budget lever, not a complexity reduction, and D-052
records it under that label rather than pretending otherwise. The alternative
is that no post-auth surface work ever fits, which contradicts the project
mandate. Guardrails: no comment deletion, no behavior change, full gauntlet at
the compaction commit, compaction lands as its own atomic commit before any
new surface code.

## 6. Readings and verdicts

Available budget = headroom 3 + compaction ~94 = ~97 lines.

**Reading 1: full scope, no levers.**
1497 + 85 (median; worst 105) = 1582-1602 against 1500.
Verdict: DOES NOT FIT.

**Reading 2: subdivision alone (the KEYING-AUDIT projection).**
Subdivision preserves the sum: sub-unit caps must add to 1500. The new surface
code lands in files already at their measured totals, so any sub-unit growth
must be paid by shrinking a sibling below measured, which requires the slim
anyway. Subdivision creates zero slack by itself; it is the recording
mechanism for a fix, not the fix.
Verdict: DOES NOT FIT. This corrects the KEYING-AUDIT assumption, same defect
class as the RELAY-ESTIMATE arithmetic correction: recorded where a reader
will find it, not silently overwritten.

**Reading 3: scope cut, refusal-only surface (sync deferred), compaction.**
Surface debt 20-35 against available ~97. Unit lands at 1424-1439 after
compaction and refusal, ~61-76 lines of headroom banked for later slices.
Verdict: FITS with wide margin. This is the fallback reading.

**Reading 4 (recommended): full scope, compaction, subdivision.**
Projected measured after compaction ~1403. Plus surface debt: median 1488
(margin ~12), worst 1508 (over by ~8). Subdivision ratchets the sub-units to
post-compaction measured totals so the tripwire, not optimism, governs the
worst case.
Verdict: FITS at median, TRIPWIRED at the worst case, exactly the shape D-043
accepted for the relay. If the wire-parser sub-unit hits its cap before the
sync parsers are done, sync defers to M2 (Reading 3 fallback) and its budget
reading is redone when it lands. Never raise.

## 7. Subdivision shape (D-043 form)

After the compaction commit, BE-SURF-03 gains two sub-units under the
post-authentication cap:

| Sub-unit | Files | Cap rule |
|---|---|---|
| Wire-parser sub-unit | parser/channel.zig, parser/session.zig | 1500 minus the session-state cap (projected ~749; measured ~636 at compaction time, so the refusal 20-35 and sync 45-70 land inside it) |
| Session-state sub-unit | session.zig, binding.zig, replay.zig, reassembly.zig | Ratcheted to measured total at the compaction commit, zero growth (projected ~751) |

Sum exactly 1500. Nothing raised. Numbers ratchet at the SPEC-edit commit from
fresh `wc -l`, never from this estimate's projections.

Tripwires:
1. Wire-parser sub-unit at cap before the refusal parser is done: stop, slim
   or shrink the parser shape, never raise.
2. Wire-parser sub-unit at cap before the sync parsers are done: sync defers
   to M2 (Reading 3), same "slim or defer, never raise" rule D-043 applied to
   store-and-forward.
3. Any bytes-to-values code found in a non-surface file: placement violation,
   stop and flag as a D-029 spec change before the next commit. Reclassifying
   to escape measurement is the gaming D-043 rejected.
4. Session-state sub-unit at cap: the state-machine slices (intent, resolver,
   render) live in NEW non-surface files, so this tripwire should never arm;
   if it does, something was placed wrong, treat as tripwire 3.

## 8. Sync deferral contingency (Daniel's call if the tripwire fires)

Backfill is not labeled MAY anywhere in SPEC; §6.4 describes it as what a
member that joins late or sees an unknown parent "needs", and lines 1029,
1054, 1150, 1592 reason as if backfill exists. The SYNC markers are
MUST-within-feature. But no sentence obligates an implementation to ship
backfill in M1, and the M11 arithmetic above shows it is the marginal item.
If tripwire 2 fires, sync defers exactly as MESH-03 deferred: conformant
deferral with the ratchet ceiling stated (M1 ceiling 104/109 instead of
109/109 while sync is out), and Daniel owns the call as he owns MESH-03 under
D-051. The estimate does not make that call now; the median reading ships sync
inside M1.

## 9. Rejected alternatives

1. Raise the cap: forbidden by D-030, never.
2. Reclassify parsers to escape measurement: gaming, rejected by D-043, and
   the placement principle in section 3 detects it (bytes-to-values is surface
   regardless of filename).
3. Delete rationale comments to buy lines: trades the audit story for the
   number; the unit exists for the auditor. Rejected.
4. Subdivision without slim: creates zero slack (Reading 2). Rejected as a
   standalone fix, kept as the recording mechanism.

## 10. Owed SPEC edits (D-029 pre-flag, before any code commit)

1. BE-SURF-03: subdivide the post-authentication unit into the wire-parser and
   session-state sub-units with the cap rule from section 7.
2. BE-SURF-03 non-surface list: add the new files (working names intent.zig,
   resolver.zig, render.zig; final names fixed at implementation) before they
   exist, so exhaustiveness holds at every commit.
3. No BE-SURF-01 edit: the Refusal (§8.5) and Sync (§6.4) wire formats are
   already declared. No BE-SIG-01 edit: domain tag 0x06 already declared.

## 11. Invalidation

What would invalidate this estimate:
- Compaction landing below ~85 lines (fmt re-expansion of compacted inits, or
  a file I miscounted): re-measure, Reading 3 becomes primary.
- Refusal or sync wire formats changing in SPEC before implementation.
- The pending-intent state machine needing wire-adjacent code (e.g. a
  serialized pending table for restart): placement would shift to surface and
  the surface column grows; restart state is memory-only per GRANT-04, so this
  should not happen.
- Differential oracle needing more than fuzz.zig (a second build target, a
  separate language reference): harness list edit, still zero M11 cost, but
  the M4 plan changes.

## 12. Pre-close checks

- [x] Who picked the denominator: 1500 from SPEC BE-SURF-03; line counts from
      `PRUMO=1 tools/prumo-verify` at c0b385e this session (1497/1500).
- [x] Placement principle checked against BE-SURF-03's own rationale and the
      ledger precedent (D-045/D-047), not invented.
- [x] Slim audit done file by file, this session, with the cosmetic/genuine
      distinction stated, not smuggled.
- [x] Sub-unit caps sum exactly to the unit cap; nothing raised.
- [x] At least two readings with explicit verdicts: four, of which one fits at
      median with tripwires and one fits with wide margin as fallback.
- [x] Does the thing need to exist: yes, 21 markers sit behind this wall and
      the project mandate is completion.

## 13. Next steps after estimate approval

1. D-052 in DECISION-LOG.md: the compaction ruling (budget lever, labeled
   cosmetic, guardrails), the subdivision shape, the tripwires, the sync
   deferral contingency, the rejected alternatives.
2. SPEC edits per section 10, one commit, flagged before any code (D-029).
3. Compaction commit: struct-init and banner density across the six files, no
   comment deletion, full gauntlet, sub-unit caps ratcheted to the fresh
   measured totals.
4. Pending-intent slice: refusal parser (surface) + intent.zig + verify.zig
   refusal verification + binding tests for GRANT-01a/04/06/06a/06b/09/10.
5. Resolver slice, render slice, sync slice (tripwire-governed), fuzz oracle,
   each atomic, each gauntleted, tripwires checked at every commit.
6. Merge to main only with Daniel's explicit approval.
