# LEDGER-ESTIMATE.md — the ledger / history / divergence slice

Date: 2026-08-08. Branch: `relay-slice` successor (to be named `ledger-slice`).
Estimate-first rule (RELAY-ESTIMATE.md precedent): this document is committed
BEFORE the decision entries, the SPEC amendment, and any code.

## 1. What is being costed

Ten unbound MUST markers, all NEEDS-CODE after the M1 keying audit:

| Marker | Requirement (one line) |
|---|---|
| BE-LEDGER-01 | Reject envelopes whose unknown parents cannot resolve within a bounded fetch; surface divergence |
| BE-LEDGER-02 | Ledger stores hashes, never plaintext; head hash MAY be published externally |
| BE-LEDGER-03 | Every Grant and every Effect MUST appear in the ledger |
| BE-HIST-01 | Clock checks govern admission only, never audit of committed signatures |
| BE-HIST-02 | A signer's certificate is anchored in the channel before first use and retained |
| BE-HIST-03 | Historical validity is a causal interval: descendant of anchor, not of revocation |
| BE-HIST-04 | Revocation is immediate for admission, causal-positioned for audit |
| BE-ENV-03 | body_type to role map enforced before the body reaches application logic |
| BE-ENV-04 | Per-(sender, channel) sliding seq window, same shape as BE-TR-03, strict maximum forbidden |
| BE-ENV-05 | Same-triple different-hash duplicate raises a divergence event, never silent drop |

Explicitly OUT of this slice: BE-SYNC-01..05 (needs parser surface, hits the
M11 wall, and BE-SYNC-05 requires the ledger store to exist first — the ledger
is its precondition), BE-MESH-03 (MAY, deferred by D-043), BE-GRANT-09 and
BE-RES-01..06 (executor layer), BE-TR-06 (daemon dispatch layer), BE-EVID-11
(no executor module exists), BE-REV-01 duration cap (see section 6).

## 2. The spec defect found while estimating (flagged, D-029)

BE-HIST-02 says the certificate is anchored "by a `Control` envelope carrying
it". That is impossible against section 6.1c: `Control` has a closed
`action_type` enum {1 Genesis, 2 Revoke} (BE-CTRL-01: no forward-compatibility
path, no extension mechanism), and its body is `ControlGenesis` or empty — no
field can carry a variable-length certificate. Sections 6.1c and 9.2
contradict each other. Pre-close check applied: read the rule against the
OTHER sections; the contradiction is real, not my misreading.

Resolution (D-046): the closed enum is the deliberate security property
(section 2.2 names it); the anchoring VEHICLE in BE-HIST-02 is the mechanism
choice. The mechanism yields, the property stands. Amended vehicle: the first
envelope accepted from a signer in a channel IS that signer's anchoring
record; the certificate is verified under BE-ID-01 through BE-ID-04 at that
moment (obtained via section 5.1a lookup keyed by the BE-ID-01-derived overlay
address) and retained with the envelopes that depend on it. "Before first use"
is satisfied because anchoring happens inside the first envelope's own
admission: the certificate is verified before the envelope is accepted, and
every later envelope is a causal descendant of that anchor. No wire change.

## 3. Where the code lives (the budget question)

The BE-SURF-03 budget units are PARSER surface, mechanically: the M5/M11
gates parse file lists from SPEC section 2.3. Post-authentication unit (M11,
1493/1500): binding.zig, parser/channel.zig, parser/session.zig,
reassembly.zig, replay.zig, session.zig. Seven lines of headroom.

The ledger is verification STATE, not parse surface. By BE-LEDGER-02 it stores
hashes and never plaintext, so it never parses envelope bodies by law. The
architecture already carries four non-budgeted verification/attestation
modules — verify.zig 418, evidence.zig 294, dag.zig 190, main.zig 13 — and
LANGUAGE.md documents them as such; that placement survived the keying sprint
and the relay round reviews. The ledger joins that class:

- NEW `src/ledger.zig` — hash store, equivocation detection, seq windows,
  anchor and revocation tables, divergence events. Non-budgeted.
- `src/verify.zig` extensions — admission integration + historical audit
  path. Already non-budgeted.
- `src/dag.zig` — reused as-is (isAncestor already walks with an explicit
  queue, BE-DEP-02 shape); at most a descendant-or-self helper.

Decision D-045 records this placement with its reversal condition: if Daniel
rules that all attacker-influenced state belongs inside the budget, ledger.zig
gets listed in BE-SURF-03 under the post-auth unit, which is only reachable
after slimming surgery on the 1493 — at which point this slice stops and the
surgery gets its own estimate. The mechanical gate (D-041: denominators are
parsed, not picked) makes the placement testable: M11's file list is read from
SPEC, so "non-budgeted" is a fact about the list, not my opinion.

## 4. Cost table

| Item | Lines (median) | Range | Notes |
|---|---|---|---|
| `ledger.zig` hash store (bounded, hashes only) | 120 | 100-150 | RelayTable precedent; caller-owned, fixed capacity, zero heap |
| Equivocation detection (same triple, hash compare) | 40 | 30-60 | Lives in the store's insert path |
| Per-(sender, channel) seq windows | 60 | 50-80 | Bounded keyed table of replay.zig's existing ReplayWindow value |
| Anchor table (pubkey to anchor hash + cert record) | 50 | 40-70 | BE-HIST-02 retention |
| Revocation causal table | 30 | 25-40 | pubkey to revocation envelope hash |
| Divergence event + bounded parent resolution hook | 70 | 50-90 | BE-LEDGER-01 boundary without the sync fetch (fetch is BE-SYNC) |
| verify.zig admission integration | 90 | 70-120 | ENV-03 role map, ENV-04 window, ENV-05/LEDGER-01 checks, LEDGER-03 recording |
| verify.zig historical audit path | 70 | 50-90 | BE-HIST-01/03/04: no clock, causal interval |
| dag.zig | 10 | 0-20 | Helper only if needed |
| `ledger_test.zig` | 320 | 260-420 | ~22 tests, literal expectations (D-027) |
| Mutation domain | ~12 mutants | 10-14 | Keys derived from the table above |

Totals: ~860 median new lines, ALL non-budgeted. Budget gates M5/M11
UNCHANGED by construction (no budgeted file touched), M9 denominator
unchanged (exit points are parser-module only), M1 ratchet 68 to 78.

## 5. Verdict

FITS without budget surgery. The slice touches zero budgeted lines. The M11
wall (1493/1500) is left intact for the sync slice, which genuinely needs
parser surface and will get its own surgery estimate.

Tripwire (relay precedent): ledger.zig above 420 lines before the markers are
bound, slim or split and log a decision; never raise.

## 6. The REV-01 question, settled by measurement

BE-REV-01's 30-day duration cap belongs in binding.zig — a BUDGETED file with
7 lines of headroom. If the measured addition (one comparison, one error arm,
the coverage member) fits inside the 7, it lands in this slice as a micro-fix.
If it does not, it is deferred to the sync slice's surgery estimate rather
than buying headroom by removing someone else's code mid-slice. Measured at
execution, decision logged either way.

## 7. What would reverse any of this

- D-045 placement: Daniel rules attacker-influenced state is budget surface.
- D-046 vehicle: a wire change to Control is wanted despite BE-CTRL-01 (would
  require amending the closed enum itself — the larger change, rejected here).
- Tripwire: ledger.zig exceeds 420 lines mid-slice.
- Measurement: admission integration costs more than 120 lines in verify.zig,
  at which point the audit path splits into its own module and gets re-costed.
