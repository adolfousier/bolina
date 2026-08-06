# Decision log

Every decision made without a second person in the room, with the reasoning. Daniel reviews at
the end; this file is where design calls live so they are not discovered in commit messages.
Format: number, date, decision, reasoning, what would reopen it. Entries that needed Daniel's
sign-off (stop-list items) are marked **STOPPED** and carry his answer when it lands.

The three pre-close checks apply to every entry below (Daniel, 2026-08-06): read it against the
rules in other sections; for every number, who picked the denominator; for every check, does the
thing being checked need to exist.

---

## D-001 — 2026-08-06 — New mode interpreted as autonomy within the stop list

Decision: "do everything there is to do, I review at the end" means: proceed alone through the
free list (§7 in full with its red team, harnesses, gates, tests, refactors, spec fixes that do
not change a guarantee), stop and wait at the six named lines, and log every solo decision here.
Reasoning: the summary rule he gave is the operative one: reversible, decide; irreversible or
guarantee-changing, stop. What would reopen it: any ambiguity about whether an item is
reversible resolves to STOP, not to decide.

## D-002 — 2026-08-06 — Pushes of `round-4-review` to origin proceed, logged

Decision: pushing this feature branch to origin is not treated as "anything leaving the repo".
Reasoning: stop item 6 reads alongside his own complaint this morning that he could not review
BE-GRANT-03c because the branch was not on origin; origin is the review surface, not an external
destination. A feature-branch push is reversible (branch can be reset or deleted), changes no
guarantee, and is not main (item 5) or publication. What would reopen it: Daniel saying pushes
also wait; until then every push is still logged here with its commit range.

## D-003 — 2026-08-06 — §7 first, stop after it

Decision: implement §7 in full and stop before transport, per his suggestion. Reasoning: §7 is
the half with no prior art, so it is where the design is most likely wrong; building transport on
top before the review is the expensive order. The suggestion is adopted as if it were a rule,
because the reasoning is the same one that produced the stop list.

## D-004 — 2026-08-06 — Red team before code, vectors before parsers

Decision: RED-TEAM-09.md (paper red team of §7, rule pairs across sections) lands before any §7
implementation code, and new test vectors land before the new parsers. Reasoning: CONTRIBUTING.md
§7 requires both, in that order; the RT-01 lesson says aim at rule pairs separated by sections.
The Span wire format and the method_id/class/ceiling table are ALREADY pinned in test/vectors.json
(BE-EVID-15 satisfied ahead of time), so the Span parser is being written against vectors, not
defining the format.

## D-005 — 2026-08-06 — Two §7 findings STOPPED for Daniel before any code depends on them

Decision: present and wait on (F1) the missing span carriage in the `Utterance` grammar —
BE-EVID-08 mandates inline spans, §6.3's grammar carries none; this is a wire format decision
(stop item 1) — and (F2) the missing role row for `Utterance` in BE-ENV-03's enumeration — adding
it is a guarantee change, and strengthening counts (stop item 2). Full text and recommended fixes
in RED-TEAM-09.md. Everything not shaped by those two answers proceeds meanwhile: Span/Effect/
Claim parsing, the class table, confidence recomputation, the causal DAG, supersession.
Reasoning: the stop list is explicit and both items are cheap to ask now, expensive to guess.

## D-006 — 2026-08-06 — Evidence evaluation is pure functions returning a state, no call wall

Decision: `src/evidence.zig` computes confidence and the three states as pure functions over
parsed structures plus two hooks; there is no callback and no `verifyGrantThen`-shaped wall.
Reasoning: the call-graph wall (M10) exists because a verified grant is authority to ACT; a
confidence evaluation authorizes nothing, it only presents. Adding a reach-path gate where there
is no effect to reach would be a check on a thing that does not need to exist, the exact failure
"remove, don't check" names. What would reopen it: any evidence-layer output becoming an input to
an effect path.

## D-007 — 2026-08-06 — The causal DAG is fixed-capacity, caller-owned, zero-heap, no recursion

Decision: `src/dag.zig` stores envelope nodes in a caller-supplied fixed-capacity pool with a
hash index; `isAncestor` walks parents with an explicit work queue and a visited set. Reasoning:
BE-WIRE-01's no-heap discipline is the project's shape for parse surfaces, and the DAG is the
first stateful structure the slice holds, so it gets the same shape rather than a new one;
§6.4 already mandates explicit work queues over attacker-influenced graphs and forbids recursion
(BE-DEP-02's letter and intent). Capacity exhaustion surfaces as a rejection/error to the caller,
never silent eviction. What would reopen it: a §11 item needing unbounded history in-process.

## D-008 — 2026-08-06 — Two slice deviations for §7, both hooks with named repayment

Decision: (a) BE-EVID-01's certificate role check is a `role_of(pubkey)` hook; the slice has no
certificate store yet. (b) BE-EVID-05's "Effect on the same resource" is an
`effect_resource(envelope_hash)` hook; `Effect` carries `grant_id`, not `resource_id`, and
resolving grant to resource needs ledger state the slice does not store. Reasoning: the same
provisional shape as BE-GRANT-03 checks 3/4/6/7/8 — deviation recorded, repayment condition
named (certificate store; full ledger), debt visible where it lives. The causal WALK itself is
implemented for real; only the two external lookups are hooks. What would reopen it: nothing —
repayment is already the plan for the next slices.

## D-009 — 2026-08-06 — Supersession is STRICT descent from the span's own Effect

Decision: in BE-EVID-05, the superseding Effect must be a strict causal descendant of the span's
`origin` Effect. Reasoning: with reflexive descent, the Effect that PUBLISHED a volatile span
would supersede it at birth, so every volatile span would support nothing, which reduces
BE-EVID-05 to "volatile evidence is worthless" and contradicts the rule's own rationale
(invalidation by a LATER observed change). The claim side needs no strictness pin: the claim
travels in an Utterance, which cannot be the superseding Effect. Pinned as a clarification of
declared semantics, not a guarantee change; recorded in RED-TEAM-09.md F3.

## D-010 — 2026-08-06 — Mixed-resolution claims resolve per span, not per claim

Decision: a claim citing several spans where some `origin`s are in the ledger and some are not:
the resolved, non-superseded spans support it (ceiling of the strongest), the unresolved ones
contribute nothing yet. The claim is `Unresolved` only when it has valid matching spans but ZERO
resolved origins, and `Unsupported` only when it has no valid matching span at all. Reasoning:
BE-EVID-02 computes from the strongest matching support, BE-EVID-09's Unresolved exists so
delivery luck does not lower confidence; rendering a partly-evidenced claim as fully pending
would discard evidence that is already resolved, and rendering it as fully supported would count
evidence that is not. The composition is the only one honoring both rules. Pinned as a
clarification; recorded in RED-TEAM-09.md F4.

## D-011 — 2026-08-06 — Evaluation runs after ledger adoption of the claim's envelope

Decision: the evaluator receives the claim's envelope hash and expects that envelope to be in the
DAG (accepted live or adopted via backfill per BE-SYNC-05). Reasoning: BE-EVID-05 asks whether the
superseding Effect is a causal ANCESTOR of the claim, which is only computable once the claim has
a causal position; adoption is verification-gated, so evaluating after adoption adds no trust.
Recorded in RED-TEAM-09.md.

## D-012 — 2026-08-06 — A span whose origin resolves to a non-Effect envelope cannot support a claim

Decision: a span whose `origin` resolves to an envelope of any body type other than `Effect` cannot
support a claim; it falls out of both the Supported and Unresolved states. Reasoning: §7.1 defines
`origin` as the hash of the Effect envelope that published the span, so a span whose origin resolves
to an Intent, Grant, Utterance, Control, or Refusal envelope contradicts its own declared structure
before any trust question is asked. Leaving this case undefined would let a member treat such a span
as supported by default; the only safe reading is fail-closed. This pins the existing structural
declaration from §7.1, it does not add a new guarantee. Recorded in RED-TEAM-09.md F7.

## D-013 — 2026-08-06 — Origin computation is underspecified (open question, not a stop)

Question: §7.1 defines a span's `origin` as the hash of the Effect envelope "in which this span was
published". The span travels inside that Effect body, which is inside the envelope, so a literal
reading makes `origin = hash(envelope containing the span's own origin bytes)` circular. The SPEC
does not state whether the hash excludes the span's own `origin` field, or whether `origin` instead
points at a prior envelope. Decision for now: in the vectors, `origin` is a deterministic opaque
anchor (`blake2s("bolina/example-effect-envelope")`), matching the pre-existing standalone span
vector that shipped in round 3. This does not change the wire format (origin is still a 32-byte
field) or any guarantee; it leaves the executor's real construction protocol as an open question for
Daniel. Not a stop: nothing irreversible and no promise changes. Flagged in RED-TEAM-09.md (open).

## D-014 — 2026-08-06 — No invented per-Effect or per-Claim span_count cap

Decision: parseEffect and parseClaim enforce NO bound on `span_count` beyond the bytes available.
They read `u8 span_count`, then read that many spans (Effect) or `span_count * 16` bytes (Claim),
truncating via the shared Cursor rejection if the buffer runs out. Reasoning: BE-TR-05 is the one
table that declares every attacker-influenced size and its hard maximum, and it declares no
per-Effect or per-Claim span cap. The only span bound in §7 is BE-EVID-10, and it sits on the
Utterance (at most 64 spans), not on the Effect body or the Claim. The enclosing envelope's
`body_len` (<= MAX_BODY) already bounds total input, so a fabricated-large `span_count` truncates
instead of allocating or looping unbounded; the parser is zero-heap and the loop is bounded by the
buffer, not by the count. Pre-close check 3 ("does the thing being checked need to exist?"): a
per-structure span cap does not exist in the spec, so inventing one would add a guarantee the spec
does not make and a rejection the spec does not require, which is exactly the kind of change that
belongs on the stop list. What would reopen it: if Daniel wants a defense-in-depth cap on inline
spans (e.g. reject an Effect with span_count > N), that is a new guarantee and I stop for it.

## D-015 — 2026-08-06 — Superseded-only and non-Effect-origin claims resolve to Unsupported, not Unresolved

Question: a claim whose only matching spans are (a) all volatile and superseded, or (b) all whose
origin resolves to a non-Effect body type, has no span contributing a ceiling. BE-EVID-09 defines
three states (Supported with an effective q8, Unresolved marked pending, Unsupported at 0.00), but
the spec does not explicitly assign these two empty-after-filtering cases to one of the two
non-Supported states. Decision: both resolve to Unsupported (0.00), not Unresolved. Reasoning:
BE-EVID-05 explicitly names the 0.00 outcome for a volatile span that is superseded by a later
strict-causal-descendant Effect on the same resource_id, so a claim left with only superseded spans
inherits that 0.00 outcome directly. D-012 (RED-TEAM-09 F7) already established that a span whose
origin resolves to a non-Effect envelope cannot support a claim and falls out of both the Supported
and Unresolved states; this decision states the consequence for the claim: Unsupported. Pre-close
checks: (1) read against other sections, BE-EVID-05's named 0.00 outcome is the controlling cross-
reference, not the Unresolved marker of BE-EVID-02b; (2) who picked the denominator, the spec's
own named outcome did, not a choice on my part; (3) does the thing being checked need to exist, yes,
both BE-EVID-05's supersession outcome and the non-Effect-origin structural rule exist. This pins
the existing declared outcomes, it does not add or strengthen a guarantee. Recorded in RED-TEAM-09.md
(F3 supersession consequence, F7 non-Effect-origin consequence).
