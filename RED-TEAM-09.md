# RED-TEAM-09: paper red-team of SPEC.md §7 (RT-02)

Red team: OpenCrabs (agent), delegated under Daniel's autonomous mode of 2026-08-06; he reviews
at the end. Transcribed here so the findings survive the chat. Aimed at rule PAIRS separated by
sections, per the RT-01 method note in RED-TEAM-08: four of six RT-01 defects were invisible
reading BE-GRANT-03 alone.

**Evidence class: Inference.** One reader (an agent) reading a document. This seals nothing and
does not substitute for §11.4 (model checking) or §11.5 (adversarial evaluation). It is the
CONTRIBUTING.md §7 red-team item for the §7 slice, done before any §7 implementation code.

## Headline

The receiver-recomputation core (BE-EVID-02, -02a, -03, -13) and the class table (§7.4) hold
under every attack attempted. The defects found are in the CARRIAGE and the ENUMERATIONS around
§7, not in the arithmetic: the piggyback that BE-EVID-08 mandates has no wire field to ride in,
and the role enumeration in BE-ENV-03 has no row for the one body type §7 exists to carry.
Two findings are STOPPED for Daniel (wire format; declared guarantee). Three are pinned as
clarifications of already-declared semantics. Six attacks are recorded as held, with the one
residual named.

## STOPPED — Daniel decides before code depends on the answer

### F1: BE-EVID-08 mandates inline spans; the Utterance grammar carries none (wire format)

BE-EVID-08 (§7.5): "An `Utterance` MUST carry, inline, the full encoded `Span` for every
`span_id` its claims reference." The grammar it refers to (§6.3):

```
Utterance := u16 text_len, text (≤ 16 KiB) ; u8 claim_count ; Claim[]
```

There is no field the spans can ride in. `Claim` carries `span_ids` only; §2.2 has no extension
mechanism; unknown trailing bytes are a parse failure. Two conforming implementations of the
current text cannot exchange an evidenced claim at all. This is stop item 1 (wire format).

Two shapes fix it:

- **(a) Utterance-level array** — append `u8 span_count ; Span[]` after `Claim[]`, bounded by
  BE-EVID-10's 64, deduplicated by `span_id` at the receiver. Mirrors `Effect`, which already
  carries spans as a sibling array of the body. Leaves the `Claim` grammar exactly as §7.2
  specifies it. BE-EVID-10's own wording ("An `Utterance` MUST carry at most ... 64 spans")
  bounds the UTTERANCE's carriage, which is what (a) gives it.
- **(b) Per-claim nesting** — each `Claim` carries its own spans after its `span_ids`.
  BE-EVID-10's "wire duplication is accepted" reads naturally here (two claims citing one span
  each carry a copy), but it changes the `Claim` grammar §7.2 already pinned, and BE-EVID-10's
  utterance-level caps then need a total-span walk across claims to enforce.

Recommendation: **(a)**, for the three reasons above. Bundled with F1, because they are rules of
the new field:

- **F5 (collision):** two spans in one utterance sharing a `span_id` with DIFFERENT bytes MUST
  reject the envelope. Identical duplicates deduplicate (BE-EVID-10); differing bytes under one
  id is equivocation at attestation granularity, and BE-ENV-05's principle — surfaced, never
  absorbed, never silently picked — applies. Proposed text is written out in the disposition.
- **F6 (phrasing):** BE-ENV-03's "Effect and any embedded Span require `executor`" admits a
  reading under which an `Utterance` embedding piggybacked spans requires its SENDER to carry
  the executor role — which would make agent-uttered claims impossible and contradict
  BE-EVID-01, which verifies a span against `Span.executor`, not against the embedding
  envelope's sender. Once F1 lands, that misreading becomes load-bearing. Reword in the same
  edit: the role check is envelope-sender-versus-body_type; embedded-span authenticity is
  BE-EVID-01's signature check.

### F2: BE-ENV-03 names no role for Utterance (declared guarantee)

BE-ENV-03 enumerates: Intent requires `agent`; Grant and Refusal require `approver`; Effect (and
embedded spans) require `executor`. `Utterance` (body type 1) has no row. Every other body type's
sender is role-gated before the body reaches application logic; the body type §7 exists to carry
is not. Adding the row is a guarantee change (a new class of envelopes becomes rejectable), and
strengthening counts under the stop list, so: STOPPED.

Proposed row, if Daniel confirms the obvious intent: "Utterance requires `agent`" — claims are
agent speech; executor speech rides in Effects. (Completeness note, no action proposed: `Control`
is also absent from the enumeration but is governed by BE-CTRL-02's admin_group check; the
enumeration could name that for the auditor who reads BE-ENV-03 alone.)

## PINNED — clarifications of declared semantics, landed in SPEC.md with this document

### F3: supersession is STRICT descent from the span's own Effect

BE-EVID-05 names "a causal descendant of the span's own `Effect`". If descent were reflexive,
the Effect that PUBLISHED a volatile span would supersede it at birth: every volatile span would
support nothing, and BE-EVID-05 would reduce to "volatile evidence is worthless", contradicting
its own rationale (invalidation by a LATER observed change). Pinned as BE-EVID-05a. The claim
side needs no pin: the claim rides in an Utterance, which cannot be the superseding Effect.

### F4: mixed resolution composes per span, not per claim

BE-EVID-09 states the three states for the clean cases. A claim citing several spans where some
`origin`s are in the ledger and some are not was undetermined. Pinned as BE-EVID-09a: the
resolved, non-superseded spans support the claim (ceiling of the strongest among them); the
unresolved ones contribute nothing yet; the claim is Unresolved only when it has valid matching
spans but zero resolved origins, Unsupported only when it has no valid matching span at all.
Reasoning in the spec entry: BE-EVID-02 computes from the strongest matching support, and
BE-EVID-02b exists so delivery luck does not LOWER confidence; rendering a partly-evidenced
claim as fully pending discards resolved evidence, and rendering it as fully supported counts
evidence that has not arrived.

### F7: a span's origin must resolve to an Effect envelope

§7.1 declares `origin` as "hash of the Effect envelope in which this span was published". A span
whose `origin` resolves to an envelope of any other body type contradicts its own declared
structure. Pinned as BE-EVID-09b: such a span cannot support a claim (it falls out of the
Supported and Unresolved states alike), fail-closed. This enforces the declaration; it adds no
new obligation on honest spans.

## Attacks attempted that HELD (recorded because a red team that only lists hits proves nothing)

### A1: supersession depends on the local ledger — does it break "same verdict at every member"?

BE-EVID-08's rationale claims a self-contained envelope yields the same verdict at every member,
but BE-EVID-05 reads the ledger. Attempted wedge: a member mid-backfill computes supersession
over a partial ledger and presents a superseded span as supporting. It does not reach: to ACCEPT
the claim's envelope U, BE-LEDGER-01 requires U's parents resolvable within bounded fetch, and
BE-SYNC-03 makes the walk explicit and budgeted; on exhaustion the envelope is REJECTED with a
surfaced condition, not adopted partial. So at evaluation time (post-adoption) the member holds
U's full ancestor closure, and every superseding Effect — being an ancestor of U — is in it. The
verdict is a function of the ancestor closure, identical for every member who accepted U.

### A2: equivocation forks the verdict

Under BE-ENV-05 equivocation, two members accept different envelopes at one `(sender, channel,
seq)`, their ancestor closures differ, and a claim can be Supported at one and superseded at the
other. Held, with the declared residual: the divergence is SURFACED with both hashes, never
absorbed, so the disagreement is flagged rather than silent. This is §9.1's honest limitation
(tamper-evidence, not tamper-resistance) one layer down.

### A3: concurrent supersession — an Effect concurrent with the claim

An Effect that modifies the resource while CONCURRENT with the claim (neither ancestor nor
descendant) does not supersede, because BE-EVID-05 anchors to the claim's causal past. A claim
can be supported by evidence a concurrent modification has already invalidated. Held BY DESIGN:
causality, not the clock, is the section's foundation (§7.3's opening argument); a claim is
accountable for what it could have known, and the modification enters later members' views as a
new Effect with its own spans. Residual named: detection of concurrent invalidation is a
later-evidence matter, not retroactive re-scoring. Candidate for a THREAT-MODEL line — flagged to
Daniel, since the threat model is amended by decision, not by an agent alone.

### A4: worst-case size of an evidenced utterance vs MAX_BODY

32 claims × (1 KiB text + 256 subject + 16×64-byte span_ids + overhead) ≈ 74 KiB, plus 64 spans
× ≤ 461 bytes ≈ 30 KiB, plus 16 KiB utterance text ≈ 120 KiB, under MAX_BODY (1 MiB − 512).
The caps compose; no additional bound needed. (Denominator check: every number here is derived
from declared bounds in §6.2/§6.3/§7.1/§7.2/BE-EVID-10, none invented.)

### A5: q8 rounding and comparison

The ceilings are integers (242/216/191/165) pinned by round-toward-zero at spec time; runtime
arithmetic compares integers only and no float enters a signed structure or a comparison.
`min(stated_q8, ceiling_q8)` is total over u8. A claim with valid support and `stated_q8 = 0`
presents 0.00 WITHOUT the "no mechanical confirmation" marker: the marker attaches to the
no-valid-span state (BE-EVID-02a), not to the number. Held.

### A6: cross-trace citation

`trace_id` is grouping, not scoping: a span from another trace supports a claim if the subject
matches (BE-EVID-03) and nothing supersedes (BE-EVID-05). Distance and trace position are
deliberately not substitutes for causality (BE-EVID-07). Held by design.

## Observations (no defect, recorded so nobody "fixes" them)

- **O1 — span cap asymmetry.** `Utterance` carriage is capped at 64 spans (BE-EVID-10); `Effect`
  carries a `u8 span_count` with no bound below 255. The asymmetry is right: Effects are
  executor-sent (small audited programs, role-gated), utterances are agent-sent (the adversarial
  surface). Do not harmonize downwards or upwards without a reason.
- **O2 — Unresolved is stable.** If backfill exhausts BE-SYNC-03's budget, the origin stays
  absent and the claim stays Unresolved indefinitely. That is the honest state, not an error to
  time out: any timeout-based downgrade would reintroduce the clock §7.3 just removed.
- **O3 — method_id 0 and ≥ 9.** Outside the table, BE-EVID-13 floors them at Inference (165).
  The vectors already pin method_id 9 → Inference (BE-EVID-15).
- **O4 — the role hook inherits the admission/audit split.** When BE-EVID-01's certificate role
  check is implemented (certificate store, deferred per the slice deviations), it must follow
  BE-HIST-01: clock-anchored for live admission, causal-interval for audit of ledger-committed
  history. Noted here because the split lives in §9 and the check lives in §7 — a pair.

## Dispositions

| Finding | Class | Disposition |
|---|---|---|
| F1 (+ F5, F6 bundled) | wire format | STOPPED for Daniel; recommendation (a), proposed normative text ready to land on his word |
| F2 | declared guarantee | STOPPED for Daniel; proposed row "Utterance requires agent" |
| F3 | clarification | PINNED as BE-EVID-05a with this document |
| F4 | clarification | PINNED as BE-EVID-09a with this document |
| F7 | clarification | PINNED as BE-EVID-09b with this document |
| A1–A6 | attacks held | recorded above |
| A3 residual | new risk | flagged to Daniel for a THREAT-MODEL decision (§3 judgement rule) |
| O1–O4 | observations | recorded above |

## Method note

Pairs examined (the RT-01 lesson, applied): BE-EVID-08 × §6.3 grammar (F1), BE-EVID-01 ×
BE-ENV-03 roles (F2, F6), BE-EVID-05 × §9 DAG semantics (A1, A3, F3), BE-EVID-09 × §6.4 backfill
budgets (A1, O2), BE-EVID-10 × BE-ENV-05 equivocation principle (F5), BE-EVID-10 × §6.2 size
budgets (A4), BE-EVID-01 × BE-HIST-01 admission/audit split (O4), §7.4 × §2.2 encoding rules
(A5). Rules read alone confirmed nothing new; every finding and every held attack came out of a
pair, same as RT-01.
