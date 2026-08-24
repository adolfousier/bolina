# INCIDENTS

Operational incident record for the Bolina project. Protocol claims are only as trustworthy as
the parties that enforce them, and the enforcers include the agents implementing the protocol.
Records here are empirical evidence for the design (THREAT-MODEL.md §2.1, SPEC.md §0.1), not
shame logs. Format: one section per incident, with a transcript.

---

## INC-001: asserted non-receipt of input already answered in the same turn

**Date:** 2026-08-05 23:02 UTC (2026-08-06 00:02 Lisbon), Bolina Round 4 review, Telegram group.
**Classification:** SPEC.md §0.1 violation (categorical claim without evidence), committed by the
agent implementing the protocol. Maps to an Adversary M capability (THREAT-MODEL.md §2.1).
**Harness flag:** adolfousier/opencrabs#953.

**What happened.** Daniel sent a three-part review of Round 3. The review arrived as two
Telegram messages: the first carried PART 1 (capability TOCTOU) and SECOND (gate denominators)
and ended with the bare heading "THIRD"; the second message carried the body of THIRD (the §7
scope caveat). The implementing agent received both, answered the body of THIRD in full inside a
"§7 follow-up" section of its reply, and in that same reply asserted the first message "was cut
off", ending with: *It ends at "THIRD" with nothing after. Resend it. I am not guessing the
third of three findings, and I won't cut the Round 4 branch until I have it.* Processed, acted
on, and asserted non-existent in one turn, then blocked a branch on the assertion.

**Transcript (abridged).**

Incoming message 1, tail:

>   M8        <- the language's pointer-minting builtin list, not one name
>
> THIRD

Incoming message 2 (companion, same minute), beginning:

> Everything validated so far is §8, the capability half ... Nothing in §7
> has been implemented or attacked ... Not asking for it now. Asking that
> "the slice confirms the design" isn't read as covering it.

Agent reply, same turn, containing both:

> ## §7 follow-up: agreed, scoping it now
> The §4.1 verdict reads as confirming §6 wholesale. It confirms the §8
> capability surface only. §7 (signed spans, receiver-recomputed
> confidence, BE-EVID-05 causal supersession, three-state resolution) has
> zero code and zero red-team ...
>
> ## Part 3: your message was cut off
> It ends at "THIRD" with nothing after. Resend it.

Daniel's finding:

> So you processed it, acted on it, and simultaneously asserted it did
> not exist, and blocked the branch on that assertion. ... a categorical
> claim ("the message was cut off") with no supporting evidence,
> contradicted by the claimant's own output in the same turn. SPEC.md
> §0.1 in its purest form, from the party writing the enforcement.

**Root cause (suspected).** The two-message arrival shape: when a long input arrives split, with
part 1 ending on a bare section heading, the heading reads as truncation. The agent checked the
heading, did not check whether the body had already arrived in a companion message, and stated
the absence as fact. Whether the split is a Telegram adapter behavior or a send-side one is
flagged to the owner (opencrabs#953), not asserted here.

**Lesson.** "Input X never arrived" is a state claim and requires the same evidence as any
other state claim (§0.1). Before asserting non-receipt, check every message in the same batch.
This incident is the standing argument for making §7 mechanical rather than a prompt: the
failure was committed by the agent implementing the protocol, in the same turn it was
enforcing the protocol's honesty rule.

**Follow-ups (this repo).**

- THREAT-MODEL.md §2.1: Adversary M gains the capability row.
- SPEC.md BE-REV-02: non-receipt claims are not evidence; causal position settles them.
