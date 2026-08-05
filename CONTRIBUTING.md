# Contributing to Bolina

This project's central claim is that a rule enforced by asking nicely is not enforced. That applies
to this document too. Everything below is sorted into **mechanical** (CI refuses the merge; no
human judgement involved) and **judgement** (a person decides, and the reasoning is recorded).

A contribution guide made entirely of good intentions would be the thing the protocol was written
against.

---

## 1. What this project is right now

Active research. A specification exists; **no implementation does**. A spec written ahead of its
implementation is the normal working mode here, not a deficiency.

Unproven claims are expected. An unproven claim that reads as a proven one is not.

### Vocabulary, binding

| Word | Means | Do not confuse with |
|---|---|---|
| **DECLARED** | Designed. Not built, not measured. | Everything is DECLARED today |
| **TESTED** | Measured under a method stated in `SPEC.md` §11 | "we ran it once and it worked" |
| **PROVED** | Exhaustively checked (model checker, or equivalent) | TESTED |
| **closed** | Nothing pending against this draft | sealed |
| **sealed** | The evidence for a specific claim exists and is recorded | closed |

`v0.2.0-draft` is **closed**. Nothing in it is **sealed**. Do not write otherwise in a commit
message, a README, a comment, or a chat summary.

---

## 2. Mechanical rules (CI refuses the merge)

None of these involve anyone's judgement, and none may be waived by agreement in a thread.

| # | Rule | Source |
|---|---|---|
| M1 | Every `BE-*` in `SPEC.md` has a test bound to it by name; every test binds to a declared `BE-*`. Bijection, verified by `prumo-verify`. | §11.1 |
| M2 | 100% mutant kill in the §8 state machine and the §7 verifier. Survivors elsewhere are recorded with a cause. | §11.2 |
| M3 | Cross-implementation test vectors pass byte-for-byte. | §11.3 |
| M4 | Differential fuzzing is clean, reporting coverage and corpus, on any change touching parsing code. **A merge gate, not a milestone.** | §11.6, BE-SURF-04 |
| M5 | Network-parsing module ≤ 1500 lines. | BE-SURF-03 |
| M6 | Build succeeds with the network disabled and no package manager. | §11.7, BE-DEP-01 |
| M7 | Shipped build is `ReleaseSafe`; compiler version and flags recorded with every result. | §11.8, `LANGUAGE.md` O1, O4 |

If a change cannot satisfy one of these, the change is wrong or the rule is wrong. Both are fine
outcomes. Merging anyway is not.

---

## 3. Judgement rules (a person decides, and writes down why)

- **The spec is not worked around.** Code that disagrees with `SPEC.md` means one of them is wrong.
  Fix the spec, in the same pull request, or fix the code. Never leave them disagreeing and never
  add a comment explaining the divergence.
- **The threat model is amended by decision, never by omission.** A newly discovered risk gets a
  numbered section in `THREAT-MODEL.md` even when there is no mitigation. §4.10 exists because a
  risk was named before it was solved.
- **New cryptography is refused.** Four primitives, listed in §2.1. Adding a fifth, or writing an
  existing one from scratch, is out of scope regardless of how good the reason sounds.
- **No third-party dependency.** Including "just for tests" and "just for the build".
- **Epistemic honesty is the review criterion.** A pull request that says "this closes BE-GRANT-03"
  and does not is worse than one that says "this partly addresses it and here is what is missing".
  The second is more useful and gets merged faster.

---

## 4. Changing the specification

1. Say what is wrong with the current text, concretely. "Unclear" is not a defect report; "these
   two rules contradict each other and here is the sequence that breaks" is.
2. Write the fix as normative text, in the existing style: `MUST`/`MUST NOT`, a `BE-*` where a rule
   is being created, and the *reasoning* in italics after the rule. The reasoning is not decoration.
   Every rule here has an incident or an argument behind it, and a rule without its reason gets
   deleted by someone who does not know why it was there.
3. Check the interactions. Half of the real defects found so far were pairs of individually
   reasonable rules that contradicted each other one layer apart.
4. Bump the draft version if the wire format changes. There is no extension mechanism (§2.2); a
   format change is a version change.

**Prefer removing a field to validating it.** The strongest fixes in this specification were
deletions: `Intent.action_digest` removed rather than checked (BE-BODY-02), `evidence_class`
replaced by a compile-time `method_id` (BE-EVID-11), membership authority removed from the DAG
(BE-CHAN-01). What does not exist cannot be forged, and a redundant field that must be checked is a
check that will eventually be forgotten.

---

## 5. Contributions written by agents

This project's threat model treats autonomous agents as **structurally unreliable rather than
malicious** (`THREAT-MODEL.md` §2.1). Refusing agent contributions would be inconsistent with
building a protocol whose entire purpose is to make agent output verifiable. So they are welcome,
under the same rules plus one:

- **Declare it.** A commit or pull request substantially produced by an agent says so, and names
  the model. This is provenance, not stigma. It is also the first thing anyone auditing a defect
  will want to know.
- **The mechanical rules do not soften.** Section 2 is enforced identically. That is the point: if
  the CI gates are real, the author's reliability stops being load-bearing.
- **A claim in a pull request description is a claim.** "Fixed", "verified", "tested" in a
  description with no CI run behind it is exactly the failure pattern in `SPEC.md` §0.1, submitted
  to the repository of the protocol written to prevent it.

---

## 6. Attribution

- `SPEC.md` §10.2 lists prior work by Daniel Carneiro that Bolina formalizes. It is a historical
  record and does not grow with new contributions.
- External work goes in §10.1 and §11.9, with the author named. See `NOTICE`.
- Contributors are listed in `CONTRIBUTORS`.
- Contributions are under Apache 2.0 (`LICENSE`), which includes the patent grant in §3. That grant
  is why the licence was chosen: a protocol is worth nothing if implementing it carries legal risk.

---

## 7. Before writing any implementation code

Two items from `THREAT-MODEL.md` §7 come first, in this order, and neither is optional:

1. **Red team of `SPEC.md` §8 on paper** — enumerate every in-edge to `EXECUTING` and attempt to
   reach it without a valid Grant. The document says "before any implementation" and means it.
2. **Test vectors (§11.3) written before the first parser** — otherwise the first implementation
   defines the format by accident, bugs included, and the second one has to match them.

Then the first slice is already specified: `LANGUAGE.md` §4. Treat it as **falsification of the
specification**, not as construction of the product. A 1400-line specification that has never been
compiled contains errors. When you find one, the specification gets fixed.
