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
| M2 | 100% mutant kill over the BE-GRANT-03 checks the slice models, the BE-GRANT-03b callback property, and the section-7 attestation properties (class derivation, ceiling integers, min recompute, subject match, supersession, three-state resolution); every check set is derived from `SPEC.md` at run time, not stated by the harness. Survivors elsewhere are recorded with a cause. | §11.2 |
| M3 | Cross-implementation test vectors pass byte-for-byte. | §11.3 |
| M4 | Differential fuzzing is clean, reporting coverage and corpus, on any change touching parsing code. **A merge gate, not a milestone.** | §11.6, BE-SURF-04 |
| M5 | Network-parsing module ≤ 1500 lines. | BE-SURF-03 |
| M6 | Build succeeds with the network disabled and no package manager. | §11.7, BE-DEP-01 |
| M7 | Shipped build is `ReleaseSafe`; compiler version and flags recorded with every result. | §11.8, `LANGUAGE.md` O1, O4 |
| M8 | The capability type is gone, so there is nothing to forge: zero code-only pointer-minting builtins (`@ptrCast` or `@ptrFromInt`) anywhere in `src/`. `verifyGrantThen` runs the effect as a callback and hands back no value, so no boundary cast remains and no negative canary is needed. | §8.2, BE-GRANT-03b |
| M9 | Every parser error exit routes through `coverage.reject()` and every accepted return through `coverage.accept()`; `src/parser.zig` contains zero raw error returns, no exceptions, and the coverage denominator is counted from those call sites at run time. | §11.6 |
| M10 | The effect is reachable only from `verifyGrantThen`: the single `execute()` call site in `src/verify.zig` is the only reach path, enforced by a zero-exceptions grep in M9's shape (the count of 1 is read from the source at run time). | §8.2, BE-GRANT-03b |

If a change cannot satisfy one of these, the change is wrong or the rule is wrong. Both are fine
outcomes. Merging anyway is not.

### Gate denominators

Every gate's denominator is derived from a source the gate does not control: `SPEC.md`, the
source tree, or the language reference. A gate that counts what it controls can be gamed by
editing the thing it counts, so a count is load-bearing only when it traces to an external
source.

- M1 derives its `BE-*` bijection from `SPEC.md` and the test file at run time.
- M2 derives the modelled-check set from `SPEC.md`'s BE-GRANT-03 enumerated list and
  conformance sentence, covers the BE-GRANT-03b callback property by mutant, and
  derives the section-7 evidence property set from the §7 tables and BE-EVID markers
  (ceiling integers, the method_id->class table, BE-EVID-02/03/05/05a/09/09b).
- M5 reads the parser module's line count from the source tree.
- M8 derives the pointer-minting builtin set `{@ptrCast, @ptrFromInt}` from the Zig language
  reference; round 4 deleted the capability value, so the count it gates is zero.
- M9 counts exit-point call sites from `src/parser.zig` and matches them against the `Branch`
  enum one for one.

A literal number in a gate is a smell. If one is unavoidable, it must cite the external source
it mirrors: M10's count of 1 mirrors the single reach path in `src/verify.zig`; M5's 1500 mirrors
BE-SURF-03's "1500 lines". M8's count is zero because round 4 deleted the capability value; a zero
count needs no external mirror, since it is the absence, not a literal. A literal that names no
source is a denominator the gate invented, and inventing a denominator is the same failure as
counting what the gate controls.

### Remove, don't check

The denominator law says a gate must not count what it controls. The complement is older and
harder-won: when a guarantee seems to need a check, the first question is whether the thing
being checked has to exist at all. A field that can be removed cannot be forged; a check that
is never written cannot be forgotten. Four times now the right fix has been the same move:

| Instance | Checked, then | Removed instead |
|---|---|---|
| `Intent.action_digest` | validated against a stored digest (BE-BODY-02) | the field deleted; the executor recomputes over the bytes it already holds |
| DAG membership authority | arbitrated by the channel (BE-CHAN-01) | granted by the CA, not by the channel; nothing left to arbitrate |
| raw parser exit | counted and reconciled against the branch set (§11.6) | routed through `coverage.reject()`/`coverage.accept()`; zero raw error returns, nothing to count |
| the verify-consume window | sealed by content (BE-GRANT-03c) | deleted; `verifyGrantThen` runs the effect inside the frame, no interval left to drift in |

Each row is a removal that retired a check site, a gate, or both. The rule is not "never check";
it is "before you write the check, prove the checked thing must exist." A check written where a
deletion was possible is debt the moment it lands, and debt of this kind has not been repaid late.

### Don't reference the constant under test

The denominator law's testing twin. A test that references the constant it verifies asserts
nothing about that constant: change the constant and both sides of the check move together, the
test stays green, and a mutant on the constant survives with the full suite passing. The window
this opens is exactly the one the denominator law closes on the gate side. So a test MUST NOT
reference the constant it verifies. Assert the literal value the spec names (`1034`, `1048576`,
`8388608`), never the module constant (`replay.WINDOW_BITS`, `ras.MAX_MESSAGE`,
`ras.MEMORY_PER_PEER`); if a mutant then survives, the survivor is the finding and names the
assertion to harden. Round 4 caught this by keying the window-bits mutant and watching it
survive a symbolic test, then killing it once the assertions went literal.

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
