# Conformance pilot findings

Findings are disagreements between the implementation and `Bolina.tla` that
the bridge surfaces. A finding is not a bug report against either side: it is
a place where two descriptions of the same system diverge, and where somebody
has to decide which one moves. Each stays open until an owner rules.

Sections refer to `ZIG-TLA-CONFORMANCE-BRIEF.md`.

---

## F-01: the model does not admit an empty prune, the implementation performs one

**Status:** open, needs a ruling. Blocks the Phase A "normal grant execution
through EffectReturn" case.

**Implementation.** `GrantLedger.commitConsumed` runs `pruneExpired` before
every append (D-061 ruling 4, to bound the log). On the first grant against a
fresh ledger there is nothing to prune, but the prune still performs the full
D-063 atomic rename: write temp, fsync temp, rename over the live path,
reopen and fsync. Those are four real durable operations and the trace
records four events for them. `src/grant_trace_test.zig` pins the ordering:
the four prune events precede `commit_consumed_11` in the happy path.

**Model.** `PruneWriteTemp` (`model/Bolina.tla:292`) is guarded by
`StableConsumed /= {}`. With an empty consumed set the action is disabled, so
a trace whose first prune happens before any commit has no admitting step and
TLC deadlocks at that event.

**Consequence if unresolved.** The most basic Phase A case fails as
`NONCONFORMANT` for a reason that is not a safety defect. That is the false
rejection risk named in brief section 12: an implementation detail mistaken
for a model action.

**Why the projector must not decide it.** Whether the ledger is empty at that
point is model state. Answering it inside the projector would mean simulating
the transition rules outside `Bolina.tla`, which section 8 forbids precisely
because the second machine can drift and still agree with itself.

**Options, none of them free.**

1. *Relax the model guard.* Drop `StableConsumed /= {}` so an empty prune is a
   legal no-op cycle. Faithful to what the implementation does, and keeps the
   crash-safety content of D-063 (`PruneRename` still swaps the set). Costs
   state space, and it is a semantic change to the model.
2. *Make the empty prune a stutter.* Honest only if the projector can tell an
   empty prune from a real one, which it cannot without modeling. Rejected on
   those grounds unless the trace itself carries the distinction, which would
   be a v2 contract change.
3. *Build Phase A fixtures with a pre-seeded ledger* so every prune is
   non-empty. Cheapest, but it dodges the finding rather than resolving it,
   and the first-grant path would stay unverified forever.
4. *Change the implementation to skip an empty prune.* A production change to
   suit a modeling convenience. Wrong direction, and it would remove a real
   durable operation from the crash surface D-063 exists to protect.

**Recommendation.** Option 1, decided by the model owner. It is the only one
that keeps the first-grant path verifiable and leaves the implementation
alone. Option 3 is acceptable only as an explicitly labelled interim, with the
first-grant path recorded as uncovered.

**Not decided here.** The model is the external contributor's lane, and this
is exactly the kind of semantic call that keeps the seal honest when someone
other than the implementer makes it.
