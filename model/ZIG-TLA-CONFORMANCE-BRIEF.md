# Zig-to-TLA+ grant-path conformance pilot

Status: proposal for review. This document does not claim that the Zig
implementation conforms to the TLA+ model.

## 1. Question

Can an execution of Bolina's Zig grant path be recorded, projected onto the
actions in `Bolina.tla`, and rejected automatically when no behavior of the
model admits that projected trace?

Yes, for a bounded test-only pilot. The useful claim would be:

> For every captured test execution `z`, the projected trace `P(z)` is an
> admitted finite prefix of `Bolina.tla` under the configuration and model
> identity recorded with the result.

That is trace conformance for observed executions. It is not a proof over all
possible Zig executions, a proof of the filesystem, or a production security
claim.

## 2. Why this bridge is needed

TLC has exhaustively checked the finite state space selected by `Bolina.cfg`.
That result is about the TLA+ state machine. The implementation was used as a
source when the model was written, but there is currently no executable link
between a Zig run and a TLA+ behavior.

The bridge supplies that missing link without treating logs as authority:

```text
instrumented Zig test execution
              |
              v
versioned append-only event trace
              |
              v
deterministic projector + binding manifest
              |
              v
generated trace-constrained TLA+ harness
              |
              v
TLC admission or first rejected event
              |
              v
digest-bound conformance receipt
```

The model remains the behavioral authority for the check. The projector may
rename concrete identifiers and remove implementation-only detail, but it must
not repair, reorder, or invent semantic events.

## 3. Pilot boundary

The first slice should cover only the grant path already represented in
`Bolina.tla`:

- intent admission and resource conflict;
- the ordered verification frame;
- durable consume at check 11;
- effect start and return;
- publication and published tombstone;
- the later `beginExecuting` bookkeeping witness;
- crash, restart, orphan publication, and orphan tombstoning;
- expiry and the four prune phases.

Parsing, certificate mathematics, cryptographic correctness, transport,
performance, and arbitrary operating-system behavior stay outside the pilot.
The verification trace records that a named check passed or refused; it does
not reimplement that check in the projector.

## 4. Conformance unit

One conformance case consists of:

1. exact Zig source and compiler identities;
2. exact `Bolina.tla`, configuration, projector, and trace-harness identities;
3. one declared scenario and fault schedule;
4. one raw append-only event trace;
5. one deterministic identifier/time projection;
6. one generated TLA+ trace harness;
7. the TLC log and terminal classification; and
8. a receipt binding every input and output by digest.

The raw trace is evidence. The normalized trace is a derived view and must
retain a one-to-one reference to every raw event it uses.

## 5. Event contract

Events should be emitted only in a test or conformance build. The sink should
append to a fixed-size in-memory buffer, perform no allocation or filesystem
I/O in the verification frame, and fail the test on overflow. This keeps
instrumentation from adding a fallible operation or a new race to the path
being measured.

Each event needs at least:

```json
{
  "schema": "bolina.grant-trace.v1",
  "run_id": "case-uuid",
  "process_epoch": 0,
  "sequence": 17,
  "event": "effect_started",
  "intent_id": "hex-or-null",
  "grant_id": "hex-or-null",
  "resource_id": "hex-or-null",
  "check": null,
  "result": "ok",
  "previous_event_sha256": "sha256-or-null-for-first-event",
  "source_anchor": "src/verify.zig:execute-callback"
}
```

Required rules:

- `(run_id, process_epoch, sequence)` is unique and strictly increasing;
- each serialized event links the preceding canonical event bytes by digest;
- identifiers are encoded canonically and never contain secret key material;
- a new process epoch is explicit after restart;
- events name completed linearization points, not intentions to perform work;
- `effect_started` is recorded at callback entry, not before dispatching the
  callback and not after it returns;
- a durable event is recorded only after the corresponding sync succeeds;
- unknown, duplicate, malformed, out-of-order, or unmapped events reject the
  case rather than being ignored.

Trace loss or buffer overflow is an `INSTRUMENTATION_ERROR`, never a shortened
passing trace. The serializer adds the digest chain after capture; hashing must
not be inserted into the verification frame.

## 6. Initial Zig-to-TLA+ binding

The exact insertion sites need code review before implementation. The intended
binding is:

| Zig observation | TLA+ action | Required observation point |
|---|---|---|
| successful intent admission | `ReceiveIntent` | after `resolveAndAdmit` returns, reading the canonical resource from the admitted table entry |
| resource-conflict refusal | `RejectResourceConflict` | after `resolveAndAdmit` returns `error.ResourceHeld` and the caller observes the refusal |
| entry to `verifyGrantThen` | `BeginVerify` | before check 0, after the pending-intent binding exists |
| successful verification check 0..10 | `VerifyCheck` | immediately after each named check passes |
| verification refusal with check and cause | observational stutter | preserve the event and advance only the trace cursor; the base model has no verification-refusal action |
| already-consumed refusal | observational stutter | preserve the refusal and emit neither `CommitConsumedCheck11` nor `EffectStart` |
| `GrantLedger.commitConsumed` success | `CommitConsumedCheck11` | after `appendSync` returns successfully |
| effect callback entry | `EffectStart` | first instruction of the wrapped `execute_effect` callback |
| effect callback return | `EffectReturn` | immediately after the callback returns |
| effect outcome publication attempt | `PublishOutcome` | currently unbound: `execute_effect` returns `void` and exposes no publication result |
| `GrantLedger.markPublished` success | `MarkPublished` | after its `appendSync` returns successfully |
| `GrantLedger.markPublished` failure | unresolved | preserve the failure; never project it as `MarkPublished` success |
| successful `beginExecuting` | `RecordExecutingWitness` | after `beginExecuting` returns |
| terminal intent completion | `FinishExecuted` or `FinishFailed` | currently unbound in the reviewed dispatch path |
| clock advance used by the case | `AdvanceTime` | when the controlled test clock changes bucket |
| pending-intent expiry | `ExpirePending` | after the expiry transition returns |
| prune temp write/sync/rename/reopen | corresponding `Prune*` action | after each operation's linearization point |
| process termination and new startup | `Crash`, then `Restart` | harness-owned epoch boundary |
| recovered orphan publication | `RecoverPublishInterrupted` | currently caller-owned and unbound; observing an orphan is not publication evidence |
| successful `tombstoneOrphan` | `RecoverMarkPublished` | after `markPublished` returns |

Two details are load-bearing:

1. Under D-067, `EffectStart` performs the normative
   `APPROVED -> EXECUTING` transition. `beginExecuting` maps to the later
   `RecordExecutingWitness`; it must never be projected as authorization for
   the effect.
2. `CommitConsumedCheck11` is emitted only after the durable commit succeeds.
   An event before `appendSync` would turn attempted durability into false
   evidence.

If a Zig path has no trustworthy observation point for one of these actions,
the pilot must report an unbound action. The projector must not synthesize it.

The current source exposes two such gaps: actual Effect publication and
terminal intent completion. A trace may conform as a finite prefix before
those points, but it may not claim the unobserved actions occurred.

## 7. Deterministic projection

The projector should be a small standalone tool with a versioned input schema.
For each case it should:

1. validate the event schema and monotonic sequence;
2. validate the event digest chain, correlation, and lifecycle completeness;
3. assign concrete intent, grant, and resource identifiers injectively to the
   finite TLA+ atoms declared by the selected configuration;
4. map controlled clock observations to TLA+ time buckets while preserving all
   expiry comparisons used by the case;
5. translate each semantic event through a checked binding table;
6. classify a case that exceeds the configuration's cardinality or time bound
   as `OUT_OF_SCOPE`, rather than `NONCONFORMANT`;
7. emit a canonical normalized trace and its digest; and
8. generate a trace-constrained TLA+ module without modifying `Bolina.tla`.

Identifier assignment must not depend on thread scheduling or hash-map
iteration. A suitable rule is first semantic occurrence, broken only by the
canonical encoded identifier. The binding manifest records the assignment so
the same raw trace always produces identical bytes.

## 8. TLC admission algorithm

The generated module should `EXTENDS Bolina` and add a trace cursor. At cursor
`k`, exactly the action and parameters named by projected event `k` are
enabled. Completion sets an explicit `TraceAccepted` marker.

The runner then checks two independent outcomes:

- TLC can reach `TraceAccepted` through the complete ordered trace; and
- all base invariants selected by the case remain true along that behavior.

A disabled expected action is a conformance failure at that event. A base
invariant violation is a model violation. An unknown event, incomplete trace,
tool failure, timeout, or digest mismatch is an indeterminate result, never a
pass.

The receipt classification is one of `ACCEPTED`, `NONCONFORMANT`,
`OUT_OF_SCOPE`, `INVALID_TRACE`, or `INSTRUMENTATION_ERROR`. Observation-only
events advance the trace cursor with `UNCHANGED state`; they are never silently
dropped. The generated harness permits a self-loop only after every event is
consumed, so deadlock checking can distinguish a blocked expected action from
successful completion.

The generator must not copy the state-transition rules into Python or Zig.
Doing so would create a second model that could drift while still agreeing
with its own traces.

## 9. Open design decisions

The pilot can validate a prefix through `EffectReturn` now. A full normal-path
trace needs two decisions first:

1. **Effect publication boundary.** `Hooks.execute_effect` returns `void`, and
   the reviewed path exposes neither Effect-publication success nor failure.
   `PublishOutcome`, `FinishExecuted`, `FinishFailed`, and real
   `RecoverPublishInterrupted` therefore have no current evidence source.
2. **Tombstone failure versus bookkeeping witness.** `dispatchGrant` ignores a
   `markPublished` failure and still calls `beginExecuting`. In contrast,
   `RecordExecutingWitness` in `Bolina.tla` requires the grant to be in
   `StablePublished`. A failed-tombstone Zig trace would be rejected by the
   current model. Reviewers must decide whether the implementation, model, or
   binding changes; the projector must not fabricate tombstone success.

These are semantic decisions, not projector conveniences. They remain visible
and block a full-path conformance claim.

## 10. Acceptance cases

The first ordering pilot is acceptable only if all phase-A cases pass. The
remaining cases gate the later full-path extension.

### Phase A: ordering bridge

- normal grant execution through `EffectReturn`;
- two independent resources;
- resource conflict refusal;
- refusal at each verification check without durable consume or effect;
- replay refusal after durable consume;
- effect start before durable consume is rejected;
- a second effect start for one grant is rejected;
- effect start without all ordered verification checks is rejected;
- `beginExecuting` used as the effect authorization point is rejected;
- consume before check 10 completes is rejected;
- a missing, duplicate, or reordered event is rejected; and
- an identifier remapped midway through a trace is rejected.

### Phase B: publication, crash, recovery, and prune

- effect return followed by publication and tombstone;
- crash after consume but before tombstone, followed by interrupted publication;
- restart clearing volatile pending state;
- expiry before verification; and
- prune completion across the old-or-new rename outcomes represented by the model.

Phase B also requires these negative controls:

- recovery retrying the action effect;
- recovery publication after a durable tombstone;
- loss of a still-acceptable consumed grant during prune/restart.

The unresolved tombstone-failure sequence is a mandatory decision case: it
must remain rejected or explicitly out of scope until the implementation/model
relationship is settled.

These controls mirror the current TLA+ mutants where possible, but they test
the trace bridge itself. A mutant killed only inside `BolinaEvaluation.tla`
does not prove that the Zig instrumentation and projector would expose it.

## 11. Drift and reproducibility

Every conformance receipt should bind:

- Zig source commit and dirty-state policy;
- Zig compiler version and build flags;
- model, configuration, evaluation module, and action-binding digests;
- projector and generated-harness digests;
- TLA+ tools version and JAR digest;
- scenario, seed, clock, scheduler, and fault schedule;
- raw and normalized trace digests; and
- TLC command, exit status, classification, and complete log digest.

A change to a bound Zig function, TLA+ action, event schema, projector, or
selected configuration invalidates the old conformance result and requires
replay. This is the drift gate; textual line numbers alone are not a stable
binding.

Before independent execution, `run-evaluation.py` also needs a portable tool
selection interface. Its current absolute local paths preserve the identity of
the completed local run but cannot be assumed on a reviewer or CI host. Any
portability change must receive a fresh digest-bound replay.

## 12. Risks

- **Observer effect:** tracing changes scheduling or error behavior. Mitigate
  with a fixed in-memory sink and a separate comparison run with tracing off.
- **Missing-event false pass:** an omitted event hides an illegal step.
  Mitigate with structural binding coverage and negative trace mutations.
- **Overfitted projection:** concrete data is collapsed until every trace fits.
  Mitigate with injective identifier mapping and explicit bound failures.
- **False rejection:** implementation detail is mistaken for a model action.
  Mitigate by allowing implementation-only stuttering steps outside the
  semantic event stream.
- **Clock distortion:** time bucketing changes an expiry comparison. Mitigate
  by recording the comparison-relevant values and proving each bucket mapping.
- **Crash ambiguity:** a process cannot emit an event after it has crashed.
  The external harness, not the process, owns crash and restart epoch events.
- **Shared bug:** model and projection repeat the same misunderstanding.
  Keep source bindings reviewable and retain adversarial negative controls.

## 13. Non-claims

A successful pilot would not establish:

- conformance of executions that were not captured;
- correctness of cryptography, parsing, memory safety, or the Zig compiler;
- POSIX, Windows, disk-controller, or power-loss semantics;
- absence of uninstrumented effect paths without a separate structural gate;
- a universal theorem over unbounded actors, resources, or time;
- security certification, release approval, or production readiness.

It would establish a narrower and useful fact: the observed, digest-bound Zig
execution projected through the reviewed binding is admitted by the exact
TLA+ model and bounds named in the receipt.

## 14. Go/no-go decision

Proceed with implementation only if reviewers accept all five points:

1. test-only in-memory instrumentation may be added at the named linearization
   points without changing the normative grant path;
2. D-067's effect-start transition and later bookkeeping witness remain
   separate events;
3. generated trace harnesses are checked by TLC against `Bolina.tla`, rather
   than by a duplicate state machine in the projector; and
4. the publication and tombstone-failure decisions in section 9 have owners
   and may not be inferred by the projector; and
5. the accepted claim is observed bounded trace conformance, with the
   non-claims above retained.

If accepted, the smallest implementation slice is one normal-path prefix
through `EffectReturn` plus two negative controls: effect-before-consume and
`beginExecuting` treated as authorization. That slice tests the bridge's
central ordering claim before adding publication, crash, recovery, and prune
complexity.
