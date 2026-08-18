"""Checked Zig-to-TLA+ binding table for the bolina.grant-trace.v1 pilot.

This file is the single place where a trace event becomes a model action.
Section 6 of ZIG-TLA-CONFORMANCE-BRIEF.md fixes the intent; section 7 requires
the translation to run through a checked table rather than ad hoc code, and
section 8 forbids restating the state-transition rules outside Bolina.tla.
Nothing here decides whether a step is legal: that is TLC's job against the
model. This table only says which action an event claims to be, and refuses
to answer when the answer is not in the trace.

Three outcomes exist for an event, and the difference is load-bearing:

  ACTION    the event names a model action, with parameters read from the
            trace (never invented).
  STUTTER   the event is real and preserved, but the base model has no action
            for it (a verification refusal, for instance). It advances the
            trace cursor with UNCHANGED state. It is never dropped: dropping
            it would let an illegal step hide between two legal ones.
  UNBOUND   the implementation exposes no trustworthy observation point for
            the action the event would have to claim. The projector must
            fail the case rather than synthesize it (brief section 6).
"""

SCHEMA = "bolina.grant-trace.v1"

ACTION = "action"
STUTTER = "stutter"
UNBOUND = "unbound"

# Parameter roles. The projector resolves each to a TLA+ atom through the
# injective assignment; it never fabricates one.
P_INTENT = "intent"
P_GRANT_INTENT = "grant_intent"  # the intent this grant binds to (correlation)
P_RESOURCE = "resource"
P_GRANT = "grant"

# tag -> (kind, TLA+ action or reason, parameter roles in TLA+ argument order)
BINDING = {
    # --- admission ---------------------------------------------------------
    "receive_intent": (ACTION, "ReceiveIntent", (P_INTENT, P_RESOURCE)),
    "reject_resource_conflict": (ACTION, "RejectResourceConflict", (P_INTENT, P_RESOURCE)),

    # --- verification frame ------------------------------------------------
    # begin_verify carries the correlation that lets every later grant-path
    # event name an intent. The model indexes the frame by intent, so the
    # projector maps grant -> intent here and reuses it downstream.
    "begin_verify": (ACTION, "BeginVerify", (P_GRANT_INTENT,)),
    "verify_check": (ACTION, "VerifyCheck", (P_GRANT_INTENT,)),

    # --- durable commit and effect ----------------------------------------
    # D-067: EffectStart performs the normative APPROVED -> EXECUTING
    # transition. record_executing_witness maps to the later bookkeeping
    # action and must never be projected as authorization for the effect.
    "commit_consumed_11": (ACTION, "CommitConsumedCheck11", (P_GRANT_INTENT,)),
    "effect_start": (ACTION, "EffectStart", (P_GRANT_INTENT,)),
    "effect_return": (ACTION, "EffectReturn", (P_GRANT_INTENT,)),
    "record_executing_witness": (ACTION, "RecordExecutingWitness", (P_GRANT_INTENT,)),

    # --- publication -------------------------------------------------------
    "publish_outcome": (ACTION, "PublishOutcome", (P_GRANT,)),
    "mark_published": (ACTION, "MarkPublished", (P_GRANT,)),
    "recover_mark_published": (ACTION, "RecoverMarkPublished", (P_GRANT,)),

    # --- prune (D-063 atomic rename, four linearization points) ------------
    "prune_temp_written": (ACTION, "PruneWriteTemp", ()),
    "prune_temp_synced": (ACTION, "PruneSyncTemp", ()),
    "prune_renamed": (ACTION, "PruneRename", ()),
    "prune_reopened": (ACTION, "PruneReopen", ()),

    # --- expiry ------------------------------------------------------------
    "expire_pending": (ACTION, "ExpirePending", (P_INTENT,)),

    # --- preserved, but no base action -------------------------------------
    # A refused effect is D-061/D-080 semantics: the capability is spent and
    # the tombstone is never written. Bolina.tla has no refusal action, so the
    # event stutters. Rejecting the case instead would make the model reject
    # correct behaviour; dropping the event would let a later illegal step
    # look adjacent to a legal one.
    "effect_refused": (STUTTER, "no base action for executor refusal (D-080)", ()),
    # D-080 ruling 1 keeps the failed tombstone fail-safe in control flow and
    # loud in evidence. Bolina.tla requires StablePublished before the witness,
    # so a failed-tombstone trace is the brief's mandatory decision case: it
    # stays explicitly out of scope until implementation and model are settled,
    # and is never projected as MarkPublished success.
    "mark_published_failed": (UNBOUND, "brief section 9.2 decision case: model requires StablePublished before the witness, implementation does not (D-080)", ()),

    # --- instrumentation ---------------------------------------------------
    # Never a shortened passing trace (brief section 5).
    "trace_overflow": (UNBOUND, "INSTRUMENTATION_ERROR: fixed sink overflowed", ()),
}

# Actions the model declares that no current Zig observation point can claim.
# Listed so a receipt can state what was NOT covered rather than implying the
# whole model was exercised.
UNOBSERVED_ACTIONS = {
    "FinishExecuted": "terminal intent completion is unbound in the reviewed dispatch path",
    "FinishFailed": "terminal intent completion is unbound in the reviewed dispatch path",
    "RecoverPublishInterrupted": "caller-owned; observing an orphan is not publication evidence",
    "AdvanceTime": "harness-owned controlled clock, not an implementation event",
    "Crash": "harness-owned process epoch boundary",
    "Restart": "harness-owned process epoch boundary",
    "ObserveIndependentResources": "model-internal observation, no implementation counterpart",
}

# Which JSON identity fields each tag is allowed to carry. The projector
# rejects a trace that fills a field the tag has no right to, which is how a
# reordered or hand-edited trace fails instead of silently reinterpreting.
IDENTITY_FIELDS = {
    "receive_intent": ("intent_id", "resource_id"),
    "reject_resource_conflict": ("intent_id", "resource_id"),
    "begin_verify": ("grant_id", "intent_id"),
    "verify_check": ("grant_id",),
    "commit_consumed_11": ("grant_id",),
    "effect_start": ("grant_id",),
    "effect_return": ("grant_id",),
    "effect_refused": ("grant_id",),
    "publish_outcome": ("grant_id",),
    "mark_published": ("grant_id",),
    "mark_published_failed": ("grant_id",),
    "record_executing_witness": ("grant_id",),
    "recover_mark_published": ("grant_id",),
    "prune_temp_written": ("ledger_id",),
    "prune_temp_synced": ("ledger_id",),
    "prune_renamed": ("ledger_id",),
    "prune_reopened": ("ledger_id",),
    "expire_pending": ("ledger_id",),
    "trace_overflow": (),
}

# The one tag that carries a check index, and its legal range. Check 11 is
# reported by commit_consumed_11 after the durable append, never as a
# verify_check: an event before appendSync would turn attempted durability
# into false evidence (brief section 6).
CHECK_TAG = "verify_check"
CHECK_RANGE = range(0, 11)
