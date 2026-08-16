------------------------------ MODULE Bolina ------------------------------
(***************************************************************************)
(* Bounded semantic projection of the Bolina SPEC section 8 grant path.    *)
(*                                                                         *)
(* Source: 492f0e31009bcb905e309de5572a2d25dee793bf                       *)
(* Decisions: D-061, D-063, D-067, D-072                                  *)
(*                                                                         *)
(* D-067 is load-bearing: EffectStart atomically establishes normative     *)
(* EXECUTING and records the only action-effect attempt. The later         *)
(* RecordExecutingWitness action represents beginExecuting bookkeeping;    *)
(* it is not authorization and is never an effect precondition.            *)
(*                                                                         *)
(* This model is finite evidence, not protocol authority, Zig conformance,  *)
(* real-filesystem evidence, or a general security proof.                  *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS IntentA, IntentB,
          GrantA, GrantB,
          ResourceA, ResourceB,
          NoIntent, NoResource,
          MaxTime

ASSUME IntentA /= IntentB
ASSUME GrantA /= GrantB
ASSUME ResourceA /= ResourceB
ASSUME MaxTime = 2

Intents == {IntentA, IntentB}
Grants == {GrantA, GrantB}
Resources == {ResourceA, ResourceB}

IntentStates == {
    "absent", "pending", "approved", "executing",
    "executed", "failed", "expired", "rejected"
}

PCNone == 13
PCDomain == (0..12) \cup {PCNone}
PrunePhases == {"idle", "temp_complete", "temp_synced", "renamed"}

GrantOf(i) == IF i = IntentA THEN GrantA ELSE GrantB

NotAfter(g) == IF g = GrantA THEN MaxTime + 1 ELSE 1

PendingDeadline(i) == IF i = IntentA THEN 1 ELSE MaxTime

SaturatingInc(n) == IF n >= 2 THEN 2 ELSE n + 1

VARIABLE state

vars == <<state>>

IntentState == state.intentState
IntentResource == state.intentResource
LockOwner == state.lockOwner
VerificationPC == state.verificationPC
StableConsumed == state.stableConsumed
StablePublished == state.stablePublished
EverCommitted == state.everCommitted
EffectCount == state.effectCount
RecoveryPublicationCount == state.recoveryPublicationCount
PublicationAttemptCount == state.publicationAttemptCount

Active(i) == IntentState[i] \in {"pending", "approved", "executing"}

Acceptable(g) == state.now < NotAfter(g)

NoVolatile ==
    /\ \A i \in Intents : ~Active(i) /\ VerificationPC[i] = PCNone
    /\ \A r \in Resources : LockOwner[r] = NoIntent

Init ==
    state = [
        intentState |-> [i \in Intents |-> "absent"],
        intentResource |-> [i \in Intents |-> NoResource],
        lockOwner |-> [r \in Resources |-> NoIntent],
        verificationPC |-> [i \in Intents |-> PCNone],
        stableConsumed |-> {},
        stablePublished |-> {},
        everCommitted |-> {},
        effectCount |-> [g \in Grants |-> 0],
        recoveryPublicationCount |-> [g \in Grants |-> 0],
        publicationAttemptCount |-> [g \in Grants |-> 0],
        validExecutingEntry |-> [i \in Intents |-> FALSE],
        commitSeenBeforeEffect |-> [g \in Grants |-> FALSE],
        committedAfterChecks |-> [g \in Grants |-> FALSE],
        executionEstablishedAtEffectStart |-> [g \in Grants |-> FALSE],
        effectReturned |-> [g \in Grants |-> FALSE],
        executionWitnessRecorded |-> [i \in Intents |-> FALSE],
        tombstoneSnapshotSet |-> [g \in Grants |-> FALSE],
        recoveryCountAtTombstone |-> [g \in Grants |-> 0],
        recoverySnapshotSet |-> [g \in Grants |-> FALSE],
        recoveryEffectSnapshot |-> [g \in Grants |-> 0],
        processUp |-> TRUE,
        restarted |-> FALSE,
        freshAfterRestart |-> FALSE,
        crashedWithVolatile |-> FALSE,
        now |-> 0,
        prunePhase |-> "idle",
        prePruneLedger |-> {},
        candidateLedger |-> {},
        recoverableOrphans |-> {},
        normalExecutionSeen |-> FALSE,
        independentResourcesSeen |-> FALSE,
        conflictRefusalSeen |-> FALSE,
        restartClearedVolatileSeen |-> FALSE,
        orphanRecoverySeen |-> FALSE,
        expirySeen |-> FALSE
        ]

ReceiveIntent(i, r) ==
    /\ state.processUp
    /\ IntentState[i] = "absent"
    /\ LockOwner[r] = NoIntent
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "pending"],
        !.intentResource = [@ EXCEPT ![i] = r],
        !.lockOwner = [@ EXCEPT ![r] = i],
        !.verificationPC = [@ EXCEPT ![i] = PCNone],
        !.freshAfterRestart = FALSE
        ]

RejectResourceConflict(i, r) ==
    /\ state.processUp
    /\ ~state.conflictRefusalSeen
    /\ IntentState[i] = "absent"
    /\ LockOwner[r] /= NoIntent
    /\ LockOwner[r] /= i
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "rejected"],
        !.intentResource = [@ EXCEPT ![i] = r],
        !.conflictRefusalSeen = TRUE
        ]

ObserveIndependentResources ==
    /\ state.processUp
    /\ ~state.independentResourcesSeen
    /\ Active(IntentA)
    /\ Active(IntentB)
    /\ IntentResource[IntentA] /= IntentResource[IntentB]
    /\ state' = [state EXCEPT !.independentResourcesSeen = TRUE]

BeginVerify(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ IntentState[i] = "pending"
    /\ Acceptable(g)
    /\ g \notin StableConsumed
    /\ IntentResource[i] \in Resources
    /\ LockOwner[IntentResource[i]] = i
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "approved"],
        !.verificationPC = [@ EXCEPT ![i] = 0]
        ]

VerifyCheck(i) ==
    /\ state.processUp
    /\ IntentState[i] = "approved"
    /\ VerificationPC[i] \in 0..10
    /\ IntentResource[i] \in Resources
    /\ LockOwner[IntentResource[i]] = i
    /\ state' = [state EXCEPT
        !.verificationPC = [@ EXCEPT ![i] = VerificationPC[i] + 1]
        ]

CommitConsumedCheck11(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ state.prunePhase = "idle"
    /\ IntentState[i] = "approved"
    /\ VerificationPC[i] = 11
    /\ IntentResource[i] \in Resources
    /\ LockOwner[IntentResource[i]] = i
    /\ g \notin StableConsumed
    /\ state' = [state EXCEPT
        !.stableConsumed = @ \cup {g},
        !.everCommitted = @ \cup {g},
        !.committedAfterChecks = [@ EXCEPT ![g] = TRUE],
        !.verificationPC = [@ EXCEPT ![i] = 12]
        ]

EffectStart(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ IntentState[i] = "approved"
    /\ VerificationPC[i] = 12
    /\ g \in StableConsumed
    /\ EffectCount[g] = 0
    /\ IntentResource[i] \in Resources
    /\ LockOwner[IntentResource[i]] = i
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "executing"],
        !.effectCount = [@ EXCEPT ![g] = 1],
        !.validExecutingEntry = [@ EXCEPT ![i] = TRUE],
        !.commitSeenBeforeEffect = [@ EXCEPT ![g] = TRUE],
        !.executionEstablishedAtEffectStart = [@ EXCEPT ![g] = TRUE]
        ]

EffectReturn(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ IntentState[i] = "executing"
    /\ EffectCount[g] = 1
    /\ ~state.effectReturned[g]
    /\ state' = [state EXCEPT
        !.effectReturned = [@ EXCEPT ![g] = TRUE]
        ]

PublishOutcome(g) ==
    /\ state.processUp
    /\ state.effectReturned[g]
    /\ PublicationAttemptCount[g] = 0
    /\ g \notin StablePublished
    /\ state' = [state EXCEPT
        !.publicationAttemptCount = [@ EXCEPT ![g] = 1]
        ]

MarkPublished(g) ==
    /\ state.processUp
    /\ state.prunePhase = "idle"
    /\ state.effectReturned[g]
    /\ PublicationAttemptCount[g] > 0
    /\ g \notin StablePublished
    /\ state' = [state EXCEPT
        !.stablePublished = @ \cup {g},
        !.recoverableOrphans = @ \ {g},
        !.tombstoneSnapshotSet = [@ EXCEPT ![g] = TRUE],
        !.recoveryCountAtTombstone = [@ EXCEPT
            ![g] = RecoveryPublicationCount[g]]
        ]

RecordExecutingWitness(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ IntentState[i] = "executing"
    /\ state.effectReturned[g]
    /\ g \in StablePublished
    /\ ~state.executionWitnessRecorded[i]
    /\ state' = [state EXCEPT
        !.executionWitnessRecorded = [@ EXCEPT ![i] = TRUE]
        ]

FinishExecuted(i) ==
    LET r == IntentResource[i] IN
    /\ state.processUp
    /\ IntentState[i] = "executing"
    /\ state.executionWitnessRecorded[i]
    /\ r \in Resources
    /\ LockOwner[r] = i
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "executed"],
        !.lockOwner = [@ EXCEPT ![r] = NoIntent],
        !.verificationPC = [@ EXCEPT ![i] = PCNone],
        !.normalExecutionSeen = TRUE
        ]

FinishFailed(i) ==
    LET r == IntentResource[i] IN
    /\ state.processUp
    /\ IntentState[i] = "executing"
    /\ state.executionWitnessRecorded[i]
    /\ r \in Resources
    /\ LockOwner[r] = i
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "failed"],
        !.lockOwner = [@ EXCEPT ![r] = NoIntent],
        !.verificationPC = [@ EXCEPT ![i] = PCNone]
        ]

AdvanceTime ==
    /\ state.processUp
    /\ state.now < MaxTime
    /\ state' = [state EXCEPT !.now = @ + 1]

ExpirePending(i) ==
    LET r == IntentResource[i] IN
    /\ state.processUp
    /\ IntentState[i] = "pending"
    /\ state.now >= PendingDeadline(i)
    /\ r \in Resources
    /\ LockOwner[r] = i
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "expired"],
        !.lockOwner = [@ EXCEPT ![r] = NoIntent],
        !.intentResource = [@ EXCEPT ![i] = NoResource],
        !.verificationPC = [@ EXCEPT ![i] = PCNone],
        !.expirySeen = TRUE
        ]

PruneWriteTemp ==
    /\ state.processUp
    /\ state.prunePhase = "idle"
    /\ StableConsumed /= {}
    /\ state' = [state EXCEPT
        !.prePruneLedger = StableConsumed,
        !.candidateLedger = {g \in StableConsumed : Acceptable(g)},
        !.prunePhase = "temp_complete"
        ]

PruneSyncTemp ==
    /\ state.processUp
    /\ state.prunePhase = "temp_complete"
    /\ state' = [state EXCEPT !.prunePhase = "temp_synced"]

PruneRename ==
    /\ state.processUp
    /\ state.prunePhase = "temp_synced"
    /\ state' = [state EXCEPT
        !.stableConsumed = state.candidateLedger,
        !.prunePhase = "renamed"
        ]

PruneReopen ==
    /\ state.processUp
    /\ state.prunePhase = "renamed"
    /\ state' = [state EXCEPT
        !.prunePhase = "idle",
        !.prePruneLedger = {},
        !.candidateLedger = {}
        ]

CrashLedgerOptions ==
    IF state.prunePhase = "renamed"
    THEN {state.prePruneLedger, state.candidateLedger}
    ELSE {StableConsumed}

Crash ==
    /\ state.processUp
    /\ \E ledger \in CrashLedgerOptions :
        state' = [state EXCEPT
            !.intentState = [i \in Intents |->
                IF Active(i) THEN "expired" ELSE IntentState[i]],
            !.intentResource = [i \in Intents |->
                IF Active(i) THEN NoResource ELSE IntentResource[i]],
            !.lockOwner = [r \in Resources |-> NoIntent],
            !.verificationPC = [i \in Intents |-> PCNone],
            !.stableConsumed = ledger,
            !.recoverableOrphans = ledger \ StablePublished,
            !.processUp = FALSE,
            !.freshAfterRestart = FALSE,
            !.crashedWithVolatile = \E i \in Intents : Active(i),
            !.prunePhase = "idle",
            !.prePruneLedger = {},
            !.candidateLedger = {}
        ]

Restart ==
    /\ ~state.processUp
    /\ state' = [state EXCEPT
        !.processUp = TRUE,
        !.restarted = TRUE,
        !.freshAfterRestart = TRUE,
        !.restartClearedVolatileSeen =
            state.restartClearedVolatileSeen \/ state.crashedWithVolatile,
        !.crashedWithVolatile = FALSE
        ]

RecoverPublishInterrupted(g) ==
    /\ state.processUp
    /\ state.restarted
    /\ g \in state.recoverableOrphans
    /\ g \in StableConsumed
    /\ g \notin StablePublished
    /\ RecoveryPublicationCount[g] < 2
    /\ state' = [state EXCEPT
        !.recoveryPublicationCount = [@ EXCEPT
            ![g] = SaturatingInc(RecoveryPublicationCount[g])],
        !.publicationAttemptCount = [@ EXCEPT
            ![g] = SaturatingInc(PublicationAttemptCount[g])],
        !.recoverySnapshotSet = [@ EXCEPT ![g] = TRUE],
        !.recoveryEffectSnapshot = [@ EXCEPT
            ![g] = IF state.recoverySnapshotSet[g]
                    THEN state.recoveryEffectSnapshot[g]
                    ELSE EffectCount[g]],
        !.orphanRecoverySeen = TRUE
        ]

RecoverMarkPublished(g) ==
    /\ state.processUp
    /\ state.prunePhase = "idle"
    /\ g \in StableConsumed
    /\ g \notin StablePublished
    /\ RecoveryPublicationCount[g] > 0
    /\ state' = [state EXCEPT
        !.stablePublished = @ \cup {g},
        !.recoverableOrphans = @ \ {g},
        !.tombstoneSnapshotSet = [@ EXCEPT ![g] = TRUE],
        !.recoveryCountAtTombstone = [@ EXCEPT
            ![g] = RecoveryPublicationCount[g]]
        ]

Next ==
    \/ \E i \in Intents, r \in Resources : ReceiveIntent(i, r)
    \/ \E i \in Intents, r \in Resources : RejectResourceConflict(i, r)
    \/ ObserveIndependentResources
    \/ \E i \in Intents : BeginVerify(i)
    \/ \E i \in Intents : VerifyCheck(i)
    \/ \E i \in Intents : CommitConsumedCheck11(i)
    \/ \E i \in Intents : EffectStart(i)
    \/ \E i \in Intents : EffectReturn(i)
    \/ \E g \in Grants : PublishOutcome(g)
    \/ \E g \in Grants : MarkPublished(g)
    \/ \E i \in Intents : RecordExecutingWitness(i)
    \/ \E i \in Intents : FinishExecuted(i)
    \/ \E i \in Intents : FinishFailed(i)
    \/ AdvanceTime
    \/ \E i \in Intents : ExpirePending(i)
    \/ PruneWriteTemp
    \/ PruneSyncTemp
    \/ PruneRename
    \/ PruneReopen
    \/ Crash
    \/ Restart
    \/ \E g \in Grants : RecoverPublishInterrupted(g)
    \/ \E g \in Grants : RecoverMarkPublished(g)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ IntentState \in [Intents -> IntentStates]
    /\ IntentResource \in [Intents -> Resources \cup {NoResource}]
    /\ LockOwner \in [Resources -> Intents \cup {NoIntent}]
    /\ VerificationPC \in [Intents -> PCDomain]
    /\ StableConsumed \subseteq Grants
    /\ StablePublished \subseteq Grants
    /\ EverCommitted \subseteq Grants
    /\ EffectCount \in [Grants -> 0..2]
    /\ RecoveryPublicationCount \in [Grants -> 0..2]
    /\ PublicationAttemptCount \in [Grants -> 0..2]
    /\ state.validExecutingEntry \in [Intents -> BOOLEAN]
    /\ state.commitSeenBeforeEffect \in [Grants -> BOOLEAN]
    /\ state.committedAfterChecks \in [Grants -> BOOLEAN]
    /\ state.executionEstablishedAtEffectStart \in [Grants -> BOOLEAN]
    /\ state.effectReturned \in [Grants -> BOOLEAN]
    /\ state.executionWitnessRecorded \in [Intents -> BOOLEAN]
    /\ state.tombstoneSnapshotSet \in [Grants -> BOOLEAN]
    /\ state.recoveryCountAtTombstone \in [Grants -> 0..2]
    /\ state.recoverySnapshotSet \in [Grants -> BOOLEAN]
    /\ state.recoveryEffectSnapshot \in [Grants -> 0..2]
    /\ state.processUp \in BOOLEAN
    /\ state.restarted \in BOOLEAN
    /\ state.freshAfterRestart \in BOOLEAN
    /\ state.crashedWithVolatile \in BOOLEAN
    /\ state.now \in 0..MaxTime
    /\ state.prunePhase \in PrunePhases
    /\ state.prePruneLedger \subseteq Grants
    /\ state.candidateLedger \subseteq Grants
    /\ state.recoverableOrphans \subseteq Grants
    /\ state.normalExecutionSeen \in BOOLEAN
    /\ state.independentResourcesSeen \in BOOLEAN
    /\ state.conflictRefusalSeen \in BOOLEAN
    /\ state.restartClearedVolatileSeen \in BOOLEAN
    /\ state.orphanRecoverySeen \in BOOLEAN
    /\ state.expirySeen \in BOOLEAN

CommitBeforeEffect ==
    \A g \in Grants :
        EffectCount[g] > 0 =>
            g \in EverCommitted /\ state.commitSeenBeforeEffect[g]

AtMostOneActionEffectAttempt ==
    \A g \in Grants : EffectCount[g] <= 1

ConsumedSurvivesRestartWhileAcceptable ==
    {g \in EverCommitted : Acceptable(g)} \subseteq StableConsumed

NoUnauthorizedExecuting ==
    \A i \in Intents :
        IntentState[i] \in {"executing", "executed", "failed"} =>
            state.validExecutingEntry[i]
            /\ state.executionEstablishedAtEffectStart[GrantOf(i)]
            /\ EffectCount[GrantOf(i)] = 1

VerificationLockHeld ==
    \A i \in Intents :
        IntentState[i] = "approved" =>
            IntentResource[i] \in Resources
            /\ LockOwner[IntentResource[i]] = i
            /\ VerificationPC[i] \in 0..12

RestartClearsPending ==
    /\ ~state.processUp => NoVolatile
    /\ state.freshAfterRestart => NoVolatile

ResourceExclusive ==
    /\ \A i \in Intents :
        Active(i) =>
            IntentResource[i] \in Resources
            /\ LockOwner[IntentResource[i]] = i
    /\ \A r \in Resources :
        LockOwner[r] /= NoIntent =>
            Active(LockOwner[r]) /\ IntentResource[LockOwner[r]] = r
    /\ \A i, j \in Intents :
        i /= j /\ Active(i) /\ Active(j) =>
            IntentResource[i] /= IntentResource[j]

ExecutionEstablishedAtEffectStart ==
    \A g \in Grants :
        EffectCount[g] > 0 => state.executionEstablishedAtEffectStart[g]

DurableWitnessNeverAuthorizesEffect ==
    \A i \in Intents :
        state.executionWitnessRecorded[i] =>
            state.validExecutingEntry[i]
            /\ EffectCount[GrantOf(i)] = 1
            /\ state.effectReturned[GrantOf(i)]

NoRecoveryPublicationAfterDurableTombstone ==
    \A g \in StablePublished :
        state.tombstoneSnapshotSet[g]
        /\ RecoveryPublicationCount[g] = state.recoveryCountAtTombstone[g]

RecoveryNeverRetriesActionEffect ==
    \A g \in Grants :
        RecoveryPublicationCount[g] > 0 =>
            state.recoverySnapshotSet[g]
            /\ EffectCount[g] = state.recoveryEffectSnapshot[g]

NoCommitBeforeCheck10 ==
    \A g \in EverCommitted : state.committedAfterChecks[g]

W01NormalExecution == state.normalExecutionSeen
W02IndependentResources == state.independentResourcesSeen
W03ConflictRefusal == state.conflictRefusalSeen
W04RestartClearsVolatile == state.restartClearedVolatileSeen
W05OrphanRecovery == state.orphanRecoverySeen
W06PendingExpiry == state.expirySeen

=============================================================================
