------------------------- MODULE BolinaEvaluation -------------------------
(***************************************************************************)
(* Bounded witness and mutation evaluation for the exact Bolina base model. *)
(* Every mutant is isolated behind its own SpecMxx configuration.           *)
(* A TLC counterexample is expected evidence for each declared case.        *)
(***************************************************************************)

EXTENDS Bolina

W01NotReached == ~W01NormalExecution
W02NotReached == ~W02IndependentResources
W03NotReached == ~W03ConflictRefusal
W04NotReached == ~W04RestartClearsVolatile
W05NotReached == ~W05OrphanRecovery
W06NotReached == ~W06PendingExpiry

M01EffectBeforeConsume(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ IntentState[i] = "approved"
    /\ VerificationPC[i] \in 0..11
    /\ g \notin StableConsumed
    /\ g \notin EverCommitted
    /\ EffectCount[g] = 0
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "executing"],
        !.effectCount = [@ EXCEPT ![g] = 1],
        !.validExecutingEntry = [@ EXCEPT ![i] = TRUE],
        !.commitSeenBeforeEffect = [@ EXCEPT ![g] = FALSE],
        !.executionEstablishedAtEffectStart = [@ EXCEPT ![g] = TRUE]
        ]

M02DuplicateEffect(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ IntentState[i] = "executing"
    /\ EffectCount[g] = 1
    /\ state.validExecutingEntry[i]
    /\ state.executionEstablishedAtEffectStart[g]
    /\ state' = [state EXCEPT
        !.effectCount = [@ EXCEPT ![g] = 2]
        ]

M03UnauthorizedExecuting(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ IntentState[i] = "pending"
    /\ ~state.validExecutingEntry[i]
    /\ EffectCount[g] = 0
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "executing"]
        ]

M04RehydratePending(i, r) ==
    /\ state.processUp
    /\ state.restarted
    /\ state.freshAfterRestart
    /\ IntentState[i] = "absent"
    /\ LockOwner[r] = NoIntent
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "pending"],
        !.intentResource = [@ EXCEPT ![i] = r],
        !.lockOwner = [@ EXCEPT ![r] = i],
        !.verificationPC = [@ EXCEPT ![i] = PCNone]
        ]

M05ReleaseVerificationLock(i) ==
    LET r == IntentResource[i] IN
    /\ state.processUp
    /\ IntentState[i] = "approved"
    /\ r \in Resources
    /\ LockOwner[r] = i
    /\ state' = [state EXCEPT
        !.lockOwner = [@ EXCEPT ![r] = NoIntent]
        ]

M06EffectWithoutExecutionEstablishment(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ IntentState[i] = "approved"
    /\ VerificationPC[i] = 12
    /\ g \in StableConsumed
    /\ EffectCount[g] = 0
    /\ ~state.executionEstablishedAtEffectStart[g]
    /\ state' = [state EXCEPT
        !.intentState = [@ EXCEPT ![i] = "executing"],
        !.effectCount = [@ EXCEPT ![g] = 1],
        !.validExecutingEntry = [@ EXCEPT ![i] = TRUE],
        !.commitSeenBeforeEffect = [@ EXCEPT ![g] = TRUE]
        ]

M07RecoveryAfterTombstone(g) ==
    /\ state.processUp
    /\ g \in StablePublished
    /\ state.tombstoneSnapshotSet[g]
    /\ RecoveryPublicationCount[g] = state.recoveryCountAtTombstone[g]
    /\ RecoveryPublicationCount[g] < 2
    /\ state' = [state EXCEPT
        !.recoveryPublicationCount = [@ EXCEPT
            ![g] = SaturatingInc(RecoveryPublicationCount[g])]
        ]

M08RecoveryRetriesEffect(g) ==
    /\ state.processUp
    /\ RecoveryPublicationCount[g] > 0
    /\ state.recoverySnapshotSet[g]
    /\ EffectCount[g] = state.recoveryEffectSnapshot[g]
    /\ EffectCount[g] < 2
    /\ state' = [state EXCEPT
        !.effectCount = [@ EXCEPT ![g] = SaturatingInc(EffectCount[g])]
        ]

M09CommitBeforeCheck10(i) ==
    LET g == GrantOf(i) IN
    /\ state.processUp
    /\ state.prunePhase = "idle"
    /\ IntentState[i] = "approved"
    /\ VerificationPC[i] \in 0..10
    /\ g \notin StableConsumed
    /\ g \notin EverCommitted
    /\ ~state.committedAfterChecks[g]
    /\ state' = [state EXCEPT
        !.stableConsumed = @ \cup {g},
        !.everCommitted = @ \cup {g},
        !.committedAfterChecks = [@ EXCEPT ![g] = FALSE]
        ]

LEGACY_TRUNCATE_MUTANT(g) ==
    /\ state.processUp
    /\ state.restarted
    /\ state.freshAfterRestart
    /\ g \in EverCommitted
    /\ g \in StableConsumed
    /\ Acceptable(g)
    /\ state' = [state EXCEPT
        !.stableConsumed = @ \ {g},
        !.recoverableOrphans = @ \ {g}
        ]

NextM01 == Next \/ \E i \in Intents : M01EffectBeforeConsume(i)
NextM02 == Next \/ \E i \in Intents : M02DuplicateEffect(i)
NextM03 == Next \/ \E i \in Intents : M03UnauthorizedExecuting(i)
NextM04 == Next \/ \E i \in Intents, r \in Resources : M04RehydratePending(i, r)
NextM05 == Next \/ \E i \in Intents : M05ReleaseVerificationLock(i)
NextM06 == Next \/ \E i \in Intents : M06EffectWithoutExecutionEstablishment(i)
NextM07 == Next \/ \E g \in Grants : M07RecoveryAfterTombstone(g)
NextM08 == Next \/ \E g \in Grants : M08RecoveryRetriesEffect(g)
NextM09 == Next \/ \E i \in Intents : M09CommitBeforeCheck10(i)
NextM10 == Next \/ \E g \in Grants : LEGACY_TRUNCATE_MUTANT(g)

SpecM01 == Init /\ [][NextM01]_vars
SpecM02 == Init /\ [][NextM02]_vars
SpecM03 == Init /\ [][NextM03]_vars
SpecM04 == Init /\ [][NextM04]_vars
SpecM05 == Init /\ [][NextM05]_vars
SpecM06 == Init /\ [][NextM06]_vars
SpecM07 == Init /\ [][NextM07]_vars
SpecM08 == Init /\ [][NextM08]_vars
SpecM09 == Init /\ [][NextM09]_vars
SpecM10 == Init /\ [][NextM10]_vars

=============================================================================
