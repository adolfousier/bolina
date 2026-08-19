#!/usr/bin/env python3
"""Generate the 12 Phase A conformance fixtures with correct SHA256 digest chains."""

import hashlib
import json
import os
import sys

SCHEMA = "bolina.grant-trace.v1"

def canonical_bytes(ev):
    body = {k: v for k, v in ev.items() if k != "previous_event_sha256"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def chain_events(events):
    """Set the digest chain on a list of event dicts in place."""
    prev = None
    for ev in events:
        ev["schema"] = SCHEMA
        ev["previous_event_sha256"] = prev
        prev = hashlib.sha256(canonical_bytes(ev)).hexdigest()


def ev(seq, tag, *, check=None, intent_id=None, grant_id=None,
       resource_id=None, ledger_id=None, pc=None, process_epoch=0):
    """Build one event dict."""
    return {
        "schema": SCHEMA,
        "sequence": seq,
        "process_epoch": process_epoch,
        "event": tag,
        "check": check,
        "intent_id": intent_id,
        "grant_id": grant_id,
        "resource_id": resource_id,
        "ledger_id": ledger_id,
        "pc": pc,
    }


def make_verify_checks(seq_start, grant_id):
    """Generate verify_check events for checks 0..10."""
    return [ev(seq_start + c, "verify_check", grant_id=grant_id, check=c, pc=c)
            for c in range(11)]


def make_prune(seq_start, ledger_id):
    """Generate the four D-063 prune phase events."""
    tags = ["prune_temp_written", "prune_temp_synced", "prune_renamed", "prune_reopened"]
    return [ev(seq_start + i, t, ledger_id=ledger_id)
            for i, t in enumerate(tags)]


# --- Fixture definitions ---

def a01_normal_execution():
    """Phase A case 1: normal grant execution through EffectReturn."""
    ledger = "ledger-main"
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
    ]
    events += make_verify_checks(2, "g-live")
    events += make_prune(13, ledger)
    events += [
        ev(17, "commit_consumed_11", grant_id="g-live"),
        ev(18, "effect_start", grant_id="g-live"),
        ev(19, "effect_return", grant_id="g-live"),
        ev(20, "publish_outcome", grant_id="g-live"),
        ev(21, "mark_published", grant_id="g-live"),
        ev(22, "record_executing_witness", grant_id="g-live"),
    ]
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a01_normal_execution",
        "intent": "normal grant execution through EffectReturn with full publication and witness",
        "expect": "ACCEPTED",
        "events": events,
    }


def a02_two_independent_resources():
    """Phase A case 2: two independent resources coexist."""
    ledger = "ledger-main"
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
    ]
    events += make_verify_checks(2, "g-live")
    events += make_prune(13, ledger)
    events += [
        ev(17, "commit_consumed_11", grant_id="g-live"),
        ev(18, "effect_start", grant_id="g-live"),
        ev(19, "effect_return", grant_id="g-live"),
        ev(20, "publish_outcome", grant_id="g-live"),
        ev(21, "mark_published", grant_id="g-live"),
        ev(22, "record_executing_witness", grant_id="g-live"),
        ev(23, "receive_intent", intent_id="i-beta", resource_id="r-archive"),
        ev(24, "begin_verify", grant_id="g-old", intent_id="i-beta"),
    ]
    events += make_verify_checks(25, "g-old")
    events += make_prune(36, ledger)
    events += [
        ev(40, "commit_consumed_11", grant_id="g-old"),
        ev(41, "effect_start", grant_id="g-old"),
        ev(42, "effect_return", grant_id="g-old"),
        ev(43, "publish_outcome", grant_id="g-old"),
        ev(44, "mark_published", grant_id="g-old"),
        ev(45, "record_executing_witness", grant_id="g-old"),
    ]
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a02_two_independent_resources",
        "intent": "two independent grants on different resources complete full execution",
        "expect": "ACCEPTED",
        "events": events,
    }


def a03_resource_conflict():
    """Phase A case 3: resource conflict refusal."""
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "reject_resource_conflict", intent_id="i-beta", resource_id="r-logs-deploy"),
    ]
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a03_resource_conflict",
        "intent": "second intent on same resource is refused with reject_resource_conflict",
        "expect": "ACCEPTED",
        "events": events,
    }


def a04_verification_refusal():
    """Phase A case 4: refusal at a verification check (stutter, no commit/effect)."""
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
        ev(2, "verify_check", grant_id="g-live", check=0, pc=0),
        ev(3, "verify_check", grant_id="g-live", check=1, pc=1),
        ev(4, "verify_check", grant_id="g-live", check=2, pc=2),
        # Check 3 refuses: the trace ends here. No commit, no effect.
        # The projector sees verify_check events for 0..2 only.
    ]
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a04_verification_refusal",
        "intent": "verification refusal at check 3 stops the grant path; no commit or effect",
        "expect": "ACCEPTED",
        "events": events,
    }


def a05_replay_refusal():
    """Phase A case 5: replay refusal after durable consume (already consumed)."""
    # The grant was consumed in a prior epoch; replay attempts fail.
    # From grant_trace_test.zig "check-11 refusal stutters": begin_verify,
    # verify_check 0..10, then nothing (no commit, no effect).
    events = [
        ev(0, "receive_intent", intent_id="i-beta", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-beta"),
    ]
    events += make_verify_checks(2, "g-live")
    # After check 10, commit_consumed_11 would fail (AlreadyConsumed).
    # The trace ends at verify_check 10: no commit, no effect, stutter.
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a05_replay_refusal",
        "intent": "replay of already-consumed grant refuses at check 11; no commit or effect",
        "expect": "ACCEPTED",
        "events": events,
    }


def a06_effect_before_consume():
    """Phase A case 6: effect_start without prior commit is NONCONFORMANT."""
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
    ]
    events += make_verify_checks(2, "g-live")
    # Skip commit_consumed_11 and prune; go straight to effect_start.
    # Bolina.tla EffectStart requires g in StableConsumed, which is false.
    events.append(ev(13, "effect_start", grant_id="g-live"))
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a06_effect_before_consume",
        "intent": "effect_start without prior durable consume is rejected by model invariant",
        "expect": "NONCONFORMANT",
        "events": events,
    }


def a07_second_effect_start():
    """Phase A case 7: second effect_start for same grant is rejected."""
    ledger = "ledger-main"
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
    ]
    events += make_verify_checks(2, "g-live")
    events += make_prune(13, ledger)
    events += [
        ev(17, "commit_consumed_11", grant_id="g-live"),
        ev(18, "effect_start", grant_id="g-live"),
        ev(19, "effect_return", grant_id="g-live"),
        # Second effect_start: EffectCount already 1, guard fails.
        ev(20, "effect_start", grant_id="g-live"),
    ]
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a07_second_effect_start",
        "intent": "second effect_start for same grant is rejected (EffectCount already 1)",
        "expect": "NONCONFORMANT",
        "events": events,
    }


def a08_effect_without_all_checks():
    """Phase A case 8: effect_start without all 11 verification checks."""
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
    ]
    # Only checks 0..5 (missing 6..10 and commit).
    events += make_verify_checks(2, "g-live")[:6]  # checks 0-5 only
    # EffectStart requires VerificationPC = 12 (after commit at check 11).
    # With PC at 6, the guard fails.
    events.append(ev(8, "effect_start", grant_id="g-live"))
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a08_effect_without_all_checks",
        "intent": "effect_start without all verification checks is rejected (PC not at 12)",
        "expect": "NONCONFORMANT",
        "events": events,
    }


def a09_witness_as_authorization():
    """Phase A case 9: record_executing_witness used as effect authorization (rejected)."""
    ledger = "ledger-main"
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
    ]
    events += make_verify_checks(2, "g-live")
    events += make_prune(13, ledger)
    events += [
        ev(17, "commit_consumed_11", grant_id="g-live"),
        # Skip effect_start and effect_return; go straight to witness.
        # RecordExecutingWitness requires effectReturned = TRUE, which is false.
        ev(18, "record_executing_witness", grant_id="g-live"),
    ]
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a09_witness_as_authorization",
        "intent": "record_executing_witness without prior effect is rejected (D-067)",
        "expect": "NONCONFORMANT",
        "events": events,
    }


def a10_consume_before_check10():
    """Phase A case 10: commit_consumed_11 before check 10 completes."""
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
    ]
    # Only checks 0..8 (missing 9 and 10).
    events += make_verify_checks(2, "g-live")[:9]  # checks 0-8
    # CommitConsumedCheck11 requires VerificationPC = 11.
    # With PC at 9, the guard fails.
    events.append(ev(11, "commit_consumed_11", grant_id="g-live"))
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a10_consume_before_check10",
        "intent": "commit_consumed_11 before check 10 completes is rejected (PC not at 11)",
        "expect": "NONCONFORMANT",
        "events": events,
    }


def a11_reordered_events():
    """Phase A case 11: duplicate event in the trace is INVALID_TRACE."""
    # Duplicate a verify_check: seq 3 appears twice (strictly increasing violated).
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
        ev(2, "verify_check", grant_id="g-live", check=0, pc=0),
        ev(2, "verify_check", grant_id="g-live", check=1, pc=1),  # duplicate seq
    ]
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a11_reordered_events",
        "intent": "duplicate sequence number in the trace is rejected as INVALID_TRACE",
        "expect": "INVALID_TRACE",
        "events": events,
    }


def a12_identifier_remap():
    """Phase A case 12: grant identity remapped midway is INVALID_TRACE."""
    # begin_verify binds g-live to i-alpha; a later event rebinds g-live to i-beta.
    events = [
        ev(0, "receive_intent", intent_id="i-alpha", resource_id="r-logs-deploy"),
        ev(1, "begin_verify", grant_id="g-live", intent_id="i-alpha"),
        ev(2, "verify_check", grant_id="g-live", check=0, pc=0),
        ev(3, "begin_verify", grant_id="g-live", intent_id="i-beta"),  # rebind!
    ]
    chain_events(events)
    return {
        "schema": SCHEMA,
        "case": "a12_identifier_remap",
        "intent": "grant identity rebound to different intent midway is rejected as INVALID_TRACE",
        "expect": "NONCONFORMANT",
        "events": events,
    }


GENERATORS = [
    a01_normal_execution,
    a02_two_independent_resources,
    a03_resource_conflict,
    a04_verification_refusal,
    a05_replay_refusal,
    a06_effect_before_consume,
    a07_second_effect_start,
    a08_effect_without_all_checks,
    a09_witness_as_authorization,
    a10_consume_before_check10,
    a11_reordered_events,
    a12_identifier_remap,
]


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "fixtures")
    os.makedirs(out_dir, exist_ok=True)
    for gen in GENERATORS:
        fixture = gen()
        path = os.path.join(out_dir, fixture["case"] + ".json")
        with open(path, "w") as f:
            json.dump(fixture, f, indent=2, sort_keys=False)
        print(f"  {fixture['case']}.json ({len(fixture['events'])} events, expect={fixture['expect']})")
    print(f"\n{len(GENERATORS)} fixtures written to {out_dir}")


if __name__ == "__main__":
    main()
