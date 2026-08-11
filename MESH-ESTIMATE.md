# MESH-ESTIMATE.md — BE-MESH-03 store-and-forward

**Date:** 2026-08-11 · **Status:** estimate-first, no code before D-058 + SPEC edit
**Scope:** BE-MESH-03 (relay store-and-forward), the single unbound M1 marker (108/109).
**Authorization:** Daniel, 2026-08-11 08:08/08:1x UTC: "keep going" + "follow the spec",
read as the D-051 option-1 ruling: build S&F inside the relay sub-unit's remaining
budget and bind the marker. Target: M1 109/109.

## 1. What SPEC declares, what is owed

Declared already: the marker (SPEC 647-650, MAY + declared quota + declared TTL,
opaque storage, metadata accepted); relay role-gating and the closed two-type
inventory (§5.2a, types 5 and 6); the redelivery text already assumes S&F exists
(SPEC 1433); THREAT-MODEL §4.4 already states the store-and-forward metadata
posture (lines 202-205), so the marker's cross-reference is satisfied as-is.

Owed (D-029 pre-flagged SPEC edit, own commit before code):
1. Mechanics clause in §5.2: store condition, drain condition, storage unit,
   keying, and the drain rewrite rule (§3 below).
2. Declared quota and TTL constants (§4 below). BE-MESH-03 says "declared";
   nothing is declared yet.
3. BE-SURF-03: place `src/relay_store.zig` in the non-surface list ahead of code.

## 2. Budget arithmetic

| Unit | Measured | Cap | Headroom |
|---|---|---|---|
| Relay sub-unit (`src/relay.zig` only) | 183 | 510 | 327 |
| Non-surface engine (`src/relay_store.zig`, new) | 0 | none (D-018) | n/a |

Predicted: surface additions to relay.zig 60-90 lines (store hook in the
UnknownRecipient branch of forwardPacket, drain at registration insert, TTL
check), landing around 250-275 of 510. Engine 130-170 lines non-surface.
No cap change, no subdivision, no tripwire expected to arm.

## 3. Design ruling proposed (D-058 records it)

Route headers carry only recipient_index, which is session-scoped (registrations
are one-shot per session), so keying stored packets by index cannot survive the
recipient coming back on a new session. The ruling:

1. Storage unit is the whole forward packet: type-5 route header plus ciphertext
   body, exactly as forwarded. No new wire types, no inventory change, no
   protocol version change.
2. Store key is the recipient's overlay_addr (persistent, BE-ID-01), resolved at
   store time through the registration table. Store only when the recipient is
   unknown as a live endpoint but known by address; otherwise the existing
   UnknownRecipient refusal stands.
3. Drain fires on type-6 registration insert for a stored overlay_addr: stored
   packets leave in store order, and the relay rewrites the route header's
   recipient_index to the new client_index. Rewrite touches relay-layer metadata
   only; the ciphertext body stays unchanged (BE-MESH-02 holds).
4. TTL purge is lazy, driven by the now_ms parameter at store, drain, and lookup
   (house pattern; no timers before the daemon milestone).
5. Quota exhaustion drops the store silently and increments a counter; live
   forwarding is never blocked by store state.

## 4. Declared constants proposed for the SPEC edit

Per overlay_addr: at most 64 stored packets and 4 MiB aggregate stored bytes.
TTL: 72 hours (259200 s), relay-local clock, same relativity as the type-5 skew
rule. Max stored packet body: 2048 bytes; a larger body is forwarded live or
refused, never stored. All five numbers are declared in the SPEC edit, all are
ratchet-friendly constants in code.

## 5. Binding tests (BE_MESH_03, literal values, D-027)

1. Store within quota stores verbatim: stored bytes byte-equal the forwarded
   packet (opacity witness, no interpretation).
2. Quota exhaustion: 65th store refused, counter moves, live forwarding
   unaffected, first 64 intact.
3. TTL: packet stored at T is gone at T + 72h + 1 (lazy purge witness).
4. Drain on registration: stored packets leave in store order with
   recipient_index rewritten to the new client_index, body unchanged, table
   empty after.
5. Unknown by address as well: existing UnknownRecipient refusal unchanged.

## 6. Harness

The mesh domain has excluded BE-MESH-03 since v10 ("stays deferred", line 79).
The slice adds the mesh-03 marker to MESH_MARKERS plus five to seven mutants
keyed to it: quota ceiling, TTL window, verbatim storage, drain order, rewrite
scope (body untouched), silent-drop counter, key-by-address. Chunked run first
(D-035), then the full suite (population rises from 118).

## 7. Slice ordering

1. D-058 ruling (DECISION-LOG, own commit).
2. SPEC edit v0.3.4-draft (own commit, D-029 pre-flagged).
3. `src/relay_store.zig` + `src/relay_store_test.zig` literal tests.
4. `src/relay.zig` wiring + relay_test additions.
5. Ratchet 108 → 109 committed with the binding tests.
6. Harness mesh-03 domain expansion, chunked run, full suite, zero-residue check.
7. Docs (LANGUAGE mutation cell + implementation row, M1-AUDIT addendum, README),
   push main, gauntlet at pushed HEAD, Portuguese closeout.

## 8. Risks

1. Rewrite-on-drain is the one invention here; D-058 must state it plainly and
   the SPEC edit must carry it, because a relay mutating bytes needs a written
   warrant even when the bytes are its own header.
2. The 2048-byte body cap must agree with whatever Noise transport maximum the
   daemon milestone declares; if SPEC later pins a different number, the
   constant moves with it (declared, not hardcoded).
3. Store state is attacker-reachable pre-auth (any node can forward); quota is
   the defense and its tests are the binding tests. No unbounded path may exist.
