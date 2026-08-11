# PHASE-C-ESTIMATE — Daemon relay serving on live traffic

**Status:** CLOSED. Phase C shipped: `src/relay_serve.zig` (216, non-surface) + 6 live UDP tests, BE-EXEC-04 bound, harness v19 144/144 killed (receipt `logs/mutation_relay_serve_full.log`), M1 112 → 113. Design questions resolved by D-060 (parse layer = pre-auth per BE-SURF-01/BE-MESH-02; endpoint map = serve-loop glue; drain batch = 8, capped by the 64-packet/recipient quota). Phase D opens next.

## Context

- Phase A (dispatch core, in-memory) shipped. Phase B (listener + live Noise handshake) shipped: full mutation suite GREEN, 138/138 killed over 15 domains, receipt `logs/mutation_daemon_full.log`.
- `relay.zig` (256/256) already carries the full relay engine: `parseRelayRoute`/`parseRelayRegistration`, `RelayTable` (`insert`/`lookup`/`prune`), `forwardPacket`, `storeDeferred`, `drainFor`, `writeRelayRoute`.
- `relay_store.zig` (139, non-surface) carries `store`/`drainNext`/`purgeExpired` with the D-058 quotas (64 packets / 4 MiB per recipient, 2048-byte body cap, 72h TTL).
- **GAP:** no daemon glue ties `listener.zig` (UDP recv/send) + `session.zig` (index lookup) + the relay engine into a live packet path. `forwardPacket` returns the bytes to forward; nothing actually calls `listener.sendTo` with them.

## Scope (what Phase C adds)

1. A daemon serve-loop: `listener.recvFrom` → classify packet → route:
   - handshake → `handshake.zig`
   - type-5 route → `forwardPacket`; on `UnknownRecipient` → `storeDeferred`
   - type-6 registration → `table.prune` + `table.insert` + `drainFor` → `listener.sendTo` each drained packet
2. Live forwarding: `listener.sendTo` to the recipient's UDP endpoint, resolved from the session table.
3. Live tests: two real UDP endpoints + one relay, real Noise sessions, forward round-trip, store-then-drain on late registration.

## Layer-0 budget finding (CRITICAL)

Measured line counts this turn:

| Unit | Measured | Cap | Headroom |
|---|---|---|---|
| `relay.zig` | 256 | 256 | **0 — FULL** |
| listener sub-unit (`listener` 175 + `handshake` 71) | 246 | 250 | 4 |
| pre-authentication total | 1496 | 1500 | 4 |
| `dispatch.zig` | 201 | non-surface | — |
| `relay_store.zig` | 139 | non-surface | — |

**Verdict:** the serve-loop CANNOT live in `relay.zig`, the listener sub-unit, or the pre-auth unit. It MUST be a new non-surface daemon file, sibling of `dispatch.zig`. No wire bytes change; no pre-auth or post-auth cap is touched. Proposed name: `src/relay_serve.zig` (non-surface, daemon area, D-059 placement shape).

## SPEC edit required (v0.3.6-draft → v0.3.7-draft)

- Declare `src/relay_serve.zig` non-surface (mirrors `dispatch.zig` placement in D-059).
- New marker: **BE-EXEC-04** (relay serving on live traffic). Recommended to keep the daemon-exec family contiguous (02/03 done, 01 reserved for phase-D lifecycle). Alternative: BE-MESH-06.
- Listener sub-unit stays 246/250; no ratchet needed. No wire bytes change.

## Design questions — RESOLVED (D-060, 2026-08-11, before code)

1. **Parse layer for type-5/6: pre-authentication on the raw datagram; session state is an acceptance gate, not a parse gate.** BE-SURF-01 names the relay route header and registration among the exactly-three structures parsed from unauthenticated input; §5.2a repeats it. The §5.2a sentence "a relay receives type 5 from a node that has already established a Noise session with it" is an ACCEPTANCE condition: `sender_index` MUST correspond to an established session at the relay. It cannot be a parse layer because BE-MESH-02 forbids the relay from holding key material — a header requiring decryption could not be parsed by a relay at all. Serve-loop shape: classify on the raw first type byte (1/2/3 → handshake, 5 → forward, 6 → register, else drop with no service), parse with the bound relay.zig parsers over fixed-size slices, THEN gate acceptance on session/registration state.
2. **Endpoint map: owned by relay_serve.zig.** Source facts: session.zig's Session/SessionTable carry indexes, keys, transcript hash — no endpoint; handshake.zig's committed session struct carries none; listener.zig's recv discards the source address and the listener sub-unit (246/250) has no room under its frozen cap. Precedent: handshake.zig declares its own flat libc sendto outside the sub-unit. relay_serve.zig carries its own recvfrom (capturing src_addr) + sendto externs over the Listener's fd and owns an index→sockaddr map populated at exactly two points: session commit during handshake, and accepted type-6 registration (the registration's source address is the client's delivery endpoint).
3. **Drain batch: the whole queue at registration — the quota IS the bound.** Registrations are one-shot per session (§5.2a, BE-MESH-04 note), so nothing after an accepted registration can trigger a deferred drain; a partial drain strands packets until TTL. Worst case is bounded by construction: 64-slot out buffer (relay_store.MAX_PER_RECIPIENT), every drained packet sent before the next datagram (honours drainFor's borrow contract). Worst-case send work: 64 x (20 + 2048) ≈ 131 KB, single-threaded, no timer.

**Forward decision table (D-060):** entry exists + endpoint known → sendTo (live). Entry exists + endpoint unknown → storeDeferred (engine re-resolves overlay_addr). No entry → drop, no service (BE-MESH-04 extended to storage by D-058). Live sendto failure → drop (UDP semantics; a retry queue would be a second undeclared storage layer).

## Test strategy

Live UDP on loopback: node A, relay R, node B. A↔R and B↔R Noise sessions via `handshake.zig`.

- **T1 forward live:** A forwards to B (registered) → B receives the body byte-for-byte.
- **T2 store-then-drain:** A forwards to B while B offline → stored; B registers late → drained in store order, `recipient_index` rewritten to fresh `client_index`, body unchanged.
- **T3 bounds:** 64th packet stored, 65th dropped; expired packet purged at drain.

Mutation harness v19: relay_serve domain (~6 mutants: forward path, store-on-unknown, drain-on-register, no-service-for-unregistered-recipient, timestamp-skew on store, quota drop).

## Ratchet / gauntlet

- **M1:** 112 → 113 if BE-EXEC-04 is bound (one new marker).
- **prumo M5:** place `src/relay_serve.zig` non-surface (D-059 shape).
- **Full mutation suite:** 138 → 144 (±), re-run green.
- Gauntlet at pushed HEAD: fmt, build test, prumo, vectors, em-dash, mutation.

## Estimate

| Item | Size |
|---|---|
| `src/relay_serve.zig` | ~120-160 lines (non-surface, no cap pressure) |
| `src/relay_serve_test.zig` | ~6-8 live tests |
| `tools/mutation-test.py` v19 | +1 domain, ~6 mutants |
| Docs | SPEC v0.3.7-draft, LANGUAGE.md, README, this estimate CLOSED |

**Risk: LOW.** The engine exists and is tested; Phase C is glue + live tests. The one real risk is design question #1 (the parse layer) — that is why this is estimate-first, not code-first.
