# PHASE-C-ESTIMATE — Daemon relay serving on live traffic

**Status:** ESTIMATE (pre-code, estimate-first). Phase B closeout must land green first.

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

## Open design questions (resolve BEFORE code — cheapest informative step first)

1. **Pre-auth vs post-session parse layer for type-5/6.** BE-SURF-01 lists the relay route header + registration among the three pre-auth structures ("parsed before authentication"), but §5.2a says a relay receives type-5 "from a node that has already established a Noise session with it." Which layer does the serve-loop parse the type-5 header at — on the raw UDP datagram (pre-session, like the listener path), or after Noise-session decryption? This determines the entire recv→route shape. **Cheapest step:** re-read §4.1a (transport wire formats) + §5.2a together and pin the layer. Do not code until resolved.
2. **Session-table endpoint mapping.** The serve-loop needs session-by-`receiver_index` lookup AND an index→UDP-endpoint map for `sendTo`. `session.zig` (215, post-auth) holds session state — confirm whether it already maps index→endpoint or whether the listener owns the endpoint map. Confirm before writing the forward path.
3. **Drain batch bound.** `drainFor` takes a caller-bounded `out[]` slice. The live path must pick a batch size that neither blocks live forwarding nor exceeds the 64-packet/recipient quota in one recv cycle.

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
