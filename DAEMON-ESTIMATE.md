# DAEMON-ESTIMATE.md — the daemon milestone: from M1 binding layer to running node

**Status:** Phase A CLOSED 2026-08-11 (D-059, SPEC v0.3.5-draft, dispatch core, full suite 131/131, harness v17). Phase B CLOSED 2026-08-11 (listener + live Noise handshake, SPEC v0.3.6-draft, daemon domain 7/7, full suite 138/138, harness v18). Phase C CLOSED 2026-08-12 (relay serving + S&F drain on live traffic, SPEC v0.3.7-draft, relay_serve domain 6/6, full suite 144/144, harness v19). Phase D CLOSED 2026-08-12 (persistence + restart semantics, SPEC v0.3.8-draft, grant_ledger domain 7/7, full suite 151/151, harness v20, BE-EXEC-01 bound M1 114/114).
**Date:** 2026-08-11
**Authorization:** Daniel, 2026-08-11 12:20 UTC: build the other things in parallel.

## 1. What M1 hands the daemon

M1 is 109/109: every wire format, state machine, and verifier the SPEC declares is bound by code and literal tests, mutation-green across fourteen domains (131/131, harness v17). `main.zig` is a 13-line DECLARED stub. Nothing listens, nothing dispatches, nothing persists. Every slice named the live wiring it deferred to this milestone:

| Slice unit | Bound now | The daemon owes |
|---|---|---|
| noise/mac/session parsers | handshake bytes verified | a listener and the live handshake over the wire |
| binding + channel admission | session-state verified | the envelope dispatch loop |
| `intent.zig` + `resolver.zig` | pending-intent machine, canonical resolution | an executor calling `resolveAndAdmit` on live intents |
| `verify.zig` Grant path | `verifyGrantThen`, single effect call site (M10) | effect execution |
| `render.zig` | the approving view | an approval interface consuming the view |
| `sync.zig` + `parser/sync.zig` | the backfill engine | a backfill scheduler driving store and serve |
| `relay.zig` + `relay_store.zig` | forwarding + store-and-forward | the relay serving loop, drain on live registration |
| `ledger.zig` + `historical.zig` | ledger rules | persistence across restarts |

## 2. SPEC constraints the daemon inherits

- BE-DEP-02: the daemon contains no recursive parser; every wire structure parses bounded, and opaque action bytes are hashed, never interpreted.
- BE-BODY-01: `Intent.action` is opaque bytes.
- BE-GRANT-04 panic discipline: in a network daemon a panic is a remote crash.
- Section 11.5: adversarial evaluation, scored on both sides.
- Status vocabulary (CONTRIBUTING.md section 1): slices falsify the specification; they do not construct the product.

## 3. Open questions the estimate owes answers to, before phasing

1. Transport: relay semantics (SPEC section 5.2, datagrams with route headers) versus a session listener; confirm the wire transport from SPEC before choosing a socket shape.
2. Persistence backend for the ledger store (file-backed versus in-memory first): a D-ruling is owed.
3. Clock source and the configuration surface.
4. First binding target: the dispatch core over an in-memory transport, or the listener skeleton? Recommendation: the dispatch core first, cheapest falsification, zero network surface, exercising every bound state machine.
5. Key material for live handshakes: D-018 forbids hardcoded secrets; a declared key path is owed with the first networked phase.

## 4. Phase sketch (pending section 3)

- Phase A (CLOSED 2026-08-11): in-memory dispatch core. Envelope admission, intent, `resolveAndAdmit`, Grant verification, the refusal transition, the effect call site, over the bound state machines, zero sockets. Seams falsified: routing, envelope gate, subject seam, executing transition, consumed commit (dispatch domain 6/6 killed, full suite 131/131). D-059 records the ruling plus one correction found below the line (verifyEnvelope is the BE-ENV-02 signature check, not a structural gate).
- Phase B (CLOSED 2026-08-11): listener and live session establishment, handshake over the wire. B1: flat libc UDP listener (BE-EXEC-02/03). B2: live Noise_IK handshake over the listener (BE-SESS-02 by construction). Daemon mutation domain: 7 mutants, 3/3 §0.4 properties covered, full suite 138/138.
- Phase C (CLOSED 2026-08-12): relay serving with store-and-forward drain on live registration. `relay_serve.zig` (216, non-surface) ties listener + session table + relay engine into a live UDP packet path with S&F drain. Daemon mutation domain relay_serve: 6 mutants, 5/5 BE-EXEC-04 properties covered, full suite 144/144. D-060 resolved the three open design questions (pre-auth parse layer, endpoint map in the serve-loop glue, drain batch 8).
- Phase D (CLOSED 2026-08-12): persistence and restart collapse semantics. `grant_ledger.zig` (358, non-surface) is a hand-rolled two-phase append log over `std.Io` (BE-DEP-01 forbids deps): commit row fsynced before the effect (BE-GRANT-01), published tombstone after, revoke rows never pruned (BE-REV-02), orphan recovery surfaces interrupted at-least-once (BE-GRANT-01a), pruneExpired drops expired consumed grants (BE-EXEC-01). Wired into the dispatch check-11 seam (D-062): the hook carries `(grant_id, not_after, now)`, commits before the effect, refuses fail-safe with no ledger. BE-EXEC-01 bound (M1 114/114). Mutation domain grant_ledger: 7 mutants, 7/7 D-061 properties covered, full suite 151/151. D-061 resolved the four design questions (sole I/O point, on-disk format, direct-file-state crash-injection, fsync observability).

Budget note: the daemon is non-surface by construction (state over parsed values, D-018 lineage). Its line budget is this estimate's job once phasing closes, not BE-SURF-03's.
