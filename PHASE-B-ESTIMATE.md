# PHASE-B-ESTIMATE.md — listener + live Noise handshake (daemon milestone, Phase B)

**Status:** CLOSED 2026-08-11. The owed SPEC edit landed at v0.3.6-draft (`fc7dfad`): §0.4 declares BE-EXEC-02/03 + BE-SESS-02, relay cap ratcheted 510→256, listener sub-unit cap 250. B1 listener 175 lines (`106e11a`), B2 live Noise_IK handshake +71, sub-unit 246/250 (`f253f51`). Ratchet 109→112, M1 112/112. Daemon mutation domain 7/7 killed (§0.4 3/3 covered), full suite 138/138 over 15 domains, receipt `logs/mutation_daemon_full.log`.
**Date:** 2026-08-11
**Authorization:** Daniel, 19:03 UTC "podes prosseguir com o plano". Estimate-first per house discipline.
**Supersedes scope note:** DAEMON-ESTIMATE.md Phase B line ("listener and live session establishment, handshake over the wire").

---

## 1. Layer 0 findings (measured, not assumed)

| Finding | Source |
|---|---|
| SPEC declares 110 unique `BE-*` markers; 109 bound, 1 SUPERSEDED excluded (D-041) | `grep -oE` over SPEC.md |
| **No `BE-EXEC`, `BE-SESS`, or `BE-DEPLOY` markers exist in SPEC** | full marker census |
| The daemon milestone currently declares zero markers of its own | marker census |
| Transport: `Noise_IK_25519_ChaChaPoly_BLAKE2s` over UDP, WireGuard field sizes | SPEC §4.1 line 416 |
| Handshake wire: type 1 init 144B, type 2 response 92B, type 3 cookie 52B, type 4 transport | SPEC §4.1 tables |
| Pre-auth budget: handshake sub-unit 990/990 (at floor), relay 256/510, total 1246/1500 | prumo at pushed HEAD ab706e7 |
| `BE-DEP-01/02`, `BE-TR-01..07` already bound (binding/noise/parser tests) | test-name census |

**The honest consequence:** Phase B cannot "bind markers" that do not exist. The listener and session-establishment runtime properties are currently undeclared. Phase B therefore OWES a SPEC edit that declares them before any code, exactly as mesh-03 owed its §5.2a clause (D-058) and dispatch owed its placement (D-059). Inventing marker names and coding against them is the failure mode this estimate exists to prevent.

## 2. Transport decision — UDP, no ambiguity

SPEC §4.1 (line 416): sessions use `Noise_IK_25519_ChaChaPoly_BLAKE2s` over UDP; the initiator knows the responder's static X25519 key from its certificate. All four messages fit the 1400-byte transport packet limit (§4.4). Relay routing (§5.2) and lighthouse endpoints (§5.1a) are datagram-shaped. **Decision: the listener is a UDP datagram socket. No TCP, no dual-stack, no stream abstraction.** This is settled by the SPEC, not a design choice.

## 3. Key-path decision — D-018 honored

D-018 forbids hardcoded secrets. Decision:
- **Tests:** deterministic keys from the `cert_test_helpers.zig` seed family (house machinery, already used end-to-end in Phase A). Zero hand-rolled crypto.
- **Production:** the daemon loads its identity (Ed25519 sig key + X25519 static key + certificate) from a file path supplied via CLI/env. **The config surface itself is Phase D**; Phase B declares the path contract but does not build the config parser. No key material ships in code, ever.

## 4. The owed SPEC edit (D-029 pre-flagged, first atomic commit of the slice)

Phase B declares three markers before writing code. Proposed normative text is drafted in the SPEC edit commit, not here; the estimate records intent and denominator keys.

| Marker | Property (intent) | Binds in |
|---|---|---|
| BE-EXEC-02 | One listener per (address, port); a second bind to the same endpoint MUST be refused | B1 |
| BE-EXEC-03 | A listener socket binds exactly one address family; no dual-stack | B1 |
| BE-SESS-02 | A failed or abandoned handshake MUST leave no half-session; partial state is cleaned before the failure returns | B2 |

**Open question flagged now:** BE-EXEC-01 (daemon lifecycle — one process, no fork-per-session, bounded resources) is a real property but architectural; its falsification is inspection + absence of fork calls, not a runtime test. Recommend declaring it but binding it by construction, not by a test. Decision owed to the SPEC edit commit.

**Placement owed by the same edit:** the listener receives attacker datagrams pre-auth, so it is surface. The pre-auth unit caps currently sum to exactly 1500 (handshake 990 + relay 510), leaving no room for a third sub-unit. The edit MUST ratchet the relay sub-unit cap from 510 down to its measured floor 256 (freeing 254 of cap room), then declare a `listener` sub-unit with cap 250. Cap sum becomes 990 + 256 + 250 = 1496 ≤ 1500. This is the D-054/D-058 ratchet-down-to-floor pattern, not a cap raise.

## 5. B1 / B2 split

| Sub-phase | Scope | Markers bound | Sockets? |
|---|---|---|---|
| **B1** | Listener skeleton: bind, refuse-second-bind, single address family, recv loop handing datagrams to a transport-agnostic handler. Zero Noise, zero handshake. | BE-EXEC-02, BE-EXEC-03 | Real localhost UDP (std.net) |
| **B2** | Live Noise_IK handshake over the listener: type 1/2/3 through the already-bound mac.zig/noise.zig, session establishment, BE-TR-01 binding exchange before any app data, half-session cleanup on failure. | BE-SESS-02 (+ exercises BE-TR-01 over the wire) | Real localhost UDP |

**Test transport decision:** real localhost UDP sockets in tests, not an injected fake transport. The socket layer is exactly what Phase B falsifies; a fake transport would falsify nothing. std.net gives deterministic loopback datagrams.

## 6. Budget arithmetic (measured)

| Unit / sub-unit | Measured | Cap | Note |
|---|---|---|---|
| pre-auth handshake | 990 | 990 | at floor, untouchable |
| pre-auth relay | 256 | 510 → **256** | ratcheted to floor by the owed edit |
| pre-auth listener (new) | 0 → ~100-150 (B1) | **250** | declared by the owed edit |
| pre-auth cap-sum | — | 1496 ≤ 1500 | compliant |

B1 listener skeleton estimated 100-150 lines; B2 adds handshake glue measured at implementation. If B2 pushes the listener past 250, the slice STOPS and re-rules (never a quiet cap raise).

## 7. Harness denominator plan

A new `daemon` domain in tools/mutation-test.py, keyed on the three declared markers (regex over the bold SPEC headers once the edit lands). Mutants target src/listener.zig (B1) and the B2 handshake-wiring sites: second-bind acceptance, dual-stack bind, half-session leak on failed handshake. Chunked run first, then full suite, zero-residue check before launch. The domain is added to the denominator ONLY after the SPEC edit commits (same sequencing as dispatch/mesh-03).

## 8. Rejected alternatives

1. **Coding against invented markers.** The names BE-EXEC/BE-SESS/BE-DEPLOY appear nowhere in SPEC; binding undeclared markers is the anti-pattern every prior slice ruled out.
2. **TCP or dual-stack listener.** SPEC §4.1 mandates UDP; §2.2 admits no extension mechanism in v0.2.
3. **Listener as non-surface glue (dispatch.zig treatment).** Rejected: dispatch is state-over-parsed-values, not reached by attacker bytes; the listener IS reached by attacker datagrams directly, so it is surface and must carry budget.
4. **Raising the pre-auth cap for the listener.** Caps MUST NOT be raised; the ratchet-down-to-floor pattern makes room instead.

## 9. Order from here

1. SPEC edit (own atomic commit, D-029 pre-flagged): declare BE-EXEC-02/03 + BE-SESS-02, ratchet relay cap 510→256, declare listener sub-unit cap 250.
2. B1: src/listener.zig + literal tests (BE-EXEC-02/03), real localhost UDP. Build + prumo green.
3. B2: live Noise handshake over the listener + BE-SESS-02 + BE-TR-01 over the wire. Build + prumo green.
4. Harness daemon domain, chunked then full suite, zero residue.
5. Docs (LANGUAGE implementation row + mutation cell, DAEMON-ESTIMATE Phase B status, README), push, gauntlet at pushed HEAD, Portuguese closeout.
