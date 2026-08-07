# RELAY-ESTIMATE.md

## 1. The question

Does BE-MESH-02/03 (relay: forward opaque ciphertext, store-and-forward, hold no key material) fit within BE-SURF-03's budget caps? The relay is the only remaining M1 worklist item with clear scope and ~510 lines of pre-auth slack. Estimate before writing code per Daniel's standing rule.

## 2. Budget state

From `prumo-verify` on main at 937b6c1 (post-M1-merge):
- M5 (pre-auth unit): 990/1500 — slack 510
- M11 (post-auth unit): 1493/1500 — slack 7 (tight!)

D-030 allows cap subdivision: "The authority MAY subdivide a cap into multiple sub-caps... provided the sum of sub-caps does not exceed the original."

## 3. Calibration against shipped actuals

From NOISE-SESSION-ESTIMATE.md and MESH-ESTIMATE.md overruns:
- Non-parser items: 1.9–3.5× over initial estimates (session.zig estimated 120, shipped 223 = 1.86×; verify.zig estimated 120, shipped 182 = 1.52×)
- Parser items: relatively accurate (bounded by fixed wire format)

Median non-parser calibration factor: **2.7×** (midpoint of 1.9–3.5×).

## 4. Itemized estimate

### 4.1 Open design question: relay routing mechanics

The SPEC defines safety properties (opaque, no keys, store-and-forward) but does NOT define routing mechanics:
- How does a packet reach its destination via the relay?
- How does a node register with a relay?
- What is the routing handle?

Current wire format (SPEC 4.1a): 16-byte data packet header = type (1 byte) || reserved (3 bytes) || receiver_index (4 bytes) || counter (8 bytes). The `receiver_index` is session-local — the relay cannot route by `receiver_index` without learning sessions, violating BE-MESH-02 ("holds no key material").

Two candidate designs:

**Design A (outer routing header + signed keepalive registration):**
- Add new outer relay header before the Noise envelope: `dst_overlay_addr` (16 bytes)
- Node registers with relay via signed keepalive: proves ownership of `overlay_addr` via Ed25519 signature by address key
- Relay maintains routing table: `overlay_addr → UDP endpoint`
- Forwarding: parse outer header, lookup endpoint, forward entire opaque Noise envelope unchanged
- Store-and-forward: optional offline blob storage per BE-MESH-03, quota + TTL bookkeeping

**Design B (observation-based index learning):**
- Relay observes `receiver_index` → `overlay_addr` mappings from passing traffic
- No explicit registration
- Problem: requires relay to observe session-established traffic to learn routes, violates BE-MESH-02 (relay cannot decrypt to learn mappings). Also vulnerable to poisoning.

**Verdict:** Design A is the only viable path. Design B violates the "no keys" constraint.

### 4.2 Line cost breakdown (Design A)

| Component | Description | Category | Lines (raw) | Lines (calibrated) |
|-----------|-------------|----------|------------|-------------------|
| Outer relay header parser | Fixed 16-byte structure (`dst_overlay_addr`), validation against ULA fd00::/8 prefix | Pre-auth | 40–70 | 40–70 (parser-like, accurate) |
| Registration/keepalive + Ed25519 verification | Signed structure (timestamp, `overlay_addr`, sig), verifySigned streaming reuse from verify.zig, ownership proof (sig by address key) | Pre-auth | 80–140 | 216–378 (2.7×) |
| relay.zig forwarding state machine | Routing table (`overlay_addr → UDP endpoint`), forward/drop policy, TTL eviction, rate limiting | Pre-auth | 100–160 | 270–432 (2.7×) |
| Store-and-forward (BE-MESH-03) | Opaque blob storage, quota bookkeeping, TTL expiry, redelivery queue | Pre-auth (if attacker reaches quota counters) or non-surface (if purely opaque + counters) | 120–200 | 324–540 (2.7×) if pre-auth; 120–200 if non-surface |
| Main.zig dispatch | Relay mode wiring, parse outer header before Noise session entry | Pre-auth | 10–20 | 10–20 (glue, accurate) |
| Tests | relay_test.zig (unit tests) + harness relay domain (~8–12 mutants) | Harness | 80–120 | 80–120 (test code, not surfaced) |

**Reading 1 (no subdivision, store-and-forward classified as pre-auth):**
- Sum (pre-auth): 40–70 + 216–378 + 270–432 + 324–540 + 10–20 = **860–1440**
- Median: **1150** (fits within 1500, slack ~350)
- Worst-case: **1440** (fits within 1500, slack ~60)

**Reading 2 (no subdivision, store-and-forward classified as non-surface):**
- Sum (pre-auth): 40–70 + 216–378 + 270–432 + 0 + 10–20 = **536–900**
- Median: **718** (fits within 1500, slack ~782)
- Worst-case: **900** (fits within 1500, slack ~600)

**Reading 3 (with D-030 subdivision, pre-auth → handshake-unit 1000 + relay-unit 500):**
- Pre-auth split: handshake-unit (parser.zig 328 + mac.zig 173 + noise.zig 489 = 990) → fits in 1000, relay-unit (860–1440 median 1150) → exceeds 500.
- Verdict: subdivision does not help; median 1150 > 500 even if worst-case fits in 1500.

### 4.3 Key assumptions and validation

- **Assumption 1:** `verifySigned` streaming from verify.zig can be reused for relay registration. Verification: verify.zig implements BE-ENV-02 domain-tagged Ed25519 verification, 182 lines, zero-heap. Reuse is straightforward.
- **Assumption 2:** Store-and-forward quota bookkeeping is attacker-reachable (attacker can send registration messages that increment counters). This is conservative; if classified as non-surface, Reading 2 applies with larger slack.
- **Assumption 3:** Outer relay header parser is parser-like and accurate (40–70 lines). Fixed-size 16-byte structure, no branching, comparable to data packet header parser (parser.zig parseDataPacketHeader is ~30 lines).

## 5. Verdict

**BOTH READINGS FIT.** The relay fits within BE-SURF-03's pre-auth cap without subdivision, with comfortable margin in Reading 1 (slack ~350 median, ~60 worst-case) and substantial margin in Reading 2 (slack ~782 median, ~600 worst-case).

**Recommendation:** Proceed with Reading 1 (conservative: store-and-forward as pre-auth). No subdivision needed per D-030 — the design fits within the existing 1500-line cap.

## 6. Scope reduction options (if needed)

If implementation exceeds budget (unlikely per Reading 1), reduce scope:
1. Drop store-and-forward (BE-MESH-03) entirely — defer to M2. Saves ~324–540 lines pre-auth.
2. Simplify registration: single一次性 registration instead of periodic keepalive. Saves ~50–100 lines.
3. Tighten rate limiting: smaller routing table, fewer entries. Saves ~20–40 lines.

## 7. Invalidation

What would invalidate this estimate?
- New wire format changes requiring larger parser (e.g., variable-length routing header).
- Registration mechanism requiring complex cryptography beyond Ed25519 (e.g., multi-party computation).
- Store-and-forward reclassified as attacker-controlled surface requiring additional validation.
- D-030 subdivision clause removed or tightened (no longer allows subcaps).

## 8. Pre-close checks

- [x] Read against BE-SURF-01 inventory: relay outer header is a new wire structure, requires BE-SURF-01 update (protocol version bump to v0.3.0).
- [x] Read against BE-SIG-01 domain tags: registration signature needs domain tag 0x07 (relayed registration), addition to BE-SIG-01 inventory.
- [x] Read against D-030 subdivision clause: subdivision not needed per Reading 1, but clause is available as fallback.
- [x] Who picked the denominator: 1500 from SPEC BE-SURF-03, line counts from prumo-verify M5/M11. Verified: `./tools/prumo-verify` reports M5 990/1500, M11 1493/1500.
- [x] Does the thing need to exist: Yes, BE-MESH-02/03 are protocol obligations in M1-AUDIT.md section C1, marked "No relay code. M2." This estimate confirms it can fit in M1, avoiding M2 deferral.

## 9. Next steps after estimate approval

1. Update BE-SURF-01: protocol version v0.2.0 → v0.3.0, add relay outer header structure.
2. Update BE-SIG-01: add domain tag 0x07 (relayed registration).
3. Implement relay.zig: outer parser, registration, forwarding, store-and-forward.
4. Wire main.zig dispatch: relay mode entry point.
5. Add relay_test.zig: unit tests + harness relay domain.
6. Run full gauntlet: fmt, build test, em-dash scan, vectors, prumo, mutation.
7. Commit atomically, push relay-slice.
8. Merge to main per Daniel's approval (stop item #1 from compaction: never push to main without explicit approval).