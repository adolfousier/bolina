# Transport Parser Line-Cost Estimate

**Date:** 2026-08-06 (Round 5, transport phase, task 1)
**Status:** VERDICT — FITS. The BE-SURF-03 budget is not a false premise.
**Precondition satisfied:** this estimate precedes all transport code, per the instruction
"estimate first, write second."

## 1. The question

Before any transport code is written, estimate the parser line cost of the five transport
components — Noise handshake, cookie, fragmentation and reassembly, anti-replay window,
lighthouse lookup — against the remaining BE-SURF-03 budget. If they do not fit, the budget
is a false premise (stop item 4) and work stops before line 1501, not at it.

## 2. Budget state (measured, not assumed)

| Quantity | Value | Source |
|---|---|---|
| BE-SURF-03 budget | 1500 lines | SPEC.md §2.3, normative |
| Counting rule | every `*.zig` under `src/parser.zig` and `src/parser/`, `wc -l` summed | `tools/prumo-verify` M5, verbatim |
| Current count | **486** | M5 measurement on `round-4-review` @ `5430e43` (only `src/parser.zig` exists; no `src/parser/` directory) |
| Remaining | **1014** | 1500 − 486 |

## 3. Calibration (measured from the existing parser)

The estimate is not intuition; it is the existing module's measured cost-per-wire-item applied
to the new structures' wire items.

`src/parser.zig` at 486 lines decomposes (measured line ranges):

| Block | Lines |
|---|---|
| Header, imports, `ParseError` | ~113 |
| Constants (limits, lengths, domain tags, body types) | 49 |
| `Cursor` | ~73 |
| Six struct definitions (Envelope, Intent, Grant, Span, Effect, Claim) | 69 |
| Six parse functions (`parseEnvelope` 44, `parseIntent` 34, `parseGrant` 54, `readSpan`+`parseSpan` 58, `parseEffect` 43, `parseClaim` 17) | 250 |

The six parse functions cover ~51 wire items (fields, bounded loops, length-prefixed ranges).
Measured ratio: **~4.9 lines of parse code per wire item, ~6.3 including the struct definition.**
Planning ratio used below: 5–6.5 lines per wire item, plus stated overhead for dispatch,
constants, and BE-TR-05 limit checks. Every structure below lists its wire items, so the
arithmetic is checkable, not taken on faith.

## 4. Per-component estimate

Wire items are read from the SPEC sections cited. Where §4 does not yet pin byte-level
layouts (handshake framing, data packet header, cookie reply), the estimate assumes the
WireGuard shape §10.1 says §4 "follows closely and deliberately", fixed-size per BE-SURF-01;
task 3 pins the exact layouts (decision D-019). If the pinning adds fields beyond this shape,
the estimate is re-run before implementation.

| # | Component | Structure(s) | Wire items | Parser lines |
|---|---|---|---|---|
| 1 | Noise handshake | Initiation (Noise_IK msg1): type, reserved[3], sender_idx u32, e[32], enc(s)[48], enc(empty payload)[16], mac1[16], mac2[16]; Response (msg2): type, reserved[3], sender_idx, receiver_idx, e[32], enc(empty payload)[16], mac1[16], mac2[16]; type dispatch | 8 + 8 + dispatch | **100–140** |
| 2 | Cookie | Cookie reply (§4.4): type, reserved[3], receiver_idx, nonce[24], cookie[16], mac1[16] | 6 | **35–50** |
| 3 | Fragmentation / reassembly (parse part) | Fragment header (§4.5): msg_id u64, index u16, total u16, plus index<total and total≤derived-max checks | 3 + 2 checks | **30–40** |
| 4 | Anti-replay window (parse part) | Data packet header (§4.3): type, reserved[3], receiver_idx, counter u64 — the counter the window consumes | 4 | **25–35** |
| 5 | Lighthouse lookup | LookupRequest (§5.1a): version, [16] addr; LookupResponse: version, [16] addr, endpoint_count u8, loop(family u8, [16] addr, u16 port), u16 cert_len, cert slice | 2 + 5 + loop | **65–92** |
| | | Constants block (message types, lengths, derived `MAX_FRAGMENTS` from MAX_MESSAGE) | | **20–30** |
| | **Five components** | | | **275–387** |

All five are flat, no-nesting structures per §2.2. The two pre-authentication ones (handshake
messages, cookie reply) are fixed-size with no variable-length field, as BE-SURF-01 requires;
lookups and fragments parse only inside established sessions (BE-MESH-07, §4.5), so they add
no pre-auth surface.

## 5. Adjacent cost the transport cannot ship without: Cert

BE-TR-01 (binding: certificate + signature over `h` inside the new session) and §5.1a
(lighthouse bootstrap returns the peer certificate) both require parsing `Cert` (§3.1). It is
not one of the five named components, so it is reported separately rather than hidden inside
them:

Cert wire items: version, role_bits, sig_pubkey[32], kex_pubkey[32], not_before, not_after,
name_len+name (≤64), group_count (≤16) + [8]*, ca_sig_count (1..4) + ([32]+[64])*, with
ascending-order and pairwise-distinct enforced at parse time (canonical encoding, §3.1).
≈ 10 items + 2 bounded loops + 2 structural checks → **65–90 lines.**

Cert verification (BE-ID-01..04) is identity-slice work and stays out of this number;
this is the parse cost only.

## 6. What is NOT counted against the budget, and why

| Item | Est. lines | Where it lives | Why it is not parser cost |
|---|---|---|---|
| Anti-replay window state machine (RFC 6479 bitmap, ≥1024, BE-TR-03) | 50–70 | transport module | Consumes authenticated post-decrypt counters; interprets no bytes |
| Reassembly context tracking (8 contexts, 8 MiB/peer, 256 MiB/node, 30 s timeout, BE-TR-05) | 80–120 | transport module | Consumes authenticated parsed fragments; interprets no bytes |
| Noise key schedule, handshake state, session AEAD, rekey (BE-TR-02), binding exchange (BE-TR-01) | 200–300 | crypto/session module | Operates on typed values the parser already produced |
| Cookie issue/rotation state, mac1 computation (BE-TR-04/04a) | 40–60 | transport module | MACs over parsed byte ranges; the cookie REPLY parse is counted above |

**Boundary rule (decision D-018):** code that turns raw bytes into typed fields lives in the
parser module and counts toward the 1500; code that tracks state over already-parsed,
authenticated values does not. The gaming direction of this rule is moving parsing OUT of the
module to flatter M5; that direction is forbidden — every read of network bytes goes through
the parser module, because BE-SURF-01's closed inventory depends on there being exactly one
place bytes become values.

## 7. Total against remaining

| Scenario | Lines | Share of remaining 1014 | Headroom |
|---|---|---|---|
| Five components, base | ~330 | 33% | 3.1× |
| Five components, worst | 387 | 38% | 2.6× |
| Five components + Cert, base | ~400 | 39% | 2.5× |
| Five components + Cert, worst | 480 | 47% | 2.1× |

Even at the worst case with Cert included, transport consumes under half of the remaining
budget. After it, ~530–670 lines remain for the channels round (§6: control messages,
backfill), which gets its own estimate before that round starts — the same discipline, not a
promise.

## 8. What would invalidate this estimate

1. The D-019 layout pin adds fields beyond the WireGuard shape assumed in §4 → re-run before
   implementation.
2. A structure the spec requires turns out to need variable-length pre-auth parsing → that is
   a BE-SURF-01 violation and a stop item, not an estimate revision.
3. The channels-round estimate (separate document, later) plus this total exceeds 1500 → stop
   item 4 fires at that point, with both numbers on the table.

## 9. Pre-close checks

1. **Read against other sections:** BE-SURF-01 (no third pre-auth structure added; the two
   named remain fixed-size ✓); BE-WIRE-01/02 (apply to all new parse code, no estimate impact);
   BE-TR-05 (every attacker-influenced size checked at parse time — counted inside the
   per-structure ranges); BE-TR-07 (msg1 payload is empty ciphertext, nothing to parse);
   §11.3 (vectors precede the parser they verify — task order respects it); §11.6 (new
   structures enter the fuzz corpus and coverage counters — that cost lands in `tools/` and
   `src/coverage.zig`, outside the M5 count, and is noted rather than silently excluded).
2. **Who picked the denominator:** 1500 ← SPEC BE-SURF-03. 486 ← M5 measurement, the spec's
   own counting rule. The 4.9–6.3 lines-per-wire-item ratio ← measured over the six existing
   parse functions (250–319 lines, ~51 wire items). No denominator in this document is
   author-chosen.
3. **Does the thing being checked need to exist:** only spec-mandated structures are counted.
   The window, reassembly state, and crypto are excluded from the parser number because they
   are not parsing — not because they are not being built; their own line costs are listed in
   §6 for completeness.

## 10. Verdict

**The five components fit.** 275–387 parser lines against 1014 remaining, i.e. 28–38% of the
remaining budget; 34–47% including the Cert parse the transport requires. The budget survives
contact with the transport layer with ≥2.1× headroom at the worst case. Proceed to transport.
