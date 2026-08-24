# Noise Session Phase Line-Cost Estimate

**Date:** 2026-08-06 (Round 5, post-merge, session phase)
**Status:** DUAL VERDICT. FITS under BE-SURF-03 as written. DOES NOT FIT under the reading
that measures all session-phase code against 1500. Which reading governs is a reviewer
decision, because it changes what the budget promises.
**Precondition satisfied:** this estimate precedes all session-phase code, per the standing
ask "estimate before you write it, not after."

## 1. The question

Round-5 review: "The Noise session phase is entirely unwritten: three handshake message
types, key schedule, session state, rekey, AEAD transport frame. 606 lines for all of that
is tight. Estimate before you write it, not after." This document is that estimate:
itemized bottom-up, calibrated against shipped actuals, written before line one of session
code.

One factual correction first, because it changes the arithmetic: the session phase is not
entirely unwritten. The wire parsing for all four message types (plus the fragment and
lookup headers) already exists in `src/parser.zig` and is counted in the current 894:
`parseHandshakeInitiation`, `parseHandshakeResponse`, `parseCookieReply`,
`parseDataPacketHeader`, `parseFragmentHeader`, `parseLookupRequest`,
`parseLookupResponse`. What remains unwritten is the key schedule, the handshake state
machine, session state, rekey, the AEAD transport frame handling, the binding exchange,
and two parsers (Cert, binding message).

## 2. Budget state (measured, not assumed)

| Quantity | Value | Source |
|---|---|---|
| BE-SURF-03 budget | 1500 lines | SPEC.md §2.3, normative |
| Counting rule | every `*.zig` under `src/parser.zig` and `src/parser/`, `wc -l` summed | `tools/prumo-verify` M5, verbatim |
| Current count | **894** | M5 measurement on `main` @ `f60d402` (only `src/parser.zig` exists) |
| Headroom | **606** | 1500 − 894 |
| Boundary rule | bytes-to-fields counts, state-over-parsed-values does not | D-018, logged 2026-08-06 |

## 3. Calibration against shipped actuals

`TRANSPORT-ESTIMATE.md` exists and preceded the transport code (it landed with the
transport commits, in the tree that was reviewed). Its parser-side numbers held up. Its §6
non-parser guesses were never calibrated against actuals, and the shipped actuals ran
1.9–3.5x over them:

| Component | §6 estimate | Shipped actual | Ratio |
|---|---|---|---|
| Anti-replay window | 50–70 | `replay.zig`, 114 | ~1.9x |
| Reassembly state | 80–120 | `reassembly.zig`, 247 | ~2.5x |
| Cookie/mac state | 40–60 | `mac.zig`, 173 | ~3.5x |

Geometric mean ~2.5x. Parser side: the five transport components were estimated 275–387;
actual `parser.zig` growth was 486 → 894 = +408, slightly above the worst case (~1.2x).

This estimate applies that calibration two ways. First, every itemized range below was
built high rather than tight. Second, where the previous estimate lumped the entire session
crypto into one line ("Noise key schedule, handshake state, session AEAD, rekey, binding
exchange: 200–300"), this one itemizes it and lands at 710–990: roughly 3–4x the old lump.
The 200–300 guess is exactly the class of number that came in 1.9–3.5x under; the
itemization is the correction, not an argument.

## 4. Itemized estimate, session phase

### 4.1 Non-parser (does not count toward M5 under D-018)

| # | Component | Contents | Lines |
|---|---|---|---|
| 1 | Noise symmetric state + key schedule | h/ck, MixHash/MixKey/MixKeyAndHash, HKDF-2/3 over BLAKE2s, EncryptAndHash/DecryptAndHash, Split | 130–170 |
| 2 | Noise_IK handshake state machine | msg1 create/process, msg2 create/process, ephemeral generation, encrypted_static + encrypted_timestamp seal/unseal, mac1-before-X25519 ordering (BE-TR-04), cookie/mac2 hooks | 180–240 |
| 3 | CipherState + transport AEAD | nonce = four zero bytes ‖ counter-BE (§4.1a), counters, replay-window consumption (reuses `replay.zig`), 2^48 bound (BE-TR-02) | 90–130 |
| 4 | Session state + table | sender/receiver indices, 512-per-node cap with refuse-new semantics, zeroization of replaced keys, rejection timers, binding gate | 150–220 |
| 5 | BE-TR-01 binding + BE-ID-01/02/03 chain | cert + Ed25519 signature over handshake hash `h` exchanged inside the session, address derived from `sig_pubkey`, full chain verification against the trust set, role_bits checks; no app data before it passes | 160–230 |
| | **Non-parser total** | | **710–990** |

Median ~850. Planning range with calibration margin: 600–1000, plan ~800. `std.crypto`
already supplies x25519, ChaCha20Poly1305, BLAKE2s, and Ed25519: no third-party crypto,
zero heap (fixed session array). Rekey has no dedicated message type (the 4-type inventory
is closed per BE-SURF-01), so BE-TR-02 is a fresh handshake plus key rotation, covered by
components 2 and 4.

### 4.2 Parser-side (counts against M5)

| # | Component | Lines |
|---|---|---|
| 6 | Cert parse (§3.1, unchanged from TRANSPORT-ESTIMATE §5) | 65–90 |
| 7 | Binding message parse (cert slice + 64-byte signature over `h`) | 15–25 |
| | Raw subtotal | 80–115 |
| | Calibrated (~1.2x, the parser-side actual ratio) | **95–140** |

`parser.zig` lands at 894 + 95–140 = **~990–1035 of 1500**, leaving ~465–510 of headroom.
The channels round (§6: control messages, backoff) still comes later and gets its own
estimate before it starts.

## 5. Verdict, both readings on the table

**Reading A: BE-SURF-03 as written.** The budget measures the parser module; D-018 draws
the boundary; session crypto is state over parsed values. Under this reading the session
phase FITS: `parser.zig` lands ~990–1035 of 1500 with ~465–510 of headroom, and the
non-parser code (~800 planned) lives outside the measured surface, the same way
`replay.zig`, `reassembly.zig`, and `mac.zig` already do.

**Reading B: all session-phase code against 1500.** The session work left to write
(parser-side 95–140 + non-parser 600–1000) is 695–1140 lines against 606 of headroom.
Total session-related code: 1589–2034, median ~1800. Under this reading it DOES NOT FIT:
overrun 90–530, median ~300. The premise "606 covers all of it" is false.

Which reading governs is the reviewer's call, not mine to resolve silently. BE-SURF-03's
wording says the parser module, and D-018 (logged, transport round) draws the boundary that
excludes session crypto. But the budget's purpose ("small enough for one person to audit")
is about attack surface, and ~800 lines of security-critical session crypto is exactly the
code that argument has to cover, and M5 as specified never sees it. Changing what the
budget measures is a change to a declared guarantee: stop-list territory, so it is flagged
before, not after. If the intent is "all code an attacker touches stays auditable as one
unit", the budget's denominator is wrong, and that finding is worth more than either
verdict.

## 6. Scope-reduction options (change neither verdict)

- BE-ID-01/02/03 chain recorded as provisional, logged debt (signature verification only):
  saves ~150–250 (component 5 shrinks). Still over under Reading B (median ~1600 vs 1500).
- `std.crypto` usage is already maximal (x25519, ChaCha20Poly1305, BLAKE2s, Ed25519 all
  from std); nothing left to shave there.
- Zero-heap is already required; the fixed 512-entry session array is the cheapest shape.

## 7. What would invalidate this estimate

1. Non-parser actuals land above 1000 → the calibration failed again; stop and re-estimate
   with actuals on the table before continuing.
2. Cert parse lands above 140 → parser-side calibration failed; same stop.
3. The D-019 pinned formats turn out to need fields beyond §4.1a as listed → parser numbers
   re-run before implementation.
4. The BE-ID chain turns out to need machinery beyond §3.1 (revocation state, anything not
   in the cert structure) → component 5 is void; re-estimate before writing it.
5. Reading B is picked as governing → stop item #4 fires now, before line 1501, exactly as
   asked, with both numbers on the table.

## 8. Pre-close checks

1. **Read against other sections:** BE-TR-01 (no app data before binding passes; counted in
   component 5); BE-TR-02 (rekey = fresh handshake + rotation, no new message type; covered
   by components 2 and 4); BE-TR-04 (mac1 verified before any X25519; counted in component
   2's ordering); BE-SURF-01 (the session phase adds no new pre-auth message type, the
   4-type inventory stays closed); §11.3 (test vectors precede the code they verify; that
   cost lands in `tools/`, outside the M5 count, noted not hidden).
2. **Who picked the denominator:** 1500 ← SPEC BE-SURF-03. 894 ← M5's own counting rule.
   The 1.9–3.5x calibration ratios ← shipped files (`replay.zig` 114, `reassembly.zig` 247,
   `mac.zig` 173, `parser.zig` +408). No denominator in this document is author-chosen.
3. **Does the thing need to exist:** every component maps to a normative item (Noise_IK
   §4.1, §4.1a pinned formats, BE-TR-01/02/04, BE-ID-01/02/03). Nothing speculative is
   counted.
