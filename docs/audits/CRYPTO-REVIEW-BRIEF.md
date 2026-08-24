# Bolina — Cryptographic Composition Review Brief

**Prepared:** 2026-08-20 · **For:** external reviewer · **Status:** draft

---

## 1. What to review

Bolina uses four standard primitives in a non-standard composition. The primitives themselves are
not in scope — they come from Zig's `std.crypto` and have published specifications and public
cryptanalysis. **The composition is in scope.** This document tells you exactly where to look.

## 2. Primitives (not in scope)

| Primitive | Use | Source |
|---|---|---|
| Ed25519 | Certificate signatures, envelope signatures, grant signatures | `std.crypto.sign.Ed25519` |
| X25519 | Noise_IK handshake (ephemeral + static DH) | `std.crypto.dh.X25519` |
| ChaCha20-Poly1305 | AEAD under Noise transport sessions | `std.crypto.aead.chacha20_poly1305` |
| BLAKE2s-256 | Address derivation, scope IDs, digest computation, domain-separated hashing | `std.crypto.hash.Blake2s256` |

## 3. Composition concerns (in scope)

These are the specific places where Bolina combines primitives in ways that don't exist elsewhere.
Each one names the code file and the SPEC section.

### 3.1 Noise_IK + Ed25519 certificate binding

**What:** The Noise_IK handshake uses X25519 static keys. Bolina binds the Noise static key to an
Ed25519 identity by signing the Noise handshake hash with the certificate's Ed25519 key
(BE-TR-01). The certificate carries both the Ed25519 public key (for signatures) and the X25519
public key (for Noise).

**Concern:** Is the binding between the two key types sound? Can an attacker who controls one key
type forge the other? The handshake hash is a Noise transcript hash — is signing it with
Ed25519 domain-separated from other Ed25519 signatures in the protocol?

**Where:**
- `src/verify.zig` lines 1-50 (session verification)
- `SPEC.md` §3 (identity), §5 (transport), BE-TR-01
- `THREAT-MODEL.md` §2.2 (Adversary N)

### 3.2 Ed25519 domain tag separation

**What:** Bolina uses Ed25519 signatures for at least 8 different purposes: certificate issuance,
envelope signing, grant signing, relay registration, resource set publication, and others. Each
has a domain tag (BE-SIG-01) prepended to the message before signing.

**Concern:** Are the domain tags sufficiently distinct? Can a signature for one purpose be
reinterpreted as another? The tag table is in SPEC.md §2 — verify every signing call site uses
the correct tag.

**Where:**
- `SPEC.md` §2, BE-SIG-01 (tag table)
- `src/verify.zig` (all signature verification)
- `src/parser.zig` (wire format, tag bytes)

### 3.3 Grant verification chain ordering

**What:** `verifyGrantThen` in `src/verify.zig` runs 14 checks in a fixed sequence (checks 0-11,
3a, 4a). Some checks depend on earlier ones (e.g., scope checks depend on certificate
verification being complete).

**Concern:** Is the ordering sound? Can a check pass because a prior check it depends on was
skipped or reordered? Are there implicit dependencies not captured in the check numbering?

**Where:**
- `src/verify.zig` lines 200-350 (the 14-check sequence)
- `SPEC.md` §8.2 (BE-GRANT-03, the verification table)

### 3.4 Scope binding (BLAKE2s ancestor walk)

**What:** Cert v3 carries `scope_ids` — 8-byte BLAKE2s-256 hashes of resource prefixes. To check
whether a cert covers a resource, `scopeCoversResource` hashes each ancestor prefix of the
resource_id and checks if any hash matches a scope_id. Empty scope = deny-all.

**Concern:** Is the ancestor walk correct? Does it handle edge cases (single-component resources,
trailing slashes, empty components)? The walk was buggy until D-085 fixed it (the '/' skip was
off by one). Are there other off-by-one risks?

**Where:**
- `src/verify.zig` lines 424-436 (`scopeCoversResource`)
- `src/verify_test.zig` lines 520-620 (scope binding tests)
- `SPEC.md` §8.2, checks 3a and 4a

### 3.5 Grant nonce ledger (BE-GRANT-01)

**What:** Every grant gets a single-use nonce. The nonce is committed to a durable ledger BEFORE
the effect executes. On restart, committed-but-unpublished grants get an `interrupted` Effect.
Crash-safe by atomic rename (D-063).

**Concern:** Is the two-phase commit sound? Can a crash between commit and effect leave a grant
executable twice? Can the atomic rename fail in a way that loses committed nonces?

**Where:**
- `src/grant_ledger.zig` (the durable ledger, 418 lines)
- `SPEC.md` §8.1, BE-GRANT-01, BE-GRANT-01a
- `THREAT-MODEL.md` §2.1 (replay defence)

### 3.6 Store-and-forward keying

**What:** The relay stores encrypted packets for offline recipients. Packets are encrypted under
the recipient's Noise session key. The relay sees only the overlay address (8-byte BLAKE2s of
the recipient's public key).

**Concern:** Can the relay read stored content? Is the keying bound to the recipient's identity
or to the session? If a session key is compromised, can old stored packets be decrypted?

**Where:**
- `src/relay_store.zig` (139 lines)
- `src/relay.zig` (storeDeferred, drainFor)
- `SPEC.md` §5.2a, BE-MESH-03

### 3.7 Revocation propagation

**What:** Revocation is recorded in a separate grant ledger (`grant_ledger.zig`). The verify chain
checks revocation as check 9. Revoked grants are never executed (BE-GRANT-06).

**Concern:** Is the revocation check in the right position in the chain? Can a grant execute
before the revocation check runs? Is the revocation ledger durable across restarts?

**Where:**
- `src/grant_ledger.zig` (revocation entries)
- `src/verify.zig` check 9
- `SPEC.md` §8.2, BE-GRANT-06

### 3.8 ChaCha20-Poly1305 nonce management under Noise

**What:** Noise transport uses ChaCha20-Poly1305 with a 64-bit nonce derived from the packet
counter. The counter is per-session and never resets.

**Concern:** Is the nonce derivation correct? Can counter overflow produce nonce reuse? What
happens at 2^64 packets?

**Where:**
- `SPEC.md` §5 (transport layer)
- Noise_IK specification (referenced in SPEC §5)

## 4. What is mechanically defended (not in scope for review)

These are covered by mutation testing (160/160 killed), fuzzing (0 divergences over 1M records),
and test vectors (77/77). A reviewer can trust these are tested and focus on the composition:

- Wire format parsing (non-recursive, length-prefixed, fixed order)
- Certificate chain validation (expiry, role separation, CA quorum)
- Envelope signature verification (correct public key, correct domain tag)
- Grant expiry (three independent expiry conditions)
- Anti-replay (sliding window at transport, nonce ledger at grant layer)

## 5. What the reviewer should produce

A written assessment covering:

1. **Composition soundness** — are the primitive combinations in §3 sound?
2. **Missing defences** — is there an attack the composition doesn't defend against that it should?
3. **Unnecessary complexity** — is there a simpler composition that achieves the same guarantees?
4. **Trust assumption audit** — are the 8 trust assumptions (THREAT-MODEL.md §6) complete and correctly stated?

## 6. Files to read (in order)

1. `SPEC.md` §0-§2 (what Bolina is, primitives, signature domain tags)
2. `SPEC.md` §3-§5 (identity, transport, mesh)
3. `SPEC.md` §7-§8 (attestation, capability grants — the novel parts)
4. `THREAT-MODEL.md` (full threat model, trust assumptions, accepted risks)
5. `src/verify.zig` (647 lines — the core verification logic)
6. `src/grant_ledger.zig` (418 lines — durable nonce ledger)
7. `src/relay_store.zig` (139 lines — store-and-forward)
8. `src/parser.zig` (328 lines — wire format)

Total: ~1,575 lines of Zig + the SPEC/THREAT-MODEL documents.

## 7. Known issues the reviewer should be aware of

| Issue | Status | Impact |
|---|---|---|
| scopeCoversResource ancestor walk was off-by-one | Fixed in D-085 (`93ea94d`) | Scope checks could pass for resources outside the cert's scope |
| GrantContext checks 6-9 trusted caller-assembled field values (F13) | Fixed in D-087: verify fetches intent/sender state itself via `intent_table`/`sender_table` references | A dispatch bug or future seam assembling mismatched values would make verify bind the grant against fiction |
| `pruneExpired` could empty the consumed-grant log on crash | Fixed in D-063 (atomic rename) | Committed grants could be re-executed after a crash |
| Zig's `std.crypto` is not vendored or hash-pinned | Accepted risk (THREAT-MODEL §4.8) | Supply chain dependency on Zig upstream |
| Coverage instrumentation is hand-rolled, not native | Accepted risk (THREAT-MODEL §4.6) | Uncounted branches invisible to fuzzing |

### 7.1 Re-verification record (loop closure, D-092 baseline)

2026-08-23: the 20 Aug reviewer re-verified this registry against sealed `e97a117` (v0.5.3). Confirmed FIXED: F1 (kex binding), F2 (ledger buffer), F3 (fsync dir), F4 (first_receipt durability), F5 (admission ordering), F6 (setRevocation subject expiry), F13 (verify-side lookups). Confirmed dispositioned: F8 -> T11 documented, F10 (revocation pruned by cert_expiry), F12 (per-epoch cookie key), MD3 ledger flock, MD4 intent slot reclaim. Per D-092 Ruling 1 this registry + dispositions enter the G1 pre-audit baseline handed to the external reviewer; it does not itself satisfy G1.

### 7.2 Second pre-audit refresh against v0.6.0 (`c5c69a2`) - dispositions

2026-08-24 refresh (same-author baseline pass, NOT G1) extended coverage to the no-clock
audit path, HTTP control plane and CA tooling. New findings, both fixed on main:

| Finding | Disposition |
|---|---|
| HIGH F15: caIssue wrote cert version=2 while the verifier gates scopeCoversResource on >=3 - every tool-minted scope silently inert | Fixed (`9c96732`): tool mints v3 ALWAYS (empty scopes deny-all per D-085 R4, issue-time note); F15 e2e drives REAL tool certs through parse+validate into verifyGrantThen - sibling-scope approver refuses, covering scope fires once, version byte pinned |
| MEDIUM F16: HTTP-admitted intents had no sender record - wire grants could never execute them (202 into UnknownSender forever) | Fixed (`b047043`): POST /v1/intents REQUIRES subject (hex64) and writes dispatchIntent's same sender record; claim operator-trusted/unauthenticated-by-crypto, lies refuse loudly at checks 4/6; F16 composition test proves HTTP admission executes via wire grant |
| Caveat: audit re-validates chains against the CURRENT trust set (CA rotation couples history) | Accepted-with-name: SPEC BE-HIST-04a |
| Caveat: flat-JSON extractor substring-matches keys; loopback+bearer assumed | Accepted-with-name: THREAT-MODEL 4.11 - beyond-loopback promotion requires a real parser |

Reviewer emphasis (refresh section 6): spend external budget on the seams - control-plane/wire
identity boundary (now subject-bound) and scope-version coupling; plus BE-HIST-04a
trust/history coupling. Cross-subsystem joints are where per-file mutation gates are weakest
by construction. Everything in section 1 is regression-tested closed; treat F1-F14 as spent.

## 8. Contact

Daniel Carneiro (`loonix`) — author. See `README.md` for contact details.
