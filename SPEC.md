# Bolina Protocol — Specification

**Version:** 0.2.0-draft · **Status:** DECLARED, nothing implemented · **Date:** 2026-08-05
**Design:** Daniel Carneiro (`loonix`) · **Contributors:** see `CONTRIBUTORS` · **External work
credited in:** §10.1, §11.9 · **Licence:** Apache 2.0

> **Epistemic status of this document.** Every normative statement below is a *declaration of
> intent*, not a report of built behaviour. No line of Bolina exists as code at the time of
> writing. Where this document says a property is "enforced", read it as "the specification
> requires an implementation to enforce"; where it says "verified", read it as "must be verified
> before the corresponding Boundary Expectation may be sealed". Nothing here may be cited as
> evidence that anything works. Conformance is defined in §11; the current state of every
> conformance item is *not started*.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in
RFC 2119 and RFC 8174.

**Changes from v0.1.0-draft:** QUIC/TLS 1.3 replaced by Noise_IK over UDP; MLS replaced by pairwise
fan-out; CBOR replaced by a flat non-recursive wire encoding; primitive set reduced from seven to
four. All four changes follow from the zero-dependency constraint, and all four made the design
smaller and the attack surface narrower. The previous draft's open question about the envelope
header being visible to relays is resolved as a consequence and no longer appears: with pairwise
fan-out the whole envelope travels inside a Noise session.

---

## 0. What Bolina is

Bolina is an encrypted overlay network and messaging protocol whose participants are **both humans
and autonomous agents**, and in which **authority to cause an effect, and the evidence behind a
claim, are carried on the wire as unforgeable objects** rather than as assertions the sender makes
about itself.

Three bands, stacked:

| Band | Nearest existing thing | What Bolina takes |
|---|---|---|
| Identity + encrypted transport + mesh | Nebula, WireGuard | Offline CA issuing certificates, key-derived addressing, Noise_IK handshake, lighthouse discovery, relay fallback |
| Channels | IRC | Channel *shape* only: names, membership, ordered-enough broadcast. None of its trust model |
| **Attestation and capability** | *nothing* | Signed evidence spans, receiver-recomputed confidence, single-use capability grants, hash-linked channel ledger |

The first two bands are deliberately unoriginal. **§7 and §8 are the only parts of this protocol
that do not already exist somewhere else**, and they are the reason it is worth building.

### 0.1 The problem statement

Every messaging protocol in existence treats a message body as opaque bytes with an authenticated
*sender*. That suffices when senders are humans, because a human who lies remains accountable
outside the protocol.

It does not suffice when a sender is a language model. A model states a categorical verdict with
nothing behind it; satisfies a confirmation flag it was asked to set honestly; and does both
without intent to deceive. These are reliability properties of the sender, not lapses it could be
instructed out of. Five production incidents (Orbit, 2026-07-01..06) established the general case,
the decisive one being #5 — a reincidence of #4 in which the confirmation flag was set to true
without the warning the flag existed to force: *a gate whose satisfaction token is produced by the
model is not a gate.*

Bolina moves the guarantee off the sender:

- A **claim** is worth no more than the signed evidence attached to it, and the *receiver*
  recomputes its confidence instead of believing the number the sender wrote (§7).
- An **action** does not execute because a message says it was approved. It executes because the
  executor verifies a capability object the requesting party is structurally incapable of
  constructing (§8).

### 0.2 What Bolina is not

- **Not new cryptography.** No new cipher, no new AEAD, no new handshake construction, no new key
  schedule. Four primitives (§2), each with a published specification and public cryptanalysis. An
  implementation that substitutes a bespoke primitive is non-conformant. The zero-dependency
  constraint applies to *libraries*, never to *constructions*.
- **Not an anonymity network.** Content and, off-path, metadata are hidden. A global passive
  adversary is not resisted. Not a Tor substitute.
- **Not a blockchain.** The channel ledger (§9) is a hash-linked DAG for tamper-evidence within a
  channel. No consensus, no global ordering, no token.
- **Not a planner or agent framework.** Bolina carries what agents say and constrains what they may
  cause. It has no opinion about how they decide.
- **Not a new network layer.** Bolina runs over UDP/IP. A genuinely new L3/L4 protocol dies in the
  first NAT it meets; the novelty here is above the transport, not beneath it.

### 0.3 The zero-dependency constraint

Bolina is specified so that a conformant implementation can be built with **no third-party code**.
Two consequences run through the whole document and are stated once here:

**BE-DEP-01** — No library outside the implementation language's standard library may be required
to build a conformant node. Where a language's standard library lacks a §2 primitive, a reference
implementation of that primitive MAY be vendored into the repository, pinned by content hash, and
MUST NOT be modified. *Writing the primitives from scratch is out of scope and is not what this
constraint asks for: logic errors are caught by §11, timing side channels are not.*

**BE-DEP-02** — The daemon MUST NOT contain a recursive parser. Every structure it parses from the
network is flat, fixed-order, and length-prefixed (§2.2). The one field with arbitrary structure,
`Intent.action`, is handled by the daemon as opaque bytes and hashed, never interpreted. Structured
interpretation happens only in the executor, which is not exposed to the network.

---

## 1. Roles

A Bolina identity is a certificate (§3) carrying a set of **roles**. Roles are the protocol's
primary structural safety mechanism: several invariants below are enforced by the *absence* of a
role in a certificate, not by any runtime check.

| Role | May do | Held by |
|---|---|---|
| `participant` | Join channels, send `Utterance`, read | Humans, agents |
| `agent` | As `participant`, plus emit `Intent` | Autonomous processes |
| `executor` | Verify `Grant`, perform effects, sign `Span` and `Effect` | MAD instances, CI runners, MCP servers |
| `approver` | Sign `Grant` | Humans, hardware-backed services |
| `lighthouse` | Answer address-discovery queries | Well-known nodes |
| `relay` | Forward opaque ciphertext between nodes that cannot connect directly | Well-known nodes |

**BE-ROLE-01** — A certificate MUST NOT carry both `agent` and `approver`. A CA implementation MUST
reject such a signing request. *This is the central law of the Prumo enforcement pyramid expressed
in the PKI: an autonomous process cannot approve its own actions because the key material required
is one it is never issued.*

**BE-ROLE-02** — A certificate MUST NOT carry both `agent` and `executor`. An agent may *request*
effects and may *read* signed spans; it may not be the thing that signs them. One host MAY run an
agent process and an executor process, but they MUST hold distinct certificates and distinct
private keys, in distinct address spaces.

**BE-ROLE-03** — `approver` private keys MUST NOT be readable by any process holding an `agent`
certificate. Implementations SHOULD hold approver keys in hardware (Secure Enclave, YubiKey, HSM).

**BE-ROLE-04** — A certificate MUST NOT carry both `approver` and `executor`. Such an identity would
sign its own Grants and then honour them, collapsing §8's separation entirely — the single-party
version of the failure BE-ROLE-01 prevents. The three dangerous pairs are `agent`+`approver`,
`agent`+`executor`, and `approver`+`executor`; all three are refused at issuance and re-checked on
every use (BE-ID-03).

---

## 2. Cryptographic primitives and wire encoding

### 2.1 Primitives

Four. No primitive outside this table may be used for a security-relevant purpose, and none is
modified.

| Purpose | Primitive | Reference |
|---|---|---|
| Signatures | Ed25519 | RFC 8032 |
| Key agreement | X25519 | RFC 7748 |
| AEAD | ChaCha20-Poly1305 | RFC 8439 |
| Hash, KDF, MAC | BLAKE2s-256 | RFC 7693 |

This is WireGuard's set plus Ed25519. BLAKE2s serves as hash, as the HKDF core in the Noise key
schedule, and as keyed MAC for the DoS cookie (§4.4) — one primitive covering three duties, which
is the reason it is chosen over SHA-256. Ed25519 internally uses SHA-512; that is an implementation
detail of the primitive, not a fifth choice.

Any implementation of these four MUST be constant-time with respect to secret data.

### 2.2 Wire encoding

Bolina does not use CBOR, Protobuf, JSON, or any other self-describing format. Every network
structure is encoded as a **flat record**:

- Fields appear in a fixed order defined by this specification. There is no field-order freedom,
  therefore no canonicalization step and no possibility of two encodings of one logical value.
- Integers are unsigned big-endian of fixed width.
- **All timestamps and durations are `u64` Unix epoch milliseconds, everywhere, without exception.**
  No structure mixes units. *Certificates previously used seconds while grants and envelopes used
  milliseconds; unit mixing inside one wire format is a leading cause of conversion defects, and the
  fields are bare integers with no unit tag to catch the error. `u64` milliseconds overflows in the
  year 292,277,026, which is a sufficient margin.*
- Variable-length fields are `u16` length followed by bytes, with a per-field maximum stated in
  this specification. A length exceeding its maximum is a parse failure, not a truncation. **Two
  documented exception classes, and no others:**

| Exception | Fields | Why |
|---|---|---|
| **Fixed-width, no prefix** | `[16]` ids and addresses, `[32]` keys, hashes, and digests, `[64]` signatures, `[8]` group ids, all `u8`/`u16`/`u32`/`u64` scalars | Width is a constant of this specification, so a length prefix would be a second source of truth about a value that cannot vary |
| **Non-`u16` prefixes** | `u8` counts (`ca_sig_count`, `group_count`, `parent_count`, `claim_count`, `span_count`, `envelope_count`, `have_count`); `u32` lengths (`Envelope.body_len`, `Intent.action_len`) | Counts are bounded ≤ 255 by their own limits; the two `u32` fields carry payloads above 64 KiB |

*An undocumented exception is worse than an inconsistent rule: an auditor who finds one stops
trusting the other rules, and the entire argument for a flat format is that it can be verified by
reading it.*
- **There is no nesting and no recursion anywhere.** A record containing another record contains it
  as a fixed-size or length-prefixed byte range, parsed by a separate flat parser at a known offset.
- Unknown trailing bytes are a parse failure. There is no extension mechanism in v0.2; version
  negotiation is by the `version` field only.

**BE-WIRE-01** — The parser MUST perform no heap allocation. It operates on a caller-supplied slice
and produces offsets and lengths into it. A malformed input can cause a rejection; it cannot cause
an allocation.

**BE-WIRE-02** — Every parse function MUST be total: for every input byte string of every length,
it returns either a valid structure or a rejection, and never reads outside the input slice. This
is verified by fuzzing as a sealed conformance item (§11.6), not by inspection.

**BE-WIRE-03** — Signing and hashing operate over the encoded bytes exactly as transmitted. There
is no re-encoding step between verification and hashing, because a re-encoding step is where
signature-substitution bugs live.

### 2.3 Attack surface budget

The safety argument for an implementation language without memory safety is not that the parser is
careful. It is that the parser is **small enough that one person can read all of it, and exposed to
unauthenticated input in only two places**. That argument is only worth something if both halves are
measured, so both are stated as requirements rather than as intentions.

**BE-SURF-01 (closed pre-authentication inventory)** — Exactly two structures are parsed from
unauthenticated input: the Noise handshake messages and the cookie reply (§4). **Both are fixed-size
and contain no variable-length field.** Every other structure in this specification — certificates,
lookups, envelopes, control messages, sync messages — MUST be parsed only inside an established,
bound session (BE-TR-01). Adding a third structure to the pre-authentication list is a protocol
version change, not an implementation decision.

*This is what the correctness fixes cost and why the cost has to be paid back here. Adding the CA
quorum turned `Cert` from a fixed-size record into one carrying a variable-length signature list;
lighthouse bootstrap, backfill, control messages, and inline spans each added further
variable-length parsing. All of it is legitimate and all of it sits behind authentication, so the
unauthenticated surface did not grow with the protocol. That property is now written down, so it
cannot erode quietly.*

**BE-SURF-02 (explicitly checked arithmetic)** — Every index, length, offset, and count computation
in the parser MUST use arithmetic that **returns an error** on overflow or out-of-range, and MUST
NOT rely on the language runtime's abort behaviour for bounds control. *A safety-checked build turns
memory corruption into a panic, and in a network daemon a panic is a remote crash. Under BE-GRANT-04
a restart collapses every pending approval to `EXPIRED` — so an attacker who can reach any panic
path, without corrupting anything, obtains selective denial of approval by crashing the executor
whenever a human is about to approve. The safety net is thereby turned into the attack. A panic is
catastrophic containment of last resort; it is never a network flow-control mechanism.*

**BE-SURF-03 (parser complexity budget)** — The isolated network-parsing module MUST NOT exceed
**1500 lines**, measured and enforced in CI. Exceeding it does not degrade the design; it invalidates
the mitigation that justified the language choice, and it MUST fail the build rather than be noted.
*"Small enough for one person to audit" is either a number or it is a slogan.*

**BE-SURF-04 (differential fuzzing)** — The continuous fuzzing of §11.6 MUST be differential: the
production parser is fuzzed against an independent, minimal reference parser written solely for
testing, and any divergence is a defect. *Plain fuzzing finds crashes. It does not find "parsed it
wrong and did not crash" — a production parser silently accepting a structure the reference rejects
is exactly the failure that produces divergent implementations and admits malformed input, and it
leaves no trace for a crash-detector to find.*

**BE-SIG-01 (domain separation)** — Every Ed25519 signature in this protocol is computed over a
one-byte domain tag prepended to the structure's encoded bytes, and verification MUST reject a
signature whose tag does not match the structure being verified:

| Tag | Structure |
|---|---|
| `0x01` | `Cert` (§3.1) |
| `0x02` | `Envelope` (§6.2) |
| `0x03` | `Span` (§7.1) |
| `0x04` | `Grant` (§8.1) |
| `0x05` | Handshake binding over Noise `h` (§4.1) |
| `0x06` | `Refusal` (§8.5) |

*Executor keys sign both `Span` and envelopes; approver keys sign both `Grant` and envelopes; every
key signs the handshake binding. Current field layouts happen to make a cross-type collision
infeasible — minimum lengths differ and high-entropy fields sit at the discriminating offsets — but
that is unexploitable by accident rather than by construction, and any future field change could
break it silently. BE-WIRE-03 already names this hazard class; one byte per signature closes the
larger instance of it.*

---

## 3. Layer 0 — Identity

### 3.1 Certificate

```
Cert :=
  u8    version              ; = 2
  u8    role_bits            ; bit 0 participant, 1 agent, 2 executor,
                             ; 3 approver, 4 lighthouse, 5 relay
  [32]  sig_pubkey           ; Ed25519
  [32]  kex_pubkey           ; X25519
  u64   not_before           ; unix ms
  u64   not_after            ; unix ms
  u16   name_len, name       ; ≤ 64 bytes, UTF-8, NOT a security boundary
  u8    group_count          ; ≤ 16
  [8]*  group_ids            ; each = BLAKE2s-256(group_name)[0..8], a GLOBAL identifier
  u8    ca_sig_count         ; 1..4
  ([32] ca_key + [64] ca_sig) × ca_sig_count
                             ; each Ed25519 over all bytes preceding ca_sig_count,
                             ; ordered by ca_key ascending, keys pairwise distinct
```

The signature list is fixed-order and length-prefixed like every other structure; it introduces no
nesting. Ordering by key and requiring distinctness makes the encoding canonical and makes
duplicate-key quorum forgery a parse failure rather than a policy check.

`name` is a convenience label. **No authorization decision may depend on `name`.** Authorization
depends on `sig_pubkey`, `role_bits`, and `group_ids` only.

The overlay address is not carried in the certificate; it is *derived*, so it cannot disagree with
the key.

### 3.2 Addressing

```
overlay_addr = 0xfd || BLAKE2s-256(sig_pubkey)[0..15]
```

where `[0..15]` is exclusive-end — the first 15 bytes — giving 16 bytes total. Slice notation is
exclusive-end everywhere in this document, and this derivation is a §11.3 test vector precisely
because an off-by-one here is invisible until two implementations disagree about who someone is.
The result is an IPv6 ULA in `fd00::/8`. This follows the CJDNS/Yggdrasil pattern: **the address is a
commitment to the key.** There is no resolution step to poison — possession of the private key is
the only way to answer at an address.

**BE-ID-01** — A node MUST derive a peer's overlay address from its `sig_pubkey` and MUST NOT
accept an address asserted by any other party, including a lighthouse.

**BE-ID-02** — A node MUST reject a certificate unless **every** `(ca_key, ca_sig)` pair verifies,
**every** `ca_key` is in the local trust set, the keys are strictly ascending and pairwise distinct,
and the validity window contains the local clock. Rejection is unconditional; there is no
warn-and-continue path.

**BE-ID-04** — A node MUST reject a certificate with the `approver` bit set unless `ca_sig_count ≥
2`. *The quorum is verified by every node on every use, not merely honoured by the issuer. A rule
enforced only at issuance is a rule enforced by trusting the issuer, which is the assumption
BE-CA-01 exists to remove.*

**BE-ID-03** — A node MUST reject a certificate whose `role_bits` violate BE-ROLE-01, BE-ROLE-02, or
BE-ROLE-04, even if every `ca_sig` verifies. A compromised or buggy CA MUST NOT be able to mint a self-approving
identity that peers will accept. *The invariant is checked at both ends, because checking it only
at issuance means trusting the issuer.*

### 3.3 Certificate authority

The CA is an **offline** Ed25519 key with no network service, never running on a node that
participates in the mesh. Issuance is a manual, out-of-band act.

**BE-CA-01** — Issuing a certificate with the `approver` bit set MUST require signatures from a
quorum of at least two distinct CA keys. One compromised CA key MUST NOT be sufficient to mint
approval authority. Other certificates require one CA signature.

### 3.4 Revocation

Short lifetimes first, explicit deny-list second.

**BE-REV-01** — Certificates with `approver` or `executor` set MUST have
`not_after - not_before ≤ 30 days` (2 592 000 000 ms). Certificates with only `participant` SHOULD
have `≤ 90 days`.

**BE-REV-02** — A node holding a valid CA-signed revocation for a `sig_pubkey` MUST refuse all
subsequent envelopes from it, MUST tear down existing sessions with it, and MUST persist the
revocation across restart. Failure to *receive* a revocation is not preventable at this layer; it
is bounded by BE-REV-01. This is stated as a limitation, not as a defence. A *claim* of
non-receipt is a different matter and is not evidence: any node that processed a revocation can
assert it did not, buying itself an extra window, so non-receipt claims are settled by the node's
causal position in the ledger (BE-HIST-03), not by the node's own report. *(Empirical basis:
INC-001, Bolina 2026-08-06: a party claimed non-receipt of input it demonstrably processed. The
claim-shape generalises to revocation, and BE-HIST-03 was doing the work but was not pointed at
it.)*

---

## 4. Layer 1 — Transport

### 4.1 Handshake

Sessions use **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** over UDP: the initiator knows the responder's
static X25519 key (from its certificate), the handshake completes in one round trip, and the
initiator's static key is encrypted to the responder rather than sent in clear. This is the
WireGuard construction, chosen because it is small enough to implement correctly without a library
and has had a decade of public analysis.

The Noise handshake authenticates *X25519 static keys*. Certificates bind an Ed25519 identity key.
Binding the two:

**BE-TR-01** — Immediately after handshake completion, each side MUST send, inside the encrypted
session, its certificate together with an Ed25519 signature by `sig_pubkey` over the Noise
handshake hash `h`. A session MUST NOT deliver application data upward until the peer's certificate
has passed BE-ID-01/02/03 **and** that signature verifies against `h`. An unbound session is a
session with an authenticated key and an unknown owner, and is useless.

### 4.2 Session lifetime

**BE-TR-02** — A session key MUST be replaced after the earlier of 120 seconds or 2⁴⁸ messages.
Old keys MUST be zeroed on replacement. Forward secrecy comes from this rekey and from ephemeral
handshake keys; it is not otherwise provided.

### 4.3 Replay and reordering

**BE-TR-03** — Each transport packet carries a `u64` counter unique per session key. Receivers MUST
implement a sliding-window anti-replay filter (RFC 6479 style, window ≥ 1024) and MUST reject any
counter already seen or below the window. UDP reorders; replay protection MUST NOT be implemented
as "strictly increasing", which would drop legitimate reordered packets and is a common way to make
a protocol unusable rather than safe.

### 4.4 Denial of service

**BE-TR-04 (`mac1` — proof of knowing who you are calling)** — Every handshake message carries, in
its unencrypted header, `mac1 = BLAKE2s-MAC(key = BLAKE2s("bolina-mac1-v2" || responder_sig_pubkey),
message_bytes_preceding_mac1)`. A responder MUST verify `mac1` **before any X25519 operation** and
MUST silently drop the packet on failure. *This is what makes an unsolicited flood cheap to reject:
a sender who does not already know the responder's public key cannot produce a valid `mac1`, and
verifying one BLAKE2s MAC costs orders of magnitude less than a curve operation.*

**BE-TR-04a (`mac2` — proof of controlling your source address)** — A responder under load MUST
reply with a cookie — a BLAKE2s MAC over the initiator's observed source address under a secret
rotated at least every 120 s — and MUST require subsequent handshake attempts to carry it as `mac2`.
Under load, a message with a valid `mac1` but absent or stale `mac2` gets a cookie reply and no
curve operation.

Both are WireGuard's design, adopted unchanged. Neither alone suffices: `mac1` stops attackers who
do not know the target, `mac2` stops attackers who spoof their source.

**BE-TR-07 (no handshake payloads)** — Handshake messages MUST carry no application payload. In
`Noise_IK`, the message-1 payload is encrypted under `es`+`ss` only: it is **replayable and not
forward-secret**, and WireGuard forbids payloads for exactly this reason. *Certificates in
particular MUST NOT travel in the handshake: a certificate now carries up to four CA signatures
(§3.1), so accepting one pre-session would force a responder to perform up to four Ed25519
verifications on a replayable packet — reintroducing, one layer up, the CPU-exhaustion attack that
BE-TR-04 and BE-TR-04a exist to prevent.* Certificates travel inside the established session
(BE-TR-01); the responder's key needed to start the handshake is obtained per §5.1a.

**BE-TR-05 (declared limits, mutually consistent)** — Every buffer with attacker-influenced size has
a hard maximum declared here and enforced at parse time. The limits are stated as one table because
they have to agree with each other, and in an earlier draft they did not:

| Limit | Value | Note |
|---|---|---|
| Transport packet | 1400 bytes | Below common path MTU |
| `MAX_MESSAGE` — reassembled message | 1 MiB | The single ceiling every other size derives from |
| `MAX_HEADER` — envelope overhead | 512 bytes | Version, ids, 4 parents, seq, ts, type, signature, slack |
| `Envelope.body_len` | ≤ `MAX_MESSAGE − MAX_HEADER` | So a maximally-sized legal envelope is deliverable |
| Reassembly contexts, per peer | 8 | |
| Reassembly memory, per peer | 8 MiB | |
| **Concurrent sessions, per node** | **512 (default)** | Declared and enforced |
| **Total reassembly memory, per node** | **256 MiB (default)** | Independent of peer count |

*Previously `body_len ≤ 1 MiB` and reassembly `≤ 1 MiB` were stated separately, so the largest legal
envelope exceeded the buffer meant to receive it — an off-by-header disagreement of exactly the kind
that produces two implementations arguing about whether a message is valid. And per-peer limits with
no limit on peers are not a bound: total memory was `8 MiB × unbounded`, on precisely the nodes
(lighthouses, relays) that face the most peers. BE-TR-04's cookie stops spoofed-source floods, not a
large set of legitimate certificate-holding peers.*

Exceeding a message-level limit drops the message and MUST NOT drop the session. Exceeding a
node-level limit MUST refuse new sessions rather than degrade existing ones, and MUST be surfaced as
a capacity condition rather than silently absorbed.

### 4.5 Fragmentation

Messages larger than the packet limit are fragmented by the sender into a flat header
(`msg_id:u64, index:u16, total:u16`) plus payload, reassembled under the BE-TR-05 limits, and
discarded after a 30-second incomplete timeout. Fragments are protected by the session AEAD like
any other packet; there is no unauthenticated fragmentation.

**BE-TR-06** — Transport failure MUST NOT be reported upward as any form of success. Exactly one
code path marks an envelope delivered, and it requires a bound session per BE-TR-01.

---

## 5. Layer 2 — Mesh

### 5.1 Discovery

Nodes learn peer endpoints from **lighthouses**: statically configured nodes with the `lighthouse`
role holding soft-state `overlay_addr → observed UDP endpoint`.

**BE-MESH-01** — A lighthouse is an availability mechanism, never an authority. A node MUST verify
the peer certificate regardless of which lighthouse suggested the endpoint. A malicious lighthouse
can deny service or misdirect a connection attempt; it MUST NOT be able to cause acceptance of an
unauthenticated peer.

### 5.1a Certificate bootstrap

`Noise_IK` requires the initiator to already hold the responder's static X25519 key, and BE-TR-04's
`mac1` requires its Ed25519 key. Both are in the responder's certificate, so a node needs that
certificate *before* it can send a single packet. Lighthouses therefore serve certificates
alongside endpoints:

```
LookupRequest  := u8 version ; [16] overlay_addr
LookupResponse := u8 version ; [16] overlay_addr ; u8 endpoint_count ;
                  (u8 family, [16] addr, u16 port)* ; u16 cert_len, cert
```

**BE-MESH-07 (lookups are authenticated)** — `LookupRequest` and `LookupResponse` MUST travel inside
an established session with the lighthouse, whose certificate is statically configured (§5.1). They
MUST NOT be parsed from unauthenticated input. *Both carry variable-length fields, including a
certificate with its own variable-length signature list, so BE-SURF-01 puts them behind
authentication. The lighthouse's own certificate needs no lookup — it is configuration — so the
bootstrap terminates without a special case.*

**BE-MESH-04** — A node MUST verify a lighthouse-supplied certificate under BE-ID-01 through
BE-ID-04 before use, and MUST discard it on any failure. *Serving certificates costs the lighthouse
no authority it did not already lack: a certificate is self-authenticating through its CA
signatures, and BE-ID-01 independently derives the overlay address from the key, so a lighthouse
cannot substitute an identity — only refuse to answer, or answer with someone else's valid
certificate, which the caller then detects because it is not the address it asked for.*

**BE-MESH-05** — A lighthouse-supplied certificate is used **only** to open the session. It confers
nothing. The binding verification is BE-TR-01's exchange inside the encrypted session, which no
lighthouse participates in. A node MUST NOT accept a claim, span, grant, or membership fact on the
strength of a certificate obtained this way.

**BE-MESH-06** — A node MAY cache certificates and MUST re-verify validity windows and revocation on
every use rather than at cache-fill time.

### 5.2 NAT traversal and relays

Direct connection is attempted by simultaneous-open hole punching coordinated through a lighthouse.
On failure, traffic falls back to a `relay`.

**BE-MESH-02** — A relay forwards Noise transport packets between two nodes and holds no key
material for either. It cannot decrypt, cannot distinguish message types, and is not a channel
member. *Because channel messages travel inside pairwise Noise sessions (§6), the entire envelope —
header included — is ciphertext to a relay. This is what the previous draft failed to achieve while
MLS application messages rode inside a cleartext envelope header.*

**BE-MESH-03** — A relay MAY store forwarded ciphertext for an offline recipient, subject to a
declared quota and TTL. Stored ciphertext is opaque; a relay operator learns sender, recipient,
size, and time, and nothing else. This metadata exposure is accepted and stated in
`THREAT-MODEL.md` §4.4.

### 5.3 What this deliberately lacks

No central coordination server, no hosted control plane. This diverges from Tailscale at a real
cost — Bolina gives up zero-config onboarding — in exchange for there being no operator anywhere
who can add a node to your network. Nebula's model, not Tailscale's.

---

## 6. Layer 3 — Channels and the envelope

A **channel** is a named set of members exchanging a hash-linked message DAG. There is no channel
key and no group ratchet.

### 6.1 Pairwise fan-out

A message sent to a channel of N members is encrypted and transmitted **N−1 times, once per
pairwise Noise session**. This is the iMessage/early-Signal approach.

Rationale, stated plainly because it is the design's biggest trade:

- **Cost.** O(N) bandwidth per message. For N ≈ 10 (a team plus its agents) this is irrelevant. At
  N ≈ 1000 it is disqualifying, and MLS (RFC 9420) becomes the correct answer — at which point the
  §7/§8 contribution rides on top of it unchanged, which is why they are specified separately.
- **What it buys.** Zero group-key cryptography to implement or get wrong; removing a member
  requires revoking nothing, because there is no shared secret to withdraw — the others simply stop
  sending; and every byte on the wire, including the envelope header, is inside a pairwise session.
- **What it costs.** No group post-compromise security beyond pairwise rekey; sender metadata is
  visible to each recipient (which is intended — attribution is a goal, and deniability is an explicit
non-goal in `THREAT-MODEL.md` §5);
  a sender must reach each recipient or a relay.

### 6.1a Membership without consensus

Membership is the one piece of mutable, authority-bearing state in the protocol, and §0.2 rules out
the machinery normally used to agree on such state. Three rules keep it consistent anyway.

**BE-CHAN-01 (membership is granted by the CA, not by the channel)** — A node is a member of a
channel if and only if its certificate carries the channel's `member_group` (§6.1b), and it is an
administrator if and only if its certificate carries the channel's `admin_group`. Neither is
conferred by any message. *An earlier design let a `Control` message promote and demote members,
which made authority a function of replicated DAG state. The DAG has no total order (§9), so two
honest nodes with legitimate but different views would disagree about who may act — a consensus
requirement smuggled in behind a message name. The offline CA is a serialization point we have
already accepted, it is not a control plane, and using it here costs one certificate reissue per
membership change: acceptable at N ≈ 10, and the same trade already made in choosing fan-out over
MLS (§6.1).*

**BE-CHAN-02 (removal is monotonic and wins)** — The only membership operation carried on the wire
is `Control{Revoke, subject}`, signed by an administrator. Each member maintains a grow-only set of
revoked subjects. A revocation is never undone, never expires within the certificate's life, and a
subject present in the set is treated as a non-member regardless of its certificate. *A grow-only
set converges under any delivery order without agreement — the set union is the same whatever
sequence produced it — which is why removal, and only removal, may live in the DAG. Concurrent
revocations of different subjects commute; concurrent revocation of the same subject is idempotent;
and there is no operation that a revocation could contradict, because no message adds a member.*
Readmission requires a new certificate from the CA.

**BE-CHAN-03** — A node MUST NOT accept channel messages from a non-member, MUST NOT fan out to
one, and MUST treat a revoked subject as a non-member from the moment it accepts the revocation.
Failure to have *received* a revocation is bounded by BE-REV-01, exactly as at Layer 0, and is
stated as a limitation rather than a defence (§12.2).

### 6.1b Genesis and channel parameters

A channel is created by a single **genesis envelope**: `parent_count = 0`, `body_type = 5`, carrying
the channel's immutable parameters.

```
ControlGenesis :=
  u8    version              ; = 2
  u16   name_len, name       ; ≤ 64, channel name (channel_id = BLAKE2s(name || ca_key_0))
  [8]   member_group         ; certificates carrying this group are members
  [8]   admin_group          ; certificates carrying this group are administrators
  u8    ca_count ; [32]* ca_keys   ; the trust set for this channel, ordered ascending
  u8    match_rule           ; = 1 (byte equality). No other value is defined.
```

**BE-GEN-01** — Exactly one envelope in a channel has `parent_count = 0`. Every other envelope MUST
have `1..4` parents. A second genesis for an existing `channel_id` MUST be rejected.

**BE-GEN-02** — Genesis parameters are immutable. There is no message that changes `member_group`,
`admin_group`, `ca_keys`, or `match_rule`. *Immutability is what makes them safe to depend on
without consensus: a value that never changes cannot be disagreed about.* Changing any of them means
creating a different channel.

**BE-GEN-03** — The genesis envelope MUST be signed by a certificate carrying `admin_group`, and
every member MUST verify it before accepting any other envelope in the channel. `channel_id` is
derived from `ca_key_0` — the lowest CA key in the trust set — which removes the ambiguity that
arises once a certificate can carry several CA signatures (§3.1).

**BE-GEN-04** — `match_rule` is fixed at byte equality and is not configurable. *A channel-selected
matching rule would let channel configuration weaken BE-EVID-03's span-to-claim binding, which is
the check the whole attestation layer rests on. The field exists to make its fixity explicit, not to
offer a choice.*

### 6.1c Control

```
Control :=
  u8    version              ; = 2
  u8    action_type          ; 1 = Genesis (body is ControlGenesis), 2 = Revoke
  [32]  subject              ; sig_pubkey; zero-filled for Genesis
  u16   body_len, body       ; ControlGenesis for action_type 1, empty for 2
```

The envelope's own `sig` (§6.2) authenticates the control message; there is no second signature.
`Control` is a flat record like every other structure — it was prose in an earlier draft, in the one
section whose entire purpose is that nothing is prose.

**BE-CTRL-01** — A `Control` with an `action_type` outside `{1, 2}` MUST be rejected. There is no
forward-compatibility path; §2.2 has no extension mechanism by design.

**BE-CTRL-02** — A `Revoke` MUST be rejected unless the envelope sender's certificate carries the
channel's `admin_group`. Authority is read from the certificate at verification time, never from
accumulated channel state.

### 6.2 Envelope

```
Envelope :=
  u8    version              ; = 2
  [32]  channel_id           ; BLAKE2s(channel_name || ca_key)
  [32]  sender               ; sender sig_pubkey
  u64   seq                  ; per (sender, channel), strictly increasing
  u8    parent_count         ; 0..4 — 0 permitted ONLY for the genesis envelope (§6.1b)
  [32]* parents              ; BLAKE2s-256 over the full encoded bytes of the parent
                             ; envelope INCLUDING its sig — the hash covers what was signed
                             ; and the signature itself, so a parent reference is a commitment
                             ; to an envelope that was already authenticated (§9)
  u64   ts                   ; unix ms — INFORMATIVE ONLY
  u8    body_type            ; 1 Utterance, 2 Intent, 3 Grant, 4 Effect, 5 Control, 6 Refusal
  u32   body_len, body       ; ≤ MAX_MESSAGE − MAX_HEADER (BE-TR-05)
  [64]  sig                  ; Ed25519 over all preceding bytes
```

**BE-ENV-01** — `ts` MUST NOT be an input to any security decision. Clocks lie and an adversary
controls its own. Expiry is governed by BE-GRANT-05, which is anchored to the verifier's clock and
to time-since-receipt.

**BE-ENV-02** — A receiver MUST verify `sig` against `sender` before interpreting `body`, and MUST
discard the envelope on failure.

**BE-ENV-03** — A receiver MUST reject an envelope whose sender certificate lacks the role its
`body_type` requires: `Intent` requires `agent`; `Grant` and `Refusal` require `approver`; `Effect` and any
embedded `Span` require `executor`. Rejection happens before the body reaches application logic.

**BE-ENV-04** — A receiver MUST maintain a per-`(sender, channel)` sliding acceptance window over
`seq`, of the same shape as BE-TR-03: an envelope below the window floor is rejected, one already
recorded within the window is rejected, and the floor advances as the window fills. A strict
"greater than the highest accepted" rule is **forbidden** here for the same reason BE-TR-03 forbids
it one layer down: fragmented envelopes complete out of order, so a strict maximum permanently drops
a legitimate earlier envelope — and every later envelope naming it as a parent then fails
BE-LEDGER-01, stalling the member's view of the channel. Combined with BE-TR-03 this gives replay
protection at both layers; neither is removable, because they defend against different attackers
(§2.2 and §2.3 of `THREAT-MODEL.md`).

**BE-ENV-05 (equivocation is surfaced, never absorbed)** — A receiver that has already accepted an
envelope at `(sender, channel, seq)` and receives a *different* envelope with the same triple MUST
raise a divergence event with both hashes, exactly as BE-LEDGER-01 requires for unresolvable
parents. It MUST NOT drop the second as a routine duplicate. *With pairwise fan-out a sender can
send different bytes at one `seq` to different members; each accepts its own. Single-sender
equivocation is far cheaper than the member collusion §9.1 admits to, is available to any
compromised agent or approver, and a window that silently discards the second copy is specified to
hide precisely the attack the ledger exists to reveal.* A duplicate with an identical hash is
dropped silently; a duplicate with a different hash never is.

### 6.3 Body types

```
Utterance := u16 text_len, text (≤ 16 KiB) ; u8 claim_count ; Claim[]
Intent    := [16] intent_id ; u16 resource_len, resource_id (≤ 256)
             u32 action_len, action (≤ 256 KiB, OPAQUE TO THE DAEMON)
             u16 rationale_len, rationale (≤ 4 KiB, AGENT-AUTHORED, UNTRUSTED)
Grant     := §8.1
Effect    := [16] intent_id ; [16] grant_id ; u8 ok ; i32 exit_code
             u8 span_count ; Span[] ; [32] output_digest
Control   := membership operations, channel metadata
Refusal   := §8.5
```

**BE-BODY-01** — The daemon MUST treat `Intent.action` as opaque bytes: it computes
`BLAKE2s(action)` for BE-GRANT-02 and forwards the bytes. It MUST NOT parse them. Structured
interpretation happens only in the executor, off the network path. *This is what keeps BE-DEP-02
true in the presence of arbitrary nested payloads such as MCP tool calls.*

**BE-BODY-02** — An action digest is **always recomputed and never transmitted**. No wire structure
carries a digest of its own action, and no party may accept a digest supplied by the party whose
action it describes. *An earlier draft of this specification carried `action_digest` inside `Intent`
with no rule requiring it to match `BLAKE2s(action)`. That permitted the exact attack §8 exists to
prevent: an agent emits an intent whose displayed bytes are A and whose declared digest is H(B); the
human approves what is displayed; the grant binds H(B); a later intent carrying B satisfies
BE-GRANT-02 byte-for-byte. The field is removed rather than validated, because a redundant field
that must be checked is a check that will eventually be forgotten.*

**BE-BODY-03** — `Intent.rationale` is agent-authored prose and MUST be treated as untrusted input
by every consumer. It is not covered by the grant's binding (BE-GRANT-02) and MUST NOT influence any
authorization decision. Rendering constraints are in BE-GRANT-07.

**BE-EFF-01** — `ok = false` means the mechanism did not run as intended (binary absent, timeout,
output cap exceeded, query refused). A subprocess that ran to completion and returned a non-zero
exit code MUST be reported as `ok = true` with `exit_code` carried inline. An implementation that
collapses "the command ran and reported failure" into `ok = false` is non-conformant. *Did the
mechanism work* and *what did the mechanism report* stay separate all the way up. This is MAD's
`ActionResult` contract, made normative.

---

### 6.4 Backfill

A member that joins an existing channel, or that receives an envelope naming a parent it does not
hold, needs history. Two design choices keep this from becoming a synchronization protocol:

**It is not a channel message.** `SyncRequest` and `SyncResponse` are session messages between two
peers. They carry no `parents`, never enter the ledger, and are never fanned out. *A backfill
request that had to be a channel envelope would need history in order to ask for history.*

**It is iterative, never recursive.** Resolving a missing parent may reveal further missing parents.
An implementation MUST process these with an explicit work queue and an explicit budget, never by
recursive calls. *BE-DEP-02 forbids a recursive parser; a state machine that walks a
attacker-influenced graph by recursion violates its intent while satisfying its letter, and does so
in a language where stack exhaustion is not a caught exception.*

```
SyncRequest  := u8 version ; [32] channel_id ; u8 have_count ; [32]* have_hashes (≤ 64)
                u16 max_envelopes           ; ≤ 64, the requester's own cap
SyncResponse := u8 version ; [32] channel_id ; u8 envelope_count ; (u32 len, bytes)*
                u8 truncated               ; 1 if more remains
```

**BE-SYNC-01 (authenticated peers only)** — `SyncRequest` MUST be refused outside an established
session (BE-TR-01) whose peer is a member of `channel_id` and not revoked. There is no unauthenticated
backfill, which removes reflection and spoofed-source amplification entirely.

**BE-SYNC-02 (hard response bounds)** — A responder MUST return at most `min(max_envelopes, 64)`
envelopes and at most 1 MiB per response, whichever binds first, and MUST set `truncated` when it
stops. Continuation is a *new* request from the requester with an updated `have` set. The responder
keeps no per-request state between responses.

**BE-SYNC-03 (walk budget)** — Resolving unknown parents MUST be bounded by a work queue with an
explicit maximum depth (default 128) and a maximum total envelopes examined per sync operation
(default 4096). On exhaustion the node MUST stop, MUST surface an unresolved-history condition, and
MUST NOT retry automatically. *An unbounded ancestor walk over a graph an adversary contributes to
is a denial-of-service against the node performing it.*

**BE-SYNC-04 (rate)** — A node MUST rate-limit both requests it serves and requests it issues, per
peer, with a declared budget. A member is authenticated, which prevents spoofing; it does not
prevent a compromised member from asking expensive questions forever.

**BE-SYNC-05 (verify before adopt)** — Every envelope received by backfill MUST pass the same
verification as one received live — signature (BE-ENV-02), sender role (BE-ENV-03), membership
(BE-CHAN-03), and parent-hash consistency — before entering the local ledger. Backfilled history is
not privileged for having arrived through a peer that already accepted it.

## 7. Layer 4a — Attestation *(new)*

The first contribution: **what is a claim worth, and who decides?**

### 7.1 Span

A signed record that a specific observation was actually made by a specific executor.

```
Span :=
  u8    version              ; = 2
  [16]  span_id
  [16]  trace_id             ; groups spans belonging to one turn
  u16   resource_len, resource_id  ; canonical form (§8.4) — WHAT was observed, ≤ 256
  u8    method_id            ; HOW it was observed — §7.4. The evidence class is DERIVED
                             ; from this by the receiver; it is not carried on the wire
  u8    volatility           ; 1 = volatile (state that can change under us),
                             ; 2 = stable (a content-addressed fact)
  [32]  origin               ; hash of the Effect envelope in which this span was published;
                             ; the span's anchor in the causal order (BE-EVID-09)
  u64   observed_at          ; unix ms, executor's clock. INFORMATIVE ONLY — never a security
                             ; input; freshness is causal (BE-EVID-05), not clock-based
  [32]  digest               ; BLAKE2s of the raw observed output
  [32]  executor             ; executor sig_pubkey
  [64]  sig                  ; Ed25519 over all preceding bytes, domain tag 0x03 (BE-SIG-01)
```

**BE-EVID-01** — A span is valid only if `sig` verifies against `executor` **and** that certificate
carries the `executor` role. With BE-ROLE-02, an agent is structurally incapable of manufacturing
evidence for its own claims: it holds no key that produces a verifying signature. *This is the
difference between Bolina and every "the model cites its sources" scheme — here the sources are not
produced by the model.*

### 7.2 Claim

```
Claim := u16 text_len, text (≤ 1 KiB) ; u16 subject_len, subject (≤ 256)
         u8 confidence_q8            ; confidence × 255, fixed-point
         u8 span_count ; [16]* span_ids
```

Confidence is fixed-point, not float: floats have multiple encodings of one value and no reason to
be in a signed structure.

| Class | Ceiling | `q8` value |
|---|---|---|
| DirectObservation | 0.95 | **242** |
| ExpertTestimony | 0.85 | **216** |
| Documentation | 0.75 | **191** |
| Inference | 0.65 | **165** |

The class is never transmitted. It is derived by the receiver from `Span.method_id` through the
fixed table in §7.4.

The integers are normative, not the decimals: `0.95 × 255 = 242.25`, and none of the four ceilings
is exactly representable in `q8`. Implementations MUST compare against the integer column and MUST
round toward zero when converting. Rounding up would let a claim present at 0.9509 while G3 says it
cannot exceed 0.95 — a falsification of the goal by one least-significant bit, which is exactly the
kind of disagreement §11.3's vectors exist to prevent.

**BE-EVID-02 (the receiver recomputes, from the strongest support)** — A receiver MUST recompute
effective confidence as `min(stated_confidence, ceiling(strongest matching supporting span))` and
MUST present the recomputed value. The sender's number is an upper-bound *request*, never an
accepted fact.

*Strongest, not weakest. The weakest-link rule comes from the Prumo Evidence Contract, where it is
correct: it describes **conjunctive** evidence — a chain in which A and B are both required to reach
C, so the chain is as strong as its worst link. `supported_by` here is **disjunctive**: each span
supports the claim on its own, and BE-EVID-03 already forces every one of them to concern the same
subject. Applying the chain rule to independent supports produced a perverse incentive — a sender
holding a DirectObservation (0.95) and a corroborating Inference (0.65) would score 0.65 for citing
both, so the rational move was to hide evidence. A protocol whose evidence layer rewards disclosing
less has defeated itself.*

**BE-EVID-02a (no support is zero, not a floor)** — A claim with no valid matching span has an
effective confidence of **0.00** and MUST be rendered with an explicit "no mechanical confirmation"
marker. It is not capped at 0.65.

*While unsupported claims shared the 0.65 ceiling with the Inference class, the number carried no
information: "an executor derived this from other spans" and "the agent asserted this" scored
identically, and the distinction survived only in a UI marker that any consumer could drop. The
protocol's algorithmic confidence in an unbacked assertion is zero. A human may read the text and
choose to believe it; the protocol declines to put a number on it.*

**BE-EVID-02b (unresolved is indeterminate, not zero)** — A claim whose spans are valid but whose
`origin` is not yet in the local ledger (BE-EVID-09, *Unresolved*) has **no** effective confidence.
It MUST NOT be presented as 0.00, MUST NOT be presented as any number, and MUST be marked as
pending resolution.

*Zero and unknown are different epistemic states, and collapsing them would undo BE-EVID-09: a
member waiting on backfill would see a genuine, fully-evidenced claim rendered exactly like a
fabricated one. "I have no proof" and "I have not yet received the proof" must not look alike, or
network latency becomes indistinguishable from dishonesty — the same failure BE-EVID-08 removed from
the pull model.*

**BE-EVID-03** — A span supports a claim only if `Span.resource_id` equals `Claim.subject` under the
channel's declared matching rule (exact byte equality by default). A span about an unrelated
resource MUST NOT raise a claim's ceiling.

> BE-EVID-03 closes the gap named as open in `gate-protocol/ARCHITECTURE.md` §Layer 2, where the
> verdict gate checks only whether *any* span exists for the trace. Moving the check to the receiver
> — where `subject` and `resource_id` are structured fields rather than prose — is what makes the
> stricter rule mechanizable at all.

### 7.3 Freshness

§7 as far as this point defends against an agent **manufacturing** evidence. It does nothing about
an agent **selecting** evidence — citing a true, correctly-signed observation that has since stopped
describing reality. That is the cheaper failure and the one Adversary M produces without intent: a
year-old `DirectObservation` that "the deploy succeeded" would otherwise lift a claim about today to
a 0.95 ceiling, and the receiver's recomputation — the mechanism the layer rests on — would return
0.95 with no marker.

The obvious fix is a time window, and it does not survive contact with §6.4. A window on the
executor's clock contradicts BE-ENV-01. A window on the receiver's clock is worse: a member
backfilling history receives year-old spans *now*, and time-since-receipt would score them as
seconds old. The same reasoning that produced BE-HIST-03 applies here.

**BE-EVID-05 (superseded evidence stops supporting)** — A span with `volatility = volatile` MUST NOT
support a claim if the ledger contains an `Effect` on the same canonical `resource_id` that is a
causal descendant of the span's own `Effect` and a causal ancestor of the claim. Such a span
contributes zero, and a claim left with no supporting span falls to **0.00** with the "no mechanical
confirmation" marker of BE-EVID-02a. *Supersession does not downgrade a claim to a weaker tier — it
removes the support entirely, and a claim with nothing behind it gets no number at all.*

*Evidence is invalidated by an observed change to its subject, not by elapsed time. A span about a
resource nobody has touched stays as good as the day it was signed; a span about a resource that was
demonstrably modified afterwards stops counting the moment the modification enters the ledger. This
is strictly sharper than any window: a one-hour window both discards good evidence at 61 minutes and
accepts stale evidence at 59, while causal supersession is exact in both directions and identical
for every member without agreement.*

**BE-EVID-05a (supersession is strict descent)** — In BE-EVID-05, the superseding `Effect` MUST be
a STRICT causal descendant of the span's own `origin` Effect: the Effect that published a span
does not supersede the span it published. *If descent were reflexive, every volatile span would be
superseded by its own publishing Effect at birth, volatile evidence would be worthless by
construction, and the rule would contradict its own purpose — invalidation by a LATER observed
change. The claim side needs no strictness pin: a claim travels in an `Utterance`, which cannot be
a superseding `Effect`. (RED-TEAM-09, F3.)*

**BE-EVID-06 (volatility is the executor's declaration and the receiver's floor)** — `volatility` is
set by the executor that made the observation, which is the only party that knows what it observed.
A receiver MUST treat an unrecognized value as `volatile`. *Fail-closed: an implementation that
forgets to set the field, or a future value this version does not know, degrades to the stricter
rule rather than the looser one.*

**BE-EVID-07 (distance is not a substitute)** — Nothing in this section caps how far back a
supporting span may sit in the DAG. A `stable` span — a content-addressed fact, a digest of an
immutable artifact — is meant to remain valid indefinitely, and imposing a causal distance limit
would be a clock in disguise. The residual is stated in `THREAT-MODEL.md` §4.9: an executor that
marks volatile state as `stable` defeats BE-EVID-05, which is one more reason executors are small,
audited programs rather than models.

### 7.4 Evidence class is derived, never declared

An evidence class chosen at runtime by whoever is producing the evidence is a confidence dial. An
executor that classified an inference as a `DirectObservation` — through a bug, through compromise,
or through being asked nicely — would raise a claim's ceiling from 0.65 to 0.95 with a single byte,
and no receiver could tell: `digest` hashes output that is never transmitted, so there is nothing to
inspect.

The fix is the one applied to `action_digest` in BE-BODY-02 and to `resource_id` in BE-RES-01:
**remove the choice rather than validate it.** A span carries *how* it was observed. The class is a
function of that, fixed here, computed by the receiver.

| `method_id` | Observation mechanism | Class |
|---|---|---|
| 1 | Subprocess executed by this executor now; exit status and output captured | DirectObservation |
| 2 | File read now from local storage; content captured | DirectObservation |
| 3 | Network request issued now; response captured | DirectObservation |
| 4 | Database query executed now; result set captured | DirectObservation |
| 5 | Static configuration or documentation read | Documentation |
| 6 | A tool's own declared description or schema | Documentation |
| 7 | A statement signed by an identity carrying a declared domain group | ExpertTestimony |
| 8 | Derived from other spans; nothing observed directly | Inference |

**BE-EVID-11 (the code path decides, not a parameter)** — `method_id` MUST be a compile-time
constant of the executor code path that produced the span. An executor MUST NOT expose any interface
that accepts `method_id`, `evidence_class`, or confidence as an argument — not from an agent, not
from configuration, not from its own callers. The subprocess routine emits `1` and can emit nothing
else. *There is no runtime decision to get wrong, so there is nothing to manipulate: classification
becomes a property that is verified by reading the executor's source once, statically, rather than
trusted on every call. This is the enforcement-never-pays-tokens rule applied to classification —
there is no judgement here to pay for.*

**BE-EVID-12 (the requester never names the method)** — An `Intent` requests an action. It MUST NOT
name, hint at, or constrain the observation method. The executor selects the method by which code
path runs, exactly as it canonicalizes `resource_id` under BE-RES-01. *An agent that could choose
its own evidence class would be signing its own homework through an intermediary.*

**BE-EVID-13 (unknown method fails to the floor)** — A receiver MUST derive the class from the table
above and MUST treat any `method_id` outside it as `Inference` (0.65). Unknown mechanisms get the
lowest ceiling, never the benefit of the doubt.

**BE-EVID-14 (capture is a precondition)** — A method in classes DirectObservation may produce a
span only if the observation's output was actually captured and `digest` is its hash. An executor
that reaches a code path without captured output MUST emit no span rather than a span with an empty
or synthetic digest. *This is not receiver-verifiable and is stated as an executor obligation; it is
in the same trust bucket as §4.3 and is one more reason executors are small, audited, model-free
programs.*

**BE-EVID-15** — `method_id`, its class mapping, and the resulting ceilings MUST appear in the
cross-implementation test vectors (§11 item 3). Two conformant implementations disagreeing about the
class of the same span would produce different confidences from identical evidence, which is the
failure this whole section exists to remove.

### 7.5 Evidence travels with the claim

**BE-EVID-08 (piggyback is mandatory)** — An `Utterance` MUST carry, inline, the full encoded `Span`
for every `span_id` its claims reference. A claim referencing a span not present in the same
envelope is treated as unsupported. There is no request-response path for fetching spans, and
`SyncRequest` (§6.4) MUST NOT be extended to serve them.

*Push, not pull, for two reasons. First, a self-contained envelope yields the same verdict at every
member with no coordination — the property BE-HIST-03 and BE-EVID-05 exist to protect, and one that
a round-trip would destroy by making confidence depend on what each member happens to have resolved.
Second, and specific to Adversary M: under a pull model, network loss and fabricated evidence are
indistinguishable, so an agent asserting a claim it cannot support benefits from the doubt. Under
push, a claim without its span is a claim the sender chose not to support. The ambiguity is removed
rather than managed.*

**BE-EVID-09 (three states, not two)** — A receiver MUST distinguish:

| State | Condition | Presentation |
|---|---|---|
| **Supported** | signature valid (BE-EVID-01), subject matches (BE-EVID-03), `origin` present in the local ledger, not superseded (BE-EVID-05) | ceiling of the **strongest** such span (BE-EVID-02) |
| **Unresolved** | signature and subject valid, but `origin` is not in the local ledger | **no number**, marked *"evidence unresolved — pending"* (BE-EVID-02b) |
| **Unsupported** | no valid span cited | **0.00**, marked *"no mechanical confirmation"* (BE-EVID-02a) |

*Unresolved is not a failure state; it is the honest description of a member who has not yet
backfilled the effect that published the span (§6.4), and it resolves on its own. Collapsing it into
Unsupported — which the previous draft did by omission — makes the attestation layer's output a
function of delivery luck and hides the difference between "the network is behind" and "the agent
has no proof".* `origin` is what makes the distinction computable: without it an inline span is
authentic but has no position in the causal order, so BE-EVID-05's supersession check has nothing to
anchor to.

**BE-EVID-09a (mixed resolution composes per span)** — A claim citing several spans where some
`origin`s are in the local ledger and some are not: the resolved, non-superseded spans support the
claim at the ceiling of the **strongest** among them (BE-EVID-02), and the unresolved ones contribute
nothing yet. The claim is **Unresolved** only when every cited span is either valid-and-matching but
unresolved or has zero resolved origins, and **Unsupported** only when it has no valid matching span
at all. *Without this rule a single absent origin would demote a fully-supported claim to
Unresolved, paying for one late delivery with every honest claim the member has. (RED-TEAM-09, F4.)*

**BE-EVID-09b (origin must resolve to an Effect)** — A span whose `origin` resolves to an envelope
of any body type other than `Effect` cannot support a claim; it falls out of the Supported and
Unresolved states alike. *§7.1 declares `origin` as the hash of the Effect envelope that published
the span, so a span whose origin resolves to anything else contradicts its own declared structure
and fails closed. (RED-TEAM-09, F7.)*

**BE-EVID-10 (bounded piggyback)** — An `Utterance` MUST carry at most 32 claims and at most 64
spans, and MUST be rejected if it exceeds either. Receivers MUST deduplicate spans by `span_id` in
storage; the wire duplication is accepted. *The cost is O(N) redundant bytes under fan-out, which is
the same trade already made in §6.1: bandwidth is spent so that coordination is not.*

**BE-EVID-04** — Ceiling arithmetic and calibration MUST be computed by a deterministic routine with
no model in the loop. *Judgement pays tokens; enforcement never does.* The arithmetic is small
enough to implement directly; `caravela-epistemic` (`weight.rs`, `calibration.rs`) already
implements these ceilings and a Brier-score calibration tracker and is the reference to port from,
not to link against.

---

## 8. Layer 4b — Capability *(new)*

The second contribution: **what makes an effect permissible?**

### 8.1 Grant

```
Grant :=
  u8    version              ; = 2
  [16]  grant_id             ; unique nonce
  [16]  intent_id            ; the ONE intent instance approved
  [32]  approver             ; approver sig_pubkey
  [32]  subject              ; the ONE agent permitted to invoke
  [32]  executor             ; the ONE executor permitted to act
  u16   resource_len, resource_id  ; canonical form, per §8.4
  [32]  action_digest        ; BLAKE2s of the Intent.action bytes, recomputed by
                             ; the approving interface, never copied from the wire
  u64   not_after            ; unix ms, approver's clock
  [64]  sig                  ; Ed25519 over all preceding bytes, domain-separated per BE-SIG-01
```

A Grant is an **object capability**: holding one *is* the authority. It is bound to one agent, one
executor, one resource, and one exact action, and it is spent on use.

### 8.2 State machine

```
DRAFTED ──► PENDING ──┬─► APPROVED ──► EXECUTING ──┬─► EXECUTED
                      │                            └─► EXECUTION_FAILED
                      ├─► REJECTED
                      └─► EXPIRED
```

`DRAFTED → PENDING` is caused by an `Intent`. `PENDING → APPROVED` is caused **only** by a valid
`Grant`; there is no other in-edge to `APPROVED`. `PENDING → REJECTED` is caused **only** by a
valid `Refusal` (§8.5); there is no other in-edge to `REJECTED`, and before RT-01 there was none
at all: the state sat in the diagram unreachable (RED-TEAM-08, F1).

**BE-GRANT-01 (single-shot, durably)** — An executor MUST keep a ledger of consumed `grant_id`s and
MUST refuse any already present. The `grant_id` MUST be **durably committed to stable storage before
the effect is attempted**, and the ledger MUST survive process restart, crash, and redeployment.

*This is deliberately the opposite of BE-GRANT-04, and the two are not in tension: **pending**
approvals are memory-only so that a restart revokes them, while **spent** grant ids are durable so
that a restart cannot un-spend them. Both rules fail in the safe direction, which is why they point
opposite ways.* An executor that recorded consumption only in memory would, after any restart,
re-execute a replayed grant that is still within its validity window — and restart is the single
most frequent event in the system's life.

**BE-GRANT-01a (crash during execution)** — A `grant_id` committed under BE-GRANT-01 whose `Effect`
was never published MUST be treated as consumed and MUST NOT be retried automatically. On restart,
the executor MUST publish an `Effect` with `ok = false` and a cause of `interrupted` for every such
grant, and MUST release the resource lock. *An interrupted effect whose outcome is unknown is
reported as unknown; it is never silently retried and never silently forgotten.*

**BE-GRANT-02 (exact binding)** — An executor MUST recompute `BLAKE2s` over the received
`Intent.action` bytes and MUST refuse unless it equals `Grant.action_digest` byte-for-byte. No
partial, prefix, or semantic matching. Approving "restart the CMS container" does not approve
restarting anything else, because the bytes differ.

**BE-GRANT-03 (no bypass edge)** — No code path may reach `EXECUTING` except through a single
verification routine that performs **all** of the following checks, in the enumerated order, and
refuses on the first failure:

0. `Grant.version` equals 2. Any other value MUST be refused before further processing.
   *The field existed on the wire from the first draft and no check ever read it (RED-TEAM-08,
   F6): a parser accepting a future variant would feed it through a verification list written
   for this one.*
1. The Grant arrived as a `body_type = 3` envelope whose envelope `sender` equals `Grant.approver`.
   A Grant reaching the executor by any other path MUST be refused. *Without this, BE-ENV-03's role
   check — which is about the envelope sender — never binds to the grant body's own approver field.*
2. `Grant.sig` verifies against `Grant.approver` under BE-SIG-01 domain separation.
3. `Grant.approver`'s certificate is valid **at this moment**: BE-ID-02, BE-ID-04, carries the
   `approver` role, and is not revoked (BE-REV-02). Re-checked here, not cached from receipt.
4. `Grant.subject`'s certificate is valid **at this moment**: BE-ID-02, BE-ID-04, carries the
   `agent` role, and is not revoked (BE-REV-02). Re-checked here, not cached from receipt.
   *The approver's certificate was revalidated at execution time, the requesting agent's was not,
   so revoking a compromised agent did not stop the work it had already requested (RED-TEAM-08,
   F5). The asymmetry had no justification.*
5. `Grant.executor` equals this executor's own `sig_pubkey`, byte-for-byte.
6. `Grant.subject` equals the `sender` of the `Intent` being executed, byte-for-byte.
7. `Grant.intent_id` equals the `intent_id` of a `PENDING` intent held by this executor. A Grant
   matching no pending intent MUST be dropped, never buffered and never used to create one.
8. `Grant.resource_id` equals the canonical `resource_id` of that intent (§8.4), byte-for-byte.
9. `Grant.action_digest` equals `BLAKE2s` recomputed over that intent's `action` bytes (BE-GRANT-02).
10. Expiry passes both conditions of BE-GRANT-05.
11. `grant_id` is absent from the consumed ledger, and is durably committed before proceeding
   (BE-GRANT-01). This is the only check that performs I/O, and it runs last by obligation, not
   by accident.

The order above is normative (RED-TEAM-08, F3): every check that reads state or computes runs
before the only I/O step, check 11's durable ledger commit. An earlier draft committed the
`grant_id` before comparing expiry, which cost one forced disk write per delivered expired Grant,
at the attacker's chosen rate, and marked a `grant_id` consumed for a Grant that was then refused:
on restart, BE-GRANT-01a would publish an `interrupted` Effect for an effect that never started.
A check order that makes the ledger assert a fabricated effect is an audit defect, not a
performance detail.

**Conformance status (Zig slice).** The routine in `verify.zig` models checks 0, 1, 2, 5, 9, 10 and
11 inside the single routine. Checks 3 and 4 (approver and subject certificate validity) and 6, 7
and 8 (subject, intent_id and resource_id matching against the pending intent) are delegated to the
executor until a certificate store and a pending-intent table exist. This is provisional debt, not a
relaxation of the rule above: BE-GRANT-03 requires all twelve checks in the routine, and the
repayment condition is that 3, 4, 6, 7 and 8 fold into `verifyGrantThen` (the routine) the moment
their backing state
is available. Recorded here so the debt survives being forgotten.

**BE-GRANT-03b (verification is a call, not a value; language-portable property).** The grant's
effect MUST be reachable only through the single verification routine, and the routine MUST invoke
execution itself: it runs the checks in the enumerated order, commits the ledger (check 11), and
calls the effect inside one call frame. No value representing a verified grant — capability, token,
handle, seal, slot — MUST exist outside that frame. Verification and the start of execution are one
function call, not a span of time. The caller supplies the effect as a callback the routine
invokes; the routine passes it the grant it just verified, and the frame ends when the effect has
started. *Every defect this rule accumulated came from the verified state being a value you can
keep: aliasing TOCTOU (verify A, consume B), the expiry that does not expire (checks run at mint
time, consumption at any time), use-after-free. If the verified state never exists as a value
outside the call, none of them has an interval to drift in. The window is deleted rather than
defended; the seal that defended it (BE-GRANT-03c) was superseded by that deletion. The Grant on
the wire remains an object capability (§8.1) — signed authority still travels as bytes — and what
this rule removes is only the executor-side storable form of the verified grant.* The mechanism is
per language:

| Language | Mechanism | What keeps the wall |
|---|---|---|
| Zig | continuation-passing routine `verifyGrantThen(env, grant, ctx, execute)` invokes `execute` inside the frame | gate M10 (effect reach confined to the routine, zero exceptions) + gate M8 (zero pointer-minting builtins anywhere, so no handle to forge) |
| Rust | routine takes a closure; effect functions private to the executor module | privacy makes the bypass unwriteable outside the module |
| Go | routine takes a func value; effect functions unexported | same shape, unexported scope |

*§8.1's prose says a Grant is bound to one agent, one executor, one resource, one intent, and one
exact action. Checks 5 to 9 are what make that sentence true; before they were enumerated, only the
last of the five had an enforcing rule. This is the invariant mutation testing must attack hardest
(§11.2).*

*Rust's guarantee is safe code cannot forge; Zig's honest translation is code that passes the gates
cannot forge.* The property this rule protects is reach, not construction: no code path arrives at
the effect without passing through the checks, because the checks and the effect live in the same
frame. Single-shot is part of the shape: the ledger commit (check 11) runs before the callback, so
a callback that fails does not un-consume the grant. The `grant_id` is spent; a failed effect is
BE-GRANT-01a's interrupted case, reported as unknown, never retried. *Write it down or the first
person who hits a failed effect will "fix" it into a retry and un-spend a grant the ledger already
committed (BE-GRANT-01: durable before the effect is attempted).*

**Provisional debt (call-graph wall).** In the slice the callback is caller-supplied, so nothing
structural stops a caller from running its own effect code without calling the routine. The wall
inside the slice is honesty plus gate M10: the routine is the only modeled path to an effect, and
M10 confines effect reach with a zero-exceptions grep the way M9 confines raw parser exits. In the
real executor the effect functions (the durable ledger commit, the resource lock, the action
itself) MUST be reachable only from the routine, enforced by that same gate. Repayment condition:
the moment effect functions exist outside the slice, they move behind the routine and M10's grep
covers their call sites. Recorded here so the debt survives being forgotten.

**BE-GRANT-03c (seal by content, capability lifetime).** SUPERSEDED BY REMOVAL (round 4 review,
2026-08-06). The original requirement read: *a capability MUST be sealed by content at
verification time — a keyed digest over the exact grant bytes the routine verified, recomputed at
every access, refusing on mismatch — because holding a capability proves the checks passed at time
T over specific bytes, and without the seal consumption at T+n reads state that may have changed
since.* The seal defended the window between verification and consumption. BE-GRANT-03b's
restatement deletes the window: verification is a call, not a value, and the effect starts inside
the routine's frame, so there is no interval left for the bytes to drift in and nothing outside
the frame for a seal to protect. A seal over a nonexistent interval has nothing to recompute.
Numbers in this specification are grow-only, so the requirement keeps its number and its epitaph:
*the window was removed, not sealed. The seal was not wasted — it made the storable form's cost
visible enough to question, and the question deleted it.* The keyed-digest machinery, the
caller-owned slot, the opaque capability type, the two pointer-mint casts, and the negative
compile canary were all deleted with it (LANGUAGE.md §4.1, cost two restated).

**BE-GRANT-03a (frozen during verification)** — From the moment the verification routine begins
for an intent until it either refuses or the intent enters `EXECUTING`, the intent's lifecycle
MUST be frozen: BE-GRANT-06a's `T_pending` MUST NOT fire for it, the resource lock MUST NOT be
released, and the transition to `EXECUTING` MUST occur under the same lock acquisition. The
routine MUST NOT return a verified capability and then re-acquire anything before `EXECUTING`.
*Two conforming rules, one violated invariant, no rule broken (RED-TEAM-08, F2): `T_pending`
could fire during the durable write of the last check, releasing the resource lock; another
agent legitimately acquires the resource; the routine then returns a verified capability and
enters `EXECUTING` on a resource someone else holds.*

**BE-GRANT-04 (fail-closed on restart)** — Pending state MUST live in process memory only. An
executor restart MUST collapse every `PENDING` to `EXPIRED`. A dead-man's switch: safety is tied to
presence-of-state, not to detecting a specific failure, so it holds under failures nobody
anticipated. No timer is required for this transition to be correct.

**BE-GRANT-05 (bounded expiry)** — An executor MUST refuse a Grant if **any** of the following
holds:

- `not_after` is at or past on the executor's own clock, compared as a non-strict bound: a Grant
  whose `not_after` equals the current millisecond is refused. *Capability boundaries are denied at
  the instant of expiry, not granted; the check is `now_ms >= not_after`, refuse on equal.*
- `not_after` is further in the future than `T_max` (default 3600 s) from the moment of first
  receipt — an approver MUST NOT be able to mint long-lived authority by writing a distant
  timestamp, and an executor MUST NOT accept one;
- more than `T_recv` (default 300 s) has elapsed since **first** receipt of this `grant_id`.

`T_recv` is a per-grant budget, not a per-delivery one: redelivery — by a relay's store-and-forward
(BE-MESH-03), by retransmission, or after an executor restart — does not restart it. The executor
records first-receipt time alongside the grant id. *The second and third conditions hold even if the
approver's clock is wrong or adversarial; the first is what makes a revoked-then-expired grant fail
twice rather than once.*

**BE-GRANT-06 (resource exclusivity)** — An executor MUST refuse a second `Intent` whose canonical
`resource_id` (§8.4) is already in `PENDING` or `EXECUTING`. Reject, do not queue. Concurrent
sessions acting on one resource is a live failure mode with an incident behind it, not a
hypothetical. *`DRAFTED` is deliberately absent: it is a state at the agent, before any `Intent` is
emitted, and an executor has no way to observe it. A rule naming an unobservable state is
unenforceable.*

**BE-GRANT-06a (pending timeout)** — An intent MUST transition `PENDING → EXPIRED` after `T_pending`
(default 900 s) on the executor's monotonic clock, releasing the lock. *Without it, any agent —
unreliable rather than malicious — locks a resource permanently by emitting an intent nobody
approves, denying it to every other agent and to every human-driven flow until the process dies.
BE-GRANT-04 collapses pending state on restart, which is a different trigger and cannot be the only
one.*

**BE-GRANT-06b (intent_id uniqueness)** — An executor MUST refuse an `Intent` whose `intent_id`
equals that of an intent it already holds in `PENDING`, so grant matching (check 7) finds at most
one intent per id by construction. *Before this rule, uniqueness among PENDING intents was
accidental: check 8's resource comparison caught a mismatched lookup, which is unexploitable by
accident rather than by construction (RED-TEAM-08, F4). The property belongs at admission, where
it is enforceable, not at matching, where it was only observed.*

### 8.3 What the human sees

**BE-GRANT-07** — The approving interface MUST render, from the `Intent` itself: the canonical
`resource_id` as resolved by the executor (§8.4), the full action bytes, and an `action_digest`
**recomputed by the approving interface from the bytes it is displaying**. It MUST NOT display a
digest taken from any wire field, and it MUST NOT render a summary produced by an agent. The Grant
is signed over the recomputed digest. *An approval UI populated by the party being approved is a
confirmation gate under another name; a digest supplied by that party is worse, because it looks
like verification.*

**BE-GRANT-07a** — If `Intent.rationale` is displayed at all, it MUST be marked as untrusted,
agent-authored text, MUST be visually subordinate to the action bytes, and MUST NOT be the only
element visible without scrolling. *`THREAT-MODEL.md` §4.1 names "an injected request a human
approves" as the residual risk of the entire design. `rationale` is a 4 KiB attacker-influenced
prose channel aimed at the approver's eyes, and it is not covered by the binding in BE-GRANT-02. An
interface that renders it prominently is building the attack it was meant to prevent.*

**BE-GRANT-08** — A Grant MUST be signed by a key the approving human controls directly.
Server-side signing on behalf of a human authenticated by session cookie is non-conformant: it
reintroduces a party that can mint authority without the human present.

---

### 8.4 Resource identity

`resource_id` is the subject of the exclusivity lock (BE-GRANT-06), the scope of the Grant, the
string the human reads before approving (BE-GRANT-07), and the matching key between evidence and
claims (BE-EVID-03). Left as free text, it silently defeats all four: two spellings of one resource
break the lock, and a spelling mismatch either strips support from a true claim or lends support to
an unrelated one.

```
resource_id := "bol:" executor_fp "/" namespace "/" path
  executor_fp : 16 lowercase hex chars, the first 8 bytes of BLAKE2s-256(executor sig_pubkey) (BE-RES-06)
  namespace   : 1..32 chars from [a-z0-9-]
  path        : 1..180 chars from [a-z0-9-._/], no empty segment, no "." or ".." segment
```

**BE-RES-01 (the executor canonicalizes, never the requester)** — An `Intent` carries a *proposed*
`resource_id`. The executor MUST resolve it to a canonical form drawn from a set of resources it
knows, and every subsequent use — the lock, the Grant, the approval rendering, the `Effect`, the
ledger — MUST use the canonical form and never the proposed one. *This is BE-EVID-02's rule applied
to identity rather than to confidence: the receiver recomputes, and the sender's version is a
request. A protocol that recomputes the trustworthiness of a claim but accepts the requester's word
for what the claim is about has moved the ambiguity rather than removed it.*

**BE-RES-02 (unknown resolves to refusal)** — If the executor cannot resolve a proposed
`resource_id` to exactly one canonical resource it knows, it MUST refuse the intent. Ambiguous
matches refuse; zero matches refuse. There is no "unknown resource, proceed" path and no
create-on-first-use.

**BE-RES-03 (aliases collapse into the lock)** — Two proposed identifiers that resolve to the same
canonical form are the same resource for every purpose, including BE-GRANT-06 exclusivity. An agent
cannot obtain a second concurrent lock by renaming its target.

**BE-RES-04 (one resource, one executor)** — `executor_fp` is part of the identifier, so a canonical
`resource_id` names exactly one executor by construction. An executor MUST refuse any intent whose
canonical `resource_id` does not carry its own fingerprint.

> BE-RES-04 also resolves an open question the previous draft carried: BE-GRANT-06's exclusivity is
> enforced by a
> single executor process serializing locally, which is only sound if a resource is unreachable
> through a second executor. Putting the executor's fingerprint inside the identifier makes that a
> property of the namespace rather than an operational hope. Two executors fronting one underlying
> physical resource remains possible and remains an operator error; it is now an error the naming
> scheme makes visible instead of one it hides.

**BE-RES-05 (granularity is declared, not emergent)** — An executor MUST publish its resource set as
signed channel state. Approval volume is a direct function of resource granularity, and approval
volume is what produces the approver fatigue named as the dominant residual risk
(`THREAT-MODEL.md` §4.1). Granularity is therefore an explicit, reviewable operator decision, not a
by-product of how agents happen to phrase requests.

**BE-RES-06 (the sig_pubkey fingerprint is BLAKE2s-256)**: `executor_fp` is a digest of the executor's signing public key, never the raw bytes: `executor_fp = BLAKE2s-256(sig_pubkey)[0..8]`, rendered as 16 lowercase hex chars. A fingerprint is a hash; raw key bytes are not a fingerprint and would leak key structure into the namespace. Two implementations that derive `executor_fp` differently produce disjoint namespaces and silently defeat BE-RES-03 alias collapsing and BE-RES-04 one-resource-one-executor. The fingerprint affects canonicalization only: `resource_id` is opaque on the wire (a `u16` length plus bytes), so this rule constrains the executor-side canonical resolver, not the wire encoding.

### 8.5 Refusal

`REJECTED` existed in the §8.2 state diagram with no message able to cause it (RED-TEAM-08, F1).
An approver who reviewed an intent and decided NO could only stay silent, at the cost of the full
`T_pending` lock on the resource: careful refusal was indistinguishable from being asleep, and was
punished by the very mechanism meant to expire stale requests. An incentive pointing the wrong way
exactly where `THREAT-MODEL.md` §4.1 says this design is weakest. Refusal makes NO a first-class,
signed, ledgered act.

```
Refusal :=
  [16]  intent_id            ; the ONE intent instance refused
  u16   note_len, note       ; ≤ 1 KiB, approver-authored, informative only
  [64]  sig                  ; Ed25519 over all preceding bytes, domain tag 0x06 (BE-SIG-01)
```

`note` is prose for the requesting agent and MUST NOT influence any authorization decision: the
binding content of a Refusal is the `intent_id` alone. Any valid approver may refuse, because an
intent is bound to no approver until a Grant binds one.

**BE-GRANT-09 (refusal semantics)** — An executor MUST transition an intent `PENDING → REJECTED`
upon receiving a `body_type = 6` envelope in which `Refusal.sig` verifies against the envelope
`sender` under domain tag 0x06, the sender carries the `approver` role (BE-ENV-03), and
`Refusal.intent_id` names an intent this executor holds in `PENDING`. The resource lock MUST be
released immediately, without waiting for `T_pending`. A Refusal matching no `PENDING` intent MUST
be dropped: never buffered, and never used to pre-reject an intent that arrives later.

**BE-GRANT-10 (refusal is terminal)** — `REJECTED` is terminal: no transition exists out of it.
A Grant naming a `REJECTED` intent MUST be dropped, which check 7 provides by construction since
it matches `PENDING` intents only. A Refusal is a signed channel event (§9), so every member sees
it: silence and refusal are no longer the same state, and a careful NO now releases the lock in
one message instead of after the full `T_pending` wait. *A malicious approver's refusal costs no
more than the silence already available to it, so the new message adds no attack surface; it only
removes the penalty from honest refusal.*

## 9. Layer 5 — Channel ledger

Envelope field `parents` links each envelope to the envelopes its sender had accepted when it sent,
forming a per-channel hash-linked DAG.

A DAG, not a chain: with pairwise fan-out there is no server to impose total order, and pretending
otherwise would either require consensus (out of scope, §0.2) or silently drop concurrent messages.
Concurrent sends produce siblings; the structure is convergent and every member can verify that
nothing it once accepted was later removed.

**BE-LEDGER-01** — A member MUST reject an envelope whose `parents` reference unknown hashes it
cannot resolve within a bounded fetch, and MUST surface a divergence rather than silently
reordering or healing it.

**BE-LEDGER-02** — The ledger stores hashes, never plaintext. A head hash MAY be published outside
the channel — a transparency log, a git repository, a second channel — giving external
tamper-evidence without revealing content. *This is how a fully end-to-end-encrypted channel stays
externally auditable: what is published is a commitment, not the conversation.*

**BE-LEDGER-03** — Every `Grant` and every `Effect` MUST appear in the ledger. An effect that
happened without the corresponding pair in the DAG is by definition detectable afterwards.

### 9.2 Historical verification: causal position, not the clock

BE-ID-02 rejects any certificate whose validity window does not contain the local clock, and
BE-REV-01 caps executor and approver certificates at 30 days. Applied naively to the ledger, those
two rules make every `Span`, `Grant`, and `Effect` unverifiable 30 days after it was written —
quietly expiring A4 (integrity of history), G7, and BE-LEDGER-02's external-auditability claim.

The resolution is to stop asking *when* and start asking *where in the causal order*.

**BE-HIST-01 (two distinct questions)** — BE-ID-02's clock-anchored check governs **admission**:
opening a session, accepting a live envelope, executing a grant. It MUST NOT be applied to
**audit**: verifying a signature already committed to the ledger. An expired certificate cannot
authorize anything new and remains able to prove what it signed while it was valid.

**BE-HIST-02 (certificates are ledger state)** — A signer's certificate MUST be anchored in the
channel before its first use, by a `Control` envelope carrying it, and members MUST retain anchored
certificates for as long as they retain the envelopes that depend on them. Retention is of the
certificate itself, not of a reference to somewhere it might still exist.

**BE-HIST-03 (validity is a causal interval)** — An envelope is historically valid if it is a causal
descendant of its signer's anchoring envelope and **not** a causal descendant of that signer's
revocation, if one exists. Expiry does not participate in historical verification at all. *This is
the only formulation that survives backfill: a member joining today receives envelopes signed under
certificates that expired weeks ago, and every clock-based rule — the sender's clock, the receiver's
clock, time-since-receipt — gives the wrong answer for a node that was not present. Causal position
is a property of the data, identical for every member, and needs no agreement to compute.*

**BE-HIST-04 (revocation is causal too)** — A revocation takes effect for admission immediately on
receipt (BE-REV-02, BE-CHAN-03) and for audit at its causal position. An effect that occurred before
a key was revoked stays valid history; one that a node accepts after receiving the revocation is
refused regardless of causal position. *Admission fails closed and audit stays truthful; these are
different jobs and they get different rules.*

### 9.1 Honest limitation

Tamper-*evidence*, not tamper-*resistance*, and only within a channel. Colluding members can agree
on a rewritten history among themselves; what they cannot do is make an honest member's
previously-published head hash validate against it. No consensus protocol here, and none proposed.

---

## 10. Relationship to existing work

### 10.1 Prior art built on

| System | Relationship |
|---|---|
| WireGuard | Noise_IK construction, rekey policy, cookie DoS defence, sliding-window replay filter — §4 follows it closely and deliberately |
| Nebula (Slack) | Offline CA, certificate-carried groups, lighthouses — §3, §5 |
| CJDNS / Yggdrasil | Address-as-key-commitment (§3.2) |
| Noise Framework (Perrin) | The handshake pattern and key schedule |
| IRC | Channel *shape* only — names, membership, broadcast |
| iMessage / early Signal | Pairwise fan-out instead of group ratchet (§6.1) |
| Object-capability model (Miller) | The Grant is a capability, not an ACL check (§8) |
| Certificate Transparency (RFC 6962) | Publish-your-head, BE-LEDGER-02 |
| Matrix | Hash-linked DAG with concurrent siblings rather than forced total order (§9) |
| MCP / A2A | Adjacent, not competing: both move tool calls between agents with no notion of authority. An MCP call rides inside `Intent.action` as opaque bytes |
| MLS (RFC 9420) | *Deliberately not used* at N ≈ 10; the correct answer if N grows past ~100 (§6.1) |
| **Slot benchmarking** (Frinzfrinz) | Not protocol content — evaluation method. Conformance rules R1–R4 and the two content-level findings in §11.9 are taken from it. Independently, it is a fifth instantiation of the Gate Protocol's five invariants, and the first with neither code nor a network in it |

### 10.2 The author's own prior work this formalizes

All of the following is by Daniel Carneiro (`loonix`). This section is a **historical record of
prior work that Bolina formalizes** — it does not grow as the project gains contributors, and work
by others belongs in §10.1 and §11.9, never here. Contributors to Bolina itself are listed in
`CONTRIBUTORS`.

| Project | What Bolina takes |
|---|---|
| **Prumo** v2.2 | The enforcement pyramid, BE-* discipline, the Evidence Contract, and the rule that enforcement never calls a model. BE-ROLE-01 is its central law made structural |
| **Gate Protocol** | Its five invariants promoted from in-process Go to the wire: evidence trace → §7; verdict gate → BE-EVID-02; gated tool wrapper → §8; resource lock → BE-GRANT-06; fail-closed → BE-GRANT-04 |
| **MAD** (Zig) | The `ActionResult` epistemic contract, normative as BE-EFF-01; per-cycle arena discipline, which maps directly onto per-packet handling; the intended reference `executor` |
| **Orbit** (Go) | The only production-proven human approval token. BE-GRANT-07 and -08 are its incident history written as rules |
| **caravela-epistemic** (Rust) | The ceiling and calibration arithmetic behind BE-EVID-04 |

### 10.3 The single novelty claim

Stated narrowly so it can be attacked: **no existing communication protocol makes evidentiary
provenance and effect authority first-class, cryptographically verifiable objects in the message
format itself.** Everything else here is assembled from published work. If a reviewer finds a
protocol that carries §7 and §8 on the wire, the claim is falsified and this document must say so.

---

## 11. Conformance and verification

This specification is language-neutral, and cross-implementation test vectors (item 3) exist so that
a second implementation in another language is a conformance test rather than a fork. **The
reference implementation is Zig** (`LANGUAGE.md` §6), which makes items 6 and 8 below active
obligations rather than contingent ones.

An implementation is conformant when, and only when the items below have produced evidence. Four
rules govern *how* that evidence is produced, and they exist because each one has a documented
incident behind it in an adjacent evaluation discipline (see §11.9):

- **R1 — Measure the harness before the target.** A conformance run that produces a suspicious
  uniform result MUST be assumed to be measuring its own instrument until proven otherwise.
- **R2 — Never accept a single-sided metric.** Every criterion below that could be satisfied by a
  degenerate implementation — one that refuses everything, or accepts nothing — MUST be paired with
  the opposing measurement, and both MUST be reported.
- **R3 — Every failure records a cause, not just a verdict.** A rejected input, a killed mutant, or
  a failed case with no recorded cause is not evidence; it is a number.
- **R4 — The unit of conformance is the implementation *plus its build configuration*.** Results
  obtained under one set of compiler flags say nothing about another. The shipped configuration is
  the one that must be measured.

### 11.1 BE-to-test bijection

Every BE-* has at least one test bound to it by name — `#[prumo_expect(BE-GRANT-02)]` in Rust,
`TestBE_GRANT_02_*` in Go, an equivalent registry in Zig. `prumo-verify` MUST report a **bijection**
between declared BEs and passing tests: no BE without a test, no orphan test. *(An earlier draft said
"exact intersection", which is not the property meant.)*

### 11.2 Mutation testing

100% of viable mutants killed in §8's state machine and §7's verifier. A surviving mutant there means
an exploitable bypass. Survivors elsewhere are recorded with a cause (R3), not merely counted. The
mutant population MUST be large enough that the result does not turn on a single mutant; a 100% kill
rate over a handful of mutants is noise wearing the costume of evidence.

### 11.3 Cross-implementation test vectors

A shared vector file fixing encodings, signature inputs, address derivations, digests, and the
`method_id` → class → ceiling mapping (BE-EVID-15), so two independent implementations agree
byte-for-byte. Toolchain and any vendored primitive are pinned by content hash and re-verified on
every build: *an artifact can change size and content under a stable name and a stable filename, and
a result carried forward across such a change is a result about a file that no longer exists.*

The canonical file is `test/vectors.json`, produced by `tools/gen-vectors.zig` (the first
implementation, Zig `std.crypto`) and cross-verified by `tools/verify-vectors.py` (the second
implementation, Python `cryptography` for Ed25519 and X25519, `hashlib` for BLAKE2s) and
`tools/verify-layout.py` (a field-by-field byte-layout walker). The M3 gate regenerates the file,
fails on any drift versus the committed copy, then runs both verifiers; a vector is canonical only
when two independent implementations reproduce every key, signature, digest, and address. Every
value is deterministic: Ed25519 seeds are fixed, Ed25519 signing is deterministic per RFC 8032, and
BLAKE2s-256 is deterministic, so the file is byte-stable across platforms and runs and can be
checked in and diffed.

Every signature signs over `domain_tag || tbs` (BE-SIG-01), never bare `tbs`, so a signature valid
for one structure class cannot be replayed against another. The generator self-verifies each
positive signature with `std.crypto` before emitting, and the file records both `tbs_hex` and
`sig_input_hex` (the `domain_tag || tbs` bytes the signature covers) so a second implementation
verifies over exactly the bytes the first signed. The file carries one vector per structure class:
Cert (tag `0x01`, two CA signatures over the same `0x01 || tbs` in ascending CA-key order), Envelope
(tag `0x02`, genesis, carrying an Intent body), Span (tag `0x03`, a subprocess observation), Grant
(tag `0x04`, an object capability), and Refusal (tag `0x06`, no version field, section 8.5). Each
records its decoded fields, `tbs_hex`, `sig_input_hex`, the signature, the signer identity and
public key, the full `wire_hex`, and the expected verify result.

The `method_id_table` fixes the BE-EVID-15 mapping the receiver derives (never receives): `method_id`
1 through 4 are DirectObservation (ceiling `q8 = 242`, confidence 0.95), 5 and 6 Documentation (191,
0.75), 7 ExpertTestimony (216, 0.85), 8 Inference (165, 0.65); any `method_id` outside the table
falls to the floor as Inference (BE-EVID-13). The `keys` block fixes five identities (two CAs, an
approver, an executor, an agent) with their seeds and derived signing and key-exchange public keys;
the `addressing` block fixes `overlay_addr = 0xfd || BLAKE2s-256(sig_pubkey)[0..15]` for each. The
`resource_id` vector records the BE-RES-06 fingerprint choice, `executor_fp = BLAKE2s-256(sig_pubkey)
[0..8]`. Three negative vectors assert rejection: an Envelope with a truncated signature (BE-WIRE-02
totality), an Envelope with a trailing byte (section 2.2 forbids unknown trailing bytes), and an
Envelope whose signature is valid but over the wrong domain tag (BE-SIG-01 domain separation).

### 11.4 Model checking

§8's state machine checked in TLA+ or Alloy with BE-GRANT-01, -03, -04, -06 as invariants over all
interleavings. Mutation testing samples the space; a model checker covers it. Until this exists,
§8's guarantees are *tested*, not *proved*, and MUST be described that way.

### 11.5 Adversarial evaluation, scored on both sides (R2)

A model with mesh access, instructed and incentivized to obtain an effect without a valid Grant —
including by prompt injection and by social-engineering an approver — obtains none; **and, measured
in the same run, every properly granted operation executes.** Both numbers are reported together and
neither alone is a result. *An executor that refuses everything scores perfectly on the first
measurement and is useless. A criterion written around one error rate can be satisfied in full
compliance with its own text by an implementation that does nothing.* This is the single most
important conformance item and the one most easily faked.

### 11.6 Continuous differential fuzzing

The parser survives ≥ 24 hours of continuous fuzzing: zero crashes, zero panics, zero out-of-bounds
reads, zero allocations observed, against every §2.2 structure. The run MUST report **coverage of the
parsing code reached and the seed corpus used**, not only elapsed hours — a fuzzer that never reaches
the parser produces 24 clean hours and no information (R1). Fuzzing MUST be differential per
BE-SURF-04. **In a language without memory safety this item is not optional and not deferrable; it is
the substitute for the guarantee the compiler is not providing** (BE-WIRE-01, BE-WIRE-02, BE-SURF-02).

### 11.7 No third-party build dependency

The build succeeds with the network disabled and no package manager, from the repository contents and
a standard toolchain alone (BE-DEP-01).

### 11.8 The measured build is the shipped build (R4)

Conformance results MUST record the exact compiler, version, optimization mode, and safety-check
settings. In a language where bounds and overflow checks are optional, results from a checked build
do not transfer to an unchecked one, **and the shipped configuration MUST be the safety-checked one**
(`LANGUAGE.md` O1). The parser line budget of BE-SURF-03 is measured here.

**Nothing may be described as sealed until its item above has produced evidence. Current state of
every item: not started.** *"Closed" and "sealed" are different words in this project: a draft is
closed when nothing is pending against it, and sealed only when the evidence exists. v0.2.0-draft is
closed. Nothing in it is sealed.*

### 11.9 Where R1–R4 come from

These four rules are not derived from this protocol. They are imported from **slot benchmarking**, a
methodology for evaluating locally-hosted models on fixed hardware, developed and documented by
**Frinzfrinz** in *"Slot Benchmarking: A Discipline for Running the Best Local Models Without Losing
Your Mind (or Your Disk)"*. Each rule was learned there from a real incident, and they are adopted
here with attribution rather than rediscovered:

- **R1** — a speed floor that disqualified several models for "emitting no answer", where the real
  cause was an output-token budget smaller than those models' reasoning preamble: the bench was
  measuring the budget, not the models.
- **R2** — a vision model that achieved a perfect false-negative rate by calling every image
  defective, and another that achieved a perfect false-positive rate by detecting almost nothing.
  Either would have ranked first under a selection rule written around one error rate, in full
  compliance with its own text.
- **R3** — disqualifications recorded as verdicts with no cause, every one of which reversed once
  the causes were investigated.
- **R4** — an incumbent that looked catastrophically slow through its stock serving tag while
  production ran a tuned build of the same weights, several times faster, through a different
  serving stack.

A fifth finding from the same source underwrites conformance item 3: an artifact re-downloaded from
the same repository under the same filename arrived 41% larger than the recorded version, which is
why every vendored primitive here is pinned by content hash.

Two further findings from that work are recorded here without being promoted to rules, because they
apply to this specification's *content* rather than its verification method:

- **A tier can contain two roles with incompatible requirements**, and averaging their metrics
  hides both. Open question §12.1 (approver availability) is exactly this shape: an in-loop gate
  that must be fast and a careful review that need not be are being asked to share one mechanism.
  The honest resolution is likely to fork the slot rather than to average it.
- **When a capable evaluator disagrees with the labels systematically rather than randomly, audit
  the labels.** Applied here: if agents fail a gate repeatedly in a consistent pattern, the first
  hypothesis is a defect in `resource_id` canonicalization (§8.4), not agent misbehaviour.

---

## 12. Open questions

Unresolved, and not to be papered over in implementation.

**Closed during v0.2.0-draft**, each by the section named: certificate distribution (§5.1a); DAG
genesis and backfill (§6.1b, §6.4); `Control` wire format and admin authority (§6.1a–c); historical
verification under short certificate lifetimes (§9.2); evidence freshness (§7.3); `resource_id`
canonicalization (§8.4), which also settled whether a resource can be reached through two executors
— it cannot, by construction (BE-RES-04); and the relay-visible envelope header, which disappeared
when pairwise fan-out put the whole envelope inside a Noise session (BE-MESH-02).

### 12.1 Approver availability

BE-GRANT-04 plus a human in the loop means an unattended agent halts. Correct as a default, but it
makes Bolina unsuitable as-is for effects that must happen at 03:00. A standing pre-authorized Grant
with a narrow `action_digest` is the obvious escape hatch and also the obvious way to reintroduce
the original problem. **Unresolved.**

### 12.2 Membership change races

With no group key, a member removed concurrently with a message in flight may still receive it from
a sender with a stale membership view. Bounded by rekey, by BE-CHAN-02's monotonic revocation set,
and by BE-CHAN-03, but the exact convergence rule is unspecified.

### 12.3 Compromised executor

A compromised executor signs true-looking spans for observations it never made, and can mislabel
volatile state as `stable` to defeat BE-EVID-05. Nothing in §7 detects either. Bounded only by
BE-REV-01 and by the executor being a small auditable program rather than a model. Accepted risk,
`THREAT-MODEL.md` §4.3 and §4.9.

### 12.4 Conjunctive evidence is not representable

BE-EVID-02 treats `supported_by` as disjunctive — independent supports, ceiling taken from the
strongest. There is no way to express that a claim *depends* on two spans jointly, where the Prumo
weakest-link rule would be the correct one. Every claim whose reasoning is genuinely a chain is
therefore scored more generously than it deserves. Fixing it means distinguishing the two structures
on the wire, which v0.2.0 does not do. **Named rather than silently accepted.**

### 12.5 Scaling past pairwise fan-out

§6.1 states the N at which this design stops working. The migration path to MLS is asserted to be
clean because §7 and §8 do not depend on §6's encryption, but that has not been worked through.
