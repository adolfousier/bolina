# Bolina — Threat Model

**Version:** 0.2.0-draft · **Companion to:** `SPEC.md` v0.2.0-draft · **Date:** 2026-08-05

> **Epistemic status.** This document declares which adversaries the protocol is *designed* to
> resist. It is not a security assessment, because there is nothing built to assess. No claim
> below has been validated by analysis, review, or attack. Read every "resists" as "is intended
> to resist, pending §7".

---

## 1. Assets

What an attacker wants, in descending order of what it would cost to lose:

| # | Asset | Loss looks like |
|---|---|---|
| A1 | **Authority to cause effects** | A production deploy, a database write, a CMS publish that no human approved |
| A2 | **Integrity of the evidence record** | A false claim carrying signed-looking backing; a true claim discarded |
| A3 | **Confidentiality of channel content** | Business strategy, credentials, customer data read by a non-member |
| A4 | **Integrity of channel history** | A past decision silently rewritten; an effect with no trace |
| A5 | **Availability** | The mesh partitioned; approvals unable to reach executors |

The ordering matters and is deliberate. **A1 above A3** is the defining choice of this protocol: a
system that keeps perfect secrets while an agent deploys unapproved code has failed at the thing
it exists for. Most messaging threat models invert this because their senders are human.

---

## 2. Adversaries

### 2.1 Adversary M — the model itself *(primary)*

**The adversary Bolina exists for, and the one no existing communication protocol models.**

A participating agent. It holds a valid certificate, a valid key, and legitimate channel
membership. It is *not assumed malicious* — it is assumed **unreliable in specific, empirically
observed ways**:

| Capability | Empirical basis |
|---|---|
| States a categorical verdict with no verification behind it | Orbit incidents #1–#5, 2026-07-01..06 |
| Satisfies a confirmation flag without honouring its purpose | Orbit incident #5 — `confirm=true` set, mandatory warning never sent |
| Misattributes cause and asserts the misattribution confidently | Orbit incident #4 — "must be cache" for a template it had itself overwritten |
| Acts on injected instructions from content it processes | Structural: any agent reading untrusted input |
| Believes and repeats a poisoned memory | Orbit, 2026-07-02 — sibling sessions produced a false "security incident" |

Note the distinction from a classical insider: Adversary M does **not need intent**. Every entry
above happened without deception being attempted. A threat model that only defends against
malicious senders will not catch any of them.

**Capabilities granted to M in analysis:** may send any envelope its roles permit, at any time,
with any content, including well-formed messages that are entirely false. May be prompt-injected
into pursuing an attacker's goal. May coordinate with other agents on the mesh. May read
everything in the channels it belongs to.

**Capabilities denied to M by construction:** cannot sign a `Span` (BE-ROLE-02, BE-EVID-01);
cannot sign a `Grant` (BE-ROLE-01); cannot raise the effective confidence of its own claims
(BE-EVID-02, receiver recomputes); cannot choose the identity of the resource it acts on
(BE-RES-01); and **cannot cause an effect without a human approval bound to those exact bytes,
that exact intent, and that exact resource** (BE-GRANT-01..08).

That last clause is the honest form. An earlier draft read "cannot cause an effect", which §4.1 of
this same document contradicts two pages later: M *can* cause an effect by getting a human to
approve one. BE-GRANT-07 and -08 are interface and key-custody rules, not construction, and the
protocol's guarantee ends where the human's attention begins.

**Defences:**

| Threat | Defence | Residual |
|---|---|---|
| Unbacked verdict | Receiver recomputes confidence against signed spans, from the strongest support (BE-EVID-02), and an unbacked claim scores **0.00** rather than sharing a floor with genuine inference (BE-EVID-02a) | Marking is not blocking. A human can still act on a claim the protocol scores at zero |
| Evidence about the wrong thing | `subject` ↔ `resource_id` matching on canonical forms (BE-EVID-03, BE-RES-01) | The executor's resource set must actually distinguish what it claims to distinguish |
| Evidence that was true and no longer is | Causal supersession: a volatile span stops supporting once an `Effect` on the same resource lands between it and the claim (BE-EVID-05) | An executor that mislabels volatile state as `stable` — §4.9 |
| Inflating a claim by misclassifying its evidence | The class is derived by the receiver from `method_id`, which is a compile-time constant of the executor's code path; no interface accepts a class (BE-EVID-11, -12, -13) | An executor whose code path is itself mislabelled — caught by reading the source once, not by trusting each call |
| Asserting a claim and blaming the network for missing proof | Spans travel inline with the claim; there is no fetch path (BE-EVID-08). Missing proof is attributable to the sender, not to delivery (BE-EVID-09) | None known at this layer |
| Self-approval | Approver key never issued to an agent certificate (BE-ROLE-01), quorum CA for approver certs (BE-CA-01) | A human who approves without reading. See §4.1 |
| Approval for X, execute Y | Digests are always recomputed, never transmitted (BE-BODY-02); byte-exact binding (BE-GRANT-02); the approval UI recomputes from the bytes it displays (BE-GRANT-07) | The human who does not read the bytes. §4.1 |
| Replay of an old approval | Single-use nonce ledger, durably committed before the effect and surviving restart (BE-GRANT-01); triple expiry including a per-grant — not per-delivery — receipt budget (BE-GRANT-05) | An effect interrupted mid-execution has an unknown outcome; BE-GRANT-01a reports it as unknown rather than retrying it |
| Concurrent agents racing one resource | Reject-don't-queue exclusivity (BE-GRANT-06) | Cross-executor races on the *same underlying* resource under two `resource_id`s — open question |
| Prompt injection acquiring authority | Injection can make M *ask* for anything; it cannot make M *able* to do anything. The approval is a separate key held by a separate party | Injection that makes a plausible-looking request a human approves. **This is the residual risk of the whole design** — see §4.1 |

### 2.2 Adversary N — the network (Dolev–Yao)

Full control of the wire: observe, drop, delay, reorder, replay, inject, and impersonate any
endpoint address.

| Threat | Defence |
|---|---|
| MITM on session setup | Noise_IK mutual static-key authentication, plus an Ed25519 certificate signature over the Noise handshake hash binding key to identity (BE-TR-01); the address is a key commitment, so there is no resolvable name to poison (BE-ID-01) |
| Envelope forgery | Ed25519 over the transmitted bytes, no re-encoding step (BE-ENV-02, BE-WIRE-03) |
| Replay | Sliding-window anti-replay at the transport (BE-TR-03) and monotonic `seq` at the channel (BE-ENV-04); grant nonce ledger (BE-GRANT-01). Both layers are required — they defend against different attackers |
| Reorder / truncate a channel | `parents` hash-linked DAG, divergence surfaced not silently healed (BE-LEDGER-01) |
| Read content | ChaCha20-Poly1305 under pairwise Noise sessions; every channel message travels inside one |
| Read content later, after key theft | Noise ephemeral handshake keys plus mandatory rekey at 120 s (BE-TR-02) |
| Handshake flood / CPU exhaustion | Cookie MAC before any X25519 operation (BE-TR-04) |
| Memory exhaustion via fragmentation | Per-peer reassembly limits **and** node-level ceilings on concurrent sessions and total reassembly memory (BE-TR-05). Per-peer limits alone were not a bound: total memory was per-peer × unbounded peers, worst on the lighthouses and relays that face the most |
| Malformed packet | Non-recursive, non-allocating, total parser (BE-WIRE-01, -02), verified by fuzzing (§11.6) |
| Hostile lighthouse misdirecting connections | Lighthouse is availability-only, never authority (BE-MESH-01) |
| Hostile relay | Sees only Noise transport packets: no key material, no message type, no envelope header (BE-MESH-02). Learns sender, recipient, size, time — accepted, §4.4 |

### 2.3 Adversary C — a compromised node

Full control of one node including its private key.

| Compromised role | Consequence | Containment |
|---|---|---|
| `participant` | Reads channels it belongs to; sends messages as that identity | Channel scoping; removal is clean because there is no shared group key to withdraw — the other members simply stop fanning out to it (SPEC §6.1); short certificate lifetimes (BE-REV-01) |
| `agent` | Same as Adversary M, but with intent | Identical structural limits — this is why M is modelled as the baseline rather than the worst case |
| `executor` | **Signs false spans; performs real effects it holds Grants for** | Weakly contained. See §4.3 |
| `approver` | **Mints authority at will** | Not contained. See §4.2 |
| `lighthouse` / `relay` | Denial of service, traffic analysis | Structurally cannot break confidentiality or authenticity |

### 2.4 Adversary A — a compromised CA

Can mint certificates, therefore identities.

**Defences:** the CA key is offline and never on a mesh node (SPEC §3.3). Minting an `approver`
certificate requires a quorum of ≥2 CA keys (BE-CA-01), **and every node verifies that quorum on
every use** (BE-ID-04, with the certificate carrying its signature list on the wire), so one stolen
CA key yields identities but not approval authority.

*The wire format previously carried a single `(ca_key, ca_sig)` pair, which made BE-CA-01
unverifiable by any peer — a claim about issuance procedure rather than a protocol property — and
this paragraph asserted a containment that did not exist.*

**Residual:** one stolen CA key still yields valid `agent`, `participant`, and `executor`
identities, and an `executor` certificate is enough to sign false evidence. This is a real gap,
mitigated only by BE-REV-01's 30-day ceiling on executor certificates. A transparency log for
issuance is the obvious next control and is **not** specified in v0.1.0.

### 2.5 Adversary H — a hostile human participant

Holds a legitimate `approver` key and approves something harmful.

**Explicitly out of scope.** Bolina guarantees that an effect had a named human's key behind it,
at a specific time, bound to specific bytes, recorded in a chain. It does not and cannot
guarantee that the human was right. Accountability, not correctness.

---

## 3. Security goals

Stated so that each is falsifiable.

| # | Goal | Falsified by |
|---|---|---|
| G1 | No effect occurs at a conformant executor without a valid `Grant` signed by an `approver` key | Any execution path reaching `EXECUTING` without grant verification |
| G2 | An `agent` certificate holder cannot produce a signature that any conformant verifier accepts as a `Span` or a `Grant` | Any accepted span/grant traceable to an agent key |
| G3 | A claim's presented confidence never exceeds the ceiling of its weakest matching supporting span | A rendered claim above ceiling |
| G4 | A `Grant` authorizes exactly one execution, of exactly one action, at exactly one executor | Any second execution from one `grant_id`, or execution of bytes ≠ `action_digest` |
| G5 | A restart of an executor cannot resurrect a pending approval | Any `PENDING` surviving process death |
| G6 | Channel content is unreadable by non-members, including relays and lighthouses | Any plaintext recoverable off-path |
| G7 | An effect that occurred is always discoverable in the channel ledger | An `Effect` with no chained `Grant`/`Effect` pair |
| G8 | An off-path observer cannot forge, alter, or replay any envelope | Any accepted forged envelope |

---

## 4. Accepted risks

Named, not hidden. Each of these is a place where the protocol stops.

### 4.1 The human who approves without reading *(the dominant residual risk)*

Every guarantee in §8 of the spec funnels authority to a human pressing a button. BE-GRANT-07
forces the *interface* to render the action from the `Intent` rather than from an agent's summary,
which removes the model from the description of what is being approved. It cannot remove approval
fatigue.

If Bolina generates enough approval requests that humans approve reflexively, it has moved the
failure rather than fixed it — and it will have done so while feeling safer, which is worse than
the original state. **This is the risk most likely to actually materialize.** Mitigation is
operational, not cryptographic: keep the number of gated actions small enough that each approval
is read. An implementation SHOULD measure approval latency and flag when it collapses toward zero.

### 4.2 Approver key compromise

An attacker with an approver private key has full authority within that key's scope. Mitigations
are conventional and outside the protocol: hardware-backed keys (BE-ROLE-03), short certificate
lifetimes (BE-REV-01), and quorum issuance (BE-CA-01). Bolina does not implement threshold
signatures in v0.1.0; multi-party approval for high-consequence actions is a candidate for v0.2.

### 4.3 Executor compromise

A compromised executor signs spans for observations it never made, and §7 has no mechanism to
detect it — the entire evidence layer roots in trusting executors to report truthfully. This is
mitigated by *what an executor is*: a small, auditable, model-free program (MAD is ~a few thousand
lines of Zig with sealed memory and subprocess gates), not a language model. The trust is placed
in the component that can be read end-to-end by a person.

Candidate future control: independent corroboration, where a claim about a high-consequence
resource requires matching spans from two executors. Not specified in v0.1.0.

### 4.4 Traffic analysis and relay metadata

A global passive observer learns who talks to whom and when. Packet sizes and timing leak activity.
Bolina is not an anonymity system (SPEC §0.2) and adds no cover traffic or mixing.

Pairwise fan-out makes this specifically worse in one way that must be stated: a channel message
appears on the wire as N−1 separate transmissions, so an observer counting packets learns the
approximate size of a channel. A relay carrying store-and-forward traffic (BE-MESH-03) learns
sender, recipient, size, and time for everything it carries — content and message type stay opaque
to it, but the social graph does not. If a relay is operated by someone outside the trust set, that
graph is exposed to them.

### 4.5 Availability

BE-GRANT-04 (fail-closed on restart) and BE-GRANT-06 (reject, don't queue) both trade availability
for safety, deliberately. A flapping executor makes forward progress impossible. That is the
intended failure direction; it is still a failure, and operators should expect it.

### 4.6 Implementation-language memory safety — ACTIVE

**The reference implementation is Zig (`LANGUAGE.md` §6, decided 2026-08-05). This risk is therefore
live, not conditional, and it is the largest one addressed in `SPEC.md` only by conformance items
6 and 8 rather than by any protocol mechanism.**

Bolina's daemon parses attacker-controlled bytes from an unauthenticated UDP socket. In a language
without memory safety, that is the classic setting for use-after-free and out-of-bounds bugs — a
failure class that **BE-\* invariants and mutation testing cannot detect by construction**, because
they exercise logic, and this class is not a logic error. An implementation could satisfy every
invariant in the specification and still be remotely exploitable.

The specification's structural answers — a non-recursive parser, no heap allocation during parse,
fixed field order, hard length maxima, and `Intent.action` treated as opaque bytes (BE-DEP-02,
BE-WIRE-01, BE-WIRE-02, BE-BODY-01) — exist largely to shrink this surface to something a person can
read in full. They shrink it; they do not remove it.

Because the daemon is written in a language without memory safety, conformance item §11.6
(continuous fuzzing, zero crashes, zero out-of-bounds reads) **is the substitute for the guarantee
the compiler is not giving**. It is mandatory and it is a merge gate, not a milestone; and
`ReleaseSafe` — with bounds and overflow checks on — is the shipped configuration, never
`ReleaseFast`. The four obligations are binding and enumerated in `LANGUAGE.md` §6.1.

**Honest statement of where this leaves the threat model:** this risk is mitigated to the level of
"small, non-recursive, non-allocating, continuously fuzzed parser written by one person who can read
all of it". That is a real and defensible position. It is not equivalent to a compiler-enforced
guarantee, and this document does not claim it is.

**Coverage measurement is hand-instrumented, not native.** The Zig toolchain's `-ffuzz` coverage is
consumed only by a WebSocket UI and emits no script-readable report, so the §11.6 coverage number is
produced by hand-placed branch counters in `src/coverage.zig` rather than a compiler-generated edge
map. The current result, 11 of 11 enumerated parser branches reached over a bounded 4,000,000-input
run, is real but weaker than native coverage in two ways: the branch set is enumerated by hand, so
an uncounted branch is invisible to this measurement; and the counters track branch reach, not edge
or path frequency. By how much this weakens the fuzzing substitute against a native instrument is
itself unknown. The follow-up is to re-run on the first stable toolchain pin that exposes native
coverage output, filed as #11. This does not reopen the decision: the crash half of §11.6 (zero
out-of-bounds reads over 7.3B inputs) is independent of coverage instrumentation and held throughout.

### 4.10 Panic-as-denial-of-service, and the safety inversion — ACTIVE

`ReleaseSafe` prevents memory corruption by aborting on an out-of-bounds read or an overflow. In a
network daemon an abort is a **remote crash**, and this protocol makes a crash consequential:
BE-GRANT-04 collapses every pending approval to `EXPIRED` on restart.

So an attacker who can reach any panic path — **without corrupting anything, without escalating,
without even authenticating if the path is pre-authentication** — obtains selective denial of
approval: crash the executor whenever a human is about to approve, and nothing is ever approved. The
mechanism designed as the last line of defence against memory corruption becomes the lever that
defeats the fail-closed property. A local safety guarantee inverted into a structural attack.

This is the sharpest interaction between the language choice and the protocol design, and it existed
undocumented from the moment Zig was decided.

**Mitigations:** BE-SURF-01 removes variable-length parsing from unauthenticated input, so reaching
a parser path at all now requires a valid certificate and a bound session — which makes the attacker
attributable and revocable. BE-SURF-02 forbids relying on the abort for bounds control, so malformed
input yields a graceful rejection rather than a crash. BE-SURF-03 and -04 shrink and test the surface
where such a path could hide.

**Residual:** none of this proves no panic path exists. The residual is bounded by §11.6 finding
them and by BE-REV-02 revoking whoever exercises them, and it is one more reason §11.6 is a merge
gate rather than a milestone.

### 4.9 Mislabelled volatility

BE-EVID-05 invalidates stale evidence by causal supersession, and it acts only on spans the executor
marked `volatile`. An executor that marks genuinely volatile state as `stable` — through a bug or
through compromise — produces evidence that never expires and never gets superseded, which is the
staleness attack with a signature on it.

Containment is the same as §4.3's and no stronger: `volatility` is chosen by a small, auditable,
model-free program, not by the agent making the claim, and BE-EVID-06 makes anything unrecognized
degrade to `volatile`. There is no protocol mechanism that detects a lying executor here, and none
is proposed.

### 4.7 Denial by lighthouse

Lighthouses cannot break authenticity but can withhold endpoints. A partitioned mesh with no
lighthouse reachable degrades to statically configured peers.

### 4.8 Zero dependencies as a security posture — and where it is not literal

The zero-dependency constraint (SPEC §0.3) removes the package-manager supply chain and keeps the
protocol code auditable by one person. Two consequences, one of which was previously stated wrongly
in this document.

**What is genuinely ours.** The Noise handshake, the anti-replay window, the cookie logic, the
parser, and both new layers are written here. When a flaw is found in any of them, nobody sends a
patch — there is no upstream and every fix is ours to find and write. That is a real cost, accepted
deliberately. It is affordable because the constructions are small, frozen, and publicly analysed;
it would not be affordable for TLS or MLS, which is one reason neither is used.

**What is not ours, and the earlier draft claimed was.** The four primitives come from Zig's
`std.crypto` (`LANGUAGE.md` §6). They are not written here, not vendored here, not hash-pinned here,
and not covered by BE-DEP-01's "MUST NOT be modified" — they are third-party code with a very active
upstream. Earlier text in this document asserted that the primitives were vendored reference
implementations and that there was "no upstream" for anything. Both were false once Zig was chosen,
and the constant-time assumption (T1) rests on code the author neither wrote nor reviewed.

**Consequence for the supply chain.** SPEC §11.3's hash-pinning control is vacuous for the reference
implementation, since there is nothing vendored to pin. The finding that motivated it — an artifact
41% larger under an unchanged name (§11.9) — applies just as well to a compiler toolchain, so the
control moves rather than disappears: **the Zig release archive is pinned and verified by hash, and
the `std.crypto` revision is recorded with every conformance result.** `LANGUAGE.md` O4 pins the
version for *reporting*; this makes it an integrity control as well.

---

## 5. Non-goals

Stated so nobody builds on an assumption the protocol never made.

1. **Anonymity / unlinkability.** Identities are stable, long-lived, and deliberately attributable.
2. **Deniability.** The opposite: Bolina exists to make effects attributable. Ed25519 signatures on
   `Grant` and `Effect` are non-repudiable *by design*. Note the tension with human chat in the
   same protocol — `Utterance` signatures are equally non-repudiable, which is a different privacy
   posture from Signal's, and users must be told.
3. **Resistance to a compromised endpoint's own screen.** Malware on an approver's laptop can see
   what they see.
4. **Byzantine consensus.** The ledger is tamper-evident, not tamper-resistant (SPEC §9.1).
5. **Protection against a wrong-but-authorized decision.** §2.5.
6. **Novel cryptography.** Any deviation from SPEC §2's four-primitive table is a defect, not a
   feature. The zero-dependency constraint applies to *libraries*; it never licenses inventing a
   construction, and it does not license writing a primitive from scratch either (SPEC §0.3).
7. **Censorship resistance.** Not a design target.

---

## 6. Trust assumptions

Bolina's guarantees hold only if all of these hold. Each is a place the whole thing rests.

| # | Assumption | If false |
|---|---|---|
| T0 | The four primitives (Ed25519, X25519, ChaCha20-Poly1305, BLAKE2s) and the Noise_IK construction are sound | Everything fails; not Bolina-specific |
| T1 | Zig's `std.crypto` implementations of those four are correct and constant-time with respect to secret data | Key recovery by timing. **This is the one place the zero-dependency posture is a statement about someone else's code**: the reference implementation writes none of the four and vendors none of them — they come from the language's standard library, with an upstream, a release cadence, and a review process none of which are ours. §4.8 |
| T2 | CA private keys are offline and uncompromised | §2.4 |
| T3 | Approver private keys are held only by the humans they name | §4.2 |
| T4 | Executors report observations truthfully | §4.3 |
| T5 | The approving human reads what BE-GRANT-07 renders | §4.1 |
| T6 | Implementations are conformant | The spec constrains nothing on its own |
| T7 | The local clock is not adversarially controlled *at the verifier* | BE-GRANT-05's second condition (time-since-receipt) is what limits this; it bounds but does not eliminate the dependency |

**T4 and T5 are the load-bearing ones.** They are also the two that cryptography cannot help with,
which is why they are named here rather than buried in a table.

---

## 7. How this document gets validated

It has not been. In order:

1. **Internal red team of §8's state machine** — a written attempt to reach `EXECUTING` without a
   valid Grant, enumerating every in-edge. Before any implementation.
2. **Model checking** — BE-GRANT-01/-03/-04/-06 as TLA+ invariants over all interleavings
   (SPEC §11.4).
3. **Adversarial evaluation with a real model, scored on both sides** — a model with mesh access,
   instructed and incentivized to obtain an effect without a Grant, including via prompt injection
   and via social-engineering an approver. Failure to obtain one is the only evidence that matters
   for G1 — **but it MUST be measured together with the rate at which properly granted operations
   succeed**, because an executor that refuses everything scores perfectly on the first number and
   is useless. Either figure alone is not a result (SPEC §11.5, rule R2 — after Frinzfrinz, slot
   benchmarking; see SPEC §11.9).
4. **External cryptographic review** of the composition — the primitives are standard, their
   *composition* here is not, and composition is where protocols fail.
5. **Public draft.** Nothing in this design benefits from being unpublished, and §10.3 of the spec
   makes a novelty claim that should be exposed to falsification early.

Until item 3 produces a result, the correct description of Bolina's central guarantee is
**"specified"** — not "proved", not "enforced", not "secure".
