# Bolina — External Cryptographic Review: Engagement Package

**Gate:** D-092 G1 (external adversarial review) · **Frozen target:** `v0.6.0` (commit `c5c69a2`) · **Prepared:** 2026-08-24 · **For:** the independent reviewer · **Contact/owner:** Daniel (`@iamloonix`)

This document is self-contained: it defines what Bolina is, what is under review, what independence means for this engagement, how to build and verify everything yourself, and what deliverable closes the gate.

---

## 1. The ask

An independent security review of the **composition** of the Bolina protocol and its reference implementation, run against a frozen, sealed release. Not a code-style audit. Not a penetration test of a deployment. A composition review: do these standard primitives, combined this way, actually deliver the authority-delegation guarantees the specification claims?

The gate this review satisfies is defined in `docs/DECISION-LOG.md` entry **D-092** (G1). It closes when every finding you produce is dispositioned — fixed in code with a regression test, or explicitly accepted and recorded by name in the threat model / decision log. "The review happened" closes nothing.

## 2. What Bolina is

Bolina is an intent-based authority delegation protocol for small meshes of mutually distrusting nodes. One node (agent) asks to perform a scoped action on a resource; another (executor) admits it only if a verifiable grant chain authorizes it; every executed grant is committed to a durable single-use ledger before its effect runs, so crashes cannot cause double execution.

Implementation facts:

| Fact | Value |
|---|---|
| Language | Zig 0.16, ~4,000 lines of `src/`, zero third-party dependencies (BE-DEP-01) |
| Transport | UDP, Noise_IK handshake, ChaCha20-Poly1305 sessions |
| Identity | Ed25519 certificates signed by a 2-of-2 CA quorum; cert carries both Ed25519 sig key and X25519 Noise static |
| Binding | Post-handshake mutual binding frame inside the encrypted session: cert + Ed25519 signature over the Noise handshake hash (BE-TR-01/01a) |
| Grants | 14-check verification chain (BE-GRANT-03), scope binding via BLAKE2s ancestor walk over cert-carried scope IDs |
| Durability | Append-only grant ledger, atomic-rename prune, exclusive flock at open (MD3), crash → `interrupted` effect, never silent re-execution |
| Control plane | Optional localhost HTTP/1.1 + JSON facade over the same dispatch machinery (no god-mode path), bearer token auth, fail-closed |
| CA tooling | Offline CLI in the same binary (`bolina ca init/issue/revoke`); revocation carries subject-expiry (BE-CTRL-03) |

## 3. Frozen target and reproduction

Review **this exact tree**, not `main` in motion (D-092 requirement):

```bash
git clone <REPO_URL> bolina && cd bolina
git checkout c5c69a2          # seal commit, tagged v0.6.0
```

Toolchain: Zig 0.16.0 (`tools/toolchain.json`). Then:

```bash
zig build test                # expect: 439 pass, 7 skip, 0 fail
zig build                     # produces zig-out/bin/bolina
bash tools/prumo-verify       # mechanical gates M1-M11; enforced gates must report failing: 0
python3 tools/mutation-test.py --help   # mutation harness (see §5)
python3 tools/fuzz_diff.py    # differential fuzz against tools/refparse.py
```

The daemon boots from environment only (`BOLINA_BIND`, `BOLINA_DATA_DIR`, `BOLINA_LEDGER`, `BOLINA_CONTROL=127.0.0.1:7421`, `BOLINA_RESOURCES`). `examples/intent_client.py` (stdlib-only Python) drives the control plane end to end; `docs/INTEGRATION.md` has the full walkthrough.

## 4. Scope

### In scope — composition questions we want answered

These are the places where standard primitives are combined in ways that do not exist elsewhere. Each names code and spec sections.

1. **Two-key-type certificate binding.** Noise_IK uses X25519 statics; identity is Ed25519. The bridge is a post-handshake binding frame: cert plus Ed25519 signature over the Noise transcript hash, both directions, inside the encrypted session, before any application data flows (`src/binding.zig`, SPEC BE-TR-01/01a). Is this sound? Domain separation between this signature and the protocol's other Ed25519 signatures?
2. **Domain tag separation (BE-SIG-01).** Eight-plus signing purposes distinguished by prefix tags (SPEC §2). Can any signature be reinterpreted across purposes? Audit every sign/verify call site against the tag table.
3. **Grant chain ordering.** `verifyGrantThen` runs a fixed 14-check sequence (`src/verify.zig`). Are there implicit order dependencies the numbering does not capture? Can any check pass on state an earlier skipped check would have rejected?
4. **Scope binding walk.** Cert-scope coverage = BLAKE2s hashes of resource-id ancestors vs 8-byte scope IDs; empty scope denies all (`scopeCoversResource`). Off-by-one history here (fixed D-085): are there residual edge cases?
5. **Ledger two-phase discipline.** Nonce committed before effect; flock exclusivity; atomic-rename prune re-flock; first-receipt durability across restart (`src/grant_ledger.zig`). Any interleaving where a committed grant executes twice or a pruned log loses commits?
6. **Revocation semantics.** Revocation envelopes carry subject fingerprint AND subject expiry (BE-CTRL-03); audit-path validation runs with zero clock input (`src/historical.zig` `validateCertNoClock`); pre-revocation envelopes audit as valid via ancestry check (BE-HIST-04). Is the conservative fallback (missing expiry ⇒ never prunable) sound? Is the no-clock chain validation actually clock-free?
7. **Store-and-forward keying.** Relay stores only ciphertext keyed to recipient sessions; overlay address is BLAKE2s of the recipient key (`src/relay_store.zig`). Forward secrecy of stored packets under later session compromise?
8. **Control plane boundary.** The HTTP facade must be pure facade: same tables, same resolver, same ledger, no privileged mutation path (`src/control_api.zig`, `src/control.zig`). Loopback-only default, bearer token, constant-time compare. Can any endpoint mutate grants or ledger outside the wire path?
9. **Nonce management.** ChaCha20-Poly1305 nonces from per-session 64-bit counters under Noise transport. Overflow/reuse analysis.
10. **Trust assumptions.** `docs/THREAT-MODEL.md` §6 lists the accepted trust assumptions — are they complete and correctly bounded?

### Out of scope

- The primitives themselves (Ed25519, X25519, ChaCha20-Poly1305, BLAKE2s from `std.crypto`) and their public cryptanalysis.
- Mechanically gated properties below, unless you believe the gate itself is unsound — saying why counts as a finding.

## 5. What is already mechanically defended (and how to check us)

We claim, and you can re-verify rather than trust:

| Claim | Evidence | Reproduce |
|---|---|---|
| Wire parser matches reference implementation | differential fuzz, 0 divergences over 1M+ records | `python3 tools/fuzz_diff.py` |
| Test vectors | 77/77 generated + independently re-parsed | `tools/gen-vectors.zig`, `tools/verify-vectors.py` |
| Mutation score | receipt `sha=d4ebf81`: 174/174 non-equivalent mutants killed, 0 survived, 1 documented equivalent, 0 timeouts | `python3 tools/mutation-test.py` (~175 mutants; each mutant = recompile + full suite) |
| Mechanical conformance gates M1-M11 | budget caps, spec-test ratchet, layout, em-dash ban, etc. | `bash tools/prumo-verify` |

Known harness limits, stated honestly: mutation anchors are regex-based and were once silently skipped by a refactor (caught by denominator reconciliation, recorded in the v0.6.0 seal paragraph); the timeout fence and per-OS socket flags in the test client date from 2026-08-24 after a hang was diagnosed live. If you find the measurement layer itself untrustworthy, that is an in-scope finding.

## 6. Independence requirements (gate definition)

Quoted intent from D-092, using the shared-authorship vocabulary of SPEC §11.4:

- You must not share authorship, employer, funding, or close collaboration with the authors of this codebase. Work from the same ecosystem is self-consistent evidence, not independence.
- The internal review of 2026-08-20 (`CRYPTO-REVIEW-FINDINGS.md`, registry F1-F14) does **not** satisfy this gate — same ecosystem as the authors. It is provided to you as **pre-audit baseline**: what was already found, what was fixed, what was accepted, including an independent re-verification pass against the previous seal (`e97a117`, v0.5.3) recorded in `docs/audits/CRYPTO-REVIEW-BRIEF.md` §7.1.
- This review runs against the frozen `v0.6.0` tree above, never against moving `main`.

## 7. Materials

| Document | What it gives you |
|---|---|
| `SPEC.md` | Normative protocol spec; every BE-* rule numbered and test-backed; seal paragraphs record what each release does and does not claim |
| `docs/THREAT-MODEL.md` | Adversary model, trust assumptions §6, accepted risks |
| `docs/DECISION-LOG.md` | 41 numbered decisions (D-001..D-092); D-092 defines this gate |
| `docs/audits/CRYPTO-REVIEW-BRIEF.md` | Baseline: composition concerns §3, known-issues registry §7 (+§7.1 re-verification) |
| `docs/audits/M1-AUDIT.md`, `KEYING-AUDIT.md`, `RED-TEAM-08.md`, `RED-TEAM-09.md`, `INCIDENTS.md` | Prior internal audits, red-team rounds, incident record |
| `CHANGELOG.md` | Full sealed version lineage v0.1.0 → v0.6.0 with receipts |
| Core source, suggested order | `src/parser.zig` (328) → `src/noise.zig` (460) → `src/binding.zig` (190) → `src/verify.zig` (711) → `src/grant_ledger.zig` (554) → `src/historical.zig` (105) → `src/daemon.zig` (342) → `src/control.zig` + `src/control_api.zig` (741) → `src/ca_material.zig` + `src/ca_cli.zig` (478) |

Total core: ~4,000 lines of Zig + the documents above.

## 8. Deliverable

A written report covering:

1. Per-area verdicts for each of the ten composition areas in §4 (sound / unsound / unsound-under-condition).
2. Missing defences: attacks the composition should resist but does not.
3. Unnecessary complexity: simpler compositions achieving the same guarantees.
4. Trust-assumption audit of THREAT-MODEL §6.
5. A findings list, each with severity, repro or argument, and recommended disposition.

Gate closure: every finding either fixed in code (with regression test) or explicitly accepted and recorded by name in the threat model / decision log. Findings may be challenged, but only with argument, not dismissal.

## 9. Logistics (owner fills before sending)

| Field | Value |
|---|---|
| Reviewer name / affiliation | ___ |
| Compensation / terms | ___ |
| Review window | ___ (suggest 3-4 weeks for scope above) |
| Repo access method | ___ (private clone invite / bundle) |
| Findings channel | ___ (private, encrypted preferred; findings embargoed until dispositioned) |
