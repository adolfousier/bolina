# Changelog

All Bolina versions since the first draft. Dates from repository history; every sealed version
names its decision ruling (DECISION-LOG) and, where applicable, its mutation-testing receipt.
This project does not use semantic versioning as a promise of API stability: minor numbers mark
milestones closed against the SPEC, and a version is *sealed* only when mechanical evidence
(tests, gates, receipts) exists for it — see SPEC §11 and the epistemic-status note at its top.

The format is adapted from [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Phase-3 receipt pipeline (Lastro) trial cycle: CI-dedicated CA under `ci/ca` (2 roots), runner
  identity minted by `lastro keygen` (`ci/runner`, fp `4286cba0dcfb79ce`), executor cert issued by
  `bolina ca issue` (serial `13eb64cc…`, TTL 30d, signed by both CI roots). Trial receipts for
  `zig build test` and `prumo-verify` under `docs/receipts/trial/`, both VERIFIED by
  `lastro verify` against the CI trust anchors.
- Gate **M12** in `tools/prumo-verify`: fails when the CI executor cert has fewer than 7 days of
  validity left, or is missing/malformed (fail-closed), with the reissue command in the message.
  Threshold from the ratified D-092 phase-3 merge condition (premortem risk #1).

### Fixed

- **Linux build**: `zig build test` (and the daemon executable) failed to compile on
  x86_64-linux with 21-22 "dependency on libc must be explicitly specified" errors: the test
  and exe modules declare `extern "c"` seams but never set `link_libc`; macOS links libc
  implicitly, so every prior suite run was macOS-only. Found by the G3 soak on dedicated
  hardware (2026-08-24). Proof of fix: cross-compile to x86_64-linux-gnu now completes the
  compile step cleanly (only the expected host-cannot-exec remains locally); native suite
  unchanged at 441 pass / 0 fail. Note for reviewers: tag v0.6.1 (`7207fb0`) predates this
  fix, so its suite is verified on macOS; Linux verification holds from main onward.

## [0.6.1] - 2026-08-24

Pre-audit refresh fixes (baseline pass against sealed v0.6.0; dispositions in
`docs/audits/CRYPTO-REVIEW-BRIEF.md` 7.2):

- **FIXED HIGH** - `ca issue` minted version-2 certificates while the grant chain only
  enforces scopes on v3+: every tool-minted scope was silently inert (`9c96732`). Tool now
  mints v3 always; empty scopes deny-all by design (D-085 R4) with an issue-time note;
  e2e test drives real tool certs through parse+validate into the grant verdict.
- **FIXED MEDIUM** - intents admitted over `POST /v1/intents` had no sender record, so a
  wire grant could never execute them (`b047043`). The endpoint now requires `subject`
  (agent pubkey, hex64) and lands the same sender record the wire path writes; F16
  composition test proves HTTP admission executes via wire grant.
- **Accepted-with-name** - BE-HIST-04a (audit vs current trust set) and the flat-JSON
  extractor posture (THREAT-MODEL 4.11).

Sealed at `322622c`. Receipt `sha=322622c`: 176/176 non-equivalent mutants killed,
0 survived, 1 documented equivalent (177 evaluated) — legacy FULL at `90e46a5` plus the
d092 chunk after a TARGETS registration fix (tools-only, zero src/ drift). d092: 2/2.

## [0.6.0] - 2026-08-24

Local control plane, offline CA tooling, integration surface. Design D-091, owner-approved
phase by phase; the v1.0 line itself is defined by D-092 (three external gates, zero features).
Receipt `d4ebf81`: 174/174 non-equivalent mutants killed, 0 survived, 0 timeouts, 1 documented
equivalent (175 evaluated).

### Added
- **Control plane** (`src/http_parse.zig`, `src/token.zig`, `src/control.zig`): opt-in HTTP/1.1
  subset on localhost via `BOLINA_CONTROL=host:port`. One `poll()` loop multiplexes the UDP wire,
  the TCP listener and up to 8 clients — zero threads, same process as the node. Per-connection
  deadlines (anti-slowloris), fixed caps, chunked transfer answered with an explicit 501.
  Bearer token auto-generated at first boot (32 bytes, file 0600, printed once), constant-time
  verification. Graceful SIGTERM drain keeps the ledger consistent.
- **Control API** (`src/control_api.zig`): `POST /v1/intents` (idempotent by client intent_id;
  202 accepted / 202 duplicate / 409 resource held / 422 unknown-or-foreign resource / 400 bad
  body) routed through the same resolver and intent table as the wire path — no god-mode path
  exists. `GET /v1/events` SSE replay by ledger cursor over a drop-oldest ring published at the
  grant-ledger commit sites. `/metrics` in Prometheus text format. `/healthz` open; everything
  else requires the token. Error-to-status mapping pinned (409/422/404/403/400/500).
- **Resource declaration**: `BOLINA_RESOURCES` (comma-separated canonical forms) registers the
  executor's resources at boot; malformed entries are fatal, none declared means fail-closed.
- **CA CLI** (`src/ca_cli.zig`, `src/ca_material.zig`): `bolina ca init|issue|list|show|revoke`
  in the same binary, offline-first. Two-of-two root signatures on issued certs; revoke emits a
  BE-CTRL-03 envelope carrying the revoked subject's own expiry. Placement cap 550 enforced.
- **Integration kit** (outside `src/`): `INTEGRATION.md`, `openapi.yaml`, and a stdlib-only
  Python example proven live against a running daemon (health, admit, idempotent retry, foreign
  rejection, events, metrics).
- **Mutation harness**: d091 defence domain (6 mutants) wired; d089/d090/d091 now gate the exit
  code (before, a surviving defence mutant failed silently — the repaired md5-dedup SKIP proved
  it); per-mutant timeout fence with a distinct TIMEOUT verdict that blocks the gate like a
  survivor (a hang is never kill evidence).

### Fixed
- Boot log double-hexed the node fingerprint (an operator would have configured garbage).
- Control-plane facade is attached by `main.zig`; earlier tests wired it by hand and a live
  daemon answered 404 to everything.
- Test-client sockets were blocking by accident: the O_NONBLOCK constant carried Linux's value,
  which on macOS is O_EXCL, so a silent server parked reads forever (one mutated evaluation held
  its harness nine hours). Now non-blocking per-OS with SO_RCVTIMEO and a wall-clock ceiling,
  proven live under the re-applied http-caps mutant.

## [0.5.3] - 2026-08-23

Audit path hardened to admission-path standard (D-090). Receipt `7035eed`: 168/168
non-equivalent killed, 0 survived, 1 documented equivalent (169 evaluated).

- `validateCertNoClock` becomes a real validator: chain validation split from window check so
  the NoClock audit path enforces roles, quorum, the BE-REV-01 lifetime cap, CA signatures and
  the trust set with zero clock input; a hidden temporal check is unrepresentable in that path.
- Revoke control bodies MAY carry the revoked subject's own expiry (`u64be` tail, BE-CTRL-03):
  prune obeys the subject's lifetime, absent tail means never-prune (fail-closed); the
  admin-expiry placeholder dies. Wire bytes change (optional tail only).
- BE-HIST-04 becomes causal: `getRevokeHash` exposes the revocation's hash, envelopes predating
  a revocation pass audit instead of blanket rejection.
- md5-dedup mutation anchor repaired after `zig fmt` reflowed `relay.zig`; d089 chunk re-ran 3/3.

## [0.5.2] - 2026-08-22

Daemon milestone closes (D-089). Receipt `7fcc336`: 162/162 non-equivalent killed, 0 survived,
1 documented equivalent.

- `src/keys.zig`: real node key material — load-or-generate X25519 + Ed25519 statics (0600
  files, 0700 dir), stored publics cross-checked against derived, trusted CA labels; the boot
  skeleton's zeroed-key placeholder (a standing D-018 violation) dies.
- `src/daemon.zig`: the node core — type 1/4/5/6 routing, own binding frame pushed immediately
  after handshake commit, pre-bound payloads gated behind verified peer binding, fail-closed
  counts-and-drops, optional relay serving (certs carry no relay role).
- `src/main.zig` env-only boot (`BOLINA_BIND` default 0.0.0.0:7420, `BOLINA_DATA_DIR`,
  `BOLINA_LEDGER`; `BOLINA_TEST_CA` dev-only-fatal), EADDRINUSE fatal, orphan tombstoning.
- End-to-end pilot: two nodes over real UDP — handshake, mutual binding, intent → grant →
  ledger commit → effect → restart orphan recovery; wrong-kex and replay rejected.
- Defence hardening: MD3 exclusive flock on the grant ledger (+ read-only audit views), MD4
  intent-table compaction (capacity freed, not just locked), MD5 relay registration dedup
  (`relay.zig` held at exactly 256 lines).
- BE-TR-01a pins the binding message byte layout; DECISION-LOG records D-089.

## [0.5.1] - 2026-08-21

Crypto-review follow-up F13 (D-087): the Grant verifier owns its checks 6-9 state through
`intent_table`/`sender_table` references. BE-SURF-03 housekeeping owed by the sealed tree:
session-state sub-unit re-floored 748→759, sync rebalanced 100→89, sum stays 1500. No wire bytes.

## [0.5.0] - 2026-08-21

External crypto review of 2026-08-20 dispositioned: findings corrected or accepted-with-name
under D-087; the review brief and findings register become the pre-audit baseline for the
future independent composition review (D-092 G1 baseline — not the review itself).

## [0.4.0] - 2026-08-20

Certificate identity scope, closed and sealed. Cert version 2→3; `group_count/group_ids`
renamed `scope_count/scope_ids`, bound 16→8 (D-085/D-086). Scope ids are 8-byte BLAKE2s
resource prefixes; empty scope denies all; grant verification gains approver- and subject-scope
coverage checks (3a/4a); genesis fields renamed to match. Wire layout byte-identical.

## [0.3.9] - 2026-08-18

Conformance milestone: all eight §11 items produce evidence with seal paragraphs (D-084).
§11.4 instrumented: bounded TLA+ grant-path checks merged under `model/` with pinned TLC runner
in CI (D-083); crash-recovery invariants; twelve Phase A conformance fixtures; `grant_trace.zig`
comptime-gated instrumentation (D-076).

## [0.3.8] - 2026-08-12

Daemon milestone Phase D closes: two-phase durable ledger with fsync barrier ships; crash-safe
prune by atomic rename (D-063); check-11 seam commits before the effect; interrupted publishes
recover idempotently (D-062). Differential oracle strengthened: four boundary seeds drive all 72
parser exit points; 1,000,000-record run surfaced three parser bound omissions plus one
production prune defect, all fixed. Continuous 24h soak deferred for want of dedicated compute
(owner ruling); TLA+ model-checking brief issued for external contribution.

## [0.3.7] - 2026-08-12

BE-EXEC-01 promoted to declared (daemon lifecycle: one process, no fork-per-session, bounded
resources, restart semantics); `grant_ledger.zig` placed non-surface ahead of code (D-061).

## [0.3.6] - 2026-08-11

BE-EXEC-04 declared (relay serving on live traffic, D-060); relay sub-unit ratcheted 510→256
(measured floor); listener sub-unit declared cap 250; Phase C closed 144/144 spec coverage.

## [0.3.5] - 2026-08-11

BE-EXEC-02/03 and BE-SESS-02 declared (listener and session markers, §0.4); `dispatch.zig`
placed non-surface (D-059); Phase A closed 131/131.

## [0.3.4] - 2026-08-11

Store-and-forward mechanics for BE-MESH-03 (store condition, keying, drain at registration,
quotas, TTL, body cap); `relay_store.zig` placed non-surface ahead of code (D-058).

## [0.3.3] - 2026-08-10

Post-authentication unit subdivided: wire-parser 652 (measured floor), session-state 748, sync
sub-unit declared cap 100 (D-054); `sync.zig` placed ahead of code; BE-SYNC-04 rate budget.

## [0.3.2] - 2026-08-10

ResourceSet domain tag `0x08` and §8.4 encoding/publication signature declared (D-053),
closing the BE-RES-05 obligation the closed tag table owed.

## [0.3.1] - 2026-08-08

BE-HIST-02 anchoring vehicle corrected (D-046/D-047): the first envelope accepted from a signer
is that signer's self-anchoring record — no cert-carrying Control action may exist; `ledger.zig`
and `historical.zig` placed non-surface (D-045 normative via D-047).

## [0.3.0] - 2026-08-07

Relay surface: type 5 route header and type 6 registration formats (§5.2a); relays join
BE-SURF-01 as the third pre-auth entry (fixed-size, role-gated); BE-SIG-01 domain tag `0x07`;
pre-auth unit subdivided handshake ≤990 / relay ≤510.

## [0.2.0] - 2026-08-06

Capability sealed by content: BE-GRANT-03b (verification is a call, not a value) and BE-GRANT-03c
(TOCTOU closure); mutation gate M2 born with its denominator derived from the SPEC; non-receipt
is not evidence (BE-REV-02).

## [0.1.0] - 2026-08-05

First draft: QUIC/TLS replaced by Noise_IK over UDP; MLS replaced by pairwise fan-out; CBOR
replaced by a flat non-recursive wire encoding; primitive set reduced seven→four — all four
changes follow from the zero-dependency constraint and narrowed the attack surface.

[0.6.0]: https://github.com/adolfousier/bolina
[0.5.3]: https://github.com/adolfousier/bolina
