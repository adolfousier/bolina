# PHASE-D-ESTIMATE - Daemon persistence + restart semantics (lifecycle milestone)

**Status:** CLOSED 2026-08-12. Phase D landed green: durable `grant_ledger.zig` (two-phase append log, fsync barrier, orphan recovery BE-GRANT-01a, pruneExpired BE-EXEC-01) wired into the dispatch check-11 seam (D-062), BE-EXEC-01 bound (M1 114/114), harness v20 grant_ledger domain 7/7, full suite 151/151 killed (receipt `logs/mutation_phase_d_full.log`), 0 survivors. The four design questions (§2 check-11 as the sole I/O point, two-phase on-disk format, direct-file-state crash-injection, fsync observability) were resolved in D-061 before code; this estimate's scope was delivered as scoped.

## Context

- Phase A (dispatch core, in-memory) shipped. Phase B (listener + live Noise handshake) shipped. Phase C (relay serving + S&F drain on live traffic) shipped pending suite green.
- `dispatch.zig:65-84` carries the **D-059 stand-in**: a module-global `consumed_registry: [MAX_CONSUMED][LEN_GRANT_ID]u8` + `consumed_len` counter, `consumedHook` does linear check-and-set, `resetConsumedRegistry()` zeros it. This is explicitly a phase-A memory stand-in. **Phase D replaces it with a durable ledger.**

## Layer-0 finding (CRITICAL - resolves the storage-backend question up front)

`build.zig.zon`:
```
// SPEC.md BE-DEP-01: no third-party dependencies. This table stays
.dependencies = .{},
```

**BE-DEP-01 forbids all third-party crates.** No SQLite, no sled, no lmdb, no rocksdb. The durable ledger MUST be hand-rolled over `std.fs` (append-only file + fsync barrier). This is non-negotiable and kills the obvious "just use SQLite" path before it is asked. The project's determinism-first posture (prumo, mutation harness, the pyramid) is consistent with a minimal, auditable, single-file append log over a dependency-laden embedded DB.

## SPEC marker inventory for Phase D (measured this pass)

| Marker | SPEC line | Demand |
|---|---|---|
| **BE-EXEC-01** | 147-148 | daemon lifecycle: one process, no fork-per-session, bounded resources. Reserved for "phase-D falsification of restart semantics." |
| **BE-GRANT-01** | 1338-1340 | consumed `grant_id` MUST be **durably committed to stable storage before the effect is attempted**; ledger survives restart/crash/redeploy. |
| **BE-GRANT-01a** | 1349-1350 | a grant_id committed under BE-GRANT-01 whose Effect was never published MUST be treated as consumed, MUST NOT be retried automatically; on restart publish an `interrupted` Effect. |
| **BE-GRANT-04** | 285-287 | restart collapses every pending approval to `EXPIRED` (memory-only by design - fail safe). |
| **BE-REV-02** | 441-443 | a node holding a CA-signed revocation MUST persist the revocation across restart. |

## The fail-safe asymmetry (the invariant Phase D must preserve)

The SPEC deliberately points the two rules in **opposite directions** (line 1343-1346):

| State | Storage | On restart | Why |
|---|---|---|---|
| Pending approval | memory-only | -> `EXPIRED` | revoke on crash (fail safe) |
| Spent grant_id | durable | stays consumed | cannot un-spend (fail safe) |
| Revocation | durable | stays revoked | never expires within cert life (line 820) |

Both fail in the safe direction. The estimate's central design question is how to make the spent-grant ledger durable WITHOUT accidentally persisting pending approvals (which must die on restart).

## Scope (what Phase D adds)

1. **`src/ledger.zig`** (non-surface, post-admission daemon area, sibling of `relay_store.zig`): hand-rolled append-only durable ledger over `std.fs` with an explicit fsync barrier. Operations: `commitConsumed(grant_id)` (fsync before return), `isConsumed(grant_id)`, `commitRevocation(sig_pubkey)`, `isRevoked(sig_pubkey)`, `recover()` (startup scan), `pruneExpired(now)`.
2. **`dispatch.zig` rewrite of the consumed seam**: replace the memory `consumed_registry` stand-in with `ledger.commitConsumed` called BEFORE the effect fires (BE-GRANT-01 ordering), keep `consumedHook` shape so the seam contract is unchanged.
3. **Restart path**: on daemon startup, `ledger.recover()` scans the log; any committed-but-unpublished grant_id publishes an `interrupted` Effect (BE-GRANT-01a); pending approvals are NOT restored (they expire, BE-GRANT-04).
4. **Bounded growth (BE-EXEC-01)**: `pruneExpired` drops consumed grant_ids past their validity window. Revocations are NOT pruned (never expire).

## Open design questions (resolve BEFORE code, cheapest informative step first)

1. **The crash-injection test shape.** BE-GRANT-01a (committed-but-unpublished -> `interrupted`) is the hardest property to falsify because it requires simulating a process crash between the fsync and the effect publish. **Cheapest step:** decide the harness shape - (a) an in-process hook that aborts after `commitConsumed` returns, (b) a real fork+kill, (c) a log-truncation trick. Pin this before writing the ledger, because it determines the ledger's on-disk format (does it need a "published" tombstone row, or does recovery infer unpublished from the absence of a later row?). Do not code until resolved.
2. **On-disk format and the "published" witness.** BE-GRANT-01a needs to distinguish "committed, effect in flight" from "committed, effect done." Two designs: (a) two-phase rows (`commit` then `published`), recovery treats commit-without-published as interrupted; (b) single commit row + a separate in-memory published set that is rebuilt on restart by replaying effects. (a) is more durable and matches the SPEC's "committed before attempted" wording. **Cheapest step:** re-read §2 (grant lifecycle, the 12-check ordered list at line 1386) and confirm check 11 is the single durable-commit point.
3. **fsync semantics on the target runtime.** `std.fs` fsync on macOS vs Linux; whether the test can observe a pre-fsync crash. **Cheapest step:** one trivial program that writes, fsyncs, reads back - confirm the barrier is observable. Do not assume.
4. **Pruning vs BE-GRANT-01 "survives redeployment."** If `pruneExpired` drops a grant_id, a redeployment after the validity window could "un-spend" it - but the grant is also expired so it would be refused on validity grounds anyway. Confirm the two checks are independent and the prune is sound. Re-read line 1346 ("within its validity window").

## Test strategy

- **T1 durable-before-effect:** read the ledger file after `commitConsumed` returns and BEFORE the effect fires - grant_id is present. (Kills the commit-after-effect mutant.)
- **T2 replay-after-restart:** commit a grant_id, drop the in-memory state, call `recover()`, replay the same grant_id -> refused (BE-GRANT-01 survives restart).
- **T3 crash-during-execution (BE-GRANT-01a):** commit grant_id, abort before publish, `recover()` -> publishes `interrupted` Effect exactly once, grant_id NOT retried.
- **T4 pending-expires (BE-GRANT-04):** a pending approval in memory is NOT in the ledger; after restart it is gone (EXPIRED), not restored.
- **T5 revocation-survives (BE-REV-02):** `commitRevocation`, restart, `isRevoked` still true.
- **T6 bounded (BE-EXEC-01):** ledger with expired grant_ids pruned by `pruneExpired`; size bounded; revocations NOT pruned.

Mutation harness v20: ledger domain (~7 mutants: commit-ordering, fsync-skip, replay-accept, crash-retry, pending-survive, revocation-forget, prune-never).

## Placement + budget (no cap pressure)

| Unit | Measured | Cap | Notes |
|---|---|---|---|
| `src/ledger.zig` (NEW) | ~140-180 est | non-surface | sibling of relay_store.zig (139). No wire bytes, no pre/post-auth cap touched. |
| `dispatch.zig` (rewrite seam) | 201 -> ~210 est | non-surface | replace memory registry with ledger call; seam contract unchanged. |
| pre-auth total | 1496 | 1500 | UNTOUCHED - Phase D is all post-admission. |
| listener sub-unit | 246 | 250 | UNTOUCHED. |

## SPEC edit required (v0.3.7-draft -> v0.3.8-draft)

- Declare **BE-EXEC-01** (promote from reserved to bound, line 147-148).
- Declare `src/ledger.zig` non-surface (D-059 placement shape).
- No wire bytes change. No pre-auth or post-auth cap change.

## Ratchet / gauntlet

- **M1:** 113 -> 114 (BE-EXEC-01 bound).
- **prumo M5:** place `src/ledger.zig` non-surface.
- **Full mutation suite:** 144 -> ~151 (±), re-run green.
- Gauntlet at pushed HEAD: fmt, build test, prumo, vectors, em-dash, mutation.

## Estimate

| Item | Size |
|---|---|
| `src/ledger.zig` | ~140-180 lines (non-surface) |
| `src/ledger_test.zig` | ~6 live tests incl. crash-injection |
| `dispatch.zig` seam rewrite | ~10 lines changed |
| `tools/mutation-test.py` v20 | +1 domain, ~7 mutants |
| Docs | SPEC v0.3.8-draft, LANGUAGE.md, README, this estimate CLOSED |

## Risk assessment

| Risk | Level | Mitigation |
|---|---|---|
| Crash-injection test is hard to make deterministic | **MEDIUM** | Resolve design question #1 first (the harness shape); this is why this is estimate-first |
| BE-DEP-01 forces hand-rolled fsync log | LOW | `std.fs` is adequate; append-only is the simplest durable structure |
| Pruning unsoundness vs "survives redeployment" | LOW | Resolve design question #4; validity-window check is independent |
| Pending/approval leak into durable store | LOW | Pending stays in session.zig memory; only spent grant_ids and revocations touch the ledger |

**Overall: MEDIUM.** Higher than Phase C (which was glue) because of the crash-recovery semantics and the no-deps constraint. The crash-injection harness shape (question #1) is the gating decision - everything else flows from it. Estimate-first is non-negotiable here; the cheapest informative step is to pin the crash-injection shape before a single line of ledger code.

## Deferred (out of Phase D scope)

- **BE-SURF-04 (the fuzz oracle)** - the only remaining original M1 marker, still deferred. Independent of the daemon milestone.
