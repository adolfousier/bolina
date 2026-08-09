# KEYING-AUDIT.md — M1 round 2: classification of the 30 unbound markers

Measured 2026-08-08 on branch `m1-keying` (off main `1f2ff5a`).

## Method

The missing list is not remembered and not hand-edited. It reproduces the exact
extractor in `tools/prumo-verify` (M1 section):

```
DECL:   grep -v 'SUPERSEDED BY REMOVAL' SPEC.md | grep -oE '^\*\*BE-[A-Z]+-[0-9]+[a-z]?'
TESTED: find src test -name '*.zig' -exec grep -hoE 'test "BE_[A-Z]+_[0-9]+[a-z]?'
MISSING = DECL - TESTED (comm -23)
```

Result: DECL 109, TESTED 79, MISSING 30, ORPHANS 0.

## Evidence greps (what the classifier looked at)

| Probe | Result |
|---|---|
| `grep -rn "executor_fp\|fingerprint" src` | 0 hits: no resolver code exists |
| `grep -rn "PENDING\|REJECTED\|EXPIRED"` intent states in src | 0 hits: no intent state machine |
| `grep -rn "SyncRequest\|backfill"` sync code in src | 0 hits: no backfill surface |
| `src/fuzz.zig` header | chaos fuzzer (bounds checks), no differential oracle |
| `grep -n "fetch\|dependency\|url" build.zig` | 0 hits: stdlib-only build |
| `src/session.zig` | `bound: bool` flag (BE-TR-01), single `open` decrypt path |
| `src/verify.zig` | `verifySigned(tag, tbs, sig, pubkey)` over transmitted tbs bytes |
| `src/parser_test.zig:811` | BE_SURF_01/02 bound by compile-time reflection: the established pattern for process markers |

## Classification

### KEYABLE now (8) — code path exists, only the named test is missing

All eight are reflection or witness tests in existing test files. Test files sit
on the BE-SURF-03 harness/non-surface lists, so M5 and M11 arithmetic is
untouched: zero protocol code, zero budget growth.

| Marker | Keying approach |
|---|---|
| BE-DEP-01 | Test scans `build.zig` and `build.zig.zon` source text: zero `.fetch(`, zero `b.dependency(`, zero external URLs. Stdlib-only is a text property of the build manifest. |
| BE-EVID-11 | Reflection: `Intent` carries no `method_id`/`evidence_class`/confidence field (the requester cannot name the method); the span class derives from `method_id` via the compile-time table; no public function in the evidence API accepts class or confidence as an argument. |
| BE-EVID-14 | Node-side slice of an executor obligation (SPEC says it is not receiver-verifiable): the wire format gives `digest` no empty encoding. It is a fixed 32-byte field; a span truncated inside the digest is refused. The narrow binding is logged in D-050. |
| BE-GRANT-08 | Witness: a grant whose signature is made by the subject's key instead of the approver's is refused; envelope sender == approver plus signature check forces the approver's own key. |
| BE-TR-06 | Witness plus reflection: `Session.open` before `bound` returns an error, never plaintext; the error union means transport failure surfaces as error only; `open` is the single decrypt path upward. |
| BE-ROLE-03 | Reflection over the binding/cert API: certificate structures carry no private-key field and no public decl hands secret material to a caller. An agent-cert holder has no API path to approver key bytes. |
| BE-SURF-03 | API-surface reflection: the pre-auth entry points (`parseHandshakeInitiation`, `parseHandshakeResponse`, `parseCookieReply`, `parseDataPacketHeader`, relay type 5/6 parsers) take no authenticated-state parameter (no cert, no session, no key). The auth line is visible in the signatures the budget splits. |
| BE-WIRE-03 | Witness: parse a valid envelope, flip one bit of the tbs region inside the transmitted buffer, verification fails. `verifySigned` consumes the transmitted slice; no re-encoded copy exists on the verify path. |

Expected ratchet movement: 79 to 87, missing 30 to 22.

### NEEDS-CODE (21) — real build work, blocked on the M11 wall

M11 reads 1497/1500: three lines of headroom. None of these fits without a
D-030 budget subdivision first, exactly like the relay round got (D-043).
Estimate before line one, per the standing rule.

| Marker set | Surface | Depends on |
|---|---|---|
| BE-GRANT-01a, 04, 06, 06a, 06b, 09, 10 (7) | Pending-intent state machine: PENDING/EXPIRED/REJECTED transitions, resource exclusivity, intent_id uniqueness, refusal semantics, fail-closed restart | Budget subdivision |
| BE-GRANT-07, 07a (2) | Approving interface render contract: canonical resource_id, action bytes, recomputed action_digest, untrusted rationale marking | BE-RES-01 canonicalization |
| BE-RES-01..06 (6) | Executor canonical resolver: proposed-to-canonical resolution, unknown resolves to refusal, alias collapse, executor_fp = BLAKE2s-256(sig_pubkey)[0..8] | Budget subdivision |
| BE-SYNC-01..05 (5) | Backfill surface: authenticated peers only, response bounds, walk budget, rate limits, verify-before-adopt | Ledger (landed), budget subdivision |
| BE-SURF-04 (1) | Differential fuzzing oracle: fuzz.zig today is chaos-only (bounds checks), SPEC §11.6 requires differential | Reference-model decision |

### DEFERRED MAY (1)

| Marker | Status |
|---|---|
| BE-MESH-03 | Store-and-forward is a MAY; deferred by D-043 with the relay slice ("slim or defer, never raise"). Deferral is conformant, not debt. But M1 counts it in the denominator, so the ratchet ceiling is 108/109 unless S&F is built or the SPEC changes. D-051 flags the call to Daniel. |

## Arithmetic check

8 + 21 + 1 = 30. After this round: 87/109 bound, 22 missing (21 needs-code
plus 1 deferred MAY). Reaching 109 requires: the budget subdivision, the five
needs-code slices above, and Daniel's MESH-03 call. In that order.

## What this round does NOT touch

- SPEC.md: no normative edits. Keying binds existing code, it does not change it.
- Mutation harness v11: denominator unchanged, 81 mutants. The full re-run in
  task 3 confirms the new tests un-kill nothing.
- The untracked mutation logs and `ralph_loop.toml`: stay untracked.

## Results (2026-08-09, branch `m1-keying`)

All eight KEYABLE markers are BOUND. Ratchet 79 to 87, exactly as projected.

| Marker | Binding test | Commit |
|---|---|---|
| BE-SURF-03 | `test "BE_SURF_03 pre-auth entry points take no authenticated state"` (parser_test.zig) | `bfb4318` |
| BE-DEP-01 | `test "BE_DEP_01 build manifests name no third-party dependency"` (parser_test.zig) | `bfb4318` |
| BE-EVID-11 | `test "BE_EVID_11 no interface accepts method, class, or confidence"` (evidence_test.zig) | `d6b8226` |
| BE-EVID-14 | `test "BE_EVID_14 digest is fixed 32 bytes and truncation is refused"` (evidence_test.zig) | `d6b8226` |
| BE-GRANT-08 | `test "BE_GRANT_08 grant signed by the subject key is refused"` (verify_test.zig) | `ca2c63c` |
| BE-WIRE-03 | `test "BE_WIRE_03 verification runs over the transmitted bytes themselves"` (verify_test.zig) | `ca2c63c` |
| BE-TR-06 | `test "BE_TR_06 transport failure surfaces as error only"` (session_test.zig) | `a009bca` |
| BE-ROLE-03 | `test "BE_ROLE_03 cert and binding surfaces carry no secret material"` (binding_test.zig) | `6635567` |

High water raised 79 to 87 with the tests (`8f29b7c`), as `tools/prumo-verify`
directed.

### Gauntlet on the committed tree (8f29b7c)

| Gate | Result |
|---|---|
| `zig fmt --check .` | clean |
| `zig build test` | green, 274 test declarations (266 + 8) |
| `tools/prumo-verify` | 0 failing: M1 87/109 (high water 87), M5 1173/1500 (handshake 990/990, relay 183/510), M8/M9/M10, M11 1497/1500 |
| `tools/verify-vectors.py` | 77 passed, 0 failed |
| em-dash scan (src + tools) | 0 |
| mutation (full re-run, D-035) | 81/81 killed, 0 survivors, log `mutation_keying.log`; zero MUTANT tags left in tree |

### Zig 0.16 notes from the round

Three toolchain facts the round hit, recorded so the next round does not
re-discover them:

- `std.fs.cwd()` is gone; file reads go through `std.Io`
  (`std.Io.Threaded.init_single_threaded` then `std.Io.Dir.cwd().readFileAlloc(io, path, a, .unlimited)`).
- `@Type` was removed: type reflection is read-only. Return-type witnesses
  read `@typeInfo(...)` fields instead of reconstructing types.
- `@typeInfo(T).@"struct".fields` values are comptime-only (they carry
  `type`), so iteration needs `inline for`; a module's decls are read with
  `@typeInfo(module)` directly, not `@typeInfo(@TypeOf(module))`.

The 22 still missing are the NEEDS-CODE and DEFERRED-MAY rows above,
unchanged: the budget subdivision comes before any of them.
