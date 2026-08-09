# Bolina — Implementation language decision

**Status:** DECIDED — **Zig everywhere** · **Decided:** 2026-08-05 · **Decision owner:** Daniel
Carneiro (`loonix`)

This is a decision record. It states the constraints, what each candidate gives, what the decision
was, and — in §6 — the obligations the decision activates. §§1–4 are preserved as the reasoning
that was available at decision time, not rewritten to agree with the outcome.

---

## 1. What the decision is bound by

Three constraints are already fixed and are not up for renegotiation in this decision:

| # | Constraint | Source |
|---|---|---|
| C1 | No third-party build dependency; standard library only, with reference primitives vendored if the stdlib lacks them | SPEC §0.3, BE-DEP-01 |
| C2 | The daemon parses attacker-controlled bytes off an unauthenticated UDP socket | SPEC §4 |
| C3 | MAD already exists in Zig, is the intended reference `executor`, and has sealed gates | SPEC §10.2 |

C1 and C2 pull in opposite directions, and that tension is the entire decision. C1 favours the
language whose standard library already contains the four primitives. C2 favours the language whose
compiler prevents the failure class that no test in `SPEC.md` §11 can catch.

---

## 2. Candidates

### 2.1 Zig everywhere

**For.**
- `std.crypto` contains Ed25519, X25519, ChaCha20-Poly1305, and BLAKE2s. C1 is satisfied with
  literally zero vendored code — the only candidate for which this is true today.
- MAD is already Zig (C3). The daemon and the executor share a language, a build, and a memory
  discipline, with no FFI and no second toolchain.
- Per-cycle arena allocation, already proven in MAD and thermally validated against RSS growth, maps
  directly onto per-packet handling.
- Cross-compilation to every target the mesh needs, from one machine, without a cross toolchain.
- Small static binaries, no runtime, no GC — the right shape for a network daemon.

**Against.**
- **No memory safety.** Under C2 this is the dominant risk, and `THREAT-MODEL.md` §4.6 states why no
  BE-\* can compensate: use-after-free and out-of-bounds reads are not logic errors, and mutation
  testing tests logic.
- The language is pre-1.0; breaking changes across versions are an ongoing maintenance tax you
  already pay in MAD.
- A smaller pool of external reviewers for an open-source security protocol.

**What it would cost to take this option responsibly** — these are not optional extras:
- `ReleaseSafe` as the *shipped* build, never `ReleaseFast`. Bounds and overflow checks stay on.
  For this workload the performance difference is irrelevant and the safety difference is not.
- SPEC §11.6 (continuous fuzzing, ≥24 h, zero crashes, zero OOB reads) promoted from a conformance
  item to a merge gate on any change to parsing code.
- A written rule that the parser allocates nothing and touches no pointer it did not receive as a
  bounded slice — which BE-WIRE-01 and BE-WIRE-02 already require, and which becomes load-bearing
  rather than merely tidy.

### 2.2 Rust daemon + Zig MAD

**For.**
- Memory safety exactly where C2 bites: the parser, the session table, the reassembly buffers.
- MAD survives unchanged (C3), speaking the existing stdio JSON-RPC boundary. No FFI.
- Mature tooling for the things this protocol needs to prove: `cargo-fuzz`, `cargo-mutants`,
  `miri`.

**Against.**
- **C1 is not satisfiable in the same sense.** Rust's standard library has no cryptography, so all
  four primitives must be vendored. Under BE-DEP-01 that is permitted — vendored, hash-pinned,
  unmodified reference implementations — but it is four pieces of code you did not write, sitting in
  the repository, that must be reviewed and re-vetted when upstream fixes something.
- Two languages, two toolchains, two build systems for one project.
- `unsafe` will still appear at the socket boundary; safety becomes a property of a reviewed
  boundary rather than of the whole binary.

### 2.3 Go everywhere

**For.**
- Memory safe. `crypto/ed25519`, `crypto/sha256` in std.
- Orbit is Go: the human-approval gate that is already mutation-tested and production-proven
  (BE-GRANT-07/-08 came from it) would migrate without a rewrite.
- Fastest path to a working mesh by a wide margin.

**Against.**
- X25519, ChaCha20-Poly1305, and BLAKE2s live in `golang.org/x/crypto` — official, but formally
  outside the standard library, so C1 is violated or requires vendoring three packages.
- A garbage collector in a daemon holding session keys means less control over when secret material
  is actually zeroed. `BE-TR-02` ("old keys MUST be zeroed on replacement") is harder to guarantee
  when the runtime may have already copied a buffer during a collection.
- Constant-time behaviour is less controllable than in Zig or Rust.

### 2.4 Rust everywhere, rewriting MAD

Rejected unless the experiment in §4 produces a surprise. It discards MAD's arena model, its sealed
Gates 1–2, and its `ActionResult` contract — proven work — to buy uniformity. C3 exists precisely to
make this the option that has to justify itself.

---

## 3. The honest summary

| | C1 zero-dep | C2 memory safety | C3 reuses MAD | Reuses Orbit's gates |
|---|---|---|---|---|
| Zig everywhere | **Fully** | ✗ | **Yes** | ✗ |
| Rust + Zig MAD | Vendored (4) | **Yes** | **Yes** | ✗ |
| Go everywhere | Vendored (3) | **Yes** | ✗ | **Yes** |
| Rust everywhere | Vendored (4) | **Yes** | ✗ | ✗ |

No option wins on every axis. The decision is which constraint you are least willing to compromise:

- If **zero dependencies** is the hard one, it is Zig, and §2.1's three costs are the price.
- If **"secure" must be defensible against a memory-corruption exploit in a network daemon**, it is
  Rust for the daemon, and four vendored primitives are the price.

Both are defensible. What is not defensible is choosing Zig and skipping the fuzzing gate, or
choosing Rust and pretending the vendored primitives are not dependencies.

---

## 4. The experiment that would settle it

Argument is `Inference` (0.65 ceiling). This produces `DirectObservation` (0.95) for roughly a day
of work, and the artefact is reusable whichever way it goes.

**Build the same slice three times** — Zig, Rust, Go — consisting of exactly:

1. The `Envelope` parser (SPEC §6.2) under BE-WIRE-01 and BE-WIRE-02.
2. Ed25519 verification of `sig`.
3. The `Grant` verifier (SPEC §8.1) with BE-GRANT-01, -02, -05.

**Measure, and record in this file:**

| Metric | Why it decides something |
|---|---|
| Third-party code in the build, in lines | C1, made concrete instead of categorical |
| Time for a clean build with the network disabled | C1's real test (SPEC §11.7) |
| Lines of implementation, and lines of `unsafe`/`@ptrCast` | Reviewability by one person |
| Crashes and OOB reads after 1 h of fuzzing the parser | C2, measured rather than assumed |
| Whether `cargo-mutants` / equivalent reaches 100% kill on the Grant verifier | SPEC §11.2 feasibility per language |
| Wall-clock time to write it | Honest cost of the safer option |

If the Zig parser survives an hour of fuzzing with no findings and the code is short enough to read
in one sitting, C2's risk is smaller than argued here and Zig wins on C1 and C3 together. If it
produces findings in the first hour, that is the answer, arrived at cheaply.

### 4.1 Result (2026-08-05, Zig slice)

The slice was built once, in Zig. §6 decided Zig ahead of this measurement, so the
experiment's surviving role was the one §6.2 assigns to it: falsification. The Rust and Go
repetitions named above were therefore not built, and the numbers below measure the Zig
implementation only; they carry no comparison against the other candidates. Everything
validated here is the §8 capability half: the Grant verifier (BE-GRANT-03) and its verification-call boundary (BE-GRANT-03b; the 03c seal was superseded by removal in round 4). Round 4 then implemented §7 (attestation) — `evidence.zig` and `dag.zig` — red-teamed it (`RED-TEAM-09.md`), and extended the mutation harness to it, so the attestation layer now carries the same mechanical proof as the capability half. The §6 language verdict below was settled by the capability pass and is unchanged by the attestation layer.

| Metric | Measured |
|---|---|
| Third-party code in the build | **0 lines.** `build.zig.zon` declares `.dependencies = .{}`; all four primitives come from `std.crypto`; nothing vendored. |
| Clean build, network disabled | **11.0 s** from an empty cache, zero fetch attempts. |
| Implementation lines | **490** capability slice (`parser.zig` 284, `verify.zig` 182, `main.zig` 13, `tests.zig` 11) + round-4 attestation layer (`evidence.zig` 258, `dag.zig` 190, `evidence_test.zig` 451, `dag_test.zig` 230, `evidence_test_helpers.zig` 202). Fuzz and vector harnesses excluded. Current state after the budget split (D-030): **two BE-SURF-03 units, each measured against its own 1500-line cap by the M5/M11 gates (`tools/prumo-verify`)** — pre-authentication **1173/1500**, subdivided per D-043 into a handshake sub-unit **990/990** (`mac.zig` 173, `noise.zig` 489, `parser.zig` 328) and a relay sub-unit **183/510** (`relay.zig` 183); post-authentication **1497/1500** (`binding.zig` 193, `parser/channel.zig` 430, `parser/session.zig` 290, `reassembly.zig` 247, `replay.zig` 114, `session.zig` 223); the split lands on BE-SURF-01's authentication boundary, and the pre-split single-unit reading plus the headroom estimate are in `NOISE-SESSION-ESTIMATE.md`. Non-budgeted implementation files outside both units: `verify.zig` 495 (Grant verifier BE-GRANT-03, plus the channel, mesh, and envelope-admission verify layers), `ledger.zig` 290 and `historical.zig` 109 (ledger store and historical audit path, non-surface per D-045/D-047), `evidence.zig` 294 and `dag.zig` 190 (attestation), `main.zig` 13, `tests.zig` 22; dedicated `*_test.zig` files total 5053; instrumentation and fuzz harness (`coverage.zig` 160, `fuzz.zig` 149) excluded. |
| Pointer-minting builtins (Zig has no `unsafe` blocks) | **0.** Round 4 deleted the storable capability: `verifyGrantThen` runs the effect as a callback inside its own frame and hands back no value, so there is no capability type to rebuild from a raw pointer, and the two boundary casts left with it. Gated by M8 (`tools/prumo-verify`): the set `{@ptrCast, @ptrFromInt}` (Zig language reference) must total zero across `src/`, with no exceptions and no negative-compile canary. |
| Verification-call boundary (BE-GRANT-03b) | **A call, not a value.** `verifyGrantThen` runs every check, commits the ledger, then invokes the effect itself with the grant by value; no handle leaves the routine, so there is nothing to keep, mutate, replay, or use after expiry. The single `execute()` call site is the only reach path to the effect, gated by M10 (`tools/prumo-verify`), a zero-exceptions grep in M9's shape. BE-GRANT-03c (the seal) is superseded by removal. |
| Crashes and OOB reads after 1 h of fuzzing | **0.** 7,300,000,000 inputs (measured loop budget), 59 min 11 s wall, ReleaseSafe: zero panics, zero macOS crash reports. The earlier "21,900,000,000 parser calls" figure was a derived product (inputs times three parsers), not a measurement, and is dropped here. |
| Exit-point coverage (SPEC §11.6) | **17 of the 64 enumerated parser exit points reached** over a bounded run of 4,000,000 inputs (24,000,000 parser calls, 0 panics), measured 2026-08-08 after the relay parsers landed. The 17 reached exits are the six original entry points (envelope, grant, intent, span, effect, claim); all 47 unreached exits belong to the transport, mesh, certificate, and relay parsers (SPEC 4.1a, 4.5, 5.1a, 5.2a, 3.1), whose entry points `src/fuzz.zig` does not call yet and whose seeds `test/vectors.json` does not carry yet (transport vectors deferred by D-020; relay seeds not yet added). The earlier "17/17, zero unreached" wording used a stale denominator: the `Branch` enum now has 64 members, derived mechanically via `@typeInfo` (`src/coverage.zig`). Measured by hand-instrumented counters, reproduced with `zig build coverage -Dcoverage -Dfuzz-budget=4000000`. Native toolchain coverage has no script-readable output on this toolchain, so manual instrumentation is the measurement, not a proxy (residual in `THREAT-MODEL.md` §4.6). Corpus: 6 seeds (envelope, grant, intent, span, effect, claim from `test/vectors.json`), 4 mutation operators (bit flip, byte overwrite, truncate, saturate), 40% mutated-seed / 60% fully-random, 4096-byte input cap. Closing the 47-exit gap needs transport and relay seeds in `test/vectors.json` and the transport and relay entry points in the harness; that is the next measurement, not this one. |
| Mutation kill | **81/81 mutants killed** (harness v11, measured 2026-08-08, full-suite re-run re-confirmed 2026-08-09 after the M1 keying round at `m1-keying` HEAD: 81/81, 0 survivors, log `mutation_keying.log`): 17 on the Grant verifier (14 over the 12 modelled BE-GRANT-03 checks, since check 10's three bounds are attacked separately, plus 3 on the BE-GRANT-03b callback property and its ordering against the expiry and ledger checks), 11 on the attestation layer (the nine section-7 properties keyed to the resolution record and supersession), 4 on the transport DoS constants (all four section-4 markers: mac1-label, cookie-rotate, window-bits, max-message), 11 on the session phase (the six section-4 session markers: key-schedule, mac1-first, nonce-counter, rekey-bound, rekey-zero, binding-sig), 8 on the channel layer (the seven section-6 markers: BE-CHAN-01/02, BE-GEN-01/03/04, BE-CTRL-01/02), 6 on the mesh layer (the four section-5 markers: BE-MESH-01/04/05/06), 11 on the relay layer (the eight §5.2a properties: route and registration formats, the signed-span boundary, unknown-recipient drop, table bound, skew bound, expiry pruning, and the 0x07 domain tag), and 13 on the ledger layer (the nine §9/BE-ENV properties over `src/ledger.zig` and `src/historical.zig`: unknown-parent rejection, hash-only commitment fidelity, count advance, equivocation divergence in both directions, window enforcement including the forbidden strict maximum, anchor and revocation immutability with signer binding, causal descent on audit, and approver gating of Grant and Refusal). All eight check sets are derived from `SPEC.md` at run time, the grant set from the enumerated 0-11 list and the conformance sentence, the evidence set from the §7 tables and BE-EVID markers, the transport and session sets from the bold BE-TR markers, and the channel, mesh, relay, and ledger sets from the section-6, section-5, §5.2a, and §9 BE-CHAN/BE-GEN/BE-CTRL, BE-MESH, relay, and BE-LEDGER/BE-ENV markers, not stated by the harness. The window-bits mutant SURVIVED against the symbolic tests and was killed only after `replay_test.zig` and `reassembly_test.zig` were rewritten to literal values; the same D-027 rule drove the session KATs, which are literal bytes from an independent Python blake2s/hmac run. The ledger round's first full re-run surfaced one survivor on the grant side: BE-REV-01's new 30-day cap rejected the check-4 role-swapped subject fixture before the role check ran, so the role mutant was unfalsifiable on that witness; retightening that fixture to the PRIVILEGED_CERT window restored the kill (98cf577, D-049). Multi-file mutation results produced before `7553d21` (which restored only the current target between mutants, so a kill could be credited to a leftover mutant from a different file) were re-run under full mutant isolation; runs are chunked by a `MUTATION_DOMAIN` env filter so each domain stays under the timeout ceiling and the restore `finally` always fires (D-035); v10 keyed the relay sub-unit's eight §5.2a properties with eleven mutants over `src/relay.zig`, and v11 keys the ledger's nine §9/BE-ENV properties with thirteen mutants over `src/ledger.zig` and `src/historical.zig`. The grant denominator read 7 rather than 12 until 2026-08-07: SPEC's conformance sentence still recorded checks 3, 4, 6, 7 and 8 as delegated to the executor after task 7 had folded them into the routine, so five enforced checks sat outside the measured set. Repairing the sentence raised the denominator and those five checks now carry mutants (D-039). |
| Wall-clock time to write it | **One session** (~3 h, evening of 2026-08-05): vectors, parser, verifier, harnesses, this measurement. |

**Verdict: the measurement confirms §6, with one residual named below.** The §6.2 trigger for
reopening was parser findings in the first hour of fuzzing; the hour produced none, under ReleaseSafe
bounds checking, against vector-seeded mutations and raw random bytes. The parser module is 1048 lines across three files (split in D-032), readable in one sitting, allocates nothing (BE-WIRE-01, O3), and the Grant verifier reached 12/12
mutant kill over the modelled checks and the callback property with plain tooling. The coverage gate (SPEC §11.6) reports
the corpus and 17 of 64 exit points, where the first merge reported neither: the 47 unreached exits are the transport, mesh,
certificate, and relay entry points named in the table above. The transport parsers share the same `Cursor.need()` routing and are
exercised by the parser test suite, but they have not had their own fuzz hour yet, and the 47-exit coverage gap is that debt.
**Residual:** the coverage is
hand-instrumented, not native; that is weaker than a compiler-backed edge map, and by how much is
itself unknown. This residual is stated in `THREAT-MODEL.md` §4.6 and tracked in a follow-up issue
for re-run on the first stable toolchain pin that exposes native coverage. No §6.2 condition fired.
The decision stands.

**Costs of Zig this slice surfaced (beyond §2.1's three).** The capability work surfaced two
language-level deficits the responsible-build list did not name, and round 4 changed how the slice
pays for each. Cost one: Zig structs have no field privacy (probed empirically: external code can
both initialize and read any field), so the unforgeability Rust gets from a private field cannot be
had by hiding a field. The earlier draft paid for it with an `opaque {}` type behind a pointer and
M8's confinement of two pointer-minting builtins; round 4 deleted the capability value outright
(`verifyGrantThen`, effect as a callback), so the deficit is now paid in API shape rather than in a
forgery wall, and M8 totals zero builtins. Cost two: Zig has no aliasing discipline, so the caller
owns both the parsed struct and the buffer its fields alias, and a write to either would defeat
every check with no unsafe builtin at all. Rust makes that bug unwriteable; the earlier draft paid
for it with a runtime seal (a keyed digest recomputed at every access, BE-GRANT-03c), turning
prevention into detection. Round 4 removes that window by design instead: the effect runs inside the
routine's frame on a grant read by value, so there is no caller-owned handle left to mutate after the
checks pass, and M10 confines the single reach path to that call. This is paid in API shape and a
call-graph gate, which is weaker than Rust's compile-time aliasing control, and it says so. These are
not optional extras: they are the price of a verification routine in a language without field privacy
or aliasing control, and they are why §6.1's obligations are binding.

---

## 5. Not part of this decision

- **The protocol does not depend on the outcome.** `SPEC.md` names no language. Cross-implementation
  test vectors (§11.3) exist so a second implementation in a different language is a conformance
  test rather than a fork.
- **The executor stays Zig** in every option except §2.4 above (the rejected rewrite-MAD option).
  MAD is not being rewritten to satisfy a daemon decision.
- **Clients are separate.** Whatever a human-facing client is written in is a later, lower-stakes
  choice; it holds no approver key material unless it is the thing rendering BE-GRANT-07.

---

## 6. Decision

**Zig everywhere.** Decided 2026-08-05 by Daniel Carneiro, ahead of the §4 measurements.

**Rationale.** C1 (zero dependencies) is the constraint that is not negotiable in this project, and
Zig is the only candidate that satisfies it with no vendored code at all — `std.crypto` already
contains all four primitives. C3 follows for free: MAD is Zig, so the daemon and the reference
executor share a language, a build, and a memory discipline, with no FFI and no second toolchain.
The decision was taken on those grounds rather than on the §4 experiment, which is a legitimate call
for a research project: §4 remains available to falsify it, and §6.2 states exactly what would.

**What this decision does not do.** It does not make C2 go away. `THREAT-MODEL.md` §4.6 is now an
*active* risk rather than a conditional one: the daemon parses attacker-controlled bytes off an
unauthenticated UDP socket in a language without memory safety, and use-after-free and
out-of-bounds reads are a failure class that no BE-\* and no mutation testing can detect, because
they exercise logic and this is not a logic error.

### 6.1 Obligations this decision activates

These were listed in §2.1 as costs. With the decision made, they are binding, and an implementation
that skips any of them is not a Zig implementation of Bolina — it is a different, weaker thing:

- **O1 — `ReleaseSafe` is the shipped build.** Never `ReleaseFast`. Bounds and overflow checks stay
  on in production. For this workload the throughput difference is irrelevant and the safety
  difference is not. Enforced by SPEC §11 item 8: results from a checked build do not transfer to
  an unchecked one.
- **O2 — Fuzzing is a merge gate, not a milestone.** SPEC §11.6 is promoted: no change touching
  parsing code merges without a clean fuzz run reporting coverage and corpus. This is the substitute
  for the guarantee the compiler is not giving, and the substitute only works if it runs every time.
  *Honest record: the Round 3 merge cycle violated the "reporting coverage and corpus" half of this
  obligation, because coverage instrumentation did not yet exist on this toolchain. The crash half
  (zero OOB reads over 7.3B inputs) held throughout. Remediation landed in the same cycle:
  hand-instrumented branch counters (`src/coverage.zig`) reported 11/11 branches and the corpus for that cycle (re-measured 2026-08-06 after the transport parsers landed as 17 of 47: the six original entry points reach all 17 of their exits, while the 30 transport, mesh, and certificate exits await their seeds and harness wiring), the
  `coverage` build step reproduces them, and the residual gap (manual counters vs a native edge map)
  is tracked in #11 for re-run on the first stable pin.*
- **O3 — The parser allocates nothing and dereferences nothing it was not handed as a bounded
  slice.** BE-WIRE-01 and BE-WIRE-02 stop being tidy design and become the load-bearing safety
  property. Any allocation inside the parse path is a defect regardless of whether it crashes.
- **O4 — Zig version is pinned and recorded** with every conformance result (SPEC §11.8), **and the
  release archive is verified by content hash** — an integrity control, not only a reporting one
  (`THREAT-MODEL.md` §4.8). The language is pre-1.0; a result obtained under one compiler version is
  a result about that version.
- **O5 — The four BE-SURF rules are part of this decision, not additions to it** (SPEC §2.3). The
  pre-authentication surface stays closed and fixed-size, parser arithmetic returns errors instead of
  aborting, the parsing module stays under 1500 lines, and fuzzing is differential. *O1 says the
  shipped build aborts rather than corrupts. `THREAT-MODEL.md` §4.10 is why that is not sufficient on
  its own: an abort is a remote crash, and BE-GRANT-04 makes a crash cancel pending approvals, so the
  safety net becomes a denial-of-approval lever. O5 is what keeps O1 from being the whole answer.*

### 6.2 What would reopen this

Stated in advance so that reopening is a decision rather than a mood:

- The §4 experiment, if run, producing parser findings in the first hour of fuzzing.
- Any exploitable memory-safety defect found in the daemon after O1–O4 are all in place — that would
  mean the mitigations are not sufficient, which is the specific thing they are claimed to be.
- Sustained inability to reach SPEC §11.2 (100% mutant kill) on the §8 state machine because of
  language tooling rather than design.

None of these is expected. All three are cheap to notice, which is the point of writing them down.
