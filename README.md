# Bolina

**An encrypted overlay network in which authority is an object on the wire, not a claim in a
message.**

> **Working name.** *Bolina* is the bowline — the knot that holds under load without slipping or
> jamming. Náutico like the rest of the family (Prumo, Caravela, Nau, Orbit), six letters, ASCII.
> Change it in one line if you have better.

**Status:** active research. The specification still leads the implementation, but it is no longer
alone: the M1 milestone is built in Zig and held by mechanical gates. Everything past M1 is draft.

This is a research project, and a specification written ahead of its implementation is the normal
working mode here, not a deficiency. Unproven claims are expected — what is *not* acceptable is an
unproven claim that reads as a proven one. Each document therefore states its epistemic status at
the top, on a three-level scale: **DECLARED** (designed, not built), **TESTED** (measured under a
stated method), **PROVED** (exhaustively checked). Most items are still **DECLARED**. The ones bound
to a named test under `SPEC.md` §11.1 have moved to **TESTED**; none is **PROVED**. `SPEC.md` §11 is
the path by which each remaining item stops being declared, and `M1-AUDIT.md` records what has
actually been measured, by which method, and what the numbers below do not cover.

Marking the state is not hedging. It is the Prumo rule — calibrated guarantees, "mechanically
enforce" rather than "mathematically prove" — applied to the document that describes it. The
ambition is unchanged by saying out loud which parts have been measured.

## Implementation status

M1 only, in Zig 0.16.0, built `ReleaseSafe` with no optimisation flag exposed. `tools/prumo-verify`
prints every gate on every run and returns non-zero if an enforced one fails.

| Measure | Value | Gate |
|---|---|---|
| BE-\* items bound to a named test | 113 of 113 declared, high-water ratchet at 113 | M1, enforced |
| Test vectors cross-verified (Zig against Python `cryptography`) | 77 passed, 0 failed | M3, enforced |
| Differential fuzz divergences (production parser against an independent Python reference) | 0 over 20000 records, reaching 69 of 72 parser exit points | M4, enforced |
| Mutants killed by the test suite | 144 of 144 | M2, measured but **not** wired into the exit code |
| Pre-authentication attack surface | 1492 of 1500 lines | M5, enforced |
| Post-authentication attack surface | 1477 of 1500 lines | M11, enforced |
| Parser exit points with a matching `Branch` member | 72 of 72, zero raw error returns | M9, enforced |
| Pointer-minting builtins in `src/` | 0 | M8, enforced |
| Call sites able to reach an effect | 1, from `verifyGrantThen` | M10, enforced |

Ten gates are enforced. One is printed and excluded on purpose: **M2** (mutation testing) has a
working harness whose result is quoted above but no wiring into the verdict. That gap is visible in
the tool's own output rather than absent from it, which is the point of printing all of them.

**M4** is honest about its own reach rather than its verdict. The oracle compares the production
parser against an independent Python reference written from the SPEC field tables alone, and zero
divergences over the bounded corpus is a real result. The corpus now drives all 22 parse entry
points and reaches 69 of the 72 measured exit points. Three are still unreached and are named on
the gate row every run rather than rounded away: `data_payload_oversize`, `cert_ca_count_oversize`, and
`bind_cert_len_zero`, each needing a shape the corpus does not construct rather than a parser path
that does not exist. What the gate proves clean is still the part it reaches.

Widening it to 22 entry points is also what made the oracle earn its keep: it reported 579
divergences where the reference accepted a fragment header the parser rejected, and the finding was
that the parser had been enforcing a bound `SPEC.md` §4.5 never stated. The sentence now lives in
the specification (D-057). A second class, 25 divergences on `Control.action_type`, turned out to
be the reference putting a verifier rule at the parse layer; BE-CTRL-01 is enforced in
`src/verify.zig` with a test binding it, so the reference was corrected instead.

What this does **not** say: no part of the protocol has been model-checked, no adversarial
evaluation against a real model has been run, and no external cryptographic review of the
composition exists. See the list at the end of this file.

---

## What it is

Bolina is a mesh network and messaging protocol whose participants are both humans and autonomous
agents. It is three bands stacked, and only the third is new:

- **Identity, encrypted transport, mesh** — an offline CA issuing certificates, addresses derived
  from public keys, Noise_IK over UDP, lighthouse discovery, relay fallback. This is Nebula and
  WireGuard, adopted rather than reinvented.
- **Channels** — IRC's shape (names, membership, broadcast) and none of its trust model. Pairwise
  fan-out, no group key.
- **Attestation and capability** — *this part does not exist anywhere else.* Evidence spans signed
  by executors, confidence ceilings recomputed by the receiver, and single-use capability grants
  signed by humans that an agent is structurally unable to forge.

## Why

Every messaging protocol treats a message as opaque bytes with an authenticated *sender*. That works
when senders are humans, because a human who lies stays accountable outside the protocol.

It fails when the sender is a language model. A model states a verdict with nothing behind it, and
satisfies a confirmation flag without honouring it — not from malice, but as a reliability property
of the sender. Five production incidents (Orbit, July 2026) established the general rule:

> A gate whose satisfaction token is produced by the model is not a gate.

Bolina's answer is to stop asking the sender for the guarantee:

- A **claim** is worth no more than the signed evidence attached to it, and the receiver recomputes
  its confidence rather than believing the sender's number.
- An **action** executes because the executor verified a capability object bound to one agent, one
  executor, one resource, and one exact byte sequence — signed by a human whose key an agent is
  never issued.

## Documents

| File | What it is |
|---|---|
| **`SPEC.md`** | The protocol. Six layers, the wire format, the state machine, and every Boundary Expectation (BE-\*) an implementation must satisfy |
| **`THREAT-MODEL.md`** | Assets, five adversaries — starting with *the model itself* — security goals stated so they can be falsified, and the accepted risks named rather than hidden |
| **`LANGUAGE.md`** | Decided: **Zig**, on the zero-dependency constraint. Records the four obligations that choice activates, and what would reopen it |
| **`M1-AUDIT.md`** | What has been measured in M1 and how: the marker-by-marker keying audit, the mutation rounds, the attack-surface budget, and the addenda that correct earlier numbers |
| **`CONTRIBUTING.md`** | The merge rules, split into mechanical (`tools/prumo-verify` refuses it) and judgement (a person decides and records why) |
| **`M1-AUDIT.md`** | What has been measured in M1 and how: the marker-by-marker keying audit, the mutation rounds, the attack-surface budget, and the addenda that correct earlier numbers |
| **`CONTRIBUTING.md`** | The merge rules, split into mechanical (`tools/prumo-verify` refuses it) and judgement (a person decides and records why) |

Read `SPEC.md` §0 and §7–§8 first; those are the parts that are not borrowed.

## Constraints

- **No new cryptography.** Four primitives — Ed25519, X25519, ChaCha20-Poly1305, BLAKE2s — each with
  a published specification and public cryptanalysis. Substituting a bespoke primitive makes an
  implementation non-conformant.
- **No third-party dependencies.** A conformant node builds from this repository and a standard
  toolchain, with the network disabled. Where a language's standard library lacks a primitive, a
  reference implementation is vendored and hash-pinned — never rewritten.
- **No recursive parser.** Every network structure is flat, fixed-order, length-prefixed, parsed
  without allocation. The one field with arbitrary structure is hashed and forwarded, never
  interpreted by the daemon.
- **Zig.** Chosen because it is the only candidate whose standard library already contains all four
  primitives, and because MAD — the reference executor — is already Zig. The cost is that Zig is not
  memory-safe, so continuous fuzzing is a merge gate rather than a milestone and `ReleaseSafe` is
  the shipped build. See `LANGUAGE.md` §6.1.

## Where it comes from

Bolina is not a new idea; it is five existing pieces of work moved from inside a process onto the
wire:

| | |
|---|---|
| **Prumo** v2.2 | The enforcement pyramid and the BE-\* discipline. Its central law — an agent cannot hold the key that approves it — becomes a PKI rule (BE-ROLE-01) |
| **Gate Protocol** | Five invariants distilled from four independent projects. Bolina is those five, promoted to a message format |
| **MAD** (Zig) | The epistemic contract that a non-zero exit code is information, not failure. Normative as BE-EFF-01. MAD is the intended reference executor |
| **Orbit** (Go) | The only production-proven human approval token. Its incident history is written here as BE-GRANT-07 and -08 |
| **caravela-epistemic** (Rust) | The evidence ceilings and Brier calibration behind BE-EVID-04 |

One piece is not the author's. The four rules governing *how* conformance evidence may be produced
(`SPEC.md` §11, R1–R4) come from **slot benchmarking** by **Frinzfrinz** — a discipline for
evaluating locally-hosted models on fixed hardware. Each of its rules was paid for there with a real
incident, and one of them caught a defect in this specification within an hour of it being written:
the adversarial evaluation in §11.5 was single-sided, and would have been passed perfectly by an
executor that refused everything. Credited in `SPEC.md` §10.1 and §11.9.

## The claim, stated so it can be attacked

**No existing communication protocol makes evidentiary provenance and effect authority first-class,
cryptographically verifiable objects in the message format itself.**

Everything else here is assembled from published work. If you find a protocol that carries `SPEC.md`
§7 and §8 on the wire, the claim is false and this repository should say so.

## What has to happen before any of this can be called secure

In order, from `SPEC.md` §11:

1. ~~Red-team `SPEC.md` §8 on paper — enumerate every in-edge to `EXECUTING`.~~ **Done**, with the
   dispositions landed in `SPEC.md`: see `RED-TEAM-08.md` (§8, by the author) and `RED-TEAM-09.md`
   (§7, delegated). Both are evidence class *Inference*: one reader reading a document. That seals
   nothing on its own, which is why (2) and (3) below are unchanged by it.
2. Model-check the state machine (TLA+ or Alloy), with BE-GRANT-01/-03/-04/-06 as invariants.
3. Run an adversarial evaluation in which a real model tries to obtain an effect without a grant —
   including by prompt injection and by social-engineering an approver — and fails, **measured
   together with the rate at which properly granted operations succeed**. An executor that refuses
   everything passes the first half perfectly and is worthless; single-sided criteria get satisfied
   by degenerate implementations in full compliance with their own text.
4. Get external cryptographic review of the *composition*. The primitives are standard; putting them
   together this way is not, and composition is where protocols fail.

Until (3) produces a result, the correct description of Bolina's central guarantee is **specified,
and mechanically gated in one implementation**: not model-checked, not evaluated against a real
model, not externally reviewed. Not proved, and not secure.

## Authorship and credits

Bolina is by **Daniel Carneiro** (`loonix`), as is all the prior work listed above under "Where it
comes from".

The evaluation rules R1–R4 in `SPEC.md` §11 are **not** the author's: they come from *slot
benchmarking* by **Frinzfrinz**, credited in `SPEC.md` §10.1 and §11.9. Any future contribution from
outside goes in those sections and never into §10.2, which is reserved for the author's own work.

## Licence

**Apache License 2.0** (`LICENSE`).

Chosen over MIT for one clause: §3's express patent grant, with automatic termination for anyone
who brings a patent claim. A protocol is worth nothing unless people can implement it, and nobody
implements a specification that might carry legal risk. MIT is silent on patents; for code that is
usually fine, for a protocol with multiple independent implementations it is not.

## Contributing

See `CONTRIBUTING.md`. The rules are split into **mechanical** (CI refuses the merge) and
**judgement** (a person decides and records why), because a contribution guide made entirely of
good intentions would be the thing this protocol was written against.

Contributions written by agents are welcome and must declare it. Refusing them would be
inconsistent with building a protocol whose purpose is to make agent output verifiable; the
mechanical gates do not soften, which is exactly the point.
