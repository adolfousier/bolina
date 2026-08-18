# SCOPE-ESTIMATE.md: resource scope for Cert (I4)

**Date:** 2026-08-18 · **Status:** estimate-first, no SPEC edit and no code before owner approval
**Scope:** v0.4 backlog item 1 (D-080 ruling 2): design what a resource scope IS before any wire byte moves.
**Authorization:** D-080 names this as the first item v0.4 opens with. This document is that design
step and nothing more. D-080's own warning governs it: designing a format under conclusion pressure
is how bad formats become permanent, so this estimate ends in questions for the owner, not in a
frozen encoding.

## 1. The residual, stated exactly

`Cert` (`src/parser/session.zig:167`) carries `version`, `role_bits`, `sig_pubkey`, `kex_pubkey`,
`not_before`, `not_after`, `name`, `group_ids` and the CA signature list. There is no resource field,
and SPEC section 3.1 says so normatively: *authorization depends on `sig_pubkey`, `role_bits`, and
`group_ids` only*.

The consequence at the capability-to-effect checkpoint: check 3 (`src/verify.zig:233`) gates the
approver on `role_bits & ROLE_APPROVER` plus durable revocation, and nothing else. Any valid
`ROLE_APPROVER` can approve a grant for any resource this executor serves. Checks 8 and 9 still bind
the grant to the intent's canonical resource and action digest, so a tricked approver cannot make the
machine run something other than what they signed (D-069 SEM_S2/S3/S5). The gap is upstream of that:
**blast radius is bounded by role, not by resource.**

D-069 ruling 3 documented it. D-080 ruling 2 accepted it as a residual and handed the design to v0.4.
Nothing below reopens either ruling; this is the design they deferred.

## 2. Budget arithmetic, and the wall

Measured today at HEAD `fe3b2be` by `tools/prumo-verify` with the pinned 0.16.0 toolchain:

| Unit | Measured | Cap | Headroom |
|---|---|---|---|
| Pre-authentication unit | 1492 | 1500 | 8 |
| Post-authentication unit | 1477 | 1500 | 23 |
| Wire-parser sub-unit (`parser/channel.zig` 399, `parser/session.zig` 253) | 652 | 652 | **0** |
| Session-state sub-unit (`binding.zig` 179, `session.zig` 215, `reassembly.zig` 240, `replay.zig` 114) | 748 | 748 | **0** |
| Sync sub-unit (`parser/sync.zig` 77) | 77 | 100 | 23 |

`parseCert` lives in the wire-parser sub-unit. `binding.validateCert` lives in the session-state
sub-unit. Both were ratcheted to their measured floor by D-052 and D-054, so **both are exactly full**.
The post-authentication cap sum leaves 23 lines across the entire unit, and BE-SURF-03 forbids raising
the sum.

`src/verify.zig` is in neither surface list. Check lines there are free; parse lines are not.

That is the binding constraint on this work, and it binds before any cryptographic argument does.
Every option in section 4 is priced in wire-parser lines first. The sequencing that follows from it:
**a compaction commit precedes the format, not the other way round** (D-052 precedent: struct-init and
banner density freed lines without deleting a single comment, then the caps ratcheted to the fresh
floor).

## 3. What a scope has to express

1. **Hierarchical.** An approver scoped to `bol:<fp>/db/` must cover `bol:<fp>/db/users` and must not
   cover `bol:<fp>/mail/queue`. A flat exact-match scope is not useful to an operator.
2. **Canonical form only.** The comparison is against the executor's canonical resource id
   (BE-RES-01, `resolver.resolveAndAdmit`), never the requester's spelling. Two spellings already
   collapse onto one canonical; scope must sit on the canonical side of that collapse or BE-RES-03 is
   silently reopened.
3. **Executor-relative or portable, pick one.** Canonical ids are `bol:` + 16 hex of
   `BLAKE2s-256(executor sig_pubkey)[0..8]` + `/ns/path`. A scope that includes the fingerprint is
   pinned to one executor; a scope over `ns/path` alone is portable and therefore means different
   resources at different executors.
4. **Fixed-size in the parser.** Variable-length fields in a pre-admission structure cost reject
   exits and surface lines, and the house pattern for exactly this problem already exists:
   `group_ids` are count-bounded 8-byte BLAKE2s-256 prefixes.
5. **No new trust root.** A scope is a bound only if it is covered by the same CA quorum that signs
   the cert, which means inside `tbs` (every byte preceding `ca_sig_count`), or in a separate
   structure carrying its own CA signature list.
6. **Fail closed, explicitly.** What an empty scope means must be written down, not inferred. Silence
   defaults to "unscoped", which is the current behaviour dressed up as a feature.

## 4. Options

| Option | Encoding | Wire-parser cost | Auditable by eye | Cert version |
|---|---|---|---|---|
| **A. Hashed scope prefixes in Cert** | `u8 scope_count` (<= 8) + `[8] scope_id` each, `scope_id = BLAKE2s-256(canonical prefix)[0..8]` | 8 to 14 lines, one bounded loop, mirrors `group_ids` | No | 3 |
| **B. Literal prefixes in Cert** | `u8 count` + per prefix `u16 len` + bytes (<= 212 each) | 20 to 30 lines, new length and bound exits | Yes | 3 |
| **C. Namespace-only scope** | `u8 count` + `[8]` hash of the `ns` component only | 6 to 10 lines | No | 3 |
| **D. Out-of-cert scope record** | new CA-signed `ApproverScope` structure, own BE-SIG-01 domain tag | 25 to 40 lines in `parser/channel.zig`, same full sub-unit | Depends on encoding | 2 (unchanged) |

**Option A** is the house pattern. Hierarchy comes from the verifier, not the encoding: walk the
grant's canonical resource id from its full form down through each ancestor prefix, hash each, match
against the scope set. The walk is bounded by the canonical grammar (path <= 180 bytes, segments
bounded by it), never by attacker-chosen input, and it runs in `verify.zig` where lines are free.
Cost is concentrated exactly where there is no room: `parseCert`.

**Option B** buys auditability with the largest surface cost of the four, in the one sub-unit that has
none. A cert whose scope you can read is worth a great deal operationally, and this is the option to
revisit if the compaction frees more than expected.

**Option C** is the cheap fallback: it bounds an approver to a namespace and never below it. Coarse,
but strictly better than role-only, and it fits in the smallest number of lines of any option here.

**Option D** leaves the frozen wire format alone: cert version stays 2, `binding.zig` stays closed,
and the cert half of the 155/155 receipt survives. Its cost is elsewhere and it is not small. A
separate record introduces its own expiry and revocation story, and it creates a presence problem:
if a missing scope record is not a refusal, absence is a bypass; if it is a refusal, every approver
needs one and the executor must know which approvers are scoped. That is executor-side policy state,
which is the thing certificates exist to avoid carrying.

**Recommendation:** A, with C as the fallback if the compaction frees fewer lines than section 2
predicts, and B revisited only if it frees many. D should be rejected for the presence problem, not
for its line cost. This recommendation is worth exactly as much as the answers to section 8.

## 5. Where the check goes

A new refusal class, `ApproverOutOfScope`, distinct from `BadApproverCert`. Distinctness is not
cosmetic: a folded error class is unfalsifiable by mutation, which is how the check-4 role mutant
went briefly unkillable (D-049).

Ordering: immediately after check 3, before check 4. The role gate must keep firing first, because
D-069 SEM_S4 pins that ordering and names any change to it as a reason to reopen the ruling. The
check needs `grant.resource_id`, which is present on entry, so no reordering of checks 8 and 9 is
required.

Numbering: the conformance sentence in SPEC section 8.2 enumerates checks 0 through 11 and that
sentence **is** the mutation denominator. D-039 is the lesson: five enforced checks sat outside the
measured set for weeks because the sentence still called them delegated. Whichever number the new
check takes, the sentence moves in the same commit as the code.

## 6. What this costs the evidence stack

| Artifact | Impact |
|---|---|
| SPEC section 3.1 | Field table, the "depends on ... only" sentence, version 2 to 3 |
| SPEC section 8.2 | Conformance sentence gains the check (denominator, D-039) |
| M1 ratchet | New marker, 114/114 becomes 115/115, high water moves |
| Mutation receipt | 155/155 at `fe3b2be` invalidated; new domain properties; full re-run required |
| `test/vectors.json` | Cert vector regenerated (`tools/gen-vectors.zig`), M3 cross-verify re-run |
| `tools/refparse.py` | Reference parser must learn the field or M4 diverges on every cert record |
| Coverage denominator | New reject exits raise 72; M9 checks the `Branch` enum one for one; M4 must reach them, which needs boundary seeds (D-056 technique), not random bytes |
| TLA+ model | Grant-path invariants gain an approver-scope precondition; D-080 already priced this as sending the model back through verification |
| `binding.zig` | The RED-TEAM-10 frozen lane reopens |

None of that is a reason not to do it. It is the reason it is a v0.4 opener and not a patch.

## 7. Slice ordering, once an option is chosen

1. Owner answers section 8 and picks an option.
2. Compaction commit in the wire-parser sub-unit, caps ratcheted to the fresh measured floor. No
   comment deletion (D-052 discipline). Full gauntlet.
3. D-0xx ruling in DECISION-LOG.md, own commit.
4. SPEC edit v0.4.0-draft, own commit, flagged before code (D-029).
5. `parseCert` field plus literal-byte vectors (D-027).
6. `verify.zig` check, `ApproverOutOfScope`, literal binding tests including the negative that a
   sibling namespace refuses and the positive that a descendant path accepts.
7. M1 ratchet committed with the binding tests.
8. `refparse.py` parity, regenerated vectors, boundary seeds for the new exits, M4 back to full
   coverage at every corpus size.
9. Harness domain plus mutants, chunked run first (D-035), then the full suite from a verified
   zero-residue tree.
10. Docs sync, push, gauntlet at pushed HEAD, closeout.

## 8. Questions the owner has to answer first

Each of these changes the encoding, so none of them can be inferred while writing it.

1. **Subject too, or approver only?** A scope on the agent cert bounds what an agent may ever be
   granted, independently of who approves. Cheaper to add now than later.
2. **Pinned or portable?** Does a scope name `bol:<fp>/ns/path` (one executor) or `ns/path` (any
   executor that serves that namespace)?
3. **Readable or opaque?** Option B costs lines that do not currently exist and buys a cert an
   operator can read. Is that worth a cap fight?
4. **Empty scope: unscoped or deny-all?** Version 3 can make it deny-all with no compatibility cost,
   because nothing is deployed. That window closes permanently the day something ships.
5. **Does scope subsume `group_ids`?** Both are 8-byte hashed identifiers used for authorization. If
   scope covers the same ground, carrying two mechanisms is a cost with no buyer.

## 9. Risks

1. **The wall is the schedule.** Zero headroom in both relevant sub-units means the compaction is not
   a preliminary, it is the first slice. If it frees fewer than roughly 15 lines, option A does not
   fit and the choice collapses to C or a cap fight.
2. **The compatibility window is open only because nothing is deployed.** A hard version 3 cutover
   with deny-all semantics is free today and expensive forever after. This is the strongest argument
   for doing it in v0.4 rather than v0.5.
3. **A scope nobody can read is a scope operators will misconfigure.** Options A and C trade
   auditability for lines. Whatever is chosen, the tooling to print a cert's scope set should land in
   the same milestone, outside the surface.
4. **The ancestor walk is a new loop in the authorization path.** It must be bounded by the canonical
   grammar and proven so by a mutant that unbounds it, or it is a DoS surface wearing a check's
   clothing.
