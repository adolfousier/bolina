# RED-TEAM-08: paper red-team of SPEC.md §8 (RT-01)

Red team: Daniel. This document was transcribed by OpenCrabs from the RT-01 review messages of
2026-08-05; the findings, attacks, and dispositions are his, and wording may differ from his
own draft in small ways.

**Evidence class: Inference.** One person reading a document. This seals nothing and does not
substitute for §11.4 (model checking) or §11.5 (adversarial evaluation). It is the first item
CONTRIBUTING.md §7 requires before any implementation, and with the dispositions below landed
in SPEC.md, that item is complete.

## Headline

No path to `EXECUTING` without a valid Grant. The ten checks of BE-GRANT-03 hold. All six
findings live in the sequencing and lifecycle AROUND the check list, not inside it.

## F1: REJECTED was unreachable

`REJECTED` sat in the §8.2 state diagram with no message able to cause it. An approver who
reviewed an intent and decided NO could only stay silent, at the cost of the full 15-minute
`T_pending` lock on the resource. Careful refusal was indistinguishable from being asleep, and
was punished by the very mechanism meant to expire stale requests: an incentive pointing the
wrong way exactly where `THREAT-MODEL.md` §4.1 says the design is weakest.

Fix: §8.5 Refusal, `body_type` 6, domain tag `0x06`, BE-GRANT-09, BE-GRANT-10.

## F2: the intent was not frozen during verification

`T_pending` could fire during the durable write in the last check, releasing the resource lock;
another agent legitimately acquires the resource; the routine then returns a verified capability
and enters `EXECUTING` on a resource someone else holds. Two conforming rules, one violated
invariant, no rule broken.

Fix: new BE-GRANT-03a: lifecycle frozen for the duration of the routine, `EXECUTING` entered
under the same lock acquisition.

## F3: check order was wrong

The durable disk write ran BEFORE the expiry comparison. Two costs: one forced write per
delivered expired Grant, at the attacker's chosen rate; and a `grant_id` marked consumed for a
Grant that was then refused, which BE-GRANT-01a finds on restart and reports as an "interrupted"
effect that never started. A check order that makes the ledger assert a fabricated effect is an
audit defect, not a performance detail.

Fix: the order is now normative in BE-GRANT-03: all pure checks first, I/O last.

## F4: intent_id was not unique among PENDING intents

`intent_id` was not required to be unique among PENDING intents; check 7 was saved only by
check 8 catching a mismatched lookup, which is unexploitable by accident rather than by
construction.

Fix: new BE-GRANT-06b, uniqueness enforced at intent admission.

## F5: the requester's certificate was not revalidated

The approver's certificate was revalidated at execution time, the requesting agent's was not.
Revoking a compromised agent therefore did not stop the work it had already requested, and
revocation is exactly what you do on discovering an agent is compromised. The asymmetry had no
justification.

Fix: new check 4, subject certificate revalidated at execution time.

## F6: Grant.version was never checked

The field existed on the wire and no check ever read it.

Fix: new check 0.

## Dispositions

| Finding | Fix landed |
|---|---|
| F1 | §8.5 Refusal: body_type 6, domain tag 0x06, BE-GRANT-09, BE-GRANT-10 |
| F2 | BE-GRANT-03a |
| F3 | BE-GRANT-03 check order made normative |
| F4 | BE-GRANT-06b |
| F5 | BE-GRANT-03 check 4 |
| F6 | BE-GRANT-03 check 0 |

## Method note for the next round

Four of the six findings were invisible when reading BE-GRANT-03 alone. They only appear when
it is read against BE-GRANT-06a, BE-GRANT-01a, and BE-REV-02, which live in different parts of
the document. Same shape as the earlier BE-TR-03 vs BE-ENV-04 contradiction: individual rules
were right; the pairs were wrong. If there is a second red-team round, aim it at rule pairs
separated by sections, not at rules in isolation.
