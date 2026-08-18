# bolina.grant-trace.v1 conformance input schema

Versioned input for the Zig-to-TLA+ projector (ZIG-TLA-CONFORMANCE-BRIEF
section 7). One file is one conformance case.

```json
{
  "schema": "bolina.grant-trace.v1",
  "case": "a01_normal_execution",
  "intent": "one sentence naming what the case exercises",
  "expect": "ACCEPTED",
  "events": [
    {"seq": 0, "tag": "receive_intent", "pc": 255, "id": "i-alpha", "id2": "r-logs-deploy", "now_ms": 1700000000000}
  ]
}
```

## Fields

| Field | Meaning |
|---|---|
| `schema` | Exactly `bolina.grant-trace.v1`. Any other value is `INVALID_TRACE`. |
| `case` | Identifier used for generated module and receipt names. |
| `expect` | Classification the case asserts. The runner fails when actual differs. |
| `seq` | Monotonic strictly increasing. A gap is legal (overflow marker), a repeat or decrease is `INVALID_TRACE`. |
| `tag` | A `grant_trace.Tag` name. Unknown tags are `INVALID_TRACE`, never silently dropped. |
| `pc` | Check index for `verify_check`, count for `expire_pending`, `255` otherwise. |
| `id` | Primary identity. Intent for the intent tags, grant for grant-path tags, ledger path for prune tags. |
| `id2` | Correlation slot, `null` or absent when the tag carries none. Canonical resource on intent tags, intent on `begin_verify` (D-082). |
| `now_ms` | Controlled clock reading, mapped to a TLA+ time bucket. |

Identifiers are opaque strings here. The Zig serializer emits FNV-1a
fingerprints as hex; the projector treats both identically because it only
ever compares them for equality and assigns them positionally.

## Why identifiers are opaque

The projector assigns TLA+ atoms by first semantic occurrence, never by
parsing the identifier. This keeps the fixture readable while producing byte
identical output for a captured trace that uses fingerprints. Assignment is
recorded in the binding manifest so the same raw trace always projects to the
same module.

## Grant to intent attribution

Grant-path events carry a grant identity, while the matching TLA+ actions take
an intent parameter. The only legitimate binding source is `begin_verify`,
which carries the grant in `id` and the intent in `id2`. A grant-path event
with no prior binding is `INVALID_TRACE`: the projector must not guess, and the
brief forbids synthesizing an unbound action.

The model ties one grant to one intent through `GrantOf`. A trace that binds
one grant to two intents, or two grants to one intent, is `INVALID_TRACE`.
