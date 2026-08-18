#!/usr/bin/env python3
"""Deterministic projector: bolina.grant-trace.v1 -> trace-constrained TLA+.

Implements section 7 of ZIG-TLA-CONFORMANCE-BRIEF.md. Given a captured trace
it validates the envelope, assigns concrete identifiers to the finite atoms of
the selected configuration, translates each event through binding.py, and
generates a module that EXTENDS Bolina and admits exactly that trace.

It deliberately does NOT restate any transition rule. The generated module
names actions and arguments; whether each is enabled is decided by Bolina.tla
under TLC. That separation is the point of the bridge (brief section 8): a
second state machine written here could drift and still agree with itself.

Exit classification is never a pass by omission. Anything the projector
cannot resolve from the trace is a refusal, not a guess.
"""

import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import binding as B


class Refusal(Exception):
    """Projection refused. classification is the receipt verdict."""

    def __init__(self, classification, detail, seq=None):
        super().__init__(detail)
        self.classification = classification
        self.detail = detail
        self.seq = seq


def canonical_bytes(ev):
    """Canonical serialization of one event for the digest chain.

    Sorted keys, no whitespace, the digest field itself excluded. The chain is
    computed after capture, never inside the verification frame (brief 5).
    """
    body = {k: v for k, v in ev.items() if k != "previous_event_sha256"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def validate_envelope(events):
    """Schema, monotonic sequence, epoch discipline, digest chain."""
    if not events:
        raise Refusal("INVALID_TRACE", "empty trace")
    prev_digest = None
    prev_seq = None
    prev_epoch = None
    for ev in events:
        seq = ev.get("sequence")
        if ev.get("schema") != B.SCHEMA:
            raise Refusal("INVALID_TRACE", "schema is %r, expected %r" % (ev.get("schema"), B.SCHEMA), seq)
        tag = ev.get("event")
        if tag not in B.BINDING:
            raise Refusal("INVALID_TRACE", "unknown event %r" % (tag,), seq)
        epoch = ev.get("process_epoch")
        if not isinstance(seq, int) or not isinstance(epoch, int):
            raise Refusal("INVALID_TRACE", "sequence and process_epoch must be integers", seq)
        if prev_seq is not None:
            # Strictly increasing within an epoch; a new epoch must be
            # explicit and restarts the sequence (brief section 5).
            if epoch == prev_epoch and seq <= prev_seq:
                raise Refusal("INVALID_TRACE", "sequence %r not strictly increasing after %r" % (seq, prev_seq), seq)
            if epoch < prev_epoch:
                raise Refusal("INVALID_TRACE", "process_epoch went backwards", seq)
        if ev.get("previous_event_sha256") != prev_digest:
            raise Refusal("INVALID_TRACE", "digest chain broken at sequence %r" % (seq,), seq)
        # Identity fields the tag has no right to carry reject the trace: this
        # is how a hand-edited or reordered trace fails loudly.
        allowed = set(B.IDENTITY_FIELDS[tag])
        for field in ("intent_id", "grant_id", "resource_id", "ledger_id"):
            if ev.get(field) is not None and field not in allowed:
                raise Refusal("INVALID_TRACE", "event %r carries %s, which it has no right to" % (tag, field), seq)
            if field in allowed and ev.get(field) is None:
                raise Refusal("INVALID_TRACE", "event %r is missing required %s" % (tag, field), seq)
        if tag == B.CHECK_TAG:
            if ev.get("check") not in B.CHECK_RANGE:
                raise Refusal("INVALID_TRACE", "verify_check carries check=%r outside 0..10" % (ev.get("check"),), seq)
        prev_digest = hashlib.sha256(canonical_bytes(ev)).hexdigest()
        prev_seq, prev_epoch = seq, epoch
    return prev_digest


class Atoms:
    """Injective assignment of trace identities to finite model atoms.

    First semantic occurrence, broken only by the encoded identifier, so the
    same raw trace always produces identical bytes (brief section 7). The
    grant assignment is NOT free: Bolina.tla fixes GrantOf(i), so a grant
    correlated to an intent must take that intent's grant atom. A trace that
    rebinds an identity midway therefore fails here rather than being
    silently renormalized.
    """

    def __init__(self, cfg):
        self.intent_atoms = list(cfg["intents"])
        self.resource_atoms = list(cfg["resources"])
        self.grant_of = dict(cfg["grant_of"])  # intent atom -> grant atom
        self.intents = {}
        self.resources = {}
        self.grants = {}   # grant identity -> grant atom
        self.grant_intent = {}  # grant identity -> intent identity

    def intent(self, ident, seq):
        if ident not in self.intents:
            if len(self.intents) >= len(self.intent_atoms):
                raise Refusal("OUT_OF_SCOPE", "trace uses more intents than the configuration declares (%d)" % len(self.intent_atoms), seq)
            self.intents[ident] = self.intent_atoms[len(self.intents)]
        return self.intents[ident]

    def resource(self, ident, seq):
        if ident not in self.resources:
            if len(self.resources) >= len(self.resource_atoms):
                raise Refusal("OUT_OF_SCOPE", "trace uses more resources than the configuration declares (%d)" % len(self.resource_atoms), seq)
            self.resources[ident] = self.resource_atoms[len(self.resources)]
        return self.resources[ident]

    def correlate(self, grant_ident, intent_ident, seq):
        """Bind a grant to an intent, once and only once."""
        prior = self.grant_intent.get(grant_ident)
        if prior is not None and prior != intent_ident:
            raise Refusal("NONCONFORMANT", "grant %s rebound from intent %s to %s midway" % (grant_ident, prior, intent_ident), seq)
        for g, i in self.grant_intent.items():
            if i == intent_ident and g != grant_ident:
                raise Refusal("NONCONFORMANT", "intent %s already bound to grant %s, now claims %s" % (intent_ident, g, grant_ident), seq)
        self.grant_intent[grant_ident] = intent_ident
        atom_i = self.intent(intent_ident, seq)
        self.grants[grant_ident] = self.grant_of[atom_i]
        return atom_i

    def intent_of_grant(self, grant_ident, seq):
        ident = self.grant_intent.get(grant_ident)
        if ident is None:
            # No begin_verify established the binding. The projector will not
            # guess which intent a grant belongs to (brief section 6).
            raise Refusal("NONCONFORMANT", "grant %s appears before any begin_verify correlated it to an intent" % (grant_ident,), seq)
        return self.intents[ident]

    def grant(self, grant_ident, seq):
        atom = self.grants.get(grant_ident)
        if atom is None:
            raise Refusal("NONCONFORMANT", "grant %s appears before any begin_verify correlated it to an intent" % (grant_ident,), seq)
        return atom


def project(events, cfg):
    """Return (steps, report), one step per event, in trace order."""
    chain_digest = validate_envelope(events)
    atoms = Atoms(cfg)
    steps = []
    for ev in events:
        tag = ev["event"]
        seq = ev["sequence"]
        kind, target, roles = B.BINDING[tag]
        if kind == B.UNBOUND:
            cls = "INSTRUMENTATION_ERROR" if tag == "trace_overflow" else "OUT_OF_SCOPE"
            raise Refusal(cls, "event %r is unbound: %s" % (tag, target), seq)
        if kind == B.STUTTER:
            steps.append(("stutter", "UNCHANGED state", seq, tag))
            continue
        args = []
        for role in roles:
            if role == B.P_INTENT:
                args.append(atoms.intent(ev["intent_id"], seq))
            elif role == B.P_RESOURCE:
                args.append(atoms.resource(ev["resource_id"], seq))
            elif role == B.P_GRANT_INTENT:
                if tag == "begin_verify":
                    args.append(atoms.correlate(ev["grant_id"], ev["intent_id"], seq))
                else:
                    args.append(atoms.intent_of_grant(ev["grant_id"], seq))
            elif role == B.P_GRANT:
                args.append(atoms.grant(ev["grant_id"], seq))
            else:
                raise Refusal("INVALID_TRACE", "unknown parameter role %r" % (role,), seq)
        text = target if not args else "%s(%s)" % (target, ", ".join(args))
        steps.append(("action", text, seq, tag))
    report = {
        "chain_digest": chain_digest,
        "events": len(events),
        "actions": sum(1 for s in steps if s[0] == "action"),
        "stutters": sum(1 for s in steps if s[0] == "stutter"),
        "intent_assignment": atoms.intents,
        "resource_assignment": atoms.resources,
        "grant_assignment": atoms.grants,
        "unobserved_actions": B.UNOBSERVED_ACTIONS,
    }
    return steps, report


MODULE_TEMPLATE = """---- MODULE {name} ----
\\* GENERATED by model/conformance/project.py. Do not edit by hand.
\\* Trace digest: {chain}
\\* Binding digest: {binding}
\\*
\\* The trace cursor admits exactly the projected events, in order. At cursor
\\* k only event k's action is offered, so a disabled action is a deadlock at
\\* that exact event rather than a silent skip. The self-loop is reachable
\\* only after every event is consumed, which keeps deadlock checking able to
\\* tell a blocked expected action from successful completion.
EXTENDS Bolina, Naturals

VARIABLES cursor, accepted
tvars == <<state, cursor, accepted>>

TraceLen == {length}

Ev(k) ==
{cases}

TraceInit ==
    /\\ Init
    /\\ cursor = 1
    /\\ accepted = FALSE

TraceStep ==
    /\\ cursor =< TraceLen
    /\\ Ev(cursor)
    /\\ cursor' = cursor + 1
    /\\ accepted' = (cursor = TraceLen)

TraceDone ==
    /\\ cursor > TraceLen
    /\\ UNCHANGED tvars

TraceNext == TraceStep \\/ TraceDone

TraceSpec == TraceInit /\\ [][TraceNext]_tvars

\\* Violated exactly when the whole trace was admitted. TLC reporting this
\\* invariant is the acceptance receipt; TLC never reporting it means some
\\* expected action was disabled.
NotAccepted == ~accepted
====
"""


def generate(name, steps, chain_digest, binding_digest):
    lines = []
    for idx, (kind, text, seq, tag) in enumerate(steps, start=1):
        head = "    " + ("CASE" if idx == 1 else "  []")
        lines.append("%s k = %d -> %s  \\* seq %s %s" % (head, idx, text, seq, tag))
    lines.append("      [] OTHER -> FALSE")
    return MODULE_TEMPLATE.format(
        name=name,
        chain=chain_digest,
        binding=binding_digest,
        length=len(steps),
        cases="\n".join(lines),
    )


def binding_digest():
    return hashlib.sha256(pathlib.Path(B.__file__).read_bytes()).hexdigest()


DEFAULT_CFG = {
    "intents": ["i1", "i2"],
    "resources": ["r1", "r2"],
    "grant_of": {"i1": "gLive", "i2": "gOld"},
}


def main(argv):
    if len(argv) != 3:
        print("usage: project.py <trace.json> <out_dir>", file=sys.stderr)
        return 2
    trace_path, out_dir = pathlib.Path(argv[1]), pathlib.Path(argv[2])
    doc = json.loads(trace_path.read_text())
    events = doc["events"] if isinstance(doc, dict) else doc
    name = "Trace_" + trace_path.stem.replace("-", "_")
    try:
        steps, report = project(events, DEFAULT_CFG)
    except Refusal as r:
        print(json.dumps({"classification": r.classification, "detail": r.detail, "sequence": r.seq}, indent=2))
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / (name + ".tla")).write_text(generate(name, steps, report["chain_digest"], binding_digest()))
    report["module"] = name
    (out_dir / (name + ".report.json")).write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps({"classification": "PROJECTED", "module": name, "events": report["events"],
                      "actions": report["actions"], "stutters": report["stutters"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
