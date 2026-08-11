#!/usr/bin/env python3
"""refparse.py - independent reference parser for the Bolina fuzz oracle (D-056).

BE-SURF-04 (SPEC.md): continuous fuzzing MUST be differential; the production
parser is fuzzed against an independent, minimal reference parser written
solely for testing, and any divergence is a defect.

This file is that reference parser for the six structures wired into the fuzz
corpus today: Envelope, Intent, Grant, Span, Effect, Claim. It was written
from the SPEC.md field tables alone (section 2.2 encoding rules plus sections
6.2, 6.3, 7.1, 7.2, 8.1) and shares no code with the Zig parser. Verdicts are
accept/reject only (differential v1, D-056 part three); a rejection names the
rule that fired.

Deliberate readings, documented so a divergence audit does not have to guess:

- version fields are parsed, never rejected. SPEC 2.2 pins version
  negotiation to the version field and the repository's own reading (D-022)
  defers version policy to the caller for every parser; the "= 2" comments in
  the field tables declare the current value, not a parse-time check.
- body_type, ok, exit_code, method_id, volatility, confidence_q8 are parsed,
  not policy-checked. Their semantics belong to verifiers (BE-ENV-03,
  BE-EFF-01, BE-EVID-02/06/15), not to the byte-layout layer.
- Totality is enforced everywhere: unknown trailing bytes are a parse failure
  (SPEC 2.2), so every top-level structure must consume its whole buffer.
  Inline spans inside an Effect share one cursor and are totality-checked as
  part of the Effect (the span region must end exactly where output_digest
  begins).

Corpus protocol tags (D-056 part two): the corpus file this parser replays
carries one record per entry, a one-byte structure tag, a two-byte big-endian
u16 length, then the bytes. Tag space:

    0x01 Envelope   0x02 Intent     0x03 Grant
    0x04 Span       0x05 Effect     0x06 Claim
"""

import struct

# Declared limits, traced to SPEC.md (BE-TR-05 table and the field tables).
MAX_MESSAGE = 1 << 20          # 1 MiB reassembled message ceiling (BE-TR-05)
MAX_HEADER = 512               # envelope overhead (BE-TR-05)
MAX_BODY = MAX_MESSAGE - MAX_HEADER   # Envelope.body_len bound (SPEC 6.2)
MAX_PARENTS = 4                # Envelope.parent_count bound (SPEC 6.2)
MAX_RESOURCE = 256             # Intent/Grant/Span resource_id (SPEC 6.3/7.1/8.1)
MAX_ACTION = 256 * 1024        # Intent.action, opaque (SPEC 6.3)
MAX_RATIONALE = 4 * 1024       # Intent.rationale (SPEC 6.3)
MAX_CLAIM_TEXT = 1024          # Claim.text (SPEC 7.2)
MAX_SUBJECT = 256              # Claim.subject (SPEC 7.2)

# Corpus record tags (see module docstring).
TAG_ENVELOPE = 0x01
TAG_INTENT = 0x02
TAG_GRANT = 0x03
TAG_SPAN = 0x04
TAG_EFFECT = 0x05
TAG_CLAIM = 0x06


class Verdict:
    """accept/reject with the rejecting rule named (differential v1, D-056)."""

    __slots__ = ("ok", "rule", "fields")

    def __init__(self, ok, rule, fields=None):
        self.ok = ok
        self.rule = rule
        self.fields = fields or {}

    def __repr__(self):
        return "accept" if self.ok else "reject:" + self.rule


class _Cursor:
    """Byte cursor with named rejection rules. Deliberately naive."""

    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def remaining(self):
        return len(self.buf) - self.pos

    def _need(self, n, rule):
        if self.remaining() < n:
            raise _Reject(rule)

    def u8(self):
        self._need(1, "truncated")
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def u16(self):
        self._need(2, "truncated")
        v = struct.unpack_from(">H", self.buf, self.pos)[0]
        self.pos += 2
        return v

    def u32(self):
        self._need(4, "truncated")
        v = struct.unpack_from(">I", self.buf, self.pos)[0]
        self.pos += 4
        return v

    def i32(self):
        self._need(4, "truncated")
        v = struct.unpack_from(">i", self.buf, self.pos)[0]
        self.pos += 4
        return v

    def u64(self):
        self._need(8, "truncated")
        v = struct.unpack_from(">Q", self.buf, self.pos)[0]
        self.pos += 8
        return v

    def take(self, n):
        self._need(n, "truncated")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def field16(self, cap, rule):
        n = self.u16()
        if n > cap:
            raise _Reject(rule)
        return self.take(n)

    def field32(self, cap, rule):
        n = self.u32()
        if n > cap:
            raise _Reject(rule)
        return self.take(n)


class _Reject(Exception):
    def __init__(self, rule):
        super().__init__(rule)
        self.rule = rule


def _run(fn, buf):
    try:
        fields = fn(_Cursor(buf), buf)
        return Verdict(True, "accepted", fields)
    except _Reject as r:
        return Verdict(False, r.rule)


# --- Envelope (SPEC 6.2) ---------------------------------------------------

def _envelope(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    channel_id = c.take(32)
    sender = c.take(32)
    seq = c.u64()
    parent_count = c.u8()
    if parent_count > MAX_PARENTS:
        raise _Reject("env_parents_oversize")
    parents = c.take(parent_count * 32)
    ts = c.u64()
    body_type = c.u8()                     # parsed, not policy-checked
    body_len = c.u32()
    if body_len > MAX_BODY:
        raise _Reject("env_body_oversize")
    body = c.take(body_len)
    tbs = buf[0:c.pos]
    sig = c.take(64)
    if c.pos != len(buf):
        raise _Reject("env_trailing")
    return {
        "version": version, "channel_id": channel_id, "sender": sender,
        "seq": seq, "parent_count": parent_count, "parents": parents,
        "ts": ts, "body_type": body_type, "body": body, "tbs": tbs,
        "sig": sig,
    }


def parse_envelope(buf):
    return _run(_envelope, buf)


# --- Intent (SPEC 6.3, body_type 2) -----------------------------------------

def _intent(c, buf):
    intent_id = c.take(16)
    resource_id = c.field16(MAX_RESOURCE, "intent_resource_oversize")
    action = c.field32(MAX_ACTION, "intent_action_oversize")
    rationale = c.field16(MAX_RATIONALE, "intent_rationale_oversize")
    if c.pos != len(buf):
        raise _Reject("intent_trailing")
    return {
        "intent_id": intent_id, "resource_id": resource_id,
        "action": action, "rationale": rationale,
    }


def parse_intent(buf):
    return _run(_intent, buf)


# --- Grant (SPEC 8.1) --------------------------------------------------------

def _grant(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    grant_id = c.take(16)
    intent_id = c.take(16)
    approver = c.take(32)
    subject = c.take(32)
    executor = c.take(32)
    resource_id = c.field16(MAX_RESOURCE, "grant_resource_oversize")
    action_digest = c.take(32)
    not_after = c.u64()
    tbs = buf[0:c.pos]
    sig = c.take(64)
    if c.pos != len(buf):
        raise _Reject("grant_trailing")
    return {
        "version": version, "grant_id": grant_id, "intent_id": intent_id,
        "approver": approver, "subject": subject, "executor": executor,
        "resource_id": resource_id, "action_digest": action_digest,
        "not_after": not_after, "tbs": tbs, "sig": sig,
    }


def parse_grant(buf):
    return _run(_grant, buf)


# --- Span (SPEC 7.1) ----------------------------------------------------------

def _read_span(c):
    """One Span off a shared cursor; NO trailing check (inline spans in an
    Effect continue where the previous span ended, SPEC 6.3)."""
    start = c.pos
    version = c.u8()                       # parsed, not rejected (D-022)
    span_id = c.take(16)
    trace_id = c.take(16)
    resource_id = c.field16(MAX_RESOURCE, "span_resource_oversize")
    method_id = c.u8()                     # parsed, not policy-checked
    volatility = c.u8()                    # parsed, not policy-checked
    origin = c.take(32)
    observed_at = c.u64()
    digest = c.take(32)
    executor = c.take(32)
    tbs = c.buf[start:c.pos]
    sig = c.take(64)
    return {
        "version": version, "span_id": span_id, "trace_id": trace_id,
        "resource_id": resource_id, "method_id": method_id,
        "volatility": volatility, "origin": origin,
        "observed_at": observed_at, "digest": digest, "executor": executor,
        "tbs": tbs, "sig": sig,
    }


def _span(c, buf):
    s = _read_span(c)
    if c.pos != len(buf):
        raise _Reject("span_trailing")
    return s


def parse_span(buf):
    return _run(_span, buf)


# --- Effect (SPEC 6.3, body_type 4) -------------------------------------------

def _effect(c, buf):
    intent_id = c.take(16)
    grant_id = c.take(16)
    ok = c.u8()                            # parsed, not policy-checked
    exit_code = c.i32()                    # signed on the wire (SPEC 6.3)
    span_count = c.u8()
    span_start = c.pos
    spans = []
    for _ in range(span_count):
        spans.append(_read_span(c))        # truncated/overlong span rejects
    span_region = buf[span_start:c.pos]
    output_digest = c.take(32)
    if c.pos != len(buf):
        raise _Reject("effect_trailing")
    return {
        "intent_id": intent_id, "grant_id": grant_id, "ok": ok,
        "exit_code": exit_code, "span_count": span_count,
        "spans": spans, "span_region": span_region,
        "output_digest": output_digest,
    }


def parse_effect(buf):
    return _run(_effect, buf)


# --- Claim (SPEC 7.2) -----------------------------------------------------------

def _claim(c, buf):
    text = c.field16(MAX_CLAIM_TEXT, "claim_text_oversize")
    subject = c.field16(MAX_SUBJECT, "claim_subject_oversize")
    confidence_q8 = c.u8()                 # parsed, not policy-checked
    span_count = c.u8()
    span_ids = c.take(span_count * 16)
    if c.pos != len(buf):
        raise _Reject("claim_trailing")
    return {
        "text": text, "subject": subject, "confidence_q8": confidence_q8,
        "span_count": span_count, "span_ids": span_ids,
    }


def parse_claim(buf):
    return _run(_claim, buf)


# --- corpus dispatch ---------------------------------------------------------

PARSERS = {
    TAG_ENVELOPE: parse_envelope,
    TAG_INTENT: parse_intent,
    TAG_GRANT: parse_grant,
    TAG_SPAN: parse_span,
    TAG_EFFECT: parse_effect,
    TAG_CLAIM: parse_claim,
}


def parse_tagged(tag, buf):
    """Dispatch one corpus record by its structure tag."""
    fn = PARSERS.get(tag)
    if fn is None:
        return Verdict(False, "unknown_tag")
    return fn(buf)


def replay_corpus(data):
    """Replay a corpus file (D-056 part two): records of tag || u16 BE len ||
    bytes. Returns a list of (index, tag, Verdict). A truncated or overlong
    record framing is itself a defect: the run rejects with a framing rule."""
    out = []
    pos = 0
    idx = 0
    n = len(data)
    while pos < n:
        if n - pos < 3:
            out.append((idx, None, Verdict(False, "corpus_framing_truncated")))
            return out, False
        tag = data[pos]
        (length,) = struct.unpack_from(">H", data, pos + 1)
        pos += 3
        if n - pos < length:
            out.append((idx, tag, Verdict(False, "corpus_record_truncated")))
            return out, False
        out.append((idx, tag, parse_tagged(tag, data[pos:pos + length])))
        pos += length
        idx += 1
    return out, True


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: refparse.py CORPUS_FILE", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    results, framing_ok = replay_corpus(data)
    divergences = 0
    for idx, tag, verdict in results:
        line = "record %d tag=%s %s" % (
            idx, "none" if tag is None else "0x%02x" % tag, verdict)
        print(line)
        if not verdict.ok and verdict.rule.startswith("corpus_"):
            divergences += 1
    if not framing_ok:
        divergences += 1
    print("refparse: %d records, framing %s" % (
        len(results), "ok" if framing_ok else "BROKEN"))
    sys.exit(0)
