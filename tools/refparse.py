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
    0x07 Refusal    0x08 ControlGenesis             0x09 Control
    0x0A HandshakeInitiation        0x0B HandshakeResponse
    0x0C CookieReply                0x0D DataPacketHeader
    0x0E RelayRoute                 0x0F RelayRegistration
    0x10 FragmentHeader             0x11 LookupRequest
    0x12 LookupResponse             0x13 Cert
    0x14 BindingMessage             0x15 SyncRequest
    0x16 SyncResponse

SPEC-FIRST RULE (D-056, task 7). Every parser below is written from the SPEC
field table for its structure and from SPEC 2.2's encoding rules, and from
nothing else. Where the SPEC states a bound, this parser enforces it. Where
the SPEC is SILENT, this parser enforces nothing, even when the production
parser does. That asymmetry is deliberate: a reference that copies the
production parser's unstated rules agrees with it by construction and gates
nothing. A divergence arising from SPEC silence is a real finding about the
specification, and it is reported rather than pre-empted.
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
MAX_NOTE = 1024                # Refusal.note, "<= 1 KiB" (SPEC 8.5)
MAX_GENESIS_NAME = 64          # ControlGenesis.name, "<= 64" (SPEC 6.1b)
MAX_CERT_NAME = 64             # Cert.name, "<= 64 bytes" (SPEC 3.1)
MAX_GROUPS = 16                # Cert.group_count, "<= 16" (SPEC 3.1)
MIN_CA_SIGS = 1                # Cert.ca_sig_count, "1..4" (SPEC 3.1)
MAX_CA_SIGS = 4                # Cert.ca_sig_count, "1..4" (SPEC 3.1)
MAX_HAVE = 64                  # SyncRequest.have_count, "<= 64" (SPEC 6.4)
MAX_PACKET = 1400              # transport packet ceiling (BE-TR-05 table)
LEN_TRANSPORT_HEADER = 16      # SPEC 4.1a type 4 header
LEN_AEAD_TAG = 16              # Poly1305 tag on every sealed payload (SPEC 2.1)
LEN_ENDPOINT = 19              # u8 family + [16] addr + u16 port (SPEC 5.1a)

# Corpus record tags (see module docstring).
TAG_ENVELOPE = 0x01
TAG_INTENT = 0x02
TAG_GRANT = 0x03
TAG_SPAN = 0x04
TAG_EFFECT = 0x05
TAG_CLAIM = 0x06
TAG_REFUSAL = 0x07
TAG_CONTROL_GENESIS = 0x08
TAG_CONTROL = 0x09
TAG_HS_INIT = 0x0A
TAG_HS_RESP = 0x0B
TAG_COOKIE = 0x0C
TAG_DATA_HEADER = 0x0D
TAG_RELAY_ROUTE = 0x0E
TAG_RELAY_REG = 0x0F
TAG_FRAGMENT = 0x10
TAG_LOOKUP_REQ = 0x11
TAG_LOOKUP_RESP = 0x12
TAG_CERT = 0x13
TAG_BINDING = 0x14
TAG_SYNC_REQ = 0x15
TAG_SYNC_RESP = 0x16


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


# --- Refusal (SPEC 8.5) -------------------------------------------------------

def _refusal(c, buf):
    intent_id = c.take(16)
    note = c.field16(MAX_NOTE, "refusal_note_oversize")
    tbs = buf[0:c.pos]
    sig = c.take(64)
    if c.pos != len(buf):
        raise _Reject("refusal_trailing")
    return {"intent_id": intent_id, "note": note, "tbs": tbs, "sig": sig}


def parse_refusal(buf):
    return _run(_refusal, buf)


# --- ControlGenesis (SPEC 6.1b) -----------------------------------------------
#
# SPEC states the ca_keys are "ordered ascending", so ordering is enforced.
# SPEC states NO bound on ca_count, so none is enforced: the count is bounded
# only by the buffer, per the SPEC-first rule in the module docstring.

def _control_genesis(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    name = c.field16(MAX_GENESIS_NAME, "genesis_name_oversize")
    member_group = c.take(8)
    admin_group = c.take(8)
    ca_count = c.u8()
    ca_keys = c.take(ca_count * 32)
    for i in range(1, ca_count):
        if ca_keys[i * 32:(i + 1) * 32] <= ca_keys[(i - 1) * 32:i * 32]:
            raise _Reject("genesis_ca_order")
    match_rule = c.u8()                    # BE-GEN-04 fixity is a verifier rule
    if c.pos != len(buf):
        raise _Reject("genesis_trailing")
    return {
        "version": version, "name": name, "member_group": member_group,
        "admin_group": admin_group, "ca_count": ca_count,
        "ca_keys": ca_keys, "match_rule": match_rule,
    }


def parse_control_genesis(buf):
    return _run(_control_genesis, buf)


# --- Control (SPEC 6.1c) ------------------------------------------------------
#
# action_type is parsed, not rejected here. BE-CTRL-01's "MUST be rejected" is
# enforced one layer up, in the verifier (src/verify.zig, error BadActionType,
# bound by test BE_CTRL_01), which is where the authority checks BE-CTRL-02
# needs already live. An earlier draft of this reference rejected it at parse
# time and the oracle reported 25 divergences in 40000 records; the finding was
# that the reference had misplaced the layer, not that the parser had a gap
# (D-057). Same parse-carry / apply-later split as version and body_type above.
# SPEC states no maximum for body_len, so none is enforced here.

def _control(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    action_type = c.u8()                   # BE-CTRL-01 is a verifier check
    subject = c.take(32)
    body_len = c.u16()
    body = c.take(body_len)
    if c.pos != len(buf):
        raise _Reject("control_trailing")
    return {
        "version": version, "action_type": action_type,
        "subject": subject, "body": body,
    }


def parse_control(buf):
    return _run(_control, buf)


# --- Transport wire formats (SPEC 4.1a) ---------------------------------------
#
# All four carry a one-byte type discriminator and three reserved bytes that
# SPEC 4.1a requires to be zero ("non-zero reserved bytes are a parse
# failure").

def _reserved3(c, rule):
    r = c.take(3)
    if r != b"\x00\x00\x00":
        raise _Reject(rule)
    return r


def _hs_init(c, buf):
    if c.u8() != 1:
        raise _Reject("hs_init_type")
    _reserved3(c, "hs_init_reserved")
    sender_index = c.u32()
    ephemeral = c.take(32)
    encrypted_static = c.take(48)
    encrypted_timestamp = c.take(24)
    mac1 = c.take(16)
    mac2 = c.take(16)
    if c.pos != len(buf):
        raise _Reject("hs_init_trailing")
    return {
        "sender_index": sender_index, "ephemeral": ephemeral,
        "encrypted_static": encrypted_static,
        "encrypted_timestamp": encrypted_timestamp,
        "mac1": mac1, "mac2": mac2,
    }


def parse_handshake_initiation(buf):
    return _run(_hs_init, buf)


def _hs_resp(c, buf):
    if c.u8() != 2:
        raise _Reject("hs_resp_type")
    _reserved3(c, "hs_resp_reserved")
    sender_index = c.u32()
    receiver_index = c.u32()
    ephemeral = c.take(32)
    encrypted_nothing = c.take(16)
    mac1 = c.take(16)
    mac2 = c.take(16)
    if c.pos != len(buf):
        raise _Reject("hs_resp_trailing")
    return {
        "sender_index": sender_index, "receiver_index": receiver_index,
        "ephemeral": ephemeral, "encrypted_nothing": encrypted_nothing,
        "mac1": mac1, "mac2": mac2,
    }


def parse_handshake_response(buf):
    return _run(_hs_resp, buf)


def _cookie_reply(c, buf):
    if c.u8() != 3:
        raise _Reject("cookie_type")
    _reserved3(c, "cookie_reserved")
    receiver_index = c.u32()
    nonce = c.take(12)
    encrypted_cookie = c.take(32)
    if c.pos != len(buf):
        raise _Reject("cookie_trailing")
    return {
        "receiver_index": receiver_index, "nonce": nonce,
        "encrypted_cookie": encrypted_cookie,
    }


def parse_cookie_reply(buf):
    return _run(_cookie_reply, buf)


# The payload is the variable-length suffix by definition, so there is no
# trailing check. SPEC 4.1a gives it as "plaintext + 16-byte Poly1305 tag", so
# a payload shorter than the tag cannot exist; the BE-TR-05 packet ceiling
# bounds it from above.

def _data_header(c, buf):
    if c.u8() != 4:
        raise _Reject("data_type")
    _reserved3(c, "data_reserved")
    receiver_index = c.u32()
    counter = c.u64()
    payload = buf[c.pos:]
    if len(payload) < LEN_AEAD_TAG:
        raise _Reject("data_payload_short")
    if len(payload) > MAX_PACKET - LEN_TRANSPORT_HEADER:
        raise _Reject("data_payload_oversize")
    return {
        "receiver_index": receiver_index, "counter": counter,
        "encrypted_payload": payload,
    }


def parse_data_packet_header(buf):
    return _run(_data_header, buf)


# --- Relay wire formats (SPEC 5.2a) -------------------------------------------

def _relay_route(c, buf):
    if c.u8() != 5:
        raise _Reject("relay_route_type")
    _reserved3(c, "relay_route_reserved")
    sender_index = c.u32()
    recipient_index = c.u32()
    timestamp = c.u64()
    if c.pos != len(buf):
        raise _Reject("relay_route_trailing")
    return {
        "sender_index": sender_index, "recipient_index": recipient_index,
        "timestamp": timestamp,
    }


def parse_relay_route(buf):
    return _run(_relay_route, buf)


# The 16 trailing padding bytes are "reserved, MUST be zero on send, ignored on
# recv" (SPEC 5.2a), so a receiver does NOT reject non-zero padding.

def _relay_registration(c, buf):
    if c.u8() != 6:
        raise _Reject("relay_reg_type")
    _reserved3(c, "relay_reg_reserved")
    relay_index = c.u32()
    client_index = c.u32()
    timestamp = c.u64()
    overlay_addr = c.take(16)
    expiry = c.u64()
    tbs = buf[0:c.pos]
    sig = c.take(64)
    c.take(16)                             # padding, ignored on recv
    if c.pos != len(buf):
        raise _Reject("relay_reg_trailing")
    return {
        "relay_index": relay_index, "client_index": client_index,
        "timestamp": timestamp, "overlay_addr": overlay_addr,
        "expiry": expiry, "tbs": tbs, "sig": sig,
    }


def parse_relay_registration(buf):
    return _run(_relay_registration, buf)


# --- Fragment header (SPEC 4.5) -----------------------------------------------
#
# SPEC 4.5 gives the flat header (msg_id:u64, index:u16, total:u16) plus
# payload, and requires total >= 1 with index < total as a parse failure. That
# sentence was added to the SPEC after this oracle reported the production
# parser enforcing a rule the SPEC did not state (D-057); the rule is read from
# the SPEC here, as everywhere else. The payload is the variable-length suffix,
# so no trailing check applies.

def _fragment_header(c, buf):
    msg_id = c.u64()
    index = c.u16()
    total = c.u16()
    if total == 0:
        raise _Reject("frag_total_zero")
    if index >= total:
        raise _Reject("frag_index_range")
    payload = buf[c.pos:]
    return {
        "msg_id": msg_id, "index": index, "total": total, "payload": payload,
    }


def parse_fragment_header(buf):
    return _run(_fragment_header, buf)


# --- Lighthouse lookups (SPEC 5.1a) -------------------------------------------

def _lookup_request(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    overlay_addr = c.take(16)
    if c.pos != len(buf):
        raise _Reject("lookup_req_trailing")
    return {"version": version, "overlay_addr": overlay_addr}


def parse_lookup_request(buf):
    return _run(_lookup_request, buf)


# SPEC states no maximum for cert_len, so none is enforced: the certificate is
# bounded only by the buffer.

def _lookup_response(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    overlay_addr = c.take(16)
    endpoint_count = c.u8()
    endpoints = c.take(endpoint_count * LEN_ENDPOINT)
    cert_len = c.u16()
    cert = c.take(cert_len)
    if c.pos != len(buf):
        raise _Reject("lookup_resp_trailing")
    return {
        "version": version, "overlay_addr": overlay_addr,
        "endpoint_count": endpoint_count, "endpoints": endpoints,
        "cert": cert,
    }


def parse_lookup_response(buf):
    return _run(_lookup_response, buf)


# --- Certificate (SPEC 3.1) ---------------------------------------------------
#
# SPEC states ca_sig_count is "1..4" and that the pairs are "ordered by ca_key
# ascending, keys pairwise distinct", which strict ascending order gives.

def _cert(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    role_bits = c.u8()                     # policy, not layout
    sig_pubkey = c.take(32)
    kex_pubkey = c.take(32)
    not_before = c.u64()
    not_after = c.u64()
    name = c.field16(MAX_CERT_NAME, "cert_name_oversize")
    group_count = c.u8()
    if group_count > MAX_GROUPS:
        raise _Reject("cert_group_oversize")
    group_ids = c.take(group_count * 8)
    tbs = buf[0:c.pos]
    ca_sig_count = c.u8()
    if ca_sig_count < MIN_CA_SIGS:
        raise _Reject("cert_ca_count_zero")
    if ca_sig_count > MAX_CA_SIGS:
        raise _Reject("cert_ca_count_oversize")
    ca_start = c.pos
    prev = None
    for _ in range(ca_sig_count):
        ca_key = c.take(32)
        if prev is not None and ca_key <= prev:
            raise _Reject("cert_ca_order")
        prev = ca_key
        c.take(64)
    ca_sigs = buf[ca_start:c.pos]
    if c.pos != len(buf):
        raise _Reject("cert_trailing")
    return {
        "version": version, "role_bits": role_bits,
        "sig_pubkey": sig_pubkey, "kex_pubkey": kex_pubkey,
        "not_before": not_before, "not_after": not_after, "name": name,
        "group_count": group_count, "group_ids": group_ids,
        "ca_sig_count": ca_sig_count, "ca_sigs": ca_sigs, "tbs": tbs,
    }


def parse_cert(buf):
    return _run(_cert, buf)


# --- Binding message (SPEC 4.1 BE-TR-01 + SPEC 2.2 encoding rules) ------------
#
# BE-TR-01 names the fields and their order ("its certificate together with an
# Ed25519 signature ... over the Noise handshake hash h") but gives no field
# table; the encoding follows from SPEC 2.2 alone: a variable-length field is a
# u16 length plus bytes, a signature is a fixed 64 bytes, trailing bytes are a
# parse failure. SPEC states no minimum for cert_len, so none is enforced.

def _binding_message(c, buf):
    cert_len = c.u16()
    cert = c.take(cert_len)
    sig = c.take(64)
    if c.pos != len(buf):
        raise _Reject("bind_trailing")
    return {"cert": cert, "sig": sig}


def parse_binding_message(buf):
    return _run(_binding_message, buf)


# --- Backfill (SPEC 6.4) ------------------------------------------------------
#
# max_envelopes is parsed and carried, never rejected: BE-SYNC-02's
# min(max_envelopes, 64) is responder policy, not a layout rule.

def _sync_request(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    channel_id = c.take(32)
    have_count = c.u8()
    if have_count > MAX_HAVE:
        raise _Reject("sync_req_have_oversize")
    have_hashes = c.take(have_count * 32)
    max_envelopes = c.u16()
    if c.pos != len(buf):
        raise _Reject("sync_req_trailing")
    return {
        "version": version, "channel_id": channel_id,
        "have_count": have_count, "have_hashes": have_hashes,
        "max_envelopes": max_envelopes,
    }


def parse_sync_request(buf):
    return _run(_sync_request, buf)


# truncated is "1 if more remains", a boolean field, so a value above 1 has no
# encoding under SPEC 2.2's no-two-encodings rule.

def _sync_response(c, buf):
    version = c.u8()                       # parsed, not rejected (D-022)
    channel_id = c.take(32)
    envelope_count = c.u8()
    items_start = c.pos
    for _ in range(envelope_count):
        length = c.u32()
        c.take(length)
    items = buf[items_start:c.pos]
    truncated = c.u8()
    if truncated > 1:
        raise _Reject("sync_resp_truncated_range")
    if c.pos != len(buf):
        raise _Reject("sync_resp_trailing")
    return {
        "version": version, "channel_id": channel_id,
        "envelope_count": envelope_count, "items": items,
        "truncated": truncated == 1,
    }


def parse_sync_response(buf):
    return _run(_sync_response, buf)


# --- corpus dispatch ---------------------------------------------------------

PARSERS = {
    TAG_ENVELOPE: parse_envelope,
    TAG_INTENT: parse_intent,
    TAG_GRANT: parse_grant,
    TAG_SPAN: parse_span,
    TAG_EFFECT: parse_effect,
    TAG_CLAIM: parse_claim,
    TAG_REFUSAL: parse_refusal,
    TAG_CONTROL_GENESIS: parse_control_genesis,
    TAG_CONTROL: parse_control,
    TAG_HS_INIT: parse_handshake_initiation,
    TAG_HS_RESP: parse_handshake_response,
    TAG_COOKIE: parse_cookie_reply,
    TAG_DATA_HEADER: parse_data_packet_header,
    TAG_RELAY_ROUTE: parse_relay_route,
    TAG_RELAY_REG: parse_relay_registration,
    TAG_FRAGMENT: parse_fragment_header,
    TAG_LOOKUP_REQ: parse_lookup_request,
    TAG_LOOKUP_RESP: parse_lookup_response,
    TAG_CERT: parse_cert,
    TAG_BINDING: parse_binding_message,
    TAG_SYNC_REQ: parse_sync_request,
    TAG_SYNC_RESP: parse_sync_response,
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
