#!/usr/bin/env python3
"""test_refparse.py - self-tests for the BE-SURF-04 reference parser (D-056).

Run with: python3 tools/test_refparse.py
No pytest, no third-party imports. Every valid wire_hex in test/vectors.json
for the six wired structures must accept; truncated, oversized, and
unknown-trailing variants must reject with a named rule.
"""

import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import refparse  # noqa: E402

REPO = os.path.dirname(HERE)
VECTORS = os.path.join(REPO, "test", "vectors.json")

failures = []


def check(name, cond, detail=""):
    if cond:
        print("PASS  %s" % name)
    else:
        print("FAIL  %s  %s" % (name, detail))
        failures.append(name)


def expect_accept(name, verdict):
    check(name, verdict.ok, "got %r" % verdict)


def expect_reject(name, verdict, rule):
    check(name, (not verdict.ok) and verdict.rule == rule,
          "got %r, wanted reject:%s" % (verdict, rule))


def h(hexstr):
    return bytes.fromhex(hexstr)


def main():
    vectors = json.load(open(VECTORS))["structures"]

    # --- valid vectors accept ---------------------------------------------
    env_wire = h(vectors["envelope_intent"]["wire_hex"])
    env_v = refparse.parse_envelope(env_wire)
    expect_accept("envelope: valid vector accepts", env_v)

    intent_body = env_v.fields.get("body", b"")
    expect_accept("intent: envelope body accepts",
                  refparse.parse_intent(intent_body))

    grant_wire = h(vectors["grant"]["wire_hex"])
    expect_accept("grant: valid vector accepts",
                  refparse.parse_grant(grant_wire))

    span_wire = h(vectors["span"]["wire_hex"])
    expect_accept("span: valid vector accepts",
                  refparse.parse_span(span_wire))

    eff_env_wire = h(vectors["effect"]["wire_hex"])
    eff_env_v = refparse.parse_envelope(eff_env_wire)
    expect_accept("effect-envelope: valid vector accepts", eff_env_v)
    effect_body = eff_env_v.fields.get("body", b"")
    eff_v = refparse.parse_effect(effect_body)
    expect_accept("effect: envelope body accepts", eff_v)
    check("effect: inline span count matches vector",
          eff_v.ok and eff_v.fields["span_count"] ==
          vectors["effect"]["fields"]["body_span_count"],
          "span_count mismatch")

    claim_wire = h(vectors["claim"]["wire_hex"])
    expect_accept("claim: valid vector accepts",
                  refparse.parse_claim(claim_wire))

    # --- truncated variants reject ----------------------------------------
    for name, wire, fn in [
        ("envelope", env_wire, refparse.parse_envelope),
        ("grant", grant_wire, refparse.parse_grant),
        ("span", span_wire, refparse.parse_span),
        ("claim", claim_wire, refparse.parse_claim),
    ]:
        expect_reject("%s: truncated last byte rejects" % name,
                      fn(wire[:-1]), "truncated")
        expect_reject("%s: empty input rejects" % name,
                      fn(b""), "truncated")
        expect_reject("%s: half input rejects" % name,
                      fn(wire[:len(wire) // 2]), "truncated")
    expect_reject("intent: truncated rejects",
                  refparse.parse_intent(intent_body[:-1]), "truncated")
    expect_reject("effect: truncated rejects",
                  refparse.parse_effect(effect_body[:-1]), "truncated")

    # --- unknown trailing bytes reject (SPEC 2.2 totality) -----------------
    expect_reject("envelope: trailing byte rejects",
                  refparse.parse_envelope(env_wire + b"\x00"),
                  "env_trailing")
    expect_reject("intent: trailing byte rejects",
                  refparse.parse_intent(intent_body + b"\x00"),
                  "intent_trailing")
    expect_reject("grant: trailing byte rejects",
                  refparse.parse_grant(grant_wire + b"\x00"),
                  "grant_trailing")
    expect_reject("span: trailing byte rejects",
                  refparse.parse_span(span_wire + b"\x00"),
                  "span_trailing")
    expect_reject("effect: trailing byte rejects",
                  refparse.parse_effect(effect_body + b"\x00"),
                  "effect_trailing")
    expect_reject("claim: trailing byte rejects",
                  refparse.parse_claim(claim_wire + b"\x00"),
                  "claim_trailing")

    # --- declared caps reject ----------------------------------------------
    env5 = bytearray(env_wire)
    env5[73] = 5  # parent_count at offset 1+32+32+8 = 73
    expect_reject("envelope: parent_count 5 rejects",
                  refparse.parse_envelope(bytes(env5)),
                  "env_parents_oversize")

    bigbody = bytearray(env_wire)
    struct.pack_into(">I", bigbody, 83, refparse.MAX_BODY + 1)
    expect_reject("envelope: body_len above MAX_BODY rejects",
                  refparse.parse_envelope(bytes(bigbody)),
                  "env_body_oversize")

    bad_res = bytearray(intent_body)
    struct.pack_into(">H", bad_res, 16, refparse.MAX_RESOURCE + 1)
    expect_reject("intent: resource_len 257 rejects",
                  refparse.parse_intent(bytes(bad_res)),
                  "intent_resource_oversize")

    bad_text = bytearray(claim_wire)
    struct.pack_into(">H", bad_text, 0, refparse.MAX_CLAIM_TEXT + 1)
    expect_reject("claim: text_len 1025 rejects",
                  refparse.parse_claim(bytes(bad_text)),
                  "claim_text_oversize")

    bad_count = bytearray(claim_wire)
    bad_count[-17] = 255  # span_count far beyond remaining bytes
    expect_reject("claim: span_ids beyond buffer rejects",
                  refparse.parse_claim(bytes(bad_count)), "truncated")

    # --- synthetic round trip ------------------------------------------------
    claim2 = (struct.pack(">H", 3) + b"abc"
              + struct.pack(">H", 2) + b"xy"
              + bytes([216]) + bytes([2])
              + bytes(32))
    v2 = refparse.parse_claim(claim2)
    expect_accept("claim: synthetic two-span accepts", v2)
    check("claim: synthetic fields decode",
          v2.ok and v2.fields["text"] == b"abc"
          and v2.fields["subject"] == b"xy"
          and v2.fields["confidence_q8"] == 216
          and v2.fields["span_count"] == 2,
          "field mismatch")

    # --- corpus framing -------------------------------------------------------
    def rec(tag, payload):
        return bytes([tag]) + struct.pack(">H", len(payload)) + payload

    corpus = (rec(refparse.TAG_ENVELOPE, env_wire)
              + rec(refparse.TAG_INTENT, intent_body)
              + rec(refparse.TAG_GRANT, grant_wire)
              + rec(refparse.TAG_SPAN, span_wire)
              + rec(refparse.TAG_EFFECT, effect_body)
              + rec(refparse.TAG_CLAIM, claim_wire))
    results, framing_ok = refparse.replay_corpus(corpus)
    check("corpus: six records replay, framing ok",
          framing_ok and len(results) == 6,
          "framing_ok=%s n=%d" % (framing_ok, len(results)))
    check("corpus: every record accepts",
          all(v.ok for _, _, v in results),
          repr([(i, v) for i, _, v in results if not v.ok]))

    results_bad, framing_bad = refparse.replay_corpus(corpus[:-1])
    check("corpus: truncated final record breaks framing",
          not framing_bad
          and results_bad[-1][2].rule in ("corpus_record_truncated",),
          repr(results_bad[-1][2]))

    unknown = refparse.parse_tagged(0x7F, b"\x00")
    expect_reject("corpus: unknown tag rejects", unknown, "unknown_tag")

    # --- verdict ----------------------------------------------------------------
    print()
    if failures:
        print("refparse tests: %d FAILURE(S): %s" % (len(failures), failures))
        return 1
    print("refparse tests: all green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
