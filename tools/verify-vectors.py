#!/usr/bin/env python3
"""Independent cross-implementation verifier for test/vectors.json (SPEC section 11.3).

This is the SECOND implementation. The Zig generator (tools/gen-vectors.zig) is the
first. If this script agrees byte-for-byte on every key, signature, digest and
address, the vector file is canonical. If any value disagrees, the bug is in
whichever implementation is wrong and the vector file must not be trusted.

Cross-checks performed:
  * Ed25519: regenerate keypair from each seed; assert pubkey matches.
  * X25519: regenerate kex pubkey from each kex_seed; assert it matches.
  * Signatures: verify every structure sig over (domain_tag || tbs) using
    cryptography's Ed25519, independent of Zig's std.crypto.
  * BLAKE2s: recompute the known-answer digests and every action/span digest.
  * Addressing: recompute overlay_addr = 0xfd || blake2s(sig_pubkey)[0..15].
  * Wire consistency: wire_hex must equal tbs_hex ++ sig (and ++ ca_sigs for cert).

Exit code 0 only if every assertion holds. Prints a per-check tally.
"""

import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

VECTORS = Path(__file__).resolve().parent.parent / "test" / "vectors.json"

passed = 0
failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL: {name}" + (f" :: {detail}" if detail else ""))


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


def blake2s(b: bytes) -> bytes:
    return hashlib.blake2s(b).digest()


def main() -> int:
    d = json.loads(VECTORS.read_text())
    print(f"Verifying {VECTORS.name} (schema_version={d['schema_version']}, "
          f"protocol={d['protocol']})\n")

    # ---- 1. primitives: BLAKE2s known answers ----
    print("[1] BLAKE2s-256 known-answer digests")
    for row in d["primitives"]["blake2s_known"]:
        got = blake2s(row["input"].encode())
        check(f"blake2s({row['input']!r})", got == hx(row["hex"]),
              f"got {got.hex()} want {row['hex']}")

    # ---- 2. keys: Ed25519 + X25519 regeneration ----
    print("[2] Key regeneration from seeds")
    for name, k in d["keys"].items():
        # Ed25519: private key in std.crypto is the 32-byte seed (RFC 8032).
        ed_priv = Ed25519PrivateKey.from_private_bytes(hx(k["seed"]))
        ed_pub = ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        check(f"{name} sig_pubkey", ed_pub == hx(k["sig_pubkey"]),
              f"got {ed_pub.hex()} want {k['sig_pubkey']}")

        x_priv = X25519PrivateKey.from_private_bytes(hx(k["kex_seed"]))
        x_pub = x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        check(f"{name} kex_pubkey", x_pub == hx(k["kex_pubkey"]),
              f"got {x_pub.hex()} want {k['kex_pubkey']}")

        # overlay_addr
        addr = bytes([0xfd]) + blake2s(hx(k["sig_pubkey"]))[:15]
        check(f"{name} overlay_addr", addr == hx(k["overlay_addr"]),
              f"got {addr.hex()} want {k['overlay_addr']}")

    # ---- 3. addressing vectors (independent recomputation) ----
    print("[3] Addressing vectors")
    for v in d["addressing"]["vectors"]:
        addr = bytes([0xfd]) + blake2s(hx(v["sig_pubkey"]))[:15]
        check(f"addr {v['sig_pubkey'][:8]}", addr == hx(v["overlay_addr"]),
              f"got {addr.hex()} want {v['overlay_addr']}")

    # ---- 4. digests ----
    print("[4] Digests (action / span / known)")
    for row in d["digests"]:
        got = blake2s(row["input_utf8"].encode())
        check(f"digest {row['name']}", got == hx(row["blake2s"]),
              f"got {got.hex()} want {row['blake2s']}")

    # ---- 5. structure signatures over (domain_tag || tbs) ----
    print("[5] Structure signatures (independent Ed25519 verify)")
    keys = d["keys"]

    def verify_struct(label: str, s: dict, default_signer: str) -> None:
        tag = hx(s["domain_tag"])
        tbs = hx(s["tbs_hex"])
        msg = tag + tbs
        # wire consistency: wire = tbs ++ sig
        pub = Ed25519PublicKey.from_public_bytes(hx(s["signer_pubkey"]))
        ok = True
        try:
            pub.verify(hx(s["sig_hex"]), msg)
        except InvalidSignature:
            ok = False
        check(f"{label} sig over tag||tbs", ok,
              f"signer={s.get('signer', default_signer)} tag={s['domain_tag']}")
        # sig_input_hex must equal tag||tbs
        check(f"{label} sig_input_hex", hx(s["sig_input_hex"]) == msg,
              f"sig_input does not equal tag({s['domain_tag']})||tbs")
        # wire consistency
        check(f"{label} wire = tbs++sig",
              hx(s["wire_hex"]) == tbs + hx(s["sig_hex"]),
              "wire_hex is not tbs_hex concatenated with sig_hex")

    st = d["structures"]
    verify_struct("envelope", st["envelope_intent"], "agent")
    verify_struct("span", st["span"], "executor")
    verify_struct("grant", st["grant"], "approver")
    verify_struct("refusal", st["refusal"], "approver")
    verify_struct("effect", st["effect"], "executor")

    # ---- 5b. Claim wire-layout cross-check (no independent sig; BE-EVID-08) ----
    print("[5b] Claim wire layout (unsigned body, authenticated inside a Utterance)")
    claim = st["claim"]
    cw = hx(claim["wire_hex"])
    off = 0
    text_len = int.from_bytes(cw[off:off + 2], "big"); off += 2
    text = cw[off:off + text_len]; off += text_len
    subj_len = int.from_bytes(cw[off:off + 2], "big"); off += 2
    subject = cw[off:off + subj_len]; off += subj_len
    conf_q8 = cw[off]; off += 1
    span_count = cw[off]; off += 1
    span_ids = [cw[off + i * 16:off + (i + 1) * 16] for i in range(span_count)]
    off += 16 * span_count
    cf = claim["fields"]
    check("claim text", text.decode("utf-8", "replace") == cf["text"], repr(text[:40]))
    check("claim subject", subject.decode("utf-8", "replace") == cf["subject"], repr(subject[:40]))
    check("claim confidence_q8", conf_q8 == cf["confidence_q8"], str(conf_q8))
    check("claim span_count", span_count == cf["span_count"], str(span_count))
    check("claim span_ids[0]", span_count >= 1 and span_ids[0] == hx(cf["span_ids_0"]))
    check("claim no trailing bytes", off == len(cw), f"trailing {len(cw) - off} bytes")

    # ---- 5c. Effect envelope body layout + inline span (SPEC 6.4) ----
    print("[5c] Effect envelope body layout (inline span + output_digest)")
    eff = st["effect"]
    ew = hx(eff["wire_hex"])
    off = 0
    check("effect env version", ew[off] == 2); off += 1
    off += 32  # channel_id
    sender = ew[off:off + 32]; off += 32
    check("effect sender == executor", sender == hx(eff["fields"]["sender_executor"]))
    seq = int.from_bytes(ew[off:off + 8], "big"); off += 8
    check("effect seq", seq == eff["fields"]["seq"], str(seq))
    pcount = ew[off]; off += 1
    check("effect parent_count == 1", pcount == 1, str(pcount))
    off += 32 * pcount  # parents
    off += 8  # ts
    check("effect body_type == 4", ew[off] == 4); off += 1
    body_len = int.from_bytes(ew[off:off + 4], "big"); off += 4
    body = ew[off:off + body_len]
    ef = eff["fields"]
    bo = 0
    check("effect body intent_id", body[bo:bo + 16] == hx(ef["body_intent_id"])); bo += 16
    check("effect body grant_id", body[bo:bo + 16] == hx(ef["body_grant_id"])); bo += 16
    check("effect body ok", body[bo] == ef["body_ok"]); bo += 1
    exit_code = int.from_bytes(body[bo:bo + 4], "big", signed=True); bo += 4
    check("effect body exit_code", exit_code == ef["body_exit_code"], str(exit_code))
    body_span_count = body[bo]; bo += 1
    check("effect body span_count == 1", body_span_count == ef["body_span_count"])
    # The inline span must be byte-identical to the standalone span vector.
    span_wire_bytes = hx(st["span"]["wire_hex"])
    check("effect inline span == standalone span wire",
          body[bo:bo + len(span_wire_bytes)] == span_wire_bytes)
    bo += len(span_wire_bytes)
    check("effect output_digest", body[bo:bo + 32] == hx(ef["body_output_digest"])); bo += 32
    check("effect body no trailing bytes", bo == len(body), f"trailing {len(body) - bo} bytes")
    # Envelope tail: after the body, exactly the 64-byte signature.
    off += body_len
    check("effect env sig placement", ew[off:off + 64] == hx(eff["sig_hex"]))
    check("effect wire fully consumed", off + 64 == len(ew))

    # cert is special: signed by CAs over (0x01 || tbs), multiple sigs.
    print("[6] Cert CA signatures")
    cert = st["cert"]
    tbs = hx(cert["tbs_hex"])
    cert_msg = hx(cert["domain_tag"]) + tbs
    check("cert sig_input_hex", hx(cert["sig_input_hex"]) == cert_msg,
          "cert sig_input is not 0x01||tbs")
    # wire = tbs ++ ca_sig_count(1) ++ for each: ca_key(32)+sig(64)
    cert_wire = hx(cert["wire_hex"])
    expected = bytearray(tbs)
    expected.append(int(cert["fields"]["ca_sig_count"]))
    for ca in cert["ca_sigs"]:
        expected += hx(ca["ca_key"])
        expected += hx(ca["sig"])
        pub = Ed25519PublicKey.from_public_bytes(hx(ca["ca_key"]))
        ok = True
        try:
            pub.verify(hx(ca["sig"]), cert_msg)
        except InvalidSignature:
            ok = False
        check(f"cert ca_sig {ca['ca_key'][:8]}", ok,
              f"CA signature did not verify over 0x01||tbs")
    check("cert wire layout", cert_wire == bytes(expected),
          "cert wire_hex does not match tbs++count++(ca_key||sig)*")

    # ---- 7. negatives: must all expect reject ----
    print("[7] Negative vectors")
    for n in d["negatives"]:
        check(f"{n['name']} expects reject", n["expect"] == "reject",
              f"got {n['expect']}")

    # ---- 8. method_id table ceilings ----
    print("[8] method_id table ceilings (q8 = round_toward_zero(conf*255))")
    expected_ceiling = {
        "DirectObservation": 242,  # 0.95
        "Documentation": 191,      # ~0.75
        "ExpertTestimony": 216,    # ~0.85
        "Inference": 165,          # ~0.65
    }
    for row in d["method_id_table"]["rows"]:
        want = expected_ceiling.get(row["class"])
        check(f"method {row['method_id']} ({row['class']}) ceiling",
              want is not None and row["ceiling_q8"] == want,
              f"got {row['ceiling_q8']} want {want}")

    print(f"\n{'='*48}")
    print(f"PASSED {passed}  FAILED {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
