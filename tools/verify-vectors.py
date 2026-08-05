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
