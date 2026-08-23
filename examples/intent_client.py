#!/usr/bin/env python3
"""Bolina control-plane client, Python stdlib only.

Talks HTTP to a running bolina daemon's control plane (127.0.0.1:7421 by
default). No third-party packages: http.client + json + sys. The bearer
token is read from the daemon's data dir (control.token, mode 0600).

Usage:
    python3 examples/intent_client.py health
    python3 examples/intent_client.py intent <intent_id_hex32> <resource_id> <action> [rationale]
    python3 examples/intent_client.py events [since_seq]
    python3 examples/intent_client.py metrics

Boot the daemon first:
    BOLINA_CONTROL=127.0.0.1:7421 \
    BOLINA_RESOURCES="bol:<node_fp_hex>/<ns>/<id>" \
    ./zig-out/bin/bolina
"""
import http.client
import json
import os
import sys

def control_endpoint() -> tuple[str, int]:
    """Mirror the daemon: BOLINA_CONTROL=host:port, default 127.0.0.1:7421."""
    spec = os.environ.get("BOLINA_CONTROL", "127.0.0.1:7421")
    host, _, port = spec.rpartition(":")
    return (host or "127.0.0.1"), int(port)


HOST, PORT = control_endpoint()
DATA_DIR = os.environ.get("BOLINA_DATA_DIR", os.path.expanduser("~/.bolina"))


def token() -> str:
    with open(os.path.join(DATA_DIR, "control.token"), "r", encoding="ascii") as f:
        return f.read().strip()


def request(method: str, path: str, body=None, auth: bool = True):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    headers = {"Host": f"{HOST}:{PORT}"}
    if auth:
        headers["Authorization"] = f"Bearer {token()}"
    payload = json.dumps(body).encode() if body is not None else None
    if payload:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(payload))
    conn.request(method, path, payload, headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data.decode("utf-8", "replace")


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "health"

    if cmd == "health":
        status, body = request("GET", "/healthz", auth=False)
        print(f"{status} {body}")
        return 0 if status == 200 else 1

    if cmd == "intent":
        if len(sys.argv) < 5:
            print(__doc__)
            return 2
        intent_id, resource_id, action = sys.argv[2:5]
        rationale = sys.argv[5] if len(sys.argv) > 5 else ""
        status, body = request("POST", "/v1/intents", {
            "intent_id": intent_id,
            "resource_id": resource_id,
            "action": action,
            "rationale": rationale,
        })
        print(f"{status} {body}")
        # 202 = admitted (or idempotent retry), 409 = resource held,
        # 422 = unknown/foreign resource, 400 = malformed body.
        return 0 if status == 202 else 1

    if cmd == "events":
        since = sys.argv[2] if len(sys.argv) > 2 else "0"
        status, body = request("GET", f"/v1/events?since={since}")
        print(f"{status}")
        for line in body.splitlines():
            if line.startswith("data:"):
                event = json.loads(line[5:])
                print(f"  seq={event.get('seq')} kind={event.get('kind')} "
                      f"grant={str(event.get('grant_id', ''))[:16]}")
        return 0

    if cmd == "metrics":
        status, body = request("GET", "/metrics")
        print(body)
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
