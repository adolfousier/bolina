# G2 Interop Handshake - runbook for the Lastro side

Goal: ONE live Noise_IK handshake between the Go implementation (initiator)
and a real `bolina` daemon (responder), then binding frames both ways, then
one Intent envelope through the established session. That closes gate G2
(D-092): two independent implementations agreeing not just on bytes but on
authority, live.

There are no frozen vectors for the handshake on purpose: frozen vectors
cover parser-level formats. The LIVE interop is itself the proof, which is
why D-092 demands it as a distinct artifact.

## Why main, not v0.6.1

The frozen tag v0.6.1 does not compile its suite on Linux (`link_libc`
missing; fixed in `f55c4b5` on main, disclosed in the G1 reviewer pack).
Use current `origin/main` HEAD. ReleaseSafe is pinned in build.zig, so the
shipped-build property holds without flags.

## Steps

1. Build + boot the daemon (Linux box):

   ```bash
   git clone https://github.com/<owner>/bolina && cd bolina
   zig build -Doptimize=ReleaseSafe        # pin is redundant; kept explicit
   ```

2. One CA, two nodes (both present certs; BE-TR-01 binds BOTH directions):

   ```bash
   ./zig-out/bin/bolina ca init --dir ca-int
   ./zig-out/bin/bolina ca issue --ca-dir ca-int --node-dir node-daemon --scope <16hex>/<ns>/<id> ...
   ./zig-out/bin/bolina ca issue --ca-dir ca-int --node-dir node-go     --scope ...
   # copy ca-int anchors into BOTH node dirs (trust set each side loads)
   ```

   Roles: executor is enough for both; scopes are irrelevant to the
   handshake itself.

3. Daemon env (all verified against main.zig):

   ```bash
   export BOLINA_BIND=127.0.0.1:7420
   export BOLINA_DATA_DIR=$PWD/node-daemon
   export BOLINA_CONTROL=127.0.0.1:7421
   # for the stage-C money shot: declare one resource whose fingerprint
   # equals the DAEMON's own identity fp (BE-RES-04). Format is strict:
   # bol:<16 hex chars>/<ns>/<id>. Wrong length or foreign fp => 422-class
   # refusal at admission, which would fake a handshake failure.
   ./zig-out/bin/bolina
   ```

   Do NOT set BOLINA_TEST_CA (always fatal in this binary).

4. Go initiator implements the IK pattern per SPEC BE-TR-04 (mac1 tag,
   message table 4.1a). Executable reference, in reading order:
   `src/noise.zig` (Initiator, full flow) and
   `src/relay_serve_test.zig` `liveHandshake` (the working sequence).
   The initiator needs the daemon's static X25519 pubkey (header
   encryption target): `node-daemon/static.pub`.

5. Binding frames: first encrypted frame EACH way post-handshake is the
   binding frame, layout pinned in SPEC BE-TR-01a (u16be cert_len ||
   cert || Ed25519 sig over 0x05 || h, domain tag 0x05). Your codec
   already verifies certs clock-free; reuse it here.

6. Success ladder (each stage independently observable):

   - **A**: Go receives a well-formed responder reply datagram.
   - **B**: both sides validate the peer cert chain against the shared
     anchors; session stays alive (no silent drop).
   - **C** (the money shot): send ONE wire Intent envelope (your codec,
     vector-conformant) over the session, then verify admission by
     querying the intent back:

     ```bash
     curl -s -H "Authorization: Bearer $(cat "$BOLINA_DATA_DIR/control.token")" \
       http://127.0.0.1:7421/v1/intents/<intent_id_hex>
     ```

     Expect status `pending`. That single word means: handshake OK,
     binding OK, envelope parsed OK, signature OK, admission decided
     identically to Zig. G2 done. NOTE: `bolina_intents_admitted_total`
     counts ONLY HTTP-path admissions and stays 0 for wire admits - it
     is not the proof (corrected after the first live run found this).

## Evidence to bring back

Daemon stdout (handshake/bind log lines), the metrics line before/after,
and the Go-side transcript. If it works, wrap the whole drive in
`lastro run` like the soak did and the receipt cites this file's commit.
