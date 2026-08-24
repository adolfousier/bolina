# G3 Soak Runbook (D-092 gate G3)

Machine under test: **the owner's old home machine** (physical hardware; no agent
SSH access by design). The agent prepares evidence tooling; the owner executes;
analysis and gate disposition return to the agent. Everything below maps 1:1 to
tools/g3-soak.sh subcommands.

## Preconditions

- Checkout of this repo AT THE FROZEN TAG:

      git fetch --tags && git checkout v0.6.1
      git rev-parse HEAD   # must print 7207fb0...

- GNU/Linux, root or sudo, python3, curl, sha256sum.
- ~6 GiB free disk for logs (they land in `~/g3-soak-logs`, never in the repo tree).

## Step 0 - deps (once, online)

    ./tools/g3-soak.sh deps

Downloads the pinned Zig 0.16.0 x86_64-linux toolchain and verifies its sha256
against the O4 hash (values embedded from tools/toolchain.json), then warm-builds
and runs a 1k-budget smoke fuzz. ReleaseSafe is NOT a flag anywhere: build.zig
pins it (LANGUAGE.md O1), so what soaks is the shipped build (R4).

## Step 1 - burn-in, 1.5h (thermal observation; co-tenants still running ON PURPOSE:
harder thermal test, and the declared co-tenancy window starts later)

    sudo ./tools/g3-soak.sh pause --auto     # see note below BEFORE using --auto
    ./tools/g3-soak.sh burnin 1.5

Watch it live: `tail -f ~/g3-soak-logs/*.log`. The THERMAL truth is in
`~/g3-soak-logs/thermal.csv` (30s samples: zone temps + per-core cur/max freq).
Throttling is recorded, not fatal; thermal SHUTDOWN ends the window per plan
(fallback then is a temporary cloud instance - decide with Daniel, do not spend
money unprompted).

`pause` refuses to guess: without `--auto` it lists detected bot/runner units and
exits. Review that list before accepting - pausing the wrong unit is worse than
re-running one command.

## Step 2 - the 24h window

If burn-in ended clean (exit 0):

    ./tools/g3-soak.sh soak 24        # run detached: nohup ./tools/g3-soak.sh soak 24 > ~/g3-soak-logs/stdout.log 2>&1 &

The machine must stay awake and alone: `pause` already masked sleep/suspend,
disabled unattended-upgrades + apt timers + cron, and journaled every action with
timestamps into `~/g3-soak-logs/co-tenancy.journal`. Record the window start time
from that journal.

What soak does until the deadline: chaos units (1B inputs each) rotating the five
canonical CI seeds, plus one differential round (Zig vs refparse.py oracle,
BE-SURF-04/D-056) after every 3rd unit, corpus auto-sized to 35% of available RAM
(clamped 100k..1M records). Panics or divergences are LOGGED AND CONTINUED - the
soak collects all evidence, exit code reports them at the end. stdout carries only
hourly HEARTBEAT lines + final SUMMARY + sha256 of every log file: the whole 24h
stream is a few KB (fits any lastro capture cap).

## Step 3 - restore (part of the gate, not an afterthought)

    sudo ./tools/g3-soak.sh restore

Un-masks sleep, re-enables timers/cron/unattended-upgrades, resumes exactly the
units the journal shows as PAUSED, writes services-after.txt. HUMAN step after:
verify the develop bot answers in #orbit-dev.

## Optional lastro receipt ("ouro", not a condition)

The stdout stream is cap-safe by construction. On the machine:

    lastro run --key <keys-dir> --namespace git \
      --path 'bolina/{sha}/soak/g3' \
      --out g3.receipt --save-output g3-stdout.log \
      -- ./tools/g3-soak.sh soak 24

Key dance (private keys NEVER travel): run `lastro keygen --dir g3-keys` on the
machine, send the two .pub hex strings to the agent, who issues an executor cert
(30d TTL, BE-REV-01) signed by the CI-dedicated CA, sends back cert.bin to drop
into g3-keys/. Verify anywhere with `lastro verify`.

## What returns to the agent for the gate receipt

Paste or transfer these five artifacts:

1. `co-tenancy.journal` (declared co-tenancy: bot paused HH:MM, runner disabled, etc.)
2. burn-in `SUMMARY` block (+ confirmation zero thermal shutdowns)
3. soak stdout.log (heartbeats + SUMMARY + LOG HASHES)
4. `thermal.csv` (or its sha256 + max temp)
5. any panic/diff-work artifacts if they exist - red evidence ships too (R2)

Gate receipt will state: machine class, co-tenancy declaration with timestamps,
continuous wall-clock duration, inputs executed, differential rounds, parser
coverage lines, and EVERY anomaly with cause (R3) - zero unexplained failures
does not mean zero log lines.

## Known limits (stated, not hidden)

- Chaos rate on unknown old hardware is unmeasured; budgets are wall-clock-driven
  so duration holds regardless of speed.
- Thermal readout depends on the machine exposing thermal_zone*/cpufreq; if absent,
  the CSV stays empty and the receipt says so instead of inventing numbers.
- Differential memory is capped by the RAM auto-size; a 4 GiB box still gets a
  valid (smaller) corpus.
