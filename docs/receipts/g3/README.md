# G3 adversarial soak receipt (D-092 gate 3, CLOSED 2026-08-25)

24h03 continuous soak on dedicated owner hardware ("the old home box"), against
frozen tag v0.6.1 (`7207fb0`), ReleaseSafe by build.zig pin (SPEC 11 R4).

## Verdict

| Metric | Value |
|--------|-------|
| Window | 2026-08-24T20:10:03Z -> 2026-08-25T20:14:01Z (1443 min, single run) |
| Chaos | 110 units = 110 billion inputs, coverage ON, 0 panics |
| Differential | 36 rounds, Zig parser vs Python reference oracle, 0 divergences |
| Thermal | max 76 C (crit 100), residual throttling only, no shutdown |
| Parser exit coverage (R1) | fuzz-summary.txt: zero unreached exit points across all rounds |
| Infra failures | 0 |

## Receipt verification

`g3-soak.receipt` is a Bolina Span signed by executor `a1c71dab7e4c24a3`
(cert serial `a6069f15…`, CI-dedicated CA). Independent verification:

```bash
lastro verify -cert ci/runner-g3/cert.bin \
  -ca ci/ca/ca/ca0.pub -ca ci/ca/ca/ca1.pub < g3-soak.receipt
# receipt: VERIFIED - resource bol:a1c71dab…/git/bolina/7207fb0…/check/g3-soak-24h
# chain validated clock-free (BE-HIST-01); digest 77b0d5159af274bb…
```

Honesty notes (R2/R3 discipline):

- The observed stream records `[lastro] exit-status=1`. Root cause was kit bug
  #5 (hash step died on a vanished log under `set -e` before emitting exit 0);
  the SUMMARY line inside the signed stream shows 0 panics / 0 divergences /
  0 infra failures. The cause is preserved in the stream itself; fixed in
  tools/g3-soak.sh the same day.
- `thermal.csv` (1.4 MB) is intentionally not committed; it is covered by
  HASHES.sha256 and lives with the operator's evidence archive.
- Co-tenancy journal: gitlab-runner + apt/cron/sleep paused with timestamps;
  one user unit (`orbit-discord-bot.service`) was paused manually by the
  operator because kit bug #1 missed user units (also fixed). Its restore
  initially FAILED (kit could not manage user units from root) and required a
  manual start; see journal tail.

Kit feedback fixed same-day in tools/g3-soak.sh: #1 user-unit detection,
#2 sudo $HOME shift, #3 system-zig PATH shadow (R4), #4 diff workdir cleanup,
#5 hash-step exit poisoning, #6 phase log prefix.
