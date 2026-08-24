#!/usr/bin/env bash
# g3-soak.sh - G3 adversarial soak kit for dedicated hardware (D-092 gate G3).
#
# Runs entirely OUTSIDE src/: evidence tooling only, same class as prumo-verify.
# Target: the frozen v0.6.1 tag checkout this script lives in. build.zig pins
# optimize to ReleaseSafe (LANGUAGE.md O1), so every fuzz invocation below is
# the shipped build by construction (SPEC R4).
#
# Subcommands:
#   deps              install pinned Zig toolchain (sha256-verified) + warm build
#   pause SVC...      pause co-tenants (bot, gitlab-runner), lock sleep/updates/cron,
#                     write co-tenancy journal        [--auto] to accept detected units
#   burnin [HOURS]    thermal observation under full chaos load (default 1.5h)
#   soak   [HOURS]    continuous chaos+differential until deadline (default 24h)
#   restore           reverse pause(), print human checklist tail
#   status            what is currently running / last heartbeat
#
# All logs land in $SOAK_LOG_DIR (default ~/g3-soak-logs), NEVER in the repo
# tree: a dirty frozen tag would poison any lastro receipt taken over it.
# stdout carries only heartbeats + summaries + final log hashes, so the whole
# 24h stream fits any reasonable capture cap (BE-EVID-14 safe by design).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${SOAK_LOG_DIR:-$HOME/g3-soak-logs}"
SEEDS=(108230699740769 42 1337 999999 3735928559)   # canonical CI matrix seeds
CHAOS_CHUNK=1000000000                              # 1B inputs per chaos unit
HEARTBEAT_SECS=3600
CORPUS_BYTES_PER_REC=1275                           # measured, D-074 note

log() { printf '[g3 %s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { printf '[g3 FATAL] %s\n' "$*" >&2; exit 2; }

need_repo() { [ -f "$REPO_ROOT/build.zig" ] || die "run from a bolina checkout"; }
ensure_logdir() { mkdir -p "$LOG_DIR"; }

zig_bin() {
  ZIG="$(command -v zig || true)"
  [ -n "$ZIG" ] || ZIG="$HOME/zig-toolchain/zig-x86_64-linux-0.16.0/zig"
  [ -x "$ZIG" ] || die "no zig; run: $0 deps"
  printf '%s' "$ZIG"
}

thermal_csv() { printf '%s/thermal.csv' "$LOG_DIR"; }

start_thermal_sampler() {
  (
    while :; do
      TS=$(date -u +%FT%TZ)
      for Z in /sys/class/thermal/thermal_zone*; do
        T=$(cat "$Z/temp" 2>/dev/null || true)
        [ -n "$T" ] && printf '%s,%s,%s\n' "$TS" "$(basename "$Z")" "$T"
      done
      for C in /sys/devices/system/cpu/cpu[0-9]*; do
        CUR=$(cat "$C/cpufreq/scaling_cur_freq" 2>/dev/null || true)
        MAX=$(cat "$C/cpufreq/cpuinfo_max_freq" 2>/dev/null || true)
        [ -n "$CUR" ] && [ -n "$MAX" ] && printf '%s,%s,%s,%s\n' "$TS" "$(basename "$C")" "$CUR" "$MAX"
      done
      UPTIME_IDLE=$(awk '{print int($1)}' /proc/loadavg 2>/dev/null || true)
      sleep 30
    done
  ) >> "$(thermal_csv)" 2>/dev/null &
  SAMPLER_PID=$!
}

max_temp_last() {  # max zone temp (millidegrees C) in the trailing N seconds of CSV
  awk -F, -v since="$1" '$2 ~ /^thermal/ && $1 >= since {if ($3+0 > m) m=$3+0} END {print m+0}' \
    "$(thermal_csv)" 2>/dev/null || echo 0
}

throttle_events_since() {  # cores running <80% of max freq while CSV shows recent activity
  awk -F, -v since="$1" '$2 ~ /^cpu[0-9]+$/ && $1 >= since && ($3+0) < 0.8*($4+0) {c++} END {print c+0}' \
    "$(thermal_csv)" 2>/dev/null || echo 0
}

heartbeat() {  # HEARTBEAT <label> lines are what a lastro-wrapped stdout captures
  NOW=$(date +%s); SINCE=$((NOW - HEARTBEAT_SECS))
  MT=$(max_temp_last "$SINCE"); TH=$(throttle_events_since "$SINCE")
  log "HEARTBEAT phase=$1 elapsed_min=$2 chaos_units=$3 diff_rounds=$4 divergences=$5 panics=0 max_temp_mC=${MT} throttle_samples=${TH}"
}

cmd_deps() {
  need_repo; ensure_logdir
  VERS="0.16.0"; URL="https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz"
  SHA="70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00"
  DIR="$HOME/zig-toolchain/zig-x86_64-linux-$VERS"
  if [ ! -x "$DIR/zig" ]; then
    log "deps downloading pinned zig $VERS (O4: hash verified)"
    curl -fsSL -o /tmp/g3-zig.tar.xz "$URL"
    echo "$SHA  /tmp/g3-zig.tar.xz" | sha256sum -c - || die "toolchain hash MISMATCH (O4 violation)"
    mkdir -p "$HOME/zig-toolchain"; tar -xJf /tmp/g3-zig.tar.xz -C "$HOME/zig-toolchain"
  fi
  export PATH="$DIR:$PATH"
  test "$(zig version)" = "$VERS" || die "zig version mismatch"
  log "deps warm build (ReleaseSafe by build.zig pin) + 1k smoke fuzz"
  (cd "$REPO_ROOT" && zig build fuzz -Dcoverage -Dfuzz-seed=42 -Dfuzz-budget=1000) \
    >"$LOG_DIR/warm-build.log" 2>&1 || { tail -20 "$LOG_DIR/warm-build.log"; die "warm build failed"; }
  grep -E "FUZZ DONE|COVERAGE" "$LOG_DIR/warm-build.log" | head -4 || true
  log "deps OK"
}

detect_units() {
  systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -iE 'bot|develop|gitlab-runner' || true
}

journal() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$LOG_DIR/co-tenancy.journal"; }

cmd_pause() {
  ensure_logdir
  UNITS=(); AUTO=no
  for A in "$@"; do [ "$A" = "--auto" ] && AUTO=yes || UNITS+=("$A"); done
  if [ ${#UNITS[@]} -eq 0 ]; then
    DETECTED=$(detect_units)
    [ -n "$DETECTED" ] || log "pause: no bot/runner units detected"
    if [ "$AUTO" != yes ]; then
      echo "Detected candidates:"; echo "$DETECTED"; echo "Re-run with --auto to pause these, or name them explicitly."; exit 2
    fi
    mapfile -t UNITS <<< "$DETECTED"
  fi
  journal "BEGIN WINDOW co-tenancy snapshot follows"
  systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' \
    > "$LOG_DIR/services-before.txt"
  for U in "${UNITS[@]:-}"; do
    [ -n "$U" ] || continue
    systemctl stop "$U" && journal "PAUSED $U" || journal "PAUSE FAILED $U (recorded; continuing)"
  done
  # sleep/updates/cron lockdown (checklist: sem sleep/updates/cron); best-effort, all recorded
  systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target 2>/dev/null \
    && journal "MASKED sleep/suspend targets" || journal "mask sleep targets FAILED"
  for T in unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer cron.service crond.service; do
    systemctl disable --now "$T" 2>/dev/null && journal "DISABLED $T" || journal "skip $T (absent or refused)"
  done
  journal "END PAUSE PHASE - machine now soak-dedicated"
  log "pause complete; journal at $LOG_DIR/co-tenancy.journal"
}

run_chaos_unit() {  # $1 seed, $2 unit index
  local SEED="$1" IDX="$2"
  local LF="$LOG_DIR/chaos-seed${SEED}-u${IDX}.log"
  local RC=0
  (cd "$REPO_ROOT" && zig build fuzz -Dcoverage -Dfuzz-seed="$SEED" -Dfuzz-budget="$CHAOS_CHUNK") \
    >"$LF" 2>&1 || RC=$?
  if [ $RC -ne 0 ]; then
    log "PANIC seed=$SEED unit=$IDX exit=$RC (see $(basename "$LF")); CONTINUING soak"
    return 1
  fi
  grep -h "FUZZ DONE\|^COVERAGE" "$LF" | tail -2 >> "$LOG_DIR/fuzz-summary.txt" || true
  return 0
}

run_diff_round() {  # $1 round index, $2 seed
  local IDX="$1" SEED="$2"
  local AVAIL_KB; AVAIL_KB=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
  local BUDGET=$(( AVAIL_KB * 1024 * 35 / 100 / CORPUS_BYTES_PER_REC ))
  (( BUDGET > 100000 )) || BUDGET=100000
  (( BUDGET < 1000000 )) || BUDGET=1000000
  local LF="$LOG_DIR/diff-r${IDX}-seed${SEED}.log"
  local RC=0
  python3 "$REPO_ROOT/tools/fuzz_diff.py" --budget "$BUDGET" --seed "$SEED" \
      --workdir "$LOG_DIR/diff-work-r$IDX" --zig "$(zig_bin)" >"$LF" 2>&1 || RC=$?
  if [ $RC -eq 1 ]; then
    log "DIFF DIVERGENCE round=$IDX seed=$SEED (artifacts kept in diff-work-r$IDX); CONTINUING soak"
    DIFF_DIV=$((DIFF_DIV+1)); return 0
  elif [ $RC -ne 0 ]; then
    log "DIFF INFRA FAILURE round=$IDX exit=$RC (see $(basename "$LF"))"
    DIFF_INFRA=$((DIFF_INFRA+1)); return 0
  fi
  grep -h "^COVERAGE\|^RECEIPT" "$LF" | tail -3 >> "$LOG_DIR/fuzz-summary.txt" || true
  return 0
}

soak_loop() {  # $1 label, $2 deadline_epoch ; chaos always, differential only in soak
  local LABEL="$1" DEADLINE="$2" DIFFMODE="$3"
  START=$(date +%s); UNIT=0; ROUND=0; DIFF_DIV=0; DIFF_INFRA=0; PANICS=0
  start_thermal_sampler
  trap 'log "ABORT signal received at unit $UNIT; partial evidence preserved in $LOG_DIR"; kill $SAMPLER_PID 2>/dev/null; exit 130' INT TERM
  log "BEGIN phase=$LABEL deadline=$(date -u -d @$DEADLINE +%FT%TZ 2>/dev/null || date -u -r "$DEADLINE" +%FT%TZ) logs=$LOG_DIR"
  while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    SEED="${SEEDS[$((UNIT % ${#SEEDS[@]}))]}"
    if run_chaos_unit "$SEED" "$UNIT"; then UNIT=$((UNIT+1)); else UNIT=$((UNIT+1)); PANICS=$((PANICS+1)); fi
    ELAPSED_MIN=$(( ($(date +%s) - START) / 60 ))
    LAST_HB=${LAST_HB:-0}
    if [ $(( $(date +%s) - LAST_HB )) -ge $HEARTBEAT_SECS ]; then
      heartbeat "$LABEL" "$ELAPSED_MIN" "$UNIT" "$ROUND" "$DIFF_DIV"; LAST_HB=$(date +%s)
    fi
    if [ "$DIFFMODE" = yes ] && [ $((UNIT % 3)) -eq 0 ]; then
      ROUND=$((ROUND+1)); run_diff_round "$ROUND" "${SEEDS[$((ROUND % ${#SEEDS[@]}))]}"
    fi
  done
  kill $SAMPLER_PID 2>/dev/null || true
  TOTAL_MIN=$(( ($(date +%s) - START) / 60 ))
  MAXTEMP=$(awk -F, '$2 ~ /^thermal/{if($3+0>m)m=$3+0; }END{print m+0}' "$(thermal_csv)")
  log "SUMMARY phase=$LABEL wall_minutes=$TOTAL_MIN chaos_units=$UNIT panics=$PANICS diff_rounds=$ROUND divergences=$DIFF_DIV infra_failures=$DIFF_INFRA max_temp_mC=$MAXTEMP"
  log "LOG HASHES BEGIN"
  ( cd "$LOG_DIR" && find . -type f \( -name 'chaos-*' -o -name 'diff-*' -o -name 'thermal.csv' -o -name 'fuzz-summary.txt' -o -name 'co-tenancy.journal' \) -print0 ) \
    | while IFS= read -r -d '' F; do sha256sum "$F"; done
  log "LOG HASHES END"
  [ "$PANICS" -eq 0 ] && [ "$DIFF_DIV" -eq 0 ] && [ "$DIFF_INFRA" -eq 0 ] || exit 1
  exit 0
}

cmd_burnin() {
  need_repo; ensure_logdir
  HOURS="${1:-1.5}"
  DEADLINE=$(( $(date +%s) + $(awk -v h="$HOURS" 'BEGIN{printf "%d", h*3600}') ))
  soak_loop burnin "$DEADLINE" no
}

cmd_soak() {
  need_repo; ensure_logdir
  HOURS="${1:-24}"
  DEADLINE=$(( $(date +%s) + $(awk -v h="$HOURS" 'BEGIN{printf "%d", h*3600}') ))
  soak_loop soak "$DEADLINE" yes
}

cmd_restore() {
  ensure_logdir
  systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target 2>/dev/null \
    && journal "UNMASKED sleep targets" || journal "unmask FAILED"
  for T in apt-daily.timer apt-daily-upgrade.timer cron.service crond.service; do
    systemctl enable --now "$T" 2>/dev/null && journal "RESTORED $T" || journal "skip $T"
  done
  systemctl enable --now unattended-upgrades.service 2>/dev/null && journal "RESTORED unattended-upgrades" || true
  PAUSED=$(grep ' PAUSED ' "$LOG_DIR/co-tenancy.journal" 2>/dev/null | awk '{print $3}' | sort -u || true)
  for U in $PAUSED; do systemctl start "$U" && journal "RESUMED $U" || journal "RESUME FAILED $U"; done
  systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' \
    > "$LOG_DIR/services-after.txt"
  journal "END WINDOW"
  log "restore done. HUMAN STEP: verify the develop bot answers in #orbit-dev."
  log "before/after service snapshots in services-before.txt / services-after.txt"
}

cmd_status() {
  echo "log dir: $LOG_DIR"; ls -lt "$LOG_DIR" 2>/dev/null | head -6
  echo "--- last lines:"; tail -5 "$LOG_DIR"/soak*.log 2>/dev/null || tail -5 "$LOG_DIR"/*.log 2>/dev/null || echo none
  pgrep -af "g3-soak|bolina-fuzz|fuzz_diff" || echo "(nothing running)"
}

case "${1:-help}" in
  deps) shift; cmd_deps "$@" ;;
  pause) shift; cmd_pause "$@" ;;
  burnin) shift; cmd_burnin "$@" ;;
  soak) shift; cmd_soak "$@" ;;
  restore) cmd_restore ;;
  status) cmd_status ;;
  *) sed -n '2,25p' "$0" ;;
esac
