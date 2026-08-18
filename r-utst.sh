#!/usr/bin/env bash
#
# r-utst.sh — run the full GhidraGPT headless unit-test suite.
#
# Usage:
#   ./r-utst.sh               # full mvn test + log audit + Ghidra-integrity guard
#   ./r-utst.sh --no-check    # skip the Ghidra-jar hash guard (tests only)
#   ./r-utst.sh --explain-noise   # also print the benign-noise reference table
#   ./r-utst.sh -h
#
# Exit: 0 = all tests green (+ Ghidra unchanged when check enabled), else 1.
#
set -euo pipefail

# Resolve repo root (directory containing this script) so it works from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Local, gitignored machine settings (GHIDRA_INSTALL_DIR, etc.). Source it if
# the variable isn't already in the environment, so `./r-utst.sh` just works.
if [[ -z "${GHIDRA_INSTALL_DIR:-}" && -f "$ROOT/test.env" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT/test.env"
fi

GHIDRA_DIR="${GHIDRA_INSTALL_DIR:-}"
if [[ -z "$GHIDRA_DIR" ]]; then
  printf '\033[1;31merror:\033[0m GHIDRA_INSTALL_DIR is not set.\n' >&2
  printf '  set it in the environment, or create %s (see README / test-plan.md).\n' "$ROOT/test.env" >&2
  exit 1
fi
# Jar-integrity baseline, committed under src/test/resources so the guard
# survives /tmp being cleared between sessions. Paths inside are relative to
# the Ghidra install root, so `sha256sum -c` is run from inside $GHIDRA_DIR.
BASELINE_SHA256="$ROOT/src/test/resources/ghidra-baseline.sha256"

check_enabled=1
explain_noise_flag=0
for arg in "$@"; do
  case "$arg" in
    --no-check) check_enabled=0 ;;
    --explain-noise) explain_noise_flag=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^#//'
      exit 0
      ;;
  esac
done

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Benign-noise model.
#
# The suite *deliberately* makes noise (tests that throw on purpose, Ghidra
# static-init, JVM/Mockito agent warnings). Those lines look alarming in the
# mvn output but are not failures. Instead of a hard-coded legend that drifts,
# we keep a data-driven list: one ERE per real-world source of noise.
#
#   BENIGN_RE[i]      — a regex that MATCHES an expected-benign line
#   BENIGN_REASON[i]  — the human reason it's expected
#
# The log audit (below) flags any "scary-looking" line that matches NONE of
# these, so a new unexpected error surfaces instead of being hand-waved.
# ---------------------------------------------------------------------------
BENIGN_RE=(
  'RuntimeException: (t|boom)$'
  'Error enhancing function: boom'
  'nextID called before UniversalIdGenerator'
  '^java\.lang\.Throwable$'
  'No JSON found in response|JSON parse incomplete'
  'Renamed function: FUN_'
  'Could not apply suggestion.*already in use'
  'A Java agent has been loaded dynamically|serviceability tool|Dynamic loading of agents|jdk\.instrument\.traceUsage'
  'Sharing is only supported for boot loader classes'
)
BENIGN_REASON=(
  'test fixtures that throw on purpose (InfraSmokeTest.msgHeadlessSafe; CodeAnalysisTest delegate-throws test)'
  'same suite — Msg.error logging of an intentional exception'
  'Ghidra DataType <clinit> noise when the first mock is built in the JVM'
  'same — stack frame printed alongside the nextID warning'
  'Parse/Pipeline tests exercising truncated-JSON + text-fallback paths'
  'Pipeline rename happy-path debug output'
  'SuggestionApplier duplicate-name-skip path'
  'Mockito inline-mock-maker self-attach (JDK 21) — environment, not a test'
  'JVM CDS / bootstrap-classpath note — environment'
)

# Lines that could be a real problem: exception-class heads (e.g.
# "java.lang.RuntimeException: boom", "java.lang.Throwable"), maven [ERROR],
# surefire per-test failure markers, assertion failures, build failure.
# Stack frames ("at <fqcn>...") are excluded separately — they're context.
SCARY_RE='Error|Exception|Throwable|^\[ERROR\]|<<< (FAILURE|ERROR)!|Caused by:|BUILD (FAILURE|ERROR)'
# Stack frames: "at <fqcn>..." — lines to drop from the signal set.
STACK_RE='^[[:space:]]*at [a-zA-Z0-9_$]'

# Audit the mvn log: classify every scary line as benign (matches a known
# pattern) or unexplained (a real signal the reader should look at).
log_audit() {
  local log="${1:-$LOG}"
  if [[ ! -f "$log" ]]; then
    printf '\n(log audit: no log file at %s)\n' "$log"
    return 0
  fi

  local stripped; stripped="$(sed -e 's/\x1b\[[0-9;]*m//g' "$log")"
  local bench;  bench="$(printf '%s\n' "${BENIGN_RE[@]}" | paste -sd'|' -)"

  # Scary candidates: match scary, drop pure stack frames and the always-safe
  # "[INFO] Tests run: ... Errors: 0" summary lines (a real failure is caught
  # separately by the per-class parser, which fails the run).
  local candidates
  candidates="$(printf '%s\n' "$stripped" \
      | grep -E "$SCARY_RE" \
      | grep -vE "$STACK_RE" \
      | grep -vE '^\[INFO\] Tests run:.*Failures: 0,' \
      || true)"

  local total unexplained
  total="$(printf '%s\n' "$candidates" | grep -c . || true)"
  unexplained="$(printf '%s\n' "$candidates" | grep -vE "$bench" || true)"
  local unexplained_n; unexplained_n="$(printf '%s\n' "$unexplained" | grep -c . || true)"

  local benign_n=$(( total - unexplained_n ))
  printf '\n\033[1mLog audit\033[0m: %d signal line(s) in mvn output — %d benign/expected, %d unexplained.\n' \
    "$total" "$benign_n" "$unexplained_n"

  if [[ -n "$unexplained" ]]; then
    printf '\033[1;33mUnexplained lines (not in the benign list — review these):\033[0m\n'
    printf '%s\n' "$unexplained" | head -25 | sed 's/^/    /'
  else
    printf 'All scary lines matched the benign noise list. Run with --explain-noise to see the reference table.\n'
  fi
}

# Human reference table for the benign-noise patterns (printed on --explain-noise).
explain_noise() {
  printf '\n\033[1mBenign-noise reference\033[0m — these "scary" lines are expected and mean nothing:\n'
  local i
  for i in "${!BENIGN_RE[@]}"; do
    printf '  * %s\n' "${BENIGN_REASON[$i]}"
    printf '      matches: %s\n' "${BENIGN_RE[$i]}"
  done
  printf '\nAny scary line matching NONE of these is a real signal — inspect the mvn log.\n'
}

# --- 0. Ghidra must be present (compile/classpath dependency, never executed) ---
if [[ ! -d "$GHIDRA_DIR" ]]; then
  printf '\033[1;31merror:\033[0m Ghidra install dir not found: %s\n' "$GHIDRA_DIR" >&2
  exit 1
fi

# --- 1. Run the full unit-test suite (single forked JVM) ---
# Output streams live to the console AND is captured for the log audit.
log "Running 'mvn test' ..."
mkdir -p "$ROOT/target"
LOG="$ROOT/target/r-utst.log"
set +e
mvn test 2>&1 | tee "$LOG"
tests_rc=${PIPESTATUS[0]}
set -e

if [[ $tests_rc -ne 0 ]]; then
  printf '\n\033[1;31mTESTS FAILED\033[0m (mvn test exit=%s)\n' "$tests_rc" >&2
  printf 'full log: %s | surefire: %s/target/surefire-reports\n' "$LOG" "$ROOT" >&2
  sed -e 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -E 'Tests run:.*(Failures: [1-9]|Errors: [1-9])|<<< (FAILURE|ERROR)!' >&2 || true
  log_audit "$LOG"
  printf '\033[0m\n'
  exit 1
fi

printf '\033[1;32mTESTS PASSED — full suite green (see live output above).\033[0m\n'
log_audit "$LOG"

# Compact per-class recap (name + tests run), straight from the surefire reports.
printf '\n\033[1mPer-class results:\033[0m\n'
for f in target/surefire-reports/*.txt; do
  [[ -e "$f" ]] || continue
  name="$(basename "$f" .txt)"
  line="$(grep -m1 -E 'Tests run: [0-9]+' "$f")"
  counts="$(printf '%s' "$line" | sed -E 's/.*Tests run: ([0-9]+), Failures: ([0-9]+), Errors: ([0-9]+), Skipped: ([0-9]+).*/\1 run, \2 fail, \3 err, \4 skip/')"
  printf '  %-55s %s\n' "$name" "$counts"
done

[[ $explain_noise_flag -eq 1 ]] && explain_noise

# --- 2. Phase 8 guard: Ghidra jars must be byte-identical to the baseline ---
if [[ "$check_enabled" -eq 1 ]]; then
  if [[ -f "$BASELINE_SHA256" ]]; then
    log "Verifying Ghidra jars unchanged vs $(basename "$BASELINE_SHA256") ..."
    # Manifest paths are root-relative → verify from inside the install dir.
    if ( cd "$GHIDRA_DIR" && sha256sum -c "$BASELINE_SHA256" ) >/dev/null 2>&1; then
      n_jars="$(grep -c . "$BASELINE_SHA256" 2>/dev/null || true)"
      printf '\033[1;32mGHIDRA UNCHANGED\033[0m (%s jars OK)\n' "${n_jars:-baseline}"
    else
      printf '\n\033[1;31mGHIDRA MODIFIED\033[0m — jar hashes differ from baseline:\n' >&2
      ( cd "$GHIDRA_DIR" && sha256sum -c "$BASELINE_SHA256" ) >&2 || true
      exit 1
    fi
  else
    printf '\033[1;33mWARN:\033[0m baseline %s not found; skipped Ghidra-integrity check.\n' "$BASELINE_SHA256"
  fi
  # tests must never write the user's real config dir
  if [[ -e "$HOME/.ghidragpt" ]]; then
    printf '\033[1;33mWARN:\033[0m %s/.ghidragpt exists (tests should use @TempDir, not the home dir).\n' "$HOME"
  fi
fi

printf '\n\033[1;32mDONE\033[0m\n'
