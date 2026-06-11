#!/usr/bin/env bash
# day1-gate.sh - VERDICT Day-1 go/no-go gate (checklist item 2; spec Open Issues #1-#3).
#
# Run ON THE SIFT VM, from anywhere:
#   ./scripts/day1-gate.sh [case_dir]        # default case_dir: /cases/szechuan
#
# Steps (each prints PASS/FAIL):
#   1. Forensic Binary Matrix  - python -m verdict_mcp.binaries --check
#   2. Dataset MD5s            - delegates to scripts/get-dataset.sh (idempotent:
#                                verifies cached files, resumes missing ones)
#   3. Volatility 3 pslist     - against BOTH memory captures. The Server 2012 R2
#                                DC image is the known weak spot (spec Open Issue
#                                #2): a DC failure is a documented PIVOT, not a
#                                blocker. A desktop failure IS a blocker.
#   4. Verdict                 - GO / PIVOT / NO-GO summary to paste back.
#
# Notes:
#   - pslist on a multi-GB image takes MINUTES; Vol3 may also download Windows
#     symbol packs on first contact with each image (needs network). Per-image
#     timeout: $VERDICT_PSLIST_TIMEOUT seconds (default 900).
#   - Gate artifacts (binaries JSON record, pslist outputs) land in
#     <repo>/runs/day1-gate/ for the gate record.

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
CASE_DIR="${1:-/cases/szechuan}"
PSLIST_TIMEOUT="${VERDICT_PSLIST_TIMEOUT:-900}"
GATE_DIR="$REPO_DIR/runs/day1-gate"
mkdir -p "$GATE_DIR"

bold()   { printf '\n=== %s ===\n' "$*"; }
log()    { printf '[day1-gate] %s\n' "$*"; }
result() { printf '[day1-gate] %-28s %s\n' "$1" "$2"; }

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  log "FATAL: no python3/python on PATH"; exit 1
fi

RES_BINARIES=FAIL RES_DATASET=FAIL RES_MEM_DC=FAIL RES_MEM_DESKTOP=FAIL

# ---------------------------------------------------------------- step 1: matrix
bold "STEP 1/4: Forensic Binary Matrix (binaries --check)"
if (cd "$REPO_DIR" && "$PY" -m verdict_mcp.binaries --check); then
  RES_BINARIES=PASS
fi
(cd "$REPO_DIR" && "$PY" -m verdict_mcp.binaries --check --json \
  > "$GATE_DIR/binaries-check.json" 2>/dev/null) || true
result "binary matrix:" "$RES_BINARIES"
[ "$RES_BINARIES" = PASS ] || log "fix red rows (see table above) before re-running; record saved to runs/day1-gate/binaries-check.json"

# --------------------------------------------------------------- step 2: dataset
bold "STEP 2/4: Dataset MD5 verification (delegating to get-dataset.sh)"
log "idempotent: already-verified archives are skipped; missing/partial ones resume."
log "if the download is still in flight this step runs long - safe to Ctrl-C and re-run."
if "$SCRIPT_DIR/get-dataset.sh" "$CASE_DIR"; then
  RES_DATASET=PASS
fi
result "dataset MD5s + extraction:" "$RES_DATASET"

# -------------------------------------------------------- step 3: vol3 vs memory
bold "STEP 3/4: Volatility 3 windows.pslist on BOTH memory captures"

find_vol() {
  # Mirror binaries.py candidate order: vol3, vol, python -m volatility3.
  # ($c is intentionally unquoted below so "python3 -m volatility3" word-splits.)
  local c out
  for c in vol3 vol "$PY -m volatility3"; do
    out="$($c -h 2>&1 || true)"
    # match "volatility" unspaced: `vol -h` only contains it via plugin names
    # like volatility3.plugins.windows.pslist (same fix as binaries.py)
    case "${out,,}" in
      *volatility*) echo "$c"; return 0 ;;
    esac
  done
  return 1
}

run_pslist() { # $1 = label, $2 = image path; returns 0 on PASS
  local label="$1" image="$2" out rc
  out="$GATE_DIR/pslist-$label.txt"
  log "pslist on $image"
  log "(this can take several minutes on a multi-GB image; first run may download symbols - timeout ${PSLIST_TIMEOUT}s)"
  # $VOL is intentionally unquoted: it may be "python3 -m volatility3".
  if command -v timeout >/dev/null 2>&1; then
    timeout "$PSLIST_TIMEOUT" $VOL -f "$image" windows.pslist >"$out" 2>&1
  else
    $VOL -f "$image" windows.pslist >"$out" 2>&1
  fi
  rc=$?
  if [ $rc -eq 0 ] && grep -qiE '(^|[[:space:]])System([[:space:]]|$)' "$out"; then
    log "$label pslist OK - output: $out"
    return 0
  fi
  log "$label pslist FAILED (exit $rc) - last lines of $out:"
  tail -n 8 "$out" | sed 's/^/[day1-gate]   /'
  return 1
}

if VOL="$(find_vol)"; then
  log "using Volatility 3 via: $VOL"
  # Locate memory captures (extracted by step 2). DC memory ships as
  # citadeldc01.mem; desktop as DESKTOP-SDN1RPT memory.
  MEM_FILES="$(find "$CASE_DIR" -type f \( -iname '*.mem' -o -iname '*.vmem' -o -iname '*.raw' \) 2>/dev/null)"
  DC_MEM="$(echo "$MEM_FILES" | grep -iE 'dc01|citadel' | head -n 1)"
  DT_MEM="$(echo "$MEM_FILES" | grep -ivE 'dc01|citadel' | grep -iE 'sdn1rpt|desktop' | head -n 1)"

  if [ -n "$DC_MEM" ]; then
    run_pslist dc01 "$DC_MEM" && RES_MEM_DC=PASS
  else
    log "DC memory capture (*.mem matching dc01/citadel) not found under $CASE_DIR"
  fi
  if [ -n "$DT_MEM" ]; then
    run_pslist desktop "$DT_MEM" && RES_MEM_DESKTOP=PASS
  else
    log "desktop memory capture (*.mem matching sdn1rpt/desktop) not found under $CASE_DIR"
  fi
else
  log "Volatility 3 not found (tried vol3, vol, $PY -m volatility3) - memory steps FAIL"
fi
result "vol3 pslist (DC01 2012 R2):" "$RES_MEM_DC"
result "vol3 pslist (DESKTOP):"      "$RES_MEM_DESKTOP"

if [ "$RES_MEM_DC" = FAIL ] && [ "$RES_MEM_DESKTOP" = PASS ]; then
  log "DC pslist failure is the KNOWN weak spot (Vol3 symbols vs Server 2012 R2,"
  log "spec Open Issue #2). This is a PIVOT, not a blocker. Documented fallback:"
  log "  -> memory analysis uses the DESKTOP capture;"
  log "  -> DC01 is covered via its disk artifacts (evtx, registry, MFT, timeline)."
fi

# --------------------------------------------------------------- step 4: verdict
bold "STEP 4/4: Gate verdict"
if [ "$RES_BINARIES" = PASS ] && [ "$RES_DATASET" = PASS ] && [ "$RES_MEM_DESKTOP" = PASS ]; then
  if [ "$RES_MEM_DC" = PASS ]; then VERDICT="GO"; else VERDICT="PIVOT"; fi
else
  VERDICT="NO-GO"
fi

echo
echo "----------------------------- paste-back block -----------------------------"
echo "DAY1-GATE RESULT: $VERDICT"
echo "  binary matrix:            $RES_BINARIES"
echo "  dataset MD5s:             $RES_DATASET"
echo "  vol3 pslist DC01:         $RES_MEM_DC$( [ "$VERDICT" = PIVOT ] && printf ' (PIVOT: desktop memory + DC disk artifacts)' )"
echo "  vol3 pslist DESKTOP:      $RES_MEM_DESKTOP"
echo "  gate artifacts:           runs/day1-gate/"
echo "-----------------------------------------------------------------------------"
echo
log "next steps:"
log "  1. paste the block above back to the build session - the GO/PIVOT/NO-GO"
log "     decision gets recorded in process-notes.md (checklist item 2)"
log "  2. ground-truth sources were verified live on 2026-06-11; remaining pins"
log "     (per-host C2 port, exact FQDN) come from the evidence during item 11"
case "$VERDICT" in
  GO)    exit 0 ;;
  PIVOT) exit 0 ;;
  *)     exit 1 ;;
esac
