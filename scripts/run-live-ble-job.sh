#!/usr/bin/env bash
# Prepare and run the ble-doctor live BLE hardware CI job on a self-hosted runner.
#
# Checks hard prerequisites (CONFIG_BT_HCIVHCI, hci_vhci loaded, /dev/vhci, /dev/bus/usb,
# BLE adapter enumerated), runs the live test target against the attached adapter, and collects
# results into an artifacts directory.
#
# Usage:
#   scripts/run-live-ble-job.sh [--results-dir DIR] [--] [cargo test args...]
#
# Environment:
#   LIVE_BLE_RESULTS_DIR   Results directory (default: artifacts/live-ble-hardware)
#   LIVE_BLE_TEST_CMD      Override test command (default: cargo test -- --ignored)
#   BLE_HW_*               Probe overrides for prerequisite checks (see live-hw-common.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RESULTS_DIR="${LIVE_BLE_RESULTS_DIR:-$REPO_ROOT/artifacts/live-ble-hardware}"
if [ "${1:-}" = "--results-dir" ]; then
  RESULTS_DIR="$2"
  shift 2
fi
if [ "${1:-}" = "--" ]; then
  shift
fi

mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/live-ble-job.log"
SUMMARY="$RESULTS_DIR/summary.txt"
PREREQ_LOG="$RESULTS_DIR/prereq-check.log"

run_logged() {
  echo "+ $*" | tee -a "$LOG"
  "$@" 2>&1 | tee -a "$LOG"
}

{
  echo "ble-doctor live BLE hardware job"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
  echo "repo_root=$REPO_ROOT"
  echo "results_dir=$RESULTS_DIR"
  echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
  echo "host=$(uname -a 2>/dev/null || echo unknown)"
} | tee "$LOG" "$SUMMARY" >/dev/null

echo "==> Checking prerequisites" | tee -a "$LOG"
set +e
bash "$SCRIPT_DIR/check-vhci-prereqs.sh" 2>&1 | tee -a "$LOG" "$PREREQ_LOG"
PREREQ_RC=${PIPESTATUS[0]}
set -e
if [ "$PREREQ_RC" -ne 0 ]; then
  echo "result=prerequisites-missing" >>"$SUMMARY"
  echo "exit_code=$PREREQ_RC" >>"$SUMMARY"
  echo "ERROR: prerequisites missing; refusing to run live BLE tests (see $PREREQ_LOG)" | tee -a "$LOG" >&2
  exit "$PREREQ_RC"
fi

echo "==> Preparing environment" | tee -a "$LOG"
# Best-effort: ensure vhci module is loaded for jobs that rely on it (prereq check already tried).
if [ "$(uname -s 2>/dev/null || echo)" = "Linux" ] && [ "${BLE_HW_SKIP_PREPARE:-0}" != "1" ]; then
  if sudo -n modprobe hci_vhci >/dev/null 2>&1; then
    echo "modprobe hci_vhci: ok" | tee -a "$LOG"
  else
    echo "modprobe hci_vhci: skipped/failed (continuing; prerequisites already validated)" | tee -a "$LOG"
  fi
fi

echo "==> Adapter visibility" | tee -a "$LOG"
{
  echo "--- /sys/class/bluetooth ---"
  ls -la /sys/class/bluetooth 2>&1 || true
  if command -v hciconfig >/dev/null 2>&1; then
    echo "--- hciconfig -a ---"
    hciconfig -a 2>&1 || true
  fi
  if command -v bluetoothctl >/dev/null 2>&1; then
    echo "--- bluetoothctl list ---"
    bluetoothctl list 2>&1 || true
  fi
} | tee -a "$LOG" "$RESULTS_DIR/adapter-info.txt" >/dev/null

cd "$REPO_ROOT"

if [ -n "${LIVE_BLE_TEST_CMD:-}" ]; then
  echo "==> Running live test target (LIVE_BLE_TEST_CMD)" | tee -a "$LOG"
  # shellcheck disable=SC2086
  set +e
  bash -lc "$LIVE_BLE_TEST_CMD" 2>&1 | tee -a "$LOG" "$RESULTS_DIR/test-output.txt"
  TEST_RC=${PIPESTATUS[0]}
  set -e
elif [ "$#" -gt 0 ]; then
  echo "==> Running live test target: cargo test $*" | tee -a "$LOG"
  set +e
  cargo test "$@" 2>&1 | tee -a "$LOG" "$RESULTS_DIR/test-output.txt"
  TEST_RC=${PIPESTATUS[0]}
  set -e
else
  echo "==> Running live test target: cargo test -- --ignored" | tee -a "$LOG"
  set +e
  cargo test -- --ignored 2>&1 | tee -a "$LOG" "$RESULTS_DIR/test-output.txt"
  TEST_RC=${PIPESTATUS[0]}
  set -e
fi

echo "exit_code=$TEST_RC" >>"$SUMMARY"
if [ "$TEST_RC" -eq 0 ]; then
  echo "result=ok" >>"$SUMMARY"
else
  echo "result=failed" >>"$SUMMARY"
fi

echo "==> Results collected in $RESULTS_DIR" | tee -a "$LOG"
echo "summary:"; cat "$SUMMARY"
exit "$TEST_RC"
