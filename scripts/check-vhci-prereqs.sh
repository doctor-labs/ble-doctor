#!/usr/bin/env bash
# Preflight for the ble-doctor self-hosted live BLE / vhci integration runner.
# Fails fast with clear messages when hard prerequisites are missing.
#
# Hard requirements for live hardware CI (#74):
#   - Linux host (self-hosted runner with hardware access)
#   - Kernel with CONFIG_BT_HCIVHCI (module or built-in) and loadable hci_vhci
#   - /dev/vhci available after loading hci_vhci (for Bumble/vhci integration)
#   - USB passthrough / USB bus present and a BLE adapter enumerated for live hardware tests
#
# Testability: probe commands/paths can be overridden via BLE_HW_* env vars (see
# scripts/live-hw-common.sh). This allows covering prerequisite checks without real radio.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=live-hw-common.sh
source "$SCRIPT_DIR/live-hw-common.sh"

fail() { ble_hw_fail "$@"; exit 1; }
warn() { ble_hw_warn "$@"; }
info() { ble_hw_info "$@"; }

info "Checking self-hosted live BLE hardware prerequisites..."

OS="$(ble_hw_uname_s)"
if [ "$OS" != "Linux" ]; then
  fail "Live BLE hardware CI requires Linux. Current OS: ${OS:-unknown}. Refusing to start."
fi

KREL="$(ble_hw_uname_r)"
info "Kernel: ${KREL:-unknown}"

# CONFIG_BT_HCIVHCI / module availability
HAVE_VHCI=0
if ble_hw_modinfo_hci_vhci; then
  HAVE_VHCI=1
  info "hci_vhci module: available (modinfo)"
fi

set +e
ble_hw_config_has_vhci
CFG_RC=$?
set -e
case "$CFG_RC" in
  0)
    HAVE_VHCI=1
    info "CONFIG_BT_HCIVHCI: enabled (kernel config)"
    ;;
  1)
    fail "Kernel config reports CONFIG_BT_HCIVHCI is not set for kernel ${KREL:-unknown}. A kernel with CONFIG_BT_HCIVHCI (module or built-in) is required."
    ;;
  2)
    # not provable from config files; rely on modinfo
    ;;
esac

if [ "$HAVE_VHCI" -ne 1 ]; then
  fail "Cannot confirm CONFIG_BT_HCIVHCI / hci_vhci availability for kernel ${KREL:-unknown}. Refusing to start: provision a kernel with CONFIG_BT_HCIVHCI before enabling live hardware CI."
fi

# Ability to load hci_vhci and create /dev/vhci (needed for vhci/Bumble integration path)
if ! ble_hw_try_modprobe_vhci; then
  fail "Runner cannot execute 'sudo modprobe hci_vhci' non-interactively. Grant passwordless sudo for modprobe to the runner user (see docs/self-hosted-runner.md) or run on a host with vhci already available."
fi
if ! ble_hw_dev_vhci_present; then
  fail "$(ble_hw_dev_vhci_path) is not present after loading hci_vhci. The host cannot provide the required vhci device."
fi
info "$(ble_hw_dev_vhci_path) is present"

# USB bus / adapter checks required for live hardware acceptance against a real adapter
if ! ble_hw_usb_bus_present; then
  fail "USB bus path ${BLE_HW_USB_BUS_PATH:-/dev/bus/usb} is not present. Live hardware CI requires USB passthrough for a BLE adapter."
fi
info "USB bus present (${BLE_HW_USB_BUS_PATH:-/dev/bus/usb})"

if ! ble_hw_adapter_enumerated; then
  fail "No BLE adapter enumerated under $(ble_hw_sys_bluetooth_root) (expected hci*). Attach/passthrough a supported BLE adapter to the runner host."
fi
info "BLE adapter enumerated under $(ble_hw_sys_bluetooth_root)"

if ble_hw_have_cmd lsusb; then
  if lsusb 2>/dev/null | grep -qi 'bluetooth'; then
    info "USB Bluetooth device detected via lsusb"
  else
    warn "lsusb does not list a Bluetooth device; verify USB passthrough if live radio tests fail."
  fi
else
  warn "'lsusb' not installed; cannot confirm USB Bluetooth device visibility."
fi

cat <<'EOF'
INFO: Live BLE hardware prerequisites satisfied.
- Kernel provides hci_vhci (CONFIG_BT_HCIVHCI)
- /dev/vhci available
- USB bus present and BLE adapter enumerated
If running in a sandbox without USB bus access or vhci-capable kernel, keep the live-hardware workflow disabled.
EOF
