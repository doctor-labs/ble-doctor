#!/usr/bin/env bash
# Shared helpers for live BLE hardware runner prerequisite checks.
# Designed to be testable without real hardware by overriding probe commands/paths via env vars.

ble_hw_fail() {
  echo "::error::$*" >&2
  echo "ERROR: $*" >&2
  return 1
}

ble_hw_warn() {
  echo "::warning::$*" >&2
  echo "WARN: $*" >&2
}

ble_hw_info() {
  echo "INFO: $*"
}

ble_hw_uname_s() { "${BLE_HW_UNAME_S_CMD:-uname}" -s 2>/dev/null || true; }
ble_hw_uname_r() { "${BLE_HW_UNAME_R_CMD:-uname}" -r 2>/dev/null || true; }

ble_hw_have_cmd() { command -v "$1" >/dev/null 2>&1; }

ble_hw_modinfo_hci_vhci() {
  if [ -n "${BLE_HW_MODINFO_RESULT:-}" ]; then
    [ "${BLE_HW_MODINFO_RESULT}" = "ok" ]
    return
  fi
  modinfo hci_vhci >/dev/null 2>&1
}

ble_hw_config_has_vhci() {
  local krel src
  krel="$(ble_hw_uname_r)"
  if [ -n "${BLE_HW_CONFIG_HAS_VHCI:-}" ]; then
    [ "${BLE_HW_CONFIG_HAS_VHCI}" = "yes" ]
    return
  fi
  local sources=()
  if [ -n "${BLE_HW_CONFIG_PATHS:-}" ]; then
    # space-separated list for tests
    # shellcheck disable=SC2206
    sources=(${BLE_HW_CONFIG_PATHS})
  else
    sources=(
      "/proc/config.gz"
      "/boot/config-${krel}"
      "/lib/modules/${krel}/build/.config"
    )
  fi
  for src in "${sources[@]}"; do
    [ -r "$src" ] || continue
    if [ "${src##*.}" = "gz" ]; then
      if zgrep -q '^CONFIG_BT_HCIVHCI=[ym]' "$src" 2>/dev/null; then return 0; fi
      if zgrep -q '^# CONFIG_BT_HCIVHCI is not set' "$src" 2>/dev/null; then return 1; fi
    else
      if grep -q '^CONFIG_BT_HCIVHCI=[ym]' "$src" 2>/dev/null; then return 0; fi
      if grep -q '^# CONFIG_BT_HCIVHCI is not set' "$src" 2>/dev/null; then return 1; fi
    fi
  done
  return 2
}

ble_hw_dev_vhci_path() { echo "${BLE_HW_DEV_VHCI_PATH:-/dev/vhci}"; }

ble_hw_dev_vhci_present() {
  [ -c "$(ble_hw_dev_vhci_path)" ]
}

ble_hw_usb_bus_present() {
  local p="${BLE_HW_USB_BUS_PATH:-/dev/bus/usb}"
  [ -d "$p" ]
}

ble_hw_sys_bluetooth_root() { echo "${BLE_HW_SYS_BLUETOOTH_PATH:-/sys/class/bluetooth}"; }

ble_hw_adapter_enumerated() {
  if [ -n "${BLE_HW_ADAPTER_ENUMERATED:-}" ]; then
    [ "${BLE_HW_ADAPTER_ENUMERATED}" = "yes" ]
    return
  fi
  local root
  root="$(ble_hw_sys_bluetooth_root)"
  [ -d "$root" ] || return 1
  compgen -G "$root/hci*" >/dev/null 2>&1
}

ble_hw_try_modprobe_vhci() {
  if [ -n "${BLE_HW_MODPROBE_RESULT:-}" ]; then
    [ "${BLE_HW_MODPROBE_RESULT}" = "ok" ]
    return
  fi
  sudo -n modprobe hci_vhci >/dev/null 2>&1
}
