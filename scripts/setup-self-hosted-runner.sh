#!/usr/bin/env bash
# Helper/setup script for registering and preparing a self-hosted GitHub Actions
# runner for ble-doctor live hardware / vhci integration CI (issue #74).
#
# This script is intended for a Linux host you control (e.g. Raspberry Pi,
# Instabbox machine, or VM with USB passthrough). It documents and automates the
# software prerequisites; it cannot grant USB passthrough or change the host
# kernel configuration by itself.
#
# Usage (example):
#   sudo bash scripts/setup-self-hosted-runner.sh
#
# After running, complete runner registration in GitHub:
#   Settings -> Actions -> Runners -> New self-hosted runner
# and configure the service with labels including: self-hosted, linux, bluetooth

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (e.g. sudo bash $0) to install packages and sudoers rules." >&2
  exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "This setup script supports Linux only." >&2
  exit 1
fi

RUNNER_USER="${RUNNER_USER:-${SUDO_USER:-}}"
if [ -z "$RUNNER_USER" ]; then
  echo "Set RUNNER_USER=<user> to configure passwordless modprobe for the GitHub runner account." >&2
  echo "Continuing without sudoers change..." >&2
fi

echo "[1/5] Installing base packages (best effort)..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3 python3-pip python3-venv kmod usbutils bluez sudo
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 python3-pip kmod usbutils bluez sudo
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm python python-pip kmod usbutils bluez sudo
else
  echo "Unsupported package manager. Install manually: python3, pip, kmod(modprobe), usbutils(lsusb), bluez, sudo." >&2
fi

echo "[2/5] Installing Bumble for the runner user context (system-wide pip may vary)..."
python3 -m pip install --upgrade bumble || {
  echo "WARN: failed to install bumble globally. Ensure the runner user can run 'python3 -m pip install --user bumble'." >&2
}

echo "[3/5] Verifying hci_vhci kernel support (hard requirement)..."
if modinfo hci_vhci >/dev/null 2>&1; then
  echo "OK: modinfo hci_vhci found for kernel $(uname -r)"
else
  cat >&2 <<EOF
ERROR: hci_vhci module not available for kernel $(uname -r).
The runner requires CONFIG_BT_HCIVHCI (module or built-in). On Instabbox/VMs this
means using a kernel/image that includes vhci support. Without it, integration-vhci
cannot run and must remain disabled (VHCI_RUNNER unset/false).
EOF
fi

echo "[4/5] Configuring passwordless sudo for modprobe (if RUNNER_USER is set)..."
if [ -n "$RUNNER_USER" ]; then
  SUDOERS_FILE="/etc/sudoers.d/ble-doctor-runner-modprobe"
  cat > "$SUDOERS_FILE" <<EOF
# Allow the ble-doctor self-hosted runner to load vhci for integration CI.
$RUNNER_USER ALL=(root) NOPASSWD: /sbin/modprobe hci_vhci, /usr/sbin/modprobe hci_vhci, /bin/modprobe hci_vhci
EOF
  chmod 0440 "$SUDOERS_FILE"
  echo "Wrote $SUDOERS_FILE"
else
  echo "Skipped sudoers configuration (RUNNER_USER not set)."
fi

echo "[5/5] Printing hard requirements and next steps..."
cat <<'EOF'

Self-hosted runner hard requirements (issue #74):
  - Linux host with a kernel that provides CONFIG_BT_HCIVHCI (module or built-in)
  - /dev/vhci creatable via `modprobe hci_vhci`
  - USB passthrough for a physical BLE adapter (e.g. CSR8510 / Plugable USB-BT5LE)
    attached to the host/VM when running live hardware acceptance tests
  - Bluetooth adapter visible to the host (check: ls /sys/class/bluetooth, lsusb)
  - Runner labels: self-hosted, linux, bluetooth
  - Repo variable VHCI_RUNNER=true enables .github/workflows/integration.yml

Important: generic sandboxes without USB bus access and without hci_vhci-capable
kernels cannot run this job. Do not enable VHCI_RUNNER there; keep the job off and
record the hardware requirement in docs/self-hosted-runner.md.

Register the runner:
  1. GitHub -> Settings -> Actions -> Runners -> New self-hosted runner (Linux)
  2. Add label 'bluetooth' during ./config.sh (linux and self-hosted are automatic)
  3. Install and start service: sudo ./svc.sh install && sudo ./svc.sh start
  4. Verify prerequisites: bash scripts/check-vhci-prereqs.sh
EOF
