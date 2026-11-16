# Self-hosted runner notes (legacy / vhci integration)

Canonical #74 documentation: **[`docs/live-hardware-runner.md`](live-hardware-runner.md)** (requirements, provisioning, run instructions, absent-prerequisite behavior, and which acceptance issues are unblocked vs still blocked).

This page remains as background for the `integration-vhci` workflow and vhci/Bumble runner setup.

## Workflows and scripts

- **Live BLE hardware CI (#74):** `.github/workflows/live-hardware.yml` (`[self-hosted, linux, ble-hardware]`, gated by `LIVE_BLE_HARDWARE_RUNNER=true`) runs `scripts/check-vhci-prereqs.sh` then `scripts/run-live-ble-job.sh` and uploads `artifacts/live-ble-hardware/`.
- **vhci/Bumble integration:** `.github/workflows/integration.yml` (`[self-hosted, linux, bluetooth]`, gated by `VHCI_RUNNER=true`) runs prerequisite checks and `cargo test -- --ignored` with a guard requiring at least one passing ignored test.
- **Prerequisite checks (fail-fast, testable):** `scripts/check-vhci-prereqs.sh`, `scripts/live-hw-common.sh`.
- **Host preparation helper:** `scripts/setup-self-hosted-runner.sh`.
- **Preflight reporting:** `ble-doctor doctor` reports `live_runner:*` prerequisites on Linux.

## Hard requirements (summary)

A compliant runner/host must provide:
- Linux with `CONFIG_BT_HCIVHCI` (module or built-in), loadable `hci_vhci`, and `/dev/vhci`
- USB passthrough / `/dev/bus/usb` and an enumerated BLE adapter (`/sys/class/bluetooth/hci*`, e.g. Plugable USB-BT5LE / CSR8510)
- Passwordless `sudo modprobe hci_vhci` for the runner user
- Rust toolchain/build deps; Python 3/Bumble as required by ignored integration tests

## Honest constraint

The offered Instabbox sandbox lacks USB bus access and `CONFIG_BT_HCIVHCI`, so live BLE/vhci jobs cannot run there as-is. Workflows/scripts must remain disabled there and refuse to start with clear prerequisite errors when requirements are missing.

See [`docs/live-hardware-runner.md`](live-hardware-runner.md) for full details.
