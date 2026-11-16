# CI

- `ci.yml` (hosted, ubuntu): `fmt --check`, `clippy -D warnings`, `test`. Runs on every PR.
- `live-hardware.yml` -> `live-ble-hardware` (self-hosted `[self-hosted, linux, ble-hardware]`, #74): runs
  `scripts/check-vhci-prereqs.sh` and refuses to start with a clear error when prerequisites are missing, then runs
  `scripts/run-live-ble-job.sh` to prepare/execute the live test target against the attached adapter and collect results
  in `artifacts/live-ble-hardware/`. **Off by default** (`if: vars.LIVE_BLE_HARDWARE_RUNNER == 'true'`). This is the
  live BLE hardware CI workflow delivered for #74.
- `integration.yml` -> `integration-vhci` (self-hosted `[self-hosted, linux, bluetooth]`): vhci/Bumble integration path,
  gated by `VHCI_RUNNER=true`. It also runs `scripts/check-vhci-prereqs.sh` to fail fast on missing prerequisites and
  requires at least one passing ignored integration test.
- `release.yml`: on tag `v*`, builds `ble-doctor` (`cargo build --release`) on linux/macos/windows and attaches the
  binaries to a GitHub release.

See [`docs/live-hardware-runner.md`](live-hardware-runner.md) for the full runner requirements, provisioning, run
instructions, absent-prerequisite behavior, and which acceptance issues are unblocked vs still blocked. (Legacy
background: [`docs/self-hosted-runner.md`](self-hosted-runner.md).)

## Register a self-hosted live BLE hardware runner (e.g. Instabbox)

Hard requirements (recorded, not optional): Linux host with `CONFIG_BT_HCIVHCI` kernel support, loadable `hci_vhci` with
`/dev/vhci` available, USB passthrough (`/dev/bus/usb`) for a physical BLE adapter, and an enumerated BLE adapter
(`hci*`). Generic sandboxes without USB bus access and without an `hci_vhci`-capable kernel cannot run live hardware
CI and must keep these workflows disabled.

1. Prepare the host: `sudo bash scripts/setup-self-hosted-runner.sh` (or follow it manually), then verify with
   `bash scripts/check-vhci-prereqs.sh`.
2. Repo Settings -> Actions -> Runners -> New self-hosted runner (Linux). Add label `ble-hardware` for the #74 workflow
   (`linux` and `self-hosted` are automatic).
3. Install/start service: `sudo ./svc.sh install && sudo ./svc.sh start`. The runner user needs passwordless sudo for
   `modprobe hci_vhci`.
4. For Instabbox/VM runners, ensure the VM/kernel provides `hci_vhci` and USB passthrough of the BLE adapter. The
   offered Instabbox sandbox currently lacks USB bus access and `CONFIG_BT_HCIVHCI`, so the live job cannot run there
   as-is and will refuse to start.

## Turn live hardware CI on

- `live-hardware.yml` (#74): set repo variable `LIVE_BLE_HARDWARE_RUNNER=true`.
- `integration.yml` (vhci/Bumble): set repo variable `VHCI_RUNNER=true`.

Enable only on a trusted repo/runner that does not accept untrusted fork PRs, and only after
`bash scripts/check-vhci-prereqs.sh` passes on the registered runner. Remove the variable(s) to disable.
