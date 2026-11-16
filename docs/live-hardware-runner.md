# Live BLE hardware CI runner (self-hosted, #74)

This page documents the **software half** delivered for issue #74: a self-hosted live BLE hardware CI setup that can run only on a properly provisioned runner. It records the runner's requirements, how to provision and run the job, how the job behaves when prerequisites are missing, and which acceptance issues this unblocks versus which still require hardware or environments this runner/setup cannot supply.

## Honest constraint (Instabbox sandbox)

The offered Instabbox machine/sandbox **cannot run the live BLE job as-is**:

- **No USB bus access** (`/dev/bus/usb` unavailable / USB passthrough not present), so a real BLE adapter cannot be attached.
- **Kernel lacks `CONFIG_BT_HCIVHCI`** (and `hci_vhci`/`/dev/vhci` unavailable), so vhci-based integration paths cannot run.

This repository does **not** pretend the live job can run there. The workflow and runner script **refuse to start with a clear prerequisite error** when requirements are missing.

## Hard runner requirements

The live hardware job requires a **self-hosted Linux runner** (recommended labels: `self-hosted`, `linux`, `ble-hardware`) provisioned with:

| Requirement | Why | How to verify |
|---|---|---|
| Linux host with hardware access | BLE/vhci tooling and sysfs checks are Linux-specific | `uname -s` = `Linux`; runner registered with `self-hosted`, `linux`, `ble-hardware` labels |
| Kernel with `CONFIG_BT_HCIVHCI` (module or built-in) and loadable `hci_vhci` | Required for vhci/HCI integration path used by live test execution on this rig | `modinfo hci_vhci`; kernel config shows `CONFIG_BT_HCIVHCI=y` or `=m`; `sudo modprobe hci_vhci` succeeds |
| `/dev/vhci` present after module load | Virtual HCI device required by the integration path | `test -c /dev/vhci` after `sudo modprobe hci_vhci` |
| USB passthrough / `/dev/bus/usb` present | Real BLE adapter must be attached to the host/VM | `test -d /dev/bus/usb` |
| BLE adapter enumerated | Live tests run against a real adapter | `ls /sys/class/bluetooth` shows `hci*`; `lsusb` shows a Bluetooth device (e.g. Plugable USB-BT5LE / CSR8510) |
| Passwordless `sudo modprobe hci_vhci` for runner user | CI must prepare vhci non-interactively and fail clearly otherwise | `sudo -n modprobe hci_vhci` |
| Rust toolchain + repo build deps | Run `cargo test` live targets | `cargo --version`; on Debian/Ubuntu: `libdbus-1-dev`, `pkg-config`, `bluez`, `usbutils` |
| Python 3 (and Bumble if running vhci/Bumble-backed ignored tests) | Some ignored/integration tests rely on Bumble/vhci harness | `python3 --version`; `python3 -m pip install --user bumble` as needed |

## Delivered software artifacts

| Area | Artifact | Purpose |
|---|---|---|
| Runner script (prepares + runs + collects) | `scripts/run-live-ble-job.sh` | Checks prerequisites, prepares environment, runs the live test target against the adapter, collects logs/results under `artifacts/live-ble-hardware/` |
| Prerequisite check (fail-fast, testable) | `scripts/check-vhci-prereqs.sh`, `scripts/live-hw-common.sh` | Validates kernel vhci support, module load/device, USB bus, adapter enumeration; exits with clear errors when missing. Supports `BLE_HW_*` overrides for tests without radio |
| Runner provisioning helper | `scripts/setup-self-hosted-runner.sh` | Best-effort host setup guidance/automation (packages, sudoers, checks); cannot create USB passthrough or change kernel |
| CI workflow (self-hosted, clearly labeled) | `.github/workflows/live-hardware.yml` | Job `live-ble-hardware` on `[self-hosted, linux, ble-hardware]`, gated by `LIVE_BLE_HARDWARE_RUNNER=true`, refuses to start with a clear message when prerequisites are missing, uploads results artifacts |
| Capability / preflight reporting | `ble-doctor doctor` (`src/doctor.rs`, `src/capability.rs` context) | Reports live-runner rig prerequisites on Linux (`live_runner:vhci_kernel`, `live_runner:vhci_device`, `live_runner:usb_bus`, `live_runner:ble_adapter`) with remediation so operators can see exactly what the rig needs |
| Documentation | `docs/live-hardware-runner.md`, `docs/CI.md`, `docs/DEFERRED-TESTS.md` | Requirements, provisioning, run instructions, absent-prereq behavior, and unblocked vs still-blocked acceptance items |

## Provisioning the runner

1. **Provision host/VM with hardware access**
   - Use a Linux host/kernel with `CONFIG_BT_HCIVHCI` available.
   - Attach/passthrough a supported BLE USB adapter (e.g. Plugable USB-BT5LE / CSR8510) so `/dev/bus/usb` and `/sys/class/bluetooth/hci*` are visible inside the runner environment.
   - For Instabbox: this requires a vhci-capable kernel/image and USB passthrough configured by the operator; the current sandbox/kernel cannot satisfy this.

2. **Prepare software prerequisites**
   - `sudo bash scripts/setup-self-hosted-runner.sh` (as root; set `RUNNER_USER=<actions-runner-user>` to configure passwordless `modprobe`).
   - Verify: `bash scripts/check-vhci-prereqs.sh` must pass on the target host.

3. **Register GitHub Actions runner**
   - GitHub: Settings → Actions → Runners → New self-hosted runner (Linux).
   - Configure labels to include: `self-hosted`, `linux`, `ble-hardware`.
   - Install/start service: `sudo ./svc.sh install && sudo ./svc.sh start`.

4. **Enable the workflow deliberately (trusted repo/runner only)**
   - Set repository variable `LIVE_BLE_HARDWARE_RUNNER=true` to allow `.github/workflows/live-hardware.yml` to run.
   - Only enable after `scripts/check-vhci-prereqs.sh` passes and on repositories that do not run untrusted fork PRs on this runner.

## Running the live BLE job

- **On the runner/host (manual):**
  ```bash
  bash scripts/run-live-ble-job.sh
  ```
  - Default live test target: `cargo test -- --ignored` (radio/live integration tests marked ignored).
  - Override: pass cargo test args (`bash scripts/run-live-ble-job.sh -- --ignored my_live_test`) or set `LIVE_BLE_TEST_CMD`.
  - Results are collected in `artifacts/live-ble-hardware/` (`summary.txt`, `prereq-check.log`, `adapter-info.txt`, `test-output.txt`, `live-ble-job.log`).

- **In CI:** enable `LIVE_BLE_HARDWARE_RUNNER=true`; workflow `.github/workflows/live-hardware.yml` runs the same script and uploads `artifacts/live-ble-hardware` as a workflow artifact.

- **Preflight visibility:** `ble-doctor doctor` reports the live-runner prerequisites on Linux so operators can confirm what the rig needs before enabling CI.

## Behavior when prerequisites are missing

- `scripts/check-vhci-prereqs.sh` and `scripts/run-live-ble-job.sh` **exit non-zero with clear `ERROR:`/`::error::` messages** identifying the missing requirement (e.g. non-Linux host, `CONFIG_BT_HCIVHCI` unavailable, cannot `sudo modprobe hci_vhci`, `/dev/vhci` missing, `/dev/bus/usb` missing, no adapter enumerated) and point to this document.
- `.github/workflows/live-hardware.yml` runs the prerequisite check before the live job and **refuses to start with a clear failure** if prerequisites are missing (it does not proceed to obscure modprobe/test failures).
- The workflow remains **disabled by default** (`LIVE_BLE_HARDWARE_RUNNER` unset/false) so hosted/sandboxed environments (including the Instabbox sandbox described above) do not run it.

## Acceptance issues: unblocked vs still blocked

**Unblocks (once a runner meeting all hard requirements is provisioned and the workflow enabled):**
- **#74 (this issue), software/setup side:** provides the runner script, prerequisite checks, CI workflow wiring, `ble-doctor doctor` preflight reporting, and operator documentation needed to run live BLE hardware CI on a self-hosted runner.
- **Self-hosted live/ignored integration execution on suitable hardware:** running the repo's live test target(s) (e.g. `cargo test -- --ignored`) against an attached adapter on a compliant host, with results collected and CI refusal when prerequisites are absent.
- **Runner-readiness validation tasks** that depend on having a documented, testable prerequisite gate (e.g. confirming a registered `self-hosted, linux, ble-hardware` runner passes `scripts/check-vhci-prereqs.sh` before enabling CI).

**Still needs hardware/environments this runner/setup cannot supply (not unblocked by this software-only change):**
- **Provisioning itself on the offered Instabbox sandbox as-is:** cannot be satisfied without operator-provided USB passthrough and a kernel/image with `CONFIG_BT_HCIVHCI` + `hci_vhci`/`/dev/vhci`.
- **Any acceptance requiring specific physical devices, captures, or radios beyond "an enumerated BLE adapter"**, e.g. real SMP pairing captures, nRF52/sniffer hardware, dual-adapter MITM, ESP32 BLECTF live flag solves, dual-mode SDP/LMP targets, or platform-specific manual smoke (Windows).
- **Kernel/stack-dependent live scenarios** blocked by host limitations (e.g. the documented kernel 6.18 `le-connection-abort-by-local` regression cases) — these require an appropriate kernel/dongle/target, not just this CI wiring.
- **Enabling CI on untrusted repositories/forks:** explicitly out of scope/unsafe for a privileged self-hosted runner; operator policy decision.

See `docs/DEFERRED-TESTS.md` for the current hardware-gated checklist and evidence requirements.
