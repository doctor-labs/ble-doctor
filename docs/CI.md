# CI

- `ci.yml` (hosted, ubuntu): `fmt --check`, `clippy -D warnings`, `test`. Runs on every PR.
- `integration.yml` -> `integration-vhci` (self-hosted `[self-hosted, linux, bluetooth]`): installs bumble, loads `hci_vhci`,
  runs `cargo test -- --ignored`, and a guard fails the job if no integration test actually passed (no silent skips).
  It is **off** (`if: vars.VHCI_RUNNER == 'true'`) so PRs stay green while no runner exists.
- `release.yml`: on tag `v*`, builds `ble-doctor` (`cargo build --release`) on linux/macos/windows and attaches the binaries to a GitHub release.
  Plain cargo build instead of cargo-dist to keep it small; no npm.

## Register the Pi runner
1. Repo Settings -> Actions -> Runners -> New self-hosted runner (Linux, ARM64); follow the download/`config.sh` steps.
2. When `config.sh` asks for labels, add `bluetooth` (`linux` and `self-hosted` are automatic).
3. `sudo ./svc.sh install && sudo ./svc.sh start`. The runner user needs passwordless sudo for `modprobe`.

## Turn the integration job on
Repo Settings -> Secrets and variables -> Actions -> Variables: add `VHCI_RUNNER` = `true`.
Remove it to disable. Only enable on a repo that does not accept untrusted fork PRs on this runner.
