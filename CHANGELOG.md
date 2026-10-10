# Changelog

## [Unreleased]

### Added
- `analyze --irk <hex>` (repeatable): resolve Resolvable Private Addresses in a capture against an
  IRK you already hold. `mac_rotation`'s detail now notes when some/all of a capture's rotating
  addresses resolve to a given IRK (one device's legitimately-rotating RPA, not several distinct
  devices) (#94). New `src/rpa.rs` (`ah`, `resolves`), verified against the Linux kernel's
  `smp_ah` self-test vector (Core Spec Vol 3 Part H 2.2.2); new `aes` dependency.
- `shell`/`explore`'s REPL gains `read [uuid]`, `write <uuid> <hex> [--yes]` (write-then-read-back),
  `recon` and `probe-writes [--yes]`: active ops against the session's own live target, no need to
  repeat `--target` (#96). Each is a fresh connect/act/disconnect reusing the existing standalone
  subcommands' logic (same safety gating: `write`/`probe-writes` need `--yes`, firmware/DFU
  characteristics are always refused). A capture subject refuses them cleanly (nothing to
  reconnect to).

## 0.3.3

doctor-kit 0.2.2. Machine output is unchanged (goldens pass untouched).

### Fixed (contract)
- Output into a closed pipe (`ble-doctor analyze x --json | head`) exits 2 with `error: cannot write to stdout`
  instead of panicking (exit 101); the `capture:`, device-list and `gatt:` preamble lines no longer panic either.
- MCP: a request with neither an `id` nor a method is answered with -32600 and `"id": null`; `explore` without a
  TTY is an error (exit 2), not a panic.

### Fixed
- MCP: an unknown tool name containing quotes yields valid JSON again (`{"error":"unknown tool: x\"y"}`), as in 0.2.0.

## 0.3.2

### Fixed
- Release assets are one archive per target (`ble-doctor-<target>.tar.gz` / `.zip` plus `.sha256`); 0.3.1 uploaded bare `ble-doctor` binaries that overwrote each other. No code change.

## 0.3.1

### Fixed
- Release builds: commit `Cargo.lock` (was gitignored), so `cargo build --locked` in the release workflow works and GitHub releases ship binaries. No code change.

## 0.3.0

Human output now uses doctor-kit faces; machine output is unchanged (pinned byte for byte by `tests/golden.rs`);
new `shell` and `explore`. ble-doctor now runs on doctor-kit 0.2.

- Human output of `scan --target` and `analyze` is drawn by a kit face (`--face rich|plain|compact`, `--theme`,
  `--color`, `--headless`, `--score`) instead of the `[PASS]/[FAIL]` table. The `capture:` / `gatt:` summary lines and
  the device list stay as preamble. `--json`, `--sarif`, `--baseline`, `--fail-on`, exit codes 0/1/2/3, fingerprints,
  SARIF bytes, `rules`, `mcp` and every other command's output are unchanged.
- New: `shell` and `explore` (on by default; build with `default-features = false` on doctor-kit to drop them) over a
  live `--target` or a `--capture` file: findings by category plus the device's services and characteristics.
  `scan --tui` opens the explorer and then prints the report (the old ratatui view is gone).
- New: `fix` (agent prompt from a finding or `--from report.json`), `install` (agent skill, Cursor rule, AGENTS.md
  block: the skill forbids the active probes), `ci install` (analyzes `captures/`; installs `libdbus-1-dev`).
- Library API removed: `cli::{Cli, Command, run(Cli)}` (the binary is `doctor_kit::run_with`; `cli::run()` replaces it),
  `report::to_table`, `baseline::report_diff`, the `tui` module, `mcp::{handle, serve}` (the kit serves MCP now).
  Kept: `report::{to_envelope, gate_exit, to_json, score}`, `baseline::{load, diff}`, `sarif::to_sarif`
  (the goldens call them), `mcp::{TOOLS, argv_for}`.
- Everything else machine-visible is unchanged on purpose (pinned by `tests/golden.rs` and `tests/golden_d6.rs`):
  baseline parsing (a bare findings array is still refused, entries without a fingerprint are still skipped, no
  size cap), bare `baseline <path>: ...` errors, the `sarif: <path>: <e>` write failure printed before anything
  else, MCP tool errors and unknown-tool text.

### Fixed (contract)

- MCP: a request that is not a JSON object, has an `id` that is not a string or integer, or has no `method`
  now gets a JSON-RPC -32600 error (it used to get no answer, an echoed id, or "method not found"); `ping` is
  answered. Errors already exited 2 (doctor/1).
- `--sarif` and `--baseline` naming the same file is refused as a usage error (bare message, exit 2, nothing
  written): 0.2.0 silently overwrote the baseline with the SARIF.

### Also in 0.3.0

- Rename: drop "V2" from the product identity (docs say "BLE Doctor"); SARIF `informationUri` and
  `Cargo.toml` `repository`/`homepage` now point to https://github.com/doctor-labs/ble-doctor.

- `mitm` implements the Linux peripheral/clone half (#63): `serve()` connects to `--target`,
  clones its enumerated GATT onto a BlueZ/bluster peripheral (one `Characteristic`/`Descriptor`
  per enumerated one), advertises it, and relays every victim read/write to the real device via
  the existing `MitmRelay`, logging each exchange, until Ctrl-C. Not implemented: forwarding the
  real device's own notifications/indications into the victim's subscription (needs a
  `GattClient::subscribe`, which does not exist yet). GATT-tree construction and the relay/event
  loop are unit-tested against `testkit::FakeClient` (no D-Bus, no radio); live validation on two
  real adapters is #68, tracked in `docs/DEFERRED-TESTS.md`.
- `fingerprint` collects LMP data on Linux (#64): HCI Read Remote Supported Features, Extended Features (pages 1-2) and
  Read Remote Version Information over a raw HCI socket (hci0, ACL handle via HCIGETCONNINFO). New `lmp` fields:
  `version` (Bluetooth Core version), `manufacturer_name`, `pages`; `features` now names page 0..2 bits (Core Spec
  Vol 2 Part C 3.3). An LMP failure becomes a note and SDP is still reported. No findings added. Not validated on
  hardware: that is #70.
- `analyze` extracts the SMP pairing exchange (L2CAP CID 6) from pcap (LE LL) and btsnoop (H4 / Linux monitor) captures (#65).
  Decoded PDUs and the derived pairing method go under `data.smp` (`{"seen": false}` when the capture has no SMP).
  New rules: `smp_legacy_pairing` (high), `smp_just_works` (medium), `smp_key_size` (high at <=7 bytes, medium below 16),
  `smp_pairing_failed` (info). Live-capture validation stays with #66/#69.

## 0.2.0

Breaking: `scan --json` and `analyze --json` now emit the shared `doctor/1` envelope
(`docs/doctor-contract.md`). Refs Vaibhav91one/android-doctor#161.

- JSON: `{score, findings}` becomes `{schema, tool, version, exit_code, score{value,label,model,coverage_gaps}, findings, data}`.
  `findings` lists failed checks only, with `fingerprint`, `category`, `message` (was `detail`),
  `location`, `remedy`; passed checks moved to `data.passed`. `analyze` puts the capture under `data.capture`.
- Exit codes: every error is now 2 (was 1); `--fail-on` (default `high`, now also `critical`) gates
  `scan`/`analyze` with exit 1; `--baseline` gates new findings with 3. `scan` and `analyze` both take
  `--sarif`, `--baseline`, `--fail-on`.
- Fingerprints are 16 hex (was 32) and hash rule id + device identity only (no severity or detail); SARIF key is `doctorFinding/v1` (was `bleDoctorFinding/v1`).
- Baselines must be a `doctor/1` envelope; match is by fingerprint. Old reports are rejected.
- `scan --json`: the device list now goes to stderr so stdout is a single JSON document.
- Human output (table, TUI, stderr diff, scan, recon, fingerprint, read-values, probes) strips control/bidi/zero-width characters.
- MCP `scan`/`analyze` accept `baseline`, `fail_on`, `sarif` and return the envelope on exit 1/3.
