# Changelog

## Unreleased

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
