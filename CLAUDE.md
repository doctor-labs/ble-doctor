# ble-doctorV2 — project context

`ble-doctor` scores the security posture of a BLE device (tag / tracker / peripheral class) from a
live GATT enumeration or a capture. It is a single **cross-platform Rust CLI** and a *superset* of
the common BLE tools, it **drives the radio itself** (no external binaries), and it **never leaks a
raw OS error**. Defensive / CTF / own-gear use only. Rust rewrite of ble-doctor v1 (Python,
archived); the full build is tracked across the repo issues.

Contributor & agent conventions (scope, architecture rules, testing discipline, workflow,
attribution) live in AGENTS.md — read it before changing anything:

@AGENTS.md

## Module map (`src/`) → owning issue

- `main.rs`, `cli.rs` — clap entry; subcommands: `scan` `analyze` `probe-writes` `read-values`
  `dfu` `doctor` `mcp` `recon` `ctf` `baseline` `handoff` `rules` `why` (+ `--tui`) — #1
- `error.rs` — `BleError` (thiserror) + `remediation()` + backend mappers (BlueZ/CoreBluetooth/WinRT) — #2
- `capability.rs` — `{Feature × Platform} → Support`, `require()` — #3
- `doctor.rs` — preflight (adapter / permission / daemon / feature table), injectable probes — #4
- `radio/mod.rs` — `Central`/`Peripheral` trait wrapper over btleplug + scan (advertised-name match) — #5
- `radio/raw.rs` — Linux raw HCI/L2CAP (bluer); exact-MTU #16, set-random-address #17 — #15
- `gatt.rs` — enumeration → `GattInfo`; CCCD / descriptor logic (macOS = "unknown") — #6
- `checks.rs`, `rules.rs` — pure checks (`CheckResult{id,severity,passed,detail}`) + rule catalog
  (`rule_docs/<id>.md`, 4 headings) — #7 / #23
- `report.rs`, `sarif.rs` — product-of-survival score (`SEVERITY_WEIGHT` HIGH30/MED15/LOW5/INFO0)
  + JSON/table + SARIF 2.1.0 (fingerprinted, volatile fields masked) — #7
- `probe/write.rs` `read.rs` `dfu.rs` — opt-in probes, firmware denylist, `--allow-dangerous` — #8/#9/#10
- `capture.rs` — native btsnoop/pcap parse + MAC-rotation (`MIN_ROTATION_OBSERVATION_SECONDS=600`) — #11
- `recon.rs` `ctf.rs` `baseline.rs` `handoff.rs` — v1-parity extras — #21/#22/#26/#27
- `mcp.rs` — MCP server exposing ONLY `scan` + `analyze` (dangerous ops never reachable) — #12
- `tui.rs` — ratatui view — #14
- `testkit/mod.rs` — no-radio fakes (`FakeCentral`, `FakeGattTree`, `FakeClient`, …) for all tests — #24

## Build & test

- `cargo build` / `cargo run -- <subcommand>`.
- Gate (must pass before any commit): `cargo fmt --check` && `cargo clippy --all-targets -- -D warnings` && `cargo test`.
- Tests are no-radio by default (via `testkit`). Live/hardware checks are listed in
  `docs/DEFERRED-TESTS.md`, never silently skipped. See AGENTS.md "Testing discipline".

## Scoring (carry from v1)

`score = 100·Π(1 − weight/100)` over FAILED checks only (`HIGH 30, MED 15, LOW 5, INFO 0`), half-up
rounded, clamped [0,100]. INFO and passed checks never move the score. One HIGH caps the score at 70.

## Status

MVP first (scan + enumerate + score/SARIF + analyze + doctor + clean errors + MCP + rules UX), then
post-MVP (raw-radio flags, fingerprint, sniffer, MITM, recon, ctf, baseline, handoff). Hardware-gated
acceptance is deferred to `docs/DEFERRED-TESTS.md`.
