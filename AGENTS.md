# AGENTS.md — ble-doctorV2 contributor & agent conventions

Conventions for anyone (human or agent) changing this repo. Read before editing.

## What this project is

`ble-doctorV2` is a single cross-platform **Rust CLI** (`ble-doctor`) that audits and **scores** the
security posture of a BLE device, and is a *superset* of the common BLE tools (bettercap, nRF
Connect, bluing, the BlueZ CLIs). It drives the radio itself — **no external tools** (no gatttool,
bdaddr, tshark, Wireshark, bettercap) — and it **never leaks a raw OS error**. It is a Rust rewrite
of ble-doctor v1 (Python, archived); v1 behaviour is re-specified across the repo issues.

## Scope / security posture (non-negotiable)

- **Defensive, CTF, and own-gear use only.** Own hardware or written authorization. Define scope
  before pointing the tool at any device you do not own.
- **No new exploit code in this repo.** This is an auditor/scorer, not a weapon. Attack primitives
  that exist (write probe, DFU probe, MITM) are gated, opt-in, and refuse firmware-update
  characteristics by default.
- Operator rig details (hosts, adapters, addresses, creds) live in `rig-notes.local.md`
  (gitignored). Never commit them.

## Architecture rules

- **Radio behind a trait.** All radio access goes through the `Central`/`Peripheral` traits in
  `src/radio/`. Logic is written against the trait so it is testable with the fakes in
  `src/testkit/` — never against btleplug directly outside `src/radio/`.
- **No raw OS error ever reaches the user.** Every backend error is mapped to `BleError`
  (`src/error.rs`), and every variant carries a `remediation()`. The catch-all is
  `BleError::OsError { context }`. A `doctor` preflight (`src/doctor.rs`) + a capability table
  (`src/capability.rs`) report what a platform can/can't do *before* an op runs, as a clean
  `Unsupported`, not a crash.
- **Capability-gated.** Platform-specific features (raw L2CAP, exact MTU, set-random-address,
  sniffing, MITM) check `capability::require(Feature::…)` first and degrade to a clean
  `Unsupported` where the platform/hardware can't do them.
- **No external binaries.** Parse captures (`src/capture.rs`) natively (btsnoop/pcap); drive sniffer
  hardware directly. The one allowance: an *optional* bluesploit cross-check (`recon`) if the binary
  happens to be present — INFO-only, heuristic, never scored.

## Testing discipline

- **No-radio by default.** Unit tests use the `src/testkit/` fakes (the Rust port of v1's synthetic
  `Fake*` classes). Wire-level code (ATT MTU, HCI commands, DFU classification) is proven with
  exact-byte codec tests. Captures are built byte-for-byte in-test.
- **Hardware/live tests are RECORDED, never silently skipped.** If an acceptance step needs a radio
  or a live connection you don't have, append it to `docs/DEFERRED-TESTS.md` with exact steps,
  hardware needed, and expected result. Clear an item only when run with evidence committed.
- Integration against a virtual radio uses **Bumble + vhci** on a self-hosted Linux runner.
  macOS/Windows backends can't be virtualized → fakes + manual smoke (also a deferred item).
- The gate for every change: `cargo fmt --check` && `cargo clippy --all-targets -- -D warnings` &&
  `cargo test`, all green. Hollow/placeholder tests are not acceptable.

## Workflow (how changes land)

- **One issue → one git worktree → one branch → one PR.** Branch name `issue-<n>-<slug>`, based on
  the latest `main`.
- Each PR must pass the gate in CI and a code review before squash-merge. Keep PRs scoped to their
  issue; shared files (`cli.rs`, `checks.rs`) are touched by one issue at a time to avoid conflicts.
- Do **not** push directly to `main`; do **not** force-push `main` or rewrite merged history.
- This repo is built by an orchestrator (Opus) coordinating worker subagents (Sonnet); workers make
  one tool call at a time, self-verify, and the orchestrator independently re-verifies before merge.

## Commit attribution

- Author/committer identity: **`Vaibhav91one <108279746+Vaibhav91one@users.noreply.github.com>`**
  (the GitHub-username noreply — never a personal/work email).
- End each commit message body with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- End PR descriptions with: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`

## Layout

See `CLAUDE.md` for the module map and the per-module → issue mapping.
