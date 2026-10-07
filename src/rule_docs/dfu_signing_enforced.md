# dfu_signing_enforced

## What it means
Whether the bootloader verifies a firmware signature. This cannot be derived from enumeration, because the verification key is compiled into the bootloader. The verdict comes from a recorded in-band probe (`ble-doctor dfu --allow-dangerous`), and the probe's own evidence travels with it.

## Why it matters
Enforced is INFO and passes. Not enforced is HIGH and fails. A signature present but invalid is MEDIUM and fails. With no probe result, or an unrecognised one, the check is INFO, passes, and carries zero score weight: a queued probe, not a pass.

## How to fix
If the bootloader does not enforce signatures, enable signature verification in the bootloader build. If the result is inconclusive, run the probe against a device you own and record its verdict.

## How to verify
Read `dfu_signing_enforced` in `ble-doctor scan --json`. It stays inconclusive until a probe verdict is recorded via `ble-doctor dfu --target <address> --allow-dangerous`.
