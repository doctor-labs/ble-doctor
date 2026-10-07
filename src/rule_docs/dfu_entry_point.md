# dfu_entry_point

## What it means
Access control of the Device Firmware Update entry point, and nothing else. The check keys on whether the DFU control point is reachable WITHOUT bonding or encryption, not on whether a DFU UUID is published at all.

## Why it matters
"A DFU service is present" is not a finding: correctly configured Nordic, TI and micro:bit products publish one. What matters is whether a peer that has never paired can reach the write. No DFU entry point in the dump, or a control point that is bond-protected or encrypted, is INFO and passes. A DFU entry point that is present but with no writable control point reported is INFO and passes, and the detail says its access control was not assessed. A control point writable without bonding is HIGH and fails. When the bonding flag came from the GATT heuristic rather than an empirical write probe, the detail says "assumed", not "is".

## How to fix
Require bonding and encryption on the DFU control point.

## How to verify
Run `ble-doctor scan --json` and read `dfu_entry_point`; confirm the basis with `ble-doctor probe-writes --target <address> --allow-dangerous` on a device you own.
