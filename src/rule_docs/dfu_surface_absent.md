# dfu_surface_absent

## What it means
Gives the absence of a DFU surface a positive identity with the evidence attached. For a device such as an AirTag, the correct result of a full GATT enumeration can be "there is no BLE firmware-update surface at all". Three outcomes: enumerated and nothing found (passes, the empty result is the result); not enumerated (INFO, inconclusive, not passed); or a DFU surface is present (INFO, not passed, absence does not apply).

## Why it matters
Without it, "nothing found" and "never enumerated" looked the same. Every outcome is INFO, which has a weight of 0, so this check can never move the score.

## How to fix
Nothing to fix. If the result is inconclusive, enumerate the device fully and re-run.

## How to verify
Run `ble-doctor scan --json` and read `dfu_surface_absent`; its detail says whether the absence is backed by a complete enumeration.
