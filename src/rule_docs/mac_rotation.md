# mac_rotation

## What it means
Whether the advertising address rotates during the capture. A Resolvable Private Address rotates on a timer in the roughly 2 to 15 minute window (Core Spec Vol 6 Part B 4.5.1.1), so one address across a whole capture only means "trackable" if the capture lasted long enough for a rotation to happen.

## Why it matters
Judging a short capture would report a false positive against a normal pre-pair target that has not started rotating yet. Below the minimum observation time, and whenever the span is unknown, the result is INCONCLUSIVE at INFO with no score weight and is not marked passed. More than one distinct address seen is INFO and passes (rotation observed). Only a capture that demonstrably outlasted the rotation interval can be called static, which is MEDIUM.

## How to fix
If the advertising address is static over a long capture, enable resolvable private addresses and rotation in the device's BLE stack.

## How to verify
Capture advertising traffic for longer than the rotation interval and run `ble-doctor analyze <capture> --json`; read `mac_rotation`.
