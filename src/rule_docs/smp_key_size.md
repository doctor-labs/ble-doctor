# smp_key_size

## What it means
The effective maximum encryption key size (the smaller of both sides' Maximum Encryption Key Size) is below 16 bytes. 7 is the spec minimum.

## Why it matters
A short key is cheap to brute-force and is the lever for KNOB-style key-size downgrades. 7 bytes or less is HIGH, 8 to 15 is MEDIUM.

## How to fix
Set the maximum encryption key size to 16 in the BLE stack and reject pairing that negotiates less.

## How to verify
Capture the pairing again and run `ble-doctor analyze <capture> --json`; read `smp_key_size` and `data.smp`.
