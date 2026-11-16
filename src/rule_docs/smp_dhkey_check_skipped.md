# smp_dhkey_check_skipped

## What it means
In an LE Secure Connections pairing, both sides exchanged their public keys but no Pairing DHKey Check followed (Core Spec Vol 3 Part H 3.5.1). The peers end up bonded without ever verifying that they derived the same key.

## Why it matters
The DHKey Check is what proves the two sides hold the same LTK. Skipping it (or capturing only one direction of the exchange) is the fingerprint of a pairing that was downgraded or intercepted; the link can be bonded to the wrong peer. Reported at MEDIUM when the capture holds both public keys, and as an INFO coverage gap when the capture is too short to tell a skipped check from a partial capture.

## How to fix
Make the device's BLE stack perform the DHKey Check in every LE Secure Connections pairing and abort the pairing when the peer's DHKey Check value is missing or wrong.

## How to verify
Capture the pairing again and run `ble-doctor analyze <capture> --json`; read `smp_dhkey_check_skipped` and `data.smp` (the `pairing_public_key` / `pairing_dhkey_check` PDUs).
