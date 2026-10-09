# smp_legacy_pairing

## What it means
The captured SMP Pairing Request/Response did not both set the Secure Connections (SC) bit in AuthReq, so the link used LE legacy pairing (Core Spec Vol 3 Part H 2.3).

## Why it matters
Legacy pairing exchanges the temporary key over the air without ECDH. A passive eavesdropper who records the pairing can brute-force the TK and recover the LTK (CrackLE-style). Reported at HIGH.

## How to fix
Enable LE Secure Connections on the device's BLE stack and require it on both sides (set the SC bit in AuthReq).

## How to verify
Capture the pairing again and run `ble-doctor analyze <capture> --json`; read `smp_legacy_pairing` and `data.smp`.
