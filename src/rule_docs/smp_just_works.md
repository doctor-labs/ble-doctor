# smp_just_works

## What it means
The association model derived from the IO capabilities, OOB flags and MITM flags (Core Spec Vol 3 Part H Table 2.8) is Just Works, which is unauthenticated.

## Why it matters
Just Works gives encryption without protection against an active man-in-the-middle during pairing. Reported at MEDIUM; devices with no input or output cannot do better without OOB.

## How to fix
Set the MITM bit and use a stronger association model: a display or keyboard IO capability for Numeric Comparison or Passkey Entry, or out-of-band pairing (OOB).

## How to verify
Capture the pairing again and run `ble-doctor analyze <capture> --json`; read `smp_just_works` and `data.smp`.
