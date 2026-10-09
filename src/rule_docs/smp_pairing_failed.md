# smp_pairing_failed

## What it means
An SMP Pairing Failed PDU was seen in the capture. The finding names the reason (Core Spec Vol 3 Part H 3.5.5).

## Why it matters
Informational: a failed pairing can be a normal user abort, or a sign of a misconfigured IO capability, a repeated-attempts lockout or an active attacker. It carries no score weight.

## How to fix
If the failure is unexpected, check the reason: align IO capabilities and AuthReq on both sides, and investigate repeated attempts or DHKey/confirm failures.

## How to verify
Capture the pairing again and run `ble-doctor analyze <capture> --json`; read `smp_pairing_failed` and `data.smp`.
