# unauthenticated_writes

## What it means
GATT characteristics that accept writes from a peer that has not bonded. The check reads `writable_chars`, each with a `requires_bonding` flag. `scan` fills the flag from a heuristic; `probe-writes` measures it empirically.

## Why it matters
A characteristic writable without bonding can be written by anyone in radio range. The check is HIGH and fails when such a characteristic is found, and INFO otherwise. Where the flag came from the heuristic rather than a probe, treat it as an estimate, not an observation.

## How to fix
Require bonding and encryption on characteristics that change device state, so a peer that has never paired cannot write them.

## How to verify
Run `ble-doctor probe-writes <address>` against a device you own to measure it. Without `--allow-all` it only touches characteristics it can justify; `--allow-dangerous` and `--payload` are explicit opt-ins described in the README.
