# Live validation on the Pi rig (2026-10-07)

First live run of ble-doctorV2 on real hardware. Defensive / own-gear.

## Rig

| | |
|---|---|
| Host | Raspberry Pi 5, kernel **6.18.50+rpt-rpi-2712**, BlueZ **5.82** |
| Adapters | hci0 onboard UART `2C:CF:67:58:8D:E9`; hci1 USB CSR `00:1A:7D:DA:71:15` |
| Target | ESP32 running hackgnar/ble_ctf, advertising **`BLECTF_1CBE` (`34:86:5D:FC:1C:BE`)** — own gear |
| Build | `cargo build` from `main`, 5m15s, exit 0 — every `cfg(target_os="linux")` path (bluer raw L2CAP/HCI, bluster MITM, SDP, sniffer) compiled on the first Linux build |

## Passed live ✅

- **`doctor` (Linux):** clean ordered report. Correct verdicts — `daemon: bluetoothd running`, `RawL2cap: needs CAP_NET_RAW`, `SetRandomAddress: needs CAP_NET_ADMIN`, `Mitm: needs second adapter + peripheral mode`. No raw OS error.
- **`scan` (Linux):** discovered **`BLECTF_1CBE`** by its advertised name at `34:86:5D:FC:1C:BE`, alongside neighbours. The ambiguous / no-match path printed the full candidate list live (the #62 behaviour).

## Blocked by the kernel 6.18 BLE regression — NOT a ble-doctor bug

Every test that needs a **held GATT connection** — `scan --target` (connect + enumerate, #6), `probe-writes` (#8), `dfu` (#10 live), exact-MTU 444 (#16), address-override (#17), MITM (#20) — failed to connect. On both adapters the connect returns:

```
gatt: unexpected OS Bluetooth error: le-connection-abort-by-local
  fix: Retry; if it persists, toggle Bluetooth off/on and rerun with --verbose.
```

This is the **Linux 6.15+ BLE connection-abort regression** ([bluez/bluez#2503](https://github.com/bluez/bluez/issues/2503)): the kernel cancels `LE Create Connection` unless discovery is kept running throughout, and this ESP32 + BlueZ 5.82 cannot hold a link long enough to enumerate. It matches ble-doctor v1's finding exactly. Keeping active discovery across the connect (the documented workaround) did not reliably help on this host.

**Key result:** ble-doctor surfaced the kernel fault as a **clean typed error with a remediation line**, never a raw traceback — validating the "no raw OS error" design against a real kernel failure. The raw L2CAP/HCI wire codecs (exact-MTU=444, LE Set Random Address) remain proven by unit tests; only the live link is blocked.

## To unblock the connection-dependent live tests

Any one of:
- a Linux host on **kernel ≤ 6.12** (or a patched 6.18), e.g. the Pi downgraded or a different Linux box / VM with USB-dongle passthrough;
- a **different-chipset BLE dongle** that interops with this kernel;
- **Bumble + vhci** virtual radio — but `hci_vhci` is **not built into this Pi's kernel**, so that path needs a kernel module first.

CTF flags 15/16 (#17/#16) specifically stay blocked until one of the above, exactly as recorded for v1.

## macOS run vs the same ESP32 (2026-10-07) — the connect tests the Pi couldn't

The ESP32 `BLECTF_1CBE` was also in BLE range of a Mac (CoreBluetooth, which has **no** kernel-6.18
regression), so the connection-dependent tests macOS supports were run live against it.

**Passed live (macOS, real ESP32):**
- **#6 enumerate** — 1 service, 13 writable characteristics (`0xff02`..`0xff16`), 5 notify/indicate
  with **`cccd=None`** (the no-CCCD case from #66, confirmed on real firmware).
- **#7 scoring + report** — **score 70/100** (one HIGH caps at 70 — the product-of-survival math),
  `unauthenticated_writes` HIGH listing all 13 chars.
- **#8 probe-writes** (`--allow-dangerous`) — all 13 writable chars **empirically Accepted unbonded**
  (`requires_bonding=false`), confirming the finding empirically, not just heuristically. (This writes
  to the board and changes ble_ctf challenge state; it is own gear and resets on reboot.)
- **#10 DFU checks** — `dfu_entry_point` / `dfu_signing_enforced` (INCONCLUSIVE, 0 weight) /
  `dfu_surface_absent` all ran; correctly reports no DFU surface as evidence.
- **#18 fingerprint** — full LE+GATT profile (services/chars/properties) + clean
  "SDP/LMP need a Linux host".

**Capability gating validated live (clean `Unsupported`, no crash) on macOS:**
- `#16` exact-MTU → "raw L2CAP/HCI is not supported on macos".
- `#17` address-override → same.
- `#20` MITM → "needs Linux with 2 adapters + peripheral mode (bluster)".

**Still genuinely blocked** (need a good-kernel Linux host near the ESP32, or a different-chipset
dongle): actually *solving* CTF flags 15/16 (#16/#17 raw radio) and live MITM (#20) — macOS cannot do
raw HCI/L2CAP or the bluster peripheral, and the Pi's kernel 6.18 aborts the link. `#9 read-values`
reads only non-SIG services; this board puts everything under the `0000ffxx` SIG base, so read-values
correctly skips it all.

## #60 regression-workaround attempt + definitive HCI-trace diagnosis (2026-10-07)

Added a Linux `bluer`-backed connect path that holds a discovery session open across
`device.connect()` (`--adapter <hciN>`), the documented fix for bug #2503. It **builds and runs on
the Pi** (kernel 6.18). But connecting to the ESP32 still failed — and an `btmon` HCI trace shows
**why, conclusively, and it is NOT bug #2503**:

```
< LE Create Connection            → Status: Success
> LE Connection Complete          → Status: Success, Handle 64   (the link forms)
< LE Read Remote Used Features     (kernel's automatic post-connect query)
> LE Read Remote Used Features    → Status: Connection Failed to be Established (0x3e)
> Disconnect Complete             → Reason: 0x3e                 (~0.5s after connect)
```

The connection physically establishes, then the **ESP32 fails the kernel's post-connect
`LE Read Remote Used Features` exchange**, and kernel 6.18 aborts with `0x3e`. BlueZ reports this as
`le-connection-abort-by-local`. This is an **ESP32 ↔ kernel-6.18 controller interop failure**,
distinct from the discovery-abort regression — holding discovery cannot fix it (confirmed: forced
continuous external `btmgmt find` throughout the connect did not help).

**Conclusions:**
- The `--adapter` + held-discovery feature (#60) is correct and valuable for the *common* 6.15+
  discovery-abort case; it simply cannot be live-verified against this ESP32, which has a different
  bug. (Verify the workaround later against a normal bonded peripheral on a 6.15+ host.)
- Connecting to **this ESP32 from Linux** needs a **kernel ≤ 6.12** (e.g. a spare SD image) — the
  only remaining path for live CTF flags 15/16 and live MITM on this rig. The full audit is already
  validated against this ESP32 via macOS (see above).
