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
