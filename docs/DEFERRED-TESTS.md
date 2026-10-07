# Deferred tests

Running checklist of hardware- or connection-gated tests that cannot run in CI.
Run them when the hardware is available, then tick the box.

Format: `[ ] #<issue> — <what> — <steps> — <hardware> — <expected>`

> **Live validation 2026-10-07 (see `ble-ctf-validation.md`):**
> - **macOS vs the real ESP32 `BLECTF_1CBE`:** #4 doctor, #5 scan, **#6 enumerate, #7 score (70/100),
>   #8 probe-writes (13 empirical), #10 DFU, #18 fingerprint** all PASS. #16/#17/#20 give a clean
>   `Unsupported` (capability gating). The "no raw OS error" design holds.
> - **Pi/Linux:** #4 doctor + #5 scan pass; the raw-radio tests that need Linux (#15/#16/#17/#20 live
>   + solving CTF flags 15/16) are **BLOCKED by the kernel 6.18 `le-connection-abort-by-local`
>   regression** (bluez#2503) — surfaced as a clean typed error, not a bug. Unblock with a Linux host
>   on kernel ≤6.12 or a different-chipset dongle.

- [ ] #25 — Injection fuzzing on nRF52 firmware — run fuzz campaign against test firmware — nRF52 dev board — crashes/anomalies are detected and reported
- [ ] Bumble+vhci integration — BLOCKED on this Pi: `hci_vhci` is not built into kernel 6.18.50+rpt-rpi-2712 (no CONFIG_BT_HCIVHCI). Needs a kernel with the module, or a different Linux host.
- [x] macOS CoreBluetooth manual smoke (cannot virtualize) — done 2026-10-07: `doctor` clean, `scan` discovered real advertisers (names + RSSI) via CoreBluetooth
- [ ] Windows WinRT manual smoke (cannot virtualize) — needs a Windows host
- [ ] #11 — SMP pairing extraction from a real capture — provide a btsnoop with an SMP pairing exchange — needs a capture — expected: classify_pairing_method returns the right method
- [x] #5 — live scan — done 2026-10-07 on macOS (CoreBluetooth) AND the Pi/Linux (BlueZ): discovered the ESP32 `BLECTF_1CBE` (34:86:5D:FC:1C:BE) by advertised name.
- [~] #4 — live doctor — macOS + Linux(Pi) DONE 2026-10-07 (clean ordered report, correct capability verdicts, no raw OS error); Windows still pending
- [ ] #15 — live L2CAP ATT channel open on Linux — run on a Linux host with CAP_NET_RAW against a BLE peer — needs Linux + adapter — expected: channel opens, MTU response parsed
- [ ] #16 — exact MTU=444 live vs ESP32 ble_ctf — on a Linux host (kernel <=6.12) with a USB dongle, request MTU 444 against the ESP32 and confirm negotiated==444 — needs Linux + dongle + ESP32 — expected: flag 16 solved
- [ ] #13 — register the Pi as a self-hosted Linux runner (labels: self-hosted,linux,bluetooth), install bumble + hci_vhci, enable the integration-vhci job (repo variable VHCI_RUNNER=true), and confirm it runs at least one Bumble+vhci test green — needs the Pi — expected: integration job passes
- [x] #6 — live GATT enumeration — done 2026-10-07 on macOS vs the ESP32 `BLECTF_1CBE`: 1 service, 13 writable chars, 5 notify with `cccd=None`; feeds #7 scoring (70/100) and #8 probe-writes (13 empirical Accepted)
- [ ] #17 — connect as 11:22:33:44:55:66 live vs ESP32 ble_ctf — on Linux (kernel <=6.12) with a dongle, set random address and connect so the peer sees it — needs Linux + dongle + ESP32 — expected: flag 15 solved
- [~] #18 — fingerprint — LE+GATT part DONE 2026-10-07 on macOS vs the ESP32 (full char/property profile, clean "SDP/LMP need a Linux host"). SDP/LMP collection still needs a Linux host + dual-mode target (and LMP read-remote-features is not yet wired; parse_lmp is ready).
- [ ] #19 — live sniffer capture — flash nRF52840 with nRF Sniffer (or use Ubertooth/Sniffle), run `ble-doctor sniff --device <port>` and feed into analyze — needs sniffer hardware — expected: adv frames captured and MAC-rotation judged
- [ ] #20 — live GATT MITM — on Linux with 2 adapters, clone the target peripheral (bluster) + central to the real device, relay and log a write — needs Linux + 2 BLE adapters + a target — expected: exchange relayed and logged
