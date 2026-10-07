# Deferred tests

Running checklist of hardware- or connection-gated tests that cannot run in CI.
Run them when the hardware is available, then tick the box.

Format: `[ ] #<issue> — <what> — <steps> — <hardware> — <expected>`

- [ ] #25 — Injection fuzzing on nRF52 firmware — run fuzz campaign against test firmware — nRF52 dev board — crashes/anomalies are detected and reported
- [ ] Bumble+vhci integration on the Pi self-hosted runner (validate in #13)
- [x] macOS CoreBluetooth manual smoke (cannot virtualize) — done 2026-10-07: `doctor` clean, `scan` discovered real advertisers (names + RSSI) via CoreBluetooth
- [ ] Windows WinRT manual smoke (cannot virtualize) — needs a Windows host
- [ ] #11 — SMP pairing extraction from a real capture — provide a btsnoop with an SMP pairing exchange — needs a capture — expected: classify_pairing_method returns the right method
- [x] #5 — live scan against a real/virtual target — done 2026-10-07 on macOS: `ble-doctor scan` discovered real advertisers with advertised names + RSSI. (Linux/vhci path still pending in #13.)
- [~] #4 — live doctor run on each OS — macOS DONE 2026-10-07 (clean ordered report, no raw OS error); Linux + Windows still pending on those hosts
- [ ] #15 — live L2CAP ATT channel open on Linux — run on a Linux host with CAP_NET_RAW against a BLE peer — needs Linux + adapter — expected: channel opens, MTU response parsed
- [ ] #16 — exact MTU=444 live vs ESP32 ble_ctf — on a Linux host (kernel <=6.12) with a USB dongle, request MTU 444 against the ESP32 and confirm negotiated==444 — needs Linux + dongle + ESP32 — expected: flag 16 solved
- [ ] #13 — register the Pi as a self-hosted Linux runner (labels: self-hosted,linux,bluetooth), install bumble + hci_vhci, enable the integration-vhci job (repo variable VHCI_RUNNER=true), and confirm it runs at least one Bumble+vhci test green — needs the Pi — expected: integration job passes
- [ ] #6 — live GATT enumeration — `ble-doctor scan --target <addr>` connects and enumerates a real/virtual target — needs adapter (or Bumble+vhci) — expected: GattInfo matches the device
- [ ] #17 — connect as 11:22:33:44:55:66 live vs ESP32 ble_ctf — on Linux (kernel <=6.12) with a dongle, set random address and connect so the peer sees it — needs Linux + dongle + ESP32 — expected: flag 15 solved
- [ ] #18 — live SDP/LMP fingerprint on Linux — run `ble-doctor fingerprint --target <addr>` on a Linux host against a BR/EDR+LE device — needs Linux + adapter + a dual-mode target — expected: SDP services + LMP features populated (note: LMP read-remote-features collection is not yet wired on Linux; parse_lmp is ready)
- [ ] #19 — live sniffer capture — flash nRF52840 with nRF Sniffer (or use Ubertooth/Sniffle), run `ble-doctor sniff --device <port>` and feed into analyze — needs sniffer hardware — expected: adv frames captured and MAC-rotation judged
- [ ] #20 — live GATT MITM — on Linux with 2 adapters, clone the target peripheral (bluster) + central to the real device, relay and log a write — needs Linux + 2 BLE adapters + a target — expected: exchange relayed and logged
