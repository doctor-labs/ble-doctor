# Deferred tests

Running checklist of hardware- or connection-gated tests that cannot run in CI.
Run them when the hardware is available, then tick the box.

Format: `[ ] #<issue> — <what> — <steps> — <hardware> — <expected>`

- [ ] #16 — Exact MTU=444 live vs ESP32 ble_ctf — connect and negotiate MTU, read negotiated value — Linux kernel <=6.12 + USB dongle, ESP32 ble_ctf — negotiated MTU is exactly 444
- [ ] #17 — Connect as 11:22:33:44:55:66 live vs ESP32 — set adapter address to 11:22:33:44:55:66, connect to ESP32 — Linux + USB dongle, ESP32 — connection accepted as that address
- [ ] #19 — Live sniffer capture into analyze — capture with sniffer, feed capture to `analyze` — Ubertooth or nRF52840 — capture parses and findings are produced
- [ ] #20 — MITM between two real adapters — relay between central and peripheral via two adapters — two BLE adapters + target device — traffic relayed and observed
- [ ] #25 — Injection fuzzing on nRF52 firmware — run fuzz campaign against test firmware — nRF52 dev board — crashes/anomalies are detected and reported
- [ ] Bumble+vhci integration on the Pi self-hosted runner (validate in #13)
- [ ] macOS CoreBluetooth + Windows WinRT manual smoke (cannot virtualize)
- [ ] #11 — SMP pairing extraction from a real capture — provide a btsnoop with an SMP pairing exchange — needs a capture — expected: classify_pairing_method returns the right method
- [ ] #5 — live scan against a real/virtual target — `ble-doctor scan` on a host with a BLE adapter (or Bumble+vhci) — needs adapter — expected: discovers the target and selects it by advertised name
- [ ] #4 — live doctor run on each OS — `ble-doctor doctor` on macOS / Linux / Windows with and without an adapter — needs those hosts/adapters — expected: clean ordered report, no raw OS error
- [ ] #15 — live L2CAP ATT channel open on Linux — run on a Linux host with CAP_NET_RAW against a BLE peer — needs Linux + adapter — expected: channel opens, MTU response parsed
- [ ] #16 — exact MTU=444 live vs ESP32 ble_ctf — on a Linux host (kernel <=6.12) with a USB dongle, request MTU 444 against the ESP32 and confirm negotiated==444 — needs Linux + dongle + ESP32 — expected: flag 16 solved
- [ ] #13 — register the Pi as a self-hosted Linux runner (labels: self-hosted,linux,bluetooth), install bumble + hci_vhci, enable the integration-vhci job (repo variable VHCI_RUNNER=true), and confirm it runs at least one Bumble+vhci test green — needs the Pi — expected: integration job passes
- [ ] #6 — live GATT enumeration — `ble-doctor scan --target <addr>` connects and enumerates a real/virtual target — needs adapter (or Bumble+vhci) — expected: GattInfo matches the device
- [ ] #17 — connect as 11:22:33:44:55:66 live vs ESP32 ble_ctf — on Linux (kernel <=6.12) with a dongle, set random address and connect so the peer sees it — needs Linux + dongle + ESP32 — expected: flag 15 solved
- [ ] #18 — live SDP/LMP fingerprint on Linux — run `ble-doctor fingerprint --target <addr>` on a Linux host against a BR/EDR+LE device — needs Linux + adapter + a dual-mode target — expected: SDP services + LMP features populated (note: LMP read-remote-features collection is not yet wired on Linux; parse_lmp is ready)
- [ ] #19 — live sniffer capture — flash nRF52840 with nRF Sniffer (or use Ubertooth/Sniffle), run `ble-doctor sniff --device <port>` and feed into analyze — needs sniffer hardware — expected: adv frames captured and MAC-rotation judged
- [ ] #20 — live GATT MITM — on Linux with 2 adapters, clone the target peripheral (bluster) + central to the real device, relay and log a write — needs Linux + 2 BLE adapters + a target — expected: exchange relayed and logged
