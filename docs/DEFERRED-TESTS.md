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
