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
- [ ] #11/#65 — SMP pairing extraction from a real capture (offline decoder + synthetic-fixture tests done in #65; only a real btsnoop/pcap remains) — provide a btsnoop with an SMP pairing exchange — needs a capture — expected: classify_pairing_method returns the right method
- [x] #5 — live scan — done 2026-10-07 on macOS (CoreBluetooth) AND the Pi/Linux (BlueZ): discovered the ESP32 `BLECTF_1CBE` (34:86:5D:FC:1C:BE) by advertised name.
- [~] #4 — live doctor — macOS + Linux(Pi) DONE 2026-10-07 (clean ordered report, correct capability verdicts, no raw OS error); Windows still pending
- [ ] #15 — live L2CAP ATT channel open on Linux — run on a Linux host with CAP_NET_RAW against a BLE peer — needs Linux + adapter — expected: channel opens, MTU response parsed
- [ ] #16 — exact MTU=444 live vs ESP32 ble_ctf — on a Linux host (kernel <=6.12) with a USB dongle, request MTU 444 against the ESP32 and confirm negotiated==444 — needs Linux + dongle + ESP32 — expected: flag 16 solved
- [ ] #13 — register the Pi as a self-hosted Linux runner (labels: self-hosted,linux,bluetooth), install bumble + hci_vhci, enable the integration-vhci job (repo variable VHCI_RUNNER=true), and confirm it runs at least one Bumble+vhci test green — needs the Pi — expected: integration job passes
- [x] #6 — live GATT enumeration — done 2026-10-07 on macOS vs the ESP32 `BLECTF_1CBE`: 1 service, 13 writable chars, 5 notify with `cccd=None`; feeds #7 scoring (70/100) and #8 probe-writes (13 empirical Accepted)
- [ ] #17 — connect as 11:22:33:44:55:66 live vs ESP32 ble_ctf — on Linux (kernel <=6.12) with a dongle, set random address and connect so the peer sees it — needs Linux + dongle + ESP32 — expected: flag 15 solved
- [~] #18 — fingerprint — LE+GATT part DONE 2026-10-07 on macOS vs the ESP32 (full char/property profile, clean "SDP/LMP need a Linux host"). SDP/LMP collection still needs a Linux host + dual-mode target. LMP read-remote-features is wired (#64, `src/hci_lmp.rs`, unit-tested with byte fixtures + a mocked transport); live check is #70: run `sudo ble-doctor fingerprint --target <BD_ADDR> --json` on Linux (CAP_NET_RAW) against a phone/classic device and confirm `lmp.version`, `lmp.manufacturer_name` and `lmp.features` match `btmon`/`hcitool info`.
- [ ] #19 — live sniffer capture — flash nRF52840 with nRF Sniffer (or use Ubertooth/Sniffle), run `ble-doctor sniff --device <port>` and feed into analyze — needs sniffer hardware — expected: adv frames captured and MAC-rotation judged
- [~] #20/#68 — live GATT MITM — the clone/serve half is DONE (#63): `mitm::live::serve` connects to the target, clones its GATT onto a bluster peripheral, advertises it and relays every victim read/write to the real device via `MitmRelay`, logged. GATT-tree construction and the relay/event-handling logic are unit-tested against `testkit::FakeClient` (no D-Bus, no radio); forwarding the real device's own notifications/indications into the victim's subscription is not implemented (needs a `GattClient::subscribe`, which doesn't exist). #68 — on Linux with 2 BLE adapters + a holdable connection to a target, run `ble-doctor mitm --target <addr> --allow-dangerous` and from a second central (or phone) connect to the clone and write a characteristic — needs Linux + 2 BLE adapters + a target — expected: the write reaches the real device and is logged.
- [ ] doctor-kit migration B3 — live `scan --target` through the kit pipeline (the radio half has no CI coverage; the fake-radio chain and the goldens do) — on a real radio (macOS and the Pi/Linux), against the ESP32 `BLECTF_1CBE` or any peripheral: (1) `ble-doctor scan` lists devices and exits 0 with nothing else; (2) `ble-doctor scan --target <addr-or-name> --timeout 8` prints the device list, `selected:`, the `gatt:` summary, then the kit face; exit 1 when a finding reaches `--fail-on high`; (3) `--json` writes ONLY the envelope on stdout (`| jq -e '.schema=="doctor/1"'`), the device list goes to stderr, and `diff <(ble-doctor-0.2.0 scan --target T --json) <(ble-doctor scan --target T --json)` is empty; (4) `--sarif out.sarif` is identical to 0.2.0's, and `--baseline <that --json file>` exits 0 (unchanged) while `--baseline` of an empty report with `--fail-on info` exits 3; (5) `scan --tui --target T` opens the explorer (`q` quits), then the report prints; (6) with Bluetooth off or no adapter: stderr `scan: ...` plus `  fix: ...`, exit 2, empty stdout; (7) over `mcp`, the `scan` tool with a target returns the same envelope — needs a BLE radio and a peripheral — expected: all seven match the pre-migration behavior
