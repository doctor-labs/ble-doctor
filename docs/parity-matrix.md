# BLE Doctor — Reference Tool Parity Matrix

This document benchmarks `ble-doctor` against standard BLE diagnostic and security reference tools (`bettercap`, `btlejack`, `Mirage`, `nRF Connect`, `SweynTooth`, `bluetoothctl`).

`ble-doctor` is designed as a single cross-platform Rust CLI that drives the radio directly (no external binary dependencies) while providing a superset of capability with standardized `doctor/1` scoring and SARIF output.

---

## Capability Matrix

| Feature Domain | `ble-doctor` | `bettercap` | `btlejack` | `Mirage` | `nRF Connect` | `SweynTooth` | `bluetoothctl` |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1. Scanning & Discovery** |
| Passive BLE Adv Scan | ✅ Native | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| Cross-Platform (Linux/macOS/Win) | ✅ Pure Rust | ⚠️ Linux/macOS | ⚠️ Linux | ⚠️ Linux | ✅ Desktop/Mobile | ⚠️ Linux | ❌ Linux only |
| Interactive Scanner TUI | ✅ `ratatui` | ❌ CLI/Web | ❌ CLI | ❌ CLI | ✅ GUI | ❌ CLI | ⚠️ CLI shell |
| Target & RSSI Filtering | ✅ | ✅ | ❌ | ⚠️ | ✅ | ❌ | ⚠️ |
| **2. GATT Services & Characteristics** |
| Full Tree Enumeration | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| Interactive Read / Write Probes | ✅ Opt-in | ✅ | ❌ | ✅ | ✅ Manual | ❌ | ✅ Manual |
| CCCD / Descriptor Inspection | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| Safe DFU Guardrails | ✅ Default block | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **3. SMP & Pairing Analysis** |
| LE Secure Connections vs Legacy | ✅ | ⚠️ Partial | ❌ | ⚠️ | ⚠️ | ❌ | ⚠️ |
| Legacy STK Derivation (Just Works) | ✅ Native `c1`/`s1` | ❌ | ⚠️ Hardware | ❌ | ❌ | ❌ | ❌ |
| Offline 6-Digit Passkey PIN Crack | ✅ `c1` sweep | ❌ | ⚠️ HW required | ❌ | ❌ | ❌ | ❌ |
| Short Key / KNOB Downgrade Check | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **4. Sniffer & Capture Ingestion** |
| Native `pcap` (LL / LL_PHDR) | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Native `btsnoop` (H4 / Linux Mon) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ HCI log |
| MAC Rotation & Privacy Tracking | ✅ `MIN_ROTATION` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Offline RPA Resolution via IRK | ✅ `ah` algorithm | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **5. MITM & Proxying** |
| GATT Service Cloning | ✅ Linux `bluster` | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Connection Hijacking | ⚠️ Hardware-gated | ❌ | ✅ Micro:bit | ⚠️ | ❌ | ❌ | ❌ |
| **6. Fuzzing & CVE Diagnostics** |
| SweynTooth Vulnerability Checks | ✅ Heuristic/Rules | ❌ | ❌ | ❌ | ❌ | ✅ Explicit POCs | ❌ |
| DFU Surface Classification | ✅ | ❌ | ❌ | ❌ | ⚠️ Manual | ❌ | ❌ |
| **7. Scoring & Machine Output** |
| Standardized `doctor/1` Score | ✅ Product-of-survival | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SARIF 2.1.0 Static Analysis Export | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Baseline Finding Diffing | ✅ Exit code 3 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Model Context Protocol (MCP) Server | ✅ `scan` & `analyze` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

---

## Detailed Gap Analysis & Parity Notes

### 1. Scanning & Radio Driver
- **`ble-doctor` vs `bluetoothctl` / `bettercap`**: `ble-doctor` uses `btleplug` and Linux `bluer` natively without spawing `bluetoothctl` or `hcitool`. On Linux, raw HCI socket flags permit custom random MAC addresses (`--as-address`) and ATT MTU negotiation (`--mtu`).
- **TUI**: `ble-doctor` includes a terminal live device list similar to `nRF Connect` desktop, rendering RSSI, advertised names, and service UUIDs.

### 2. SMP / Cryptography Parity
- **`btlejack`**: `btlejack` uses dedicated Micro:bit hardware sniffer firmware to intercept LL connections and extract STKs during pairing. `ble-doctor` brings this cryptanalysis natively to software: it parses `pcap`/`btsnoop` captures, implements Bluetooth Core Spec Vol 3 Part H §2.2 (`e`, `c1`, `s1`), verifies `Mconfirm`/`Sconfirm`, derives STK for Just Works (TK=0), and performs bounded offline enumeration of 6-digit Passkey Entry PINs (`000000..=999999`) in under 20ms without external binaries.

### 3. Capture & Privacy Analysis
- **RPA & MAC Rotation**: Unlike standard packet analyzers, `ble-doctor` inspects advertising timestamps to flag static public addresses across long observation windows (`MIN_ROTATION_OBSERVATION_SECONDS=600`), and resolves Resolvable Private Addresses (RPAs) using the §2.2.2 `ah` security function when an IRK is supplied.

### 4. Machine Standard Integration (`doctor/1`, SARIF, MCP)
- **Scoring**: `score = 100 · ∏(1 - weight/100)` over failed checks (`CRIT=50`, `HIGH=30`, `MED=15`, `LOW=5`, `INFO=0`).
- **SARIF 2.1.0**: Enables direct integration into GitHub Security / CI static analysis pipelines.
- **MCP Server**: Implements model context protocol endpoints for AI agent automation while gating dangerous write/DFU subcommands.
