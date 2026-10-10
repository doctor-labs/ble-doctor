//! Sniffer ingestion (no Wireshark). Parses **Sniffle** host output (NCC Group Sniffle,
//! `python_cli/sniffle/pcap.py` / `sniffle_hw.py`): one base64 line per message; decoded bytes are
//! `[len/3][type][body]`; type 0x10 = BLE packet with body
//! `<u32 ts_us><u16 len|dir<<15><i8 rssi><u8 channel><data>` (little-endian).
//! Advertising `data` = 2-byte PDU header (type in low nibble) + payload starting with AdvA (LE).
//! Format layout is from memory of the Sniffle source, unverified against hardware (see DEFERRED #19).
//! Output is the `capture.rs` shape, so it feeds `check_mac_rotation` unchanged.

use crate::capability::{self, Feature};
use crate::capture::{AdvFrame, CaptureInfo};
use crate::error::BleError;

const MSG_PACKET: u8 = 0x10;

fn b64(line: &str) -> Option<Vec<u8>> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in line.trim().bytes().take_while(|&c| c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Parse a Sniffle text stream; non-advertising, malformed, or non-packet lines are skipped.
/// ponytail: u32 µs timestamps wrap at ~71 min; unwrap if longer captures matter.
pub fn parse_sniffle(text: &str) -> CaptureInfo {
    let mut info = CaptureInfo {
        capture_flavour: Some("sniffle".into()),
        ..Default::default()
    };
    for raw in text.lines().filter_map(b64) {
        let [_, ty, body @ ..] = raw.as_slice() else {
            continue;
        };
        if *ty != MSG_PACKET || body.len() < 8 + 8 {
            continue;
        }
        let ts = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let (chan, pdu) = (body[7], &body[8..]);
        // ADV_IND, ADV_DIRECT_IND, ADV_NONCONN_IND, SCAN_RSP, ADV_SCAN_IND carry AdvA first.
        if !(37..=39).contains(&chan) || !matches!(pdu[0] & 0x0F, 0 | 1 | 2 | 4 | 6) {
            continue;
        }
        let mac: Vec<String> = pdu[2..8].iter().rev().map(|b| format!("{b:02x}")).collect();
        let ts_secs = ts as f64 / 1e6;
        info.adv_mac_addresses.push(mac.join(":"));
        info.adv_frame_timestamps.push(ts_secs);
        let adv_data = pdu
            .get(8..8 + (pdu[1] as usize).saturating_sub(6))
            .unwrap_or(&[]);
        info.adv_frames.push(AdvFrame {
            ts: ts_secs,
            mac_onair: pdu[2..8].try_into().unwrap(),
            pdu_type: pdu[0] & 0x0F,
            adv_data: adv_data.to_vec(),
        });
    }
    if let (Some(min), Some(max)) = (
        info.adv_frame_timestamps.iter().cloned().reduce(f64::min),
        info.adv_frame_timestamps.iter().cloned().reduce(f64::max),
    ) {
        if info.adv_frame_timestamps.len() >= 2 {
            info.duration_seconds = Some(max - min);
        }
    }
    info
}

/// Drive a USB/serial sniffer at `device` (e.g. `/dev/ttyACM0`).
/// No serial backend is wired yet: fails cleanly, never panics.
pub fn drive_sniffer(device: &str) -> Result<CaptureInfo, BleError> {
    capability::require(Feature::Sniff).map_err(|_| BleError::Unsupported {
        feature: "sniff".into(),
        platform: format!("{:?}", capability::Platform::current()),
    })?;
    if !std::path::Path::new(device).exists() {
        return Err(BleError::DeviceNotFound);
    }
    // ponytail: needs a serial crate + sniffer hardware; use `sniff --from-file` meanwhile.
    Err(BleError::Unsupported {
        feature: "live sniffer capture".into(),
        platform: "this build (no serial backend)".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::check_mac_rotation;

    const A_1S: &str = "BxBAQg8ACwDOJQAJBQQDAgGqAgEG";
    const B_700S: &str = "BxAAJ7kpCwDOJQAJBQQDAgG7AgEG";
    const A_700S: &str = "BxAAJ7kpCwDOJQAJBQQDAgGqAgEG";

    #[test]
    fn parses_addresses_and_timestamps() {
        let i = parse_sniffle(&format!("{A_1S}\njunk!\n{B_700S}\n"));
        assert_eq!(
            i.adv_mac_addresses,
            ["aa:01:02:03:04:05", "bb:01:02:03:04:05"]
        );
        assert_eq!(i.adv_frame_timestamps, [1.0, 700.0]);
        assert_eq!(i.duration_seconds, Some(699.0));
    }

    #[test]
    fn rotation_verdicts() {
        let rot = check_mac_rotation(&parse_sniffle(&format!("{A_1S}\n{B_700S}")), &[]);
        assert!(rot.passed);
        let stat = check_mac_rotation(&parse_sniffle(&format!("{A_1S}\n{A_700S}")), &[]);
        assert!(!stat.passed);
    }

    #[test]
    fn drive_without_hardware_is_clean_error() {
        assert_eq!(
            drive_sniffer("/dev/does-not-exist-ble-sniffer"),
            Err(BleError::DeviceNotFound)
        );
    }
}
