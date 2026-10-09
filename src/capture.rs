//! Native btsnoop/pcap ingestion and capture-based checks (no tshark).

use crate::checks::{CheckResult, Severity};
use serde::Serialize;
use std::collections::HashSet;

/// A RPA rotates on a ~2-15 min timer; a capture shorter than this cannot call an address static.
pub const MIN_ROTATION_OBSERVATION_SECONDS: f64 = 600.0;

const LINKTYPE_BLUETOOTH_LE_LL: u32 = 251;
const LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: u32 = 256;
const ADV_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
const BTSNOOP_DATALINK_H4: u32 = 1002;
const BTSNOOP_DATALINK_LINUX_MONITOR: u32 = 2001;
/// Microseconds from the btsnoop (year 0) epoch to the Unix epoch.
const BTSNOOP_EPOCH_OFFSET: i64 = 0x00DC_DDB3_0F2F_8000;

/// Fields extracted from a capture (v1 `collect_capture_fields`).
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct CaptureInfo {
    pub adv_mac_addresses: Vec<String>,
    pub adv_frame_timestamps: Vec<f64>,
    pub duration_seconds: Option<f64>,
    pub capture_flavour: Option<String>,
}

fn fmt_mac(le: &[u8]) -> String {
    let b: Vec<String> = le.iter().rev().map(|x| format!("{x:02x}")).collect();
    b.join(":")
}

fn u32_at(d: &[u8], o: usize, be: bool) -> Option<u32> {
    let a: [u8; 4] = d.get(o..o + 4)?.try_into().ok()?;
    Some(if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    })
}

fn finish(mut info: CaptureInfo) -> CaptureInfo {
    let ts = &info.adv_frame_timestamps;
    if ts.len() >= 2 {
        let min = ts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = ts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        info.duration_seconds = Some(max - min);
    }
    info
}

/// Parse a pcap or btsnoop capture from bytes.
pub fn parse_capture(data: &[u8]) -> Result<CaptureInfo, String> {
    if data.starts_with(b"btsnoop\0") {
        return parse_btsnoop(data);
    }
    parse_pcap(data)
}

fn parse_pcap(d: &[u8]) -> Result<CaptureInfo, String> {
    let magic = u32_at(d, 0, false).ok_or("file too short")?;
    // (big-endian file, nanosecond timestamps)
    let (be, nano) = match magic {
        0xA1B2_C3D4 => (false, false),
        0xA1B2_3C4D => (false, true),
        0xD4C3_B2A1 => (true, false),
        0x4D3C_B2A1 => (true, true),
        _ => return Err("unrecognised capture format (not pcap or btsnoop)".into()),
    };
    let linktype = u32_at(d, 20, be).ok_or("truncated pcap header")?;
    let skip = match linktype {
        LINKTYPE_BLUETOOTH_LE_LL => 0,
        LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR => 10,
        other => return Err(format!("unsupported pcap linktype {other}")),
    };
    let mut info = CaptureInfo {
        capture_flavour: Some("pcap-le-ll".into()),
        ..Default::default()
    };
    let mut off = 24;
    while let (Some(sec), Some(frac), Some(len)) = (
        u32_at(d, off, be),
        u32_at(d, off + 4, be),
        u32_at(d, off + 8, be),
    ) {
        let Some(pkt) = d.get(off + 16..off + 16 + len as usize) else {
            break;
        };
        off += 16 + len as usize;
        let ll = pkt.get(skip..).unwrap_or(&[]);
        // AA(4) hdr(2) AdvA(6); PDU types 0,1,2,4,6 carry AdvA first.
        if ll.len() < 12 || u32::from_le_bytes(ll[0..4].try_into().unwrap()) != ADV_ACCESS_ADDRESS {
            continue;
        }
        if !matches!(ll[4] & 0x0F, 0 | 1 | 2 | 4 | 6) {
            continue;
        }
        let div = if nano { 1e9 } else { 1e6 };
        info.adv_mac_addresses.push(fmt_mac(&ll[6..12]));
        info.adv_frame_timestamps
            .push(sec as f64 + frac as f64 / div);
    }
    Ok(finish(info))
}

fn parse_btsnoop(d: &[u8]) -> Result<CaptureInfo, String> {
    let datalink = u32_at(d, 12, true).ok_or("truncated btsnoop header")?;
    if datalink != BTSNOOP_DATALINK_H4 && datalink != BTSNOOP_DATALINK_LINUX_MONITOR {
        return Err(format!("unsupported btsnoop datalink {datalink}"));
    }
    let mut info = CaptureInfo {
        capture_flavour: Some(
            if datalink == BTSNOOP_DATALINK_H4 {
                "btsnoop-h4"
            } else {
                "btsnoop-linux-monitor"
            }
            .into(),
        ),
        ..Default::default()
    };
    let mut off = 16;
    while let (Some(incl), Some(flags), Some(ts_hi), Some(ts_lo)) = (
        u32_at(d, off + 4, true),
        u32_at(d, off + 8, true),
        u32_at(d, off + 16, true),
        u32_at(d, off + 20, true),
    ) {
        let Some(pkt) = d.get(off + 24..off + 24 + incl as usize) else {
            break;
        };
        off += 24 + incl as usize;
        // Linux monitor: flags is the opcode (3 = HCI event). H4: payload starts with type 0x04.
        let evt = if datalink == BTSNOOP_DATALINK_LINUX_MONITOR {
            (flags & 0xFFFF == 3).then_some(pkt)
        } else {
            (pkt.first() == Some(&4)).then(|| &pkt[1..])
        };
        let ts_us = ((u64::from(ts_hi) << 32) | u64::from(ts_lo)) as i64 - BTSNOOP_EPOCH_OFFSET;
        let ts = ts_us as f64 / 1e6;
        for mac in evt.map(le_adv_reports).unwrap_or_default() {
            info.adv_mac_addresses.push(mac);
            info.adv_frame_timestamps.push(ts);
        }
    }
    Ok(finish(info))
}

/// Addresses from an HCI LE Meta event (0x3e): legacy (0x02) and extended (0x0d) adv reports.
fn le_adv_reports(e: &[u8]) -> Vec<String> {
    let mut out = vec![];
    if e.len() < 4 || e[0] != 0x3E {
        return out;
    }
    let (sub, n, mut p) = (e[2], e[3], 4);
    for _ in 0..n {
        // fixed bytes before dlen: legacy = type,atype,addr(6); extended = type(2),atype,addr(6),
        // phy1,phy2,sid,txp,rssi,interval(2),dtype,daddr(6)
        let (addr_at, dlen_at) = match sub {
            0x02 => (p + 2, p + 8),
            0x0D => (p + 3, p + 24),
            _ => return out,
        };
        let (Some(a), Some(&dlen)) = (e.get(addr_at..addr_at + 6), e.get(dlen_at)) else {
            return out;
        };
        out.push(fmt_mac(a));
        // legacy reports have a trailing RSSI byte
        p = dlen_at + 1 + dlen as usize + usize::from(sub == 0x02);
    }
    out
}

/// Duration-aware MAC rotation verdict (v1 `check_mac_rotation`).
pub fn check_mac_rotation(info: &CaptureInfo) -> CheckResult {
    let id = "mac_rotation".to_string();
    let macs = &info.adv_mac_addresses;
    let unique = macs.iter().collect::<HashSet<_>>().len();
    let (severity, passed, detail) = if macs.len() < 2 {
        (
            Severity::Info,
            false,
            "Not enough advertisement frames captured to judge MAC rotation.".to_string(),
        )
    } else if unique > 1 {
        (
            Severity::Info,
            true,
            format!(
                "MAC address rotates ({unique} unique addresses across {} frames).",
                macs.len()
            ),
        )
    } else {
        match info.duration_seconds {
            None => (
                Severity::Info,
                false,
                format!(
                    "MAC rotation INCONCLUSIVE - one address across {} frames, but the capture carries no usable timestamps.",
                    macs.len()
                ),
            ),
            Some(s) if s < MIN_ROTATION_OBSERVATION_SECONDS => (
                Severity::Info,
                false,
                format!(
                    "MAC rotation INCONCLUSIVE - one address across {} frames, but the capture spans only {s:.0}s, below the {MIN_ROTATION_OBSERVATION_SECONDS:.0}s needed to outlast a Resolvable Private Address rotation. Capture longer before judging.",
                    macs.len()
                ),
            ),
            Some(s) => (
                Severity::Medium,
                false,
                format!(
                    "MAC address is static across all {} captured advertisement frames over {s:.0}s - trackable.",
                    macs.len()
                ),
            ),
        }
    };
    CheckResult {
        id,
        severity,
        passed,
        detail,
        // every INFO non-pass above is a "cannot judge yet" verdict
        inconclusive: severity == Severity::Info && !passed,
    }
}

const TABLE_2_8: [[&str; 5]; 5] = [
    [
        "just_works",
        "just_works",
        "passkey_entry",
        "just_works",
        "passkey_entry",
    ],
    [
        "just_works",
        "just_works",
        "passkey_entry",
        "just_works",
        "passkey_entry",
    ],
    [
        "numeric_comparison",
        "numeric_comparison",
        "passkey_entry",
        "just_works",
        "passkey_entry",
    ],
    ["just_works"; 5],
    [
        "passkey_entry",
        "passkey_entry",
        "passkey_entry",
        "just_works",
        "numeric_comparison",
    ],
];

/// One side's SMP pairing parameters.
#[derive(Debug, Clone, Copy)]
pub struct PairingSide {
    pub io: u8,
    pub oob: bool,
    pub mitm: bool,
    pub sc: bool,
}

/// LE pairing association model (Core Spec Vol 3 Part H 2.3.5.1, Tables 2.6-2.8).
pub fn classify_pairing_method(i: PairingSide, r: PairingSide) -> &'static str {
    if i.io > 4 || r.io > 4 {
        return "unknown";
    }
    let sc = i.sc && r.sc;
    if (i.oob && r.oob) || (sc && (i.oob || r.oob)) {
        return "oob";
    }
    if !(i.mitm || r.mitm) {
        return "just_works";
    }
    let m = TABLE_2_8[i.io as usize][r.io as usize];
    if m == "numeric_comparison" && !sc {
        return "just_works";
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcap(macs: &[[u8; 6]], ts: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(0xA1B2_C3D4u32.to_le_bytes());
        out.extend([2, 0, 4, 0]);
        out.extend([0u8; 8]);
        out.extend(65535u32.to_le_bytes());
        out.extend(LINKTYPE_BLUETOOTH_LE_LL.to_le_bytes());
        for (mac, t) in macs.iter().zip(ts) {
            let mut p = ADV_ACCESS_ADDRESS.to_le_bytes().to_vec();
            let adv = [0x02, 0x01, 0x06];
            p.extend([0x40, 6 + adv.len() as u8]); // ADV_IND, TxAdd=1
            p.extend(mac.iter().rev()); // AdvA little-endian
            p.extend(adv);
            p.extend([0, 0, 0]); // crc
            out.extend(t.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            out.extend((p.len() as u32).to_le_bytes());
            out.extend((p.len() as u32).to_le_bytes());
            out.extend(p);
        }
        out
    }

    fn mac(n: u8) -> [u8; 6] {
        [0xC0, 0, 0, 0, 0, n]
    }

    #[test]
    fn rotating_addresses_pass() {
        let macs: Vec<_> = (0..5).map(mac).collect();
        let info = parse_capture(&pcap(&macs, &[0, 300, 600, 900, 1200])).unwrap();
        assert_eq!(info.adv_mac_addresses[1], "c0:00:00:00:00:01");
        let r = check_mac_rotation(&info);
        assert!(r.passed);
        assert_eq!(r.severity, Severity::Info);
    }

    #[test]
    fn static_address_over_600s_is_medium() {
        let info = parse_capture(&pcap(&[mac(1); 3], &[0, 300, 700])).unwrap();
        assert_eq!(info.duration_seconds, Some(700.0));
        let r = check_mac_rotation(&info);
        assert!(!r.passed);
        assert_eq!(r.severity, Severity::Medium);
    }

    #[test]
    fn short_capture_is_inconclusive() {
        let r = check_mac_rotation(&parse_capture(&pcap(&[mac(1); 3], &[0, 5, 30])).unwrap());
        assert!(!r.passed);
        assert_eq!(r.severity, Severity::Info);
        assert!(r.detail.contains("INCONCLUSIVE"));
    }

    #[test]
    fn btsnoop_linux_monitor_adv_reports() {
        let mut out = b"btsnoop\0".to_vec();
        out.extend(1u32.to_be_bytes());
        out.extend(BTSNOOP_DATALINK_LINUX_MONITOR.to_be_bytes());
        for (i, n) in [1u8, 2].iter().enumerate() {
            let mut e = vec![0x3E, 0, 0x02, 1, 0, 1];
            e.extend(mac(*n).iter().rev());
            e.extend([3, 2, 1, 6, 0xC8]); // dlen + data + rssi
            e[1] = (e.len() - 2) as u8;
            let ts = (1_700_000_000i64 + i as i64 * 700) * 1_000_000 + BTSNOOP_EPOCH_OFFSET;
            out.extend((e.len() as u32).to_be_bytes());
            out.extend((e.len() as u32).to_be_bytes());
            out.extend(3u32.to_be_bytes());
            out.extend(0u32.to_be_bytes());
            out.extend(ts.to_be_bytes());
            out.extend(e);
        }
        let info = parse_capture(&out).unwrap();
        assert_eq!(
            info.capture_flavour.as_deref(),
            Some("btsnoop-linux-monitor")
        );
        assert_eq!(info.adv_mac_addresses.len(), 2);
        assert_eq!(info.duration_seconds, Some(700.0));
    }

    #[test]
    fn pairing_method_table() {
        let s = |io, mitm, sc| PairingSide {
            io,
            oob: false,
            mitm,
            sc,
        };
        assert_eq!(
            classify_pairing_method(s(3, true, true), s(3, true, true)),
            "just_works"
        );
        assert_eq!(
            classify_pairing_method(s(0, true, false), s(2, true, false)),
            "passkey_entry"
        );
        assert_eq!(
            classify_pairing_method(s(4, true, true), s(4, true, true)),
            "numeric_comparison"
        );
        assert_eq!(
            classify_pairing_method(s(4, true, false), s(4, true, false)),
            "just_works"
        );
        assert_eq!(
            classify_pairing_method(s(9, true, true), s(0, true, true)),
            "unknown"
        );
        let oob = PairingSide {
            oob: true,
            ..s(0, false, false)
        };
        assert_eq!(classify_pairing_method(oob, oob), "oob");
    }
}
