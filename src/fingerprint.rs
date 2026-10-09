//! Device fingerprint: LE+GATT profile (cross-platform) plus SDP/LMP (Linux raw HCI only).

use crate::error::BleError;
use crate::gatt::GattInfo;
use serde::Serialize;
use std::collections::BTreeSet;

pub const NOTE_NEEDS_LINUX: &str = "SDP/LMP need a Linux host";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SdpRecord {
    /// ServiceClassIDList (attr 0x0001) 16-bit UUIDs as hex, e.g. "110b".
    pub service_classes: Vec<String>,
    /// ServiceName (attr 0x0100).
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SdpInfo {
    pub records: Vec<SdpRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LmpInfo {
    pub lmp_version: u8,
    /// Bluetooth Core version for `lmp_version`, e.g. "Bluetooth 5.2".
    pub version: String,
    pub manufacturer: u16,
    pub manufacturer_name: Option<String>,
    pub subversion: u16,
    /// Feature page 0 as 16 hex chars (byte 0 first).
    pub features_hex: String,
    /// Feature pages 0..=2 as hex (as many as the peer reported).
    pub pages: Vec<String>,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fingerprint {
    pub address: String,
    pub name: Option<String>,
    pub service_uuids: Vec<String>,
    /// Distinct writable or subscribable characteristics (GattInfo carries no others).
    pub char_count: usize,
    pub writable_count: usize,
    pub notify_count: usize,
    pub notable_chars: Vec<String>,
    pub pairing_method: String,
    pub gatt_enumerated: bool,
    pub sdp: Option<SdpInfo>,
    pub lmp: Option<LmpInfo>,
    pub notes: Vec<String>,
}

/// Cross-platform LE+GATT summary; SDP/LMP left `None`.
pub fn le_gatt_fingerprint(gatt: &GattInfo) -> Fingerprint {
    let mut all = BTreeSet::new();
    let mut notable = vec![];
    for w in &gatt.writable_chars {
        all.insert(w.uuid.clone());
        notable.push(format!("{} writable [{}]", w.uuid, w.properties.join(",")));
    }
    for s in &gatt.subscribe_chars {
        all.insert(s.uuid.clone());
    }
    Fingerprint {
        address: gatt.target.clone(),
        name: gatt.target_name.clone(),
        service_uuids: gatt.service_uuids.clone(),
        char_count: all.len(),
        writable_count: gatt.writable_chars.len(),
        notify_count: gatt.subscribe_chars.len(),
        notable_chars: notable,
        pairing_method: gatt.pairing_method.clone(),
        gatt_enumerated: gatt.gatt_enumerated,
        sdp: None,
        lmp: None,
        notes: vec![],
    }
}

// ---------- pure parsers ----------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Elem {
    Uint(u64),
    Uuid(String),
    Text(String),
    Seq(Vec<Elem>),
    Other,
}

/// Parse one SDP data element; returns it and the bytes consumed.
fn parse_elem(b: &[u8]) -> Option<(Elem, usize)> {
    let h = *b.first()?;
    let (ty, sz) = (h >> 3, h & 7);
    let (hdr, len): (usize, usize) = match sz {
        0..=4 => (1, [1usize, 2, 4, 8, 16][sz as usize]),
        5 => (2, *b.get(1)? as usize),
        6 => (3, u16::from_be_bytes([*b.get(1)?, *b.get(2)?]) as usize),
        _ => (
            5,
            u32::from_be_bytes(b.get(1..5)?.try_into().ok()?) as usize,
        ),
    };
    // nil (type 0) has size index 0 but zero length
    let len = if ty == 0 { 0 } else { len };
    let body = b.get(hdr..hdr.checked_add(len)?)?;
    let e = match ty {
        1 | 2 if len <= 8 => Elem::Uint(body.iter().fold(0u64, |a, x| (a << 8) | *x as u64)),
        3 => Elem::Uuid(match len {
            2 => format!("{:04x}", u16::from_be_bytes([body[0], body[1]])),
            4 => format!("{:08x}", u32::from_be_bytes(body.try_into().ok()?)),
            _ => body.iter().map(|x| format!("{x:02x}")).collect(),
        }),
        4 => Elem::Text(String::from_utf8_lossy(body).into_owned()),
        6 | 7 => {
            let (mut v, mut i) = (vec![], 0);
            while i < body.len() {
                let (e, n) = parse_elem(&body[i..])?;
                v.push(e);
                i += n;
            }
            Elem::Seq(v)
        }
        _ => Elem::Other,
    };
    Some((e, hdr + len))
}

/// Parse an SDP ServiceSearchAttributeResponse PDU (0x07) into records.
/// Continuation state is not followed (ponytail: single-PDU responses only).
pub fn parse_sdp_response(pdu: &[u8]) -> Result<SdpInfo, String> {
    if pdu.len() < 7 || pdu[0] != 0x07 {
        return Err("not an SDP ServiceSearchAttribute response".into());
    }
    let n = u16::from_be_bytes([pdu[5], pdu[6]]) as usize;
    let data = pdu.get(7..7 + n).ok_or("truncated SDP response")?;
    let (Elem::Seq(lists), _) = parse_elem(data).ok_or("bad SDP data element")? else {
        return Err("SDP attribute lists not a sequence".into());
    };
    let mut records = vec![];
    for rec in lists {
        let Elem::Seq(attrs) = rec else { continue };
        let (mut classes, mut name) = (vec![], None);
        for kv in attrs.chunks(2) {
            match kv {
                [Elem::Uint(0x0001), Elem::Seq(u)] => {
                    classes.extend(u.iter().filter_map(|e| match e {
                        Elem::Uuid(s) => Some(s.clone()),
                        _ => None,
                    }))
                }
                [Elem::Uint(0x0100), Elem::Text(t)] => name = Some(t.clone()),
                _ => {}
            }
        }
        records.push(SdpRecord {
            service_classes: classes,
            name,
        });
    }
    Ok(SdpInfo { records })
}

/// Core Spec Vol 2 Part C 3.3 "Link Manager Supported Features" bit names:
/// `(page, byte, bit, name)`. Page 0 = Table 3.2, page 1 = host features, page 2 = Table 3.3 (ext.).
/// Reserved / RFU bits are omitted.
const FEATURE_BITS: &[(usize, usize, u8, &str)] = &[
    (0, 0, 0, "3-slot packets"),
    (0, 0, 1, "5-slot packets"),
    (0, 0, 2, "encryption"),
    (0, 0, 3, "slot offset"),
    (0, 0, 4, "timing accuracy"),
    (0, 0, 5, "role switch"),
    (0, 0, 6, "hold mode"),
    (0, 0, 7, "sniff mode"),
    (0, 1, 1, "power control requests"),
    (0, 1, 2, "channel quality driven data rate"),
    (0, 1, 3, "SCO link"),
    (0, 1, 4, "HV2 packets"),
    (0, 1, 5, "HV3 packets"),
    (0, 1, 6, "u-law log synchronous data"),
    (0, 1, 7, "A-law log synchronous data"),
    (0, 2, 0, "CVSD synchronous data"),
    (0, 2, 1, "paging parameter negotiation"),
    (0, 2, 2, "power control"),
    (0, 2, 3, "transparent synchronous data"),
    (0, 2, 7, "broadcast encryption"),
    (0, 3, 1, "EDR ACL 2 Mb/s"),
    (0, 3, 2, "EDR ACL 3 Mb/s"),
    (0, 3, 3, "enhanced inquiry scan"),
    (0, 3, 4, "interlaced inquiry scan"),
    (0, 3, 5, "interlaced page scan"),
    (0, 3, 6, "RSSI with inquiry results"),
    (0, 3, 7, "extended SCO link (EV3)"),
    (0, 4, 0, "EV4 packets"),
    (0, 4, 1, "EV5 packets"),
    (0, 4, 3, "AFH capable peripheral"),
    (0, 4, 4, "AFH classification peripheral"),
    (0, 4, 5, "BR/EDR not supported"),
    (0, 4, 6, "LE supported (controller)"),
    (0, 4, 7, "3-slot EDR ACL packets"),
    (0, 5, 0, "5-slot EDR ACL packets"),
    (0, 5, 1, "sniff subrating"),
    (0, 5, 2, "pause encryption"),
    (0, 5, 3, "AFH capable central"),
    (0, 5, 4, "AFH classification central"),
    (0, 5, 5, "EDR eSCO 2 Mb/s"),
    (0, 5, 6, "EDR eSCO 3 Mb/s"),
    (0, 5, 7, "3-slot EDR eSCO packets"),
    (0, 6, 0, "extended inquiry response"),
    (0, 6, 1, "simultaneous LE and BR/EDR (controller)"),
    (0, 6, 3, "Secure Simple Pairing (controller)"),
    (0, 6, 4, "encapsulated PDU"),
    (0, 6, 5, "erroneous data reporting"),
    (0, 6, 6, "non-flushable packet boundary flag"),
    (0, 7, 0, "link supervision timeout changed event"),
    (0, 7, 1, "inquiry TX power level"),
    (0, 7, 2, "enhanced power control"),
    (0, 7, 7, "extended features"),
    (1, 0, 0, "Secure Simple Pairing (host)"),
    (1, 0, 1, "LE supported (host)"),
    (1, 0, 2, "simultaneous LE and BR/EDR (host)"),
    (1, 0, 3, "Secure Connections (host)"),
    (2, 0, 0, "connectionless peripheral broadcast transmitter"),
    (2, 0, 1, "connectionless peripheral broadcast receiver"),
    (2, 0, 2, "synchronization train"),
    (2, 0, 3, "synchronization scan"),
    (2, 0, 4, "inquiry response notification event"),
    (2, 0, 5, "generalized interlaced scan"),
    (2, 0, 6, "coarse clock adjustment"),
    (2, 1, 0, "Secure Connections (controller)"),
    (2, 1, 1, "ping"),
    (2, 1, 2, "slot availability mask"),
    (2, 1, 3, "train nudging"),
];

/// Named features set in `pages[0..=2]` (8 bytes each).
pub fn lmp_feature_names(pages: &[[u8; 8]]) -> Vec<String> {
    FEATURE_BITS
        .iter()
        .filter(|(p, byte, bit, _)| pages.get(*p).is_some_and(|f| f[*byte] >> bit & 1 == 1))
        .map(|(_, _, _, n)| n.to_string())
        .collect()
}

/// LMP VersNr -> Bluetooth Core version (Assigned Numbers, "LMP Version").
pub fn core_version(lmp: u8) -> String {
    const V: &[&str] = &[
        "1.0b",
        "1.1",
        "1.2",
        "2.0 + EDR",
        "2.1 + EDR",
        "3.0 + HS",
        "4.0",
        "4.1",
        "4.2",
        "5.0",
        "5.1",
        "5.2",
        "5.3",
        "5.4",
        "6.0",
    ];
    V.get(lmp as usize)
        .map(|v| format!("Bluetooth {v}"))
        .unwrap_or_else(|| format!("unknown (LMP {lmp})"))
}

/// Company identifier -> name (Assigned Numbers, "Company Identifiers"). Compact subset of
/// common controller vendors; unknown ids yield `None` (the numeric id is always reported).
pub fn company_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0000 => "Ericsson Technology Licensing",
        0x0001 => "Nokia Mobile Phones",
        0x0002 => "Intel Corp.",
        0x0003 => "IBM Corp.",
        0x0004 => "Toshiba Corp.",
        0x0006 => "Microsoft",
        0x0008 => "Motorola",
        0x0009 => "Infineon Technologies AG",
        0x000A => "Qualcomm Technologies International, Ltd. (CSR)",
        0x000D => "Texas Instruments Inc.",
        0x000F => "Broadcom Corporation",
        0x001D => "Qualcomm",
        0x0030 => "STMicroelectronics",
        0x0046 => "MediaTek, Inc.",
        0x004C => "Apple, Inc.",
        0x0059 => "Nordic Semiconductor ASA",
        0x005D => "Realtek Semiconductor Corporation",
        0x0075 => "Samsung Electronics Co. Ltd.",
        0x0087 => "Garmin International, Inc.",
        0x00E0 => "Google",
        0x0131 => "Cypress Semiconductor",
        _ => return None,
    })
}

/// Build `LmpInfo` from the remote feature pages (0..=2, 8 bytes each) and an HCI Read Remote
/// Version Complete event's parameters (status, handle:2, version, manufacturer:2, subversion:2).
pub fn parse_lmp(pages: &[[u8; 8]], version_evt: &[u8]) -> Result<LmpInfo, String> {
    let hex = |f: &[u8; 8]| f.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let Some(p0) = pages.first() else {
        return Err("no LMP feature page".into());
    };
    match version_evt {
        [0, _, _, ver, m0, m1, s0, s1] => {
            let manufacturer = u16::from_le_bytes([*m0, *m1]);
            Ok(LmpInfo {
                lmp_version: *ver,
                version: core_version(*ver),
                manufacturer,
                manufacturer_name: company_name(manufacturer).map(String::from),
                subversion: u16::from_le_bytes([*s0, *s1]),
                features_hex: hex(p0),
                pages: pages.iter().map(hex).collect(),
                features: lmp_feature_names(pages),
            })
        }
        _ => Err("bad Read Remote Version Complete event".into()),
    }
}

// ---------- collection (Linux only) ----------

/// SDP, LMP, and notes (e.g. LMP failed while SDP worked).
pub type BrEdrResult = Result<(Option<SdpInfo>, Option<LmpInfo>, Vec<String>), BleError>;

/// Collect SDP + LMP for BD_ADDR `addr`. Off Linux: `an Unsupported error.
pub async fn collect_br_edr(addr: &str) -> BrEdrResult {
    crate::radio::raw::ensure_raw_supported()?;
    collect_impl(addr).await
}

#[cfg(not(target_os = "linux"))]
async fn collect_impl(_addr: &str) -> BrEdrResult {
    Err(BleError::Unsupported {
        feature: "SDP/LMP fingerprint".into(),
        platform: std::env::consts::OS.into(),
    })
}

#[cfg(target_os = "linux")]
async fn collect_impl(addr: &str) -> BrEdrResult {
    use bluer::l2cap::{SocketAddr, Stream};
    use bluer::AddressType;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let os = |e: &dyn std::fmt::Display| BleError::OsError {
        context: e.to_string(),
    };
    let peer: bluer::Address = addr.parse().map_err(|e| os(&e))?;
    let mut s = Stream::connect(SocketAddr::new(peer, AddressType::BrEdr, 0x0001))
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => BleError::PermissionDenied,
            std::io::ErrorKind::TimedOut => BleError::ConnectTimeout,
            _ => os(&e),
        })?;
    // ServiceSearchAttributeRequest: PublicBrowseGroup, max 0xFFFF bytes, all attributes.
    let req = [
        0x06, 0, 1, 0, 0x11, 0x35, 0x03, 0x19, 0x10, 0x02, 0xFF, 0xFF, 0x35, 0x05, 0x0A, 0, 0,
        0xFF, 0xFF, 0x00,
    ];
    s.write_all(&req).await.map_err(|e| os(&e))?;
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.map_err(|e| os(&e))?;
    let sdp = parse_sdp_response(&buf[..n]).map_err(|c| BleError::OsError { context: c })?;
    // The L2CAP link above keeps the ACL connection up; query LMP over a raw HCI socket on it.
    // ponytail: hci0 only (matches raw::send_hci_command); take --adapter when multi-adapter matters.
    let peer_bytes = crate::radio::raw::parse_bd_addr(addr)?;
    let lmp = tokio::task::spawn_blocking(move || {
        let mut hci = crate::hci_lmp::linux::RawHci::open(0, 5)?;
        let handle = hci.acl_handle(peer_bytes)?;
        crate::hci_lmp::read_remote_lmp(&mut hci, handle)
            .map_err(|context| BleError::OsError { context })
    })
    .await
    .map_err(|e| os(&e))?;
    drop(s);
    Ok(match lmp {
        Ok(l) => (Some(sdp), Some(l), vec![]),
        Err(e) => (Some(sdp), None, vec![format!("LMP failed: {e}")]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatt::extract_gatt_fields;
    use crate::testkit::{FakeCharacteristic as C, FakeGattTree};

    #[test]
    fn le_gatt_counts() {
        let t = FakeGattTree::new()
            .service(
                "0000180d-0000-1000-8000-00805f9b34fb",
                vec![
                    C::new("00002a37-0000-1000-8000-00805f9b34fb", "", &["write"]),
                    C::notify_with_cccd("00002a38-0000-1000-8000-00805f9b34fb", ""),
                ],
            )
            .service(
                "6e400001-b5a3-f393-e0a9-e50e24dcca9e",
                vec![C::new(
                    "6e400002-b5a3-f393-e0a9-e50e24dcca9e",
                    "",
                    &["write-without-response", "write"],
                )],
            );
        let g = extract_gatt_fields(&t.to_services(), "AA:BB", Some("dev"));
        let f = le_gatt_fingerprint(&g);
        assert_eq!(f.service_uuids.len(), 2);
        assert_eq!((f.writable_count, f.notify_count, f.char_count), (2, 1, 3));
        assert_eq!(f.name.as_deref(), Some("dev"));
        assert!(f.sdp.is_none() && f.lmp.is_none());
    }

    #[test]
    fn sdp_sample() {
        // record: {0x0001: [0x110b], 0x0100: "Audio"}
        let rec = [
            0x35, 0x12, 0x09, 0x00, 0x01, 0x35, 0x03, 0x19, 0x11, 0x0B, 0x09, 0x01, 0x00, 0x25,
            0x05, b'A', b'u', b'd', b'i', b'o',
        ];
        let mut data = vec![0x35, rec.len() as u8];
        data.extend(rec);
        let mut pdu = vec![0x07, 0, 1, 0, 0, 0, data.len() as u8];
        pdu[5] = 0;
        pdu.extend(&data);
        pdu.push(0);
        let i = parse_sdp_response(&pdu).unwrap();
        assert_eq!(i.records.len(), 1);
        assert_eq!(i.records[0].service_classes, ["110b"]);
        assert_eq!(i.records[0].name.as_deref(), Some("Audio"));
        assert!(parse_sdp_response(&[0x01]).is_err());
    }

    #[test]
    fn lmp_sample() {
        let feat = [0xFF, 0, 0, 0x06, 0x40, 0, 0, 0];
        let evt = [0, 0x40, 0, 0x09, 0x0F, 0x00, 0x34, 0x12];
        let l = parse_lmp(&[feat], &evt).unwrap();
        assert_eq!(
            (l.lmp_version, l.manufacturer, l.subversion),
            (9, 15, 0x1234)
        );
        assert_eq!(l.version, "Bluetooth 5.0");
        assert_eq!(l.manufacturer_name.as_deref(), Some("Broadcom Corporation"));
        assert!(l.features.contains(&"sniff mode".to_string()));
        assert!(l.features.contains(&"EDR ACL 3 Mb/s".to_string()));
        assert!(l
            .features
            .contains(&"LE supported (controller)".to_string()));
        assert!(parse_lmp(&[], &evt).is_err());
        assert!(parse_lmp(&[feat], &evt[1..]).is_err());
    }

    #[test]
    fn decoders() {
        assert_eq!(core_version(0), "Bluetooth 1.0b");
        assert_eq!(core_version(14), "Bluetooth 6.0");
        assert_eq!(core_version(99), "unknown (LMP 99)");
        assert_eq!(company_name(0x004C), Some("Apple, Inc."));
        assert_eq!(company_name(0xFFFE), None);
        // page 2 byte 1 bit 0 = Secure Connections (controller); page 1 absent -> no host names
        let p0 = [0u8; 8];
        let p2 = [0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            lmp_feature_names(&[p0, [0; 8], p2]),
            ["Secure Connections (controller)"]
        );
        // names are unique so the table has no copy-paste duplicates
        let mut n: Vec<_> = FEATURE_BITS.iter().map(|x| x.3).collect();
        n.sort();
        n.dedup();
        assert_eq!(n.len(), FEATURE_BITS.len());
    }

    #[tokio::test]
    async fn collection_unsupported_off_linux() {
        let r = collect_br_edr("AA:BB:CC:DD:EE:FF").await;
        if cfg!(target_os = "linux") {
            assert!(r.is_err() || r.is_ok());
        } else {
            assert!(matches!(r, Err(BleError::Unsupported { .. })));
        }
    }
}
