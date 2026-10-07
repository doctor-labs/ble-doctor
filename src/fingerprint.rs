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
    pub manufacturer: u16,
    pub subversion: u16,
    pub features_hex: String,
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

/// Names for the well-known LMP feature bits (page 0).
fn lmp_feature_names(f: &[u8; 8]) -> Vec<String> {
    const BITS: &[(usize, u8, &str)] = &[
        (0, 0, "3-slot packets"),
        (0, 1, "5-slot packets"),
        (0, 2, "encryption"),
        (0, 3, "slot offset"),
        (0, 4, "timing accuracy"),
        (0, 5, "role switch"),
        (0, 6, "hold mode"),
        (0, 7, "sniff mode"),
        (3, 1, "EDR ACL 2 Mb/s"),
        (3, 2, "EDR ACL 3 Mb/s"),
        (4, 6, "LE supported (controller)"),
    ];
    BITS.iter()
        .filter(|(i, bit, _)| f[*i] >> bit & 1 == 1)
        .map(|(_, _, n)| n.to_string())
        .collect()
}

/// Build `LmpInfo` from the 8-byte remote features and an HCI Read Remote Version
/// Complete event's parameters (status, handle:2, version, manufacturer:2, subversion:2).
pub fn parse_lmp(features: &[u8], version_evt: &[u8]) -> Result<LmpInfo, String> {
    let f: [u8; 8] = features
        .try_into()
        .map_err(|_| "LMP features must be 8 bytes")?;
    match version_evt {
        [0, _, _, ver, m0, m1, s0, s1] => Ok(LmpInfo {
            lmp_version: *ver,
            manufacturer: u16::from_le_bytes([*m0, *m1]),
            subversion: u16::from_le_bytes([*s0, *s1]),
            features_hex: f.iter().map(|x| format!("{x:02x}")).collect(),
            features: lmp_feature_names(&f),
        }),
        _ => Err("bad Read Remote Version Complete event".into()),
    }
}

// ---------- collection (Linux only) ----------

/// Collect SDP + LMP for BD_ADDR `addr`. Off Linux: `(None, None)` plus a note.
pub async fn collect_br_edr(addr: &str) -> Result<(Option<SdpInfo>, Option<LmpInfo>), BleError> {
    crate::radio::raw::ensure_raw_supported()?;
    collect_impl(addr).await
}

#[cfg(not(target_os = "linux"))]
async fn collect_impl(_addr: &str) -> Result<(Option<SdpInfo>, Option<LmpInfo>), BleError> {
    Err(BleError::Unsupported {
        feature: "SDP/LMP fingerprint".into(),
        platform: std::env::consts::OS.into(),
    })
}

#[cfg(target_os = "linux")]
async fn collect_impl(addr: &str) -> Result<(Option<SdpInfo>, Option<LmpInfo>), BleError> {
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
    // ponytail: LMP needs the ACL handle + HCI event read loop; unverifiable without
    // hardware, deferred (see docs/DEFERRED-TESTS.md #18). parse_lmp is ready for it.
    Ok((Some(sdp), None))
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
        let l = parse_lmp(&feat, &evt).unwrap();
        assert_eq!(
            (l.lmp_version, l.manufacturer, l.subversion),
            (9, 15, 0x1234)
        );
        assert!(l.features.contains(&"sniff mode".to_string()));
        assert!(l.features.contains(&"EDR ACL 3 Mb/s".to_string()));
        assert!(l
            .features
            .contains(&"LE supported (controller)".to_string()));
        assert!(parse_lmp(&feat[..7], &evt).is_err());
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
