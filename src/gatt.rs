//! GATT model and enumeration (port of v1 collectors.extract_gatt_fields).

use serde::Serialize;

pub const BASIS_SIGNED_WRITES: &str = "authenticated-signed-writes-property";
pub const BASIS_SIG_ASSIGNED: &str = "sig-assigned-service";
pub const BASIS_ASSUMED_PROTECTED: &str = "assumed-protected-unverified";

const SIG_SUFFIX: &str = "-0000-1000-8000-00805f9b34fb";
const CCCD: &str = "00002902-0000-1000-8000-00805f9b34fb";

/// Enumerated descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GattDescriptor {
    pub uuid: String,
}

/// Enumerated characteristic. `descriptors == None` = backend did not expose them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GattChar {
    pub uuid: String,
    pub properties: Vec<String>,
    pub description: Option<String>,
    pub descriptors: Option<Vec<GattDescriptor>>,
}

/// Enumerated service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GattService {
    pub uuid: String,
    pub characteristics: Vec<GattChar>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WritableChar {
    pub uuid: String,
    pub requires_bonding: bool,
    pub bonding_basis: String,
    pub service_uuid: String,
    pub properties: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubscribeChar {
    pub uuid: String,
    pub service_uuid: String,
    pub properties: Vec<String>,
    /// `None` = unknown (backend exposes no descriptors anywhere).
    pub cccd: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GattInfo {
    pub target: String,
    pub target_name: Option<String>,
    pub service_uuids: Vec<String>,
    pub writable_chars: Vec<WritableChar>,
    pub subscribe_chars: Vec<SubscribeChar>,
    pub pairing_method: String,
    pub dfu_probe: Option<String>,
    pub bonding_verified: bool,
    pub gatt_enumerated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondingEstimate {
    pub requires_bonding: bool,
    pub basis: &'static str,
}

fn has_prop(props: &[String], names: &[&str]) -> bool {
    props
        .iter()
        .any(|p| names.contains(&p.to_lowercase().replace('_', "-").as_str()))
}

/// WRITE or WRITE_WITHOUT_RESPONSE advertised.
pub fn is_writable(props: &[String]) -> bool {
    has_prop(props, &["write", "write-without-response"])
}

fn is_subscribable(props: &[String]) -> bool {
    has_prop(props, &["notify", "indicate"])
}

/// Expand a 16/32-bit or 128-bit UUID to lowercase 128-bit; `None` if unparseable.
fn normalize_uuid(u: &str) -> Option<String> {
    let s = u.trim().to_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let hex = |t: &str| t.chars().all(|c| c.is_ascii_hexdigit());
    match s.len() {
        4 if hex(s) => Some(format!("0000{s}{SIG_SUFFIX}")),
        8 if hex(s) => Some(format!("{s}{SIG_SUFFIX}")),
        36 if hex(&s.replace('-', "")) && s.matches('-').count() == 4 => Some(s.to_string()),
        _ => None,
    }
}

/// True if the UUID is in the Bluetooth SIG assigned space (Base UUID suffix).
pub fn is_sig_assigned_uuid(u: &str) -> bool {
    normalize_uuid(u).is_some_and(|n| n.ends_with(SIG_SUFFIX))
}

/// HEURISTIC, not a measurement; errs towards `requires_bonding = true` (see v1 docs).
pub fn estimate_requires_bonding(
    char_uuid: &str,
    props: &[String],
    service_uuid: &str,
) -> BondingEstimate {
    if has_prop(props, &["authenticated-signed-writes"]) {
        BondingEstimate {
            requires_bonding: true,
            basis: BASIS_SIGNED_WRITES,
        }
    } else if is_sig_assigned_uuid(char_uuid) && is_sig_assigned_uuid(service_uuid) {
        BondingEstimate {
            requires_bonding: false,
            basis: BASIS_SIG_ASSIGNED,
        }
    } else {
        BondingEstimate {
            requires_bonding: true,
            basis: BASIS_ASSUMED_PROTECTED,
        }
    }
}

/// Build the `GattInfo` from an enumerated service list.
pub fn extract_gatt_fields(
    services: &[GattService],
    target: &str,
    target_name: Option<&str>,
) -> GattInfo {
    let mut service_uuids = vec![];
    let mut writable_chars = vec![];
    // (char, descriptor uuids)
    let mut subs: Vec<(SubscribeChar, Option<Vec<String>>)> = vec![];
    let mut any_descriptor = false;
    for s in services.iter().filter(|s| !s.uuid.is_empty()) {
        service_uuids.push(s.uuid.clone());
        for c in s.characteristics.iter().filter(|c| !c.uuid.is_empty()) {
            let descs = c
                .descriptors
                .as_ref()
                .map(|d| d.iter().map(|d| d.uuid.clone()).collect::<Vec<_>>());
            any_descriptor |= descs.as_ref().is_some_and(|d| !d.is_empty());
            if is_subscribable(&c.properties) {
                subs.push((
                    SubscribeChar {
                        uuid: c.uuid.clone(),
                        service_uuid: s.uuid.clone(),
                        properties: c.properties.clone(),
                        cccd: None,
                    },
                    descs,
                ));
            }
            if is_writable(&c.properties) {
                let e = estimate_requires_bonding(&c.uuid, &c.properties, &s.uuid);
                writable_chars.push(WritableChar {
                    uuid: c.uuid.clone(),
                    requires_bonding: e.requires_bonding,
                    bonding_basis: e.basis.into(),
                    service_uuid: s.uuid.clone(),
                    properties: c.properties.clone(),
                    description: c.description.clone(),
                });
            }
        }
    }
    // Device-level CCCD resolution: present -> true; descriptors exposed somewhere but not
    // here -> false; no descriptors exposed anywhere -> unknown (never "absent").
    let subscribe_chars = subs
        .into_iter()
        .map(|(mut c, d)| {
            let found =
                d.is_some_and(|d| d.iter().any(|u| normalize_uuid(u).as_deref() == Some(CCCD)));
            c.cccd = if found {
                Some(true)
            } else if any_descriptor {
                Some(false)
            } else {
                None
            };
            c
        })
        .collect();
    GattInfo {
        target: target.into(),
        target_name: target_name.map(Into::into),
        service_uuids,
        writable_chars,
        subscribe_chars,
        pairing_method: "unknown".into(),
        dfu_probe: None,
        bonding_verified: false,
        gatt_enumerated: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FakeCharacteristic as C, FakeGattTree};

    const SIG_SVC: &str = "0000180d-0000-1000-8000-00805f9b34fb";
    const SIG_CH: &str = "00002a39-0000-1000-8000-00805f9b34fb";
    const VENDOR_SVC: &str = "0000aaa0-0000-1000-8000-aabbccddeeff";
    const VENDOR_CH: &str = "0000aaa1-0000-1000-8000-aabbccddeeff";

    fn p(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn writable_and_sig_helpers() {
        assert!(is_writable(&p(&["write"])));
        assert!(is_writable(&p(&["Write_Without_Response"])));
        assert!(!is_writable(&p(&["read", "notify"])));
        assert!(is_sig_assigned_uuid(SIG_CH));
        assert!(is_sig_assigned_uuid("2A39"));
        assert!(!is_sig_assigned_uuid(VENDOR_CH));
        assert!(!is_sig_assigned_uuid("garbage"));
    }

    #[test]
    fn writable_chars_and_bonding_basis() {
        let t = FakeGattTree::new()
            .service(SIG_SVC, vec![C::new(SIG_CH, "", &["write"])])
            .service(
                VENDOR_SVC,
                vec![
                    C::new(VENDOR_CH, "", &["write-without-response"]),
                    C::new("00002a00-0000-1000-8000-00805f9b34fb", "", &["read"]),
                ],
            )
            .service(
                SIG_SVC.replace("180d", "180f").as_str(),
                vec![C::new(
                    SIG_CH,
                    "",
                    &["authenticated-signed-writes", "write"],
                )],
            );
        let i = extract_gatt_fields(&t.to_services(), "AA", Some("n"));
        assert_eq!(i.service_uuids.len(), 3);
        assert_eq!(i.writable_chars.len(), 3);
        let w = &i.writable_chars;
        assert!(!w[0].requires_bonding && w[0].bonding_basis == BASIS_SIG_ASSIGNED);
        assert!(w[1].requires_bonding && w[1].bonding_basis == BASIS_ASSUMED_PROTECTED);
        assert!(w[2].requires_bonding && w[2].bonding_basis == BASIS_SIGNED_WRITES);
        assert_eq!(w[1].service_uuid, VENDOR_SVC);
        assert_eq!(
            (i.pairing_method.as_str(), i.dfu_probe.clone()),
            ("unknown", None)
        );
        assert!(i.gatt_enumerated && !i.bonding_verified);
    }

    #[test]
    fn cccd_three_states() {
        let cccd = |t: FakeGattTree| {
            extract_gatt_fields(&t.to_services(), "", None)
                .subscribe_chars
                .iter()
                .map(|c| c.cccd)
                .collect::<Vec<_>>()
        };
        let with = || C::notify_with_cccd("a", "");
        let without = || C::notify_without_cccd("b", "");
        let unknown = || C::notify_unknown_cccd("c", "");
        // descriptors exposed on the device: with=true, without=false
        assert_eq!(
            cccd(FakeGattTree::new().service("s", vec![with(), without()])),
            vec![Some(true), Some(false)]
        );
        // nothing exposes descriptors: unknown, never absent
        assert_eq!(
            cccd(FakeGattTree::new().service("s", vec![without(), unknown()])),
            vec![None, None]
        );
    }
}
