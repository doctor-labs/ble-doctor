//! Canonical check types and pure checks (v1 `checks.py`).
//! Reused by every probe/check issue: build a `CheckResult`, feed it to `report`/`sarif`.

use crate::gatt::{GattInfo, WritableChar};
use crate::probe::dfu::{
    DFU_VERDICT_ENFORCED, DFU_VERDICT_NOT_ENFORCED, DFU_VERDICT_SIGNATURE_INVALID,
};
use serde::Serialize;
use std::collections::BTreeSet;

pub use crate::capture::check_mac_rotation;

/// DFU/OTA entry points (services and the control-point characteristics themselves, since a
/// collector may report either): a *superset* mixing services with characteristics that are
/// entry points in their own right (v1 `DFU_SERVICE_UUIDS`). Presence alone is not a finding —
/// `check_dfu_entry_point` and `check_dfu_surface_absent` are the checks that decide that.
pub const DFU_SERVICE_UUIDS: &[&str] = &[
    "0000fe59-0000-1000-8000-00805f9b34fb", // Nordic Secure DFU Service
    "00001530-1212-efde-1523-785feabcd123", // Nordic Legacy DFU Service
    "8e400001-f315-4f60-9fb8-838830daea50", // Nordic Experimental Buttonless DFU Service
    "8ec90001-f315-4f60-9fb8-838830daea50", // Nordic Secure DFU Control Point
    "8ec90003-f315-4f60-9fb8-838830daea50", // Nordic Buttonless DFU Without Bond Sharing
    "8ec90004-f315-4f60-9fb8-838830daea50", // Nordic Buttonless DFU With Bond Sharing
    "f000ffc0-0451-4000-b000-000000000000", // TI Over-the-Air Download (OAD) Service
    "f000ffc5-0451-4000-b000-000000000000", // TI OAD Control
    "e95d93b0-251d-470a-a062-fa1922dfa9a8", // micro:bit DFU Control Service
    "00001625-1212-efde-1623-785feabcd123", // LEGO Wireless Protocol v3 Bootloader Service
];

const SIG_SUFFIX: &str = "-0000-1000-8000-00805f9b34fb";

/// Canonicalise a reported UUID to lowercase dashed 128-bit form; `None` if unparseable
/// (v1 `_normalize_uuid`).
fn normalize_dfu_uuid(value: &str) -> Option<String> {
    let s = value.trim().trim_matches(|c| c == '{' || c == '}').trim();
    let s = s.to_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let s: String = s.chars().filter(|c| *c != '-' && *c != ' ').collect();
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let s = match s.len() {
        4 => format!("0000{s}{SIG_SUFFIX}"),
        8 => format!("{s}{SIG_SUFFIX}"),
        32 => format!(
            "{}-{}-{}-{}-{}",
            &s[0..8],
            &s[8..12],
            &s[12..16],
            &s[16..20],
            &s[20..32]
        ),
        _ => return None,
    };
    Some(s)
}

/// True if `value` names a DFU/OTA entry point in any accepted spelling.
pub fn is_dfu_uuid(value: &str) -> bool {
    normalize_dfu_uuid(value).is_some_and(|n| DFU_SERVICE_UUIDS.contains(&n.as_str()))
}

/// Every DFU/OTA entry point this GATT dump reports, normalised and sorted (v1
/// `find_dfu_entry_points`): searches `service_uuids` and both UUID fields of `writable_chars`,
/// since a flat characteristic-only dump never reports which service it lives in.
pub fn find_dfu_entry_points(info: &GattInfo) -> Vec<String> {
    let mut found = BTreeSet::new();
    for s in &info.service_uuids {
        if let Some(n) = normalize_dfu_uuid(s) {
            if DFU_SERVICE_UUIDS.contains(&n.as_str()) {
                found.insert(n);
            }
        }
    }
    for c in &info.writable_chars {
        for u in [&c.uuid, &c.service_uuid] {
            if let Some(n) = normalize_dfu_uuid(u) {
                if DFU_SERVICE_UUIDS.contains(&n.as_str()) {
                    found.insert(n);
                }
            }
        }
    }
    found.into_iter().collect()
}

/// The `writable_chars` entries that sit on the DFU write surface: its own UUID is a known DFU
/// control point, or the service it lives in is a known DFU service.
fn dfu_write_surface_chars(info: &GattInfo) -> Vec<&WritableChar> {
    info.writable_chars
        .iter()
        .filter(|c| is_dfu_uuid(&c.uuid) || is_dfu_uuid(&c.service_uuid))
        .collect()
}

/// ACCESS CONTROL of the DFU entry point, and nothing else (v1 `check_dfu_entry_point`, issue
/// #35). HIGH only when a DFU control point is reachable without bonding; a published DFU UUID
/// on its own is never a finding.
pub fn check_dfu_entry_point(info: &GattInfo) -> CheckResult {
    let entry_points = find_dfu_entry_points(info);
    if entry_points.is_empty() {
        return CheckResult::new(
            "dfu_entry_point",
            Severity::Info,
            true,
            "No DFU/OTA entry point detected.",
        );
    }
    let surface = dfu_write_surface_chars(info);
    let open: Vec<&WritableChar> = surface
        .iter()
        .copied()
        .filter(|c| !c.requires_bonding)
        .collect();
    if !open.is_empty() {
        let uuids: BTreeSet<&str> = open.iter().map(|c| c.uuid.as_str()).collect();
        let bases: BTreeSet<&str> = open.iter().map(|c| c.bonding_basis.as_str()).collect();
        let provenance = if info.bonding_verified {
            " measured by an unauthenticated-write probe.".to_string()
        } else {
            format!(
                " requires_bonding is the collector's heuristic ({}), not a measurement — run \
                 `ble-doctor probe-writes` to confirm.",
                bases.into_iter().collect::<Vec<_>>().join(", ")
            )
        };
        return CheckResult::new(
            "dfu_entry_point",
            Severity::High,
            false,
            format!(
                "DFU write surface reachable without bonding: {} — a client that has never \
                 paired can write to the firmware update surface ({} DFU entry point(s) \
                 present).{provenance}",
                uuids.into_iter().collect::<Vec<_>>().join(", "),
                entry_points.len()
            ),
        );
    }
    if surface.is_empty() {
        return CheckResult::new(
            "dfu_entry_point",
            Severity::Info,
            true,
            format!(
                "DFU entry point present ({}) but no writable DFU control point was reported, \
                 so its access control was not assessed. Presence alone is not a finding.",
                entry_points.join(", ")
            ),
        );
    }
    let provenance = if info.bonding_verified {
        "measured by an unauthenticated-write probe"
    } else {
        "assumed from the GATT table, not measured — run `ble-doctor probe-writes` to establish it"
    };
    CheckResult::new(
        "dfu_entry_point",
        Severity::Info,
        true,
        format!(
            "DFU entry point present ({}) and its control point requires bonding or an \
             encrypted link ({provenance}).",
            entry_points.join(", ")
        ),
    )
}

/// SIGNING. Not derivable from enumeration; the verdict comes from an in-band probe recorded in
/// `GattInfo::dfu_probe` (v1 `check_dfu_signing_enforced`, issue #35). Absent/unrecognised probe
/// is INCONCLUSIVE at INFO — zero score weight, a queued probe, not a pass or a fail.
pub fn check_dfu_signing_enforced(info: &GattInfo) -> CheckResult {
    match info.dfu_probe.as_deref() {
        Some(v) if v == DFU_VERDICT_ENFORCED => CheckResult::new(
            "dfu_signing_enforced",
            Severity::Info,
            true,
            "A signing probe found the bootloader rejecting an unsigned image.",
        ),
        Some(v) if v == DFU_VERDICT_NOT_ENFORCED => CheckResult::new(
            "dfu_signing_enforced",
            Severity::High,
            false,
            "The bootloader accepted an unsigned firmware image — firmware signing is not \
             enforced, so anyone who can reach the DFU control point can flash arbitrary code.",
        ),
        Some(v) if v == DFU_VERDICT_SIGNATURE_INVALID => CheckResult::new(
            "dfu_signing_enforced",
            Severity::Medium,
            false,
            "The bootloader rejected a firmware image whose signature did not verify.",
        ),
        other => {
            let reason = match other {
                None => "no signing probe was run",
                Some(_) => "no recognised signing probe verdict was recorded",
            };
            CheckResult::new(
                "dfu_signing_enforced",
                Severity::Info,
                true,
                format!(
                    "Signing status not established ({reason}); INCONCLUSIVE, carries zero \
                     score weight. Next probe: write a Secure DFU Command carrying an unsigned \
                     init packet to the DFU control point and classify the response."
                ),
            )
        }
    }
}

/// Gives the ABSENCE of a DFU surface a positive identity, with the evidence attached (v1
/// `check_dfu_surface_absent`, issue #36). Only claims absence after a complete GATT
/// enumeration; "we never looked" must never read as "there is nothing there".
pub fn check_dfu_surface_absent(info: &GattInfo) -> CheckResult {
    if !info.gatt_enumerated {
        return CheckResult::new(
            "dfu_surface_absent",
            Severity::Info,
            false,
            "GATT enumeration did not complete — DFU status unknown (INCONCLUSIVE, not \
             evidence of absence).",
        );
    }
    let found = find_dfu_entry_points(info);
    if !found.is_empty() {
        return CheckResult::new(
            "dfu_surface_absent",
            Severity::Info,
            false,
            format!(
                "DFU surface present ({}) — absence does not apply. Whether the update is \
                 signed is reported separately.",
                found.join(", ")
            ),
        );
    }
    CheckResult::new(
        "dfu_surface_absent",
        Severity::Info,
        true,
        format!(
            "GATT fully enumerated ({} services, {} writable characteristics); no DFU/OTA \
             entry point present. The empty result is evidence, not missing data — this target \
             exposes no BLE firmware-update surface.",
            info.service_uuids.len(),
            info.writable_chars.len()
        ),
    )
}

/// Finding severity. Ordered: `Info < Low < Medium < High < Critical`. Serializes lowercase (v1 values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Lowercase name (v1 `Severity.value`).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// One check verdict (v1 `CheckResult`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub id: String,
    pub severity: Severity,
    pub passed: bool,
    pub detail: String,
}

impl CheckResult {
    pub fn new(id: &str, severity: Severity, passed: bool, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            severity,
            passed,
            detail: detail.into(),
        }
    }
}

/// HIGH if any writable characteristic does not require bonding, else INFO pass.
pub fn check_unauthenticated_writes(info: &GattInfo) -> CheckResult {
    let open: Vec<&str> = info
        .writable_chars
        .iter()
        .filter(|c| !c.requires_bonding)
        .map(|c| c.uuid.as_str())
        .collect();
    if open.is_empty() {
        CheckResult::new(
            "unauthenticated_writes",
            Severity::Info,
            true,
            "No characteristics writable without bonding.",
        )
    } else {
        CheckResult::new(
            "unauthenticated_writes",
            Severity::High,
            false,
            format!("Writable without bonding: {}", open.join(", ")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatt::extract_gatt_fields;
    use crate::testkit::{FakeCharacteristic as C, FakeGattTree};

    const SIG_SVC: &str = "0000180d-0000-1000-8000-00805f9b34fb";
    const SIG_CH: &str = "00002a39-0000-1000-8000-00805f9b34fb";
    const VENDOR_CH: &str = "0000aaa1-0000-1000-8000-aabbccddeeff";

    fn info(chars: Vec<C>) -> GattInfo {
        let t = FakeGattTree::new().service(SIG_SVC, chars);
        extract_gatt_fields(&t.to_services(), "AA", None)
    }

    #[test]
    fn unbonded_write_is_high_fail() {
        // SIG-assigned writable => assumed unprotected (requires_bonding=false).
        let r = check_unauthenticated_writes(&info(vec![C::new(SIG_CH, "", &["write"])]));
        assert_eq!((r.severity, r.passed), (Severity::High, false));
        assert!(r.detail.contains(SIG_CH));
    }

    #[test]
    fn bonded_or_no_writes_pass() {
        let r = check_unauthenticated_writes(&info(vec![C::new(VENDOR_CH, "", &["write"])]));
        assert_eq!((r.severity, r.passed), (Severity::Info, true));
        let r = check_unauthenticated_writes(&info(vec![]));
        assert!(r.passed);
    }

    #[test]
    fn severity_order_and_names() {
        assert!(Severity::Info < Severity::Low && Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"high\"");
    }

    const DFU_SVC: &str = "0000fe59-0000-1000-8000-00805f9b34fb";
    const DFU_CP: &str = "8ec90001-f315-4f60-9fb8-838830daea50";

    fn blank_gatt() -> GattInfo {
        GattInfo {
            target: "AA".into(),
            target_name: None,
            service_uuids: vec![],
            writable_chars: vec![],
            subscribe_chars: vec![],
            pairing_method: "unknown".into(),
            dfu_probe: None,
            bonding_verified: false,
            gatt_enumerated: true,
        }
    }

    fn wchar(uuid: &str, service_uuid: &str, requires_bonding: bool) -> WritableChar {
        WritableChar {
            uuid: uuid.into(),
            requires_bonding,
            bonding_basis: "test".into(),
            service_uuid: service_uuid.into(),
            properties: vec!["write".into()],
            description: None,
        }
    }

    #[test]
    fn dfu_entry_point_absent_passes() {
        let r = check_dfu_entry_point(&blank_gatt());
        assert_eq!((r.severity, r.passed), (Severity::Info, true));
    }

    #[test]
    fn dfu_entry_point_writable_unbonded_is_high() {
        let mut g = blank_gatt();
        g.service_uuids = vec![DFU_SVC.into()];
        g.writable_chars = vec![wchar(DFU_CP, DFU_SVC, false)];
        let r = check_dfu_entry_point(&g);
        assert_eq!((r.severity, r.passed), (Severity::High, false));
        assert!(r.detail.contains(DFU_CP));
    }

    #[test]
    fn dfu_entry_point_writable_bonded_is_info() {
        let mut g = blank_gatt();
        g.service_uuids = vec![DFU_SVC.into()];
        g.writable_chars = vec![wchar(DFU_CP, DFU_SVC, true)];
        let r = check_dfu_entry_point(&g);
        assert_eq!((r.severity, r.passed), (Severity::Info, true));
    }

    #[test]
    fn dfu_signing_enforced_every_state() {
        let case = |v: Option<&str>| {
            let mut g = blank_gatt();
            g.dfu_probe = v.map(String::from);
            check_dfu_signing_enforced(&g)
        };
        let r = case(None);
        assert_eq!((r.severity, r.passed), (Severity::Info, true));
        assert!(r.detail.contains("INCONCLUSIVE"));
        let r = case(Some("enforced"));
        assert_eq!((r.severity, r.passed), (Severity::Info, true));
        let r = case(Some("not_enforced"));
        assert_eq!((r.severity, r.passed), (Severity::High, false));
        let r = case(Some("signature_present_but_invalid"));
        assert_eq!((r.severity, r.passed), (Severity::Medium, false));
        let r = case(Some("junk"));
        assert_eq!((r.severity, r.passed), (Severity::Info, true));
    }

    #[test]
    fn dfu_surface_absent_only_claims_absence_when_enumerated() {
        let mut g = blank_gatt();
        g.gatt_enumerated = false;
        let r = check_dfu_surface_absent(&g);
        assert_eq!((r.severity, r.passed), (Severity::Info, false));
        assert!(r.detail.contains("did not complete"));

        let g2 = blank_gatt();
        let r = check_dfu_surface_absent(&g2);
        assert_eq!((r.severity, r.passed), (Severity::Info, true));

        let mut g3 = blank_gatt();
        g3.service_uuids = vec![DFU_SVC.into()];
        let r = check_dfu_surface_absent(&g3);
        assert_eq!((r.severity, r.passed), (Severity::Info, false));
        assert!(r.detail.contains("DFU surface present"));
    }

    #[test]
    fn is_dfu_uuid_accepts_short_forms() {
        assert!(is_dfu_uuid(DFU_SVC));
        assert!(is_dfu_uuid("0xFE59"));
        assert!(is_dfu_uuid("{0000FE59-0000-1000-8000-00805F9B34FB}"));
        assert!(!is_dfu_uuid("0000aaa1-0000-1000-8000-aabbccddeeff"));
        assert!(!is_dfu_uuid("garbage"));
    }
}
