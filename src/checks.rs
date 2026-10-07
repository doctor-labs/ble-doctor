//! Canonical check types and pure checks (v1 `checks.py`).
//! Reused by every probe/check issue: build a `CheckResult`, feed it to `report`/`sarif`.

use crate::gatt::GattInfo;
use serde::Serialize;

pub use crate::capture::check_mac_rotation;

/// Finding severity. Ordered: `Info < Low < Medium < High`. Serializes lowercase (v1 values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    /// Lowercase name (v1 `Severity.value`).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
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
}
