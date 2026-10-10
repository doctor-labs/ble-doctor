//! SARIF 2.1.0 output (v1 `sarif.py`). Only FAILED findings become results.

use crate::checks::{CheckResult, Severity};
use doctor_core::Score;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub use doctor_core::sarif::SCHEMA_URI as SARIF_SCHEMA;
const INFORMATION_URI: &str = "https://github.com/doctor-labs/ble-doctor";

fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.5",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

/// Stable id of one finding for baselines: first 16 hex of sha256(`rule id\ndevice`), the device
/// identity trimmed and uppercased. Severity and detail wording are deliberately not part of it, so
/// re-rating a rule or rewording a message never turns a baseline entry "new". One function serves
/// JSON, SARIF and baseline. Device = the `--target` as passed (scan) or the single peripheral
/// address in the capture, else empty (analyze); never a file path.
pub fn fingerprint(r: &CheckResult, device: &str) -> String {
    doctor_core::fingerprint(format!("{}\n{}", r.id, device.trim().to_uppercase()).as_bytes())
}

/// One SARIF run. `score` (the doctor/1 score object) is recorded in run properties. `location` is the artifact URI
/// (a capture path); `None` = live scan (logical "BLE device" location).
pub fn to_sarif(
    score: &Score,
    results: &[CheckResult],
    location: Option<&str>,
    device: &str,
) -> Value {
    let failed: Vec<&CheckResult> = results.iter().filter(|r| !r.passed).collect();
    let mut worst: BTreeMap<&str, Severity> = BTreeMap::new();
    for r in &failed {
        let e = worst.entry(r.id.as_str()).or_insert(r.severity);
        *e = (*e).max(r.severity);
    }
    let rules: Vec<Value> = worst
        .iter()
        .map(|(id, s)| {
            json!({
                "id": id, "name": id,
                "shortDescription": {"text": id},
                "defaultConfiguration": {"level": s.sarif_level()},
                "properties": {"tags": ["security", "bluetooth"], "security-severity": security_severity(*s)},
            })
        })
        .collect();
    let loc = match location {
        Some(u) => {
            json!({"physicalLocation": {"artifactLocation": {"uri": u.replace(' ', "%20")}}})
        }
        None => json!({"logicalLocations": [{"name": "BLE device", "kind": "device"}]}),
    };
    let out: Vec<Value> = failed
        .iter()
        .map(|r| {
            json!({
                "ruleId": r.id,
                "ruleIndex": worst.keys().position(|k| *k == r.id).unwrap(),
                "level": r.severity.sarif_level(),
                "message": {"text": r.detail},
                "locations": [loc.clone()],
                "partialFingerprints": doctor_core::sarif::partial_fingerprints(&fingerprint(r, device)),
                "properties": {"severity": r.severity.as_str()},
            })
        })
        .collect();
    doctor_core::sarif::document(
        "ble-doctor",
        env!("CARGO_PKG_VERSION"),
        INFORMATION_URI,
        rules,
        out,
        score,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(id: &str, s: Severity, passed: bool, d: &str) -> CheckResult {
        CheckResult::new(id, s, passed, d)
    }

    #[test]
    fn structure_failed_only_and_maps() {
        let rs = [
            r("a", Severity::High, false, "bad"),
            r("a", Severity::Low, false, "meh"),
            r("b", Severity::Info, true, "ok"),
            r("c", Severity::Medium, false, "mid"),
        ];
        let v = to_sarif(&Score::new(40, "ble/1", 0), &rs, None, "AA");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["$schema"], SARIF_SCHEMA);
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "ble-doctor");
        let res = run["results"].as_array().unwrap();
        assert_eq!(res.len(), 3, "passed check excluded");
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2, "rules deduped, passed-only id absent");
        assert_eq!(rules[0]["id"], "a");
        assert_eq!(rules[0]["defaultConfiguration"]["level"], "error");
        assert_eq!(rules[0]["properties"]["security-severity"], "8.5");
        assert_eq!(rules[1]["defaultConfiguration"]["level"], "warning");
        assert_eq!(rules[1]["properties"]["security-severity"], "5.5");
        assert_eq!(res[1]["level"], "note");
        assert_eq!(res[1]["ruleIndex"], 0);
        assert_eq!(res[2]["ruleIndex"], 1);
        assert_eq!(
            res[0]["locations"][0]["logicalLocations"][0]["kind"],
            "device"
        );
        assert_eq!(
            res[0]["partialFingerprints"]["doctorFinding/v1"]
                .as_str()
                .unwrap()
                .len(),
            16
        );
        assert_eq!(security_severity(Severity::Low), "3.0");
        assert_eq!(security_severity(Severity::Info), "0.0");
    }

    #[test]
    fn capture_location_is_physical() {
        let v = to_sarif(
            &Score::new(100, "ble/1", 0),
            &[r("a", Severity::Low, false, "x")],
            Some("my cap.pcap"),
            "",
        );
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "my%20cap.pcap"
        );
    }

    #[test]
    fn fingerprint_is_rule_plus_device_only() {
        let a = r("m", Severity::Medium, false, "static across 3 frames");
        let b = r("m", Severity::High, false, "reworded, 40 frames");
        assert_eq!(fingerprint(&a, "aa:bb"), fingerprint(&b, " AA:BB "));
        assert_ne!(fingerprint(&a, "AA:BB"), fingerprint(&a, "AA:BC"));
        assert_ne!(
            fingerprint(&a, "AA:BB"),
            fingerprint(&r("n", Severity::Medium, false, ""), "AA:BB")
        );
        let f = fingerprint(&a, "");
        assert!(
            f.len() == 16
                && f.bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
