//! SARIF 2.1.0 output (v1 `sarif.py`). Only FAILED findings become results.

use crate::checks::{CheckResult, Severity};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/Vaibhav91one/ble-doctor";

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.5",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

/// Replace the numbers that grow with capture length with `#`: a frame count
/// (`3 frames`, `3 captured advertisement frames`) and a duration after `over `/`only ` (`900s`).
/// Not every digit: a UUID or address differing in digits is a different finding.
fn mask_volatile(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_digit()) {
            let mut j = i;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let rest = &s[j..];
            let after_word = |w: &str| {
                rest.starts_with(w)
                    && !rest[w.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
            };
            let count = [
                " captured advertisement frames",
                " captured advertisement frame",
                " frames",
                " frame",
            ]
            .iter()
            .any(|w| after_word(w));
            let dur = after_word("s") && (s[..i].ends_with("over ") || s[..i].ends_with("only "));
            if count || dur {
                out.push('#');
                i = j;
                continue;
            }
            out.push_str(&s[i..j]);
            i = j;
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Stable id of one finding: sha256(`id\nseverity\ndetail`), volatile numbers masked, first 16 hex.
pub fn fingerprint(r: &CheckResult) -> String {
    let text = format!(
        "{}\n{}\n{}",
        r.id,
        r.severity.as_str(),
        mask_volatile(&r.detail)
    );
    let hex: String = Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    hex[..16].to_string()
}

/// One SARIF run. `score` (the doctor/1 score object) is recorded in run properties. `location` is the artifact URI
/// (a capture path); `None` = live scan (logical "BLE device" location).
pub fn to_sarif(score: &Value, results: &[CheckResult], location: Option<&str>) -> Value {
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
                "defaultConfiguration": {"level": level(*s)},
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
                "level": level(r.severity),
                "message": {"text": r.detail},
                "locations": [loc.clone()],
                "partialFingerprints": {"doctorFinding/v1": fingerprint(r)},
                "properties": {"severity": r.severity.as_str()},
            })
        })
        .collect();
    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ble-doctor", "version": env!("CARGO_PKG_VERSION"),
                                "informationUri": INFORMATION_URI, "rules": rules}},
            "results": out,
            "properties": {"score": score},
        }],
    })
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
        let v = to_sarif(&json!(40), &rs, None);
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
        assert_eq!(level(Severity::Info), "note");
    }

    #[test]
    fn capture_location_is_physical() {
        let v = to_sarif(
            &json!(100),
            &[r("a", Severity::Low, false, "x")],
            Some("my cap.pcap"),
        );
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "my%20cap.pcap"
        );
    }

    #[test]
    fn fingerprint_masks_volatile_only() {
        let a = r(
            "m",
            Severity::Medium,
            false,
            "static across all 3 captured advertisement frames over 900s - trackable.",
        );
        let b = r(
            "m",
            Severity::Medium,
            false,
            "static across all 40 captured advertisement frames over 1800s - trackable.",
        );
        assert_eq!(fingerprint(&a), fingerprint(&b));
        let c = r(
            "m",
            Severity::Medium,
            false,
            "one address across 5 frames, spans only 30s.",
        );
        let d = r(
            "m",
            Severity::Medium,
            false,
            "one address across 9 frames, spans only 700s.",
        );
        assert_eq!(fingerprint(&c), fingerprint(&d));
        // other digits are NOT masked; severity and id are part of the hash
        let u1 = r(
            "w",
            Severity::High,
            false,
            "Writable without bonding: 0000aaa1",
        );
        let u2 = r(
            "w",
            Severity::High,
            false,
            "Writable without bonding: 0000aaa2",
        );
        assert_ne!(fingerprint(&u1), fingerprint(&u2));
        let esc = r(
            "w",
            Severity::Low,
            false,
            "Writable without bonding: 0000aaa1",
        );
        assert_ne!(fingerprint(&u1), fingerprint(&esc));
        assert_eq!(
            mask_volatile("12 frames, 7 frameworks"),
            "# frames, 7 frameworks"
        );
    }
}
