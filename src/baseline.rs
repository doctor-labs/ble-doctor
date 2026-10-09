//! Baseline diffing: which failures are NEW versus a saved known-good report (v1 `baseline.py`).

use crate::checks::{CheckResult, Severity};
use crate::report::{compute_score, sanitize};
use crate::sarif::fingerprint;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

/// Process exit code when NEW failures reach `--fail-on` under `--baseline`.
pub const EXIT_GATE_FAILED: i32 = 3;

/// Drift between a scan and its baseline.
#[derive(Debug, Serialize)]
pub struct BaselineDiff<'a> {
    pub new_failures: Vec<&'a CheckResult>,
    /// Baseline findings no longer failing in the current scan.
    pub resolved: Vec<&'a Value>,
    /// current score - baseline score.
    pub score_delta: i32,
}

/// Read and validate a saved `--json` envelope (doctor/1). Missing/unreadable/malformed is an error, never a pass.
pub fn load(path: &std::path::Path) -> Result<Value, String> {
    let v: Value = std::fs::read_to_string(path)
        .map_err(|e| format!("baseline {}: {e}", path.display()))
        .and_then(|t| {
            serde_json::from_str(&t)
                .map_err(|e| format!("baseline {}: bad JSON: {e}", path.display()))
        })?;
    if v["schema"] != "doctor/1" || !v["findings"].is_array() {
        return Err(format!(
            "baseline {}: not a doctor/1 envelope (re-create it with `--json`)",
            path.display()
        ));
    }
    Ok(v)
}

pub fn parse_severity(s: &str) -> Option<Severity> {
    [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .into_iter()
    .find(|v| v.as_str() == s)
}

/// Fingerprints of the findings in a doctor/1 envelope (every finding there is a failure).
pub fn failed_fingerprints(report: &Value) -> HashSet<String> {
    report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| f["fingerprint"].as_str().map(str::to_string))
        .collect()
}

/// Failed checks whose fingerprint is not a finding in the baseline.
pub fn new_failures<'a>(current: &'a [CheckResult], baseline: &Value) -> Vec<&'a CheckResult> {
    let known = failed_fingerprints(baseline);
    current
        .iter()
        .filter(|r| !r.passed && !known.contains(&fingerprint(r)))
        .collect()
}

pub fn diff<'a>(current: &'a [CheckResult], baseline: &'a Value) -> BaselineDiff<'a> {
    let now: HashSet<String> = current
        .iter()
        .filter(|r| !r.passed)
        .map(fingerprint)
        .collect();
    let resolved = baseline["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["fingerprint"].as_str().is_some_and(|x| !now.contains(x)))
        .collect();
    let base_score = baseline["score"]["value"].as_i64().unwrap_or(100) as i32;
    BaselineDiff {
        new_failures: new_failures(current, baseline),
        resolved,
        score_delta: i32::from(compute_score(current)) - base_score,
    }
}

/// Print the diff to stderr (stdout stays clean for `--json`).
pub fn report_diff(d: &BaselineDiff) {
    eprintln!("baseline: score delta {:+}", d.score_delta);
    for r in &d.new_failures {
        eprintln!(
            "  NEW      {:?} {}: {}",
            r.severity,
            sanitize(&r.id),
            sanitize(&r.detail)
        );
    }
    for f in &d.resolved {
        eprintln!(
            "  RESOLVED {} {}: {}",
            sanitize(f["severity"].as_str().unwrap_or("?")),
            sanitize(f["id"].as_str().unwrap_or("?")),
            sanitize(f["message"].as_str().unwrap_or(""))
        );
    }
    if d.new_failures.is_empty() && d.resolved.is_empty() {
        eprintln!("  no change");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fp(id: &str, s: Severity, d: &str) -> String {
        fingerprint(&CheckResult::new(id, s, false, d))
    }

    fn base() -> Value {
        json!({"schema": "doctor/1", "score": {"value": 85}, "findings": [
            {"id":"mac_rotation","severity":"medium","message":"static MAC",
             "fingerprint": fp("mac_rotation", Severity::Medium, "static MAC")},
            {"id":"old_issue","severity":"low","message":"gone soon",
             "fingerprint": fp("old_issue", Severity::Low, "gone soon")}]})
    }

    #[test]
    fn new_failure_found_shared_and_passing_ignored() {
        let cur = [
            CheckResult::new("mac_rotation", Severity::Medium, false, "static MAC"),
            CheckResult::new("ok", Severity::High, true, "fine"),
            CheckResult::new(
                "unauthenticated_writes",
                Severity::High,
                false,
                "Writable: a",
            ),
        ];
        let b = base();
        let d = diff(&cur, &b);
        assert_eq!(d.new_failures.len(), 1);
        assert_eq!(d.new_failures[0].id, "unauthenticated_writes");
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.resolved[0]["id"], "old_issue");
        assert_eq!(d.score_delta, 100 * 7 / 10 * 85 / 100 - 85);
    }

    #[test]
    fn envelope_marks_baseline_state() {
        let cur = [
            CheckResult::new("mac_rotation", Severity::Medium, false, "static MAC"),
            CheckResult::new("w", Severity::High, false, "new one"),
        ];
        let loc = json!({"kind": "device", "ref": "A"});
        let v = crate::report::to_envelope(&cur, &loc, Some(&base()), 3, json!({}));
        assert_eq!(v["baseline"], json!({"new": 1, "unchanged": 1, "fixed": 1}));
        let states: Vec<_> = v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["baseline_state"].as_str().unwrap())
            .collect();
        assert_eq!(states, ["new", "unchanged"]); // sorted high first
    }

    #[test]
    fn missing_or_bad_baseline_is_error() {
        let dir = std::env::temp_dir().join(format!("bd-base-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load(&dir.join("nope.json"))
            .unwrap_err()
            .contains("nope.json"));
        let p = dir.join("bad.json");
        std::fs::write(&p, "{}").unwrap();
        assert!(load(&p).unwrap_err().contains("doctor/1"));
        std::fs::write(&p, base().to_string()).unwrap();
        assert!(load(&p).is_ok());
    }
}
