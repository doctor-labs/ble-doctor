//! Baseline diffing: which failures are NEW versus a saved known-good report (v1 `baseline.py`).

use crate::checks::{CheckResult, Severity};
use crate::report::compute_score;
use crate::sarif::fingerprint;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

/// Process exit code when new failures reach the severity gate.
pub const EXIT_GATE_FAILED: i32 = 3;

/// Drift between a scan and its baseline.
#[derive(Debug, Serialize)]
pub struct BaselineDiff<'a> {
    pub new_failures: Vec<&'a CheckResult>,
    /// Baseline failures no longer failing in the current scan.
    pub resolved: Vec<CheckResult>,
    /// current score - baseline score.
    pub score_delta: i32,
}

/// Read and validate a saved `--json` report. Missing/unreadable/malformed is an error, never a pass.
pub fn load(path: &std::path::Path) -> Result<Value, String> {
    let v: Value = std::fs::read_to_string(path)
        .map_err(|e| format!("baseline {}: {e}", path.display()))
        .and_then(|t| {
            serde_json::from_str(&t)
                .map_err(|e| format!("baseline {}: bad JSON: {e}", path.display()))
        })?;
    if !v["findings"].is_array() {
        return Err(format!("baseline {}: no findings array", path.display()));
    }
    Ok(v)
}

pub fn parse_severity(s: &str) -> Option<Severity> {
    [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
    ]
    .into_iter()
    .find(|v| v.as_str() == s)
}

/// FAILED findings of a report dict (malformed entries are skipped).
fn failed_findings(report: &Value) -> Vec<CheckResult> {
    report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| !f["passed"].as_bool().unwrap_or(false))
        .filter_map(|f| {
            Some(CheckResult::new(
                f["id"].as_str()?,
                parse_severity(f["severity"].as_str()?)?,
                false,
                f["detail"].as_str().unwrap_or(""),
            ))
        })
        .collect()
}

/// Fingerprints of the FAILED findings in a report dict.
pub fn failed_fingerprints(report: &Value) -> HashSet<String> {
    failed_findings(report).iter().map(fingerprint).collect()
}

/// Failed checks whose fingerprint is not a failure in the baseline.
pub fn new_failures<'a>(current: &'a [CheckResult], baseline: &Value) -> Vec<&'a CheckResult> {
    let known = failed_fingerprints(baseline);
    current
        .iter()
        .filter(|r| !r.passed && !known.contains(&fingerprint(r)))
        .collect()
}

pub fn diff<'a>(current: &'a [CheckResult], baseline: &Value) -> BaselineDiff<'a> {
    let now: HashSet<String> = current
        .iter()
        .filter(|r| !r.passed)
        .map(fingerprint)
        .collect();
    let resolved = failed_findings(baseline)
        .into_iter()
        .filter(|r| !now.contains(&fingerprint(r)))
        .collect();
    let base_score = baseline["score"].as_i64().unwrap_or(100) as i32;
    BaselineDiff {
        new_failures: new_failures(current, baseline),
        resolved,
        score_delta: i32::from(compute_score(current)) - base_score,
    }
}

/// Severity gate: `severity` is at or above `threshold`.
pub fn reaches(severity: Severity, threshold: Severity) -> bool {
    severity >= threshold
}

/// Print the diff to stderr (stdout stays clean for `--json`); true when the gate trips.
pub fn report_and_gate(checks: &[CheckResult], baseline: &Value, threshold: Severity) -> bool {
    let d = diff(checks, baseline);
    eprintln!("baseline: score delta {:+}", d.score_delta);
    for r in &d.new_failures {
        eprintln!("  NEW      {:?} {}: {}", r.severity, r.id, r.detail);
    }
    for r in &d.resolved {
        eprintln!("  RESOLVED {:?} {}: {}", r.severity, r.id, r.detail);
    }
    if d.new_failures.is_empty() && d.resolved.is_empty() {
        eprintln!("  no change");
    }
    d.new_failures
        .iter()
        .any(|r| reaches(r.severity, threshold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> Value {
        json!({"score": 85, "findings": [
            {"id":"mac_rotation","severity":"medium","passed":false,"detail":"static MAC"},
            {"id":"old_issue","severity":"low","passed":false,"detail":"gone soon"},
            {"id":"ok","severity":"high","passed":true,"detail":"fine"}]})
    }

    #[test]
    fn new_high_failure_trips_gate() {
        let cur = [
            CheckResult::new("mac_rotation", Severity::Medium, false, "static MAC"),
            CheckResult::new(
                "unauthenticated_writes",
                Severity::High,
                false,
                "Writable: a",
            ),
        ];
        let d = diff(&cur, &base());
        assert_eq!(d.new_failures.len(), 1);
        assert_eq!(d.new_failures[0].id, "unauthenticated_writes");
        assert!(report_and_gate(&cur, &base(), Severity::High));
        assert!(!report_and_gate(&cur[..1], &base(), Severity::High));
    }

    #[test]
    fn shared_failure_not_new_and_passing_ignored() {
        let cur = [
            CheckResult::new("mac_rotation", Severity::Medium, false, "static MAC"),
            CheckResult::new("ok", Severity::High, true, "fine"),
        ];
        assert!(new_failures(&cur, &base()).is_empty());
    }

    #[test]
    fn resolved_and_score_delta() {
        let cur = [CheckResult::new(
            "mac_rotation",
            Severity::Medium,
            false,
            "static MAC",
        )];
        let d = diff(&cur, &base());
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.resolved[0].id, "old_issue");
        assert_eq!(d.score_delta, 85 - 85); // 100 * 0.85 = 85
        let clean = [CheckResult::new("mac_rotation", Severity::Medium, true, "")];
        assert_eq!(diff(&clean, &base()).score_delta, 15);
        assert_eq!(diff(&clean, &base()).resolved.len(), 2);
    }

    #[test]
    fn reaches_orders_severities() {
        assert!(reaches(Severity::High, Severity::Medium));
        assert!(!reaches(Severity::Low, Severity::Medium));
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
        assert!(load(&p).unwrap_err().contains("no findings"));
        std::fs::write(&p, base().to_string()).unwrap();
        assert!(load(&p).is_ok());
    }
}
