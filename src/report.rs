//! Score + report rendering (v1 `report.py`).

use crate::checks::{CheckResult, Severity};
use serde_json::{json, Value};

/// Score penalty per failed check, in percent.
pub fn severity_weight(s: Severity) -> u32 {
    match s {
        Severity::High => 30,
        Severity::Medium => 15,
        Severity::Low => 5,
        Severity::Info => 0,
    }
}

/// `100 * prod(1 - w/100)` over FAILED checks, half-up rounded, clamped to [0,100].
pub fn compute_score(results: &[CheckResult]) -> u8 {
    let mut score = 100.0_f64;
    for r in results.iter().filter(|r| !r.passed) {
        score *= 1.0 - f64::from(severity_weight(r.severity)) / 100.0;
    }
    (score + 0.5).floor().clamp(0.0, 100.0) as u8
}

/// `{"score": n, "findings": [{id, severity, passed, detail}]}`.
pub fn to_dict(results: &[CheckResult]) -> Value {
    json!({ "score": compute_score(results), "findings": results })
}

pub fn to_json(results: &[CheckResult]) -> String {
    serde_json::to_string_pretty(&to_dict(results)).expect("report serializes")
}

pub fn to_table(results: &[CheckResult]) -> String {
    let mut out = format!("BLE Doctor - score: {}/100\n", compute_score(results));
    for r in results {
        let mark = if r.passed { "PASS" } else { "FAIL" };
        out.push_str(&format!(
            "\n[{mark}] {} ({}): {}",
            r.id,
            r.severity.as_str(),
            r.detail
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(sev: Severity) -> CheckResult {
        CheckResult::new("x", sev, false, "d")
    }

    #[test]
    fn weights_strictly_ordered() {
        let w: Vec<u32> = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
        ]
        .map(severity_weight)
        .to_vec();
        assert!(w.windows(2).all(|p| p[0] < p[1]), "{w:?}");
        assert_eq!(w, [0, 5, 15, 30]);
    }

    #[test]
    fn score_cases() {
        assert_eq!(compute_score(&[]), 100);
        assert_eq!(
            compute_score(&[CheckResult::new("x", Severity::High, true, "")]),
            100
        );
        assert_eq!(compute_score(&[f(Severity::Info)]), 100);
        assert_eq!(compute_score(&[f(Severity::High)]), 70);
        assert_eq!(compute_score(&[f(Severity::Medium)]), 85);
        // 100 * .7 * .85 = 59.5 -> half-up 60
        assert_eq!(compute_score(&[f(Severity::High), f(Severity::Medium)]), 60);
        assert!(
            compute_score(&[f(Severity::High), f(Severity::Medium)])
                > compute_score(&[f(Severity::High), f(Severity::High)])
        );
    }

    #[test]
    fn dict_and_table() {
        let r = [f(Severity::High)];
        let d = to_dict(&r);
        assert_eq!(d["score"], 70);
        assert_eq!(d["findings"][0]["severity"], "high");
        assert_eq!(d["findings"][0]["passed"], false);
        assert!(to_table(&r).contains("score: 70/100"));
        assert!(to_table(&r).contains("[FAIL] x (high): d"));
        assert!(to_json(&r).contains("\"score\": 70"));
    }
}
