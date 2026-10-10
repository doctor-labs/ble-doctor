//! Score + report rendering (v1 `report.py`).

use crate::checks::{CheckResult, Severity};
use doctor_core::{BaselineCounts, BaselineState, Envelope, ExitCode, Finding, Location, Score};
use serde_json::{json, Value};

/// Score penalty per failed check, in percent.
pub fn severity_weight(s: Severity) -> u32 {
    match s {
        Severity::Critical => 50,
        Severity::High => 30,
        Severity::Medium => 15,
        Severity::Low => 5,
        Severity::Info => 0,
    }
}

/// `100 * prod(1 - w/100)` over the severities of FAILED checks, half-up rounded, clamped to [0,100].
pub fn product_score(failed: impl Iterator<Item = Severity>) -> u8 {
    let score = failed.fold(100.0_f64, |s, v| {
        s * (1.0 - f64::from(severity_weight(v)) / 100.0)
    });
    (score + 0.5).floor().clamp(0.0, 100.0) as u8
}

/// [`product_score`] over the failed checks of `results`.
pub fn compute_score(results: &[CheckResult]) -> u8 {
    product_score(results.iter().filter(|r| !r.passed).map(|r| r.severity))
}

/// The one sanitizer for every human renderer (table, stderr diff, TUI, handoff, scan device list):
/// device names and GATT strings come off the air and are attacker-controlled.
pub use doctor_core::sanitize;

/// The doctor/1 score object: ble's formula, shared shape and labels.
pub fn score(results: &[CheckResult]) -> Score {
    Score::new(compute_score(results), "ble/1", coverage_gaps(results))
}

/// Checks that could not run to a verdict.
pub fn coverage_gaps(results: &[CheckResult]) -> usize {
    results.iter().filter(|r| r.inconclusive).count()
}

/// Exit code for a findings run (doctor/1 section 4). With a baseline only NEW findings gate (3).
pub fn gate_exit(results: &[CheckResult], fail_on: Severity, new: Option<&[&CheckResult]>) -> i32 {
    let hit = |r: &CheckResult| !r.passed && r.severity >= fail_on;
    i32::from(
        match new {
            Some(n) if n.iter().any(|r| hit(r)) => ExitCode::NewFindings,
            Some(_) => ExitCode::Ok,
            None if results.iter().any(hit) => ExitCode::Findings,
            None => ExitCode::Ok,
        }
        .code(),
    )
}

/// One finding (doctor/1 section 2) for a FAILED check.
pub(crate) fn finding(
    r: &CheckResult,
    location: &Location,
    fingerprint: String,
    state: Option<BaselineState>,
) -> Finding {
    let rule = crate::rules::get(&r.id);
    Finding {
        id: r.id.clone(),
        fingerprint,
        severity: r.severity,
        confidence: None,
        category: rule.map_or("other", |x| x.category).to_string(),
        message: r.detail.clone(),
        location: location.clone(),
        evidence: vec![],
        remedy: crate::rules::remedy(&r.id),
        baseline_state: state,
        extra: Default::default(),
    }
}

/// The doctor/1 envelope. `data` extras (capture info...) are merged
/// under `data` next to `passed` (the passed checks). `exit` is the code this run returns.
pub fn to_envelope(
    results: &[CheckResult],
    location: &Location,
    device: &str,
    baseline: Option<&Value>,
    exit: i32,
    extra: Value,
) -> Value {
    let known = baseline.map(crate::baseline::failed_fingerprints);
    let failed: Vec<(&CheckResult, String)> = results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| (r, crate::sarif::fingerprint(r, device)))
        .collect();
    let mut findings: Vec<Finding> = failed
        .iter()
        .map(|(r, fp)| {
            let st = known.as_ref().map(|k| {
                if k.contains(fp) {
                    BaselineState::Unchanged
                } else {
                    BaselineState::New
                }
            });
            finding(r, location, fp.clone(), st)
        })
        .collect();
    Finding::sort(&mut findings);
    let mut data = json!({ "passed": results.iter().filter(|r| r.passed).collect::<Vec<_>>() });
    if let Value::Object(m) = extra {
        data.as_object_mut().unwrap().extend(m);
    }
    let mut env = Envelope::new(
        "ble-doctor",
        env!("CARGO_PKG_VERSION"),
        u8::try_from(exit).expect("exit code fits a u8"),
        score(results),
        findings,
        data,
    );
    if let Some(k) = known {
        let now: std::collections::HashSet<&String> = failed.iter().map(|f| &f.1).collect();
        let unchanged = now.iter().filter(|f| k.contains(**f)).count();
        env.baseline = Some(BaselineCounts {
            new: now.len() - unchanged,
            unchanged,
            fixed: k.iter().filter(|f| !now.contains(f)).count(),
        });
    }
    env.to_value()
}

pub fn to_json(envelope: &Value) -> String {
    serde_json::to_string_pretty(envelope).expect("report serializes")
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
    fn envelope_table_and_sanitize() {
        let r = [
            f(Severity::High),
            CheckResult::new("ok", Severity::Info, true, "fine"),
        ];
        let loc = Location::new(doctor_core::LocationKind::Device, "AA");
        let v = to_envelope(&r, &loc, "AA", None, 1, json!({}));
        assert_eq!(v["score"]["value"], 70);
        assert_eq!(v["score"]["label"], "needs work");
        assert_eq!(v["findings"].as_array().unwrap().len(), 1);
        assert_eq!(v["data"]["passed"][0]["id"], "ok");
        assert_eq!(gate_exit(&r, Severity::High, None), 1);
        assert_eq!(gate_exit(&r, Severity::Critical, None), 0);
    }

    #[test]
    fn explicit_inconclusive_flag_counts_as_coverage_gap() {
        let r = [
            CheckResult::new("dfu_signing_enforced", Severity::Info, true, "x").inconclusive(),
            CheckResult::new(
                "a",
                Severity::Info,
                false,
                "mentions INCONCLUSIVE only in text",
            ),
        ];
        assert_eq!(coverage_gaps(&r), 1);
    }
}
