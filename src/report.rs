//! Score + report rendering (v1 `report.py`).

use crate::checks::{CheckResult, Severity};
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

/// `100 * prod(1 - w/100)` over FAILED checks, half-up rounded, clamped to [0,100].
pub fn compute_score(results: &[CheckResult]) -> u8 {
    let mut score = 100.0_f64;
    for r in results.iter().filter(|r| !r.passed) {
        score *= 1.0 - f64::from(severity_weight(r.severity)) / 100.0;
    }
    (score + 0.5).floor().clamp(0.0, 100.0) as u8
}

/// Strip control / invisible / bidi / format characters (whitespace becomes a plain space).
/// The one helper for every human renderer (table, stderr diff, TUI, handoff, scan device list):
/// device names and GATT strings come off the air and are attacker-controlled.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| {
            !c.is_control()
                && !matches!(*c as u32,
                    0xAD | 0x61C | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E
                    | 0x2060..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0xE0000..=0xE007F)
        })
        .collect()
}

/// Checks that could not run to a verdict.
pub fn coverage_gaps(results: &[CheckResult]) -> usize {
    results.iter().filter(|r| r.inconclusive).count()
}

/// `good` (>=90), `needs work` (>=60), `critical`; `incomplete` replaces `good` on coverage gaps.
pub fn score_label(value: u8, gaps: usize) -> &'static str {
    match value {
        90.. if gaps > 0 => "incomplete",
        90.. => "good",
        60.. => "needs work",
        _ => "critical",
    }
}

/// Exit code for a findings run (doctor/1 section 4). With a baseline only NEW findings gate (3).
pub fn gate_exit(results: &[CheckResult], fail_on: Severity, new: Option<&[&CheckResult]>) -> i32 {
    let hit = |r: &CheckResult| !r.passed && r.severity >= fail_on;
    match new {
        Some(n) => 3 * i32::from(n.iter().any(|r| hit(r))),
        None => i32::from(results.iter().any(hit)),
    }
}

/// One finding object (doctor/1 section 2) for a FAILED check.
fn finding(r: &CheckResult, location: &Value, device: &str, state: Option<&str>) -> Value {
    let rule = crate::rules::get(&r.id);
    let mut f = json!({
        "id": r.id,
        "fingerprint": crate::sarif::fingerprint(r, device),
        "severity": r.severity,
        "category": rule.map_or("other", |x| x.category),
        "message": r.detail,
        "location": location,
        "remedy": crate::rules::remedy(&r.id),
    });
    if let Some(s) = state {
        f["baseline_state"] = json!(s);
    }
    f
}

/// The doctor/1 envelope. `location` is `{kind, ref}`; `data` extras (capture info...) are merged
/// under `data` next to `passed` (the passed checks). `exit` is the code this run returns.
pub fn to_envelope(
    results: &[CheckResult],
    location: &Value,
    device: &str,
    baseline: Option<&Value>,
    exit: i32,
    extra: Value,
) -> Value {
    let known = baseline.map(crate::baseline::failed_fingerprints);
    let mut failed: Vec<(&CheckResult, String)> = results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| (r, crate::sarif::fingerprint(r, device)))
        .collect();
    failed.sort_by(|a, b| (b.0.severity, &a.0.id, &a.1).cmp(&(a.0.severity, &b.0.id, &b.1)));
    let findings: Vec<Value> = failed
        .iter()
        .map(|(r, fp)| {
            let st = known
                .as_ref()
                .map(|k| if k.contains(fp) { "unchanged" } else { "new" });
            finding(r, location, device, st)
        })
        .collect();
    let value = compute_score(results);
    let gaps = coverage_gaps(results);
    let mut data = json!({ "passed": results.iter().filter(|r| r.passed).collect::<Vec<_>>() });
    if let Value::Object(m) = extra {
        data.as_object_mut().unwrap().extend(m);
    }
    let mut v = json!({
        "schema": "doctor/1",
        "tool": "ble-doctor",
        "version": env!("CARGO_PKG_VERSION"),
        "exit_code": exit,
        "score": {"value": value, "label": score_label(value, gaps), "model": "ble/1", "coverage_gaps": gaps},
        "findings": findings,
        "data": data,
    });
    if let Some(k) = known {
        let now: std::collections::HashSet<&String> = failed.iter().map(|f| &f.1).collect();
        let unchanged = now.iter().filter(|f| k.contains(**f)).count();
        v["baseline"] = json!({"new": now.len() - unchanged, "unchanged": unchanged, "fixed": k.iter().filter(|f| !now.contains(f)).count()});
    }
    v
}

pub fn to_json(envelope: &Value) -> String {
    serde_json::to_string_pretty(envelope).expect("report serializes")
}

pub fn to_table(results: &[CheckResult]) -> String {
    let mut out = format!("BLE Doctor - score: {}/100\n", compute_score(results));
    for r in results {
        let mark = if r.passed { "PASS" } else { "FAIL" };
        out.push_str(&format!(
            "\n[{mark}] {} ({}): {}",
            sanitize(&r.id),
            r.severity.as_str(),
            sanitize(&r.detail)
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
    fn envelope_table_and_sanitize() {
        let r = [
            f(Severity::High),
            CheckResult::new("ok", Severity::Info, true, "fine"),
        ];
        let loc = json!({"kind": "device", "ref": "AA"});
        let v = to_envelope(&r, &loc, "AA", None, 1, json!({}));
        assert_eq!(v["score"]["value"], 70);
        assert_eq!(v["score"]["label"], "needs work");
        assert_eq!(v["findings"].as_array().unwrap().len(), 1);
        assert_eq!(v["data"]["passed"][0]["id"], "ok");
        assert!(to_table(&r).contains("[FAIL] x (high): d"));
        assert_eq!(gate_exit(&r, Severity::High, None), 1);
        assert_eq!(gate_exit(&r, Severity::Critical, None), 0);
        assert_eq!(score_label(95, 1), "incomplete");
    }

    /// doctor/1 section 8: an ESC sequence in an attacker-controlled detail never reaches the table.
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

    #[test]
    fn esc_does_not_reach_human_output() {
        let r = [CheckResult::new(
            "x",
            Severity::Low,
            false,
            "evil\x1b[31mred\u{202e}rtl\u{200b}",
        )];
        let t = to_table(&r);
        assert!(!t.contains('\x1b') && !t.contains('\u{202e}') && !t.contains('\u{200b}'));
        assert!(t.contains("evil[31mred"));
    }
}
