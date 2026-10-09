//! Agent-friendly handoff bundle (v1 `handoff.py` + `prompts.clean`; emit only, no agent launching).
//!
//! Shape (stable):
//! `{"version":1,"score":n,"counts":{"total","failed","shown"},"findings":[{id,severity,detail,suggested_next_action}]}`
//! Failed findings only, worst severity first (stable within a severity), capped at [`MAX_FINDINGS`].

use crate::checks::CheckResult;
use serde_json::{json, Value};
use std::path::Path;

/// Max chars of any device-supplied value (v1 `MAX_VALUE`).
pub const MAX_VALUE: usize = 300;
/// Max findings in a bundle (v1 `MAX_FINDINGS`).
pub const MAX_FINDINGS: usize = 20;

/// The shared sanitizer ([`crate::report::sanitize`]) capped at [`MAX_VALUE`] chars.
pub fn sanitize(s: &str) -> String {
    crate::report::sanitize(s).chars().take(MAX_VALUE).collect()
}

/// Per-rule follow-up for an agent; unknown ids get a generic review step.
fn next_action(id: &str) -> &'static str {
    if id.starts_with("dfu_") {
        "run dfu probe to confirm the DFU surface empirically"
    } else if id == "unauthenticated_writes" {
        "run probe-writes to confirm empirically"
    } else if id == "mac_rotation" {
        "capture >10min and re-run analyze"
    } else {
        "run `ble-doctor why <id>` and review the rule guidance"
    }
}

/// Build the handoff bundle from scan findings.
pub fn handoff(findings: &[CheckResult]) -> Value {
    let mut failed: Vec<&CheckResult> = findings.iter().filter(|f| !f.passed).collect();
    failed.sort_by_key(|f| std::cmp::Reverse(f.severity)); // stable sort
    let items: Vec<Value> = failed
        .iter()
        .take(MAX_FINDINGS)
        .map(|f| {
            json!({
                "id": sanitize(&f.id),
                "severity": f.severity,
                "detail": sanitize(&f.detail),
                "suggested_next_action": next_action(&f.id),
            })
        })
        .collect();
    json!({
        "version": 1,
        "score": crate::report::compute_score(findings),
        "counts": {"total": findings.len(), "failed": failed.len(), "shown": items.len()},
        "findings": items,
    })
}

/// Read a doctor/1 `--json` envelope and build its bundle (no radio).
pub fn from_report(path: &Path) -> Result<Value, String> {
    let report = crate::baseline::load(path)?;
    let findings: Vec<CheckResult> = report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| {
            Some(CheckResult::new(
                f["id"].as_str()?,
                crate::baseline::parse_severity(f["severity"].as_str()?)?,
                false, // every doctor/1 finding is a failure
                f["message"].as_str().unwrap_or(""),
            ))
        })
        .collect();
    Ok(handoff(&findings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Severity;

    fn r(id: &str, sev: Severity, passed: bool, d: &str) -> CheckResult {
        CheckResult::new(id, sev, passed, d)
    }

    #[test]
    fn sanitize_strips_and_caps() {
        assert_eq!(sanitize("a\u{0007}b\u{202E}c\u{200B}d\n"), "abcd ");
        assert_eq!(sanitize(&"x".repeat(1000)).chars().count(), 300);
    }

    #[test]
    fn bundle_filters_sorts_caps() {
        let mut v = vec![
            r("ok", Severity::High, true, "fine"),
            r("mac_rotation", Severity::Low, false, "bad\u{0000}mac"),
            r("unauthenticated_writes", Severity::High, false, "w"),
            r("dfu_entry_point", Severity::Medium, false, "d"),
            r("weird", Severity::Info, false, "z"),
        ];
        let b = handoff(&v);
        assert_eq!(
            b.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["counts", "findings", "score", "version"]
        );
        assert_eq!(b["counts"], json!({"total": 5, "failed": 4, "shown": 4}));
        let f = b["findings"].as_array().unwrap();
        let ids: Vec<_> = f.iter().map(|x| x["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            [
                "unauthenticated_writes",
                "dfu_entry_point",
                "mac_rotation",
                "weird"
            ]
        );
        assert_eq!(f[2]["detail"], "badmac");
        assert_eq!(
            f[0].as_object().unwrap().keys().collect::<Vec<_>>(),
            ["detail", "id", "severity", "suggested_next_action"]
        );
        assert!(f[0]["suggested_next_action"]
            .as_str()
            .unwrap()
            .contains("probe-writes"));
        assert!(f[1]["suggested_next_action"]
            .as_str()
            .unwrap()
            .contains("dfu probe"));
        assert!(f[2]["suggested_next_action"]
            .as_str()
            .unwrap()
            .contains("re-run analyze"));
        assert_eq!(f[0]["severity"], "high");

        v = (0..30)
            .map(|i| r(&format!("x{i}"), Severity::Low, false, ""))
            .collect();
        let b = handoff(&v);
        assert_eq!(b["findings"].as_array().unwrap().len(), 20);
        assert_eq!(b["counts"]["failed"], 30);
    }
}
