//! ble-doctor on doctor-kit: one `Doctor` for the findings subjects (a capture file; a live device
//! joins in a later step). The checks stay pure functions returning `CheckResult`; [`collected`] maps
//! their results onto kit findings, byte for byte what `report::to_envelope` builds.

use crate::checks::CheckResult;
use crate::report::{coverage_gaps, finding, product_score, sanitize};
use doctor_core::{Envelope, Location, LocationKind, Score};
use doctor_kit::baseline::BaselineError;
use doctor_kit::{Check, Collected, Ctx, Doctor, ScanFailure, TargetKind};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

/// What a run looks at. The kit walks no directory for it (`TargetKind::Detached`).
pub enum Subject {
    /// Nothing chosen (`fix` without `--from`).
    None,
    /// One btsnoop/pcap capture.
    Capture(PathBuf),
}

pub struct BleDoctor {
    pub subject: Subject,
    /// Print the human preamble (capture summary) to stdout before the report.
    pub say: bool,
    /// The one gathered result: `shell` and `explore` re-scan, a radio must not be hit twice.
    cache: Mutex<Option<Result<Collected, ScanFailure>>>,
}

impl BleDoctor {
    pub fn new(subject: Subject, say: bool) -> Self {
        BleDoctor {
            subject,
            say,
            cache: Mutex::new(None),
        }
    }

    fn gather(&self) -> Result<Collected, ScanFailure> {
        match &self.subject {
            Subject::None => Err(ScanFailure::new(
                "nothing to scan: pass `--from <report.json>`, or a subject on the command",
            )),
            Subject::Capture(path) => self.gather_capture(path),
        }
    }

    fn gather_capture(&self, path: &std::path::Path) -> Result<Collected, ScanFailure> {
        let info = std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|b| crate::capture::parse_capture(&b))
            .map_err(|e| ScanFailure {
                exit: 2,
                stderr: format!("analyze: {}\n", sanitize(&e)),
                envelope: None,
            })?;
        let smp = crate::smp::analyze(&info.smp_pdus);
        let mut checks = vec![crate::capture::check_mac_rotation(&info)];
        checks.extend(smp.checks);
        // Peripheral identity: the one address in the capture; rotating/absent -> empty.
        let mut addrs: Vec<&String> = info.adv_mac_addresses.iter().collect();
        addrs.sort();
        addrs.dedup();
        let device = if addrs.len() == 1 {
            addrs[0].as_str()
        } else {
            ""
        };
        if self.say {
            println!(
                "capture: {} ({} adv frames)",
                sanitize(info.capture_flavour.as_deref().unwrap_or("unknown")),
                info.adv_mac_addresses.len()
            );
            for l in &smp.summary {
                println!("{}", sanitize(l));
            }
        }
        let loc = Location::new(LocationKind::File, path.display().to_string());
        Ok(collected(
            &checks,
            &loc,
            device,
            json!({"capture": info, "smp": smp.data}),
        ))
    }
}

/// Failed checks become findings (fingerprint = rule + `device`), passed ones go under
/// `data.passed`, `extra` is merged next to them, inconclusive checks are coverage gaps.
pub fn collected(
    results: &[CheckResult],
    location: &Location,
    device: &str,
    extra: Value,
) -> Collected {
    let mut data = json!({ "passed": results.iter().filter(|r| r.passed).collect::<Vec<_>>() });
    if let Value::Object(m) = extra {
        data.as_object_mut().unwrap().extend(m);
    }
    Collected {
        findings: results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| finding(r, location, crate::sarif::fingerprint(r, device), None))
            .collect(),
        data,
        gaps: coverage_gaps(results),
    }
}

impl Doctor for BleDoctor {
    fn name(&self) -> &str {
        "ble-doctor"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn about(&self) -> &str {
        "Cross-platform BLE diagnostics and security CLI"
    }
    fn categories(&self) -> Vec<&'static str> {
        vec!["gatt", "privacy", "dfu", "pairing", "other"]
    }
    /// Unused: `collect` is ours (the checks are pure functions over collected data).
    fn checks(&self) -> Vec<Box<dyn Check>> {
        vec![]
    }
    fn target(&self) -> TargetKind {
        TargetKind::Detached
    }

    /// ble's product model (`ble/1`): 100 * prod(1 - weight) over the findings.
    fn score(&self, findings: &[doctor_core::Finding], _: &Ctx) -> Option<Score> {
        Some(Score::new(
            product_score(findings.iter().map(|f| f.severity)),
            "ble/1",
            0,
        ))
    }
    fn score_collected(&self, c: &Collected, _: &Ctx) -> Option<Score> {
        Some(Score::new(
            product_score(c.findings.iter().map(|f| f.severity)),
            "ble/1",
            c.gaps,
        ))
    }
    fn render_json(&self, env: &Envelope) -> String {
        serde_json::to_string_pretty(&env.to_value()).expect("report serializes") + "\n"
    }

    fn baseline_message(&self, e: &BaselineError) -> String {
        sanitize(&match e {
            BaselineError::Unreadable { path, err } => format!("baseline {path}: {err}"),
            BaselineError::NotJson { path, err } => format!("baseline {path}: bad JSON: {err}"),
            BaselineError::NotDoctor1 { path } => {
                format!("baseline {path}: not a doctor/1 envelope (re-create it with `--json`)")
            }
            other => other.to_string(),
        })
    }
    /// The drift against the baseline on stderr (stdout stays clean for `--json`), in check order.
    fn baseline_hook(&self, saved: &Value, env: &mut Envelope) -> Result<(), ScanFailure> {
        let base_score = saved["score"]["value"].as_i64().unwrap_or(100) as i32;
        eprintln!(
            "baseline: score delta {:+}",
            i32::from(env.score.value) - base_score
        );
        let now: HashSet<&str> = env
            .findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();
        let mut changed = false;
        let cache = self.cache.lock().unwrap();
        for f in cache.iter().flatten().flat_map(|c| &c.findings) {
            let is_new = env.findings.iter().any(|e| {
                e.fingerprint == f.fingerprint
                    && e.baseline_state == Some(doctor_core::BaselineState::New)
            });
            if is_new {
                changed = true;
                eprintln!(
                    "  NEW      {:?} {}: {}",
                    f.severity,
                    sanitize(&f.id),
                    sanitize(&f.message)
                );
            }
        }
        for f in saved["findings"].as_array().into_iter().flatten() {
            if f["fingerprint"].as_str().is_some_and(|x| !now.contains(x)) {
                changed = true;
                eprintln!(
                    "  RESOLVED {} {}: {}",
                    sanitize(f["severity"].as_str().unwrap_or("?")),
                    sanitize(f["id"].as_str().unwrap_or("?")),
                    sanitize(f["message"].as_str().unwrap_or(""))
                );
            }
        }
        if !changed {
            eprintln!("  no change");
        }
        Ok(())
    }

    fn collect(&self, _: &Ctx) -> Result<Collected, ScanFailure> {
        self.cache
            .lock()
            .unwrap()
            .get_or_insert_with(|| self.gather())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Severity;
    use crate::{baseline, report};
    use doctor_kit::baseline as kit_baseline;

    fn results() -> Vec<CheckResult> {
        vec![
            CheckResult::new("mac_rotation", Severity::Info, false, "few frames").inconclusive(),
            CheckResult::new(
                "unauthenticated_writes",
                Severity::High,
                false,
                "Writable: a",
            ),
            CheckResult::new("dfu_surface_absent", Severity::Info, true, "none"),
            CheckResult::new("smp_just_works", Severity::Medium, false, "just works"),
        ]
    }

    /// The kit pipeline reproduces `report::to_envelope` exactly, with and without a baseline.
    #[test]
    fn kit_envelope_equals_report_to_envelope() {
        let (loc, dev, extra) = (
            Location::new(LocationKind::Device, "AA:BB"),
            "AA:BB",
            json!({"smp": {"seen": false}}),
        );
        let r = results();
        let d = BleDoctor::new(Subject::None, false);
        *d.cache.lock().unwrap() = Some(Ok(collected(&r, &loc, dev, extra.clone())));
        let ctx = Ctx::detached(Default::default(), Severity::High);

        let env = d.try_scan(&ctx).unwrap();
        let want = report::to_envelope(&r, &loc, dev, None, 1, extra.clone());
        assert_eq!(env.to_value(), want);
        assert_eq!(d.render_json(&env), report::to_json(&want) + "\n");

        let base = json!({"schema": "doctor/1", "score": {"value": 85}, "findings": [
            {"id": "smp_just_works", "fingerprint": crate::sarif::fingerprint(&r[3], dev)},
            {"id": "gone", "fingerprint": "ffffffffffffffff"}]});
        let saved = kit_baseline::Saved {
            fingerprints: baseline::failed_fingerprints(&base),
            doc: base.clone(),
        };
        let mut env = d.try_scan(&ctx).unwrap();
        kit_baseline::apply(&d, &mut env, &saved);
        env.exit_code = kit_baseline::gate(&d, &env, Severity::High, true);
        let want = report::to_envelope(&r, &loc, dev, Some(&base), 3, extra);
        assert_eq!(env.to_value(), want);
    }
}
