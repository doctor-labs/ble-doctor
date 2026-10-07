//! Environment diagnosis (`doctor`): ordered preflight, pure over injectable probes.

use crate::capability::{support, Feature, Platform, Support};
use crate::error::BleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub name: String,
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
}

/// Probe results; `None` = could not be determined (reported as unknown, never a failure).
#[derive(Debug, Clone, Copy, Default)]
pub struct Probes {
    pub adapter_present: Option<bool>,
    pub adapter_powered: Option<bool>,
    pub permission_ok: Option<bool>,
    pub daemon_running: Option<bool>,
}

impl Probes {
    /// Best-effort, lightweight live detection. Anything not cheaply knowable stays `None`.
    // TODO(#5): detect adapter presence/power through the radio layer.
    pub fn detect() -> Self {
        let mut p = Probes::default();
        if cfg!(target_os = "linux") {
            p.adapter_present = std::fs::read_dir("/sys/class/bluetooth")
                .ok()
                .map(|mut d| d.next().is_some());
            p.daemon_running = std::process::Command::new("pgrep")
                .args(["-x", "bluetoothd"])
                .output()
                .ok()
                .map(|o| o.status.success());
        }
        p
    }
}

fn res(name: &str, status: Status, detail: &str, fix: Option<&str>) -> CheckResult {
    CheckResult {
        name: name.into(),
        status,
        detail: detail.into(),
        fix: fix.map(Into::into),
    }
}

const ALL_FEATURES: [Feature; 12] = [
    Feature::Scan,
    Feature::Enumerate,
    Feature::Descriptors,
    Feature::Read,
    Feature::Write,
    Feature::Subscribe,
    Feature::RetrieveMtu,
    Feature::RequestExactMtu,
    Feature::SetRandomAddress,
    Feature::RawL2cap,
    Feature::Sniff,
    Feature::Mitm,
];

/// Run all checks in dependency order: adapter, permission, daemon (Linux), features.
pub fn run_doctor(p: &Probes, platform: Platform) -> Vec<CheckResult> {
    let mut out = Vec::new();

    out.push(match (p.adapter_present, p.adapter_powered) {
        (Some(false), _) => res(
            "adapter",
            Status::Fail,
            "no Bluetooth adapter found",
            Some(BleError::AdapterNotFound.remediation()),
        ),
        (Some(true), Some(false)) => res(
            "adapter",
            Status::Fail,
            "adapter present but powered off",
            Some(BleError::AdapterOff.remediation()),
        ),
        (Some(true), Some(true)) => res("adapter", Status::Ok, "adapter present and powered", None),
        (Some(true), None) => res(
            "adapter",
            Status::Warn,
            "adapter present, power state unknown",
            None,
        ),
        (None, _) => res("adapter", Status::Warn, "adapter state unknown", None),
    });

    let perm_fix = match platform {
        Platform::MacOs => "Guidance: enable Bluetooth for your terminal in System Settings > Privacy & Security > Bluetooth.",
        Platform::Linux => "Guidance: add your user to the `bluetooth` group, or grant CAP_NET_ADMIN and CAP_NET_RAW to the binary.",
        Platform::Windows => "Guidance: turn the Bluetooth radio on in Settings > Bluetooth & devices.",
    };
    out.push(match p.permission_ok {
        Some(true) => res("permission", Status::Ok, "Bluetooth access granted", None),
        Some(false) => res(
            "permission",
            Status::Fail,
            "Bluetooth access denied",
            Some(perm_fix),
        ),
        None => res(
            "permission",
            Status::Warn,
            "permission unknown (not checked)",
            Some(perm_fix),
        ),
    });

    if platform == Platform::Linux {
        out.push(match p.daemon_running {
            Some(true) => res("daemon", Status::Ok, "bluetoothd is running", None),
            Some(false) => res(
                "daemon",
                Status::Fail,
                "bluetoothd is not running",
                Some("Run: sudo systemctl restart bluetooth"),
            ),
            None => res("daemon", Status::Warn, "bluetoothd state unknown", None),
        });
    }

    for f in ALL_FEATURES {
        let (status, detail, fix) = match support(f, platform) {
            Support::Supported => (Status::Ok, "supported".to_string(), None),
            Support::Unsupported => (Status::Warn, "unsupported on this platform".into(), None),
            Support::NeedsCapability(c) => (Status::Warn, format!("needs {c}"), None),
        };
        out.push(CheckResult {
            name: format!("feature:{f:?}"),
            status,
            detail,
            fix,
        });
    }
    out
}

/// Print the report; returns the exit code (1 if any hard Fail, else 0 — warnings are diagnostic only).
pub fn print_report(results: &[CheckResult]) -> i32 {
    for r in results {
        let tag = match r.status {
            Status::Ok => "OK  ",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        };
        println!("[{tag}] {}: {}", r.name, r.detail);
        if let Some(fix) = &r.fix {
            let line = if fix.starts_with("Run:") || fix.starts_with("Guidance:") {
                fix.clone()
            } else {
                format!("Guidance: {fix}")
            };
            println!("       {line}");
        }
    }
    i32::from(results.iter().any(|r| r.status == Status::Fail))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Probes {
        Probes {
            adapter_present: Some(true),
            adapter_powered: Some(true),
            permission_ok: Some(true),
            daemon_running: Some(true),
        }
    }

    fn get<'a>(r: &'a [CheckResult], n: &str) -> &'a CheckResult {
        r.iter().find(|c| c.name == n).unwrap()
    }

    #[test]
    fn healthy_linux_all_ok() {
        let r = run_doctor(&good(), Platform::Linux);
        for n in ["adapter", "permission", "daemon"] {
            assert_eq!(get(&r, n).status, Status::Ok);
        }
    }

    #[test]
    fn adapter_absent_fails_with_fix() {
        let p = Probes {
            adapter_present: Some(false),
            ..good()
        };
        let c = &run_doctor(&p, Platform::MacOs)[0];
        assert_eq!(c.status, Status::Fail);
        assert!(c.fix.is_some());
    }

    #[test]
    fn powered_off_fails() {
        let p = Probes {
            adapter_powered: Some(false),
            ..good()
        };
        assert_eq!(
            get(&run_doctor(&p, Platform::Linux), "adapter").status,
            Status::Fail
        );
    }

    #[test]
    fn unknown_permission_warns_not_fails() {
        let p = Probes {
            permission_ok: None,
            ..good()
        };
        let r = run_doctor(&p, Platform::MacOs);
        assert_eq!(get(&r, "permission").status, Status::Warn);
        assert!(get(&r, "permission").detail.contains("unknown"));
    }

    #[test]
    fn linux_daemon_down_has_restart_hint_and_others_skip_daemon() {
        let p = Probes {
            daemon_running: Some(false),
            ..good()
        };
        let r = run_doctor(&p, Platform::Linux);
        let d = get(&r, "daemon");
        assert_eq!(d.status, Status::Fail);
        assert!(d
            .fix
            .as_ref()
            .unwrap()
            .contains("systemctl restart bluetooth"));
        assert!(!run_doctor(&p, Platform::Windows)
            .iter()
            .any(|c| c.name == "daemon"));
    }

    #[test]
    fn ordering_adapter_permission_daemon_features() {
        let r = run_doctor(&good(), Platform::Linux);
        let names: Vec<&str> = r.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            &names[..4],
            ["adapter", "permission", "daemon", "feature:Scan"]
        );
        assert_eq!(r.len(), 3 + ALL_FEATURES.len());
    }

    #[test]
    fn feature_table_reflects_support() {
        let r = run_doctor(&good(), Platform::MacOs);
        assert_eq!(get(&r, "feature:Scan").status, Status::Ok);
        assert_eq!(get(&r, "feature:RawL2cap").status, Status::Warn);
    }

    #[test]
    fn exit_code_only_on_fail() {
        assert_eq!(print_report(&run_doctor(&good(), Platform::MacOs)), 0);
        let p = Probes {
            adapter_present: Some(false),
            ..good()
        };
        assert_eq!(print_report(&run_doctor(&p, Platform::MacOs)), 1);
    }
}
