//! MCP tools. Exposes ONLY `scan` and `analyze`; the stdio loop is doctor-kit's (`BleDoctor::mcp_tools`).
//!
//! Each tool re-invokes this binary with the matching subcommand plus `--json`, so an agent reads
//! exactly the report a person would. Dangerous subcommands (probe-writes, read-values, dfu,
//! recon, ctf, raw-radio flags) are not in `TOOLS` and `argv_for` never builds them: no path exists.

use doctor_kit::mcp::{exec_self_fmt, ExecOpts};
use doctor_kit::McpTool;
use serde_json::{json, Value};

/// The complete, closed tool whitelist.
pub const TOOLS: [&str; 2] = ["scan", "analyze"];

/// Reject anything that could be parsed as a CLI flag.
fn sanitize<'a>(name: &str, v: &'a str) -> Result<&'a str, String> {
    if v.starts_with('-') {
        Err(format!("{name} must be a value, not an option"))
    } else {
        Ok(v)
    }
}

/// Build the CLI argv for a whitelisted tool; the only place subcommands are chosen.
/// `baseline`, `fail_on`, `sarif`, and `as_address` pass straight through to the CLI flags of the same name.
/// Excluded over MCP: `--tui`, `--mtu`, `--timeout`, `--adapter` (interactive or raw-radio).
pub fn argv_for(tool: &str, args: &Value) -> Result<Vec<String>, String> {
    let get = |k: &str| args.get(k).and_then(Value::as_str);
    let mut a = match tool {
        "scan" => {
            let mut a = vec!["scan".to_string(), "--json".to_string()];
            if let Some(t) = get("target").filter(|t| !t.is_empty()) {
                a.push("--target".into());
                a.push(sanitize("target", t)?.to_string());
            }
            a
        }
        "analyze" => {
            let f = get("capture_file").ok_or("capture_file is required")?;
            vec![
                "analyze".into(),
                sanitize("capture_file", f)?.to_string(),
                "--json".into(),
            ]
        }
        other => return Err(format!("unknown tool: {other}")),
    };
    for k in ["baseline", "fail_on", "sarif", "as_address"] {
        if let Some(v) = get(k).filter(|v| !v.is_empty()) {
            a.push(format!("--{}", k.replace('_', "-")));
            a.push(sanitize(k, v)?.to_string());
        }
    }
    Ok(a)
}

/// Run this binary with `argv`; Ok(stdout) on exit 0/1/3, Err(message) otherwise. The message is the
/// child's stderr, or `exit <status>` when it said nothing, as ble has always reported it.
fn run_cli(argv: &[String]) -> Result<String, String> {
    const MARK: &str = "\u{1}";
    let opts = ExecOpts {
        ok_codes: vec![0, 1, 3],
        timeout: None,
        max_bytes: usize::MAX / 2,
    };
    exec_self_fmt(argv, &opts, Some("\u{1}{code}\u{1}{stderr}")).map_err(|e| {
        match e.strip_prefix(MARK).and_then(|r| r.split_once(MARK)) {
            Some((code, "")) => format!("exit exit status: {code}"),
            Some((_, stderr)) => stderr.to_string(),
            None => e,
        }
    })
}

/// The two tools, with ble's schemas. Errors are `{"error": <message>}` JSON text.
pub fn tools() -> Vec<McpTool> {
    let flags = json!({
        "baseline": {"type": "string", "description": "Saved doctor/1 --json envelope to diff against"},
        "fail_on": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "sarif": {"type": "string", "description": "Write SARIF 2.1.0 to this file"}
    });
    let tool = |name: &'static str, description: &str, own: Value, required: Option<&str>| {
        let mut props = own;
        props
            .as_object_mut()
            .unwrap()
            .extend(flags.as_object().unwrap().clone());
        let mut schema = json!({"type": "object", "properties": props});
        if let Some(r) = required {
            schema["required"] = json!([r]);
        }
        McpTool {
            name: name.into(),
            description: description.into(),
            schema,
            call: Box::new(move |args| {
                argv_for(name, args)
                    .and_then(|a| run_cli(&a))
                    .map_err(|e| json!({"error": e}).to_string())
            }),
        }
    };
    vec![
        tool(
            "scan",
            "Score a live BLE device by passive GATT enumeration (same doctor/1 JSON as `ble-doctor scan --json`).",
            json!({
                "target": {"type": "string"},
                "as_address": {"type": "string", "description": "Connect presenting this BLE address (LE Set Random Address; Linux only)"}
            }),
            None,
        ),
        tool(
            "analyze",
            "Score a BLE capture file (same doctor/1 JSON as `ble-doctor analyze --json`).",
            json!({"capture_file": {"type": "string"}}),
            Some("capture_file"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::{BleDoctor, Out, Subject};
    use std::collections::BTreeSet;

    fn call(req: Value) -> Value {
        let d = BleDoctor::new(Subject::None, None, Out::Quiet);
        doctor_kit::mcp::handle(&d, &req).unwrap()
    }

    #[test]
    fn tools_list_is_exactly_scan_and_analyze() {
        let r = call(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}));
        let names: BTreeSet<&str> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, BTreeSet::from(["scan", "analyze"]));
        assert_eq!(BTreeSet::from(TOOLS), names);
    }

    #[test]
    fn dangerous_ops_unreachable() {
        for t in [
            "probe-writes",
            "probe_writes",
            "read-values",
            "dfu",
            "recon",
            "ctf",
            "doctor",
            "mcp",
            "fix",
        ] {
            assert!(argv_for(t, &json!({})).is_err(), "{t} reachable");
            let r = call(json!({"id":1,"method":"tools/call","params":{"name":t,"arguments":{}}}));
            assert_eq!(r["result"]["isError"], true, "{t}");
        }
    }

    #[test]
    fn flag_like_values_rejected() {
        assert!(argv_for("scan", &json!({"target": "--as-address"})).is_err());
        assert!(argv_for("scan", &json!({"target": "-x"})).is_err());
        assert!(argv_for("analyze", &json!({"capture_file": "--help"})).is_err());
        assert!(argv_for("analyze", &json!({})).is_err());
        let r = call(
            json!({"id":1,"method":"tools/call","params":{"name":"scan","arguments":{"target":"-v"}}}),
        );
        assert_eq!(r["result"]["isError"], true);
        assert_eq!(
            r["result"]["content"][0]["text"],
            r#"{"error":"target must be a value, not an option"}"#
        );
    }

    #[test]
    fn argv_only_json_paths() {
        assert_eq!(
            argv_for("scan", &json!({"target": "AA:BB"})).unwrap(),
            ["scan", "--json", "--target", "AA:BB"]
        );
        assert_eq!(
            argv_for("analyze", &json!({"capture_file": "c.cap"})).unwrap(),
            ["analyze", "c.cap", "--json"]
        );
    }

    #[test]
    fn contract_flags_pass_through() {
        assert_eq!(
            argv_for("analyze", &json!({"capture_file": "c", "baseline": "b.json", "fail_on": "low", "sarif": "o.sarif", "as_address": "11:22:33:44:55:66"})).unwrap(),
            ["analyze", "c", "--json", "--baseline", "b.json", "--fail-on", "low", "--sarif", "o.sarif", "--as-address", "11:22:33:44:55:66"]
        );
        assert!(argv_for("scan", &json!({"baseline": "-x"})).is_err());
    }
}
