//! MCP server (hand-rolled stdio JSON-RPC). Exposes ONLY `scan` and `analyze`.
//!
//! Each tool re-invokes this binary with the matching subcommand plus `--json`, so an agent reads
//! exactly the report a person would. Dangerous subcommands (probe-writes, read-values, dfu,
//! recon, ctf, raw-radio flags) are not in `TOOLS` and `argv_for` never builds them: no path exists.

use serde_json::{json, Value};
use std::io::{BufRead, Write};

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
pub fn argv_for(tool: &str, args: &Value) -> Result<Vec<String>, String> {
    let get = |k: &str| args.get(k).and_then(Value::as_str);
    match tool {
        "scan" => {
            let mut a = vec!["scan".to_string(), "--json".to_string()];
            if let Some(t) = get("target").filter(|t| !t.is_empty()) {
                a.push("--target".into());
                a.push(sanitize("target", t)?.to_string());
            }
            Ok(a)
        }
        "analyze" => {
            let f = get("capture_file").ok_or("capture_file is required")?;
            Ok(vec![
                "analyze".into(),
                sanitize("capture_file", f)?.to_string(),
                "--json".into(),
            ])
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

fn tool_list() -> Value {
    json!([
        {"name": "scan",
         "description": "Score a live BLE device by passive GATT enumeration (same JSON as `ble-doctor scan --json`).",
         "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}}},
        {"name": "analyze",
         "description": "Score a BLE capture file (same JSON as `ble-doctor analyze --json`).",
         "inputSchema": {"type": "object", "properties": {"capture_file": {"type": "string"}},
                         "required": ["capture_file"]}}
    ])
}

/// Run this binary with `argv`; Ok(stdout) on exit 0, Err(message) otherwise.
fn run_cli(argv: &[String]) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let out = std::process::Command::new(exe)
        .args(argv)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if msg.is_empty() {
            format!("exit {}", out.status)
        } else {
            msg
        })
    }
}

/// Handle one JSON-RPC message. Returns None for notifications.
pub fn handle(msg: &Value, run: &dyn Fn(&[String]) -> Result<String, String>) -> Option<Value> {
    let id = msg.get("id")?.clone();
    let reply = |r: Result<Value, (i64, String)>| match r {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, m)) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}})
        }
    };
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    Some(reply(match msg.get("method").and_then(Value::as_str) {
        Some("initialize") => Ok(json!({
            "protocolVersion": params.get("protocolVersion").and_then(Value::as_str).unwrap_or("2024-11-05"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "ble-doctor", "version": env!("CARGO_PKG_VERSION")}
        })),
        Some("ping") => Ok(json!({})),
        Some("tools/list") => Ok(json!({"tools": tool_list()})),
        Some("tools/call") => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let res = argv_for(name, &args).and_then(|a| run(&a));
            let (text, is_error) = match res {
                Ok(t) => (t, false),
                Err(e) => (json!({"error": e}).to_string(), true),
            };
            Ok(json!({"content": [{"type": "text", "text": text}], "isError": is_error}))
        }
        _ => Err((-32601, "method not found".into())),
    }))
}

/// Serve MCP over stdio (newline-delimited JSON-RPC) until stdin closes.
pub fn serve() {
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(m) => handle(&m, &run_cli),
            Err(_) => Some(json!({"jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": "parse error"}})),
        };
        if let Some(r) = resp {
            let _ = writeln!(out, "{r}");
            let _ = out.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn never(_: &[String]) -> Result<String, String> {
        panic!("runner must not be called")
    }

    #[test]
    fn tools_list_is_exactly_scan_and_analyze() {
        let r = handle(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            &never,
        )
        .unwrap();
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
        ] {
            assert!(argv_for(t, &json!({})).is_err(), "{t} reachable");
            let r = handle(
                &json!({"id":1,"method":"tools/call","params":{"name":t,"arguments":{}}}),
                &never,
            )
            .unwrap();
            assert_eq!(r["result"]["isError"], true);
        }
    }

    #[test]
    fn flag_like_values_rejected() {
        assert!(argv_for("scan", &json!({"target": "--as-address"})).is_err());
        assert!(argv_for("scan", &json!({"target": "-x"})).is_err());
        assert!(argv_for("analyze", &json!({"capture_file": "--help"})).is_err());
        assert!(argv_for("analyze", &json!({})).is_err());
        let r = handle(
            &json!({"id":1,"method":"tools/call","params":{"name":"scan","arguments":{"target":"-v"}}}),
            &never,
        )
        .unwrap();
        assert_eq!(r["result"]["isError"], true);
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
    fn call_routes_through_runner_and_notifications_get_no_reply() {
        let run = |a: &[String]| Ok(format!("ran {}", a[0]));
        let r = handle(
            &json!({"id":2,"method":"tools/call","params":{"name":"analyze","arguments":{"capture_file":"c"}}}),
            &run,
        )
        .unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "ran analyze");
        assert!(handle(&json!({"method":"notifications/initialized"}), &never).is_none());
    }
}
