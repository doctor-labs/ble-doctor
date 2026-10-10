//! Owner decision 6: only protocol/contract fixes may change machine-visible behavior; everything
//! else stays exactly as ble-doctor 0.2.0 had it. One golden per reverted or kept case (the files in
//! tests/golden/d6_*); tests/golden.rs stays as B0 wrote it.
//! Regenerate with `UPDATE_GOLDENS=1 cargo test --test golden_d6`.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_ble-doctor");
const PCAP: &str = "mac_rotation.pcap";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn mask(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace(env!("CARGO_PKG_VERSION"), "@VERSION@")
}

fn golden(name: &str, actual: &str) {
    let path = root().join("golden").join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(
        want, actual,
        "golden {name} differs (UPDATE_GOLDENS=1 to regenerate)"
    );
}

fn cli(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(BIN)
        .args(args)
        .current_dir(root().join("fixtures"))
        .output()
        .unwrap();
    (o.status.code().unwrap(), mask(&o.stdout), mask(&o.stderr))
}

fn snap(name: &str, args: &[&str]) -> i32 {
    let (code, out, err) = cli(args);
    golden(
        name,
        &format!("exit: {code}\n--- stdout ---\n{out}--- stderr ---\n{err}"),
    );
    code
}

/// Reverted: a baseline must be a doctor/1 object; the kit's bare-array dialect is refused, bare.
#[test]
fn baseline_bare_array_is_refused() {
    let code = snap(
        "d6_baseline_bare_array.txt",
        &[
            "analyze",
            PCAP,
            "--json",
            "--baseline",
            "baseline_array.json",
        ],
    );
    assert_eq!(code, 2);
}

/// Reverted: a baseline finding with no fingerprint is skipped (not an error), so the current
/// finding is NEW and gates with exit 3.
#[test]
fn baseline_entry_without_fingerprint_is_skipped() {
    let code = snap(
        "d6_baseline_no_fingerprint.txt",
        &[
            "analyze",
            PCAP,
            "--json",
            "--fail-on",
            "medium",
            "--baseline",
            "baseline_nofp.json",
        ],
    );
    assert_eq!(code, 3);
}

/// Reverted: a baseline error prints bare (no `error: ` prefix), exit 2, nothing on stdout.
#[test]
fn preflight_error_text_is_bare() {
    let code = snap(
        "d6_preflight_missing_baseline.txt",
        &["analyze", PCAP, "--json", "--baseline", "nope.json"],
    );
    assert_eq!(code, 2);
}

/// Reverted print order: a failed `--sarif` write is `sarif: <path>: <e>`, exit 2 (the contract's
/// exit code for an error, which was already ble's), and NOTHING on stdout; the kit would print the
/// report first.
#[test]
fn sarif_write_failure_prints_nothing() {
    let code = snap(
        "d6_sarif_write_failure.txt",
        &[
            "analyze",
            PCAP,
            "--json",
            "--sarif",
            "no-such-dir/out.sarif",
        ],
    );
    assert_eq!(code, 2);
}

/// Reverted: `--sarif` naming the baseline file is not refused (0.2.0 wrote the SARIF over it).
/// Runs on a scratch copy so the fixture stays intact.
#[test]
fn sarif_over_baseline_is_not_refused() {
    let d = std::env::temp_dir().join(format!("bd-d6-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let base = d.join("base.json");
    std::fs::copy(root().join("fixtures/baseline_empty.json"), &base).unwrap();
    let b = base.to_str().unwrap();
    let (code, _, err) = cli(&["analyze", PCAP, "--json", "--baseline", b, "--sarif", b]);
    assert_eq!((code, err.as_str()), (0, "baseline: score delta -15\n  NEW      Medium mac_rotation: MAC address is static across all 3 captured advertisement frames over 700s - trackable.\n"));
    assert!(std::fs::read_to_string(&base).unwrap().contains("\"runs\""));
}

/// MCP over stdio. Kept (protocol fixes, decision 6): `ping` answers `{}`, and a request that is not
/// an object, has a bad `id` or no `method` gets JSON-RPC -32600 (0.2.0 stayed silent, echoed the
/// bad id or said "method not found"). Unchanged: the unknown-tool text `{"error":"unknown tool: dfu"}`.
#[test]
fn mcp_protocol_fixes_and_unknown_tool() {
    use std::io::Write;
    use std::process::Stdio;
    let lines = [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dfu","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fix","arguments":{}}}"#,
        "[]",
        "123",
        r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":9}"#,
    ];
    let mut child = Command::new(BIN)
        .arg("mcp")
        .current_dir(root().join("fixtures"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(lines.join("\n").as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    golden("d6_mcp_protocol.jsonl", &mask(&out.stdout));
}
