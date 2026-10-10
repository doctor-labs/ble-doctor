//! Golden snapshots (migration step B0): today's exact machine-output bytes, pinned before any change.
//!
//! Covered: `analyze --json`/SARIF/exit codes on committed capture fixtures, the pure check-to-envelope
//! chain `scan` uses (no radio), `--help` of every command, `rules list --json`, the MCP stdio transcript.
//! NOT covered by design: human text output (it will change to kit faces).
//! Regenerate with `UPDATE_GOLDENS=1 cargo test --test golden` (rewrites tests/golden/* and tests/fixtures/*).
//! The crate version is masked as `@VERSION@` so a release bump does not touch the goldens.

use ble_doctor::{baseline, checks, gatt, report, sarif, testkit::*};
use doctor_core::{Location, LocationKind};
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Once;

const BIN: &str = env!("CARGO_BIN_EXE_ble-doctor");
const PCAP: &str = "mac_rotation.pcap";
const SMP: &str = "smp_legacy.btsnoop";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}
fn updating() -> bool {
    std::env::var_os("UPDATE_GOLDENS").is_some()
}

/// Static address over 700 s: mac_rotation fails at MEDIUM (same builder as tests/conformance.rs).
fn pcap_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xA1B2_C3D4u32.to_le_bytes());
    out.extend([2, 0, 4, 0]);
    out.extend([0u8; 8]);
    out.extend(65535u32.to_le_bytes());
    out.extend(251u32.to_le_bytes()); // LINKTYPE_BLUETOOTH_LE_LL
    for t in [0u32, 300, 700] {
        let mut p = 0x8E89_BED6u32.to_le_bytes().to_vec();
        let adv = [0x02, 0x01, 0x06];
        p.extend([0x40, 6 + adv.len() as u8]);
        p.extend([1, 0, 0, 0, 0, 0xC0]);
        p.extend(adv);
        p.extend([0, 0, 0]);
        out.extend(t.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend((p.len() as u32).to_le_bytes());
        out.extend((p.len() as u32).to_le_bytes());
        out.extend(p);
    }
    out
}

/// btsnoop with a legacy Just Works SMP exchange (HIGH finding).
fn btsnoop_bytes() -> Vec<u8> {
    let mut cap = b"btsnoop\0".to_vec();
    cap.extend(1u32.to_be_bytes());
    cap.extend(1002u32.to_be_bytes()); // H4
    for smp in [[1u8, 3, 0, 1, 16, 1, 1], [2, 3, 0, 1, 16, 1, 1]] {
        let mut pkt = vec![2, 0x40, 0x00, 11, 0, 7, 0, 6, 0];
        pkt.extend(smp);
        cap.extend((pkt.len() as u32).to_be_bytes());
        cap.extend((pkt.len() as u32).to_be_bytes());
        cap.extend([0u8; 16]);
        cap.extend(pkt);
    }
    cap
}

/// Write committed fixtures when regenerating (once per process, before any test reads them).
fn fixtures() -> PathBuf {
    static ONCE: Once = Once::new();
    let dir = root().join("fixtures");
    ONCE.call_once(|| {
        if updating() {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(PCAP), pcap_bytes()).unwrap();
            std::fs::write(dir.join(SMP), btsnoop_bytes()).unwrap();
            std::fs::write(dir.join("garbage.pcap"), b"not a capture").unwrap();
            std::fs::write(
                dir.join("baseline_empty.json"),
                r#"{"schema":"doctor/1","score":{"value":100},"findings":[]}"#,
            )
            .unwrap();
            std::fs::write(dir.join("baseline_bad.json"), "{not json").unwrap();
        }
    });
    dir
}

fn mask(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace(env!("CARGO_PKG_VERSION"), "@VERSION@")
}

/// Compare `actual` to tests/golden/<name> byte for byte (or rewrite it under UPDATE_GOLDENS=1).
fn golden(name: &str, actual: &str) {
    let path = root().join("golden").join(name);
    if updating() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (run UPDATE_GOLDENS=1 cargo test --test golden)",
            path.display()
        )
    });
    assert!(
        want == actual.as_bytes(),
        "golden {name} differs; if intended, regenerate with UPDATE_GOLDENS=1\n--- want\n{}\n--- got\n{actual}",
        String::from_utf8_lossy(&want)
    );
}

/// Run the binary inside tests/fixtures (relative paths keep output machine independent).
fn cli(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(BIN)
        .args(args)
        .current_dir(fixtures())
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

/// A fresh scratch dir per test (the test name is the dir name).
fn scratch() -> PathBuf {
    let n = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let d = std::env::temp_dir().join(format!("bd-golden-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn analyze_json_fail_on_matrix() {
    for (cap, tag) in [(PCAP, "pcap"), (SMP, "smp")] {
        for fo in ["info", "low", "medium", "high", "critical"] {
            snap(
                &format!("analyze_{tag}_fail_on_{fo}.txt"),
                &["analyze", cap, "--json", "--fail-on", fo],
            );
        }
    }
    // default --fail-on is high: MEDIUM exits 0, HIGH exits 1
    assert_eq!(
        snap("analyze_pcap_default.txt", &["analyze", PCAP, "--json"]),
        0
    );
    assert_eq!(
        snap("analyze_smp_default.txt", &["analyze", SMP, "--json"]),
        1
    );
}

#[test]
fn analyze_sarif_bytes() {
    let d = scratch();
    for (cap, tag) in [(PCAP, "pcap"), (SMP, "smp")] {
        let out = d.join(format!("{tag}.sarif"));
        let (code, ..) = cli(&["analyze", cap, "--json", "--sarif", out.to_str().unwrap()]);
        assert!(code <= 1);
        golden(
            &format!("analyze_{tag}.sarif"),
            &mask(&std::fs::read(&out).unwrap()),
        );
    }
}

#[test]
fn analyze_baseline_and_errors() {
    let d = scratch();
    // new finding vs empty baseline: 3 at/above fail-on, 0 below it
    assert_eq!(
        snap(
            "baseline_new_gates_3.txt",
            &[
                "analyze",
                PCAP,
                "--json",
                "--fail-on",
                "medium",
                "--baseline",
                "baseline_empty.json"
            ]
        ),
        3
    );
    assert_eq!(
        snap(
            "baseline_new_below_fail_on.txt",
            &[
                "analyze",
                PCAP,
                "--json",
                "--baseline",
                "baseline_empty.json"
            ]
        ),
        0
    );
    // an envelope is a valid baseline for itself: nothing new -> 0
    let (_, own, _) = cli(&["analyze", PCAP, "--json", "--fail-on", "medium"]);
    let own_path = d.join("own.json");
    std::fs::write(&own_path, &own).unwrap();
    let own_s = own_path.to_str().unwrap();
    assert_eq!(
        snap(
            "baseline_unchanged_0.txt",
            &[
                "analyze",
                PCAP,
                "--json",
                "--fail-on",
                "medium",
                "--baseline",
                own_s
            ]
        ),
        0
    );
    // a baseline from another capture: smp findings new, mac_rotation fixed
    assert_eq!(
        snap(
            "baseline_new_and_fixed.txt",
            &["analyze", SMP, "--json", "--baseline", own_s]
        ),
        3
    );
    // errors exit 2 with nothing on stdout
    for (n, args) in [
        (
            "err_missing_capture",
            vec!["analyze", "nope.pcap", "--json"],
        ),
        (
            "err_garbage_capture",
            vec!["analyze", "garbage.pcap", "--json"],
        ),
        (
            "err_missing_baseline",
            vec!["analyze", PCAP, "--json", "--baseline", "nope.json"],
        ),
        (
            "err_bad_baseline_json",
            vec!["analyze", PCAP, "--json", "--baseline", "baseline_bad.json"],
        ),
        (
            "err_bad_fail_on",
            vec!["analyze", PCAP, "--json", "--fail-on", "bogus"],
        ),
        ("err_scan_json_needs_target", vec!["scan", "--json"]),
        ("err_scan_mtu_needs_target", vec!["scan", "--mtu"]),
    ] {
        assert_eq!(snap(&format!("{n}.txt"), &args), 2, "{n}");
    }
}

#[test]
fn rules_list_json() {
    snap("rules_list_json.txt", &["rules", "list", "--json"]);
}

/// Root help plus every (nested) subcommand's help, walked from each `Commands:` block.
#[test]
fn help_texts() {
    fn walk(path: &[String], all: &mut String) {
        let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
        args.push("--help");
        let (code, out, _) = cli(&args);
        assert_eq!(code, 0);
        all.push_str(&format!("===== ble-doctor {} =====\n{out}", path.join(" ")));
        let subs = out
            .split("Commands:\n")
            .nth(1)
            .map(|s| {
                s.lines()
                    .take_while(|l| l.starts_with("  "))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for l in subs {
            let name = l.split_whitespace().next().unwrap();
            if name != "help" {
                walk(&[path, &[name.to_string()]].concat(), all);
            }
        }
    }
    let mut all = String::new();
    walk(&[], &mut all);
    golden("help.txt", &all);
}

#[test]
fn mcp_stdio_transcript() {
    let lines = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"analyze","arguments":{"capture_file":"mac_rotation.pcap","fail_on":"medium"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"analyze","arguments":{"capture_file":"nope.pcap"}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"dfu","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"scan","arguments":{"target":"--as-address"}}}"#,
        r#"{"jsonrpc":"2.0","id":8,"method":"nope/nope"}"#,
        "not json",
        "",
    ];
    let mut child = Command::new(BIN)
        .arg("mcp")
        .current_dir(fixtures())
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
    golden("mcp_transcript.jsonl", &mask(&out.stdout));
}

/// The pure chain `scan --target` runs after enumeration: GATT tree -> GattInfo -> 4 checks -> gate ->
/// envelope / SARIF. Mirrors `cli::emit` (no radio, no process).
fn scan_chain(tag: &str, tree: FakeGattTree) {
    let target = "AA:BB:CC:DD:EE:FF";
    let g = gatt::extract_gatt_fields(&tree.to_services(), target, Some("Fake"));
    let results = [
        checks::check_unauthenticated_writes(&g),
        checks::check_dfu_entry_point(&g),
        checks::check_dfu_signing_enforced(&g),
        checks::check_dfu_surface_absent(&g),
    ];
    let loc = Location::new(LocationKind::Device, target);
    let own = {
        let code = report::gate_exit(&results, checks::Severity::High, None);
        report::to_envelope(&results, &loc, target, None, code, json!({}))
    };
    let empty = json!({"schema":"doctor/1","score":{"value":100},"findings":[]});
    let mut out = String::new();
    for (label, fo, base) in [
        ("no baseline, fail-on high", "high", None),
        ("no baseline, fail-on info", "info", None),
        ("empty baseline, fail-on high", "high", Some(&empty)),
        ("self baseline, fail-on info", "info", Some(&own)),
    ] {
        let sev = checks::Severity::parse(fo).unwrap();
        let diff = base.map(|b| baseline::diff(&results, b, target));
        let code = report::gate_exit(
            &results,
            sev,
            diff.as_ref().map(|d| d.new_failures.as_slice()),
        );
        let env = report::to_envelope(&results, &loc, target, base, code, json!({}));
        out.push_str(&format!(
            "### {label}: exit {code}\n{}\n",
            report::to_json(&env)
        ));
    }
    let sarif_doc = sarif::to_sarif(&report::score(&results), &results, None, target);
    out.push_str(&format!(
        "### sarif\n{}\n",
        serde_json::to_string_pretty(&sarif_doc).unwrap()
    ));
    golden(&format!("scan_chain_{tag}.txt"), &mask(out.as_bytes()));
}

#[test]
fn scan_pure_chain() {
    const DFU: &str = "0000fe59-0000-1000-8000-00805f9b34fb";
    const SVC: &str = "0000aaa0-0000-1000-8000-00805f9b34fb";
    scan_chain(
        "insecure",
        FakeGattTree::new()
            .service(
                SVC,
                vec![
                    FakeCharacteristic::new(
                        "0000aaa1-0000-1000-8000-00805f9b34fb",
                        SVC,
                        &["write"],
                    ),
                    FakeCharacteristic::notify_without_cccd(
                        "0000aaa2-0000-1000-8000-00805f9b34fb",
                        SVC,
                    ),
                ],
            )
            .service(
                DFU,
                vec![FakeCharacteristic::new(
                    "8ec90001-f315-4f60-9fb8-838830daea50",
                    DFU,
                    &["write", "notify"],
                )],
            ),
    );
    scan_chain(
        "clean",
        FakeGattTree::new().service(
            SVC,
            vec![FakeCharacteristic::new(
                "0000aaa1-0000-1000-8000-00805f9b34fb",
                SVC,
                &["read"],
            )],
        ),
    );
}
