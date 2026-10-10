//! Human output of the findings commands (kit faces); machine output is pinned by tests/golden.rs.

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_ble-doctor"))
        .args(args)
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
        .output()
        .unwrap();
    (
        o.status.code().unwrap(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn analyze_prints_the_preamble_then_a_face() {
    for face in ["plain", "rich", "compact"] {
        let (code, out, err) = run(&["analyze", "mac_rotation.pcap", "--face", face]);
        assert_eq!((code, err.as_str()), (0, ""), "{face}");
        assert!(
            out.starts_with("capture: pcap-le-ll (3 adv frames)\n"),
            "{out}"
        );
        assert!(
            out.contains("mac_rotation") && out.contains("85"),
            "{face}: {out}"
        );
        assert!(!out.contains('\x1b'), "piped output has no color: {out:?}");
    }
    let (code, out, _) = run(&["analyze", "smp_legacy.btsnoop", "--headless"]);
    assert_eq!(code, 1);
    assert!(out.contains("smp_legacy_pairing"), "{out}");
}

#[test]
fn score_and_json_keep_stdout_clean() {
    let (code, out, _) = run(&["analyze", "mac_rotation.pcap", "--score"]);
    assert_eq!((code, out.as_str()), (0, "85\n"));
    let (_, out, _) = run(&["analyze", "mac_rotation.pcap", "--json"]);
    assert!(
        out.starts_with("{\n"),
        "no preamble before the envelope: {out}"
    );
}

#[test]
fn bad_baseline_and_sarif_clash_are_refused_before_any_output() {
    let (code, out, err) = run(&["analyze", "mac_rotation.pcap", "--baseline", "nope.json"]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(err.starts_with("baseline nope.json: "), "{err}");
    let (code, out, err) = run(&[
        "analyze",
        "mac_rotation.pcap",
        "--baseline",
        "baseline_empty.json",
        "--sarif",
        "baseline_empty.json",
    ]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(err.contains("same file"), "{err}");
}
