//! Human output of the findings commands (kit faces); machine output is pinned by tests/golden.rs.

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_ble-doctor"))
        .args(args)
        .env_remove("BLE_DOCTOR_TARGET")
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
fn bad_baseline_is_refused_before_any_output() {
    let (code, out, err) = run(&["analyze", "mac_rotation.pcap", "--baseline", "nope.json"]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(err.starts_with("baseline nope.json: "), "{err}");
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bd-kit-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn install_writes_ble_specific_agent_files() {
    let d = scratch("install");
    let (code, out, err) = run(&["install", "--dir", d.to_str().unwrap()]);
    assert_eq!((code, err.as_str()), (0, ""), "{out}");
    let skill = std::fs::read_to_string(d.join(".claude/skills/ble-doctor/SKILL.md")).unwrap();
    assert!(skill.contains("analyze <capture"), "{skill}");
    assert!(skill.contains("Never run `probe-writes`"), "{skill}");
    assert!(
        !skill.contains("scan --scope changed"),
        "kit default text leaked: {skill}"
    );
    let agents = std::fs::read_to_string(d.join("AGENTS.md")).unwrap();
    assert!(agents.contains("--allow-dangerous"), "{agents}");
}

#[test]
fn ci_install_analyzes_captures_and_installs_dbus() {
    let (code, out, _) = run(&["ci", "install", "--print"]);
    assert_eq!(code, 0);
    assert!(out.contains("libdbus-1-dev"), "{out}");
    assert!(out.contains("ble-doctor analyze"), "{out}");
    assert!(
        !out.contains("scan . --scope"),
        "kit default scan line leaked: {out}"
    );
    let d = scratch("ci");
    let (code, ..) = run(&["ci", "install", "--dir", d.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(d.join(".github/workflows/ble-doctor.yml").is_file());
}

#[test]
fn fix_builds_a_prompt_from_a_saved_report() {
    let d = scratch("fix");
    let (_, json, _) = run(&["analyze", "mac_rotation.pcap", "--json"]);
    let report = d.join("report.json");
    std::fs::write(&report, json).unwrap();
    let (code, out, err) = run(&["fix", "--from", report.to_str().unwrap()]);
    assert_eq!((code, err.as_str()), (0, ""));
    assert!(out.contains("mac_rotation"), "{out}");
    // Without --from and without a target there is nothing to scan: a clean error, exit 2.
    let (code, out, err) = run(&["fix"]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(err.contains("nothing to scan"), "{err}");
}
