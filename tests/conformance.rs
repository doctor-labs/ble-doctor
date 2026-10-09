//! doctor/1 conformance (docs/doctor-contract.md section 9): run `analyze --json` over a fixture.

use serde_json::Value;
use std::process::Command;

/// Static address over 700 s: mac_rotation fails at MEDIUM.
fn fixture() -> Vec<u8> {
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

fn run(args: &[&str]) -> (i32, String, Value) {
    // Unique per test (libtest names the thread after it): tests run in parallel and share the pid,
    // while repeated runs inside one test must see the same path (determinism check).
    let t = std::thread::current();
    let dir = std::env::temp_dir().join(format!(
        "bd-conf-{}-{}",
        std::process::id(),
        t.name().unwrap_or("main")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cap = dir.join("c.pcap");
    std::fs::write(&cap, fixture()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ble-doctor"))
        .arg("analyze")
        .arg(&cap)
        .args(args)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let v = serde_json::from_str(&text).unwrap_or(Value::Null);
    (out.status.code().unwrap(), text, v)
}

#[test]
fn analyze_json_is_doctor_1() {
    let sev = ["critical", "high", "medium", "low", "info"];
    let (code, _, v) = run(&["--json", "--fail-on", "medium"]);
    assert_eq!(code, 1);
    let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "data",
            "exit_code",
            "findings",
            "schema",
            "score",
            "tool",
            "version"
        ]
    );
    assert_eq!(v["schema"], "doctor/1");
    assert_eq!(v["tool"], "ble-doctor");
    assert_eq!(v["exit_code"], code);
    assert_eq!(v["score"]["model"], "ble/1");
    assert_eq!(
        (v["score"]["value"].as_i64(), v["score"]["label"].as_str()),
        (Some(85), Some("needs work"))
    );
    let f = &v["findings"][0];
    assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    for k in [
        "id",
        "fingerprint",
        "severity",
        "category",
        "message",
        "location",
        "remedy",
    ] {
        assert!(f.get(k).is_some(), "missing {k}");
    }
    assert!(sev.contains(&f["severity"].as_str().unwrap()));
    let fp = f["fingerprint"].as_str().unwrap();
    assert!(
        fp.len() == 16
            && fp
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(f["location"]["kind"], "file");
    assert!(f["remedy"].is_string());

    // default --fail-on high: a MEDIUM finding exits 0, and exit_code says so
    let (code0, _, v0) = run(&["--json"]);
    assert_eq!((code0, v0["exit_code"].as_i64()), (0, Some(0)));

    // determinism: identical apart from `data`
    let (_, _, mut a) = run(&["--json", "--fail-on", "medium"]);
    let (_, _, mut b) = run(&["--json", "--fail-on", "medium"]);
    a["data"] = Value::Null;
    b["data"] = Value::Null;
    assert_eq!(a, b);
}

#[test]
fn baseline_gate_exits_3_and_bad_input_exits_2() {
    let dir = std::env::temp_dir().join(format!("bd-conf-b-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let empty = dir.join("empty.json");
    std::fs::write(
        &empty,
        r#"{"schema":"doctor/1","score":{"value":100},"findings":[]}"#,
    )
    .unwrap();
    let (code, _, v) = run(&[
        "--json",
        "--fail-on",
        "medium",
        "--baseline",
        empty.to_str().unwrap(),
    ]);
    assert_eq!(code, 3);
    assert_eq!(v["exit_code"], 3);
    assert_eq!(v["findings"][0]["baseline_state"], "new");
    assert_eq!(v["baseline"]["new"], 1);
    // the saved envelope is a valid baseline for itself: nothing new -> 0
    let (_, text, _) = run(&["--json", "--fail-on", "medium"]);
    let own = dir.join("own.json");
    std::fs::write(&own, text).unwrap();
    let (code, _, v) = run(&[
        "--json",
        "--fail-on",
        "medium",
        "--baseline",
        own.to_str().unwrap(),
    ]);
    assert_eq!(
        (code, v["findings"][0]["baseline_state"].as_str()),
        (0, Some("unchanged"))
    );
    // unreadable baseline / missing capture are errors: exit 2
    let (code, _, _) = run(&["--json", "--baseline", dir.join("nope").to_str().unwrap()]);
    assert_eq!(code, 2);
    let out = Command::new(env!("CARGO_BIN_EXE_ble-doctor"))
        .args(["analyze", "/nonexistent/x.pcap", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// Issue #65: a btsnoop with a legacy Just Works exchange -> data.smp plus smp_* findings.
#[test]
fn analyze_extracts_smp_pairing() {
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
    let dir = std::env::temp_dir().join(format!("bd-conf-smp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.btsnoop");
    std::fs::write(&path, cap).unwrap();
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_ble-doctor"))
            .arg("analyze")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };
    let out = run(&["--json"]);
    assert_eq!(out.status.code(), Some(1)); // legacy pairing is HIGH
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["data"]["smp"]["pairing"]["method"], "just_works");
    let ids: Vec<_> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"smp_legacy_pairing") && ids.contains(&"smp_just_works"));
    assert!(!ids.contains(&"smp_key_size"));
    let human = String::from_utf8(run(&[]).stdout).unwrap();
    assert!(human.contains("smp: pairing method just_works, legacy pairing"));
}
