use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn make_exec_dummy(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
    let mut perms = fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&p, perms).unwrap();
    p
}

fn run_check_with(envs: &[(&str, &str)], extra_path: Option<&Path>) -> std::process::Output {
    let mut cmd = Command::new("bash");
    cmd.arg(script("scripts/check-vhci-prereqs.sh"));
    cmd.current_dir(repo_root());
    if let Some(p) = extra_path {
        let old = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{}", p.display(), old));
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("run check-vhci-prereqs.sh")
}

#[test]
fn prereq_check_fails_on_non_linux_with_clear_message() {
    let tmp = tempfile_dir();
    let bindir = tmp.join("bin");
    fs::create_dir_all(&bindir).unwrap();
    make_exec_dummy(
        &bindir,
        "uname",
        r#"if [ "${1:-}" = "-s" ]; then echo Darwin; else /usr/bin/uname "$@"; fi"#,
    );
    let out = run_check_with(&[], Some(&bindir));
    assert!(!out.status.success(), "expected failure on non-Linux");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("requires Linux") || stderr.contains("Refusing to start"),
        "stderr should explain refusal clearly, got: {stderr}"
    );
}

#[test]
fn prereq_check_passes_when_all_requirements_satisfied_via_overrides() {
    let tmp = tempfile_dir();
    let bindir = tmp.join("bin");
    fs::create_dir_all(&bindir).unwrap();
    make_exec_dummy(
        &bindir,
        "uname",
        r#"if [ "${1:-}" = "-s" ]; then echo Linux; elif [ "${1:-}" = "-r" ]; then echo 6.1.0-test; else /usr/bin/uname "$@"; fi"#,
    );
    let usb = tmp.join("dev-bus-usb");
    let sysbt = tmp.join("sys-bluetooth");
    fs::create_dir_all(&usb).unwrap();
    fs::create_dir_all(sysbt.join("hci0")).unwrap();

    let out = run_check_with(
        &[
            ("BLE_HW_CONFIG_HAS_VHCI", "yes"),
            ("BLE_HW_MODINFO_RESULT", "ok"),
            ("BLE_HW_MODPROBE_RESULT", "ok"),
            ("BLE_HW_DEV_VHCI_PATH", "/dev/null"),
            ("BLE_HW_USB_BUS_PATH", usb.to_str().unwrap()),
            ("BLE_HW_SYS_BLUETOOTH_PATH", sysbt.to_str().unwrap()),
        ],
        Some(&bindir),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected success, status={:?}\nstdout={stdout}\nstderr={stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("Live BLE hardware prerequisites satisfied")
            || stdout.contains("prerequisites satisfied"),
        "stdout={stdout}\nstderr={stderr}"
    );
}

#[test]
fn prereq_check_fails_when_vhci_kernel_support_missing() {
    let tmp = tempfile_dir();
    let bindir = tmp.join("bin");
    fs::create_dir_all(&bindir).unwrap();
    make_exec_dummy(
        &bindir,
        "uname",
        r#"if [ "${1:-}" = "-s" ]; then echo Linux; elif [ "${1:-}" = "-r" ]; then echo 6.1.0-test; else /usr/bin/uname "$@"; fi"#,
    );
    let out = run_check_with(
        &[
            ("BLE_HW_CONFIG_HAS_VHCI", "no"),
            ("BLE_HW_MODINFO_RESULT", "fail"),
        ],
        Some(&bindir),
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("CONFIG_BT_HCIVHCI") || stderr.contains("hci_vhci"),
        "stderr={stderr}"
    );
}

#[test]
fn prereq_check_fails_when_usb_bus_missing() {
    let tmp = tempfile_dir();
    let bindir = tmp.join("bin");
    fs::create_dir_all(&bindir).unwrap();
    make_exec_dummy(
        &bindir,
        "uname",
        r#"if [ "${1:-}" = "-s" ]; then echo Linux; elif [ "${1:-}" = "-r" ]; then echo 6.1.0-test; else /usr/bin/uname "$@"; fi"#,
    );
    let sysbt = tmp.join("sys-bluetooth");
    fs::create_dir_all(sysbt.join("hci0")).unwrap();
    let out = run_check_with(
        &[
            ("BLE_HW_CONFIG_HAS_VHCI", "yes"),
            ("BLE_HW_MODINFO_RESULT", "ok"),
            ("BLE_HW_MODPROBE_RESULT", "ok"),
            ("BLE_HW_DEV_VHCI_PATH", "/dev/null"),
            ("BLE_HW_USB_BUS_PATH", tmp.join("no-usb").to_str().unwrap()),
            ("BLE_HW_SYS_BLUETOOTH_PATH", sysbt.to_str().unwrap()),
        ],
        Some(&bindir),
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("/dev/bus/usb") || stderr.contains("USB"),
        "stderr={stderr}"
    );
}

#[test]
fn prereq_check_fails_when_no_adapter_enumerated() {
    let tmp = tempfile_dir();
    let bindir = tmp.join("bin");
    fs::create_dir_all(&bindir).unwrap();
    make_exec_dummy(
        &bindir,
        "uname",
        r#"if [ "${1:-}" = "-s" ]; then echo Linux; elif [ "${1:-}" = "-r" ]; then echo 6.1.0-test; else /usr/bin/uname "$@"; fi"#,
    );
    let usb = tmp.join("dev-bus-usb");
    let sysbt = tmp.join("sys-bluetooth-empty");
    fs::create_dir_all(&usb).unwrap();
    fs::create_dir_all(&sysbt).unwrap();
    let out = run_check_with(
        &[
            ("BLE_HW_CONFIG_HAS_VHCI", "yes"),
            ("BLE_HW_MODINFO_RESULT", "ok"),
            ("BLE_HW_MODPROBE_RESULT", "ok"),
            ("BLE_HW_DEV_VHCI_PATH", "/dev/null"),
            ("BLE_HW_USB_BUS_PATH", usb.to_str().unwrap()),
            ("BLE_HW_SYS_BLUETOOTH_PATH", sysbt.to_str().unwrap()),
        ],
        Some(&bindir),
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("adapter") || stderr.contains("hci"),
        "stderr={stderr}"
    );
}

fn tempfile_dir() -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "ble-doctor-live-prereq-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}
