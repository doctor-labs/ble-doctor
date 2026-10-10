//! ble-doctor on doctor-kit: one `Doctor` for the findings subjects (a capture file, a live device).
//! The checks stay pure functions returning `CheckResult`; [`collected`] maps their results onto kit
//! findings, byte for byte what `report::to_envelope` builds. The one async-to-sync bridge of the
//! findings path is [`block`]; everything around the radio is generic over `Central`/`GattClient`.

use crate::checks::CheckResult;
use crate::error::BleError;
use crate::gatt::GattInfo;
use crate::radio::{select_target_device, Central, DiscoveredDevice, GattClient};
use crate::report::{coverage_gaps, finding, product_score, sanitize};
use doctor_core::{Envelope, Location, LocationKind, Score};
use doctor_kit::baseline::BaselineError;
use doctor_kit::{Check, Collected, Ctx, Doctor, Node, ScanFailure, TargetKind};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// What a run looks at. The kit walks no directory for it (`TargetKind::Detached`).
pub enum Subject {
    /// Nothing chosen (`fix` without `--from`).
    None,
    /// One btsnoop/pcap capture.
    Capture(PathBuf),
    /// A live device: scan for `target` (address, id or name), connect, enumerate GATT.
    Live { target: String, timeout: u64 },
}

/// Where the human chatter (device list, summaries) goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Out {
    /// A person reads stdout: chatter on stdout, then the face.
    Human,
    /// stdout is reserved for the envelope (`--json`, `--score`): chatter on stderr.
    Machine,
    /// A full-screen UI or a shell owns the terminal: no chatter.
    Quiet,
}

/// Run a future from the synchronous kit pipeline. `main` is `#[tokio::main]` (multi-thread), so
/// blocking the current worker is allowed; this is the only bridge the findings path needs.
pub fn block<F: Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

/// One line per device seen: stdout for people, stderr when stdout carries the envelope.
pub fn print_devices(devs: &[DiscoveredDevice], out: Out) {
    for d in devs {
        let line = format!(
            "{}  addr={} name={} adv={} rssi={}",
            sanitize(&d.id),
            d.address.as_deref().unwrap_or("-"),
            sanitize(d.name.as_deref().unwrap_or("-")),
            sanitize(d.adv_local_name.as_deref().unwrap_or("-")),
            d.rssi.map_or("-".into(), |r| r.to_string())
        );
        match out {
            Out::Human => println!("{line}"),
            Out::Machine => eprintln!("{line}"),
            Out::Quiet => {}
        }
    }
}

fn failure(stderr: String) -> ScanFailure {
    ScanFailure {
        exit: 2,
        stderr,
        envelope: None,
    }
}

/// Scan, pick `target`, connect, read the GATT tree. The errors are the ones `scan` has always
/// printed (`scan: ..`, `gatt: ..`, each with its remediation where there is one).
pub async fn enumerate<C, G, F>(
    central: &C,
    connect: impl FnOnce(DiscoveredDevice) -> F,
    target: &str,
    dur: Duration,
    out: Out,
) -> Result<GattInfo, ScanFailure>
where
    C: Central,
    G: GattClient,
    F: Future<Output = Result<G, BleError>>,
{
    let with_fix =
        |what: &str, e: BleError| failure(format!("{what}: {e}\n  fix: {}\n", e.remediation()));
    let devs = central.scan(dur).await.map_err(|e| with_fix("scan", e))?;
    print_devices(&devs, out);
    let d = select_target_device(&devs, target).map_err(|e| failure(format!("scan: {e}\n")))?;
    if out == Out::Human {
        println!("selected: {}", sanitize(&d.id));
    }
    let name = d.adv_local_name.clone().or_else(|| d.name.clone());
    let id = d.id.clone();
    let client = connect(d.clone()).await.map_err(|e| with_fix("gatt", e))?;
    let services = client.services().await.map_err(|e| with_fix("gatt", e))?;
    Ok(crate::gatt::extract_gatt_fields(
        &services,
        &id,
        name.as_deref(),
    ))
}

/// The services of a live device as a shell tree: each service lists its writable and
/// subscribable characteristics (the ones the checks look at). Strings come off the air.
pub fn gatt_node(g: &GattInfo) -> Node {
    let mut root = Node::new(
        "services",
        "device",
        sanitize(g.target_name.as_deref().unwrap_or(&g.target)),
    )
    .meta("target", sanitize(&g.target))
    .meta("pairing_method", sanitize(&g.pairing_method))
    .meta("services", g.service_uuids.len());
    for svc in &g.service_uuids {
        let mut n = Node::new(svc, "service", "");
        for w in g.writable_chars.iter().filter(|w| &w.service_uuid == svc) {
            n = n.child(
                Node::new(&w.uuid, "characteristic", sanitize(&w.properties.join(",")))
                    .meta("requires_bonding", w.requires_bonding)
                    .meta("bonding_basis", sanitize(&w.bonding_basis))
                    .meta(
                        "description",
                        sanitize(w.description.as_deref().unwrap_or("")),
                    ),
            );
        }
        for c in g
            .subscribe_chars
            .iter()
            .filter(|c| &c.service_uuid == svc)
            .filter(|c| !g.writable_chars.iter().any(|w| w.uuid == c.uuid))
        {
            n = n.child(
                Node::new(&c.uuid, "characteristic", sanitize(&c.properties.join(",")))
                    .meta("cccd", c.cccd.map_or("unknown".into(), |b| b.to_string())),
            );
        }
        n.summary = format!("{} characteristics", n.children.len());
        root = root.child(n);
    }
    root
}

/// The four live checks over an enumerated device, as findings. The fingerprint identity is `target`
/// exactly as given.
pub fn live_collected(g: &GattInfo, target: &str) -> Collected {
    let checks = [
        crate::checks::check_unauthenticated_writes(g),
        crate::checks::check_dfu_entry_point(g),
        crate::checks::check_dfu_signing_enforced(g),
        crate::checks::check_dfu_surface_absent(g),
    ];
    let loc = Location::new(LocationKind::Device, target);
    collected(&checks, &loc, target, json!({}))
}

pub struct BleDoctor {
    pub subject: Subject,
    /// `--adapter`, for the commands that talk to a local adapter.
    pub adapter: Option<String>,
    pub out: Out,
    /// The live device's GATT tree, for the shell and explorer.
    gatt: Mutex<Option<GattInfo>>,
    /// The one gathered result: `shell` and `explore` re-scan, a radio must not be hit twice.
    cache: Mutex<Option<Result<Collected, ScanFailure>>>,
}

impl BleDoctor {
    pub fn new(subject: Subject, adapter: Option<String>, out: Out) -> Self {
        BleDoctor {
            subject,
            adapter,
            out,
            gatt: Mutex::new(None),
            cache: Mutex::new(None),
        }
    }

    fn gather(&self) -> Result<Collected, ScanFailure> {
        match &self.subject {
            Subject::None => Err(ScanFailure::new(
                "nothing to scan: pass `--from <report.json>`, or a subject on the command",
            )),
            Subject::Capture(path) => self.gather_capture(path),
            Subject::Live { target, timeout } => self.gather_live(target, *timeout),
        }
    }

    fn gather_live(&self, target: &str, timeout: u64) -> Result<Collected, ScanFailure> {
        use crate::radio::{connect_client, BtleplugCentral};
        let dur = Duration::from_secs(timeout);
        let adapter = self.adapter.as_deref();
        let g = block(enumerate(
            &BtleplugCentral,
            |d| async move { connect_client(adapter, &d, dur).await },
            target,
            dur,
            self.out,
        ))?;
        if self.out == Out::Human {
            println!(
                "gatt: {} services, {} writable, {} subscribable",
                g.service_uuids.len(),
                g.writable_chars.len(),
                g.subscribe_chars.len()
            );
            for w in &g.writable_chars {
                println!(
                    "  write {} requires_bonding={} ({})",
                    sanitize(&w.uuid),
                    w.requires_bonding,
                    sanitize(&w.bonding_basis)
                );
            }
            for s in &g.subscribe_chars {
                println!("  notify {} cccd={:?}", sanitize(&s.uuid), s.cccd);
            }
        }
        let c = live_collected(&g, target);
        *self.gatt.lock().unwrap() = Some(g);
        Ok(c)
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
        if self.out == Out::Human {
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
    /// `message` is raw here, as ble has always written it (see [`BleDoctor::collect`]).
    fn render_json(&self, env: &Envelope) -> String {
        let mut env = env.clone();
        let cache = self.cache.lock().unwrap();
        for f in &mut env.findings {
            if let Some(raw) = cache
                .iter()
                .flatten()
                .flat_map(|c| &c.findings)
                .find(|r| r.fingerprint == f.fingerprint)
            {
                f.message.clone_from(&raw.message);
            }
        }
        serde_json::to_string_pretty(&env.to_value()).expect("report serializes") + "\n"
    }

    /// ble's SARIF (rules with `security-severity`, check order, no trailing newline).
    fn render_sarif(&self, env: &Envelope) -> String {
        let cache = self.cache.lock().unwrap();
        let failed: Vec<_> = cache.iter().flatten().flat_map(|c| &c.findings).collect();
        let at = failed
            .first()
            .filter(|f| f.location.kind == LocationKind::File)
            .map(|f| f.location.reference.as_str());
        let doc = crate::sarif::document(
            &env.score,
            failed.iter().map(|f| {
                (
                    f.id.as_str(),
                    f.severity,
                    f.message.as_str(),
                    f.fingerprint.clone(),
                )
            }),
            at,
        );
        serde_json::to_string_pretty(&doc).expect("sarif serializes")
    }

    /// Agent skill: what is safe to run (a capture, or a passive scan) and what is not.
    fn skill_body(&self) -> String {
        "# ble-doctor\n\n\
`ble-doctor` scores the security posture of a BLE device. Run it; do not guess.\n\n\
```sh\n\
ble-doctor analyze <capture.pcap|.btsnoop> --json   # a capture file: offline, always safe\n\
ble-doctor scan --target <addr|name> --json         # a live device: passive GATT enumeration, needs a radio\n\
ble-doctor fix --from report.json [<finding-id>]    # a prompt to hand to a coding agent\n\
ble-doctor why <finding-id>                         # what a rule means and how to verify it\n\
ble-doctor mcp                                      # `scan` and `analyze` as an MCP stdio server\n\
```\n\n\
`scan` needs `--target` (or `BLE_DOCTOR_TARGET`); without it, it only lists nearby devices.\n\n\
Never run `probe-writes`, `read-values`, `dfu`, `ctf` or `mitm`, and never pass `--allow-dangerous`: they\n\
write to or intercept a device. Use them only on hardware you own or are authorized to test, on the\n\
owner's explicit instruction.\n\n\
Envelope: `schema` is `doctor/1`; `findings[]` hold `id`, `severity`, `location`, `message`, `remedy`;\n\
`score.value` is 0-100 (`ble/1`). Exit code 0 = clean, 1 = findings at or above `--fail-on` (default\n\
high), 3 = new findings against `--baseline`, 2 = the tool failed. Fix at the source, then re-run.\n"
            .into()
    }
    /// ble-doctor builds with BlueZ's D-Bus headers on Linux.
    fn ci_setup_steps(&self) -> String {
        "- uses: dtolnay/rust-toolchain@stable\n\
- run: sudo apt-get update && sudo apt-get install -y libdbus-1-dev pkg-config\n\
- run: cargo install --locked ble-doctor"
            .into()
    }
    /// CI has no radio: it analyzes the captures committed under `captures/`.
    fn ci_workflow(&self) -> String {
        let steps: String = self
            .ci_setup_steps()
            .lines()
            .map(|l| format!("      {l}\n"))
            .collect();
        format!(
            "# Written by `ble-doctor ci install`. Analyzes the captures committed under captures/.
name: ble-doctor

on:
  pull_request:

permissions:
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
{steps}      - name: Analyze captures
        run: |
          shopt -s nullglob
          rc=0
          for f in captures/*.pcap captures/*.btsnoop captures/*.cap; do
            ble-doctor analyze \"$f\" --headless --fail-on high || rc=1
          done
          exit $rc
"
        )
    }

    /// The kit's findings tree, plus the device's services for a live subject.
    fn tree(&self, env: &Envelope, ctx: &Ctx) -> Node {
        let mut root = doctor_kit::session::default_tree(env, ctx);
        root.meta.retain(|_, v| !v.is_null());
        let subject = match &self.subject {
            Subject::Capture(p) => p.display().to_string(),
            Subject::Live { target, .. } => target.clone(),
            Subject::None => "-".into(),
        };
        root.meta.insert("target".into(), json!(sanitize(&subject)));
        if let Some(g) = self.gatt.lock().unwrap().as_ref() {
            root.children.push(gatt_node(g));
        }
        root
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

    /// The gathered findings, with `message` sanitized: the kit's faces and shell print it as is, and
    /// GATT strings come off the air. `--json` and SARIF still carry the raw text.
    fn collect(&self, _: &Ctx) -> Result<Collected, ScanFailure> {
        let mut c = self
            .cache
            .lock()
            .unwrap()
            .get_or_insert_with(|| self.gather())
            .clone()?;
        for f in &mut c.findings {
            f.message = sanitize(&f.message);
        }
        Ok(c)
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

    fn device(id: &str, addr: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            id: id.into(),
            address: Some(addr.into()),
            adv_local_name: Some("Fake".into()),
            ..Default::default()
        }
    }

    /// The live path without a radio: scan -> select -> connect -> GATT -> the four checks.
    #[tokio::test]
    async fn live_enumeration_over_the_fakes() {
        use crate::testkit::{FakeCentral, FakeCharacteristic, FakeClient, FakeGattTree};
        const SVC: &str = "0000aaa0-0000-1000-8000-00805f9b34fb";
        let tree = FakeGattTree::new().service(
            SVC,
            vec![FakeCharacteristic::new(
                "0000aaa1-0000-1000-8000-00805f9b34fb",
                SVC,
                &["write"],
            )],
        );
        let target = "AA:BB:CC:DD:EE:FF";
        let central = FakeCentral::new(vec![
            device("dev-1", target),
            device("dev-2", "11:22:33:44:55:66"),
        ]);
        let g = enumerate(
            &central,
            |_| async { Ok(FakeClient::new(tree.clone())) },
            target,
            Duration::from_secs(1),
            Out::Quiet,
        )
        .await
        .unwrap();
        assert_eq!(
            g.service_uuids,
            crate::gatt::extract_gatt_fields(&tree.to_services(), "dev-1", Some("Fake"))
                .service_uuids
        );
        let c = live_collected(&g, target);
        let ids: Vec<&str> = c.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["unauthenticated_writes"]);
        assert_eq!(c.findings[0].location.kind, LocationKind::Device);
        assert_eq!(c.findings[0].location.reference, target);
        assert_eq!(c.data["passed"].as_array().unwrap().len(), 3);
    }

    /// The shell tree of a live device: findings by category, then services and their characteristics.
    #[tokio::test]
    async fn shell_tree_lists_services_and_characteristics() {
        use crate::testkit::{FakeCentral, FakeCharacteristic, FakeClient, FakeGattTree};
        const SVC: &str = "0000aaa0-0000-1000-8000-00805f9b34fb";
        let tree = FakeGattTree::new().service(
            SVC,
            vec![
                FakeCharacteristic::new("0000aaa1-0000-1000-8000-00805f9b34fb", SVC, &["write"]),
                FakeCharacteristic::notify_without_cccd(
                    "0000aaa2-0000-1000-8000-00805f9b34fb",
                    SVC,
                ),
            ],
        );
        let g = enumerate(
            &FakeCentral::new(vec![device("dev", "AA:BB:CC:DD:EE:FF")]),
            |_| async { Ok(FakeClient::new(tree.clone())) },
            "AA:BB:CC:DD:EE:FF",
            Duration::from_secs(1),
            Out::Quiet,
        )
        .await
        .unwrap();
        let d = BleDoctor::new(
            Subject::Live {
                target: "AA:BB:CC:DD:EE:FF".into(),
                timeout: 1,
            },
            None,
            Out::Quiet,
        );
        *d.cache.lock().unwrap() = Some(Ok(live_collected(&g, "AA:BB:CC:DD:EE:FF")));
        *d.gatt.lock().unwrap() = Some(g);
        let ctx = Ctx::detached(Default::default(), Severity::High);
        let env = d.try_scan(&ctx).unwrap();
        let root = d.tree(&env, &ctx);
        let names: Vec<&str> = root.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["gatt", "services"]);
        let gatt = root.children.last().unwrap();
        assert_eq!(gatt.children[0].name, SVC);
        let chars: Vec<&str> = gatt.children[0]
            .children
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(chars.len(), 2, "{chars:?}");
        assert_eq!(root.meta["target"], "AA:BB:CC:DD:EE:FF");
    }

    /// The three live failures keep the text and the exit code `scan` has always had.
    #[tokio::test]
    async fn live_failures_print_as_before() {
        use crate::testkit::{FakeCentral, FakeClient};
        let one = |c: FakeCentral, connect_fails: bool| async move {
            enumerate(
                &c,
                |_| async move {
                    if connect_fails {
                        Err(BleError::ConnectTimeout)
                    } else {
                        Ok(FakeClient::default())
                    }
                },
                "AA:BB:CC:DD:EE:FF",
                Duration::from_secs(1),
                Out::Quiet,
            )
            .await
            .unwrap_err()
        };
        let f = one(FakeCentral::failing(BleError::PermissionDenied), false).await;
        let want = BleError::PermissionDenied;
        assert_eq!(
            (f.exit, f.stderr),
            (2, format!("scan: {want}\n  fix: {}\n", want.remediation()))
        );
        let f = one(FakeCentral::new(vec![]), false).await;
        assert_eq!(
            (f.exit, f.stderr),
            (2, format!("scan: {}\n", BleError::DeviceNotFound))
        );
        let f = one(
            FakeCentral::new(vec![device("d", "AA:BB:CC:DD:EE:FF")]),
            true,
        )
        .await;
        let want = BleError::ConnectTimeout;
        assert_eq!(
            (f.exit, f.stderr),
            (2, format!("gatt: {want}\n  fix: {}\n", want.remediation()))
        );
    }

    /// doctor/1 section 8: an attacker-controlled detail never reaches the human faces, while
    /// `--json` keeps the raw text it always had.
    #[test]
    fn esc_in_a_detail_stays_out_of_the_faces_but_not_the_json() {
        let evil = "evil\x1b[31mred\u{202e}rtl";
        let loc = Location::new(LocationKind::Device, "AA");
        let d = BleDoctor::new(Subject::None, None, Out::Quiet);
        let r = [CheckResult::new("x", Severity::Low, false, evil)];
        *d.cache.lock().unwrap() = Some(Ok(collected(&r, &loc, "AA", json!({}))));
        let env = d
            .try_scan(&Ctx::detached(Default::default(), Severity::High))
            .unwrap();
        for face in [
            doctor_kit::Face::Plain,
            doctor_kit::Face::Rich,
            doctor_kit::Face::Compact,
        ] {
            let mut theme = doctor_kit::Theme::default();
            theme.enabled = false;
            let t = doctor_kit::face::render(face, &env, &theme);
            assert!(
                !t.contains('\x1b') && !t.contains('\u{202e}'),
                "{face:?}: {t}"
            );
        }
        let v: Value = serde_json::from_str(&d.render_json(&env)).unwrap();
        assert_eq!(v["findings"][0]["message"], evil);
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
        let d = BleDoctor::new(Subject::None, None, Out::Quiet);
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
