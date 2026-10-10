//! Command-line interface: doctor-kit's `run_with` owns the process, this module registers ble's own
//! commands next to the kit's. `scan` and `analyze` report through the kit; the other commands
//! (probes, MITM, CTF, fingerprint, sniffer ...) are plain functions over their arguments.

use crate::kit::{block, print_devices, BleDoctor, Out, Subject};
use crate::report::sanitize as san;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{Arg, ArgMatches, Args, FromArgMatches, Subcommand};
use doctor_core::Severity;
use doctor_kit::{
    finish as kit_finish, preflight, Ctx, Doctor, ExtCommand, Extensions, Face, Meta, OutputArgs,
};
use std::process::ExitCode;

const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// `--fail-on` as a `Severity`, which is what the kit's `OutputArgs::from_matches` reads.
fn severity() -> impl TypedValueParser<Value = Severity> {
    PossibleValuesParser::new(SEVERITIES).map(|s| Severity::parse(&s).expect("listed severity"))
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
    #[arg(long, env = "BLE_DOCTOR_TARGET")]
    target: Option<String>,
    /// Scan duration in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,
    /// Request exactly this ATT MTU from --target (a BLE address; Linux only)
    #[arg(long, requires = "target")]
    mtu: Option<u16>,
    /// Connect to --target presenting this BLE address (LE Set Random Address; Linux only)
    #[arg(long, requires = "target", conflicts_with = "mtu")]
    as_address: Option<String>,
    /// Emit the doctor/1 JSON envelope (needs --target)
    #[arg(long, requires = "target")]
    json: bool,
    /// Show the findings in an interactive terminal UI (needs --target)
    #[arg(long, requires = "target", conflicts_with = "json")]
    tui: bool,
    /// Write a SARIF 2.1.0 report to this file (needs --target)
    #[arg(long, requires = "target")]
    sarif: Option<std::path::PathBuf>,
    /// Diff findings against a saved doctor/1 `--json` report; exit 3 if NEW failures reach --fail-on
    #[arg(long, requires = "target")]
    baseline: Option<std::path::PathBuf>,
    /// Exit 1 (3 with --baseline, new findings only) when a finding is at or above this severity
    #[arg(long, default_value = "high", value_parser = severity())]
    fail_on: Severity,
}

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to a btsnoop/pcap capture
    capture: std::path::PathBuf,
    /// Emit the doctor/1 JSON envelope
    #[arg(long)]
    json: bool,
    /// Write a SARIF 2.1.0 report to this file
    #[arg(long)]
    sarif: Option<std::path::PathBuf>,
    /// Diff findings against a saved doctor/1 `--json` report; exit 3 if NEW failures reach --fail-on
    #[arg(long)]
    baseline: Option<std::path::PathBuf>,
    /// Exit 1 (3 with --baseline, new findings only) when a finding is at or above this severity
    #[arg(long, default_value = "high", value_parser = severity())]
    fail_on: Severity,
}

#[derive(Args, Debug)]
pub struct SniffArgs {
    /// Serial/USB sniffer port (e.g. /dev/ttyACM0)
    #[arg(long, conflicts_with = "from_file")]
    device: Option<String>,
    /// Saved Sniffle text dump to parse instead of live capture
    #[arg(long)]
    from_file: Option<std::path::PathBuf>,
    /// Emit JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct FingerprintArgs {
    /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
    #[arg(long, env = "BLE_DOCTOR_TARGET")]
    target: Option<String>,
    /// Scan/connect timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,
    /// Emit JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct ProbeWritesArgs {
    /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
    #[arg(long, env = "BLE_DOCTOR_TARGET")]
    target: Option<String>,
    /// Required: this writes to the device. Firmware/DFU characteristics are still
    /// refused regardless of this flag.
    #[arg(long)]
    allow_dangerous: bool,
    /// Scan/connect timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,
    /// Emit JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct ReadValuesArgs {
    /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
    #[arg(long, env = "BLE_DOCTOR_TARGET")]
    target: Option<String>,
    /// Scan/connect timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,
}

#[derive(Args, Debug)]
pub struct DfuArgs {
    /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
    #[arg(long, env = "BLE_DOCTOR_TARGET")]
    target: Option<String>,
    /// Required: this writes to the device.
    #[arg(long)]
    allow_dangerous: bool,
    /// Also probe the bond-sharing buttonless characteristic (8ec90004-...)
    #[arg(long)]
    bond_sharing: bool,
    /// Scan/connect timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,
    /// Emit JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct ReconArgs {
    /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
    #[arg(long, env = "BLE_DOCTOR_TARGET")]
    target: String,
    /// Scan/connect timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,
    /// Also run the external bluesploit cross-check (heuristic, INFO-only, never scored)
    #[arg(long)]
    bluesploit: bool,
    /// Emit JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct CtfArgs {
    #[command(subcommand)]
    action: CtfCmd,
}

#[derive(Args, Debug)]
pub struct HandoffArgs {
    /// A `scan --json` report file to turn into the bundle (no radio)
    #[arg(long)]
    report: std::path::PathBuf,
}

#[derive(Args, Debug)]
pub struct RulesArgs {
    #[command(subcommand)]
    action: RulesCmd,
}

#[derive(Args, Debug)]
pub struct WhyArgs {
    /// Rule / check id
    id: String,
    /// A `--json` report file to pull the matching finding from
    #[arg(long)]
    report: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct MitmArgs {
    /// The real target device to relay to (address / identifier / name)
    #[arg(long, env = "BLE_DOCTOR_TARGET")]
    target: String,
    /// Required: this actively intercepts GATT traffic between a victim
    /// and the real device (scope: own hardware or written authorization only).
    #[arg(long)]
    allow_dangerous: bool,
}

/// `ctf` subcommands: brute-write / read-N / write-then-read against a
/// characteristic, carried over from v1's `solve_macos.py` helper patterns.
/// Own-gear / CTF scope only; never wired into `mcp`.
#[derive(Subcommand, Debug)]
pub enum CtfCmd {
    /// Write 0x00..=0xff to --char one byte at a time, reading --read-char back
    /// after each write, until the read-back contains --contains.
    Brute {
        /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
        #[arg(long, env = "BLE_DOCTOR_TARGET")]
        target: String,
        /// Characteristic UUID to brute-write
        #[arg(long)]
        char_uuid: String,
        /// Characteristic UUID to read back after each write
        #[arg(long)]
        read_uuid: String,
        /// Stop once the read-back value contains this substring (ASCII)
        #[arg(long)]
        contains: String,
        /// Scan/connect timeout in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
    /// Read a characteristic `n` times in a row
    ReadN {
        /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
        #[arg(long, env = "BLE_DOCTOR_TARGET")]
        target: String,
        /// Characteristic UUID to read
        #[arg(long)]
        char_uuid: String,
        /// Number of reads
        #[arg(long, default_value_t = 1)]
        n: usize,
        /// Scan/connect timeout in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
    /// Write a value, then read a (possibly different) characteristic back
    WriteThenRead {
        /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
        #[arg(long, env = "BLE_DOCTOR_TARGET")]
        target: String,
        /// Characteristic UUID to write
        #[arg(long)]
        char_uuid: String,
        /// Bytes to write, as hex (e.g. "01ff")
        #[arg(long)]
        data: String,
        /// Characteristic UUID to read back
        #[arg(long)]
        read_uuid: String,
        /// Scan/connect timeout in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
}

/// `rules` subcommands.
#[derive(Subcommand, Debug)]
pub enum RulesCmd {
    /// List rules
    List {
        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Explain a rule
    Explain {
        /// Rule id
        id: String,
    },
}

/// The subject of `shell` and `explore`: a live device, or a capture file.
#[derive(Args, Debug)]
pub struct SessionArgs {
    /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
    #[arg(long, env = "BLE_DOCTOR_TARGET", required_unless_present = "capture")]
    target: Option<String>,
    /// Scan/connect timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,
    /// Open a btsnoop/pcap capture instead of a live device
    #[arg(long)]
    capture: Option<std::path::PathBuf>,
}

/// `shell` arguments.
#[derive(Args, Debug)]
pub struct ShellArgs {
    #[command(flatten)]
    session: SessionArgs,
    /// Run these `;`-separated commands and exit
    #[arg(short = 'c')]
    command: Option<String>,
    /// Print every reply as one JSON record (for agents)
    #[arg(long)]
    json: bool,
}

/// `command` for ble's own `vn` arguments: `run` gets them parsed.
macro_rules! ext {
    ($order:expr, $name:literal, $A:ty, $f:path) => {
        ExtCommand {
            command: <$A>::augment_args(clap::Command::new($name))
                .about(about($name))
                .display_order($order),
            run: |bd, m| $f(bd, &<$A>::from_arg_matches(m).map_err(|e| e.to_string())?),
        }
    };
}

fn about(name: &str) -> &'static str {
    match name {
        "scan" => "Scan for BLE devices",
        "analyze" => "Analyze a capture or device",
        "sniff" => "Ingest a BLE sniffer (Sniffle) stream and judge MAC rotation; needs sniffer hardware for --device",
        "fingerprint" => "Device fingerprint: LE+GATT profile (+ SDP/LMP on Linux)",
        "probe-writes" => "Probe writable characteristics (EMPIRICAL: connects without bonding and writes)",
        "read-values" => "Read characteristic values on non-SIG services (lists length + preview only)",
        "dfu" => "Probe DFU surface (EMPIRICAL buttonless probe: writes to the device without bonding)",
        "doctor" => "Diagnose the local BLE environment",
        "mcp" => "Run the MCP server",
        "recon" => "Recon a target (native GATT inventory)",
        "ctf" => "CTF helpers (own-gear / CTF scope only; never reachable via `mcp`)",
        "baseline" => "Baseline snapshots",
        "handoff" => "Export a handoff bundle",
        "rules" => "Inspect rules",
        "why" => "Explain a finding (rule doc, plus the finding from a report JSON)",
        "shell" => "Interactive shell over a live device or a capture",
        "explore" => "Full-screen explorer over a live device or a capture",
        "mitm" => "GATT MITM: clone the target as a peripheral and relay+log traffic to/from it (Linux + 2 adapters + peripheral mode only; EMPIRICAL/active)",
        _ => unreachable!("{name}"),
    }
}

/// The kit's report tail for a findings command. `--sarif` is written here, before anything is
/// printed and not atomically, as ble always has: a failed write is `sarif: <path>: <e>` on stderr,
/// exit 2, nothing on stdout (so the kit never sees the path: its own write prints first, and its
/// refusal of `--sarif` == `--baseline` is a new behavior).
fn findings(bd: &BleDoctor, m: &ArgMatches) -> Result<u8, String> {
    let mut o = OutputArgs::from_matches(m, bd);
    let sarif = o.sarif.take();
    let pre = match preflight(bd, &o) {
        Ok(p) => p,
        Err(f) => return Ok(doctor_kit::output::report_failure(bd, &f)),
    };
    let ctx = Ctx::detached(Default::default(), o.fail_on);
    let scanned = bd.try_scan(&ctx);
    if let (Some(path), Ok(env)) = (&sarif, &scanned) {
        if let Err(e) = std::fs::write(path, bd.render_sarif(env)) {
            eprintln!("sarif: {}: {e}", path.display());
            fail();
        }
    }
    Ok(kit_finish(bd, pre, scanned, &o))
}

/// A findings command: ble's own arguments plus the kit's presentation flags (`--theme-file` is
/// left out: nothing is looked up next to a capture or a radio).
fn findings_command<A: Args>(name: &'static str, order: usize) -> clap::Command {
    let own = ["json", "sarif", "baseline", "fail_on", "theme_file"];
    A::augment_args(clap::Command::new(name))
        .about(about(name))
        .args(
            OutputArgs::args_with(Severity::High)
                .into_iter()
                .filter(|a| !own.contains(&a.get_id().as_str())),
        )
        // `--face` lists its values inline: a value with its own help text would turn the whole
        // help into the long layout.
        .mut_arg("face", |a| {
            a.value_parser(
                PossibleValuesParser::new(["plain", "rich", "compact"])
                    .map(|s| <Face as clap::ValueEnum>::from_str(&s, true).expect("listed face")),
            )
        })
        .display_order(order)
}

/// ble's commands, in the order `--help` has always listed them.
pub fn extensions() -> Extensions<BleDoctor> {
    let plain =
        |order: usize,
         name: &'static str,
         run: fn(&BleDoctor, &ArgMatches) -> Result<u8, String>| ExtCommand {
            command: clap::Command::new(name)
                .about(about(name))
                .display_order(order),
            run,
        };
    Extensions {
        commands: vec![
            ExtCommand {
                command: findings_command::<ScanArgs>("scan", 0),
                run: scan,
            },
            ExtCommand {
                command: findings_command::<AnalyzeArgs>("analyze", 1),
                run: findings,
            },
            ext!(2, "sniff", SniffArgs, sniff),
            ext!(3, "fingerprint", FingerprintArgs, fingerprint),
            ext!(4, "probe-writes", ProbeWritesArgs, probe_writes),
            ext!(5, "read-values", ReadValuesArgs, read_values),
            ext!(6, "dfu", DfuArgs, dfu),
            plain(7, "doctor", |_, _| {
                use crate::{capability::Platform, doctor};
                let results = doctor::run_doctor(&doctor::Probes::detect(), Platform::current());
                std::process::exit(doctor::print_report(&results))
            }),
            plain(8, "mcp", |bd, _| {
                doctor_kit::mcp::serve(bd)
                    .map(|_| 0)
                    .map_err(|e| e.to_string())
            }),
            ext!(9, "recon", ReconArgs, recon),
            ext!(10, "ctf", CtfArgs, ctf),
            plain(11, "baseline", |_, _| {
                println!("baseline: not yet implemented (#26)");
                Ok(0)
            }),
            ext!(12, "handoff", HandoffArgs, handoff),
            ext!(13, "rules", RulesArgs, rules_cmd),
            ext!(14, "why", WhyArgs, why_cmd),
            ext!(15, "mitm", MitmArgs, mitm),
            ExtCommand {
                command: ShellArgs::augment_args(clap::Command::new("shell"))
                    .about(about("shell"))
                    .display_order(16),
                run: shell,
            },
            ExtCommand {
                command: SessionArgs::augment_args(clap::Command::new("explore"))
                    .about(about("explore"))
                    .display_order(17),
                run: explore,
            },
        ],
        global_args: vec![Arg::new("adapter")
            .long("adapter")
            .value_name("ADAPTER")
            .display_order(0)
            .help("Local Bluetooth adapter (e.g. hci0). Linux only; ignored elsewhere")],
        ..Default::default()
    }
}

/// Scan the subject once (a failure is reported as `scan` reports it), then hand the session to the
/// kit's shell or explorer; both read the cached result, so the radio is hit once.
fn session(bd: &BleDoctor) -> Result<Ctx, u8> {
    let ctx = Ctx::detached(Default::default(), Severity::High);
    bd.try_scan(&ctx)
        .map(|_| ctx)
        .map_err(|f| doctor_kit::output::report_failure(bd, &f))
}

fn shell(bd: &BleDoctor, m: &ArgMatches) -> Result<u8, String> {
    let a = ShellArgs::from_arg_matches(m).map_err(|e| e.to_string())?;
    match session(bd) {
        Ok(ctx) => doctor_kit::repl::run(bd, ctx, a.command.as_deref(), a.json),
        Err(code) => Ok(code),
    }
}

fn explore(bd: &BleDoctor, _: &ArgMatches) -> Result<u8, String> {
    match session(bd) {
        Ok(ctx) => doctor_kit::tui::run(bd, ctx).map(|_| 0),
        Err(code) => Ok(code),
    }
}

/// The doctor, from the parsed command line: the adapter and the subject (a capture for `analyze`,
/// the target for `scan`, `shell` and `explore`; `$BLE_DOCTOR_TARGET` for the kit's `fix`).
fn build(m: &ArgMatches) -> Result<BleDoctor, String> {
    let sub = m.subcommand();
    let flag = |id: &str| {
        sub.and_then(|(_, s)| s.try_get_one::<bool>(id).ok().flatten().copied())
            .unwrap_or(false)
    };
    let adapter = sub
        .and_then(|(_, s)| s.try_get_one::<String>("adapter").ok().flatten())
        .or_else(|| m.try_get_one::<String>("adapter").ok().flatten())
        .cloned();
    let live = |target: Option<String>, timeout: u64| {
        target
            .filter(|t| !t.is_empty())
            .map_or(Subject::None, |target| Subject::Live { target, timeout })
    };
    let subject = match sub {
        Some(("analyze", s)) => Subject::Capture(
            s.get_one::<std::path::PathBuf>("capture")
                .cloned()
                .unwrap_or_default(),
        ),
        Some(("shell" | "explore", s)) => match s.get_one::<std::path::PathBuf>("capture") {
            Some(c) => Subject::Capture(c.clone()),
            None => live(
                s.get_one::<String>("target").cloned(),
                s.get_one::<u64>("timeout").copied().unwrap_or(5),
            ),
        },
        Some(("scan", s)) => live(
            s.get_one::<String>("target").cloned(),
            s.get_one::<u64>("timeout").copied().unwrap_or(5),
        ),
        _ => live(std::env::var("BLE_DOCTOR_TARGET").ok(), 5),
    };
    // The shell keeps stdout for its replies (the device list goes to stderr); the explorer owns the
    // whole terminal.
    let out = match sub.map(|(n, _)| n) {
        Some("shell") => Out::Machine,
        Some("explore") => Out::Quiet,
        _ => match (flag("json") || flag("score"), flag("tui")) {
            (true, _) => Out::Machine,
            (_, true) => Out::Quiet,
            _ => Out::Human,
        },
    };
    Ok(BleDoctor::new(subject, adapter, out))
}

/// The whole CLI.
pub fn run() -> ExitCode {
    let meta = Meta::of(&BleDoctor::new(Subject::None, None, Out::Quiet));
    doctor_kit::run_with(meta, extensions(), build)
}

/// `scan`: the two raw-radio modes and the bare device list are ble's own; with a target the
/// findings go through the kit (`--tui` opens the kit's explorer first).
fn scan(bd: &BleDoctor, m: &ArgMatches) -> Result<u8, String> {
    let ScanArgs {
        target,
        timeout,
        mtu,
        as_address,
        tui,
        ..
    } = ScanArgs::from_arg_matches(m).map_err(|e| e.to_string())?;
    if let (Some(t), Some(a)) = (&target, &as_address) {
        match block(crate::radio::raw::set_random_address_and_connect(a, t)) {
            Ok(()) => println!("connected to {t} as {a}"),
            Err(e) => {
                eprintln!("as-address: {e}\n  fix: {}", e.remediation());
                fail();
            }
        }
        return Ok(0);
    }
    if let (Some(t), Some(mtu)) = (&target, mtu) {
        match block(crate::radio::raw::request_exact_mtu(t, mtu)) {
            Ok(n) => println!("negotiated MTU: {n}"),
            Err(e) => {
                eprintln!("mtu: {e}\n  fix: {}", e.remediation());
                fail();
            }
        }
        return Ok(0);
    }
    if target.is_none() {
        use crate::radio::{BtleplugCentral, Central};
        match block(BtleplugCentral.scan(std::time::Duration::from_secs(timeout))) {
            Ok(devs) => print_devices(&devs, Out::Human),
            Err(e) => {
                eprintln!("scan: {e}\n  fix: {}", e.remediation());
                fail();
            }
        }
        return Ok(0);
    }
    if tui {
        // Scan first so a failure is reported as ever, then explore the cached result.
        let ctx = Ctx::detached(Default::default(), Severity::High);
        if let Err(f) = bd.try_scan(&ctx) {
            return Ok(doctor_kit::output::report_failure(bd, &f));
        }
        if let Err(e) = doctor_kit::tui::run(bd, ctx) {
            eprintln!("tui: {e}");
            fail();
        }
    }
    findings(bd, m)
}

fn sniff(_: &BleDoctor, args: &SniffArgs) -> Result<u8, String> {
    let SniffArgs {
        device,
        from_file,
        json,
    } = args;
    let res = match (from_file, device) {
        (Some(f), _) => std::fs::read_to_string(f)
            .map(|t| crate::sniffer::parse_sniffle(&t))
            .map_err(|e| format!("{}: {e}", f.display())),
        (None, Some(d)) => {
            crate::sniffer::drive_sniffer(d).map_err(|e| format!("{e}\n  fix: {}", e.remediation()))
        }
        (None, None) => Err("pass --device <port> or --from-file <dump>".into()),
    };
    match res {
        Ok(info) => {
            let r = crate::capture::check_mac_rotation(&info);
            if *json {
                let v = serde_json::json!({"capture": info, "checks": [r]});
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                println!("sniffer: {} adv frames", info.adv_mac_addresses.len());
                let tag = if r.passed { "PASS" } else { "FAIL" };
                println!(
                    "[{tag}] {:?} {}: {}",
                    r.severity,
                    san(&r.id),
                    san(&r.detail)
                );
            }
        }
        Err(e) => {
            eprintln!("sniff: {e}");
            fail();
        }
    }
    Ok(0)
}

fn recon(bd: &BleDoctor, args: &ReconArgs) -> Result<u8, String> {
    let ReconArgs {
        target,
        timeout,
        bluesploit,
        json,
    } = args;
    use crate::radio::{
        connect_client, select_target_device, BtleplugCentral, Central, GattClient,
    };
    let dur = std::time::Duration::from_secs(*timeout);
    let res = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let devs = BtleplugCentral.scan(dur).await?;
            let d = select_target_device(&devs, target)?.clone();
            let name = d.adv_local_name.clone().or_else(|| d.name.clone());
            let c = connect_client(bd.adapter.as_deref(), &d, dur).await?;
            let s = c.services().await?;
            Ok::<_, crate::error::BleError>(crate::gatt::extract_gatt_fields(
                &s,
                &d.id,
                name.as_deref(),
            ))
        })
    });
    let gi = match res {
        Ok(g) => g,
        Err(e) => {
            eprintln!("recon: {e}\n  fix: {}", e.remediation());
            fail();
        }
    };
    let inv = crate::recon::inventory(&gi);
    let bs = bluesploit.then(crate::recon::bluesploit_recon);
    if *json {
        let v = serde_json::json!({"inventory": inv, "bluesploit_crosscheck": bs});
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        print!("{}", crate::recon::render(&inv));
        if let Some(b) = bs {
            println!(
                "\nbluesploit cross-check (EXTERNAL, HEURISTIC scrape, INFO only, not scored):"
            );
            println!("{}", serde_json::to_string_pretty(&b).unwrap());
        }
    }
    Ok(0)
}

fn probe_writes(bd: &BleDoctor, args: &ProbeWritesArgs) -> Result<u8, String> {
    let ProbeWritesArgs {
        target,
        allow_dangerous,
        timeout,
        json,
    } = args;
    if !allow_dangerous {
        eprintln!(
            "probe-writes: refused. This EMPIRICALLY writes to the device without \
             bonding (scope: own hardware or written authorization only). Pass \
             --allow-dangerous to proceed; firmware/DFU characteristics are still \
             refused regardless."
        );
        fail();
    }
    let Some(target) = target else {
        eprintln!("probe-writes: --target is required");
        fail();
    };
    use crate::radio::{
        connect_client, select_target_device, BtleplugCentral, Central, GattClient,
    };
    let dur = std::time::Duration::from_secs(*timeout);
    let res = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let devs = BtleplugCentral.scan(dur).await?;
            let d = select_target_device(&devs, target)?.clone();
            let name = d.adv_local_name.clone().or_else(|| d.name.clone());
            let c = connect_client(bd.adapter.as_deref(), &d, dur).await?;
            let s = c.services().await?;
            let gi = crate::gatt::extract_gatt_fields(&s, &d.id, name.as_deref());
            let results =
                crate::probe::write::probe_write_access(&c, &gi.writable_chars, true).await;
            Ok::<_, crate::error::BleError>((gi, results))
        })
    });
    match res {
        Ok((mut gi, results)) => {
            gi.writable_chars = crate::probe::write::results_to_writable_chars(&results);
            let finding = crate::checks::check_unauthenticated_writes(&gi);
            if *json {
                let v = serde_json::json!({
                    "results": results.iter().map(|r| serde_json::json!({
                        "uuid": r.uuid,
                        "service_uuid": r.service_uuid,
                        "outcome": format!("{:?}", r.outcome),
                        "requires_bonding": r.requires_bonding,
                    })).collect::<Vec<_>>(),
                    "finding": finding,
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                for r in &results {
                    println!(
                        "  {} ({}) -> {:?} requires_bonding={:?}",
                        san(&r.uuid),
                        san(&r.service_uuid),
                        r.outcome,
                        r.requires_bonding
                    );
                }
                let tag = if finding.passed { "PASS" } else { "FAIL" };
                println!(
                    "[{tag}] {:?} {}: {}",
                    finding.severity,
                    san(&finding.id),
                    san(&finding.detail)
                );
            }
        }
        Err(e) => {
            eprintln!("probe-writes: {e}\n  fix: {}", e.remediation());
            fail();
        }
    }
    Ok(0)
}

fn fingerprint(bd: &BleDoctor, args: &FingerprintArgs) -> Result<u8, String> {
    let FingerprintArgs {
        target,
        timeout,
        json,
    } = args;
    let Some(target) = target else {
        eprintln!("fingerprint: --target is required");
        fail();
    };
    use crate::radio::{
        connect_client, select_target_device, BtleplugCentral, Central, GattClient,
    };
    let dur = std::time::Duration::from_secs(*timeout);
    let res = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let devs = BtleplugCentral.scan(dur).await?;
            let d = select_target_device(&devs, target)?.clone();
            let name = d.adv_local_name.clone().or_else(|| d.name.clone());
            let c = connect_client(bd.adapter.as_deref(), &d, dur).await?;
            let g = crate::gatt::extract_gatt_fields(&c.services().await?, &d.id, name.as_deref());
            let mut f = crate::fingerprint::le_gatt_fingerprint(&g);
            match crate::fingerprint::collect_br_edr(d.address.as_deref().unwrap_or(target)).await {
                Ok((sdp, lmp, notes)) => {
                    f.sdp = sdp;
                    f.lmp = lmp;
                    f.notes.extend(notes);
                }
                Err(crate::error::BleError::Unsupported { .. }) => {
                    f.notes.push(crate::fingerprint::NOTE_NEEDS_LINUX.into())
                }
                Err(e) => f.notes.push(format!("SDP/LMP failed: {e}")),
            }
            Ok::<_, crate::error::BleError>(f)
        })
    });
    match res {
        Ok(f) if *json => println!("{}", serde_json::to_string_pretty(&f).expect("serialize")),
        Ok(f) => {
            println!(
                "{} name={}",
                san(&f.address),
                san(f.name.as_deref().unwrap_or("-"))
            );
            println!(
                "services={} chars={} writable={} notify={} pairing={}",
                f.service_uuids.len(),
                f.char_count,
                f.writable_count,
                f.notify_count,
                f.pairing_method
            );
            for u in &f.service_uuids {
                println!("  service {}", san(u));
            }
            for n in &f.notable_chars {
                println!("  {}", san(n));
            }
            if let Some(s) = &f.sdp {
                for r in &s.records {
                    println!(
                        "  sdp {:?} {}",
                        r.service_classes,
                        san(r.name.as_deref().unwrap_or(""))
                    );
                }
            }
            if let Some(l) = &f.lmp {
                println!(
                    "  lmp {} (v{}) mfr={} (0x{:04x}) subversion=0x{:04x}",
                    l.version,
                    l.lmp_version,
                    l.manufacturer_name.as_deref().unwrap_or("unknown"),
                    l.manufacturer,
                    l.subversion
                );
                println!("  lmp features: {}", l.features.join(", "));
            }
            for n in &f.notes {
                println!("  note: {}", san(n));
            }
        }
        Err(e) => {
            eprintln!("fingerprint: {e}\n  fix: {}", e.remediation());
            fail();
        }
    }
    Ok(0)
}

fn read_values(bd: &BleDoctor, args: &ReadValuesArgs) -> Result<u8, String> {
    let ReadValuesArgs { target, timeout } = args;
    let Some(target) = target else {
        eprintln!("read-values: --target is required");
        fail();
    };
    eprintln!(
        "read-values: reading can change device state (scope: own hardware or written \
         authorization only). SIG services and firmware/DFU characteristics are skipped."
    );
    use crate::radio::{
        connect_client, select_target_device, BtleplugCentral, Central, GattClient,
    };
    let dur = std::time::Duration::from_secs(*timeout);
    let res = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let devs = BtleplugCentral.scan(dur).await?;
            let d = select_target_device(&devs, target)?.clone();
            let c = connect_client(bd.adapter.as_deref(), &d, dur).await?;
            let chars = crate::probe::read::read_chars(&c.services().await?);
            Ok::<_, crate::error::BleError>(crate::probe::read::read_values(&c, &chars).await)
        })
    });
    match res {
        Ok(results) => {
            use crate::probe::read::ReadOutcome::*;
            for r in &results {
                match &r.outcome {
                    Value { len, preview } => {
                        println!(
                            "  {} ({}) len={len} \"{}\"",
                            san(&r.uuid),
                            san(&r.service_uuid),
                            san(preview)
                        )
                    }
                    Skipped(why) => println!("  {} skipped: {}", san(&r.uuid), san(why)),
                    Error(e) => {
                        println!("  {} read error: {}", san(&r.uuid), san(&e.to_string()))
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("read-values: {e}\n  fix: {}", e.remediation());
            fail();
        }
    }
    Ok(0)
}

fn dfu(bd: &BleDoctor, args: &DfuArgs) -> Result<u8, String> {
    let DfuArgs {
        target,
        allow_dangerous,
        bond_sharing,
        timeout,
        json,
    } = args;
    if !allow_dangerous {
        eprintln!(
            "dfu: refused. This EMPIRICALLY writes to the buttonless-DFU characteristic \
             without bonding (scope: own hardware or written authorization only). Pass \
             --allow-dangerous to proceed."
        );
        fail();
    }
    let Some(target) = target else {
        eprintln!("dfu: --target is required");
        fail();
    };
    use crate::radio::{
        connect_client, select_target_device, BtleplugCentral, Central, GattClient,
    };
    let dur = std::time::Duration::from_secs(*timeout);
    let bond_sharing = *bond_sharing;
    let res = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let devs = BtleplugCentral.scan(dur).await?;
            let d = select_target_device(&devs, target)?.clone();
            let name = d.adv_local_name.clone().or_else(|| d.name.clone());
            let c = connect_client(bd.adapter.as_deref(), &d, dur).await?;
            let s = c.services().await?;
            let gi = crate::gatt::extract_gatt_fields(&s, &d.id, name.as_deref());
            let buttonless = crate::probe::dfu::probe_buttonless(&c, bond_sharing).await;
            Ok::<_, crate::error::BleError>((gi, buttonless))
        })
    });
    match res {
        Ok((gi, buttonless)) => {
            let entry_point = crate::checks::check_dfu_entry_point(&gi);
            let surface_absent = crate::checks::check_dfu_surface_absent(&gi);
            if *json {
                let v = serde_json::json!({
                    "buttonless": {
                        "uuid": buttonless.uuid,
                        "outcome": format!("{:?}", buttonless.outcome),
                        "triggerable_unbonded": buttonless.triggerable_unbonded,
                    },
                    "dfu_entry_point": entry_point,
                    "dfu_surface_absent": surface_absent,
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                println!(
                    "buttonless {} -> {:?} triggerable_unbonded={}",
                    san(&buttonless.uuid),
                    buttonless.outcome,
                    buttonless.triggerable_unbonded
                );
                for r in [&entry_point, &surface_absent] {
                    let tag = if r.passed { "PASS" } else { "FAIL" };
                    println!(
                        "[{tag}] {:?} {}: {}",
                        r.severity,
                        san(&r.id),
                        san(&r.detail)
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("dfu: {e}\n  fix: {}", e.remediation());
            fail();
        }
    }
    Ok(0)
}

fn ctf(bd: &BleDoctor, args: &CtfArgs) -> Result<u8, String> {
    let CtfArgs { action } = args;
    eprintln!(
        "ctf: own-gear / CTF scope only (own hardware or a device you are authorized to test, \
         e.g. hackgnar/ble_ctf). This writes to the device."
    );
    use crate::radio::{connect_client, select_target_device, BtleplugCentral, Central};
    match action {
        CtfCmd::Brute {
            target,
            char_uuid,
            read_uuid,
            contains,
            timeout,
        } => {
            let dur = std::time::Duration::from_secs(*timeout);
            let res = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let devs = BtleplugCentral.scan(dur).await?;
                    let d = select_target_device(&devs, target)?.clone();
                    let c = connect_client(bd.adapter.as_deref(), &d, dur).await?;
                    Ok::<_, crate::error::BleError>(
                        crate::ctf::brute_write(&c, char_uuid, read_uuid, |v| {
                            String::from_utf8_lossy(v).contains(contains.as_str())
                        })
                        .await,
                    )
                })
            });
            match res {
                Ok(Some((byte, value))) => println!(
                    "found byte 0x{byte:02x} -> {:?} ({})",
                    value,
                    san(&String::from_utf8_lossy(&value))
                ),
                Ok(None) => {
                    println!("brute: exhausted 0x00..=0xff without a match");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("ctf brute: {e}\n  fix: {}", e.remediation());
                    fail();
                }
            }
        }
        CtfCmd::ReadN {
            target,
            char_uuid,
            n,
            timeout,
        } => {
            let dur = std::time::Duration::from_secs(*timeout);
            let n = *n;
            let res = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let devs = BtleplugCentral.scan(dur).await?;
                    let d = select_target_device(&devs, target)?.clone();
                    let c = connect_client(bd.adapter.as_deref(), &d, dur).await?;
                    Ok::<_, crate::error::BleError>(crate::ctf::read_n(&c, char_uuid, n).await)
                })
            });
            match res {
                Ok(values) => {
                    for (i, v) in values.iter().enumerate() {
                        println!("read {i}: {v:?} ({})", san(&String::from_utf8_lossy(v)));
                    }
                }
                Err(e) => {
                    eprintln!("ctf read-n: {e}\n  fix: {}", e.remediation());
                    fail();
                }
            }
        }
        CtfCmd::WriteThenRead {
            target,
            char_uuid,
            data,
            read_uuid,
            timeout,
        } => {
            let data = match hex_decode(data) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("ctf write-then-read: {e}");
                    fail();
                }
            };
            let dur = std::time::Duration::from_secs(*timeout);
            let res = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let devs = BtleplugCentral.scan(dur).await?;
                    let d = select_target_device(&devs, target)?.clone();
                    let c = connect_client(bd.adapter.as_deref(), &d, dur).await?;
                    crate::ctf::write_then_read(&c, char_uuid, &data, read_uuid).await
                })
            });
            match res {
                Ok(v) => println!("{v:?} ({})", san(&String::from_utf8_lossy(&v))),
                Err(e) => {
                    eprintln!("ctf write-then-read: {e}\n  fix: {}", e.remediation());
                    fail();
                }
            }
        }
    }
    Ok(0)
}

fn rules_cmd(_: &BleDoctor, args: &RulesArgs) -> Result<u8, String> {
    let RulesArgs { action } = args;
    match action {
        RulesCmd::List { json } => println!("{}", rules_list(*json)),
        RulesCmd::Explain { id } => finish(explain(id)),
    }
    Ok(0)
}

fn why_cmd(_: &BleDoctor, args: &WhyArgs) -> Result<u8, String> {
    let WhyArgs { id, report } = args;
    finish(why(id, report.as_deref()));
    Ok(0)
}

fn handoff(_: &BleDoctor, args: &HandoffArgs) -> Result<u8, String> {
    let HandoffArgs { report } = args;
    finish(
        crate::handoff::from_report(report)
            .map(|v| serde_json::to_string_pretty(&v).unwrap() + "\n")
            .map_err(|e| (2, format!("handoff: {e}"))),
    );
    Ok(0)
}

#[cfg(target_os = "linux")]
fn mitm(bd: &BleDoctor, args: &MitmArgs) -> Result<u8, String> {
    let MitmArgs {
        target,
        allow_dangerous,
    } = args;
    if !allow_dangerous {
        mitm_refused();
    }
    let res = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(crate::mitm::live::serve(
            bd.adapter.as_deref(),
            target,
            *allow_dangerous,
        ))
    });
    if let Err(e) = res {
        eprintln!("mitm: {e}");
        fail();
    }
    Ok(0)
}

#[cfg(not(target_os = "linux"))]
fn mitm(_: &BleDoctor, args: &MitmArgs) -> Result<u8, String> {
    if !args.allow_dangerous {
        mitm_refused();
    }
    use crate::capability::{require, Feature};
    let err = require(Feature::Mitm).expect_err("Mitm is Unsupported off Linux");
    eprintln!(
        "mitm: {err}\n  fix: needs Linux with 2 adapters + peripheral mode (bluster); \
         not available on this platform."
    );
    fail();
}

fn mitm_refused() -> ! {
    eprintln!(
        "mitm: refused. This ACTIVELY intercepts GATT traffic between a victim and the \
         real device by cloning it as a peripheral (scope: own hardware or written \
         authorization only). Pass --allow-dangerous to proceed."
    );
    fail();
}

/// Decode a hex string (e.g. "01ff") into bytes for `ctf write-then-read --data`.
/// Error exit (doctor/1: 2 = usage error, bad input, or the tool could not run). The single place
/// every error path leaves through.
fn fail() -> ! {
    std::process::exit(2)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string: {s:?}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex {s:?}: {e}")))
        .collect()
}

fn finish(r: Result<String, (i32, String)>) {
    match r {
        Ok(t) => print!("{t}"),
        Err((code, msg)) => {
            eprintln!("{msg}");
            std::process::exit(code);
        }
    }
}

fn rules_list(json: bool) -> String {
    use crate::rules::rules;
    if json {
        return serde_json::to_string_pretty(rules()).expect("rules serialize");
    }
    rules()
        .iter()
        .map(|r| {
            format!(
                "{:<24} {:<8} {:<14} {}",
                r.id,
                r.category,
                r.severities.join("/"),
                r.title
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The rule doc, or exit 2 with a "did you mean" hint.
fn explain(id: &str) -> Result<String, (i32, String)> {
    crate::rules::rule_text(id)
        .map(str::to_string)
        .ok_or_else(|| {
            let mut m = format!("unknown rule '{id}'");
            let near = crate::rules::near_misses(id);
            if !near.is_empty() {
                m.push_str(&format!("\ndid you mean: {}?", near.join(", ")));
            }
            m.push_str("\n(run `ble-doctor rules list`)");
            (2, m)
        })
}

/// Rule doc, preceded by the matching finding when a report is given (exit 2 on a bad report).
fn why(id: &str, report: Option<&std::path::Path>) -> Result<String, (i32, String)> {
    let doc = explain(id)?;
    let Some(path) = report else {
        return Ok(doc);
    };
    let v: serde_json::Value = std::fs::read_to_string(path)
        .map_err(|e| (2, format!("why: {}: {e}", path.display())))
        .and_then(|t| serde_json::from_str(&t).map_err(|e| (2, format!("why: bad report: {e}"))))?;
    let find = |arr: &serde_json::Value| {
        arr.as_array()
            .and_then(|a| a.iter().find(|f| f["id"] == id))
            .cloned()
    };
    let (f, tag) = match (find(&v["findings"]), find(&v["data"]["passed"])) {
        (Some(f), _) => (f, "FAIL"),
        (None, Some(f)) => (f, "PASS"),
        _ => return Err((2, format!("why: no finding '{id}' in {}", path.display()))),
    };
    Ok(format!(
        "[{tag}] {} {}: {}\n\n{doc}",
        crate::report::sanitize(f["severity"].as_str().unwrap_or("?")),
        id,
        crate::report::sanitize(f["message"].as_str().or(f["detail"].as_str()).unwrap_or(""))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_command_is_valid() {
        let meta = Meta::of(&BleDoctor::new(Subject::None, None, Out::Quiet));
        doctor_kit::command_with(&meta, &extensions()).debug_assert();
    }

    #[test]
    fn rules_list_json_len_matches_catalog() {
        let v: serde_json::Value = serde_json::from_str(&rules_list(true)).unwrap();
        assert_eq!(v.as_array().unwrap().len(), crate::rules::RULES.len());
    }

    #[test]
    fn explain_known_and_unknown() {
        assert!(explain("mac_rotation")
            .unwrap()
            .contains("## What it means"));
        let (code, msg) = explain("mac_rotaton").unwrap_err();
        assert_eq!(code, 2);
        assert!(msg.contains("did you mean: mac_rotation"), "{msg}");
    }

    #[test]
    fn why_with_report() {
        let dir = std::env::temp_dir().join(format!("bd-why-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("r.json");
        std::fs::write(
            &p,
            r#"{"schema":"doctor/1","score":{"value":70},"findings":[{"id":"unauthenticated_writes","severity":"high","message":"Writable: aaa1"}],"data":{"passed":[]}}"#,
        )
        .unwrap();
        let out = why("unauthenticated_writes", Some(&p)).unwrap();
        assert!(out.contains("[FAIL] high unauthenticated_writes: Writable: aaa1"));
        assert!(out.contains("## How to verify"));
        assert_eq!(why("mac_rotation", Some(&p)).unwrap_err().0, 2);
        assert_eq!(
            why("mac_rotation", Some(&dir.join("nope"))).unwrap_err().0,
            2
        );
        assert_eq!(why("bogus", None).unwrap_err().0, 2);
    }
}
