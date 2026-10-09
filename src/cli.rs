//! Command-line interface (clap). All handlers are stubs for now.

use crate::report::sanitize as san;
use clap::{Parser, Subcommand};

/// BLE diagnostics and security CLI.
#[derive(Parser, Debug)]
#[command(name = "ble-doctor", version, about)]
pub struct Cli {
    /// Local Bluetooth adapter (e.g. hci0). Linux only; ignored elsewhere.
    #[arg(long, global = true)]
    pub adapter: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// Top-level subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan for BLE devices
    Scan {
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
        #[arg(long, default_value = "high", value_parser = SEVERITIES)]
        fail_on: String,
    },
    /// Analyze a capture or device
    Analyze {
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
        #[arg(long, default_value = "high", value_parser = SEVERITIES)]
        fail_on: String,
    },
    /// Ingest a BLE sniffer (Sniffle) stream and judge MAC rotation; needs sniffer hardware for --device
    Sniff {
        /// Serial/USB sniffer port (e.g. /dev/ttyACM0)
        #[arg(long, conflicts_with = "from_file")]
        device: Option<String>,
        /// Saved Sniffle text dump to parse instead of live capture
        #[arg(long)]
        from_file: Option<std::path::PathBuf>,
        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Device fingerprint: LE+GATT profile (+ SDP/LMP on Linux)
    Fingerprint {
        /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
        #[arg(long, env = "BLE_DOCTOR_TARGET")]
        target: Option<String>,
        /// Scan/connect timeout in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,
        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Probe writable characteristics (EMPIRICAL: connects without bonding and writes)
    ProbeWrites {
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
    },
    /// Read characteristic values on non-SIG services (lists length + preview only)
    ReadValues {
        /// Target address / identifier / name (or set BLE_DOCTOR_TARGET)
        #[arg(long, env = "BLE_DOCTOR_TARGET")]
        target: Option<String>,
        /// Scan/connect timeout in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
    /// Probe DFU surface (EMPIRICAL buttonless probe: writes to the device without bonding)
    Dfu {
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
    },
    /// Diagnose the local BLE environment
    Doctor,
    /// Run the MCP server
    Mcp,
    /// Recon a target (native GATT inventory)
    Recon {
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
    },
    /// CTF helpers (own-gear / CTF scope only; never reachable via `mcp`)
    Ctf {
        #[command(subcommand)]
        action: CtfCmd,
    },
    /// Baseline snapshots
    Baseline,
    /// Export a handoff bundle
    Handoff {
        /// A `scan --json` report file to turn into the bundle (no radio)
        #[arg(long)]
        report: std::path::PathBuf,
    },
    /// Inspect rules
    Rules {
        #[command(subcommand)]
        action: RulesCmd,
    },
    /// Explain a finding (rule doc, plus the finding from a report JSON)
    Why {
        /// Rule / check id
        id: String,
        /// A `--json` report file to pull the matching finding from
        #[arg(long)]
        report: Option<std::path::PathBuf>,
    },
    /// GATT MITM: clone the target as a peripheral and relay+log traffic
    /// to/from it (Linux + 2 adapters + peripheral mode only; EMPIRICAL/active)
    Mitm {
        /// The real target device to relay to (address / identifier / name)
        #[arg(long, env = "BLE_DOCTOR_TARGET")]
        target: String,
        /// Required: this actively intercepts GATT traffic between a victim
        /// and the real device (scope: own hardware or written authorization only).
        #[arg(long)]
        allow_dangerous: bool,
    },
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

impl Command {
    /// Stub message: command name and tracking issue.
    pub fn stub(&self) -> (&'static str, u32) {
        match self {
            Command::Scan { .. } => ("scan", 7),
            Command::Analyze { .. } => ("analyze", 11),
            Command::ProbeWrites { .. } => ("probe-writes", 8),
            Command::Sniff { .. } => ("sniff", 19),
            Command::Fingerprint { .. } => ("fingerprint", 18),
            Command::ReadValues { .. } => ("read-values", 9),
            Command::Dfu { .. } => ("dfu", 10),
            Command::Doctor => ("doctor", 4),
            Command::Mcp => ("mcp", 12),
            Command::Recon { .. } => ("recon", 21),
            Command::Ctf { .. } => ("ctf", 22),
            Command::Baseline => ("baseline", 26),
            Command::Handoff { .. } => ("handoff", 27),
            Command::Rules { .. } | Command::Why { .. } => ("rules", 23),
            Command::Mitm { .. } => ("mitm", 20),
        }
    }
}

/// Dispatch a parsed CLI.
pub fn run(cli: Cli) {
    if let Command::Mcp = &cli.command {
        crate::mcp::serve();
        return;
    }
    if let Command::Analyze {
        capture,
        json,
        sarif,
        baseline,
        fail_on,
    } = &cli.command
    {
        let res = std::fs::read(capture)
            .map_err(|e| e.to_string())
            .and_then(|b| crate::capture::parse_capture(&b));
        match res {
            Ok(info) => {
                let smp = crate::smp::analyze(&info.smp_pdus);
                let mut checks = vec![crate::capture::check_mac_rotation(&info)];
                checks.extend(smp.checks);
                let loc = serde_json::json!({"kind": "file", "ref": capture.display().to_string()});
                let human = format!(
                    "capture: {} ({} adv frames)\n{}{}",
                    crate::report::sanitize(info.capture_flavour.as_deref().unwrap_or("unknown")),
                    info.adv_mac_addresses.len(),
                    crate::report::to_table(&checks),
                    smp.summary
                        .iter()
                        .map(|l| format!("\n{}", crate::report::sanitize(l)))
                        .collect::<String>()
                );
                let extra = serde_json::json!({"capture": info, "smp": smp.data});
                // Peripheral identity: the one address in the capture; rotating/absent -> empty.
                let mut addrs: Vec<&String> = info.adv_mac_addresses.iter().collect();
                addrs.sort();
                addrs.dedup();
                let dev = if addrs.len() == 1 {
                    addrs[0].as_str()
                } else {
                    ""
                };
                let code = emit(
                    &checks,
                    &loc,
                    dev,
                    extra,
                    *json,
                    sarif,
                    baseline,
                    fail_on,
                    Some(&human),
                );
                if code != 0 {
                    std::process::exit(code);
                }
            }
            Err(e) => {
                eprintln!("analyze: {}", crate::report::sanitize(&e));
                fail();
            }
        }
        return;
    }
    if let Command::Sniff {
        device,
        from_file,
        json,
    } = &cli.command
    {
        let res = match (from_file, device) {
            (Some(f), _) => std::fs::read_to_string(f)
                .map(|t| crate::sniffer::parse_sniffle(&t))
                .map_err(|e| format!("{}: {e}", f.display())),
            (None, Some(d)) => crate::sniffer::drive_sniffer(d)
                .map_err(|e| format!("{e}\n  fix: {}", e.remediation())),
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
        return;
    }
    if let Command::Scan {
        target: Some(t),
        as_address: Some(a),
        ..
    } = &cli.command
    {
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(crate::radio::raw::set_random_address_and_connect(a, t))
        });
        match res {
            Ok(()) => println!("connected to {t} as {a}"),
            Err(e) => {
                eprintln!("as-address: {e}\n  fix: {}", e.remediation());
                fail();
            }
        }
        return;
    }
    if let Command::Scan {
        target: Some(t),
        mtu: Some(m),
        ..
    } = &cli.command
    {
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(crate::radio::raw::request_exact_mtu(t, *m))
        });
        match res {
            Ok(n) => println!("negotiated MTU: {n}"),
            Err(e) => {
                eprintln!("mtu: {e}\n  fix: {}", e.remediation());
                fail();
            }
        }
        return;
    }
    if let Command::Scan {
        target,
        timeout,
        json,
        tui,
        sarif,
        baseline,
        fail_on,
        ..
    } = &cli.command
    {
        use crate::radio::{select_target_device, BtleplugCentral, Central};
        let dur = std::time::Duration::from_secs(*timeout);
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(BtleplugCentral.scan(dur))
        });
        match res {
            Ok(devs) => {
                // --json: stdout carries only the envelope, so the device list goes to stderr.
                for d in &devs {
                    let line = format!(
                        "{}  addr={} name={} adv={} rssi={}",
                        crate::report::sanitize(&d.id),
                        d.address.as_deref().unwrap_or("-"),
                        crate::report::sanitize(d.name.as_deref().unwrap_or("-")),
                        crate::report::sanitize(d.adv_local_name.as_deref().unwrap_or("-")),
                        d.rssi.map_or("-".into(), |r| r.to_string())
                    );
                    if *json {
                        eprintln!("{line}");
                    } else {
                        println!("{line}");
                    }
                }
                if let Some(t) = target {
                    match select_target_device(&devs, t) {
                        Ok(d) => {
                            if !*json {
                                println!("selected: {}", crate::report::sanitize(&d.id));
                            }
                            let id = d.id.clone();
                            let dev = d.clone();
                            let name = d.adv_local_name.clone().or_else(|| d.name.clone());
                            let gi = tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current().block_on(async {
                                    use crate::radio::{connect_client, GattClient};
                                    let c =
                                        connect_client(cli.adapter.as_deref(), &dev, dur).await?;
                                    let s = c.services().await?;
                                    Ok::<_, crate::error::BleError>(
                                        crate::gatt::extract_gatt_fields(&s, &id, name.as_deref()),
                                    )
                                })
                            });
                            match gi {
                                Ok(g) => {
                                    let checks = [
                                        crate::checks::check_unauthenticated_writes(&g),
                                        crate::checks::check_dfu_entry_point(&g),
                                        crate::checks::check_dfu_signing_enforced(&g),
                                        crate::checks::check_dfu_surface_absent(&g),
                                    ];
                                    let loc = serde_json::json!({"kind": "device", "ref": t});
                                    if *json {
                                        let code = emit(
                                            &checks,
                                            &loc,
                                            t,
                                            serde_json::json!({}),
                                            true,
                                            sarif,
                                            baseline,
                                            fail_on,
                                            None,
                                        );
                                        if code != 0 {
                                            std::process::exit(code);
                                        }
                                        return;
                                    }
                                    if *tui {
                                        let score = crate::report::compute_score(&checks);
                                        if let Err(e) = crate::tui::run_tui(score, &checks) {
                                            eprintln!("tui: {e}");
                                            fail();
                                        }
                                        let code = emit(
                                            &checks,
                                            &loc,
                                            t,
                                            serde_json::json!({}),
                                            false,
                                            sarif,
                                            baseline,
                                            fail_on,
                                            None,
                                        );
                                        if code != 0 {
                                            std::process::exit(code);
                                        }
                                        return;
                                    }
                                    println!(
                                        "gatt: {} services, {} writable, {} subscribable",
                                        g.service_uuids.len(),
                                        g.writable_chars.len(),
                                        g.subscribe_chars.len()
                                    );
                                    for w in &g.writable_chars {
                                        println!(
                                            "  write {} requires_bonding={} ({})",
                                            san(&w.uuid),
                                            w.requires_bonding,
                                            san(&w.bonding_basis)
                                        );
                                    }
                                    for s in &g.subscribe_chars {
                                        println!("  notify {} cccd={:?}", san(&s.uuid), s.cccd);
                                    }
                                    let human = format!("\n{}", crate::report::to_table(&checks));
                                    let code = emit(
                                        &checks,
                                        &loc,
                                        t,
                                        serde_json::json!({}),
                                        false,
                                        sarif,
                                        baseline,
                                        fail_on,
                                        Some(&human),
                                    );
                                    if code != 0 {
                                        std::process::exit(code);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("gatt: {e}\n  fix: {}", e.remediation());
                                    fail();
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("scan: {e}");
                            fail();
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("scan: {e}\n  fix: {}", e.remediation());
                fail();
            }
        }
        return;
    }
    if let Command::Recon {
        target,
        timeout,
        bluesploit,
        json,
    } = &cli.command
    {
        use crate::radio::{
            connect_client, select_target_device, BtleplugCentral, Central, GattClient,
        };
        let dur = std::time::Duration::from_secs(*timeout);
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let devs = BtleplugCentral.scan(dur).await?;
                let d = select_target_device(&devs, target)?.clone();
                let name = d.adv_local_name.clone().or_else(|| d.name.clone());
                let c = connect_client(cli.adapter.as_deref(), &d, dur).await?;
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
        return;
    }
    if let Command::ProbeWrites {
        target,
        allow_dangerous,
        timeout,
        json,
    } = &cli.command
    {
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
                let c = connect_client(cli.adapter.as_deref(), &d, dur).await?;
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
        return;
    }
    if let Command::Fingerprint {
        target,
        timeout,
        json,
    } = &cli.command
    {
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
                let c = connect_client(cli.adapter.as_deref(), &d, dur).await?;
                let g =
                    crate::gatt::extract_gatt_fields(&c.services().await?, &d.id, name.as_deref());
                let mut f = crate::fingerprint::le_gatt_fingerprint(&g);
                match crate::fingerprint::collect_br_edr(d.address.as_deref().unwrap_or(target))
                    .await
                {
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
        return;
    }
    if let Command::ReadValues { target, timeout } = &cli.command {
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
                let c = connect_client(cli.adapter.as_deref(), &d, dur).await?;
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
        return;
    }
    if let Command::Dfu {
        target,
        allow_dangerous,
        bond_sharing,
        timeout,
        json,
    } = &cli.command
    {
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
                let c = connect_client(cli.adapter.as_deref(), &d, dur).await?;
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
        return;
    }
    if let Command::Ctf { action } = &cli.command {
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
                        let c = connect_client(cli.adapter.as_deref(), &d, dur).await?;
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
                        let c = connect_client(cli.adapter.as_deref(), &d, dur).await?;
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
                        let c = connect_client(cli.adapter.as_deref(), &d, dur).await?;
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
        return;
    }
    if let Command::Mitm {
        target,
        allow_dangerous,
    } = &cli.command
    {
        if !allow_dangerous {
            eprintln!(
                "mitm: refused. This ACTIVELY intercepts GATT traffic between a victim and the \
                 real device by cloning it as a peripheral (scope: own hardware or written \
                 authorization only). Pass --allow-dangerous to proceed."
            );
            fail();
        }
        #[cfg(target_os = "linux")]
        {
            let res = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(crate::mitm::live::serve(target, *allow_dangerous))
            });
            if let Err(e) = res {
                eprintln!("mitm: {e}");
                fail();
            }
            return;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            use crate::capability::{require, Feature};
            let err = require(Feature::Mitm).expect_err("Mitm is Unsupported off Linux");
            eprintln!(
                "mitm: {err}\n  fix: needs Linux with 2 adapters + peripheral mode (bluster); \
                 not available on this platform."
            );
            fail();
        }
    }
    if let Command::Doctor = &cli.command {
        use crate::{capability::Platform, doctor};
        let results = doctor::run_doctor(&doctor::Probes::detect(), Platform::current());
        std::process::exit(doctor::print_report(&results));
    }
    if let Command::Rules { action } = &cli.command {
        match action {
            RulesCmd::List { json } => println!("{}", rules_list(*json)),
            RulesCmd::Explain { id } => finish(explain(id)),
        }
        return;
    }
    if let Command::Why { id, report } = &cli.command {
        finish(why(id, report.as_deref()));
        return;
    }
    if let Command::Handoff { report } = &cli.command {
        finish(
            crate::handoff::from_report(report)
                .map(|v| serde_json::to_string_pretty(&v).unwrap() + "\n")
                .map_err(|e| (2, format!("handoff: {e}"))),
        );
        return;
    }
    let (name, issue) = cli.command.stub();
    println!("{name}: not yet implemented (#{issue})");
}

/// Decode a hex string (e.g. "01ff") into bytes for `ctf write-then-read --data`.
/// Error exit (doctor/1: 2 = usage error, bad input, or the tool could not run). The single place
/// every error path leaves through.
fn fail() -> ! {
    std::process::exit(2)
}

/// Shared tail of the findings commands (scan, analyze): baseline, exit code, SARIF, output.
/// Prints the envelope (`json`) or `human` (plus the baseline diff on stderr); returns the exit code.
#[allow(clippy::too_many_arguments)]
fn emit(
    checks: &[crate::checks::CheckResult],
    loc: &serde_json::Value,
    device: &str,
    extra: serde_json::Value,
    json: bool,
    sarif: &Option<std::path::PathBuf>,
    baseline: &Option<std::path::PathBuf>,
    fail_on: &str,
    human: Option<&str>,
) -> i32 {
    use crate::baseline;
    let sev = baseline::parse_severity(fail_on).expect("clap-validated");
    let base = match baseline.as_deref().map(baseline::load).transpose() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}", crate::report::sanitize(&e));
            fail();
        }
    };
    let diff = base.as_ref().map(|b| baseline::diff(checks, b, device));
    let code = crate::report::gate_exit(
        checks,
        sev,
        diff.as_ref().map(|d| d.new_failures.as_slice()),
    );
    let env = crate::report::to_envelope(checks, loc, device, base.as_ref(), code, extra);
    if let Some(path) = sarif {
        let v = crate::sarif::to_sarif(
            &env["score"],
            checks,
            loc["ref"].as_str().filter(|_| loc["kind"] == "file"),
            device,
        );
        if let Err(e) = std::fs::write(path, serde_json::to_string_pretty(&v).unwrap()) {
            eprintln!("sarif: {}: {e}", path.display());
            fail();
        }
    }
    if let Some(d) = &diff {
        baseline::report_diff(d);
    }
    if json {
        println!("{}", crate::report::to_json(&env));
    } else if let Some(h) = human {
        println!("{h}");
    }
    code
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
    use clap::CommandFactory;

    #[test]
    fn clap_command_is_valid() {
        Cli::command().debug_assert();
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
