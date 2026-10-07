//! Command-line interface (clap). All handlers are stubs for now.

use clap::{Parser, Subcommand};

/// BLE diagnostics and security CLI.
#[derive(Parser, Debug)]
#[command(name = "ble-doctor", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

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
        /// Emit the scored report as JSON (needs --target)
        #[arg(long, requires = "target")]
        json: bool,
        /// Write a SARIF 2.1.0 report to this file (needs --target)
        #[arg(long, requires = "target")]
        sarif: Option<std::path::PathBuf>,
        /// Diff findings against a saved `--json` report; exit 3 if NEW failures reach --fail-on
        #[arg(long, requires = "target")]
        baseline: Option<std::path::PathBuf>,
        /// Severity gate for new failures (with --baseline)
        #[arg(long, default_value = "high", value_parser = ["info", "low", "medium", "high"], requires = "baseline")]
        fail_on: String,
    },
    /// Analyze a capture or device
    Analyze {
        /// Path to a btsnoop/pcap capture
        capture: std::path::PathBuf,
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
    /// Probe DFU surface
    Dfu,
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
    /// CTF helpers
    Ctf,
    /// Baseline snapshots
    Baseline,
    /// Export a handoff bundle
    Handoff,
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
            Command::ReadValues { .. } => ("read-values", 9),
            Command::Dfu => ("dfu", 10),
            Command::Doctor => ("doctor", 4),
            Command::Mcp => ("mcp", 12),
            Command::Recon { .. } => ("recon", 21),
            Command::Ctf => ("ctf", 22),
            Command::Baseline => ("baseline", 26),
            Command::Handoff => ("handoff", 27),
            Command::Rules { .. } | Command::Why { .. } => ("rules", 23),
        }
    }
}

/// Dispatch a parsed CLI.
pub fn run(cli: Cli) {
    if let Command::Mcp = &cli.command {
        crate::mcp::serve();
        return;
    }
    if let Command::Analyze { capture, json } = &cli.command {
        let res = std::fs::read(capture)
            .map_err(|e| e.to_string())
            .and_then(|b| crate::capture::parse_capture(&b));
        match res {
            Ok(info) => {
                let r = crate::capture::check_mac_rotation(&info);
                if *json {
                    let v = serde_json::json!({"capture": info, "checks": [r]});
                    println!("{}", serde_json::to_string_pretty(&v).unwrap());
                } else {
                    println!(
                        "capture: {} ({} adv frames)",
                        info.capture_flavour.as_deref().unwrap_or("unknown"),
                        info.adv_mac_addresses.len()
                    );
                    let tag = if r.passed { "PASS" } else { "FAIL" };
                    println!("[{tag}] {:?} {}: {}", r.severity, r.id, r.detail);
                }
            }
            Err(e) => {
                eprintln!("analyze: {e}");
                std::process::exit(1);
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
                std::process::exit(1);
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
                std::process::exit(1);
            }
        }
        return;
    }
    if let Command::Scan {
        target,
        timeout,
        json,
        sarif,
        baseline,
        fail_on,
        ..
    } = &cli.command
    {
        use crate::radio::{select_target_device, BtleplugCentral, Central};
        let base = match baseline.as_deref().map(crate::baseline::load).transpose() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("scan: {e}");
                std::process::exit(1);
            }
        };
        let gate = |checks: &[crate::checks::CheckResult]| -> bool {
            let sev = crate::baseline::parse_severity(fail_on).expect("clap-validated");
            base.as_ref()
                .is_some_and(|b| crate::baseline::report_and_gate(checks, b, sev))
        };
        let dur = std::time::Duration::from_secs(*timeout);
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(BtleplugCentral.scan(dur))
        });
        match res {
            Ok(devs) => {
                for d in &devs {
                    println!(
                        "{}  addr={} name={} adv={} rssi={}",
                        d.id,
                        d.address.as_deref().unwrap_or("-"),
                        d.name.as_deref().unwrap_or("-"),
                        d.adv_local_name.as_deref().unwrap_or("-"),
                        d.rssi.map_or("-".into(), |r| r.to_string())
                    );
                }
                if let Some(t) = target {
                    match select_target_device(&devs, t) {
                        Ok(d) => {
                            println!("selected: {}", d.id);
                            let id = d.id.clone();
                            let name = d.adv_local_name.clone().or_else(|| d.name.clone());
                            let gi = tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current().block_on(async {
                                    use crate::radio::{BtleplugClient, GattClient};
                                    let c = BtleplugClient::connect(&id, dur).await?;
                                    let s = c.services().await?;
                                    Ok::<_, crate::error::BleError>(
                                        crate::gatt::extract_gatt_fields(&s, &id, name.as_deref()),
                                    )
                                })
                            });
                            match gi {
                                Ok(g) => {
                                    let checks = [crate::checks::check_unauthenticated_writes(&g)];
                                    let score = crate::report::compute_score(&checks);
                                    if let Some(path) = sarif {
                                        let v = crate::sarif::to_sarif(score, &checks, None);
                                        let body = serde_json::to_string_pretty(&v).unwrap();
                                        if let Err(e) = std::fs::write(path, body) {
                                            eprintln!("sarif: {}: {e}", path.display());
                                            std::process::exit(1);
                                        }
                                    }
                                    if *json {
                                        println!("{}", crate::report::to_json(&checks));
                                        if gate(&checks) {
                                            std::process::exit(crate::baseline::EXIT_GATE_FAILED);
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
                                            w.uuid, w.requires_bonding, w.bonding_basis
                                        );
                                    }
                                    for s in &g.subscribe_chars {
                                        println!("  notify {} cccd={:?}", s.uuid, s.cccd);
                                    }
                                    println!("\n{}", crate::report::to_table(&checks));
                                    if gate(&checks) {
                                        std::process::exit(crate::baseline::EXIT_GATE_FAILED);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("gatt: {e}\n  fix: {}", e.remediation());
                                    std::process::exit(1);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("scan: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("scan: {e}\n  fix: {}", e.remediation());
                std::process::exit(1);
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
            select_target_device, BtleplugCentral, BtleplugClient, Central, GattClient,
        };
        let dur = std::time::Duration::from_secs(*timeout);
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let devs = BtleplugCentral.scan(dur).await?;
                let d = select_target_device(&devs, target)?.clone();
                let name = d.adv_local_name.clone().or_else(|| d.name.clone());
                let c = BtleplugClient::connect(&d.id, dur).await?;
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
                std::process::exit(1);
            }
        };
        let inv = crate::recon::inventory(&gi);
        let bs = bluesploit.then(crate::recon::bluesploit_recon);
        if *json {
            let v = serde_json::json!({"inventory": inv, "bluesploit_crosscheck": bs});
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        } else {
            println!(
                "target: {} ({})",
                inv.target,
                inv.target_name.as_deref().unwrap_or("-")
            );
            for s in &inv.services {
                println!("service {}", s.uuid);
                for c in &s.characteristics {
                    println!(
                        "  char {} [{}] writable={} subscribable={}",
                        c.uuid,
                        c.properties.join(","),
                        c.writable,
                        c.subscribable
                    );
                }
            }
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
            std::process::exit(1);
        }
        let Some(target) = target else {
            eprintln!("probe-writes: --target is required");
            std::process::exit(1);
        };
        use crate::radio::{
            select_target_device, BtleplugCentral, BtleplugClient, Central, GattClient,
        };
        let dur = std::time::Duration::from_secs(*timeout);
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let devs = BtleplugCentral.scan(dur).await?;
                let d = select_target_device(&devs, target)?.clone();
                let name = d.adv_local_name.clone().or_else(|| d.name.clone());
                let c = BtleplugClient::connect(&d.id, dur).await?;
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
                            r.uuid, r.service_uuid, r.outcome, r.requires_bonding
                        );
                    }
                    let tag = if finding.passed { "PASS" } else { "FAIL" };
                    println!(
                        "[{tag}] {:?} {}: {}",
                        finding.severity, finding.id, finding.detail
                    );
                }
            }
            Err(e) => {
                eprintln!("probe-writes: {e}\n  fix: {}", e.remediation());
                std::process::exit(1);
            }
        }
        return;
    }
    if let Command::ReadValues { target, timeout } = &cli.command {
        let Some(target) = target else {
            eprintln!("read-values: --target is required");
            std::process::exit(1);
        };
        eprintln!(
            "read-values: reading can change device state (scope: own hardware or written \
             authorization only). SIG services and firmware/DFU characteristics are skipped."
        );
        use crate::radio::{
            select_target_device, BtleplugCentral, BtleplugClient, Central, GattClient,
        };
        let dur = std::time::Duration::from_secs(*timeout);
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let devs = BtleplugCentral.scan(dur).await?;
                let d = select_target_device(&devs, target)?.clone();
                let c = BtleplugClient::connect(&d.id, dur).await?;
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
                            println!("  {} ({}) len={len} \"{preview}\"", r.uuid, r.service_uuid)
                        }
                        Skipped(why) => println!("  {} skipped: {why}", r.uuid),
                        Error(e) => println!("  {} read error: {e}", r.uuid),
                    }
                }
            }
            Err(e) => {
                eprintln!("read-values: {e}\n  fix: {}", e.remediation());
                std::process::exit(1);
            }
        }
        return;
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
    let (name, issue) = cli.command.stub();
    println!("{name}: not yet implemented (#{issue})");
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

/// Rule doc, preceded by the matching finding when a report is given (exit 1 on a bad report).
fn why(id: &str, report: Option<&std::path::Path>) -> Result<String, (i32, String)> {
    let doc = explain(id)?;
    let Some(path) = report else {
        return Ok(doc);
    };
    let v: serde_json::Value = std::fs::read_to_string(path)
        .map_err(|e| (1, format!("why: {}: {e}", path.display())))
        .and_then(|t| serde_json::from_str(&t).map_err(|e| (1, format!("why: bad report: {e}"))))?;
    let f = v["findings"]
        .as_array()
        .and_then(|a| a.iter().find(|f| f["id"] == id))
        .ok_or_else(|| (1, format!("why: no finding '{id}' in {}", path.display())))?;
    let tag = if f["passed"].as_bool().unwrap_or(false) {
        "PASS"
    } else {
        "FAIL"
    };
    Ok(format!(
        "[{tag}] {} {}: {}\n\n{doc}",
        f["severity"].as_str().unwrap_or("?"),
        id,
        f["detail"].as_str().unwrap_or("")
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
            r#"{"score":70,"findings":[{"id":"unauthenticated_writes","severity":"high","passed":false,"detail":"Writable: aaa1"}]}"#,
        )
        .unwrap();
        let out = why("unauthenticated_writes", Some(&p)).unwrap();
        assert!(out.contains("[FAIL] high unauthenticated_writes: Writable: aaa1"));
        assert!(out.contains("## How to verify"));
        assert_eq!(why("mac_rotation", Some(&p)).unwrap_err().0, 1);
        assert_eq!(
            why("mac_rotation", Some(&dir.join("nope"))).unwrap_err().0,
            1
        );
        assert_eq!(why("bogus", None).unwrap_err().0, 2);
    }
}
