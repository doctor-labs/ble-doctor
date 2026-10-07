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
    },
    /// Analyze a capture or device
    Analyze {
        /// Path to a btsnoop/pcap capture
        capture: std::path::PathBuf,
        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
    /// Probe writable characteristics
    ProbeWrites,
    /// Read characteristic values
    ReadValues,
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
    /// Explain a finding
    Why,
}

/// `rules` subcommands.
#[derive(Subcommand, Debug)]
pub enum RulesCmd {
    /// List rules
    List,
    /// Explain a rule
    Explain,
}

impl Command {
    /// Stub message: command name and tracking issue.
    pub fn stub(&self) -> (&'static str, u32) {
        match self {
            Command::Scan { .. } => ("scan", 7),
            Command::Analyze { .. } => ("analyze", 11),
            Command::ProbeWrites => ("probe-writes", 8),
            Command::ReadValues => ("read-values", 9),
            Command::Dfu => ("dfu", 10),
            Command::Doctor => ("doctor", 4),
            Command::Mcp => ("mcp", 12),
            Command::Recon { .. } => ("recon", 21),
            Command::Ctf => ("ctf", 22),
            Command::Baseline => ("baseline", 26),
            Command::Handoff => ("handoff", 27),
            Command::Rules {
                action: RulesCmd::List,
            } => ("rules list", 23),
            Command::Rules {
                action: RulesCmd::Explain,
            } => ("rules explain", 23),
            Command::Why => ("why", 23),
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
    if let Command::Doctor = &cli.command {
        use crate::{capability::Platform, doctor};
        let results = doctor::run_doctor(&doctor::Probes::detect(), Platform::current());
        std::process::exit(doctor::print_report(&results));
    }
    let (name, issue) = cli.command.stub();
    println!("{name}: not yet implemented (#{issue})");
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
    fn rules_list_maps_to_issue_23() {
        let cli = Cli::try_parse_from(["ble-doctor", "rules", "list"]).unwrap();
        assert_eq!(cli.command.stub(), ("rules list", 23));
    }
}
