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
    /// Recon a target
    Recon,
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
            Command::Recon => ("recon", 21),
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
    if let Command::Scan { target, timeout } = &cli.command {
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
                        Ok(d) => println!("selected: {}", d.id),
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
