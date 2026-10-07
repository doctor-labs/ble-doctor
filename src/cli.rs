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
    Scan,
    /// Analyze a capture or device
    Analyze,
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
            Command::Scan => ("scan", 7),
            Command::Analyze => ("analyze", 11),
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
