pub mod discover;

use anyhow::Result;
use clap::{Parser, Subcommand};

use discover::DiscoverArgs;

#[derive(Parser, Debug)]
#[command(
    name = "rastreo",
    version,
    about = "Enrichment-aware network discovery"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Increase log verbosity (can be repeated: -v, -vv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress all output except errors.
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Probe one or more targets and emit DeviceRecord events.
    Discover(DiscoverArgs),
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Discover(args) => discover::run(args).await,
    }
}
