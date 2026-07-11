#[cfg(feature = "config")]
pub mod catalog;
pub mod discover;

use anyhow::Result;
use clap::{Parser, Subcommand};

use discover::DiscoverArgs;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    /// Human-readable text output (default).
    #[default]
    Text,
    /// One JSON object per line, suitable for Loki / ELK / Splunk ingestion.
    Json,
}

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

    /// Log line format: `text` (default) or `json` for structured ingestion.
    #[arg(
        long,
        value_enum,
        env = "RASTREO_LOG_FORMAT",
        default_value_t = LogFormat::Text,
        global = true
    )]
    pub log_format: LogFormat,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Probe one or more targets and emit DeviceRecord events.
    Discover(DiscoverArgs),
}

pub async fn run(cli: Cli, cancel: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    match cli.command {
        Command::Discover(args) => discover::run(args, cancel).await,
    }
}
