#[cfg(feature = "config")]
pub mod catalog;
pub mod discover;
#[cfg(feature = "config")]
pub mod validate;

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

// One Command per process from argv; clap cannot derive Args on a boxed variant, so the size gap is harmless.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Probe one or more targets and emit DeviceRecord events.
    Discover(DiscoverArgs),
    /// Inspect the scenario catalog.
    #[cfg(feature = "config")]
    Catalog(CatalogArgs),
    /// Validate a scenario file offline: config shape and sink config, no probing or connecting.
    #[cfg(feature = "config")]
    Validate(validate::ValidateArgs),
}

#[cfg(feature = "config")]
#[derive(clap::Args, Debug)]
pub struct CatalogArgs {
    #[command(subcommand)]
    pub action: CatalogAction,
}

#[cfg(feature = "config")]
#[derive(Subcommand, Debug)]
pub enum CatalogAction {
    /// List every catalog scenario (@name) with its resolved path.
    List,
}

pub async fn run(cli: Cli, cancel: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    match cli.command {
        Command::Discover(args) => discover::run(args, cancel).await,
        #[cfg(feature = "config")]
        Command::Catalog(args) => match args.action {
            CatalogAction::List => catalog::run_list(),
        },
        #[cfg(feature = "config")]
        Command::Validate(args) => validate::run(args),
    }
}
