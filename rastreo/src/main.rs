use clap::Parser;

mod cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let parsed = cli::Cli::parse();
    init_tracing(parsed.verbose, parsed.quiet);

    tokio::select! {
        result = cli::run(parsed) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::warn!("interrupted, shutting down");
            Ok(())
        }
    }
}

fn init_tracing(verbose: u8, quiet: bool) {
    use tracing_subscriber::EnvFilter;
    let level = if quiet {
        "error"
    } else {
        match verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    // Stderr keeps stdout clean for NDJSON output from the stdout sink.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();
}
