use clap::Parser;

mod cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let parsed = cli::Cli::parse();
    init_tracing(parsed.verbose, parsed.quiet);

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    let signal_tx = cancel_tx.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = signal_tx.send(true);
    });

    cli::run(parsed, cancel_rx).await
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let sigint = tokio::signal::ctrl_c();
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(?e, "could not install SIGTERM handler; SIGINT only");
            sigint.await.ok();
            tracing::warn!("SIGINT received, draining and flushing sink");
            return;
        }
    };

    tokio::select! {
        _ = sigint => tracing::warn!("SIGINT received, draining and flushing sink"),
        _ = sigterm.recv() => tracing::warn!("SIGTERM received, draining and flushing sink"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::warn!("SIGINT received, draining and flushing sink");
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
