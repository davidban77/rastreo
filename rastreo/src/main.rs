use anyhow::Context;
use clap::Parser;

mod cli;
mod otlp;

pub use cli::LogFormat;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let parsed = cli::Cli::parse();
    let otlp_config = otlp::config_from_env().context("failed to load OTLP config")?;
    init_tracing(
        parsed.verbose,
        parsed.quiet,
        parsed.log_format,
        otlp_config.as_ref(),
    )?;
    // Guard must outlive the discover run so pending OTLP exports flush before we exit.
    let _otlp_guard = init_otlp_metrics(otlp_config.as_ref())?;

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

#[cfg(feature = "otlp")]
fn init_tracing(
    verbose: u8,
    quiet: bool,
    log_format: LogFormat,
    otlp_config: Option<&otlp::OtlpConfig>,
) -> anyhow::Result<()> {
    rastreo_core::observability::otlp::init_tracing(
        default_level(verbose, quiet),
        matches!(log_format, LogFormat::Json),
        otlp_config,
    )
}

#[cfg(not(feature = "otlp"))]
fn init_tracing(
    verbose: u8,
    quiet: bool,
    log_format: LogFormat,
    _otlp_config: Option<&otlp::OtlpConfig>,
) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    let level = default_level(verbose, quiet);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    match log_format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .json()
                .init();
        }
    }
    Ok(())
}

fn default_level(verbose: u8, quiet: bool) -> &'static str {
    if quiet {
        "error"
    } else {
        match verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    }
}

#[cfg(feature = "otlp")]
fn init_otlp_metrics(config: Option<&otlp::OtlpConfig>) -> anyhow::Result<Option<otlp::OtlpGuard>> {
    if config.is_none() {
        return Ok(None);
    }
    let mut guard = otlp::OtlpGuard::empty();
    if let Some(provider) = otlp::stashed_logger_provider() {
        otlp::attach_logger(&mut guard, provider);
    }
    if let Some(provider) = otlp::stashed_tracer_provider() {
        otlp::attach_tracer(&mut guard, provider);
    }
    Ok(Some(guard))
}

#[cfg(not(feature = "otlp"))]
fn init_otlp_metrics(_config: Option<&otlp::OtlpConfig>) -> anyhow::Result<Option<()>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    #[test]
    fn log_format_default_is_text() {
        assert_eq!(LogFormat::default(), LogFormat::Text);
    }

    #[test]
    fn log_format_parses_from_str_text_and_json() {
        assert_eq!(
            LogFormat::from_str("text", true).expect("text parses"),
            LogFormat::Text,
        );
        assert_eq!(
            LogFormat::from_str("json", true).expect("json parses"),
            LogFormat::Json,
        );
    }

    #[test]
    fn log_format_rejects_unknown_value() {
        assert!(LogFormat::from_str("yaml", true).is_err());
    }

    #[test]
    fn cli_defaults_log_format_to_text() {
        // SAFETY: no other test in this binary reads or writes RASTREO_LOG_FORMAT concurrently;
        // clearing an ambient value protects the default-parse assertion against a caller
        // (e.g., `RASTREO_LOG_FORMAT=json cargo test`) that would otherwise flip the default.
        unsafe {
            std::env::remove_var("RASTREO_LOG_FORMAT");
        }
        let cli =
            cli::Cli::try_parse_from(["rastreo", "discover", "--target", "127.0.0.1", "-p", "22"])
                .expect("default parse");
        assert_eq!(cli.log_format, LogFormat::Text);
    }

    #[test]
    fn cli_accepts_log_format_json() {
        let cli = cli::Cli::try_parse_from([
            "rastreo",
            "--log-format",
            "json",
            "discover",
            "--target",
            "127.0.0.1",
            "-p",
            "22",
        ])
        .expect("explicit parse");
        assert_eq!(cli.log_format, LogFormat::Json);
    }

    #[test]
    fn cli_rejects_unknown_log_format() {
        let result = cli::Cli::try_parse_from([
            "rastreo",
            "--log-format",
            "yaml",
            "discover",
            "--target",
            "127.0.0.1",
            "-p",
            "22",
        ]);
        assert!(result.is_err(), "unknown log format must be rejected");
    }
}
