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
        &filter_directive(verbose, quiet, std::env::var("RUST_LOG").ok().as_deref()),
        matches!(log_format, LogFormat::Json),
        cli::stderr_supports_colour(),
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
    let directive = filter_directive(verbose, quiet, std::env::var("RUST_LOG").ok().as_deref());
    let filter = EnvFilter::new(directive);
    match log_format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .with_ansi(cli::stderr_supports_colour())
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

/// A `-q` / `-v` typed on this invocation is more specific than ambient `RUST_LOG`, so it wins.
/// The result always parses, so every subscriber can build its filter without a fallback of its own.
fn filter_directive(verbose: u8, quiet: bool, rust_log: Option<&str>) -> String {
    match rust_log {
        Some(directive) if !quiet && verbose == 0 && !directive.is_empty() && parses(directive) => {
            directive.to_string()
        }
        _ => default_level(verbose, quiet).to_string(),
    }
}

fn parses(directive: &str) -> bool {
    tracing_subscriber::EnvFilter::builder()
        .parse(directive)
        .is_ok()
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
    fn default_level_walks_the_verbosity_ladder() {
        assert_eq!(default_level(0, false), "info");
        assert_eq!(default_level(1, false), "debug");
        assert_eq!(default_level(2, false), "trace");
        assert_eq!(default_level(9, false), "trace");
        assert_eq!(default_level(3, true), "error");
    }

    #[test]
    fn rust_log_wins_when_no_verbosity_flag_was_given() {
        assert_eq!(
            filter_directive(0, false, Some("rastreo_core=debug")),
            "rastreo_core=debug"
        );
    }

    #[test]
    fn quiet_beats_rust_log() {
        assert_eq!(filter_directive(0, true, Some("debug")), "error");
    }

    #[test]
    fn verbose_beats_rust_log() {
        assert_eq!(filter_directive(1, false, Some("error")), "debug");
        assert_eq!(filter_directive(2, false, Some("error")), "trace");
    }

    #[test]
    fn an_empty_rust_log_falls_back_to_the_flag_derived_level() {
        assert_eq!(filter_directive(0, false, Some("")), "info");
    }

    #[test]
    fn a_malformed_rust_log_falls_back_to_the_flag_derived_level() {
        assert_eq!(filter_directive(0, false, Some("rastreo=shout")), "info");
        assert_eq!(filter_directive(0, true, Some("rastreo=shout")), "error");
    }

    #[test]
    fn every_directive_handed_to_a_subscriber_parses() {
        for (verbose, quiet, rust_log) in [
            (0, false, None),
            (0, false, Some("rastreo_core=debug")),
            (0, false, Some("rastreo=shout")),
            (1, false, Some("error")),
            (0, true, Some("debug")),
            (9, false, None),
        ] {
            let directive = filter_directive(verbose, quiet, rust_log);
            assert!(parses(&directive), "unparseable directive: {directive}");
        }
    }

    #[test]
    fn an_unset_rust_log_falls_back_to_the_flag_derived_level() {
        assert_eq!(filter_directive(0, false, None), "info");
        assert_eq!(filter_directive(0, true, None), "error");
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
