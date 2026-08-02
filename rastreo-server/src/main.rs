use std::future::IntoFuture;
use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use rastreo_core::{GuardedResolver, HickoryResolver, Resolver};
use rastreo_server::{
    build_app_with_timeout, spawn_sink_probe,
    state::{
        AppState, AuthConfig, MetricsConfig, OtlpConfig, ReadinessConfig, ShutdownConfig,
        SinkProbeConfig, TargetGuardConfig,
    },
};
use tokio::sync::watch;

#[cfg(test)]
mod argv;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
enum LogFormat {
    /// Human-readable text output (default).
    #[default]
    Text,
    /// One JSON object per line, suitable for Loki / ELK / Splunk ingestion.
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "rastreo-server",
    version,
    about = "HTTP control plane for rastreo"
)]
struct Cli {
    #[arg(long, default_value_t = 8080, env = "RASTREO_SERVER_PORT")]
    port: u16,

    #[arg(long, default_value = "0.0.0.0", env = "RASTREO_SERVER_BIND")]
    bind: IpAddr,

    #[arg(
        long,
        env = "RASTREO_SERVER_REQUEST_TIMEOUT_MS",
        default_value_t = 60_000,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    request_timeout_ms: u64,

    /// Log line format: `text` (default) or `json` for structured ingestion.
    #[arg(
        long,
        value_enum,
        env = "RASTREO_LOG_FORMAT",
        default_value_t = LogFormat::Text,
    )]
    log_format: LogFormat,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let otlp_config =
        OtlpConfig::from_env("rastreo-server", true).context("failed to load OTLP config")?;
    init_tracing(cli.log_format, otlp_config.as_ref())?;

    let guard = TargetGuardConfig::from_env().context("failed to load target-guard config")?;
    let base_resolver =
        HickoryResolver::from_system().context("failed to initialize system resolver")?;
    let resolver: Arc<dyn Resolver> = Arc::new(GuardedResolver::new(
        Arc::new(base_resolver),
        guard.allowlist.clone(),
        guard.max_total_hosts,
    ));
    let readiness = ReadinessConfig::from_env().context("failed to load readiness config")?;
    let metrics_config = MetricsConfig::from_env().context("failed to load metrics config")?;
    let auth = AuthConfig::from_env().context("failed to load auth config")?;
    let sink_probe = SinkProbeConfig::from_env().context("failed to load sink-probe config")?;
    let shutdown = ShutdownConfig::from_env().context("failed to load shutdown config")?;
    let max_result_bytes = rastreo_server::state::max_result_bytes_from_env()
        .context("failed to load result-capture limit")?;
    let state = AppState::with_config(resolver, readiness, metrics_config)
        .with_auth(auth)
        .with_body_limit(guard.max_body_bytes)
        .with_result_limit(max_result_bytes);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (state, probe_handle) = spawn_sink_probe(state, &sink_probe, shutdown_rx.clone()).await;

    // Guard must outlive the axum serve loop so pending OTLP exports flush on shutdown.
    let _otlp_guard = init_otlp(
        otlp_config.as_ref(),
        Arc::clone(&state.metrics),
        Arc::clone(&state.sink_reachability),
    )?;

    let app = build_app_with_timeout(state, Duration::from_millis(cli.request_timeout_ms));
    let addr = SocketAddr::new(cli.bind, cli.port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to {addr}"))?;
    tracing::info!(%addr, "rastreo-server listening");

    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = signal_tx.send(true);
    });

    let mut shutdown_wait = shutdown_rx.clone();
    let graceful = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_wait.changed().await;
        })
        .into_future();

    let mut hard_timeout_rx = shutdown_rx.clone();
    let hard_timeout = shutdown.timeout;
    tokio::select! {
        result = graceful => {
            result?;
            if let Some(handle) = probe_handle {
                let _ = handle.await;
            }
        }
        _ = async move {
            // The hard-timeout clock starts on the signal, not at startup, so an idle server is never force-exited early.
            let _ = hard_timeout_rx.wait_for(|drain| *drain).await;
            tokio::time::sleep(hard_timeout).await;
        } => {
            tracing::warn!(
                timeout_secs = hard_timeout.as_secs(),
                "graceful shutdown exceeded timeout; forcing exit"
            );
            std::process::exit(0);
        }
    }
    Ok(())
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
            tracing::warn!("SIGINT received, draining inflight requests and probe task");
            return;
        }
    };

    tokio::select! {
        _ = sigint => tracing::warn!("SIGINT received, draining inflight requests and probe task"),
        _ = sigterm.recv() => tracing::warn!("SIGTERM received, draining inflight requests and probe task"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::warn!("SIGINT received, draining inflight requests and probe task");
    }
}

const DEFAULT_LOG_LEVEL: &str = "info";

// NO_COLOR / CLICOLOR_FORCE are deliberately not consulted: the server carries no owo-colors dep.
fn stderr_is_terminal() -> bool {
    std::io::stderr().is_terminal()
}

fn filter_directive(rust_log: Option<&str>) -> String {
    rust_log
        .filter(|d| !d.is_empty() && tracing_subscriber::EnvFilter::builder().parse(d).is_ok())
        .unwrap_or(DEFAULT_LOG_LEVEL)
        .to_string()
}

fn env_filter_directive() -> String {
    filter_directive(std::env::var("RUST_LOG").ok().as_deref())
}

#[cfg(feature = "otlp")]
fn init_tracing(log_format: LogFormat, otlp: Option<&OtlpConfig>) -> anyhow::Result<()> {
    rastreo_core::observability::otlp::init_tracing(
        &env_filter_directive(),
        matches!(log_format, LogFormat::Json),
        stderr_is_terminal(),
        otlp,
    )
}

#[cfg(not(feature = "otlp"))]
fn init_tracing(log_format: LogFormat, _otlp: Option<&OtlpConfig>) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::new(env_filter_directive());
    match log_format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .with_ansi(stderr_is_terminal())
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

#[cfg(feature = "otlp")]
fn init_otlp(
    config: Option<&OtlpConfig>,
    metrics: Arc<rastreo_server::state::Metrics>,
    sink_reachability: Arc<rastreo_server::state::SinkReachability>,
) -> anyhow::Result<Option<rastreo_server::observability::OtlpGuard>> {
    let Some(cfg) = config else { return Ok(None) };
    let mut guard =
        rastreo_server::observability::init_metrics_only(cfg, metrics, sink_reachability)?;
    if let Some(provider) = rastreo_core::observability::otlp::stashed_logger_provider() {
        rastreo_core::observability::otlp::attach_logger(&mut guard, provider);
    }
    if let Some(provider) = rastreo_core::observability::otlp::stashed_tracer_provider() {
        rastreo_core::observability::otlp::attach_tracer(&mut guard, provider);
    }
    Ok(Some(guard))
}

#[cfg(not(feature = "otlp"))]
fn init_otlp(
    _config: Option<&OtlpConfig>,
    _metrics: Arc<rastreo_server::state::Metrics>,
    _sink_reachability: Arc<rastreo_server::state::SinkReachability>,
) -> anyhow::Result<Option<()>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    fn parse_cli<I, S>(argv: I) -> std::result::Result<Cli, clap::Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString> + Clone,
    {
        argv::parse_without_env(argv)
    }

    #[test]
    fn args_request_timeout_ms_defaults_to_60000() {
        let cli = parse_cli(["rastreo-server"]).expect("default parse");
        assert_eq!(cli.request_timeout_ms, 60_000);
    }

    #[test]
    fn args_request_timeout_ms_rejects_zero() {
        let result = parse_cli(["rastreo-server", "--request-timeout-ms", "0"]);
        assert!(result.is_err(), "zero must be rejected");
    }

    #[test]
    fn args_request_timeout_ms_accepts_explicit_value() {
        let cli =
            parse_cli(["rastreo-server", "--request-timeout-ms", "30000"]).expect("explicit parse");
        assert_eq!(cli.request_timeout_ms, 30_000);
    }

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
    fn rust_log_drives_the_filter_when_it_parses() {
        assert_eq!(
            filter_directive(Some("rastreo_core=debug")),
            "rastreo_core=debug"
        );
    }

    #[test]
    fn an_unset_empty_or_malformed_rust_log_falls_back_to_info() {
        assert_eq!(filter_directive(None), "info");
        assert_eq!(filter_directive(Some("")), "info");
        assert_eq!(filter_directive(Some("rastreo=shout")), "info");
    }

    #[test]
    fn cli_defaults_log_format_to_text() {
        let cli = parse_cli(["rastreo-server"]).expect("default parse");
        assert_eq!(cli.log_format, LogFormat::Text);
    }

    #[test]
    fn cli_accepts_log_format_json() {
        let cli = parse_cli(["rastreo-server", "--log-format", "json"]).expect("explicit parse");
        assert_eq!(cli.log_format, LogFormat::Json);
    }

    #[test]
    fn cli_rejects_unknown_log_format() {
        let result = parse_cli(["rastreo-server", "--log-format", "yaml"]);
        assert!(result.is_err(), "unknown log format must be rejected");
    }
}
