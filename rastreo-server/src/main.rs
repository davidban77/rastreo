use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use rastreo_core::{HickoryResolver, Resolver};
use rastreo_server::{build_app_with_timeout, state::AppState};

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let resolver: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().context("failed to initialize system resolver")?);
    let state = AppState::new(resolver);

    let app = build_app_with_timeout(state, Duration::from_millis(cli.request_timeout_ms));
    let addr = SocketAddr::new(cli.bind, cli.port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to {addr}"))?;
    tracing::info!(%addr, "rastreo-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn args_request_timeout_ms_defaults_to_60000() {
        let cli = Cli::try_parse_from(["rastreo-server"]).expect("default parse");
        assert_eq!(cli.request_timeout_ms, 60_000);
    }

    #[test]
    fn args_request_timeout_ms_rejects_zero() {
        let result = Cli::try_parse_from(["rastreo-server", "--request-timeout-ms", "0"]);
        assert!(result.is_err(), "zero must be rejected");
    }

    #[test]
    fn args_request_timeout_ms_accepts_explicit_value() {
        let cli = Cli::try_parse_from(["rastreo-server", "--request-timeout-ms", "30000"])
            .expect("explicit parse");
        assert_eq!(cli.request_timeout_ms, 30_000);
    }
}
