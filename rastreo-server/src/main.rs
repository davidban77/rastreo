use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use rastreo_core::{HickoryResolver, Resolver};
use rastreo_server::{build_app, state::AppState};

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

    let app = build_app(state);
    let addr = SocketAddr::new(cli.bind, cli.port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to {addr}"))?;
    tracing::info!(%addr, "rastreo-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
