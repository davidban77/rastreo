use axum::{routing::get, Json, Router};
use clap::Parser;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};

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

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
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

    let app = Router::new().route("/health", get(health));
    let addr = SocketAddr::new(cli.bind, cli.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "rastreo-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
