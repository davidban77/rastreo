use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "rastreo",
    version,
    about = "Enrichment-aware network discovery"
)]
struct Cli {}

fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();
    Ok(())
}
