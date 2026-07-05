use anyhow::{anyhow, Result};

fn main() -> Result<()> {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "all".to_string());
    match cmd.as_str() {
        "generate" => xtask::generate_all(),
        "render" => xtask::render_all(),
        "all" => {
            xtask::generate_all()?;
            xtask::render_all()
        }
        other => Err(anyhow!(
            "unknown subcommand: {other}. valid: generate | render | all"
        )),
    }
}
