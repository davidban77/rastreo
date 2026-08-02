use anyhow::{anyhow, Result};

fn main() -> Result<()> {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "all".to_string());
    match cmd.as_str() {
        "generate" => match out_dir()? {
            Some(dir) => xtask::generate_into(&[&dir]),
            None => xtask::generate_all(),
        },
        "render" => xtask::render_all(),
        "gen-gnmi" => xtask::gen_gnmi(),
        "all" => {
            xtask::generate_all()?;
            xtask::render_all()
        }
        other => Err(anyhow!(
            "unknown subcommand: {other}. valid: generate [--out <dir>] | render | gen-gnmi | all"
        )),
    }
}

fn out_dir() -> Result<Option<std::path::PathBuf>> {
    let mut args = std::env::args().skip(2);
    match args.next() {
        None => Ok(None),
        Some(flag) if flag == "--out" => args
            .next()
            .map(std::path::PathBuf::from)
            .map(Some)
            .ok_or_else(|| anyhow!("--out needs a directory")),
        Some(other) => Err(anyhow!("unknown argument: {other}. valid: --out <dir>")),
    }
}
