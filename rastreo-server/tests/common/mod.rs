use std::process::Command;

/// The binary under test with an empty environment: nothing reaches it that the test did not set.
pub fn rastreo_server() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rastreo-server"));
    cmd.env_clear();
    cmd
}
