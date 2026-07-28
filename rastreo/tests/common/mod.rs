use std::process::Command;

/// Every variable the binary reads that would otherwise leak the developer's shell into a golden.
const SCRUBBED: &[&str] = &[
    "RUST_LOG",
    "RASTREO_LOG_FORMAT",
    "RASTREO_FORMAT",
    "RASTREO_CATALOG_DIR",
    "XDG_CONFIG_HOME",
    "RASTREO_ASCII",
    "LC_ALL",
    "LC_CTYPE",
    "LANG",
    "NO_COLOR",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "FORCE_COLOR",
    "COLORTERM",
    "TERM",
    "TERM_PROGRAM",
    "IGNORE_IS_TERMINAL",
    "RASTREO_OTLP_ENDPOINT",
    "RASTREO_OTLP_METRICS_ENABLED",
    "RASTREO_OTLP_LOGS_ENABLED",
    "RASTREO_OTLP_TRACES_ENABLED",
    "RASTREO_OTLP_METRICS_INTERVAL_SECS",
    "RASTREO_OTLP_SERVICE_NAME",
    "RASTREO_OTLP_PROTOCOL",
    "RASTREO_SNMP_COMMUNITY",
];

pub fn rastreo() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rastreo"));
    for var in SCRUBBED {
        cmd.env_remove(var);
    }
    cmd
}
