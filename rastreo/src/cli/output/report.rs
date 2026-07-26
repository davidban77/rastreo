//! Result lines the catalog and validate subcommands write to stderr: no theme, no verbosity gate.

pub(crate) fn print_catalog_empty(message: &str) {
    eprintln!("{message}");
}

pub(crate) fn print_scenario_invalid(label: &str, reason: &str) {
    eprintln!("{label}: {reason}");
}
