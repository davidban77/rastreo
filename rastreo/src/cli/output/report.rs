//! Plain result lines the catalog and validate subcommands write: no theme.

use super::OutputMode;

// An advisory, not chrome: nothing but this names where it looked, which is the only
// explanation an empty listing has.
pub(crate) fn print_catalog_empty(message: &str, mode: OutputMode) {
    if !mode.prints_advisories() {
        return;
    }
    eprintln!("{message}");
}

pub(crate) fn print_scenario_valid(label: &str, mode: OutputMode) {
    if !mode.prints_chrome() {
        return;
    }
    println!("{label}: ok");
}

pub(crate) fn print_validated(total: usize, mode: OutputMode) {
    if !mode.prints_chrome() {
        return;
    }
    println!("{total} scenario(s) validated: all valid");
}

// Ungated on purpose: `-q` suppresses status output, not failures.
pub(crate) fn print_scenario_invalid(label: &str, reason: &str) {
    eprintln!("{label}: {reason}");
}
