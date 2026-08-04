mod banner;
mod destination;
mod hints;
mod humanize;
mod progress;
#[cfg(feature = "config")]
mod report;
pub(crate) mod theme;
mod width;

pub(crate) use banner::{accumulate, print_complete, print_start};
#[cfg(feature = "config")]
pub(crate) use banner::{print_aggregate, print_blank, print_failed, print_notice};
pub(crate) use destination::{record_destination, RecordDestination};
#[cfg(feature = "config")]
pub(crate) use hints::enrich_feature_hint;
pub(crate) use hints::{
    enrich_scan_error_hint, print_note, print_refusal_hint, print_runtime_hints, rebuild_hint,
};
pub(crate) use progress::{progress_display_loop, progress_style};
#[cfg(feature = "config")]
pub(crate) use report::{
    print_catalog_empty, print_scenario_invalid, print_scenario_valid, print_validated,
};
pub(crate) use width::stdout_table_width;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

impl Verbosity {
    pub(crate) fn from_flags(quiet: bool, verbose: u8) -> Self {
        if quiet {
            Verbosity::Quiet
        } else if verbose > 0 {
            Verbosity::Verbose
        } else {
            Verbosity::Normal
        }
    }

    pub(crate) fn prints_chrome(self) -> bool {
        self != Verbosity::Quiet
    }

    pub(crate) fn prints_detail(self) -> bool {
        self == Verbosity::Verbose
    }
}

/// What a run says about its result, given the verbosity flags, whether the user asked for machine
/// output, and where the record stream lands relative to stderr. Refusal printers take no gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputMode {
    verbosity: Verbosity,
    machine_output: bool,
    destination: RecordDestination,
}

impl OutputMode {
    pub(crate) fn new(verbosity: Verbosity, machine_output: bool) -> Self {
        Self {
            verbosity,
            machine_output,
            destination: RecordDestination::Separate,
        }
    }

    pub(crate) fn with_record_destination(self, destination: RecordDestination) -> Self {
        Self {
            destination,
            ..self
        }
    }

    pub(crate) fn record_destination(self) -> RecordDestination {
        self.destination
    }

    /// Banners, the progress line, and `validate`'s `ok` lines and summary.
    pub(crate) fn prints_chrome(self) -> bool {
        self.verbosity.prints_chrome()
            && !self.would_land_in_the_record_stream()
            && (!self.machine_output || self.verbosity == Verbosity::Verbose)
    }

    /// Hints, notes, and notices printed while the run is still producing records.
    pub(crate) fn prints_advisories(self) -> bool {
        self.verbosity.prints_chrome() && !self.would_land_in_the_record_stream()
    }

    /// Hints that travel with a refusal, which ends the record stream wherever it lands.
    pub(crate) fn prints_refusal_hints(self) -> bool {
        self.verbosity.prints_chrome()
    }

    pub(crate) fn prints_detail(self) -> bool {
        self.verbosity.prints_detail()
    }

    // Machine records merged into one capture make every stderr line a line the consumer must parse.
    fn would_land_in_the_record_stream(self) -> bool {
        self.machine_output && self.destination == RecordDestination::SharedCapture
    }
}

impl From<Verbosity> for OutputMode {
    fn from(verbosity: Verbosity) -> Self {
        Self::new(verbosity, false)
    }
}

#[cfg(test)]
pub(super) fn rust_sources(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const STDERR_WRITES: [&str; 3] = ["eprintln!", "eprint!", "stderr()"];
    const STDOUT_MACROS: [&str; 2] = ["println!", "print!"];
    const STDOUT_HANDLE: [&str; 1] = ["stdout()"];

    /// Each file outside `cli/output/` that writes an answer to stdout, and how many times.
    const STDOUT_WRITES_OUTSIDE_OUTPUT: [(&str, usize); 2] =
        [("cli/catalog.rs", 1), ("cli/discover.rs", 2)];

    fn src_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn write_sites(body: &str, forms: &[&str]) -> usize {
        forms
            .iter()
            .map(|form| {
                body.match_indices(form)
                    .filter(|(at, _)| {
                        !body[..*at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_')
                    })
                    .count()
            })
            .sum()
    }

    fn sources_outside_output() -> Vec<PathBuf> {
        let src = src_dir();
        let files = rust_sources(&src);
        assert!(files.len() > 3, "expected to walk the crate source tree");
        let output_dir = src.join("cli").join("output");
        files
            .into_iter()
            .filter(|p| !p.starts_with(&output_dir))
            .collect()
    }

    fn body_of(path: &Path) -> String {
        std::fs::read_to_string(path).expect("read source")
    }

    fn relative(path: &Path) -> String {
        path.strip_prefix(src_dir())
            .unwrap_or(path)
            .display()
            .to_string()
    }

    #[test]
    fn no_source_outside_output_writes_to_stderr() {
        let offenders: Vec<String> = sources_outside_output()
            .iter()
            .filter(|p| write_sites(&body_of(p), &STDERR_WRITES) > 0)
            .map(|p| relative(p))
            .collect();

        assert!(
            offenders.is_empty(),
            "terminal output belongs in cli/output/, where Verbosity and the theme are applied. \
             This walks src/ outside cli/output/ for `eprintln!`, `eprint!`, and a `stderr()` \
             handle, so a write cannot dodge it through `writeln!`. Found: {offenders:?}"
        );
    }

    #[test]
    fn only_the_named_answers_write_to_stdout_outside_output() {
        let src = src_dir();
        for (named, _) in STDOUT_WRITES_OUTSIDE_OUTPUT {
            assert!(
                src.join(named).is_file(),
                "{named} is pinned here but does not exist; point the entry at the file that \
                 writes the answer, or drop it"
            );
        }

        let mut by_hand: Vec<String> = Vec::new();
        let mut off_by: Vec<String> = Vec::new();
        for path in sources_outside_output() {
            let body = body_of(&path);
            if write_sites(&body, &STDOUT_HANDLE) > 0 {
                by_hand.push(relative(&path));
            }
            let pinned = STDOUT_WRITES_OUTSIDE_OUTPUT
                .iter()
                .find(|(named, _)| src.join(named) == path)
                .map_or(0, |(_, count)| *count);
            let found = write_sites(&body, &STDOUT_MACROS);
            if found != pinned {
                off_by.push(format!("{}: {found}, pinned at {pinned}", relative(&path)));
            }
        }

        assert!(
            by_hand.is_empty(),
            "a `stdout()` handle writes past the Verbosity gate and past the count below, since \
             `writeln!(std::io::stdout(), ..)` names no print macro. Outside cli/output/ the \
             answers reach stdout through the macro family so this walk can count them. \
             Found: {by_hand:?}"
        );
        assert!(
            off_by.is_empty(),
            "the only stdout writes outside cli/output/ are the answers no verbosity flag reaches \
             — the catalog listing, and the dry-run plan once per --format. Adding, moving, or \
             deleting one means changing the pinned count. Whether a counted write is *gated* is \
             beyond a source walk: the -q runs in tests/quiet_flag.rs and \
             tests/cli_probe_selection.rs are what pin that. Off by: {off_by:?}"
        );
    }

    #[test]
    fn a_stderr_write_is_not_read_as_a_stdout_one() {
        assert_eq!(
            write_sites("eprintln!(\"x\"); eprint!(\"x\");", &STDERR_WRITES),
            2
        );
        assert_eq!(
            write_sites("eprintln!(\"x\"); eprint!(\"x\");", &STDOUT_MACROS),
            0
        );
        assert_eq!(
            write_sites("println!(\"x\"); print!(\"x\");", &STDOUT_MACROS),
            2
        );
        assert_eq!(
            write_sites("println!(\"x\"); print!(\"x\");", &STDERR_WRITES),
            0
        );
        assert_eq!(write_sites("writeln!(out, \"x\");", &STDOUT_MACROS), 0);
        assert_eq!(
            write_sites("writeln!(std::io::stdout(), \"x\");", &STDOUT_HANDLE),
            1
        );
        assert_eq!(
            write_sites("writeln!(std::io::stderr(), \"x\");", &STDERR_WRITES),
            1
        );
        assert_eq!(
            write_sites("writeln!(std::io::stderr(), \"x\");", &STDOUT_HANDLE),
            0
        );
    }

    #[test]
    fn a_name_ending_in_stdout_is_not_read_as_a_stream_handle() {
        assert_eq!(
            write_sites("fn a_run_writes_to_stdout() {}", &STDOUT_HANDLE),
            0
        );
        assert_eq!(
            write_sites("theme::stderr_supports_colour()", &STDERR_WRITES),
            0
        );
        // main.rs hands tracing the fn item, not a handle; the walk covers src/ only because of it.
        assert_eq!(
            write_sites(".with_writer(std::io::stderr)", &STDERR_WRITES),
            0
        );
    }

    #[test]
    fn progress_and_completion_render_the_same_elapsed_identically() {
        for elapsed in [
            Duration::from_millis(820),
            Duration::from_millis(4_200),
            Duration::from_secs(63),
            Duration::from_secs(7_200),
        ] {
            let mut p = rastreo_core::DiscoveryProgress::default();
            p.targets_total = 10;
            p.targets_completed = 1;
            p.elapsed_ms = elapsed.as_millis();
            let progress_line = theme::strip_ansi(&progress::format_progress_line(&p));

            let mut s = rastreo_core::DiscoverySummary::default();
            s.elapsed = elapsed;
            let banner_line = theme::strip_ansi(&banner::complete_line("discover", &s));

            let rendered = humanize::duration(elapsed);
            assert!(
                progress_line.contains(&format!("elapsed: {rendered}")),
                "progress line disagrees for {elapsed:?}: {progress_line}"
            );
            assert!(
                banner_line.contains(&format!("completed in {rendered}")),
                "completion banner disagrees for {elapsed:?}: {banner_line}"
            );
        }
    }

    #[test]
    fn no_flags_is_normal() {
        assert_eq!(Verbosity::from_flags(false, 0), Verbosity::Normal);
    }

    #[test]
    fn a_single_v_is_verbose() {
        assert_eq!(Verbosity::from_flags(false, 1), Verbosity::Verbose);
    }

    #[test]
    fn repeated_v_stays_verbose_because_extra_levels_only_raise_tracing() {
        assert_eq!(Verbosity::from_flags(false, 2), Verbosity::Verbose);
        assert_eq!(Verbosity::from_flags(false, 9), Verbosity::Verbose);
    }

    #[test]
    fn quiet_wins_over_verbose() {
        assert_eq!(Verbosity::from_flags(true, 3), Verbosity::Quiet);
    }

    #[test]
    fn quiet_prints_neither_chrome_nor_detail() {
        assert!(!Verbosity::Quiet.prints_chrome());
        assert!(!Verbosity::Quiet.prints_detail());
    }

    #[test]
    fn normal_prints_chrome_without_detail() {
        assert!(Verbosity::Normal.prints_chrome());
        assert!(!Verbosity::Normal.prints_detail());
    }

    #[test]
    fn verbose_prints_both() {
        assert!(Verbosity::Verbose.prints_chrome());
        assert!(Verbosity::Verbose.prints_detail());
    }

    #[test]
    fn human_output_prints_chrome_and_advisories() {
        let mode = OutputMode::new(Verbosity::Normal, false);
        assert!(mode.prints_chrome());
        assert!(mode.prints_advisories());
    }

    #[test]
    fn machine_output_drops_chrome_but_keeps_advisories() {
        let mode = OutputMode::new(Verbosity::Normal, true);
        assert!(!mode.prints_chrome());
        assert!(mode.prints_advisories());
    }

    #[test]
    fn verbose_restores_chrome_under_machine_output() {
        let mode = OutputMode::new(Verbosity::Verbose, true);
        assert!(mode.prints_chrome());
        assert!(mode.prints_detail());
    }

    #[test]
    fn quiet_silences_machine_and_human_output_alike() {
        for machine_output in [false, true] {
            let mode = OutputMode::new(Verbosity::Quiet, machine_output);
            assert!(!mode.prints_chrome());
            assert!(!mode.prints_advisories());
            assert!(!mode.prints_detail());
            assert!(!mode.prints_refusal_hints());
        }
    }

    #[test]
    fn a_bare_verbosity_converts_to_human_output() {
        assert_eq!(
            OutputMode::from(Verbosity::Normal),
            OutputMode::new(Verbosity::Normal, false)
        );
    }

    #[test]
    fn a_bare_verbosity_assumes_the_streams_are_separate() {
        assert!(OutputMode::from(Verbosity::Normal).prints_advisories());
    }

    #[test]
    fn machine_records_merged_into_one_capture_silence_the_chrome_and_the_advisories() {
        let mode = OutputMode::new(Verbosity::Normal, true)
            .with_record_destination(RecordDestination::SharedCapture);
        assert!(!mode.prints_advisories());
        assert!(!mode.prints_chrome());
    }

    #[test]
    fn verbose_does_not_restore_chrome_into_a_merged_machine_capture() {
        let mode = OutputMode::new(Verbosity::Verbose, true)
            .with_record_destination(RecordDestination::SharedCapture);
        assert!(!mode.prints_chrome());
        assert!(!mode.prints_advisories());
    }

    #[test]
    fn a_refusal_hint_reaches_the_merged_capture_the_advisories_are_kept_out_of() {
        for verbosity in [Verbosity::Normal, Verbosity::Verbose] {
            let mode = OutputMode::new(verbosity, true)
                .with_record_destination(RecordDestination::SharedCapture);
            assert!(!mode.prints_advisories());
            assert!(mode.prints_refusal_hints());
        }
    }

    #[test]
    fn every_destination_keeps_its_refusal_hints() {
        for destination in [
            RecordDestination::Separate,
            RecordDestination::SharedTerminal,
            RecordDestination::SharedCapture,
        ] {
            for machine_output in [false, true] {
                let mode = OutputMode::new(Verbosity::Normal, machine_output)
                    .with_record_destination(destination);
                assert!(
                    mode.prints_refusal_hints(),
                    "{destination:?}, machine_output: {machine_output}"
                );
            }
        }
    }

    #[test]
    fn a_bare_verbosity_assumes_the_streams_are_separate_until_told_otherwise() {
        assert_eq!(
            OutputMode::from(Verbosity::Normal).record_destination(),
            RecordDestination::Separate
        );
    }

    #[test]
    fn the_record_destination_is_read_back_as_it_was_set() {
        let mode = OutputMode::from(Verbosity::Normal)
            .with_record_destination(RecordDestination::SharedTerminal);
        assert_eq!(mode.record_destination(), RecordDestination::SharedTerminal);
    }

    #[test]
    fn human_records_merged_into_one_capture_keep_their_advisories() {
        let mode = OutputMode::new(Verbosity::Normal, false)
            .with_record_destination(RecordDestination::SharedCapture);
        assert!(mode.prints_advisories());
        assert!(mode.prints_chrome());
    }

    #[test]
    fn machine_records_on_a_shared_terminal_keep_their_advisories() {
        let mode = OutputMode::new(Verbosity::Normal, true)
            .with_record_destination(RecordDestination::SharedTerminal);
        assert!(mode.prints_advisories());
    }

    #[test]
    fn verbose_restores_chrome_on_a_terminal_that_also_carries_json() {
        let mode = OutputMode::new(Verbosity::Verbose, true)
            .with_record_destination(RecordDestination::SharedTerminal);
        assert!(mode.prints_chrome());
    }

    #[test]
    fn machine_records_on_their_own_stream_keep_every_stderr_printer() {
        let mode = OutputMode::new(Verbosity::Normal, true)
            .with_record_destination(RecordDestination::Separate);
        assert!(mode.prints_advisories());
    }
}
