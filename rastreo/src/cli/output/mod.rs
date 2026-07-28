mod banner;
mod hints;
mod humanize;
mod progress;
#[cfg(feature = "config")]
mod report;
pub(crate) mod theme;
mod width;

#[cfg(feature = "config")]
pub(crate) use banner::ScenarioTally;
#[cfg(feature = "config")]
pub(crate) use banner::{accumulate, print_aggregate, print_blank, print_failed, print_notice};
pub(crate) use banner::{print_complete, print_start};
#[cfg(feature = "config")]
pub(crate) use hints::enrich_feature_hint;
pub(crate) use hints::{
    enrich_scan_error_hint, print_hint, print_note, print_runtime_hints, rebuild_hint,
};
pub(crate) use progress::{progress_display_loop, progress_style};
#[cfg(feature = "config")]
pub(crate) use report::{print_catalog_empty, print_scenario_invalid};
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

/// What stderr carries, given the verbosity flags and whether the user asked for machine output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputMode {
    verbosity: Verbosity,
    machine_output: bool,
}

impl OutputMode {
    pub(crate) fn new(verbosity: Verbosity, machine_output: bool) -> Self {
        Self {
            verbosity,
            machine_output,
        }
    }

    /// Banners and the progress line.
    pub(crate) fn prints_chrome(self) -> bool {
        self.verbosity.prints_chrome()
            && (!self.machine_output || self.verbosity == Verbosity::Verbose)
    }

    /// Hints, notes, and notices.
    pub(crate) fn prints_advisories(self) -> bool {
        self.verbosity.prints_chrome()
    }

    pub(crate) fn prints_detail(self) -> bool {
        self.verbosity.prints_detail()
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
    use std::time::Duration;

    #[test]
    fn no_cli_source_outside_output_writes_to_stderr() {
        let cli = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli");
        let files = rust_sources(&cli);
        assert!(files.len() > 3, "expected to walk the cli source tree");

        let output_dir = cli.join("output");
        let offenders: Vec<String> = files
            .iter()
            .filter(|p| !p.starts_with(&output_dir))
            .filter(|p| {
                let body = std::fs::read_to_string(p).expect("read source");
                body.contains("eprintln!") || body.contains("eprint!")
            })
            .map(|p| p.display().to_string())
            .collect();

        assert!(
            offenders.is_empty(),
            "terminal output belongs in cli/output/, where Verbosity and the theme are applied; \
             found direct stderr writes in {offenders:?}"
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
        }
    }

    #[test]
    fn a_bare_verbosity_converts_to_human_output() {
        assert_eq!(
            OutputMode::from(Verbosity::Normal),
            OutputMode::new(Verbosity::Normal, false)
        );
    }
}
