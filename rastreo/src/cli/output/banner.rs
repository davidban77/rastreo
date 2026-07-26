use rastreo_core::{DiscoveryPlan, DiscoverySummary};

use super::humanize;
use super::theme::{self, glyphs};
use super::Verbosity;

const DETAIL_LABEL_WIDTH: usize = 14;

pub(crate) fn print_start(plan: &DiscoveryPlan, target_specs: usize, verbosity: Verbosity) {
    if !verbosity.prints_chrome() {
        return;
    }
    eprintln!("{}", start_line(plan, target_specs));
}

pub(crate) fn print_complete(label: &str, summary: &DiscoverySummary, verbosity: Verbosity) {
    if !verbosity.prints_chrome() {
        return;
    }
    eprintln!("{}", complete_line(label, summary));
    print_detail(summary, verbosity);
}

#[cfg(feature = "config")]
pub(crate) fn print_aggregate(
    tally: ScenarioTally,
    summary: &DiscoverySummary,
    verbosity: Verbosity,
) {
    if !verbosity.prints_chrome() {
        return;
    }
    eprintln!("{}", aggregate_line(tally, summary));
    print_detail(summary, verbosity);
}

fn print_detail(summary: &DiscoverySummary, verbosity: Verbosity) {
    if !verbosity.prints_detail() {
        return;
    }
    for line in detail_lines(summary) {
        eprintln!("{line}");
    }
}

#[cfg(feature = "config")]
pub(crate) fn print_blank(verbosity: Verbosity) {
    if !verbosity.prints_chrome() {
        return;
    }
    eprintln!();
}

// Ungated on purpose: `-q` suppresses status output, not failures.
#[cfg(feature = "config")]
pub(crate) fn print_failed(label: &str, error: &str) {
    eprintln!("{}", failed_line(label, error));
}

#[cfg(feature = "config")]
pub(crate) fn print_notice(text: &str, verbosity: Verbosity) {
    if !verbosity.prints_chrome() {
        return;
    }
    eprintln!("{} {}", theme::label(glyphs().bullet), theme::label(text));
}

#[cfg(feature = "config")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ScenarioTally {
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
}

#[cfg(feature = "config")]
fn aggregate_label(tally: ScenarioTally) -> String {
    if tally.completed == tally.total {
        format!("{} scenarios", tally.total)
    } else {
        format!("{} of {} scenarios", tally.completed, tally.total)
    }
}

#[cfg(feature = "config")]
fn aggregate_line(tally: ScenarioTally, summary: &DiscoverySummary) -> String {
    completion_line(
        &aggregate_label(tally),
        summary,
        needs_attention(summary) || tally.failed > 0,
    )
}

// sink_type is deliberately not carried: scenarios in one file may write to different sinks.
#[cfg(feature = "config")]
pub(crate) fn accumulate(agg: &mut DiscoverySummary, scenario: &DiscoverySummary) {
    agg.targets_resolved += scenario.targets_resolved;
    agg.probe_attempts += scenario.probe_attempts;
    agg.records_emitted += scenario.records_emitted;
    agg.links_emitted += scenario.links_emitted;
    agg.profiles_emitted += scenario.profiles_emitted;
    agg.dlq_records += scenario.dlq_records;
    agg.cancelled |= scenario.cancelled;
    agg.elapsed += scenario.elapsed;
    for (kind, n) in &scenario.error_counts {
        *agg.error_counts.entry(*kind).or_insert(0) += n;
    }
    if agg.first_probe_error.is_none() {
        agg.first_probe_error = scenario.first_probe_error.clone();
    }
    for entry in &scenario.probes_by_kind {
        match agg.probes_by_kind.iter_mut().find(|e| e.kind == entry.kind) {
            Some(existing) => {
                existing.attempted += entry.attempted;
                existing.errored += entry.errored;
            }
            None => agg.probes_by_kind.push(entry.clone()),
        }
    }
    for (sink, class, n) in &scenario.dlq_records_by_type_and_class {
        match agg
            .dlq_records_by_type_and_class
            .iter_mut()
            .find(|(s, c, _)| s == sink && c == class)
        {
            Some(existing) => existing.2 += n,
            None => agg.dlq_records_by_type_and_class.push((*sink, *class, *n)),
        }
    }
}

fn segment(label: &str, value: impl std::fmt::Display) -> String {
    format!("{} {}", theme::label(label), theme::value(value))
}

fn start_line(plan: &DiscoveryPlan, target_specs: usize) -> String {
    let probers = if plan.probers.is_empty() {
        "<none>".to_string()
    } else {
        plan.probers.join(", ")
    };
    let segments = [
        segment("targets:", target_specs),
        segment("probes:", probers),
        segment("concurrency:", plan.max_concurrent),
        segment("timeout:", format!("{}ms", plan.timeout_ms)),
        segment("sink:", &plan.sink),
    ];
    format!(
        "{} {}  {}",
        theme::ok(glyphs().start),
        theme::name(&plan.scenario),
        segments.join(&theme::sep())
    )
}

// Probe faults are expected data on a real scan; only a scan-level problem tints the banner.
fn needs_attention(summary: &DiscoverySummary) -> bool {
    summary.cancelled || summary.dlq_records > 0
}

pub(super) fn complete_line(label: &str, summary: &DiscoverySummary) -> String {
    completion_line(label, summary, needs_attention(summary))
}

fn completion_line(label: &str, summary: &DiscoverySummary, attention: bool) -> String {
    let glyph = if attention {
        theme::warn(glyphs().done)
    } else {
        theme::done(glyphs().done)
    };
    let verb = if summary.cancelled {
        "cancelled after"
    } else {
        "completed in"
    };
    let faults: usize = summary.error_counts.values().sum();

    let mut segments = vec![
        segment(verb, humanize::duration(summary.elapsed)),
        segment("hosts:", humanize::count(summary.targets_resolved)),
        segment("records:", humanize::count(summary.records_emitted)),
        segment("probes:", humanize::count(summary.probe_attempts)),
        segment("faults:", humanize::count(faults)),
    ];
    if summary.links_emitted > 0 {
        segments.push(segment("links:", humanize::count(summary.links_emitted)));
    }
    if summary.profiles_emitted > 0 {
        segments.push(segment(
            "profiles:",
            humanize::count(summary.profiles_emitted),
        ));
    }
    if summary.dlq_records > 0 {
        segments.push(format!(
            "{} {}",
            theme::label("dlq:"),
            theme::err(humanize::count(summary.dlq_records))
        ));
    }
    if let Some(sink) = summary.sink_type {
        segments.push(segment("sink:", sink.as_label()));
    }

    format!(
        "{} {}  {}",
        glyph,
        theme::name(label),
        segments.join(&theme::sep())
    )
}

#[cfg(feature = "config")]
fn failed_line(label: &str, error: &str) -> String {
    format!(
        "{} {}  {} {} {}",
        theme::err(glyphs().done),
        theme::name(label),
        theme::err("failed"),
        theme::label(glyphs().arrow),
        error
    )
}

fn detail_line(label: &str, body: String) -> String {
    let padded = format!("{label:<width$}", width = DETAIL_LABEL_WIDTH);
    format!(
        "  {} {} {body}",
        theme::label(glyphs().bullet),
        theme::label(padded),
    )
}

fn detail_lines(summary: &DiscoverySummary) -> Vec<String> {
    let mut lines = Vec::new();

    if !summary.probes_by_kind.is_empty() {
        let body = summary
            .probes_by_kind
            .iter()
            .map(|e| {
                format!(
                    "{} {} ({} err)",
                    theme::value(e.kind.label()),
                    humanize::count(e.attempted),
                    humanize::count(e.errored)
                )
            })
            .collect::<Vec<_>>()
            .join(&theme::sep());
        lines.push(detail_line("probes by kind", body));
    }

    if !summary.error_counts.is_empty() {
        let body = summary
            .error_counts
            .iter()
            .map(|(kind, n)| format!("{} {}", theme::value(kind.as_label()), humanize::count(*n)))
            .collect::<Vec<_>>()
            .join(&theme::sep());
        lines.push(detail_line("faults by kind", body));
    }

    if let Some(fault) = &summary.first_probe_error {
        lines.push(detail_line(
            "first fault",
            format!(
                "{} {} {}",
                theme::value(fault.kind.as_label()),
                theme::label(glyphs().arrow),
                fault.detail
            ),
        ));
    }

    if !summary.dlq_records_by_type_and_class.is_empty() {
        let body = summary
            .dlq_records_by_type_and_class
            .iter()
            .map(|(sink, class, n)| {
                format!(
                    "{} {}",
                    theme::value(format!("{}/{}", sink.as_label(), class.as_label())),
                    humanize::count(usize::try_from(*n).unwrap_or(usize::MAX))
                )
            })
            .collect::<Vec<_>>()
            .join(&theme::sep());
        lines.push(detail_line("dlq", body));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use rastreo_core::config::{BaseProbeConfig, DiscoverScenarioConfig};
    use rastreo_core::{
        PlanKnobs, ProbeErrorKind, ProbeFault, ProbeKind, ProbeKindSummary, ProberConfig,
        SinkConfig, SinkErrorClass, SinkType, Target,
    };
    use std::time::Duration;

    use super::super::theme::strip_ansi;

    fn plan(name: &str, ports: Vec<u16>, targets: usize) -> DiscoveryPlan {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let targets = (0..targets)
            .map(|i| Target::Ip(format!("10.0.0.{}", i + 1).parse().expect("ip")))
            .collect();
        let config =
            DiscoverScenarioConfig::new(base, targets, vec![ProberConfig::TcpConnect { ports }]);
        DiscoveryPlan::new(
            name.to_string(),
            &config,
            &[],
            PlanKnobs {
                max_concurrent: 64,
                probe_rate: None,
                retries: 0,
                timeout_ms: 1000,
            },
        )
    }

    fn summary() -> DiscoverySummary {
        let mut s = DiscoverySummary::default();
        s.targets_resolved = 254;
        s.probe_attempts = 1778;
        s.records_emitted = 12;
        s.elapsed = Duration::from_millis(4200);
        s.sink_type = Some(SinkType::Stdout);
        s
    }

    fn kind_summary(kind: ProbeKind, attempted: usize, errored: usize) -> ProbeKindSummary {
        let mut e = ProbeKindSummary::default();
        e.kind = kind;
        e.attempted = attempted;
        e.errored = errored;
        e
    }

    fn fully_populated() -> DiscoverySummary {
        let mut s = summary();
        s.links_emitted = 4;
        s.profiles_emitted = 2;
        s.dlq_records = 6;
        s.cancelled = true;
        s.error_counts.insert(ProbeErrorKind::PermissionDenied, 2);
        s.probes_by_kind = vec![kind_summary(ProbeKind::TcpConnect, 1778, 2)];
        s.first_probe_error = Some(ProbeFault::new(
            ProbeErrorKind::PermissionDenied,
            "raw socket requires CAP_NET_RAW",
        ));
        s.dlq_records_by_type_and_class = vec![(SinkType::File, SinkErrorClass::WriteFailure, 6)];
        s
    }

    fn serialized_keys(summary: &DiscoverySummary) -> std::collections::BTreeSet<String> {
        serde_json::to_value(summary)
            .expect("DiscoverySummary serializes")
            .as_object()
            .expect("DiscoverySummary is a JSON object")
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn start_line_renders_the_scan_shape_in_one_line() {
        let line = strip_ansi(&start_line(&plan("discover", vec![22, 80], 3), 3));
        assert_eq!(
            line,
            "▶ discover  targets: 3 | probes: tcp_connect (ports 22, 80) | concurrency: 64 | timeout: 1000ms | sink: stdout"
        );
    }

    #[test]
    fn start_line_reports_the_spec_count_not_the_expanded_host_count() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let config = DiscoverScenarioConfig::new(
            base,
            vec![Target::Cidr("10.0.0.0/24".parse().expect("cidr"))],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let plan = DiscoveryPlan::new(
            "discover".into(),
            &config,
            &[],
            PlanKnobs {
                max_concurrent: 8,
                probe_rate: None,
                retries: 0,
                timeout_ms: 500,
            },
        );
        let line = strip_ansi(&start_line(&plan, 1));
        assert!(line.contains("targets: 1"), "{line}");
    }

    #[test]
    fn start_line_names_an_empty_prober_list() {
        let mut empty = plan("discover", vec![22], 1);
        empty.probers.clear();
        let line = strip_ansi(&start_line(&empty, 1));
        assert!(line.contains("probes: <none>"), "{line}");
    }

    #[test]
    fn complete_line_renders_the_headline_counters() {
        let line = strip_ansi(&complete_line("discover", &summary()));
        assert_eq!(
            line,
            "■ discover  completed in 4.2s | hosts: 254 | records: 12 | probes: 1,778 | faults: 0 | sink: stdout"
        );
    }

    #[test]
    fn complete_line_labels_faults_and_counts_every_kind() {
        let mut s = summary();
        s.error_counts.insert(ProbeErrorKind::PermissionDenied, 2);
        s.error_counts.insert(ProbeErrorKind::DnsFailed, 1);
        let line = strip_ansi(&complete_line("discover", &s));
        assert!(line.contains("faults: 3"), "{line}");
        assert!(!line.contains("errors:"), "faults are not errors: {line}");
    }

    #[test]
    fn complete_line_omits_zero_valued_conditional_segments() {
        let line = strip_ansi(&complete_line("discover", &summary()));
        for absent in ["links:", "profiles:", "dlq:"] {
            assert!(!line.contains(absent), "{absent} should be hidden: {line}");
        }
    }

    #[test]
    fn complete_line_shows_links_and_profiles_when_the_second_streams_emitted() {
        let mut s = summary();
        s.links_emitted = 4;
        s.profiles_emitted = 2;
        let line = strip_ansi(&complete_line("discover", &s));
        assert!(line.contains("links: 4"), "{line}");
        assert!(line.contains("profiles: 2"), "{line}");
    }

    #[test]
    fn complete_line_shows_dlq_when_records_were_quarantined() {
        let mut s = summary();
        s.dlq_records = 4;
        assert!(strip_ansi(&complete_line("discover", &s)).contains("dlq: 4"));
    }

    #[test]
    fn complete_line_omits_the_sink_segment_when_no_sink_is_attributed() {
        let mut s = summary();
        s.sink_type = None;
        assert!(!strip_ansi(&complete_line("2 scenarios", &s)).contains("sink:"));
    }

    #[test]
    fn complete_line_says_cancelled_after_when_the_scan_was_interrupted() {
        let mut s = summary();
        s.cancelled = true;
        let line = strip_ansi(&complete_line("discover", &s));
        assert!(line.contains("cancelled after 4.2s"), "{line}");
        assert!(!line.contains("completed in"), "{line}");
    }

    #[test]
    fn completion_glyph_is_plain_when_only_probe_faults_occurred() {
        let mut s = summary();
        s.error_counts.insert(ProbeErrorKind::PermissionDenied, 9);
        s.first_probe_error = Some(ProbeFault::new(ProbeErrorKind::PermissionDenied, "denied"));
        assert!(
            !needs_attention(&s),
            "probe faults are expected data, not a scan-level problem"
        );
    }

    #[test]
    fn completion_glyph_needs_attention_when_cancelled() {
        let mut s = summary();
        s.cancelled = true;
        assert!(needs_attention(&s));
    }

    #[test]
    fn completion_glyph_needs_attention_when_records_were_quarantined() {
        let mut s = summary();
        s.dlq_records = 1;
        assert!(needs_attention(&s));
    }

    const FIELD_NEEDLES: &[(&str, &str)] = &[
        ("targets_resolved", "hosts: 254"),
        ("probe_attempts", "probes: 1,778"),
        ("records_emitted", "records: 12"),
        ("links_emitted", "links: 4"),
        ("profiles_emitted", "profiles: 2"),
        ("error_counts", "faults: 2"),
        ("probes_by_kind", "tcp_connect 1,778 (2 err)"),
        ("dlq_records", "dlq: 6"),
        ("dlq_records_by_type_and_class", "file/write_failure 6"),
        ("sink_type", "sink: stdout"),
        ("cancelled", "cancelled after"),
        ("first_probe_error", "raw socket requires CAP_NET_RAW"),
        ("elapsed_ms", "4.2s"),
    ];

    #[test]
    fn completion_output_reaches_every_discovery_summary_field() {
        let s = fully_populated();
        let mut rendered = strip_ansi(&complete_line("discover", &s));
        for line in detail_lines(&s) {
            rendered.push('\n');
            rendered.push_str(&strip_ansi(&line));
        }

        for (field, needle) in FIELD_NEEDLES {
            assert!(
                rendered.contains(needle),
                "{field} is not surfaced ({needle:?} missing):\n{rendered}"
            );
        }
    }

    // Blind spot: a new skip_serializing_if field that fully_populated() leaves at its default never reaches serialized_keys.
    #[test]
    fn the_completion_needle_table_covers_every_serialized_summary_field() {
        let covered: std::collections::BTreeSet<String> = FIELD_NEEDLES
            .iter()
            .map(|(field, _)| (*field).to_string())
            .collect();
        assert_eq!(
            serialized_keys(&fully_populated()),
            covered,
            "a new DiscoverySummary field must be surfaced by the completion output"
        );
    }

    fn assert_glyph_role(line: &str, painted: &str, not_painted: &str) {
        assert!(
            line.contains(painted),
            "expected {painted:?} in {line:?}, got {not_painted:?} instead"
        );
        assert!(!line.contains(not_painted), "{line:?}");
    }

    #[test]
    fn a_clean_completion_paints_the_glyph_with_the_done_role() {
        theme::with_colour(|| {
            let line = complete_line("discover", &summary());
            assert_glyph_role(
                &line,
                &theme::done(glyphs().done),
                &theme::warn(glyphs().done),
            );
        });
    }

    #[test]
    fn probe_faults_alone_still_paint_the_glyph_with_the_done_role() {
        theme::with_colour(|| {
            let mut s = summary();
            s.error_counts.insert(ProbeErrorKind::PermissionDenied, 9);
            s.first_probe_error = Some(ProbeFault::new(ProbeErrorKind::PermissionDenied, "denied"));
            let line = complete_line("discover", &s);
            assert_glyph_role(
                &line,
                &theme::done(glyphs().done),
                &theme::warn(glyphs().done),
            );
        });
    }

    #[test]
    fn a_cancelled_completion_paints_the_glyph_with_the_warn_role() {
        theme::with_colour(|| {
            let mut s = summary();
            s.cancelled = true;
            let line = complete_line("discover", &s);
            assert_glyph_role(
                &line,
                &theme::warn(glyphs().done),
                &theme::done(glyphs().done),
            );
        });
    }

    #[test]
    fn quarantined_records_paint_the_glyph_with_the_warn_role() {
        theme::with_colour(|| {
            let mut s = summary();
            s.dlq_records = 1;
            let line = complete_line("discover", &s);
            assert_glyph_role(
                &line,
                &theme::warn(glyphs().done),
                &theme::done(glyphs().done),
            );
        });
    }

    #[test]
    fn the_start_banner_paints_its_glyph_with_the_ok_role() {
        theme::with_colour(|| {
            let line = start_line(&plan("discover", vec![22], 1), 1);
            assert!(line.contains(&theme::ok(glyphs().start)), "{line:?}");
        });
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_failed_scenario_paints_its_glyph_with_the_err_role() {
        theme::with_colour(|| {
            let line = failed_line("scenario 'bad' (1 of 2)", "sink error: pipe broke");
            assert!(line.contains(&theme::err(glyphs().done)), "{line:?}");
        });
    }

    #[test]
    fn start_line_ignores_the_resolution_dependent_plan_fields() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let config = DiscoverScenarioConfig::new(
            base,
            vec![Target::Cidr("10.0.0.0/30".parse().expect("cidr"))],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let knobs = PlanKnobs {
            max_concurrent: 8,
            probe_rate: None,
            retries: 0,
            timeout_ms: 500,
        };
        let resolution = rastreo_core::ResolvedScenarioTarget::new(
            Target::Cidr("10.0.0.0/30".parse().expect("cidr")),
            Ok(vec!["10.0.0.1".parse().expect("ip")]),
        );
        let unresolved = DiscoveryPlan::new("discover".into(), &config, &[], knobs);
        let resolved = DiscoveryPlan::new(
            "discover".into(),
            &config,
            std::slice::from_ref(&resolution),
            knobs,
        );
        assert!(resolved.total_probes > unresolved.total_probes);
        assert_eq!(
            strip_ansi(&start_line(&unresolved, 1)),
            strip_ansi(&start_line(&resolved, 1))
        );
    }

    #[test]
    fn detail_lines_are_empty_for_a_scan_with_nothing_to_break_down() {
        assert!(detail_lines(&DiscoverySummary::default()).is_empty());
    }

    #[test]
    fn detail_lines_break_down_probes_by_kind() {
        let mut s = summary();
        s.probes_by_kind = vec![
            kind_summary(ProbeKind::TcpConnect, 254, 0),
            kind_summary(ProbeKind::Dns, 254, 2),
        ];
        let lines: Vec<String> = detail_lines(&s).iter().map(|l| strip_ansi(l)).collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "  • probes by kind tcp_connect 254 (0 err) | dns 254 (2 err)"
        );
    }

    #[test]
    fn detail_lines_break_down_faults_by_kind() {
        let mut s = summary();
        s.error_counts.insert(ProbeErrorKind::PermissionDenied, 2);
        s.error_counts.insert(ProbeErrorKind::DnsFailed, 1);
        let lines: Vec<String> = detail_lines(&s).iter().map(|l| strip_ansi(l)).collect();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("faults by kind") && l.contains("permission_denied 2")),
            "{lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("dns_failed 1")),
            "{lines:#?}"
        );
    }

    #[test]
    fn detail_lines_surface_the_first_fault_with_its_detail() {
        let mut s = summary();
        s.first_probe_error = Some(ProbeFault::new(
            ProbeErrorKind::PermissionDenied,
            "raw socket requires CAP_NET_RAW",
        ));
        let lines: Vec<String> = detail_lines(&s).iter().map(|l| strip_ansi(l)).collect();
        assert!(
            lines
                .iter()
                .any(|l| l
                    == "  • first fault    permission_denied → raw socket requires CAP_NET_RAW"),
            "{lines:#?}"
        );
    }

    #[test]
    fn detail_lines_break_down_dlq_by_destination_and_class() {
        let mut s = summary();
        s.dlq_records = 4;
        s.dlq_records_by_type_and_class = vec![(SinkType::File, SinkErrorClass::WriteFailure, 4)];
        let lines: Vec<String> = detail_lines(&s).iter().map(|l| strip_ansi(l)).collect();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("dlq") && l.contains("file/write_failure 4")),
            "{lines:#?}"
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn failed_line_names_the_scenario_and_the_error() {
        let line = strip_ansi(&failed_line(
            "scenario 'bad' (1 of 2)",
            "sink error: pipe broke",
        ));
        assert_eq!(
            line,
            "■ scenario 'bad' (1 of 2)  failed → sink error: pipe broke"
        );
    }

    #[cfg(feature = "config")]
    fn tally(total: usize, completed: usize, failed: usize) -> ScenarioTally {
        ScenarioTally {
            total,
            completed,
            failed,
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn the_aggregate_label_counts_every_scenario_when_all_of_them_ran() {
        let line = strip_ansi(&aggregate_line(tally(3, 3, 0), &summary()));
        assert!(line.starts_with("■ 3 scenarios  completed in"), "{line}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn the_aggregate_label_names_the_shortfall_when_a_scenario_did_not_complete() {
        let line = strip_ansi(&aggregate_line(tally(3, 1, 1), &summary()));
        assert!(line.starts_with("■ 1 of 3 scenarios"), "{line}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_failed_scenario_paints_the_aggregate_glyph_with_the_warn_role() {
        theme::with_colour(|| {
            let line = aggregate_line(tally(3, 2, 1), &summary());
            assert_glyph_role(
                &line,
                &theme::warn(glyphs().done),
                &theme::done(glyphs().done),
            );
        });
    }

    #[cfg(feature = "config")]
    #[test]
    fn an_all_clean_aggregate_paints_the_glyph_with_the_done_role() {
        theme::with_colour(|| {
            let line = aggregate_line(tally(3, 3, 0), &summary());
            assert_glyph_role(
                &line,
                &theme::done(glyphs().done),
                &theme::warn(glyphs().done),
            );
        });
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_cancelled_aggregate_says_cancelled_after_and_paints_the_warn_role() {
        let mut s = summary();
        s.cancelled = true;
        assert!(strip_ansi(&aggregate_line(tally(3, 0, 0), &s)).contains("cancelled after"));
        theme::with_colour(|| {
            let line = aggregate_line(tally(3, 0, 0), &s);
            assert_glyph_role(
                &line,
                &theme::warn(glyphs().done),
                &theme::done(glyphs().done),
            );
        });
    }

    #[cfg(feature = "config")]
    #[test]
    fn accumulate_sums_every_headline_counter() {
        let mut agg = DiscoverySummary::default();
        let mut a = summary();
        a.links_emitted = 1;
        a.profiles_emitted = 2;
        a.dlq_records = 3;
        let mut b = summary();
        b.elapsed = Duration::from_millis(800);
        accumulate(&mut agg, &a);
        accumulate(&mut agg, &b);
        assert_eq!(agg.targets_resolved, 508);
        assert_eq!(agg.probe_attempts, 3556);
        assert_eq!(agg.records_emitted, 24);
        assert_eq!(agg.links_emitted, 1);
        assert_eq!(agg.profiles_emitted, 2);
        assert_eq!(agg.dlq_records, 3);
        assert_eq!(agg.elapsed, Duration::from_millis(5000));
    }

    #[cfg(feature = "config")]
    #[test]
    fn accumulate_merges_fault_tallies_by_kind() {
        let mut agg = DiscoverySummary::default();
        let mut a = DiscoverySummary::default();
        a.error_counts.insert(ProbeErrorKind::DnsFailed, 2);
        let mut b = DiscoverySummary::default();
        b.error_counts.insert(ProbeErrorKind::DnsFailed, 3);
        b.error_counts.insert(ProbeErrorKind::Other, 1);
        accumulate(&mut agg, &a);
        accumulate(&mut agg, &b);
        assert_eq!(agg.error_counts[&ProbeErrorKind::DnsFailed], 5);
        assert_eq!(agg.error_counts[&ProbeErrorKind::Other], 1);
    }

    #[cfg(feature = "config")]
    #[test]
    fn accumulate_merges_probe_kind_rows_instead_of_appending_duplicates() {
        let mut agg = DiscoverySummary::default();
        let mut a = DiscoverySummary::default();
        a.probes_by_kind = vec![kind_summary(ProbeKind::TcpConnect, 10, 1)];
        let mut b = DiscoverySummary::default();
        b.probes_by_kind = vec![
            kind_summary(ProbeKind::TcpConnect, 5, 2),
            kind_summary(ProbeKind::Dns, 7, 0),
        ];
        accumulate(&mut agg, &a);
        accumulate(&mut agg, &b);
        assert_eq!(agg.probes_by_kind.len(), 2);
        let tcp = agg
            .probes_by_kind
            .iter()
            .find(|e| e.kind == ProbeKind::TcpConnect)
            .expect("tcp row");
        assert_eq!((tcp.attempted, tcp.errored), (15, 3));
    }

    #[cfg(feature = "config")]
    #[test]
    fn accumulate_merges_dlq_rows_by_destination_and_class() {
        let mut agg = DiscoverySummary::default();
        let mut a = DiscoverySummary::default();
        a.dlq_records_by_type_and_class = vec![(SinkType::File, SinkErrorClass::WriteFailure, 2)];
        let mut b = DiscoverySummary::default();
        b.dlq_records_by_type_and_class = vec![
            (SinkType::File, SinkErrorClass::WriteFailure, 3),
            (SinkType::File, SinkErrorClass::FlushFailure, 1),
        ];
        accumulate(&mut agg, &a);
        accumulate(&mut agg, &b);
        assert_eq!(agg.dlq_records_by_type_and_class.len(), 2);
        assert_eq!(agg.dlq_records_by_type_and_class[0].2, 5);
    }

    #[cfg(feature = "config")]
    #[test]
    fn accumulate_carries_every_serialized_field_except_the_sink() {
        let scenario = fully_populated();
        let mut agg = DiscoverySummary::default();
        accumulate(&mut agg, &scenario);

        let mut expected = serde_json::to_value(&scenario).expect("serialize");
        let mut actual = serde_json::to_value(&agg).expect("serialize");
        for value in [&mut expected, &mut actual] {
            let _ = value.as_object_mut().expect("object").remove("sink_type");
        }
        assert_eq!(
            actual, expected,
            "a new DiscoverySummary field must be folded into the multi-scenario aggregate"
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn accumulate_leaves_the_sink_unattributed_across_scenarios() {
        let mut agg = DiscoverySummary::default();
        accumulate(&mut agg, &fully_populated());
        assert!(agg.sink_type.is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn accumulate_latches_the_first_fault_and_any_cancellation() {
        let mut agg = DiscoverySummary::default();
        let mut a = DiscoverySummary::default();
        a.first_probe_error = Some(ProbeFault::new(ProbeErrorKind::DnsFailed, "first"));
        let mut b = DiscoverySummary::default();
        b.first_probe_error = Some(ProbeFault::new(ProbeErrorKind::Other, "second"));
        b.cancelled = true;
        accumulate(&mut agg, &a);
        accumulate(&mut agg, &b);
        assert_eq!(
            agg.first_probe_error.as_ref().map(|f| f.detail.as_str()),
            Some("first")
        );
        assert!(agg.cancelled);
    }
}
