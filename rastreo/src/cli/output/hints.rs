use rastreo_core::hint_for_error_kind;

use super::theme::{self, glyphs};
use super::OutputMode;

#[cfg(feature = "config")]
const FEATURE_GATED_VARIANTS: &[(&str, &str)] = &[
    ("http", "http"),
    ("snmp", "snmp"),
    ("arp", "arp"),
    ("ndp", "ndp"),
    ("ssh", "ssh"),
    ("icmp", "icmp"),
    ("tls", "tls"),
    ("mib_enrichment", "mib_enrichment"),
];

const RELEASE_BUNDLED_FEATURES: &str =
    "kafka, http, snmp, arp, ndp, nats, ssh, icmp, tls, gnmi, lldp";

const DNS_RESOLUTION_HINT: &str =
    "DNS resolution failed for the target. Check the resolver configuration or the target's hostname.";

// Resolver / sink errors abort the whole scan and are not kinded, so they hint by string match.
// Needles are lowercase and matched against the whole rendered error chain, not just its top level.
const SCAN_ERROR_HINT_PATTERNS: &[(&str, &str)] = &[
    ("dns lookup failed", DNS_RESOLUTION_HINT),
    ("no records", DNS_RESOLUTION_HINT),
];

pub(crate) fn enrich_scan_error_hint(error_msg: &str) -> Option<String> {
    let lower = error_msg.to_lowercase();
    SCAN_ERROR_HINT_PATTERNS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, hint)| (*hint).to_string())
}

fn runtime_probe_hint(summary: &rastreo_core::DiscoverySummary) -> Option<&'static str> {
    summary
        .first_probe_error
        .as_ref()
        .and_then(|fault| hint_for_error_kind(fault.kind))
}

const ZERO_RECORDS_HINT: &str =
    "0 records emitted — no probe reached an open port. Check target reachability and port list.";

fn runtime_hint_line(summary: &rastreo_core::DiscoverySummary) -> Option<String> {
    if summary.cancelled {
        return None;
    }
    if summary.first_probe_error.is_some() {
        return runtime_probe_hint(summary).map(str::to_string);
    }
    if summary.records_emitted == 0 && summary.probe_attempts > 0 {
        return Some(ZERO_RECORDS_HINT.to_string());
    }
    None
}

pub(crate) fn print_hint(hint: &str, mode: OutputMode) {
    if !mode.prints_advisories() {
        return;
    }
    eprintln!("{}", hint_line(hint));
}

pub(crate) fn print_runtime_hints(summary: &rastreo_core::DiscoverySummary, mode: OutputMode) {
    if let Some(hint) = runtime_hint_line(summary) {
        print_hint(&hint, mode);
    }
}

/// Pre-scan advisory about how the requested scan was interpreted; not a failure.
pub(crate) fn print_note(note: &str, mode: OutputMode) {
    if !mode.prints_advisories() {
        return;
    }
    eprintln!("{}", note_line(note));
}

fn hint_line(hint: &str) -> String {
    format!(
        "{} {} {hint}",
        theme::warn(glyphs().warn),
        theme::label("hint:")
    )
}

fn note_line(note: &str) -> String {
    format!(
        "{} {} {note}",
        theme::label(glyphs().bullet),
        theme::label("note:")
    )
}

pub(crate) fn rebuild_hint(name: &str, feature: &str) -> String {
    format!(
        "'{name}' requires the '{feature}' Cargo feature. Rebuild with --features {feature} or use the release Docker image which bundles {RELEASE_BUNDLED_FEATURES}."
    )
}

#[cfg(feature = "config")]
pub(crate) fn enrich_feature_hint(error_msg: &str) -> Option<String> {
    const NEEDLE: &str = "unknown variant `";
    let start = error_msg.find(NEEDLE)? + NEEDLE.len();
    let rest = &error_msg[start..];
    let end = rest.find('`')?;
    let variant = &rest[..end];
    let feature = FEATURE_GATED_VARIANTS
        .iter()
        .find(|(name, _)| *name == variant)
        .map(|(_, feat)| *feat)?;
    Some(rebuild_hint(variant, feature))
}

#[cfg(test)]
mod tests {
    use super::super::Verbosity;
    use super::*;

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_http_variant() {
        let msg = "scenarios: unknown variant `http`, expected one of `tcp_connect`, `dns` at line 4 column 3";
        let hint = enrich_feature_hint(msg).expect("hint");
        assert!(hint.contains("--features http"), "hint: {hint}");
        assert!(hint.contains("'http'"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_snmp_variant() {
        let msg = "unknown variant `snmp`, expected one of `tcp_connect`";
        let hint = enrich_feature_hint(msg).expect("hint");
        assert!(hint.contains("--features snmp"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_arp_variant() {
        let hint = enrich_feature_hint("unknown variant `arp`, expected one of ...").expect("hint");
        assert!(hint.contains("--features arp"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_ndp_variant() {
        let hint = enrich_feature_hint("unknown variant `ndp`, expected one of ...").expect("hint");
        assert!(hint.contains("--features ndp"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_ssh_variant() {
        let hint = enrich_feature_hint("unknown variant `ssh`, expected one of ...").expect("hint");
        assert!(hint.contains("--features ssh"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_icmp_variant() {
        let hint =
            enrich_feature_hint("unknown variant `icmp`, expected one of ...").expect("hint");
        assert!(hint.contains("--features icmp"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_tls_variant() {
        let hint = enrich_feature_hint("unknown variant `tls`, expected one of ...").expect("hint");
        assert!(hint.contains("--features tls"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_names_the_bundled_release_features() {
        let hint = enrich_feature_hint("unknown variant `ssh`, expected one of ...").expect("hint");
        assert!(hint.contains(RELEASE_BUNDLED_FEATURES), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_maps_mib_enrichment_variant_to_feature() {
        let hint =
            enrich_feature_hint("unknown variant `mib_enrichment`, expected one of `direct`")
                .expect("hint");
        assert!(hint.contains("--features mib_enrichment"), "hint: {hint}");
        assert!(hint.contains("'mib_enrichment'"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_does_not_fire_for_typo_variant() {
        let msg = "unknown variant `htttp`, expected one of `tcp_connect`";
        assert!(enrich_feature_hint(msg).is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_does_not_fire_when_no_unknown_variant_marker() {
        assert!(enrich_feature_hint("missing field `targets`").is_none());
    }

    // The chain a failed `A`/`AAAA` lookup renders, verbatim from a live run.
    const DNS_LOOKUP_FAILED_CHAIN: &str = "DNS lookup failed for does-not-exist.invalid: no records found for Query { name: Name(\"does-not-exist.invalid.\"), query_type: AAAA, query_class: IN }";

    #[test]
    fn enrich_scan_error_hint_matches_a_failed_dns_lookup_chain() {
        let hint = enrich_scan_error_hint(DNS_LOOKUP_FAILED_CHAIN).expect("hint");
        assert_eq!(hint, DNS_RESOLUTION_HINT);
    }

    #[test]
    fn enrich_scan_error_hint_matches_the_resolver_no_records_message() {
        let msg = rastreo_core::ResolverError::DnsNoRecords {
            name: "missing.lab".into(),
        }
        .to_string();
        let hint = enrich_scan_error_hint(&msg).expect("hint");
        assert_eq!(hint, DNS_RESOLUTION_HINT);
    }

    #[test]
    fn enrich_scan_error_hint_is_case_insensitive() {
        let hint = enrich_scan_error_hint(&DNS_LOOKUP_FAILED_CHAIN.to_uppercase()).expect("hint");
        assert_eq!(hint, DNS_RESOLUTION_HINT);
    }

    #[test]
    fn enrich_scan_error_hint_returns_none_for_unknown_message() {
        assert!(enrich_scan_error_hint("some totally novel failure mode").is_none());
    }

    #[test]
    fn enrich_scan_error_hint_returns_none_for_empty_message() {
        assert!(enrich_scan_error_hint("").is_none());
    }

    #[test]
    fn enrich_scan_error_hint_ignores_probe_fault_strings() {
        assert!(enrich_scan_error_hint("raw socket: Permission denied (os error 13)").is_none());
    }

    #[test]
    fn enrich_scan_error_hint_ignores_a_sink_failure_chain() {
        assert!(enrich_scan_error_hint(
            "output sink failed: failed to open file sink at /nope/out.ndjson: No such file or directory (os error 2)"
        )
        .is_none());
    }

    fn summary_with_fault(
        kind: rastreo_core::ProbeErrorKind,
        detail: &str,
    ) -> rastreo_core::DiscoverySummary {
        let mut summary = rastreo_core::DiscoverySummary::default();
        summary.first_probe_error = Some(rastreo_core::ProbeFault::new(kind, detail));
        summary
    }

    #[test]
    fn runtime_probe_hint_derives_permission_denied_from_kind() {
        // detail omits any "permission denied" substring: the hint must come from the kind.
        let summary = summary_with_fault(
            rastreo_core::ProbeErrorKind::PermissionDenied,
            "snmp egress blocked",
        );
        let hint = runtime_probe_hint(&summary).expect("hint");
        assert!(hint.contains("CAP_NET_RAW"), "hint: {hint}");
    }

    #[test]
    fn runtime_probe_hint_derives_decode_failed_from_kind() {
        let summary = summary_with_fault(rastreo_core::ProbeErrorKind::DecodeFailed, "gibberish");
        let hint = runtime_probe_hint(&summary).expect("hint");
        assert!(hint.contains("could not parse"), "hint: {hint}");
    }

    #[test]
    fn runtime_probe_hint_agrees_with_core_hint_for_the_same_kind() {
        for kind in [
            rastreo_core::ProbeErrorKind::PermissionDenied,
            rastreo_core::ProbeErrorKind::DnsFailed,
            rastreo_core::ProbeErrorKind::DecodeFailed,
            rastreo_core::ProbeErrorKind::AuthFailed,
        ] {
            let summary = summary_with_fault(kind, "x");
            assert_eq!(
                runtime_probe_hint(&summary),
                rastreo_core::hint_for_error_kind(kind),
                "CLI runtime hint must match the shared core hint for {kind:?}"
            );
        }
    }

    #[test]
    fn runtime_probe_hint_is_none_for_other_kind() {
        let summary = summary_with_fault(rastreo_core::ProbeErrorKind::Other, "unclassified");
        assert!(runtime_probe_hint(&summary).is_none());
    }

    #[test]
    fn runtime_probe_hint_is_none_without_a_fault() {
        let summary = rastreo_core::DiscoverySummary::default();
        assert!(runtime_probe_hint(&summary).is_none());
    }

    #[test]
    fn print_runtime_hints_no_op_when_records_emitted() {
        let mut summary = rastreo_core::DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 1;
        summary.records_emitted = 1;
        assert!(
            runtime_hint_line(&summary).is_none(),
            "records emitted with no fault must produce no hint"
        );
        print_runtime_hints(&summary, OutputMode::from(Verbosity::Normal));
    }

    #[test]
    fn hint_line_carries_the_warn_glyph_and_the_hint_prefix() {
        let line = super::super::theme::strip_ansi(&hint_line("check the port list"));
        assert_eq!(line, "⚠ hint: check the port list");
    }

    #[test]
    fn hint_line_paints_its_glyph_with_the_warn_role() {
        theme::with_colour(|| {
            let line = hint_line("check the port list");
            assert!(line.contains(&theme::warn(glyphs().warn)), "{line:?}");
        });
    }

    #[test]
    fn note_line_carries_the_bullet_glyph_and_the_note_prefix() {
        let line = super::super::theme::strip_ansi(&note_line("icmp is not in the default set"));
        assert_eq!(line, "• note: icmp is not in the default set");
    }

    #[test]
    fn advisories_survive_machine_output() {
        let mode = OutputMode::new(Verbosity::Normal, true);
        assert!(mode.prints_advisories());
        print_hint("still printed", mode);
        print_note("still printed", mode);
    }

    #[test]
    fn print_note_is_silent_under_quiet() {
        print_note("suppressed", OutputMode::from(Verbosity::Quiet));
    }

    #[test]
    fn rebuild_hint_names_the_feature_and_the_bundled_release_set() {
        let hint = rebuild_hint("gnmi", "gnmi");
        assert!(hint.contains("--features gnmi"), "hint: {hint}");
        assert!(hint.contains("'gnmi'"), "hint: {hint}");
        assert!(hint.contains(RELEASE_BUNDLED_FEATURES), "hint: {hint}");
    }

    #[test]
    fn the_bundled_release_set_is_exactly_what_the_dockerfile_builds() {
        let declared: std::collections::BTreeSet<&str> = include_str!("../../../../Dockerfile")
            .lines()
            .find_map(|line| line.trim().strip_prefix("ARG FEATURES="))
            .expect("Dockerfile declares ARG FEATURES=")
            .split(',')
            .map(str::trim)
            .collect();
        let advertised: std::collections::BTreeSet<&str> =
            RELEASE_BUNDLED_FEATURES.split(", ").collect();
        assert_eq!(
            advertised, declared,
            "the rebuild hint must name every feature the release image bundles"
        );
    }

    #[test]
    fn runtime_hint_line_returns_fault_hint_even_when_a_record_was_kept() {
        // SNMP decode-failure keeps the device (records_emitted == 1) yet latches a fault.
        let mut summary =
            summary_with_fault(rastreo_core::ProbeErrorKind::DecodeFailed, "gibberish");
        summary.probe_attempts = 1;
        summary.records_emitted = 1;
        let line = runtime_hint_line(&summary).expect("fault hint must fire despite a kept record");
        assert_eq!(
            line.as_str(),
            rastreo_core::hint_for_error_kind(rastreo_core::ProbeErrorKind::DecodeFailed)
                .expect("decode hint")
        );
    }

    #[test]
    fn runtime_hint_line_falls_back_to_zero_records_hint_without_a_fault() {
        let mut summary = rastreo_core::DiscoverySummary::default();
        summary.probe_attempts = 1;
        summary.records_emitted = 0;
        let line = runtime_hint_line(&summary).expect("fallback hint");
        assert_eq!(line, ZERO_RECORDS_HINT);
        assert!(
            !line.starts_with("hint:"),
            "content must be prefix-free; the label is added at the print layer: {line}"
        );
    }

    #[test]
    fn runtime_hint_line_no_op_when_cancelled() {
        let mut summary = rastreo_core::DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 1;
        summary
            .error_counts
            .insert(rastreo_core::ProbeErrorKind::PermissionDenied, 1);
        summary.cancelled = true;
        summary.first_probe_error = Some(rastreo_core::ProbeFault::new(
            rastreo_core::ProbeErrorKind::PermissionDenied,
            "permission denied",
        ));
        assert!(runtime_hint_line(&summary).is_none());
        print_runtime_hints(&summary, OutputMode::from(Verbosity::Normal));
    }
}
