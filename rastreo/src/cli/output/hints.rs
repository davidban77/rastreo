use rastreo_core::hint_for_error_kind;

#[cfg(feature = "config")]
const FEATURE_GATED_VARIANTS: &[(&str, &str)] = &[
    ("http", "http"),
    ("snmp", "snmp"),
    ("arp", "arp"),
    ("ndp", "ndp"),
    ("ssh", "ssh"),
    ("icmp", "icmp"),
    ("tls", "tls"),
    ("oui_enrichment", "oui"),
    ("mib_enrichment", "mib_enrichment"),
];

#[cfg(feature = "config")]
const RELEASE_BUNDLED_FEATURES: &str = "kafka, http, snmp, arp, ndp, oui, nats, ssh, icmp, tls";

// Resolver / sink errors abort the whole scan and are not kinded, so they hint by string match.
const SCAN_ERROR_HINT_PATTERNS: &[(&str, &str)] = &[
    (
        "nxdomain",
        "DNS resolution failed for the target. Check the resolver configuration or the target's hostname.",
    ),
    (
        "dns lookup failed",
        "DNS resolution failed for the target. Check the resolver configuration or the target's hostname.",
    ),
    (
        "no records found",
        "DNS resolution failed for the target. Check the resolver configuration or the target's hostname.",
    ),
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

pub(crate) fn print_runtime_hints(summary: &rastreo_core::DiscoverySummary) {
    if let Some(hint) = runtime_hint_line(summary) {
        eprintln!("hint: {hint}");
    }
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
    Some(format!(
        "'{variant}' requires the '{feature}' Cargo feature. Rebuild with --features {feature} or use the release Docker image which bundles {RELEASE_BUNDLED_FEATURES}."
    ))
}

#[cfg(test)]
mod tests {
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
    fn enrich_feature_hint_names_current_bundled_release_features() {
        let hint = enrich_feature_hint("unknown variant `ssh`, expected one of ...").expect("hint");
        for feat in [
            "kafka", "http", "snmp", "arp", "ndp", "oui", "nats", "ssh", "icmp", "tls",
        ] {
            assert!(hint.contains(feat), "hint missing '{feat}': {hint}");
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_maps_oui_enrichment_variant_to_oui_feature() {
        let hint =
            enrich_feature_hint("unknown variant `oui_enrichment`, expected one of `direct`")
                .expect("hint");
        assert!(hint.contains("--features oui"), "hint: {hint}");
        assert!(hint.contains("'oui_enrichment'"), "hint: {hint}");
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

    #[test]
    fn enrich_scan_error_hint_matches_nxdomain() {
        let hint =
            enrich_scan_error_hint("resolver error: NXDOMAIN for example.com").expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
    }

    #[test]
    fn enrich_scan_error_hint_matches_dns_lookup_failed() {
        let hint = enrich_scan_error_hint("resolver error: DNS lookup failed for x.invalid")
            .expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
    }

    #[test]
    fn enrich_scan_error_hint_matches_no_records_found() {
        let hint = enrich_scan_error_hint("resolver error: no records found").expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
    }

    #[test]
    fn enrich_scan_error_hint_is_case_insensitive() {
        let hint =
            enrich_scan_error_hint("RESOLVER ERROR: NXDOMAIN for example.com").expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
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
        assert!(enrich_scan_error_hint("probe error: raw socket: Permission denied").is_none());
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
        print_runtime_hints(&summary);
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
        print_runtime_hints(&summary);
    }
}
