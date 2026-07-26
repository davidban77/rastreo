pub(crate) fn print_summary(label: &str, summary: &rastreo_core::DiscoverySummary) {
    let status = if summary.cancelled {
        "cancelled"
    } else {
        "complete"
    };
    let probe_errors: usize = summary.error_counts.values().sum();
    eprintln!(
        "{label} {}: targets_resolved={} probe_attempts={} probe_errors={} records_emitted={} elapsed_ms={}",
        status,
        summary.targets_resolved,
        summary.probe_attempts,
        probe_errors,
        summary.records_emitted,
        summary.elapsed.as_millis(),
    );
}
