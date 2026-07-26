use std::io::Write;
use std::time::{Duration, Instant};

use rastreo_core::DiscoveryProgress;
use tokio::sync::watch;

const PROGRESS_REDRAW_INTERVAL: Duration = Duration::from_secs(1);
// Below a few completed targets, a linear ETA extrapolation is too noisy to be useful.
const ETA_MIN_COMPLETED: usize = 3;

pub(crate) async fn progress_display_loop(
    mut rx: watch::Receiver<DiscoveryProgress>,
    is_tty: bool,
) {
    let mut last_draw: Option<Instant> = None;
    while rx.changed().await.is_ok() {
        let snapshot = rx.borrow().clone();
        if snapshot.targets_total == 0 {
            continue;
        }
        let now = Instant::now();
        if should_redraw(last_draw, now, PROGRESS_REDRAW_INTERVAL) {
            redraw_progress(&snapshot, is_tty);
            last_draw = Some(now);
        }
    }
    finalize_progress_line(is_tty);
}

fn should_redraw(last_draw: Option<Instant>, now: Instant, interval: Duration) -> bool {
    match last_draw {
        None => true,
        Some(t) => now.duration_since(t) >= interval,
    }
}

fn format_progress_line(p: &DiscoveryProgress) -> String {
    let total = p.targets_total;
    let done = p.targets_completed;
    let pct = done.saturating_mul(100).checked_div(total).unwrap_or(0);
    let mut line = format!(
        "targets {done}/{total} ({pct}%), records {}",
        p.records_emitted
    );
    if done >= ETA_MIN_COMPLETED && done < total {
        let remaining = (total - done) as u128;
        let eta_secs = p.elapsed_ms.saturating_mul(remaining) / done as u128 / 1000;
        line.push_str(&format!(", ETA ~{eta_secs}s"));
    }
    line
}

// stderr, not stdout: records stream to stdout and the progress line must not corrupt them.
fn redraw_progress(p: &DiscoveryProgress, is_tty: bool) {
    let line = format_progress_line(p);
    let mut err = std::io::stderr();
    if is_tty {
        let _ = write!(err, "\r\x1b[K{line}");
    } else {
        let _ = writeln!(err, "{line}");
    }
    let _ = err.flush();
}

fn finalize_progress_line(is_tty: bool) {
    if is_tty {
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[K");
        let _ = err.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(
        completed: usize,
        total: usize,
        records: usize,
        elapsed_ms: u128,
    ) -> DiscoveryProgress {
        let mut p = DiscoveryProgress::default();
        p.targets_completed = completed;
        p.targets_total = total;
        p.records_emitted = records;
        p.elapsed_ms = elapsed_ms;
        p
    }

    #[test]
    fn should_redraw_always_true_on_first_draw() {
        assert!(should_redraw(
            None,
            Instant::now(),
            PROGRESS_REDRAW_INTERVAL
        ));
    }

    #[test]
    fn should_redraw_false_before_interval_elapses() {
        let t = Instant::now();
        assert!(!should_redraw(
            Some(t),
            t + Duration::from_millis(500),
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn should_redraw_true_at_and_after_interval() {
        let t = Instant::now();
        assert!(should_redraw(
            Some(t),
            t + Duration::from_secs(1),
            Duration::from_secs(1)
        ));
        assert!(should_redraw(
            Some(t),
            t + Duration::from_millis(1500),
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn format_progress_line_early_scan_omits_eta() {
        let line = format_progress_line(&progress(0, 10, 0, 0));
        assert_eq!(line, "targets 0/10 (0%), records 0");
        assert!(
            !line.contains("ETA"),
            "no ETA before any target completes: {line}"
        );
    }

    #[test]
    fn format_progress_line_below_eta_threshold_omits_eta() {
        let line = format_progress_line(&progress(2, 10, 1, 4000));
        assert!(
            !line.contains("ETA"),
            "ETA must stay hidden under the threshold: {line}"
        );
        assert!(line.contains("targets 2/10 (20%)"), "{line}");
    }

    #[test]
    fn format_progress_line_shows_linear_eta_after_threshold() {
        // 5 of 10 done in 10s ⇒ 5 remaining at 2s each ⇒ ~10s left.
        let line = format_progress_line(&progress(5, 10, 3, 10_000));
        assert_eq!(line, "targets 5/10 (50%), records 3, ETA ~10s");
    }

    #[test]
    fn format_progress_line_at_completion_is_full_percent_without_eta() {
        let line = format_progress_line(&progress(10, 10, 8, 20_000));
        assert_eq!(line, "targets 10/10 (100%), records 8");
    }
}
