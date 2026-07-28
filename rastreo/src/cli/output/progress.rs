use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use rastreo_core::DiscoveryProgress;
use tokio::sync::watch;

use super::humanize;
use super::theme;
use super::OutputMode;

const TTY_REDRAW_INTERVAL: Duration = Duration::from_millis(250);
// Plain output accumulates one line per redraw, so a CI log gets a heartbeat, not a flood.
const PLAIN_REDRAW_INTERVAL: Duration = Duration::from_secs(5);
// Below a few completed targets, a linear ETA extrapolation is too noisy to be useful.
const ETA_MIN_COMPLETED: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgressStyle {
    InPlace,
    Lines,
    Silent,
}

pub(crate) fn progress_style(records_on_stdout: bool) -> ProgressStyle {
    style_for(
        std::io::stderr().is_terminal(),
        std::io::stdout().is_terminal(),
        records_on_stdout,
    )
}

// An in-place redraw owns the row it paints, and it cannot own one that records are landing on.
fn style_for(
    stderr_is_terminal: bool,
    stdout_is_terminal: bool,
    records_on_stdout: bool,
) -> ProgressStyle {
    if records_on_stdout && stdout_is_terminal && stderr_is_terminal {
        ProgressStyle::Silent
    } else if stderr_is_terminal {
        ProgressStyle::InPlace
    } else {
        ProgressStyle::Lines
    }
}

pub(crate) async fn progress_display_loop(
    mut rx: watch::Receiver<DiscoveryProgress>,
    style: ProgressStyle,
    mode: OutputMode,
) {
    if !mode.prints_chrome() || style == ProgressStyle::Silent {
        return;
    }
    let interval = redraw_interval(style);
    // A TTY redraws in place so it draws at once; plain output waits an interval to stay quiet on short scans.
    let mut last_draw: Option<Instant> = (style == ProgressStyle::Lines).then(Instant::now);
    while rx.changed().await.is_ok() {
        let snapshot = rx.borrow().clone();
        if snapshot.targets_total == 0 {
            continue;
        }
        let now = Instant::now();
        if should_redraw(last_draw, now, interval) {
            render_progress(style, &snapshot);
            last_draw = Some(now);
        }
    }
    finalize_progress_line(style);
}

fn redraw_interval(style: ProgressStyle) -> Duration {
    match style {
        ProgressStyle::InPlace => TTY_REDRAW_INTERVAL,
        ProgressStyle::Lines | ProgressStyle::Silent => PLAIN_REDRAW_INTERVAL,
    }
}

fn should_redraw(last_draw: Option<Instant>, now: Instant, interval: Duration) -> bool {
    match last_draw {
        None => true,
        Some(t) => now.duration_since(t) >= interval,
    }
}

fn eta(p: &DiscoveryProgress) -> Option<Duration> {
    let (done, total) = (p.targets_completed, p.targets_total);
    if done < ETA_MIN_COMPLETED || done >= total {
        return None;
    }
    let remaining = (total - done) as u128;
    let ms = p.elapsed_ms.saturating_mul(remaining) / done as u128;
    Some(Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX)))
}

pub(super) fn format_progress_line(p: &DiscoveryProgress) -> String {
    let (done, total) = (p.targets_completed, p.targets_total);
    let pct = done.saturating_mul(100).checked_div(total).unwrap_or(0);
    let elapsed = Duration::from_millis(u64::try_from(p.elapsed_ms).unwrap_or(u64::MAX));

    let mut segments = vec![
        format!(
            "{} {}",
            theme::label("hosts:"),
            theme::value(format!(
                "{}/{} ({pct}%)",
                humanize::count(done),
                humanize::count(total)
            ))
        ),
        format!(
            "{} {}",
            theme::label("records:"),
            theme::value(humanize::count(p.records_emitted))
        ),
        format!(
            "{} {}",
            theme::label("rate:"),
            theme::value(humanize::rate(done, elapsed))
        ),
        format!(
            "{} {}",
            theme::label("elapsed:"),
            theme::value(humanize::duration(elapsed))
        ),
    ];
    if let Some(remaining) = eta(p) {
        segments.push(format!(
            "{} {}",
            theme::label("eta:"),
            theme::value(humanize::duration(remaining))
        ));
    }
    format!("  {}", segments.join(&theme::sep()))
}

// stderr, not stdout: records stream to stdout and the progress line must not corrupt them.
fn render_progress(style: ProgressStyle, p: &DiscoveryProgress) {
    let mut err = std::io::stderr();
    let line = format_progress_line(p);
    let _ = match style {
        ProgressStyle::InPlace => write!(err, "{}{line}", theme::ERASE_LINE),
        ProgressStyle::Lines => writeln!(err, "{line}"),
        ProgressStyle::Silent => return,
    };
    let _ = err.flush();
}

fn finalize_progress_line(style: ProgressStyle) {
    if style == ProgressStyle::InPlace {
        let mut err = std::io::stderr();
        let _ = write!(err, "{}", theme::ERASE_LINE);
        let _ = err.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::super::theme::strip_ansi;
    use super::super::Verbosity;
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
    fn tty_redraws_four_times_a_second() {
        assert_eq!(
            redraw_interval(ProgressStyle::InPlace),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn plain_output_redraws_once_every_five_seconds() {
        assert_eq!(
            redraw_interval(ProgressStyle::Lines),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn records_streaming_to_the_same_terminal_silence_the_progress_line() {
        assert_eq!(style_for(true, true, true), ProgressStyle::Silent);
    }

    #[test]
    fn a_terminal_stderr_redraws_in_place_when_records_go_elsewhere() {
        assert_eq!(style_for(true, true, false), ProgressStyle::InPlace);
        assert_eq!(style_for(true, false, true), ProgressStyle::InPlace);
        assert_eq!(style_for(true, false, false), ProgressStyle::InPlace);
    }

    #[test]
    fn a_redirected_stderr_always_gets_whole_lines() {
        for stdout_is_terminal in [false, true] {
            for records_on_stdout in [false, true] {
                assert_eq!(
                    style_for(false, stdout_is_terminal, records_on_stdout),
                    ProgressStyle::Lines,
                    "stdout_is_terminal: {stdout_is_terminal}, records_on_stdout: {records_on_stdout}"
                );
            }
        }
    }

    #[test]
    fn should_redraw_always_true_on_first_draw() {
        assert!(should_redraw(None, Instant::now(), TTY_REDRAW_INTERVAL));
    }

    #[test]
    fn should_redraw_false_before_interval_elapses() {
        let t = Instant::now();
        assert!(!should_redraw(
            Some(t),
            t + Duration::from_millis(100),
            TTY_REDRAW_INTERVAL
        ));
    }

    #[test]
    fn should_redraw_true_at_and_after_interval() {
        let t = Instant::now();
        assert!(should_redraw(
            Some(t),
            t + TTY_REDRAW_INTERVAL,
            TTY_REDRAW_INTERVAL
        ));
        assert!(should_redraw(
            Some(t),
            t + Duration::from_millis(400),
            TTY_REDRAW_INTERVAL
        ));
    }

    #[test]
    fn format_progress_line_early_scan_omits_eta() {
        let line = strip_ansi(&format_progress_line(&progress(0, 10, 0, 0)));
        assert_eq!(
            line,
            "  hosts: 0/10 (0%) | records: 0 | rate: - | elapsed: 0ms"
        );
    }

    #[test]
    fn format_progress_line_below_eta_threshold_omits_eta() {
        let line = strip_ansi(&format_progress_line(&progress(2, 10, 1, 4000)));
        assert!(!line.contains("eta:"), "{line}");
        assert!(line.contains("hosts: 2/10 (20%)"), "{line}");
    }

    #[test]
    fn format_progress_line_shows_linear_eta_after_threshold() {
        // 5 of 10 done in 10s ⇒ 5 remaining at 2s each ⇒ ~10s left.
        let line = strip_ansi(&format_progress_line(&progress(5, 10, 3, 10_000)));
        assert_eq!(
            line,
            "  hosts: 5/10 (50%) | records: 3 | rate: 0.5/s | elapsed: 10.0s | eta: 10.0s"
        );
    }

    #[test]
    fn format_progress_line_at_completion_is_full_percent_without_eta() {
        let line = strip_ansi(&format_progress_line(&progress(10, 10, 8, 20_000)));
        assert_eq!(
            line,
            "  hosts: 10/10 (100%) | records: 8 | rate: 0.5/s | elapsed: 20.0s"
        );
    }

    #[test]
    fn format_progress_line_groups_thousands_in_large_scans() {
        let line = strip_ansi(&format_progress_line(&progress(
            12_000, 65_536, 4_501, 60_000,
        )));
        assert!(line.contains("hosts: 12,000/65,536 (18%)"), "{line}");
        assert!(line.contains("records: 4,501"), "{line}");
        assert!(line.contains("rate: 200/s"), "{line}");
    }

    #[tokio::test]
    async fn quiet_returns_before_the_loop_ever_watches_the_channel() {
        let (tx, rx) = watch::channel(DiscoveryProgress::default());
        let finished = tokio::time::timeout(
            Duration::from_millis(50),
            progress_display_loop(rx, ProgressStyle::Lines, OutputMode::from(Verbosity::Quiet)),
        )
        .await;
        assert!(finished.is_ok(), "quiet must not start the display loop");
        drop(tx);
    }

    #[tokio::test]
    async fn machine_output_returns_before_the_loop_ever_watches_the_channel() {
        let (tx, rx) = watch::channel(DiscoveryProgress::default());
        let finished = tokio::time::timeout(
            Duration::from_millis(50),
            progress_display_loop(
                rx,
                ProgressStyle::Lines,
                OutputMode::new(Verbosity::Normal, true),
            ),
        )
        .await;
        assert!(
            finished.is_ok(),
            "machine output must not start the display loop"
        );
        drop(tx);
    }

    #[tokio::test]
    async fn a_silent_style_returns_before_the_loop_ever_watches_the_channel() {
        let (tx, rx) = watch::channel(DiscoveryProgress::default());
        let finished = tokio::time::timeout(
            Duration::from_millis(50),
            progress_display_loop(
                rx,
                ProgressStyle::Silent,
                OutputMode::from(Verbosity::Normal),
            ),
        )
        .await;
        assert!(
            finished.is_ok(),
            "a shared terminal must not start the display loop"
        );
        drop(tx);
    }

    #[tokio::test]
    async fn a_chrome_verbosity_keeps_watching_until_the_sender_drops() {
        let (tx, rx) = watch::channel(DiscoveryProgress::default());
        let finished = tokio::time::timeout(
            Duration::from_millis(50),
            progress_display_loop(
                rx,
                ProgressStyle::Lines,
                OutputMode::from(Verbosity::Normal),
            ),
        )
        .await;
        assert!(
            finished.is_err(),
            "the loop must watch while a sender lives"
        );
        drop(tx);
    }

    #[test]
    fn eta_is_none_before_the_threshold_and_at_completion() {
        assert!(eta(&progress(2, 10, 0, 4_000)).is_none());
        assert!(eta(&progress(10, 10, 0, 4_000)).is_none());
    }

    #[test]
    fn eta_extrapolates_linearly_from_completed_targets() {
        assert_eq!(
            eta(&progress(5, 10, 0, 10_000)),
            Some(Duration::from_secs(10))
        );
    }
}
