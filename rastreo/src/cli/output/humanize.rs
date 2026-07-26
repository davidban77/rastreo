use std::time::Duration;

pub(crate) fn duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1_000 {
        return format!("{ms}ms");
    }
    let tenths = (ms + 50) / 100;
    if tenths < 600 {
        return format!("{}.{}s", tenths / 10, tenths % 10);
    }
    let secs = (ms + 500) / 1_000;
    if secs < 3_600 {
        return format!("{}m{:02}s", secs / 60, secs % 60);
    }
    let mins = (secs + 30) / 60;
    format!("{}h{:02}m", mins / 60, mins % 60)
}

pub(crate) fn count(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    let lead = digits.len() % 3;
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && i % 3 == lead {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub(crate) fn rate(n: usize, d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs <= 0.0 {
        return "-".to_string();
    }
    let per_sec = n as f64 / secs;
    if per_sec >= 10.0 {
        format!("{}/s", count(per_sec.round() as usize))
    } else {
        format!("{per_sec:.1}/s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Duration::from_millis(0), "0ms")]
    #[case(Duration::from_millis(820), "820ms")]
    #[case(Duration::from_millis(999), "999ms")]
    #[case(Duration::from_secs(1), "1.0s")]
    #[case(Duration::from_millis(4_200), "4.2s")]
    #[case(Duration::from_millis(59_900), "59.9s")]
    #[case(Duration::from_secs(60), "1m00s")]
    #[case(Duration::from_secs(63), "1m03s")]
    #[case(Duration::from_secs(3_599), "59m59s")]
    #[case(Duration::from_secs(3_600), "1h00m")]
    #[case(Duration::from_secs(7_200), "2h00m")]
    fn duration_renders_each_magnitude_band(#[case] input: Duration, #[case] expected: &str) {
        assert_eq!(duration(input), expected);
    }

    #[test]
    fn duration_never_renders_sixty_seconds_as_a_sub_minute_value() {
        assert_eq!(duration(Duration::from_millis(59_960)), "1m00s");
    }

    #[test]
    fn duration_never_renders_sixty_minutes_as_a_sub_hour_value() {
        assert_eq!(duration(Duration::from_millis(3_599_600)), "1h00m");
    }

    #[rstest]
    #[case(0, "0")]
    #[case(7, "7")]
    #[case(999, "999")]
    #[case(1_000, "1,000")]
    #[case(1_778, "1,778")]
    #[case(12_345, "12,345")]
    #[case(1_234_567, "1,234,567")]
    fn count_groups_thousands(#[case] input: usize, #[case] expected: &str) {
        assert_eq!(count(input), expected);
    }

    #[test]
    fn rate_is_a_dash_for_a_zero_window() {
        assert_eq!(rate(10, Duration::ZERO), "-");
    }

    #[test]
    fn rate_keeps_one_decimal_below_ten_per_second() {
        assert_eq!(rate(3, Duration::from_secs(2)), "1.5/s");
    }

    #[test]
    fn rate_rounds_to_whole_units_above_ten_per_second() {
        assert_eq!(rate(1_778, Duration::from_secs(2)), "889/s");
    }

    #[test]
    fn rate_groups_thousands_like_count() {
        assert_eq!(rate(24_000, Duration::from_secs(2)), "12,000/s");
    }
}
