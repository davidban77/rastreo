//! RFC 3339 UTC serde helpers for `SystemTime` fields; used via `#[serde(with = ...)]`.

use std::time::SystemTime;

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    let dt: DateTime<Utc> = (*t).into();
    let rendered = Rfc3339Utc::render(&dt);
    let text = rendered.as_str().map_err(serde::ser::Error::custom)?;
    s.serialize_str(text)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
    let s = String::deserialize(d)?;
    let dt = DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom)?;
    Ok(SystemTime::from(dt.with_timezone(&Utc)))
}

pub fn date_time_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut schema = generator.subschema_for::<String>();
    schema.insert("format".to_owned(), "date-time".into());
    schema
}

// `-262143-12-31T23:59:60.999999999Z`, the widest rendering chrono's year range admits.
const RENDER_CAPACITY: usize = 33;

/// UTC RFC 3339 with `SecondsFormat::AutoSi` subseconds, rendered on the stack.
struct Rfc3339Utc {
    bytes: [u8; RENDER_CAPACITY],
    len: usize,
}

fn two_digits(value: u32) -> [u8; 2] {
    [b'0' + (value / 10) as u8, b'0' + (value % 10) as u8]
}

impl Rfc3339Utc {
    fn render(dt: &DateTime<Utc>) -> Self {
        let (second, nanosecond) = match dt.nanosecond().checked_sub(1_000_000_000) {
            Some(leap) => (dt.second() + 1, leap),
            None => (dt.second(), dt.nanosecond()),
        };
        let month = two_digits(dt.month());
        let day = two_digits(dt.day());
        let hour = two_digits(dt.hour());
        let minute = two_digits(dt.minute());
        let second = two_digits(second);

        let mut out = Self {
            bytes: [0; RENDER_CAPACITY],
            len: 0,
        };
        out.push_year(dt.year());
        #[rustfmt::skip]
        out.push(&[
            b'-', month[0], month[1],
            b'-', day[0], day[1],
            b'T', hour[0], hour[1],
            b':', minute[0], minute[1],
            b':', second[0], second[1],
        ]);
        out.push_subsecond(nanosecond);
        out.push(b"Z");
        out
    }

    fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.bytes[..self.len])
    }

    fn push(&mut self, chunk: &[u8]) {
        let end = self.len + chunk.len();
        // Dropping a chunk would emit a plausible but wrong timestamp; fail loudly in tests instead.
        debug_assert!(end <= RENDER_CAPACITY);
        if let Some(slot) = self.bytes.get_mut(self.len..end) {
            slot.copy_from_slice(chunk);
            self.len = end;
        }
    }

    fn push_year(&mut self, year: i32) {
        if !(0..=9999).contains(&year) {
            self.push_signed_year(year);
            return;
        }
        let centuries = two_digits(year as u32 / 100);
        let years = two_digits(year as u32 % 100);
        self.push(&[centuries[0], centuries[1], years[0], years[1]]);
    }

    fn push_signed_year(&mut self, year: i32) {
        const MIN_DIGITS: usize = 4;
        let mut digits = [b'0'; 6];
        let mut magnitude = year.unsigned_abs();
        let mut first = digits.len();
        while magnitude > 0 {
            first -= 1;
            digits[first] = b'0' + (magnitude % 10) as u8;
            magnitude /= 10;
        }
        self.push(&[if year < 0 { b'-' } else { b'+' }]);
        self.push(&digits[first.min(digits.len() - MIN_DIGITS)..]);
    }

    fn push_subsecond(&mut self, nanosecond: u32) {
        if nanosecond == 0 {
            return;
        }
        let width = if nanosecond.is_multiple_of(1_000_000) {
            3
        } else if nanosecond.is_multiple_of(1_000) {
            6
        } else {
            9
        };
        let mut fraction = [b'.'; 10];
        let mut rest = nanosecond;
        for slot in fraction[1..].iter_mut().rev() {
            *slot = b'0' + (rest % 10) as u8;
            rest /= 10;
        }
        self.push(&fraction[..=width]);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use chrono::{NaiveDate, SecondsFormat, TimeZone};

    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Wrapper {
        #[serde(with = "crate::model::serde_iso8601")]
        t: SystemTime,
    }

    fn rendered(dt: &DateTime<Utc>) -> String {
        Rfc3339Utc::render(dt)
            .as_str()
            .expect("render is ascii")
            .to_owned()
    }

    fn chrono_reference(dt: &DateTime<Utc>) -> String {
        dt.to_rfc3339_opts(SecondsFormat::AutoSi, true)
    }

    fn assert_matches_chrono(dt: &DateTime<Utc>) {
        assert_eq!(rendered(dt), chrono_reference(dt), "for {dt:?}");
    }

    fn at(seconds: i64, nanoseconds: u32) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, nanoseconds)
            .single()
            .expect("in-range timestamp")
    }

    #[test]
    fn the_epoch_renders_without_a_fraction() {
        assert_eq!(rendered(&at(0, 0)), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn subsecond_width_follows_the_smallest_si_unit_that_keeps_every_digit() {
        for (nanoseconds, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:00.000000001Z"),
            (999, "1970-01-01T00:00:00.000000999Z"),
            (1_000, "1970-01-01T00:00:00.000001Z"),
            (999_999, "1970-01-01T00:00:00.000999999Z"),
            (999_999_000, "1970-01-01T00:00:00.999999Z"),
            (1_000_000, "1970-01-01T00:00:00.001Z"),
            (999_000_000, "1970-01-01T00:00:00.999Z"),
            (999_999_999, "1970-01-01T00:00:00.999999999Z"),
        ] {
            let dt = at(0, nanoseconds);
            assert_eq!(rendered(&dt), expected);
            assert_matches_chrono(&dt);
        }
    }

    #[test]
    fn a_dense_subsecond_corpus_matches_chrono() {
        let mut corpus: Vec<u32> = vec![0, 1, 999, 1_000, 999_999, 1_000_000, 999_999_999];
        corpus.extend(0..1_000);
        corpus.extend((0..1_000).map(|n| n * 1_000));
        corpus.extend((0..1_000).map(|n| n * 1_000_000));
        corpus.extend((0..1_000).map(|n| n * 999_983));
        corpus.extend([10, 100, 10_000, 100_000, 10_000_000, 100_000_000]);
        corpus.extend([123_456_789, 500_000_000, 999_999_000, 999_000_999]);

        for nanoseconds in corpus {
            assert_matches_chrono(&at(0, nanoseconds));
            assert_matches_chrono(&at(1_754_000_000, nanoseconds));
        }
    }

    #[test]
    fn a_pseudo_random_sweep_across_the_whole_chrono_range_matches_chrono() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..20_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let seconds = (state as i64) % 8_000_000_000_000;
            let nanoseconds = ((state >> 32) % 1_000_000_000) as u32;
            assert_matches_chrono(&at(seconds, nanoseconds));
        }
    }

    #[test]
    fn every_second_of_a_leap_day_matches_chrono() {
        let midnight = NaiveDate::from_ymd_opt(2024, 2, 29)
            .expect("leap day")
            .and_hms_opt(0, 0, 0)
            .expect("midnight")
            .and_utc()
            .timestamp();
        for offset in 0..86_400i64 {
            assert_matches_chrono(&at(midnight + offset, offset as u32 * 11_573));
        }
    }

    #[test]
    fn years_outside_the_four_digit_range_carry_an_explicit_sign() {
        for (dt, expected) in [
            (at(-62_167_219_200, 0), "0000-01-01T00:00:00Z"),
            (at(-62_167_219_201, 0), "-0001-12-31T23:59:59Z"),
            (at(253_402_300_799, 0), "9999-12-31T23:59:59Z"),
            (at(253_402_300_800, 0), "+10000-01-01T00:00:00Z"),
        ] {
            assert_eq!(rendered(&dt), expected);
            assert_matches_chrono(&dt);
        }
    }

    #[test]
    fn the_widest_representable_rendering_fills_the_buffer_exactly() {
        let widest = NaiveDate::MIN
            .and_hms_nano_opt(23, 59, 59, 1_999_999_999)
            .expect("leap second on the earliest date")
            .and_utc();
        assert_matches_chrono(&widest);
        assert_eq!(rendered(&widest).len(), RENDER_CAPACITY);

        for edge in [DateTime::<Utc>::MIN_UTC, DateTime::<Utc>::MAX_UTC] {
            assert_matches_chrono(&edge);
        }
    }

    #[test]
    fn a_leap_second_rolls_into_a_sixtieth_second_like_chrono() {
        let dt = NaiveDate::from_ymd_opt(2016, 12, 31)
            .expect("date")
            .and_hms_nano_opt(23, 59, 59, 1_500_000_000)
            .expect("leap second")
            .and_utc();
        assert_eq!(rendered(&dt), "2016-12-31T23:59:60.500Z");
        assert_matches_chrono(&dt);
    }

    #[test]
    fn system_times_on_both_sides_of_the_epoch_serialize_like_chrono() {
        for offset in [0u64, 1, 999_999_999, 1_754_000_000] {
            for nanoseconds in [0u32, 1, 1_000, 1_000_000, 999_999_999] {
                let span = Duration::new(offset, nanoseconds);
                for t in [UNIX_EPOCH + span, UNIX_EPOCH - span] {
                    let dt: DateTime<Utc> = t.into();
                    assert_eq!(
                        serde_json::to_string(&Wrapper { t }).expect("serialize"),
                        format!("{{\"t\":\"{}\"}}", chrono_reference(&dt))
                    );
                }
            }
        }
    }

    #[test]
    fn serializing_a_microsecond_instant_renders_six_fractional_digits() {
        let t = SystemTime::from(
            NaiveDate::from_ymd_opt(2026, 7, 27)
                .expect("date")
                .and_hms_micro_opt(9, 14, 23, 917_897)
                .expect("time")
                .and_utc(),
        );
        let value = serde_json::to_value(Wrapper { t }).expect("serialize");
        assert_eq!(value["t"], "2026-07-27T09:14:23.917897Z");
    }

    #[test]
    fn serialized_timestamps_round_trip_back_to_the_same_instant() {
        for nanoseconds in [0u32, 1, 1_000, 1_000_000, 123_456_789] {
            let t = UNIX_EPOCH + Duration::new(1_754_000_000, nanoseconds);
            let json = serde_json::to_string(&Wrapper { t }).expect("serialize");
            let back: Wrapper = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back.t, t);
        }
    }
}
