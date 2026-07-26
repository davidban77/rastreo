//! Every colour and glyph decision in the CLI. Nothing else calls owo-colors.
//!
//! Roles allocate a `String` per call — a few dozen per run, never on the per-record path.

use std::fmt::Display;
use std::sync::OnceLock;

use clap::builder::styling::{AnsiColor, Styles};
use owo_colors::{OwoColorize, Stream::Stderr};

pub(crate) const HELP_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default());

pub(crate) fn label(v: impl Display) -> String {
    v.if_supports_color(Stderr, |t| t.dimmed()).to_string()
}

pub(crate) fn value(v: impl Display) -> String {
    v.if_supports_color(Stderr, |t| t.cyan()).to_string()
}

pub(crate) fn name(v: impl Display) -> String {
    v.if_supports_color(Stderr, |t| t.bold()).to_string()
}

pub(crate) fn ok(v: impl Display) -> String {
    v.if_supports_color(Stderr, |t| t.green()).to_string()
}

pub(crate) fn done(v: impl Display) -> String {
    v.if_supports_color(Stderr, |t| t.blue()).to_string()
}

pub(crate) fn warn(v: impl Display) -> String {
    v.if_supports_color(Stderr, |t| t.yellow()).to_string()
}

pub(crate) fn err(v: impl Display) -> String {
    v.if_supports_color(Stderr, |t| t.red()).to_string()
}

pub(crate) fn sep() -> String {
    label(" | ")
}

/// Asks the same detector that paints the banners, so tracing lines never disagree with them.
pub(crate) fn stderr_supports_colour() -> bool {
    !ok("x").eq("x")
}

/// CR plus CSI erase-in-line: rewinds the cursor and clears the line it sat on.
pub(crate) const ERASE_LINE: &str = "\r\x1b[K";

pub(crate) struct Glyphs {
    pub start: &'static str,
    pub done: &'static str,
    pub warn: &'static str,
    pub bullet: &'static str,
    pub arrow: &'static str,
}

pub(crate) const UNICODE: Glyphs = Glyphs {
    start: "▶",
    done: "■",
    warn: "⚠",
    bullet: "•",
    arrow: "→",
};

pub(crate) const ASCII: Glyphs = Glyphs {
    start: ">",
    done: "#",
    warn: "!",
    bullet: "*",
    arrow: "->",
};

pub(crate) fn glyphs() -> &'static Glyphs {
    static CACHED: OnceLock<&'static Glyphs> = OnceLock::new();
    CACHED.get_or_init(|| {
        let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
        glyphs_for(
            std::env::var("RASTREO_ASCII").ok().as_deref(),
            locale.as_deref(),
        )
    })
}

fn glyphs_for(ascii_override: Option<&str>, locale: Option<&str>) -> &'static Glyphs {
    if matches!(ascii_override, Some(v) if !v.is_empty() && v != "0") {
        return &ASCII;
    }
    match locale {
        // An unset locale is the norm on macOS and Windows terminals, which render UTF-8 anyway.
        None => &UNICODE,
        Some(l) => {
            let l = l.to_ascii_lowercase();
            if l.contains("utf-8") || l.contains("utf8") {
                &UNICODE
            } else {
                &ASCII
            }
        }
    }
}

// owo-colors' override is one process-global AtomicU8, so concurrent tests would read each
// other's setting. Every mutator serializes here.
#[cfg(test)]
fn colour_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub(crate) fn with_colour<T>(f: impl FnOnce() -> T) -> T {
    let _guard = colour_guard();
    owo_colors::with_override(true, f)
}

#[cfg(test)]
pub(crate) fn without_colour<T>(f: impl FnOnce() -> T) -> T {
    let _guard = colour_guard();
    owo_colors::with_override(false, f)
}

/// Drop CSI sequences so a layout assertion holds whether or not the terminal took colour.
#[cfg(test)]
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        if chars.next() != Some('[') {
            continue;
        }
        for c in chars.by_ref() {
            if c.is_ascii_alphabetic() {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_transparent_without_colour_and_distinct_with_it() {
        without_colour(|| {
            assert_eq!(label("targets:"), "targets:");
            assert_eq!(value(42), "42");
            assert_eq!(name("discover"), "discover");
            assert_eq!(ok("▶"), "▶");
            assert_eq!(done("■"), "■");
            assert_eq!(warn("⚠"), "⚠");
            assert_eq!(err("dlq"), "dlq");
            assert_eq!(sep(), " | ");
        });

        with_colour(|| {
            let painted = [
                label("x"),
                value("x"),
                name("x"),
                ok("x"),
                done("x"),
                warn("x"),
                err("x"),
            ];
            for s in &painted {
                assert!(s.contains('\u{1b}'), "expected an escape sequence in {s:?}");
                assert_eq!(strip_ansi(s), "x", "payload must survive: {s:?}");
            }
            let distinct: std::collections::BTreeSet<&String> = painted.iter().collect();
            assert_eq!(
                distinct.len(),
                painted.len(),
                "each role must render a distinct colour"
            );
        });
    }

    #[test]
    fn stderr_supports_colour_tracks_the_role_renderers() {
        without_colour(|| assert!(!stderr_supports_colour()));
        with_colour(|| assert!(stderr_supports_colour()));
    }

    #[test]
    fn strip_ansi_removes_only_the_escape_sequences() {
        assert_eq!(strip_ansi("\u{1b}[36m22, 80\u{1b}[0m"), "22, 80");
        assert_eq!(strip_ansi("plain"), "plain");
        assert_eq!(strip_ansi(""), "");
    }

    #[test]
    fn glyphs_default_to_unicode_when_no_locale_is_set() {
        assert_eq!(glyphs_for(None, None).start, UNICODE.start);
    }

    #[test]
    fn glyphs_are_unicode_for_a_utf8_locale() {
        for locale in ["en_US.UTF-8", "en_US.utf8", "C.UTF-8", "es_ES.Utf-8"] {
            assert_eq!(
                glyphs_for(None, Some(locale)).done,
                UNICODE.done,
                "locale {locale}"
            );
        }
    }

    #[test]
    fn glyphs_fall_back_to_ascii_for_a_non_utf8_locale() {
        for locale in ["C", "POSIX", "en_US.ISO8859-1"] {
            assert_eq!(
                glyphs_for(None, Some(locale)).done,
                ASCII.done,
                "locale {locale}"
            );
        }
    }

    #[test]
    fn rastreo_ascii_forces_ascii_over_a_utf8_locale() {
        assert_eq!(
            glyphs_for(Some("1"), Some("en_US.UTF-8")).start,
            ASCII.start
        );
    }

    #[test]
    fn rastreo_ascii_zero_or_empty_does_not_force_ascii() {
        assert_eq!(glyphs_for(Some("0"), None).start, UNICODE.start);
        assert_eq!(glyphs_for(Some(""), None).start, UNICODE.start);
    }

    #[test]
    fn ascii_table_is_pure_ascii() {
        for g in [
            ASCII.start,
            ASCII.done,
            ASCII.warn,
            ASCII.bullet,
            ASCII.arrow,
        ] {
            assert!(g.is_ascii(), "{g:?} is not ASCII");
        }
    }

    fn sources_outside_theme() -> Vec<std::path::PathBuf> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let files = super::super::rust_sources(&src);
        assert!(files.len() > 3, "expected to walk the crate source tree");
        files
            .into_iter()
            .filter(|p| p.file_name().is_some_and(|n| n != "theme.rs"))
            .collect()
    }

    fn offenders(needles: &[&str]) -> Vec<String> {
        sources_outside_theme()
            .iter()
            .filter(|p| {
                let body = std::fs::read_to_string(p).expect("read source");
                needles.iter().any(|n| body.contains(n))
            })
            .map(|p| p.display().to_string())
            .collect()
    }

    #[test]
    fn no_source_file_outside_theme_touches_owo_colors() {
        let found = offenders(&["owo_colors", "if_supports_color"]);
        assert!(
            found.is_empty(),
            "colour decisions belong in theme.rs; found owo-colors usage in {found:?}"
        );
    }

    #[test]
    fn no_source_file_outside_theme_writes_a_raw_ansi_escape() {
        let found = offenders(&["\\x1b[", "\\u{1b}["]);
        assert!(
            found.is_empty(),
            "escape sequences belong in theme.rs; found raw CSI literals in {found:?}"
        );
    }
}
