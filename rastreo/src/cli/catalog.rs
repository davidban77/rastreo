#![cfg(feature = "config")]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

const CATALOG_DIR_ENV: &str = "RASTREO_CATALOG_DIR";
const XDG_CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";
const HOME_ENV: &str = "HOME";
const ETC_CATALOG_DIR: &str = "/etc/rastreo/catalog";
const MAX_LISTED_NAMES_PER_DIR: usize = 20;

/// Resolve a catalog `@name` to a scenario path: search `RASTREO_CATALOG_DIR` if set, else the user config dir then `/etc/rastreo/catalog`; first directory wins, `.yml` before `.yaml`.
pub fn resolve_catalog_name(name: &str) -> Result<PathBuf> {
    resolve_catalog_name_with_env(name, &StdEnv)
}

trait Env {
    fn var(&self, key: &str) -> Option<String>;
}

struct StdEnv;

impl Env for StdEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// List every catalog `@name` across the search path with the exact scenario path a run would load, sorted and deduped by name.
pub fn list_catalog() -> Vec<(String, PathBuf)> {
    list_catalog_with_env(&StdEnv)
}

pub fn run_list() -> Result<()> {
    let entries = list_catalog();
    if entries.is_empty() {
        super::output::print_catalog_empty(&none_found_message(&search_dirs(&StdEnv)));
        return Ok(());
    }
    print!("{}", format_listing(&entries));
    Ok(())
}

fn list_catalog_with_env(env: &dyn Env) -> Vec<(String, PathBuf)> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for dir in &search_dirs(env) {
        names.extend(list_catalog_names(dir));
    }
    // Resolve each name back through resolve_catalog_name so the listed path matches what a run picks: first directory wins, .yml before .yaml.
    names
        .into_iter()
        .filter_map(|name| {
            resolve_catalog_name_with_env(&name, env)
                .ok()
                .map(|path| (name, path))
        })
        .collect()
}

fn none_found_message(dirs: &[PathBuf]) -> String {
    let searched = dirs
        .iter()
        .map(|d| d.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("no catalog scenarios found (searched: {searched})")
}

fn format_listing(entries: &[(String, PathBuf)]) -> String {
    let width = entries
        .iter()
        .map(|(name, _)| name.len() + 1)
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (name, path) in entries {
        let handle = format!("@{name}");
        let _ = writeln!(out, "{handle:<width$}  ->  {}", path.display());
    }
    out
}

fn resolve_catalog_name_with_env(name: &str, env: &dyn Env) -> Result<PathBuf> {
    if name.is_empty() {
        return Err(anyhow!("catalog name may not be empty"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(anyhow!(
            "catalog name may not contain path separators: {name:?}"
        ));
    }

    let stem = strip_yaml_suffix(name);
    let dirs = search_dirs(env);

    for dir in &dirs {
        for ext in ["yml", "yaml"] {
            let candidate = dir.join(format!("{stem}.{ext}"));
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(anyhow!(not_found_message(stem, &dirs)))
}

fn strip_yaml_suffix(name: &str) -> &str {
    name.strip_suffix(".yml")
        .or_else(|| name.strip_suffix(".yaml"))
        .unwrap_or(name)
}

fn search_dirs(env: &dyn Env) -> Vec<PathBuf> {
    if let Some(raw) = env.var(CATALOG_DIR_ENV) {
        return raw
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    let mut dirs = Vec::new();
    let user_dir = if let Some(xdg) = env.var(XDG_CONFIG_HOME_ENV).filter(|s| !s.is_empty()) {
        PathBuf::from(xdg).join("rastreo").join("catalog")
    } else if let Some(home) = env.var(HOME_ENV).filter(|s| !s.is_empty()) {
        PathBuf::from(home)
            .join(".config")
            .join("rastreo")
            .join("catalog")
    } else {
        return vec![PathBuf::from(ETC_CATALOG_DIR)];
    };
    dirs.push(user_dir);
    dirs.push(PathBuf::from(ETC_CATALOG_DIR));
    dirs
}

fn not_found_message(name: &str, dirs: &[PathBuf]) -> String {
    let existing_dirs: Vec<&Path> = dirs.iter().filter(|d| d.is_dir()).map(|p| &**p).collect();

    let mut msg = format!("catalog scenario '@{name}' not found");
    msg.push_str("\nsearched directories:");
    for dir in dirs {
        let marker = if dir.is_dir() { "" } else { " (missing)" };
        msg.push_str(&format!("\n  - {}{marker}", dir.display()));
    }

    if existing_dirs.is_empty() {
        msg.push_str(
            "\nno catalog directories exist; create `~/.config/rastreo/catalog/` and add scenario YAML files there",
        );
        return msg;
    }

    let mut any_available = false;
    for dir in &existing_dirs {
        let names = list_catalog_names(dir);
        if names.is_empty() {
            continue;
        }
        any_available = true;
        msg.push_str(&format!("\navailable in {}:", dir.display()));
        for n in names.iter().take(MAX_LISTED_NAMES_PER_DIR) {
            msg.push_str(&format!("\n  - @{n}"));
        }
        if names.len() > MAX_LISTED_NAMES_PER_DIR {
            let extra = names.len() - MAX_LISTED_NAMES_PER_DIR;
            msg.push_str(&format!("\n  ... and {extra} more"));
        }
    }
    if !any_available {
        msg.push_str("\nno scenario YAML files present in any searched directory");
    }

    msg
}

fn list_catalog_names(dir: &Path) -> Vec<String> {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut names = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let stem = match file_name
            .strip_suffix(".yml")
            .or_else(|| file_name.strip_suffix(".yaml"))
        {
            Some(s) => s.to_string(),
            None => continue,
        };
        names.push(stem);
    }
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    struct FakeEnv(HashMap<String, String>);

    impl FakeEnv {
        fn new() -> Self {
            Self(HashMap::new())
        }
        fn set(mut self, key: &str, val: impl Into<String>) -> Self {
            self.0.insert(key.into(), val.into());
            self
        }
    }

    impl Env for FakeEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    fn touch(dir: &Path, rel: &str) -> PathBuf {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(&p, b"version: 1\n").expect("write file");
        p
    }

    #[test]
    fn resolve_catalog_name_finds_yml_in_user_dir() {
        let home = TempDir::new().expect("tempdir");
        let expected = touch(home.path(), ".config/rastreo/catalog/foo.yml");
        let env = FakeEnv::new().set(HOME_ENV, home.path().to_string_lossy().into_owned());
        let got = resolve_catalog_name_with_env("foo", &env).expect("resolves");
        assert_eq!(got, expected);
    }

    #[test]
    fn resolve_catalog_name_prefers_yml_over_yaml() {
        let dir = TempDir::new().expect("tempdir");
        let yml = touch(dir.path(), "foo.yml");
        let _yaml = touch(dir.path(), "foo.yaml");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        let got = resolve_catalog_name_with_env("foo", &env).expect("resolves");
        assert_eq!(got, yml);
    }

    #[test]
    fn resolve_catalog_name_falls_back_to_yaml_when_yml_missing() {
        let dir = TempDir::new().expect("tempdir");
        let yaml = touch(dir.path(), "foo.yaml");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        let got = resolve_catalog_name_with_env("foo", &env).expect("resolves");
        assert_eq!(got, yaml);
    }

    #[test]
    fn resolve_catalog_name_prefers_first_dir_in_catalog_path() {
        let a = TempDir::new().expect("a");
        let b = TempDir::new().expect("b");
        let a_file = touch(a.path(), "foo.yml");
        let _b_file = touch(b.path(), "foo.yml");
        let joined = format!(
            "{}:{}",
            a.path().to_string_lossy(),
            b.path().to_string_lossy()
        );
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, joined);
        let got = resolve_catalog_name_with_env("foo", &env).expect("resolves");
        assert_eq!(got, a_file);
    }

    #[test]
    fn resolve_catalog_name_prefers_user_dir_over_etc() {
        let home = TempDir::new().expect("tempdir");
        let user_file = touch(home.path(), ".config/rastreo/catalog/foo.yml");
        let env = FakeEnv::new().set(HOME_ENV, home.path().to_string_lossy().into_owned());
        let got = resolve_catalog_name_with_env("foo", &env).expect("resolves");
        assert_eq!(got, user_file);
    }

    #[test]
    fn resolve_catalog_name_strips_yml_suffix_from_input() {
        let dir = TempDir::new().expect("tempdir");
        let file = touch(dir.path(), "foo.yml");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        let got = resolve_catalog_name_with_env("foo.yml", &env).expect("resolves");
        assert_eq!(got, file);
    }

    #[test]
    fn resolve_catalog_name_strips_yaml_suffix_from_input() {
        let dir = TempDir::new().expect("tempdir");
        let file = touch(dir.path(), "foo.yaml");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        let got = resolve_catalog_name_with_env("foo.yaml", &env).expect("resolves");
        assert_eq!(got, file);
    }

    #[test]
    fn resolve_catalog_name_rejects_path_separators() {
        let env = FakeEnv::new();
        let err = resolve_catalog_name_with_env("foo/bar", &env).expect_err("slash");
        assert!(format!("{err}").contains("path separators"));
        let err = resolve_catalog_name_with_env("foo\\bar", &env).expect_err("backslash");
        assert!(format!("{err}").contains("path separators"));
    }

    #[test]
    fn resolve_catalog_name_rejects_empty_string() {
        let env = FakeEnv::new();
        let err = resolve_catalog_name_with_env("", &env).expect_err("empty");
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn resolve_catalog_name_reports_available_names_on_miss() {
        let dir = TempDir::new().expect("tempdir");
        touch(dir.path(), "alpha.yml");
        touch(dir.path(), "beta.yaml");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        let err = resolve_catalog_name_with_env("missing", &env).expect_err("miss");
        let msg = format!("{err}");
        assert!(msg.contains("@missing"), "{msg}");
        assert!(msg.contains("searched directories"), "{msg}");
        assert!(msg.contains("@alpha"), "{msg}");
        assert!(msg.contains("@beta"), "{msg}");
    }

    #[test]
    fn resolve_catalog_name_reports_no_dirs_when_none_exist() {
        let placeholder = TempDir::new().expect("tempdir");
        let missing = placeholder.path().join("nonexistent");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, missing.to_string_lossy().into_owned());
        let err = resolve_catalog_name_with_env("anything", &env).expect_err("miss");
        let msg = format!("{err}");
        assert!(msg.contains("no catalog directories exist"), "{msg}");
        assert!(msg.contains("~/.config/rastreo/catalog/"), "{msg}");
    }

    #[test]
    fn search_dirs_uses_xdg_when_set() {
        let xdg = TempDir::new().expect("tempdir");
        let env = FakeEnv::new().set(
            XDG_CONFIG_HOME_ENV,
            xdg.path().to_string_lossy().into_owned(),
        );
        let dirs = search_dirs(&env);
        assert!(
            dirs[0].ends_with("rastreo/catalog"),
            "first dir: {:?}",
            dirs[0]
        );
        assert!(dirs[0].starts_with(xdg.path()));
        assert_eq!(
            dirs.last().map(|p| p.as_path()),
            Some(Path::new(ETC_CATALOG_DIR))
        );
    }

    #[test]
    fn search_dirs_skips_empty_entries_in_catalog_env() {
        let dir = TempDir::new().expect("tempdir");
        let joined = format!("::{}::", dir.path().to_string_lossy());
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, joined);
        let dirs = search_dirs(&env);
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0], dir.path());
    }

    #[test]
    fn strip_yaml_suffix_leaves_stem_unchanged() {
        assert_eq!(strip_yaml_suffix("office"), "office");
        assert_eq!(strip_yaml_suffix("office.yml"), "office");
        assert_eq!(strip_yaml_suffix("office.yaml"), "office");
        assert_eq!(strip_yaml_suffix("some.thing.yml"), "some.thing");
    }

    #[test]
    fn resolve_catalog_name_truncates_listing_when_dir_has_more_than_max() {
        let dir = TempDir::new().expect("tempdir");
        let total = MAX_LISTED_NAMES_PER_DIR + 5;
        for i in 1..=total {
            touch(dir.path(), &format!("name-{i:02}.yml"));
        }
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        let err = resolve_catalog_name_with_env("missing", &env).expect_err("miss");
        let msg = format!("{err}");
        assert!(msg.contains("@name-01"), "{msg}");
        assert!(
            msg.contains(&format!("@name-{MAX_LISTED_NAMES_PER_DIR:02}")),
            "{msg}"
        );
        let overflow_marker = format!("@name-{:02}", MAX_LISTED_NAMES_PER_DIR + 1);
        assert!(!msg.contains(&overflow_marker), "{msg}");
        assert!(!msg.contains(&format!("@name-{total:02}")), "{msg}");
        let extra = total - MAX_LISTED_NAMES_PER_DIR;
        assert!(msg.contains(&format!("... and {extra} more")), "{msg}");
    }

    #[test]
    fn list_catalog_names_returns_sorted_deduped_stems() {
        let dir = TempDir::new().expect("tempdir");
        touch(dir.path(), "b.yml");
        touch(dir.path(), "a.yaml");
        touch(dir.path(), "c.txt");
        let names = list_catalog_names(dir.path());
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn list_catalog_returns_names_sorted_with_resolved_paths() {
        let dir = TempDir::new().expect("tempdir");
        let foo = touch(dir.path(), "foo.yml");
        let bar = touch(dir.path(), "bar.yaml");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        let got = list_catalog_with_env(&env);
        assert_eq!(
            got,
            vec![("bar".to_string(), bar), ("foo".to_string(), foo)]
        );
    }

    #[test]
    fn list_catalog_first_dir_wins_matches_resolve_catalog_name() {
        let a = TempDir::new().expect("a");
        let b = TempDir::new().expect("b");
        let a_file = touch(a.path(), "shared.yml");
        let _b_file = touch(b.path(), "shared.yml");
        let joined = format!(
            "{}:{}",
            a.path().to_string_lossy(),
            b.path().to_string_lossy()
        );
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, joined);
        let listed = list_catalog_with_env(&env);
        let shared = listed
            .iter()
            .find(|(name, _)| name == "shared")
            .expect("shared listed");
        let resolved = resolve_catalog_name_with_env("shared", &env).expect("resolves");
        assert_eq!(shared.1, a_file);
        assert_eq!(shared.1, resolved);
    }

    #[test]
    fn list_catalog_yml_shadows_yaml_of_same_name() {
        let dir = TempDir::new().expect("tempdir");
        let yml = touch(dir.path(), "office.yml");
        let _yaml = touch(dir.path(), "office.yaml");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        let office: Vec<_> = list_catalog_with_env(&env)
            .into_iter()
            .filter(|(name, _)| name == "office")
            .collect();
        assert_eq!(office.len(), 1);
        assert_eq!(office[0].1, yml);
    }

    #[test]
    fn list_catalog_is_empty_when_no_catalog_files_present() {
        let dir = TempDir::new().expect("tempdir");
        let env = FakeEnv::new().set(CATALOG_DIR_ENV, dir.path().to_string_lossy().into_owned());
        assert!(list_catalog_with_env(&env).is_empty());
    }

    #[test]
    fn none_found_message_lists_searched_dirs() {
        let msg = none_found_message(&[PathBuf::from("/a/catalog"), PathBuf::from("/b/catalog")]);
        assert!(msg.contains("no catalog scenarios found"), "{msg}");
        assert!(msg.contains("/a/catalog"), "{msg}");
        assert!(msg.contains("/b/catalog"), "{msg}");
    }

    #[test]
    fn format_listing_shows_each_handle_and_path_on_its_own_line() {
        let entries = vec![
            ("a".to_string(), PathBuf::from("/x/a.yml")),
            ("longer".to_string(), PathBuf::from("/x/longer.yaml")),
        ];
        let out = format_listing(&entries);
        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(out.contains("@a"), "{out}");
        assert!(out.contains("@longer"), "{out}");
        assert!(out.contains("/x/a.yml"), "{out}");
        assert!(out.contains("/x/longer.yaml"), "{out}");
    }
}
