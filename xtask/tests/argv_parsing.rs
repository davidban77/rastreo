use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent")
        .to_path_buf()
}

/// Every clap call that parses an argv the caller hands it, resolving `env =` against the process as it goes.
const ARGV_ENTRY_POINTS: [&str; 7] = [
    "parse_from",
    "try_parse_from",
    "update_from",
    "try_update_from",
    "get_matches_from",
    "try_get_matches_from",
    "try_get_matches_from_mut",
];

const FILES_THAT_MAY_NAME_AN_ENTRY_POINT: [&str; 3] = [
    "rastreo/src/cli/argv.rs",
    "rastreo-server/src/argv.rs",
    "xtask/tests/argv_parsing.rs",
];

fn names_an_argv_entry_point(body: &str) -> bool {
    ARGV_ENTRY_POINTS.iter().any(|call| {
        body.match_indices(call).any(|(at, _)| {
            !body[at + call.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
        })
    })
}

fn declared_members(manifest: &str) -> Vec<String> {
    let lines: Vec<&str> = manifest.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.trim_start().starts_with("members"))
        .expect("the workspace manifest declares members");
    let tail = lines[start..].join("\n");
    let list = tail
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(list, _)| list)
        .expect("the members list is a bracketed array");
    list.split(',')
        .map(|entry| entry.trim().trim_matches('"').to_string())
        .filter(|entry| !entry.is_empty())
        .collect()
}

fn crate_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(root)
        .expect("read the workspace root")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();
    out.sort();
    out
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_source_file_parses_an_argv_against_the_ambient_environment() {
    let root = workspace_root();
    let crates = crate_dirs(&root);
    let declared = declared_members(
        &fs::read_to_string(root.join("Cargo.toml")).expect("read the workspace manifest"),
    );
    let unwalked: Vec<&String> = declared
        .iter()
        .filter(|member| !crates.contains(&root.join(member)))
        .collect();
    assert!(
        unwalked.is_empty(),
        "this guard walks the workspace's top-level crate directories, and {unwalked:?} is \
         declared but not among {crates:?}"
    );

    let owners: Vec<PathBuf> = FILES_THAT_MAY_NAME_AN_ENTRY_POINT
        .iter()
        .map(|rel| root.join(rel))
        .collect();
    for owner in &owners {
        assert!(
            owner.is_file(),
            "{} is exempt from this guard but no longer exists; point the exemption at the file \
             that defines the env-free parse, or drop it",
            owner.display()
        );
    }

    let mut files = Vec::new();
    for dir in &crates {
        rust_sources(dir, &mut files);
    }
    assert!(
        files.len() > 50,
        "walked {} files, expected the whole workspace source tree",
        files.len()
    );

    let offenders: Vec<String> = files
        .iter()
        .filter(|path| !owners.contains(path))
        .filter(|path| names_an_argv_entry_point(&fs::read_to_string(path).expect("read source")))
        .map(|path| {
            path.strip_prefix(&root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "clap resolves an `env =` argument against the developer's shell, so an in-process parse \
         asserts a default the caller's environment can flip. Parse through the crate's \
         `argv::parse_without_env`, and assert env-backed parsing from `tests/`, against a spawned \
         binary whose environment the test owns. Found: {offenders:?}"
    );
}

#[test]
fn the_member_parser_reads_a_multi_line_list_and_stops_before_default_members() {
    let manifest = "[workspace]\nmembers = [\n    \"rastreo-core\",\n    \"crates/nested\",\n]\ndefault-members = [\"rastreo-core\"]\n";
    assert_eq!(
        declared_members(manifest),
        ["rastreo-core", "crates/nested"]
    );
}

#[test]
fn every_clap_call_that_takes_an_argv_is_matched() {
    for call in [
        "let cli = Cli::parse_from([\"rastreo\"]);",
        "let cli = Cli::try_parse_from([\"rastreo\"])?;",
        "cli.update_from([\"rastreo\"]);",
        "cli.try_update_from([\"rastreo\"])?;",
        "Cli::command().get_matches_from([\"rastreo\"])",
        "Cli::command().try_get_matches_from([\"rastreo\"])?",
        "command.try_get_matches_from_mut([\"rastreo\"])?",
    ] {
        assert!(names_an_argv_entry_point(call), "{call}");
    }
}

#[test]
fn a_call_that_takes_no_argv_is_not_matched() {
    for call in [
        "let cli = Cli::parse();",
        "command.get_matches()",
        "DateTime::parse_from_rfc3339(&s)",
        "self.update_from_arg_matches(&matches)",
    ] {
        assert!(!names_an_argv_entry_point(call), "{call}");
    }
}
