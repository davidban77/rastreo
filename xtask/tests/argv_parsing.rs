mod common;

use std::fs;
use std::path::PathBuf;

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

#[test]
fn no_source_file_parses_an_argv_against_the_ambient_environment() {
    let (root, files) = common::workspace_sources();

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
        common::declared_members(manifest),
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
