use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent")
        .to_path_buf()
}

#[derive(Debug, PartialEq, Eq)]
struct DocumentedType {
    name: String,
    section: Option<String>,
}

const NO_SECTION: &str = "not in the changelog";

/// The `| `type` — gloss | Section |` rows of CONTRIBUTING.md's commit-type table.
fn documented_types(contributing: &str) -> Vec<DocumentedType> {
    contributing
        .lines()
        .filter_map(|line| {
            let mut cells = line.strip_prefix('|')?.split('|');
            let name = cells.next()?.trim().strip_prefix('`')?;
            let name = name.split('`').next()?;
            let section = cells.next()?.trim();
            (!name.is_empty() && !section.is_empty()).then(|| DocumentedType {
                name: name.to_string(),
                section: (section != NO_SECTION).then(|| section.to_string()),
            })
        })
        .collect()
}

/// The `types:` block the PR-title check accepts.
fn accepted_types(workflow: &str) -> Vec<String> {
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(workflow).expect("parse the commitlint workflow");
    let jobs = doc
        .get("jobs")
        .and_then(|jobs| jobs.as_mapping())
        .expect("the workflow declares jobs");
    let mut found: Vec<String> = Vec::new();
    for (_, job) in jobs {
        // A job that calls a reusable workflow declares `uses:` and has no steps to read.
        let Some(steps) = job.get("steps").and_then(|steps| steps.as_sequence()) else {
            continue;
        };
        for step in steps {
            if let Some(types) = step.get("with").and_then(|with| with.get("types")) {
                let listed = types.as_str().expect("the types input is a block scalar");
                found.extend(listed.split_whitespace().map(str::to_string));
            }
        }
    }
    assert!(
        !found.is_empty(),
        "no step in the commitlint workflow declares a `types` input"
    );
    found
}

/// The `type` → changelog `section` pairs release-please renders.
fn changelog_sections(config: &str) -> Vec<(String, String)> {
    let doc: serde_json::Value =
        serde_json::from_str(config).expect("parse the release-please config");
    doc["packages"]["."]["changelog-sections"]
        .as_array()
        .expect("the root package declares changelog-sections")
        .iter()
        .map(|entry| {
            (
                entry["type"].as_str().expect("section type").to_string(),
                entry["section"]
                    .as_str()
                    .expect("section heading")
                    .to_string(),
            )
        })
        .collect()
}

/// The `commit-message.prefix` each dependabot ecosystem puts at the head of its PR titles.
fn dependabot_prefixes(config: &str) -> Vec<String> {
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(config).expect("parse the dependabot config");
    let updates = doc
        .get("updates")
        .and_then(|updates| updates.as_sequence())
        .expect("the dependabot config declares updates");
    let found: Vec<String> = updates
        .iter()
        .filter_map(|update| update.get("commit-message")?.get("prefix")?.as_str())
        .map(str::to_string)
        .collect();
    assert!(
        !found.is_empty(),
        "no dependabot update declares a commit-message prefix"
    );
    found
}

fn disagreements(
    documented: &[DocumentedType],
    accepted: &[String],
    sections: &[(String, String)],
) -> Vec<String> {
    let mut out = Vec::new();
    for entry in documented {
        if !accepted.contains(&entry.name) {
            out.push(format!(
                "`{}` is documented in CONTRIBUTING.md but the PR-title check rejects it",
                entry.name
            ));
        }
        let rendered = sections
            .iter()
            .find(|(name, _)| *name == entry.name)
            .map(|(_, section)| section.clone());
        if rendered != entry.section {
            out.push(match (&entry.section, &rendered) {
                (Some(documented), None) => format!(
                    "CONTRIBUTING.md puts `{}` under '{documented}', release-please renders no section for it",
                    entry.name
                ),
                (None, Some(rendered)) => format!(
                    "CONTRIBUTING.md says `{}` is {NO_SECTION}, release-please renders it under '{rendered}'",
                    entry.name
                ),
                (Some(documented), Some(rendered)) => format!(
                    "`{}` is '{documented}' in CONTRIBUTING.md and '{rendered}' in release-please",
                    entry.name
                ),
                (None, None) => unreachable!("equal values are not a disagreement"),
            });
        }
    }
    for name in accepted {
        if !documented.iter().any(|entry| entry.name == *name) {
            out.push(format!(
                "the PR-title check accepts `{name}`, which CONTRIBUTING.md does not document"
            ));
        }
    }
    for (name, section) in sections {
        if !documented.iter().any(|entry| entry.name == *name) {
            out.push(format!(
                "release-please renders `{name}` under '{section}', which CONTRIBUTING.md does not document"
            ));
        }
    }
    out
}

#[test]
fn the_three_commit_type_lists_agree() {
    let root = workspace_root();
    let documented = documented_types(
        &fs::read_to_string(root.join("CONTRIBUTING.md")).expect("read CONTRIBUTING.md"),
    );
    let accepted = accepted_types(
        &fs::read_to_string(root.join(".github/workflows/commitlint.yml"))
            .expect("read the commitlint workflow"),
    );
    let sections = changelog_sections(
        &fs::read_to_string(root.join("release-please-config.json"))
            .expect("read the release-please config"),
    );
    assert!(
        documented.len() > 5,
        "parsed {documented:?}, expected CONTRIBUTING.md's commit-type table"
    );

    assert_eq!(
        disagreements(&documented, &accepted, &sections),
        Vec::<String>::new(),
        "CONTRIBUTING.md is the list of commit types; the PR-title check and the changelog \
         config are checked against it"
    );
}

#[test]
fn every_dependabot_prefix_is_a_documented_commit_type() {
    let root = workspace_root();
    let documented = documented_types(
        &fs::read_to_string(root.join("CONTRIBUTING.md")).expect("read CONTRIBUTING.md"),
    );
    let prefixes = dependabot_prefixes(
        &fs::read_to_string(root.join(".github/dependabot.yml"))
            .expect("read the dependabot config"),
    );

    let undocumented: Vec<&String> = prefixes
        .iter()
        .filter(|prefix| !documented.iter().any(|entry| entry.name == **prefix))
        .collect();
    assert!(
        undocumented.is_empty(),
        "dependabot titles its PRs with these prefixes, so a prefix CONTRIBUTING.md does not \
         document is a PR that cannot pass the title check: {undocumented:?}"
    );
}

fn documented(name: &str, section: Option<&str>) -> DocumentedType {
    DocumentedType {
        name: name.to_string(),
        section: section.map(str::to_string),
    }
}

#[test]
fn a_type_ci_rejects_is_a_disagreement() {
    let found = disagreements(
        &[documented("feat", Some("Features"))],
        &[],
        &[("feat".to_string(), "Features".to_string())],
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("rejects it"), "{found:?}");
}

#[test]
fn a_type_with_no_changelog_section_is_a_disagreement() {
    let found = disagreements(
        &[documented("feat", Some("Features"))],
        &["feat".to_string()],
        &[],
    );
    assert_eq!(
        found,
        ["CONTRIBUTING.md puts `feat` under 'Features', release-please renders no section for it"]
    );
}

#[test]
fn a_section_heading_that_drifted_is_a_disagreement() {
    let found = disagreements(
        &[documented("perf", Some("Performance"))],
        &["perf".to_string()],
        &[("perf".to_string(), "Perf".to_string())],
    );
    assert_eq!(
        found,
        ["`perf` is 'Performance' in CONTRIBUTING.md and 'Perf' in release-please"]
    );
}

#[test]
fn an_undocumented_type_is_a_disagreement_from_either_side() {
    let found = disagreements(
        &[],
        &["deps".to_string()],
        &[("style".to_string(), "Styling".to_string())],
    );
    assert_eq!(
        found,
        [
            "the PR-title check accepts `deps`, which CONTRIBUTING.md does not document",
            "release-please renders `style` under 'Styling', which CONTRIBUTING.md does not document",
        ]
    );
}

#[test]
fn a_documented_type_that_lands_nowhere_agrees_with_an_absent_section() {
    assert_eq!(
        disagreements(&[documented("test", None)], &["test".to_string()], &[]),
        Vec::<String>::new()
    );
}

#[test]
fn the_table_parser_reads_the_type_and_its_section() {
    let table = "| Type | Section |\n|---|---|\n| `feat` — new capability | Features |\n| `test` — tests only | not in the changelog |\n";
    assert_eq!(
        documented_types(table),
        [
            documented("feat", Some("Features")),
            documented("test", None)
        ]
    );
}

#[test]
fn the_workflow_parser_reads_the_block_scalar() {
    let workflow =
        "jobs:\n  commitlint:\n    steps:\n      - uses: some/action@v1\n        with:\n          types: |\n            feat\n            fix\n          requireScope: false\n";
    assert_eq!(accepted_types(workflow), ["feat", "fix"]);
}

#[test]
fn the_workflow_parser_reads_past_a_job_that_declares_no_steps() {
    let workflow = "jobs:\n  reusable:\n    uses: ./.github/workflows/other.yml\n  commitlint:\n    steps:\n      - uses: some/action@v1\n        with:\n          types: |\n            feat\n";
    assert_eq!(accepted_types(workflow), ["feat"]);
}

#[test]
fn the_dependabot_parser_reads_every_ecosystem_prefix() {
    let config = "version: 2\nupdates:\n  - package-ecosystem: cargo\n    commit-message:\n      prefix: deps\n  - package-ecosystem: github-actions\n    commit-message:\n      prefix: ci\n";
    assert_eq!(dependabot_prefixes(config), ["deps", "ci"]);
}

#[test]
fn the_release_config_parser_reads_the_section_pairs() {
    let config =
        r#"{"packages":{".":{"changelog-sections":[{"type":"feat","section":"Features"}]}}}"#;
    assert_eq!(
        changelog_sections(config),
        [("feat".to_string(), "Features".to_string())]
    );
}
