use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent")
        .to_path_buf()
}

#[test]
fn committed_device_record_render_matches_current_schema() {
    let root = workspace_root();
    let raw = fs::read_to_string(root.join("schemas/device-record-v1.json"))
        .expect("read device-record schema");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse schema");
    let rendered = xtask::render_schema(&value, "rastreo-core/src/model/device.rs");
    let committed =
        fs::read_to_string(root.join("docs/site/docs/reference/schema/device-record.md"))
            .expect("read committed device-record.md");
    assert_eq!(
        rendered, committed,
        "committed device-record.md is out of sync with the schema. Run `task schema:all`."
    );
}

#[test]
fn committed_link_record_render_matches_current_schema() {
    let root = workspace_root();
    let raw = fs::read_to_string(root.join("schemas/link-record-v1.json"))
        .expect("read link-record schema");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse schema");
    let rendered = xtask::render_schema(&value, "rastreo-core/src/model/link.rs");
    let committed = fs::read_to_string(root.join("docs/site/docs/reference/schema/link-record.md"))
        .expect("read committed link-record.md");
    assert_eq!(
        rendered, committed,
        "committed link-record.md is out of sync with the schema. Run `task schema:all`."
    );
}

#[test]
fn committed_collection_profile_render_matches_current_schema() {
    let root = workspace_root();
    let raw = fs::read_to_string(root.join("schemas/collection-profile-record-v1.json"))
        .expect("read collection-profile schema");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse schema");
    let rendered = xtask::render_schema(&value, "rastreo-core/src/model/collection_profile.rs");
    let committed = fs::read_to_string(
        root.join("docs/site/docs/reference/schema/collection-profile-record.md"),
    )
    .expect("read committed collection-profile-record.md");
    assert_eq!(
        rendered, committed,
        "committed collection-profile-record.md is out of sync with the schema. Run `task schema:all`."
    );
}

#[test]
fn committed_scan_metadata_render_matches_current_schema() {
    let root = workspace_root();
    let raw = fs::read_to_string(root.join("schemas/scan-metadata-v1.json"))
        .expect("read scan-metadata schema");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse schema");
    let rendered = xtask::render_schema(&value, "rastreo-core/src/model/scan.rs");
    let committed =
        fs::read_to_string(root.join("docs/site/docs/reference/schema/scan-metadata.md"))
            .expect("read committed scan-metadata.md");
    assert_eq!(
        rendered, committed,
        "committed scan-metadata.md is out of sync with the schema. Run `task schema:all`."
    );
}

#[test]
fn committed_scenario_render_matches_current_schema() {
    let root = workspace_root();
    let raw =
        fs::read_to_string(root.join("schemas/scenario-v1.json")).expect("read scenario schema");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse schema");
    let rendered = xtask::render_schema(&value, "rastreo-core/src/config/mod.rs");
    let committed =
        fs::read_to_string(root.join("docs/site/docs/reference/schema/scenario-config.md"))
            .expect("read committed scenario-config.md");
    assert_eq!(
        rendered, committed,
        "committed scenario-config.md is out of sync with the schema. Run `task schema:all`."
    );
}

#[test]
fn committed_discovery_plan_render_matches_current_schema() {
    let root = workspace_root();
    let raw = fs::read_to_string(root.join("schemas/discovery-plan-v1.json"))
        .expect("read discovery-plan schema");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse schema");
    let rendered = xtask::render_schema(&value, "rastreo-core/src/plan.rs");
    let committed =
        fs::read_to_string(root.join("docs/site/docs/reference/schema/discovery-plan.md"))
            .expect("read committed discovery-plan.md");
    assert_eq!(
        rendered, committed,
        "committed discovery-plan.md is out of sync with the schema. Run `task schema:all`."
    );
}

// Spawns the generator instead of calling `schema_for!` in-process: the committed files are what
// `cargo run -p xtask -- generate` writes, and an outer `--all-features` build hands this binary's
// derives feature-gated variants that generator never resolves.
#[test]
fn committed_schemas_match_the_canonical_generator() {
    let root = workspace_root();
    let out = tempfile::tempdir().expect("tempdir");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = std::process::Command::new(cargo)
        .args(["run", "--quiet", "-p", "xtask", "--", "generate", "--out"])
        .arg(out.path())
        .current_dir(&root)
        .status()
        .expect("run the schema generator");
    assert!(status.success(), "the generator exited with {status:?}");

    for (name, _) in xtask::SCHEMAS {
        let generated = fs::read_to_string(out.path().join(name))
            .unwrap_or_else(|e| panic!("read generated {name}: {e}"));
        let committed = fs::read_to_string(root.join("schemas").join(name))
            .unwrap_or_else(|e| panic!("read committed {name}: {e}"));
        assert_eq!(
            committed, generated,
            "committed {name} is out of sync with the type derives. Run `task schema:all`."
        );

        let served = fs::read_to_string(root.join("docs/site/docs/schemas").join(name))
            .unwrap_or_else(|e| panic!("read served {name}: {e}"));
        assert_eq!(
            served, generated,
            "docs/site/docs/schemas/{name} is out of sync with schemas/{name}. Run `task schema:all`."
        );
    }
}

#[test]
fn dlq_envelope_schema_copies_are_byte_identical() {
    let root = workspace_root();
    let source = fs::read(root.join("schemas/dlq-envelope-v1.json"))
        .expect("read schemas/dlq-envelope-v1.json");
    let served = fs::read(root.join("docs/site/docs/schemas/dlq-envelope-v1.json"))
        .expect("read docs/site/docs/schemas/dlq-envelope-v1.json");
    assert_eq!(
        source, served,
        "docs/site/docs/schemas/dlq-envelope-v1.json is out of sync with schemas/dlq-envelope-v1.json. \
         Copy the hand-authored source into the served dir so its $id URL resolves."
    );
}

#[test]
fn scenario_schema_defaults_are_version_stable() {
    let root = workspace_root();
    let raw =
        fs::read_to_string(root.join("schemas/scenario-v1.json")).expect("read scenario schema");
    // Shape-check rather than exact-match against `env!("CARGO_PKG_VERSION")`: the latter
    // resolves to xtask's own version (0.0.0), not rastreo-core's. A schemars default that
    // bakes a semver starts with a digit after `rastreo/`; a stable placeholder such as
    // `rastreo/<version>` does not.
    let marker = "\"default\": \"rastreo/";
    let baked = raw.match_indices(marker).find_map(|(idx, _)| {
        let tail = &raw[idx + marker.len()..];
        tail.starts_with(|c: char| c.is_ascii_digit())
            .then(|| tail.chars().take_while(|c| *c != '"').collect::<String>())
    });
    assert!(
        baked.is_none(),
        "scenario-v1.json contains a version-baked default `rastreo/{}` — \
         use a schemars-only stable default (see http::default_user_agent_schema) \
         to keep the committed schema stable across release bumps.",
        baked.as_deref().unwrap_or("")
    );
}
