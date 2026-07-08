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
fn committed_schemas_match_derives() {
    let root = workspace_root();
    let device_committed =
        fs::read_to_string(root.join("schemas/device-record-v1.json")).expect("read device schema");
    let device_current = xtask::device_record_schema().expect("device schema");
    assert_eq!(
        device_committed, device_current,
        "committed device-record-v1.json is out of sync with the DeviceRecord derives. Run `task schema:generate`."
    );

    let scan_committed =
        fs::read_to_string(root.join("schemas/scan-metadata-v1.json")).expect("read scan schema");
    let scan_current = xtask::scan_metadata_schema().expect("scan schema");
    assert_eq!(
        scan_committed, scan_current,
        "committed scan-metadata-v1.json is out of sync with the ScanMetadata derives. Run `task schema:generate`."
    );

    let scenario_committed =
        fs::read_to_string(root.join("schemas/scenario-v1.json")).expect("read scenario schema");
    let scenario_current = xtask::scenario_file_schema().expect("scenario schema");
    assert_eq!(
        scenario_committed, scenario_current,
        "committed scenario-v1.json is out of sync with the ScenarioFile derives. Run `task schema:generate`."
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
