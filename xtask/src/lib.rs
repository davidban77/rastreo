use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use schemars::schema_for;
use serde_json::Value;

/// Canonical serving base for all JSON Schemas. Files under `docs/site/docs/schemas/` are picked up by mkdocs and served at this base by GitHub Pages.
pub const SCHEMA_BASE_URL: &str = "https://davidban77.github.io/rastreo/schemas";

pub fn workspace_root() -> Result<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask crate has no parent")?
        .to_path_buf())
}

/// Vendored openconfig/gnmi source: tag `v0.14.1`, commit `8b7dd494c4f6ff517431965d662621d8884bad0f`.
pub const GNMI_PROTO_TAG: &str = "v0.14.1";
pub const GNMI_PROTO_SHA: &str = "8b7dd494c4f6ff517431965d662621d8884bad0f";

/// Regenerates the checked-in gNMI bindings from the vendored protos. Requires `protoc` on PATH;
/// the normal `cargo build --workspace` never runs this — it consumes the committed output.
pub fn gen_gnmi() -> Result<()> {
    let root = workspace_root()?;
    let proto_root = root.join("rastreo-core").join("proto");
    let gnmi_proto = proto_root
        .join("github.com/openconfig/gnmi/proto/gnmi/gnmi.proto")
        .to_path_buf();
    let gnmi_ext_proto = proto_root
        .join("github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto")
        .to_path_buf();

    let out_dir = tempfile::Builder::new()
        .prefix("rastreo-gnmi-gen")
        .tempdir()
        .context("create temp out dir for codegen")?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .out_dir(out_dir.path())
        .compile_protos(&[&gnmi_proto, &gnmi_ext_proto], &[&proto_root])
        .context("tonic-prost-build codegen failed (is protoc installed?)")?;

    let gnmi_rs = fs::read_to_string(out_dir.path().join("gnmi.rs"))
        .context("read generated gnmi.rs from out dir")?;
    let gnmi_ext_rs = fs::read_to_string(out_dir.path().join("gnmi_ext.rs"))
        .context("read generated gnmi_ext.rs from out dir")?;

    let combined = format!(
        "pub mod gnmi {{\n{gnmi_rs}}}\npub mod gnmi_ext {{\n{gnmi_ext_rs}}}\n",
        gnmi_rs = indent(&gnmi_rs),
        gnmi_ext_rs = indent(&gnmi_ext_rs),
    );

    let dest = root
        .join("rastreo-core/src/prober/gnmi/generated.rs")
        .to_path_buf();
    fs::write(&dest, &combined).with_context(|| format!("write {}", dest.display()))?;
    println!(
        "Wrote {} (openconfig/gnmi {GNMI_PROTO_TAG} @ {GNMI_PROTO_SHA})",
        dest.display()
    );
    Ok(())
}

fn indent(src: &str) -> String {
    let mut out = String::with_capacity(src.len() + src.len() / 16);
    for line in src.lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            out.push_str("    ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

pub fn generate_all() -> Result<()> {
    let root = workspace_root()?;
    let schemas_dir = root.join("schemas");
    let docs_schemas_dir = root.join("docs").join("site").join("docs").join("schemas");
    fs::create_dir_all(&schemas_dir)
        .with_context(|| format!("create {}", schemas_dir.display()))?;
    fs::create_dir_all(&docs_schemas_dir)
        .with_context(|| format!("create {}", docs_schemas_dir.display()))?;
    for (name, content) in [
        ("device-record-v1.json", device_record_schema()?),
        ("scan-metadata-v1.json", scan_metadata_schema()?),
        ("scenario-v1.json", scenario_file_schema()?),
        ("discovery-plan-v1.json", discovery_plan_schema()?),
    ] {
        write_schema(&schemas_dir, name, &content)?;
        write_schema(&docs_schemas_dir, name, &content)?;
    }
    Ok(())
}

pub fn render_all() -> Result<()> {
    let root = workspace_root()?;
    let schemas_dir = root.join("schemas");
    let docs_dir = root
        .join("docs")
        .join("site")
        .join("docs")
        .join("reference")
        .join("schema");
    fs::create_dir_all(&docs_dir).with_context(|| format!("create {}", docs_dir.display()))?;

    render_schema_file(
        &schemas_dir.join("device-record-v1.json"),
        &docs_dir.join("device-record.md"),
        "rastreo-core/src/model/device.rs",
    )?;
    render_schema_file(
        &schemas_dir.join("scan-metadata-v1.json"),
        &docs_dir.join("scan-metadata.md"),
        "rastreo-core/src/model/scan.rs",
    )?;
    render_schema_file(
        &schemas_dir.join("scenario-v1.json"),
        &docs_dir.join("scenario-config.md"),
        "rastreo-core/src/config/mod.rs",
    )?;
    render_schema_file(
        &schemas_dir.join("discovery-plan-v1.json"),
        &docs_dir.join("discovery-plan.md"),
        "rastreo-core/src/plan.rs",
    )?;
    Ok(())
}

pub fn device_record_schema() -> Result<String> {
    render_schema_json(
        schema_for!(rastreo_core::DeviceRecord),
        "device-record-v1.json",
        "DeviceRecord",
    )
}

pub fn scan_metadata_schema() -> Result<String> {
    render_schema_json(
        schema_for!(rastreo_core::ScanMetadata),
        "scan-metadata-v1.json",
        "ScanMetadata",
    )
}

pub fn scenario_file_schema() -> Result<String> {
    render_schema_json(
        schema_for!(rastreo_core::config::ScenarioFile),
        "scenario-v1.json",
        "ScenarioFile",
    )
}

pub fn discovery_plan_schema() -> Result<String> {
    render_schema_json(
        schema_for!(rastreo_core::DiscoveryPlan),
        "discovery-plan-v1.json",
        "DiscoveryPlan",
    )
}

fn render_schema_json(
    schema: schemars::Schema,
    file_name: &str,
    type_name: &str,
) -> Result<String> {
    let mut value: Value = serde_json::to_value(&schema)
        .with_context(|| format!("convert {type_name} schema to JSON value"))?;
    if let Value::Object(map) = &mut value {
        map.insert(
            "$id".to_string(),
            Value::String(format!("{SCHEMA_BASE_URL}/{file_name}")),
        );
    }
    let json = serde_json::to_string_pretty(&value)
        .with_context(|| format!("serialize {type_name} schema"))?;
    Ok(format!("{json}\n"))
}

fn write_schema(dir: &Path, file_name: &str, content: &str) -> Result<()> {
    let path = dir.join(file_name);
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    println!("Wrote {}", path.display());
    Ok(())
}

fn render_schema_file(schema_path: &Path, out_path: &Path, source_of_truth: &str) -> Result<()> {
    let raw = fs::read_to_string(schema_path)
        .with_context(|| format!("read {}", schema_path.display()))?;
    let schema: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse JSON in {}", schema_path.display()))?;
    let markdown = render_schema(&schema, source_of_truth);
    fs::write(out_path, markdown).with_context(|| format!("write {}", out_path.display()))?;
    println!("Wrote {}", out_path.display());
    Ok(())
}

pub fn render_schema(schema: &Value, source_of_truth: &str) -> String {
    let title = schema
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Schema");
    let top_description = schema
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("Wire schema for {title} emitted by rastreo."));
    let front_matter_desc = one_line(&top_description);
    let schema_id = schema.get("$id").and_then(Value::as_str).unwrap_or("n/a");
    let draft = schema
        .get("$schema")
        .and_then(Value::as_str)
        .unwrap_or("n/a");
    let defs = definitions(schema);

    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("description: {front_matter_desc}\n"));
    out.push_str("---\n\n");
    out.push_str(&format!("# {title}\n\n"));
    out.push_str(
        "<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->\n\n",
    );
    out.push_str(&format!("{top_description}\n\n"));
    out.push_str(&format!("- Schema ID: `{schema_id}`\n"));
    out.push_str(&format!("- JSON Schema draft: `{draft}`\n"));
    out.push_str(&format!("- Source of truth: `{source_of_truth}`\n\n"));

    out.push_str("## Fields\n\n");
    out.push_str(&render_fields_table(schema, &defs));

    if !defs.is_empty() {
        out.push_str("\n## Definitions\n\n");
        for (name, def) in &defs {
            out.push_str(&render_definition(name, def, &defs));
        }
    }

    out
}

type Definitions<'a> = Vec<(&'a str, &'a Value)>;

fn definitions(schema: &Value) -> Definitions<'_> {
    let key = if schema.get("$defs").is_some() {
        "$defs"
    } else {
        "definitions"
    };
    schema
        .get(key)
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.as_str(), v)).collect::<Vec<_>>())
        .unwrap_or_default()
}

fn render_fields_table(schema: &Value, defs: &Definitions<'_>) -> String {
    let properties = schema.get("properties").and_then(Value::as_object);
    let Some(properties) = properties else {
        return "_no fields_\n".to_string();
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str("| Field | Type | Required | Description |\n");
    out.push_str("|---|---|---|---|\n");
    for (name, spec) in properties {
        let ty = format_type(spec, defs);
        let req = if required.iter().any(|r| r == name) {
            "yes"
        } else {
            "no"
        };
        let desc = extract_description(spec)
            .map(|d| escape_cell(&one_line(&d)))
            .unwrap_or_else(|| "—".to_string());
        out.push_str(&format!("| `{name}` | {ty} | {req} | {desc} |\n"));
    }
    out
}

fn render_definition(name: &str, def: &Value, defs: &Definitions<'_>) -> String {
    let mut out = String::new();
    let anchor = anchor_for(name);
    out.push_str(&format!("### `{name}` {{#{anchor}}}\n\n"));

    if let Some(desc) = def.get("description").and_then(Value::as_str) {
        out.push_str(desc);
        out.push_str("\n\n");
    }

    if let Some(variants) = def.get("oneOf").and_then(Value::as_array) {
        out.push_str("One of:\n\n");
        for v in variants {
            out.push_str(&format!("- {}\n", format_variant(v, defs)));
        }
        out.push('\n');
        return out;
    }

    if let Some(variants) = def.get("anyOf").and_then(Value::as_array) {
        out.push_str("Any of:\n\n");
        for v in variants {
            out.push_str(&format!("- {}\n", format_variant(v, defs)));
        }
        out.push('\n');
        return out;
    }

    let props = def.get("properties").and_then(Value::as_object);
    if let Some(props) = props {
        let required: Vec<&str> = def
            .get("required")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        out.push_str("| Field | Type | Required | Description |\n");
        out.push_str("|---|---|---|---|\n");
        for (fname, fspec) in props {
            let ty = format_type(fspec, defs);
            let req = if required.iter().any(|r| r == fname) {
                "yes"
            } else {
                "no"
            };
            let desc = extract_description(fspec)
                .map(|d| escape_cell(&one_line(&d)))
                .unwrap_or_else(|| "—".to_string());
            out.push_str(&format!("| `{fname}` | {ty} | {req} | {desc} |\n"));
        }
        out.push('\n');
        return out;
    }

    let ty = format_type(def, defs);
    out.push_str(&format!("Type: {ty}\n\n"));
    out
}

fn format_variant(v: &Value, defs: &Definitions<'_>) -> String {
    let merged = merge_ref_siblings(v, defs);
    let v = merged.as_ref().unwrap_or(v);
    if let Some(props) = v.get("properties").and_then(Value::as_object) {
        let parts: Vec<String> = props
            .iter()
            .map(|(name, spec)| format!("`{name}`: {}", format_property_type(spec, defs)))
            .collect();
        return format!("{{ {} }}", parts.join(", "));
    }
    if let Some(label) = const_or_enum_label(v) {
        return label;
    }
    format_type(v, defs)
}

fn format_property_type(spec: &Value, defs: &Definitions<'_>) -> String {
    if let Some(label) = const_or_enum_label(spec) {
        return label;
    }
    format_type(spec, defs)
}

// schemars 1.x emits `const` for single-value discriminants where 0.8 emitted `enum: [x]`.
fn const_or_enum_label(spec: &Value) -> Option<String> {
    if let Some(c) = spec.get("const").and_then(Value::as_str) {
        return Some(format!("`{c}`"));
    }
    let values = spec.get("enum").and_then(Value::as_array)?;
    let parts: Vec<String> = values
        .iter()
        .filter_map(|val| val.as_str().map(|s| format!("`{s}`")))
        .collect();
    (!parts.is_empty()).then(|| parts.join(" \\| "))
}

// 2020-12 keeps sibling keywords alongside `$ref`; merge referenced def props/required with local (local wins).
fn merge_ref_siblings(v: &Value, defs: &Definitions<'_>) -> Option<Value> {
    let reference = v.get("$ref").and_then(Value::as_str)?;
    if v.get("properties").is_none() && v.get("required").is_none() {
        return None;
    }
    let name = reference.rsplit('/').next()?;
    let target = defs.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)?;

    let mut merged = v.clone();
    let obj = merged.as_object_mut()?;
    obj.remove("$ref");

    let mut props = target
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(local) = v.get("properties").and_then(Value::as_object) {
        for (k, val) in local {
            props.insert(k.clone(), val.clone());
        }
    }
    if !props.is_empty() {
        obj.insert("properties".to_string(), Value::Object(props));
    }

    let mut required = target
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(local) = v.get("required").and_then(Value::as_array) {
        for r in local {
            if !required.contains(r) {
                required.push(r.clone());
            }
        }
    }
    if !required.is_empty() {
        obj.insert("required".to_string(), Value::Array(required));
    }

    Some(merged)
}

fn format_type(spec: &Value, defs: &Definitions<'_>) -> String {
    if let Some(c) = spec.get("const").and_then(Value::as_str) {
        return format!("`{c}`");
    }
    if let Some(r) = spec.get("$ref").and_then(Value::as_str) {
        return format_ref(r);
    }
    if let Some(all_of) = spec.get("allOf").and_then(Value::as_array) {
        let mut inner: Vec<String> = Vec::new();
        for item in all_of {
            let s = format_type(item, defs);
            if !s.is_empty() {
                inner.push(s);
            }
        }
        if inner.len() == 1 {
            return inner.remove(0);
        }
        return inner.join(" & ");
    }
    if let Some(any_of) = spec.get("anyOf").and_then(Value::as_array) {
        return any_of
            .iter()
            .map(|v| format_type(v, defs))
            .collect::<Vec<_>>()
            .join(" \\| ");
    }
    if let Some(one_of) = spec.get("oneOf").and_then(Value::as_array) {
        return one_of
            .iter()
            .map(|v| format_type(v, defs))
            .collect::<Vec<_>>()
            .join(" \\| ");
    }
    if let Some(ty) = spec.get("type") {
        return format_type_field(ty, spec, defs);
    }
    "unknown".to_string()
}

fn format_type_field(ty: &Value, spec: &Value, defs: &Definitions<'_>) -> String {
    let fmt = spec.get("format").and_then(Value::as_str);
    if let Some(list) = ty.as_array() {
        let parts: Vec<String> = list
            .iter()
            .filter_map(|t| t.as_str().map(|n| scalar_type_label(n, fmt)))
            .collect();
        return parts.join(" \\| ");
    }
    if let Some(name) = ty.as_str() {
        match name {
            "array" => {
                let items = spec
                    .get("items")
                    .map(|i| format_type(i, defs))
                    .unwrap_or_else(|| "unknown".to_string());
                return format!("array<{items}>");
            }
            "object" => return "object".to_string(),
            other => return scalar_type_label(other, fmt),
        }
    }
    "unknown".to_string()
}

fn scalar_type_label(name: &str, format: Option<&str>) -> String {
    match name {
        "integer" | "number" => format
            .map(|f| f.to_string())
            .unwrap_or_else(|| name.to_string()),
        "string" => match format {
            Some(fmt) => format!("string ({fmt})"),
            None => "string".to_string(),
        },
        other => other.to_string(),
    }
}

fn format_ref(reference: &str) -> String {
    let name = reference.rsplit('/').next().unwrap_or(reference);
    let anchor = anchor_for(name);
    format!("[`{name}`](#{anchor})")
}

fn anchor_for(name: &str) -> String {
    name.to_lowercase()
}

fn extract_description(spec: &Value) -> Option<String> {
    if let Some(d) = spec.get("description").and_then(Value::as_str) {
        return Some(d.to_string());
    }
    if let Some(list) = spec.get("allOf").and_then(Value::as_array) {
        for item in list {
            if let Some(d) = item.get("description").and_then(Value::as_str) {
                return Some(d.to_string());
            }
        }
    }
    None
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn escape_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn device_schema_value() -> Value {
        let raw = device_record_schema().expect("device schema");
        serde_json::from_str(&raw).expect("parse device schema")
    }

    fn scan_schema_value() -> Value {
        let raw = scan_metadata_schema().expect("scan schema");
        serde_json::from_str(&raw).expect("parse scan schema")
    }

    fn scenario_schema_value() -> Value {
        let raw = scenario_file_schema().expect("scenario schema");
        serde_json::from_str(&raw).expect("parse scenario schema")
    }

    fn discovery_plan_schema_value() -> Value {
        let raw = discovery_plan_schema().expect("discovery-plan schema");
        serde_json::from_str(&raw).expect("parse discovery-plan schema")
    }

    #[test]
    fn regenerate_schemas_is_idempotent() {
        let a = device_record_schema().expect("first gen");
        let b = device_record_schema().expect("second gen");
        assert_eq!(a, b);
        let a2 = scan_metadata_schema().expect("first gen");
        let b2 = scan_metadata_schema().expect("second gen");
        assert_eq!(a2, b2);
    }

    #[test]
    fn scenario_schema_generation_is_idempotent() {
        let a = scenario_file_schema().expect("first gen");
        let b = scenario_file_schema().expect("second gen");
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn scenario_file_schema_names_current_type() {
        let json = scenario_file_schema().expect("gen");
        assert!(json.contains("\"title\": \"ScenarioFile\""));
    }

    #[test]
    fn scenario_file_schema_carries_versioned_id() {
        let value = scenario_schema_value();
        assert_eq!(
            value["$id"].as_str(),
            Some("https://davidban77.github.io/rastreo/schemas/scenario-v1.json")
        );
    }

    #[test]
    fn scenario_schema_id_matches_served_url() {
        let value = scenario_schema_value();
        assert_eq!(
            value["$id"].as_str(),
            Some(format!("{SCHEMA_BASE_URL}/scenario-v1.json").as_str())
        );
    }

    #[test]
    fn device_record_schema_id_matches_served_url() {
        let value = device_schema_value();
        assert_eq!(
            value["$id"].as_str(),
            Some(format!("{SCHEMA_BASE_URL}/device-record-v1.json").as_str())
        );
    }

    #[test]
    fn scan_metadata_schema_id_matches_served_url() {
        let value = scan_schema_value();
        assert_eq!(
            value["$id"].as_str(),
            Some(format!("{SCHEMA_BASE_URL}/scan-metadata-v1.json").as_str())
        );
    }

    #[test]
    fn scenario_schema_declares_expected_top_level_shape() {
        let value = scenario_schema_value();
        let props = value["properties"]
            .as_object()
            .expect("properties is an object");
        for field in ["version", "kind", "scenarios"] {
            assert!(
                props.contains_key(field),
                "expected top-level `{field}` property"
            );
        }
        let required: Vec<&str> = value["required"]
            .as_array()
            .expect("required array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for field in ["version", "kind", "scenarios"] {
            assert!(
                required.contains(&field),
                "expected `{field}` to be required"
            );
        }
    }

    #[test]
    fn scenario_schema_prober_config_covers_shipped_probers() {
        let value = scenario_schema_value();
        let defs = value["$defs"]
            .as_object()
            .or_else(|| value["definitions"].as_object())
            .expect("definitions present");
        let prober = defs
            .get("ProberConfig")
            .expect("ProberConfig definition present");
        let variants = prober["oneOf"]
            .as_array()
            .expect("ProberConfig oneOf variants");
        assert_eq!(
            variants.len(),
            12,
            "expected 12 prober variants (tcp_connect, http, dns, udp, snmp, arp, ndp, ssh, icmp, tls, gnmi, reverse_dns); got {}",
            variants.len()
        );
    }

    #[test]
    fn scenario_schema_contains_no_redacted_default_leaks() {
        // Regression guard: schemars serializes `#[serde(default = ...)]` values
        // through the field's `Serialize` impl. Redacted newtypes (Password / Community)
        // must have a companion `#[schemars(default = ...)]` returning the plaintext,
        // otherwise the emitted schema surfaces the `<redacted:HHHHHHHH>` token as the
        // suggested default and misleads IDE autocomplete. Match on the `"default":`
        // key so intentional description prose mentioning the redaction format doesn't
        // trip the guard.
        let json = scenario_file_schema().expect("gen");
        assert!(
            !json.contains("\"default\": \"<redacted:"),
            "scenario schema leaked a redacted default token; check every `#[serde(default)]` on a `Password` / `Community` field for a matching `#[schemars(default)]` override"
        );
    }

    #[test]
    fn device_record_schema_names_current_type() {
        let json = device_record_schema().expect("gen");
        assert!(json.contains("\"title\": \"DeviceRecord\""));
    }

    #[test]
    fn scan_metadata_schema_names_current_type() {
        let json = scan_metadata_schema().expect("gen");
        assert!(json.contains("\"title\": \"ScanMetadata\""));
    }

    #[test]
    fn discovery_plan_schema_generation_is_idempotent() {
        let a = discovery_plan_schema().expect("first gen");
        let b = discovery_plan_schema().expect("second gen");
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn discovery_plan_schema_names_current_type() {
        let json = discovery_plan_schema().expect("gen");
        assert!(json.contains("\"title\": \"DiscoveryPlan\""));
    }

    #[test]
    fn discovery_plan_schema_id_matches_served_url() {
        let value = discovery_plan_schema_value();
        assert_eq!(
            value["$id"].as_str(),
            Some(format!("{SCHEMA_BASE_URL}/discovery-plan-v1.json").as_str())
        );
    }

    #[test]
    fn discovery_plan_schema_expresses_target_resolution_as_one_of() {
        let value = discovery_plan_schema_value();
        let defs = value["definitions"]
            .as_object()
            .or_else(|| value["$defs"].as_object())
            .expect("definitions present");
        let target_resolution = defs
            .get("TargetResolution")
            .expect("TargetResolution definition present");
        let variants = target_resolution["oneOf"]
            .as_array()
            .expect("TargetResolution is a oneOf");
        assert_eq!(variants.len(), 2, "resolved and error arms");
        let keys: Vec<String> = variants
            .iter()
            .filter_map(|v| v["properties"].as_object())
            .flat_map(|m| m.keys().cloned())
            .collect();
        assert!(keys.contains(&"resolved".to_string()), "got {keys:?}");
        assert!(keys.contains(&"error".to_string()), "got {keys:?}");
    }

    #[test]
    fn render_produces_deterministic_output() {
        let schema = device_schema_value();
        let a = render_schema(&schema, "rastreo-core/src/model/device.rs");
        let b = render_schema(&schema, "rastreo-core/src/model/device.rs");
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn render_output_includes_all_top_level_fields() {
        let schema = device_schema_value();
        let md = render_schema(&schema, "rastreo-core/src/model/device.rs");
        for field in [
            "identity_key",
            "mgmt_ip",
            "mac",
            "manufacturer",
            "platform",
            "role",
            "confidence",
            "last_seen",
            "signals",
            "schema_version",
            "schema_id",
            "alt_ips",
            "possible_alias_of",
            "scan_metadata",
        ] {
            assert!(
                md.contains(&format!("`{field}`")),
                "missing field `{field}` in rendered output"
            );
        }
    }

    #[test]
    fn render_output_includes_required_marker_for_required_fields() {
        let schema = device_schema_value();
        let md = render_schema(&schema, "rastreo-core/src/model/device.rs");
        let table_start = md.find("## Fields").expect("has fields section");
        let table_end = md[table_start..]
            .find("\n## ")
            .map(|i| table_start + i)
            .unwrap_or(md.len());
        let table = &md[table_start..table_end];
        for line in table.lines() {
            if line.contains("`identity_key`") {
                assert!(
                    line.contains("| yes |"),
                    "identity_key must be required: {line}"
                );
            }
            if line.contains("`mgmt_ip`") {
                assert!(line.contains("| no |"), "mgmt_ip must be optional: {line}");
            }
        }
    }

    #[test]
    fn render_output_includes_definitions_section_for_signal_variants() {
        let schema = device_schema_value();
        let md = render_schema(&schema, "rastreo-core/src/model/device.rs");
        assert!(md.contains("## Definitions"));
        assert!(md.contains("### `Signal`"));
        for variant in [
            "OpenPort",
            "HttpBanner",
            "SnmpSysObjectId",
            "SnmpSysDescr",
            "Mac",
            "DnsHost",
            "NtpBanner",
            "SipUserAgent",
            "MemcachedVersion",
            "StunMappedAddress",
            "SnmpSysName",
        ] {
            assert!(
                md.contains(&format!("`{variant}`")),
                "missing Signal variant `{variant}`"
            );
        }
    }

    #[test]
    fn render_scan_metadata_lists_scan_id() {
        let schema = scan_schema_value();
        let md = render_schema(&schema, "rastreo-core/src/model/scan.rs");
        assert!(md.contains("`scan_id`"));
        assert!(md.contains("`initiated_at`"));
    }

    #[test]
    fn generated_file_marker_present() {
        let schema = device_schema_value();
        let md = render_schema(&schema, "rastreo-core/src/model/device.rs");
        assert!(md.contains("<!-- GENERATED FILE"));
    }

    #[test]
    fn front_matter_description_is_single_line() {
        let schema = device_schema_value();
        let md = render_schema(&schema, "rastreo-core/src/model/device.rs");
        let desc_line = md
            .lines()
            .find(|l| l.starts_with("description:"))
            .expect("has description in front matter");
        assert!(!desc_line[13..].contains('\n'));
    }

    #[test]
    fn format_variant_renders_const_as_backticked_value() {
        let spec = json!({"type": "string", "const": "secondary"});
        assert_eq!(format_variant(&spec, &Vec::new()), "`secondary`");
    }

    #[test]
    fn format_variant_renders_multi_value_enum_as_union() {
        let spec = json!({"type": "string", "enum": ["a", "b"]});
        assert_eq!(format_variant(&spec, &Vec::new()), "`a` \\| `b`");
    }

    #[test]
    fn format_property_type_renders_const_as_backticked_value() {
        let spec = json!({"type": "string", "const": "tcp_connect"});
        assert_eq!(format_property_type(&spec, &Vec::new()), "`tcp_connect`");
    }

    #[test]
    fn format_variant_merges_ref_siblings_into_field_list() {
        let target = json!({
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}},
                "timeout_ms": {"type": "integer"}
            },
            "required": ["targets"]
        });
        let defs: Definitions = vec![("DiscoverScenarioConfig", &target)];
        let variant = json!({
            "type": "object",
            "$ref": "#/$defs/DiscoverScenarioConfig",
            "properties": {"signal_type": {"type": "string", "const": "discover"}},
            "required": ["signal_type"]
        });
        let out = format_variant(&variant, &defs);
        assert!(out.contains("`targets`"), "merged ref field missing: {out}");
        assert!(
            out.contains("`timeout_ms`"),
            "merged ref field missing: {out}"
        );
        assert!(
            out.contains("`signal_type`: `discover`"),
            "local discriminant missing: {out}"
        );
    }

    #[test]
    fn scenario_render_shows_tagged_discriminants() {
        let md = render_schema(&scenario_schema_value(), "rastreo-core/src/config/mod.rs");
        for token in ["`tcp_connect`", "`http`", "`snmp`", "`discover`", "`md5`"] {
            assert!(md.contains(token), "scenario render missing {token}");
        }
    }

    #[test]
    fn scenario_render_scenario_entry_lists_all_discover_fields() {
        let md = render_schema(&scenario_schema_value(), "rastreo-core/src/config/mod.rs");
        let header = "### `ScenarioEntry`";
        let start = md.find(header).expect("ScenarioEntry section");
        let after = start + header.len();
        let end = md[after..]
            .find("\n### ")
            .map(|i| after + i)
            .unwrap_or(md.len());
        let section = &md[start..end];
        for field in [
            "classifier",
            "encoder",
            "fuser",
            "max_concurrent",
            "name",
            "probe_rate",
            "probers",
            "retries",
            "sink",
            "targets",
            "timeout_ms",
            "signal_type",
        ] {
            assert!(
                section.contains(&format!("`{field}`")),
                "ScenarioEntry variant missing `{field}`: {section}"
            );
        }
    }

    #[test]
    fn device_render_shows_alt_ip_role_values() {
        let md = render_schema(&device_schema_value(), "rastreo-core/src/model/device.rs");
        for token in [
            "`secondary`",
            "`loopback`",
            "`vrrp`",
            "`hsrp`",
            "`carp`",
            "`anycast`",
            "`vip`",
        ] {
            assert!(md.contains(token), "device render missing {token}");
        }
    }

    #[test]
    fn format_type_renders_nullable_union() {
        let spec = json!({"type": ["string", "null"]});
        assert_eq!(format_type(&spec, &Vec::new()), "string \\| null");
    }

    #[test]
    fn format_type_preserves_format_hint_on_nullable_union() {
        let spec = json!({"type": ["string", "null"], "format": "ip"});
        assert_eq!(format_type(&spec, &Vec::new()), "string (ip) \\| null");
    }

    #[test]
    fn format_type_renders_array_with_ref_items() {
        let spec = json!({"type": "array", "items": {"$ref": "#/definitions/Signal"}});
        let out = format_type(&spec, &Vec::new());
        assert!(out.starts_with("array<"), "got: {out}");
        assert!(out.contains("`Signal`"));
    }

    #[test]
    fn format_type_renders_ref_as_link() {
        let spec = json!({"$ref": "#/definitions/IdentityKey"});
        let out = format_type(&spec, &Vec::new());
        assert!(out.contains("`IdentityKey`"));
        assert!(out.contains("(#identitykey)"));
    }

    #[test]
    fn format_type_extracts_ref_from_allof_wrapper() {
        let spec = json!({
            "allOf": [{"$ref": "#/definitions/IdentityKey"}]
        });
        let out = format_type(&spec, &Vec::new());
        assert!(out.contains("`IdentityKey`"), "got: {out}");
    }

    #[test]
    fn format_type_renders_integer_format() {
        let spec = json!({"type": "integer", "format": "uint16"});
        assert_eq!(format_type(&spec, &Vec::new()), "uint16");
    }

    #[test]
    fn format_type_renders_string_format() {
        let spec = json!({"type": "string", "format": "date-time"});
        assert_eq!(format_type(&spec, &Vec::new()), "string (date-time)");
    }

    #[test]
    fn extract_description_reads_allof_description() {
        let spec = json!({
            "description": "outer",
            "allOf": [{"$ref": "#/definitions/T"}]
        });
        assert_eq!(extract_description(&spec).as_deref(), Some("outer"));
    }

    #[test]
    fn one_line_collapses_whitespace() {
        assert_eq!(one_line("a\nb  c\td"), "a b c d");
    }

    #[test]
    fn escape_cell_escapes_pipe() {
        assert_eq!(escape_cell("a | b"), "a \\| b");
    }
}
