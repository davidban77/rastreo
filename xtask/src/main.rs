use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use schemars::schema_for;

fn main() -> Result<()> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask crate has no parent")?
        .to_path_buf();
    let schemas_dir = workspace_root.join("schemas");
    fs::create_dir_all(&schemas_dir)
        .with_context(|| format!("create {}", schemas_dir.display()))?;
    generate_all(&schemas_dir)
}

fn generate_all(dir: &Path) -> Result<()> {
    write_schema(dir, "device-record-v1.json", device_record_schema()?)?;
    write_schema(dir, "scan-metadata-v1.json", scan_metadata_schema()?)?;
    Ok(())
}

fn device_record_schema() -> Result<String> {
    let schema = schema_for!(rastreo_core::DeviceRecord);
    let json = serde_json::to_string_pretty(&schema).context("serialize DeviceRecord schema")?;
    Ok(format!("{json}\n"))
}

fn scan_metadata_schema() -> Result<String> {
    let schema = schema_for!(rastreo_core::ScanMetadata);
    let json = serde_json::to_string_pretty(&schema).context("serialize ScanMetadata schema")?;
    Ok(format!("{json}\n"))
}

fn write_schema(dir: &Path, file_name: &str, content: String) -> Result<()> {
    let path = dir.join(file_name);
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    println!("Wrote {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regenerate_schemas_is_idempotent() {
        let device_a = device_record_schema().expect("first gen");
        let device_b = device_record_schema().expect("second gen");
        assert_eq!(device_a, device_b, "DeviceRecord schema must be stable");

        let scan_a = scan_metadata_schema().expect("first gen");
        let scan_b = scan_metadata_schema().expect("second gen");
        assert_eq!(scan_a, scan_b, "ScanMetadata schema must be stable");
    }

    #[test]
    fn device_record_schema_names_current_type() {
        let json = device_record_schema().expect("gen");
        assert!(
            json.contains("\"title\": \"DeviceRecord\""),
            "expected DeviceRecord title, got: {json}"
        );
    }

    #[test]
    fn scan_metadata_schema_names_current_type() {
        let json = scan_metadata_schema().expect("gen");
        assert!(
            json.contains("\"title\": \"ScanMetadata\""),
            "expected ScanMetadata title, got: {json}"
        );
    }
}
