use std::time::SystemTime;

use schemars::JsonSchema;

use crate::model::scan::ScanMetadata;

/// Canonical URL for the current `LinkRecord` JSON Schema, served from the rastreo docs site.
pub const LINK_SCHEMA_ID: &str = "https://davidban77.github.io/rastreo/schemas/link-record-v1.json";

/// Schema version stamped on every `LinkRecord`; versioned independently of the device record.
pub const LINK_CURRENT_SCHEMA_VERSION: &str = "v1";

/// One end of a discovered link. `identity_key` correlates the endpoint to a probed device; it is
/// `None` for a neighbor rastreo learned via LLDP but never probed ("known-unknown").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct LinkEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    pub chassis_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sys_name: Option<String>,
    pub port: String,
}

/// A deduplicated topology edge between two endpoints. Both directions of a physical link collapse
/// into one record keyed by the unordered pair of LLDP chassis-ids.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct LinkRecord {
    pub schema_version: String,
    pub schema_id: String,
    pub a: LinkEndpoint,
    pub b: LinkEndpoint,
    /// Discovery mechanism that produced the link (`lldp` today; leaves room for `cdp`/`gnmi`).
    pub discovered_via: String,
    #[serde(with = "crate::model::serde_iso8601")]
    #[schemars(schema_with = "crate::model::serde_iso8601::date_time_schema")]
    pub observed_at: SystemTime,
    pub scan_metadata: ScanMetadata,
}

impl LinkRecord {
    pub const SCHEMA_VERSION: &'static str = LINK_CURRENT_SCHEMA_VERSION;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(chassis: &str) -> LinkEndpoint {
        LinkEndpoint {
            identity_key: Some(format!("mac:{chassis}")),
            chassis_id: chassis.to_string(),
            sys_name: Some("sw01".to_string()),
            port: "Gi0/1".to_string(),
        }
    }

    fn sample() -> LinkRecord {
        LinkRecord {
            schema_version: LinkRecord::SCHEMA_VERSION.to_string(),
            schema_id: LINK_SCHEMA_ID.to_string(),
            a: endpoint("aabbccddeeff"),
            b: endpoint("001122334455"),
            discovered_via: "lldp".to_string(),
            observed_at: SystemTime::UNIX_EPOCH,
            scan_metadata: ScanMetadata::default(),
        }
    }

    #[test]
    fn link_record_round_trips_json() {
        let record = sample();
        let s = serde_json::to_string(&record).expect("serialize");
        let back: LinkRecord = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, record);
    }

    #[test]
    fn link_record_carries_current_schema_version_and_id() {
        let record = sample();
        assert_eq!(record.schema_version, LINK_CURRENT_SCHEMA_VERSION);
        assert_eq!(
            record.schema_id,
            "https://davidban77.github.io/rastreo/schemas/link-record-v1.json"
        );
    }

    #[test]
    fn link_endpoint_omits_identity_and_sysname_when_none() {
        let endpoint = LinkEndpoint {
            identity_key: None,
            chassis_id: "aabbccddeeff".to_string(),
            sys_name: None,
            port: "Gi0/1".to_string(),
        };
        let json = serde_json::to_value(&endpoint).expect("serialize");
        let obj = json.as_object().expect("object");
        assert!(obj.get("identity_key").is_none());
        assert!(obj.get("sys_name").is_none());
        assert!(obj.get("chassis_id").is_some());
        assert!(obj.get("port").is_some());
    }

    #[test]
    fn observed_at_serializes_as_rfc3339_string() {
        use std::time::Duration;
        let record = LinkRecord {
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_720_000_000),
            ..sample()
        };
        let json = serde_json::to_value(&record).expect("serialize");
        assert_eq!(json["observed_at"].as_str(), Some("2024-07-03T09:46:40Z"));
    }

    #[test]
    fn json_schema_marks_observed_at_as_date_time_string() {
        let schema = schemars::schema_for!(LinkRecord);
        let json = serde_json::to_value(&schema).expect("schema serializes");
        assert_eq!(json["properties"]["observed_at"]["type"], "string");
        assert_eq!(json["properties"]["observed_at"]["format"], "date-time");
    }

    #[test]
    fn json_schema_declares_endpoint_and_scan_metadata() {
        let schema = schemars::schema_for!(LinkRecord);
        let json = serde_json::to_value(&schema).expect("schema serializes");
        assert!(json["properties"].get("a").is_some());
        assert!(json["properties"].get("b").is_some());
        assert!(json["properties"].get("scan_metadata").is_some());
    }

    #[test]
    fn link_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LinkRecord>();
        assert_send_sync::<LinkEndpoint>();
    }
}
