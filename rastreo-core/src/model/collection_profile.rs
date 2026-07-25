use std::time::SystemTime;

use schemars::JsonSchema;

use crate::model::outcome::Transport;
use crate::model::scan::ScanMetadata;

/// Canonical URL for the current `CollectionProfileRecord` JSON Schema, served from the rastreo docs site.
pub const COLLECTION_PROFILE_SCHEMA_ID: &str =
    "https://davidban77.github.io/rastreo/schemas/collection-profile-record-v1.json";

/// Schema version stamped on every `CollectionProfileRecord`; versioned independently of the device record.
pub const COLLECTION_PROFILE_CURRENT_SCHEMA_VERSION: &str = "v1";

/// How to collect telemetry from a discovered endpoint: the endpoint that answered, the confidence
/// in the profile, and a protocol-tagged `collection` descriptor. One record per gNMI endpoint, so a
/// device with two management endpoints yields two profiles sharing an `identity_key`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct CollectionProfileRecord {
    /// Schema version tag; always `COLLECTION_PROFILE_CURRENT_SCHEMA_VERSION` for records emitted by this build.
    pub schema_version: String,
    /// Canonical schema URL; always `COLLECTION_PROFILE_SCHEMA_ID` for records emitted by this build.
    pub schema_id: String,
    /// Identity of the device this profile belongs to; shared across the device's endpoints.
    pub identity_key: String,
    /// The endpoint that returned the capability data.
    pub endpoint: ProfileEndpoint,
    pub confidence: ProfileConfidence,
    /// Optional human-readable note about the profile; omitted when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Protocol-tagged descriptor of what to collect and how.
    pub collection: Collection,
    /// RFC 3339 UTC timestamp of when the capability data was observed.
    #[serde(with = "crate::model::serde_iso8601")]
    #[schemars(schema_with = "crate::model::serde_iso8601::date_time_schema")]
    pub observed_at: SystemTime,
    /// Provenance stamped by the pipeline at scan entry.
    pub scan_metadata: ScanMetadata,
}

impl CollectionProfileRecord {
    pub const SCHEMA_VERSION: &'static str = COLLECTION_PROFILE_CURRENT_SCHEMA_VERSION;
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ProfileEndpoint {
    /// IP address the endpoint answered on.
    pub address: String,
    pub port: u16,
    pub transport: Transport,
}

/// How much the profile can be trusted. v1 is always `advertised_only`: the models and any suggested
/// subscriptions are derived from the endpoint's advertised capabilities, not verified against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProfileConfidence {
    AdvertisedOnly,
    VerifiedOnDevice,
}

/// Protocol-tagged collection descriptor. The `protocol` tag discriminates the variant, leaving room
/// for `snmp` and other protocols without reshaping the envelope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(tag = "protocol", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Collection {
    Gnmi {
        /// gNMI protocol version the endpoint advertised, when reported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gnmi_version: Option<String>,
        /// Recommended encoding for subscriptions, chosen from the endpoint's advertised encodings.
        encoding: String,
        /// YANG models the endpoint advertised support for.
        supported_models: Vec<String>,
        /// Subscriptions matched from the advertised models that a collector can stream.
        suggested_subscriptions: Vec<Subscription>,
    },
}

/// A recommended gNMI subscription a collector can stream, matched from the device's advertised models.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Subscription {
    pub name: String,
    /// gNMI path origin (e.g. `openconfig`).
    pub origin: String,
    /// gNMI path to subscribe to.
    pub path: String,
    /// Subscription mode (e.g. `sample`, `on_change`, `target_defined`).
    pub mode: String,
    /// Absent (null) for on-change or target-defined modes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_interval_ns: Option<u64>,
    /// Advertised model this subscription was matched from.
    pub matched_model: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CollectionProfileRecord {
        CollectionProfileRecord {
            schema_version: CollectionProfileRecord::SCHEMA_VERSION.to_string(),
            schema_id: COLLECTION_PROFILE_SCHEMA_ID.to_string(),
            identity_key: "mac:aabbccddeeff".to_string(),
            endpoint: ProfileEndpoint {
                address: "10.0.0.1".to_string(),
                port: 57400,
                transport: Transport::Tls,
            },
            confidence: ProfileConfidence::AdvertisedOnly,
            note: None,
            collection: Collection::Gnmi {
                gnmi_version: Some("0.10.0".to_string()),
                encoding: "JSON_IETF".to_string(),
                supported_models: vec!["openconfig-interfaces 3.0.0 (OpenConfig)".to_string()],
                suggested_subscriptions: Vec::new(),
            },
            observed_at: SystemTime::UNIX_EPOCH,
            scan_metadata: ScanMetadata::default(),
        }
    }

    #[test]
    fn collection_profile_round_trips_json() {
        let record = sample();
        let s = serde_json::to_string(&record).expect("serialize");
        let back: CollectionProfileRecord = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, record);
    }

    #[test]
    fn collection_serializes_with_protocol_tag() {
        let record = sample();
        let json = serde_json::to_value(&record).expect("serialize");
        assert_eq!(json["collection"]["protocol"], "gnmi");
        assert_eq!(json["confidence"], "advertised_only");
    }

    #[test]
    fn empty_suggested_subscriptions_serialize_as_a_present_array() {
        let json = serde_json::to_value(sample()).expect("serialize");
        assert_eq!(
            json["collection"]["suggested_subscriptions"]
                .as_array()
                .expect("array")
                .len(),
            0
        );
    }

    #[test]
    fn observed_at_serializes_as_rfc3339_string() {
        use std::time::Duration;
        let record = CollectionProfileRecord {
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_720_000_000),
            ..sample()
        };
        let json = serde_json::to_value(&record).expect("serialize");
        assert_eq!(json["observed_at"].as_str(), Some("2024-07-03T09:46:40Z"));
    }

    #[test]
    fn json_schema_marks_observed_at_as_date_time_string() {
        let schema = schemars::schema_for!(CollectionProfileRecord);
        let json = serde_json::to_value(&schema).expect("schema serializes");
        assert_eq!(json["properties"]["observed_at"]["type"], "string");
        assert_eq!(json["properties"]["observed_at"]["format"], "date-time");
    }

    #[test]
    fn collection_profile_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CollectionProfileRecord>();
        assert_send_sync::<Collection>();
        assert_send_sync::<Subscription>();
    }
}
