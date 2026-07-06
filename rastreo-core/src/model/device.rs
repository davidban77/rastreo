use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use schemars::JsonSchema;

use crate::error::ConfigError;
use crate::model::outcome::{ProbeKind, Signal};
use crate::model::scan::ScanMetadata;

/// Version tag stamped on every emitted `DeviceRecord`. Increment when the wire shape changes in a backward-incompatible way.
pub const CURRENT_SCHEMA_VERSION: &str = "v1";

/// Canonical URL for the current `DeviceRecord` JSON Schema. Consumers may fetch the schema at this URL for validation.
pub const CURRENT_SCHEMA_ID: &str = "https://schemas.rastreo.dev/device-record/v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct IdentityKey(Arc<str>);

impl IdentityKey {
    // Rejects empty / whitespace-only input; trims and lowercases the value.
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigError> {
        let s = value.into();
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::invalid("identity key cannot be empty"));
        }
        Ok(Self(Arc::from(trimmed.to_lowercase())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for IdentityKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for IdentityKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        IdentityKey::new(s).map_err(serde::de::Error::custom)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
#[schemars(transparent)]
pub struct Confidence(f64);

impl Confidence {
    // Rejects non-finite values and any value outside [0.0, 1.0].
    pub fn new(v: f64) -> Result<Self, ConfigError> {
        if v.is_finite() && (0.0..=1.0).contains(&v) {
            Ok(Self(v))
        } else {
            Err(ConfigError::invalid(format!(
                "confidence must be finite and in [0.0, 1.0], got {v}"
            )))
        }
    }

    pub fn value(self) -> f64 {
        self.0
    }
}

/// Role hint attached to each `AltIp`. Values map 1:1 to NetBox / Nautobot / Infrahub IP-address role models so downstream reconcilers pull the role directly instead of re-inferring it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AltIpRole {
    /// Secondary interface address on the same device.
    Secondary,
    /// Loopback address. Not currently inferred; reserved for future SNMP `ifDescr` signal.
    Loopback,
    /// VRRP virtual IP — detected from the `00:00:5e:00:01:XX` or `00:00:5e:00:02:XX` MAC prefix.
    Vrrp,
    /// HSRP virtual IP — detected from the `00:00:0c:07:ac:XX` MAC prefix.
    Hsrp,
    /// CARP virtual IP. Not currently inferred from MAC because CARP shares the VRRPv2 prefix; reserved for future signal-based detection.
    Carp,
    /// Anycast address. Not currently inferred; reserved.
    Anycast,
    /// Virtual IP (VIP) fronting real IPs. Not currently inferred; reserved.
    Vip,
}

/// Additional IP merged into a `DeviceRecord` by the identity fuser, carrying the role hint and the probe kinds that responded on that IP.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct AltIp {
    pub address: IpAddr,

    /// Role hint mapped to NetBox / Nautobot / Infrahub IP-address role models. `None` when the identity fuser can't infer a role from available signals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<AltIpRole>,

    /// Probe kinds that responded on this IP before the identity fuser merged it into the primary record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responded_via: Vec<ProbeKind>,
}

impl AltIp {
    /// Construct an `AltIp` with a bare address and no metadata.
    pub fn new(address: IpAddr) -> Self {
        Self {
            address,
            role: None,
            responded_via: Vec::new(),
        }
    }
}

/// Deserialization of `DeviceRecord` requires `schema_version` and `schema_id`.
/// Legacy NDJSON produced by rastreo v0.5 or earlier will fail to deserialize;
/// consumers should tag legacy records with an explicit v0 marker before ingest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct DeviceRecord {
    /// Canonical device identifier: `mac:XX:XX:XX:XX:XX:XX` when a MAC is discovered, else `ip:<address>`. Consumers use this as the primary identity key across scans.
    pub identity_key: IdentityKey,
    /// Management IP the device was probed on. For multi-IP devices merged by the identity fuser, this is the first target IP that survived resolution.
    pub mgmt_ip: Option<IpAddr>,
    /// First MAC address emitted across all probers against this device. Formatted as lower-case colon-separated hex.
    pub mac: Option<String>,
    /// Vendor name resolved from the MAC OUI prefix by the OUI enrichment fuser. `null` when the OUI is not in the bundled Wireshark manuf database.
    pub manufacturer: Option<String>,
    /// Fielded platform identifier (e.g. `cisco_ios`, `linux`, `junos`) derived from SNMP `sysDescr` or SSH banner parsing. Currently always `null`; populated once platform classification lands.
    pub platform: Option<String>,
    /// Fielded device role (e.g. `router`, `switch`, `host`) derived from `sysObjectID` prefix or port-based heuristics. Currently always `null`; populated once role classification lands.
    pub role: Option<String>,
    /// Confidence score in `[0.0, 1.0]` computed as `baseline + signals_observed * per_signal`, clamped. Higher values indicate stronger evidence that the record reflects a real device.
    pub confidence: Confidence,
    /// RFC 3339 UTC timestamp of the most recent probe that produced signals for this device.
    #[serde(with = "crate::model::serde_iso8601")]
    #[schemars(schema_with = "crate::model::serde_iso8601::date_time_schema")]
    pub last_seen: SystemTime,
    /// Deduplicated list of every observable fact collected from every prober that targeted this device.
    pub signals: Vec<Signal>,
    /// Schema version tag; always `CURRENT_SCHEMA_VERSION` for records emitted by this build.
    pub schema_version: String,
    /// Canonical schema URL; always `CURRENT_SCHEMA_ID` for records emitted by this build.
    pub schema_id: String,
    /// Additional IPs merged into this device by the identity fuser — empty when no identity fuser is configured or when the fuser saw nothing to merge. Each entry carries a role hint and the probe kinds that responded on that IP.
    #[serde(default)]
    pub alt_ips: Vec<AltIp>,
    /// When set, this record is a medium-confidence alias of another record identified by the given `IdentityKey`.
    #[serde(default)]
    pub possible_alias_of: Option<IdentityKey>,
    /// Provenance stamped by the pipeline at scan entry.
    #[serde(default)]
    pub scan_metadata: ScanMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn identity_key_accepts_lowercase_mac() {
        let k = IdentityKey::new("aa:bb:cc:dd:ee:ff").expect("valid");
        assert_eq!(k.as_str(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn identity_key_lowercases_mixed_case_input() {
        let k = IdentityKey::new("AA:BB:cc:DD:Ee:ff").expect("valid");
        assert_eq!(k.as_str(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn identity_key_trims_surrounding_whitespace() {
        let k = IdentityKey::new("  router-1  ").expect("valid");
        assert_eq!(k.as_str(), "router-1");
    }

    #[test]
    fn identity_key_rejects_empty_string() {
        let err = IdentityKey::new("").expect_err("empty must error");
        assert!(format!("{err}").contains("cannot be empty"));
    }

    #[test]
    fn identity_key_rejects_whitespace_only() {
        let err = IdentityKey::new("   \t\n  ").expect_err("whitespace must error");
        assert!(format!("{err}").contains("cannot be empty"));
    }

    #[test]
    fn identity_key_deserialize_rejects_empty_string() {
        let result: Result<IdentityKey, _> = serde_json::from_str("\"\"");
        assert!(result.is_err(), "empty string must fail deserialize");
    }

    #[test]
    fn identity_key_deserialize_rejects_whitespace_only() {
        let result: Result<IdentityKey, _> = serde_json::from_str("\"   \"");
        assert!(result.is_err(), "whitespace-only must fail deserialize");
    }

    #[test]
    fn confidence_accepts_zero() {
        let c = Confidence::new(0.0).expect("0.0 is valid");
        assert_eq!(c.value(), 0.0);
    }

    #[test]
    fn confidence_accepts_half() {
        let c = Confidence::new(0.5).expect("0.5 is valid");
        assert_eq!(c.value(), 0.5);
    }

    #[test]
    fn confidence_accepts_one() {
        let c = Confidence::new(1.0).expect("1.0 is valid");
        assert_eq!(c.value(), 1.0);
    }

    #[test]
    fn confidence_rejects_below_zero() {
        Confidence::new(-0.1).expect_err("-0.1 must error");
    }

    #[test]
    fn confidence_rejects_above_one() {
        Confidence::new(1.1).expect_err("1.1 must error");
    }

    #[test]
    fn confidence_rejects_nan() {
        Confidence::new(f64::NAN).expect_err("NaN must error");
    }

    #[test]
    fn confidence_rejects_infinity() {
        Confidence::new(f64::INFINITY).expect_err("infinity must error");
        Confidence::new(f64::NEG_INFINITY).expect_err("negative infinity must error");
    }

    #[test]
    fn device_record_round_trips_json() {
        let record = DeviceRecord {
            identity_key: IdentityKey::new("router-1").expect("identity key"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            manufacturer: Some("Cisco".into()),
            platform: Some("IOS-XR".into()),
            role: Some("router".into()),
            confidence: Confidence::new(0.8).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: vec![Signal::Mac("aa:bb:cc:dd:ee:ff".into())],
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: ScanMetadata::default(),
        };
        let s = serde_json::to_string(&record).expect("serialize");
        let back: DeviceRecord = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back.identity_key.as_str(), "router-1");
        assert_eq!(back.mgmt_ip, record.mgmt_ip);
        assert_eq!(back.confidence.value(), 0.8);
        assert_eq!(back.signals.len(), 1);
    }

    #[test]
    fn device_record_carries_current_schema_version() {
        let record = fresh_record();
        assert_eq!(record.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(record.schema_version, "v1");
    }

    #[test]
    fn device_record_schema_id_matches_published_url() {
        let record = fresh_record();
        assert_eq!(record.schema_id, CURRENT_SCHEMA_ID);
        assert!(record.schema_id.starts_with("https://"));
    }

    #[test]
    fn device_record_alt_ips_defaults_to_empty() {
        let record = fresh_record();
        assert!(record.alt_ips.is_empty());
    }

    #[test]
    fn device_record_possible_alias_of_defaults_to_none() {
        let record = fresh_record();
        assert!(record.possible_alias_of.is_none());
    }

    #[test]
    fn schemars_derives_produce_valid_json_schema() {
        let schema = schemars::schema_for!(DeviceRecord);
        let json = serde_json::to_value(&schema).expect("schema serializes");
        assert!(json.get("$schema").is_some(), "top-level $schema missing");
        assert_eq!(
            json["properties"]["schema_version"]["type"], "string",
            "schema_version property must be typed as string"
        );
        assert!(
            json["properties"].get("scan_metadata").is_some(),
            "scan_metadata property must be present"
        );
    }

    fn fresh_record() -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new("id").expect("identity"),
            mgmt_ip: None,
            mac: None,
            manufacturer: None,
            platform: None,
            role: None,
            confidence: Confidence::new(0.0).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: ScanMetadata::default(),
        }
    }

    #[test]
    fn device_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IdentityKey>();
        assert_send_sync::<Confidence>();
        assert_send_sync::<DeviceRecord>();
    }

    #[test]
    fn system_time_serializes_as_rfc3339_string() {
        use std::time::Duration;
        let record = DeviceRecord {
            last_seen: SystemTime::UNIX_EPOCH + Duration::from_secs(1_720_000_000),
            ..fresh_record()
        };
        let json = serde_json::to_value(&record).expect("serialize");
        let s = json["last_seen"].as_str().expect("last_seen is a string");
        assert_eq!(s, "2024-07-03T09:46:40Z", "unexpected rfc3339: {s}");
    }

    #[test]
    fn rfc3339_deserializes_to_system_time() {
        let json = serde_json::to_value(fresh_record()).expect("serialize");
        let mut object = json.as_object().expect("obj").clone();
        object.insert(
            "last_seen".to_string(),
            serde_json::Value::String("2024-07-03T09:46:40Z".to_string()),
        );
        let back: DeviceRecord =
            serde_json::from_value(serde_json::Value::Object(object)).expect("deserialize");
        let elapsed = back
            .last_seen
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("epoch positive");
        assert_eq!(elapsed.as_secs(), 1_720_000_000);
        assert_eq!(elapsed.subsec_nanos(), 0);
    }

    #[test]
    fn rfc3339_handles_sub_second_precision() {
        use std::time::Duration;
        let ts = SystemTime::UNIX_EPOCH + Duration::new(1_720_000_000, 123_456_789);
        let record = DeviceRecord {
            last_seen: ts,
            ..fresh_record()
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let back: DeviceRecord = serde_json::from_str(&json).expect("deserialize");
        let elapsed = back
            .last_seen
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("epoch positive");
        assert_eq!(elapsed.subsec_nanos(), 123_456_789);
    }

    #[test]
    fn rfc3339_deserializer_accepts_non_utc_offset() {
        let json = r#"{"identity_key":"ip:1.1.1.1","mgmt_ip":"1.1.1.1","mac":null,"manufacturer":null,"platform":null,"role":null,"confidence":0.1,"last_seen":"2024-07-03T15:16:40+05:30","signals":[],"schema_version":"v1","schema_id":"https://schemas.rastreo.dev/device-record/v1.json","alt_ips":[],"possible_alias_of":null,"scan_metadata":{"scan_id":"","scenario_name":null,"initiated_at":"1970-01-01T00:00:00Z","source_config_hash":null}}"#;
        let back: DeviceRecord = serde_json::from_str(json).expect("deserialize offset-input");
        let elapsed = back
            .last_seen
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("epoch positive");
        assert_eq!(elapsed.as_secs(), 1_720_000_000);
    }

    #[test]
    fn alt_ip_new_defaults_role_to_none_and_responded_via_to_empty() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let alt = AltIp::new(ip);
        assert_eq!(alt.address, ip);
        assert!(alt.role.is_none());
        assert!(alt.responded_via.is_empty());
    }

    #[test]
    fn alt_ip_role_serializes_as_snake_case() {
        for (role, wire) in [
            (AltIpRole::Secondary, "\"secondary\""),
            (AltIpRole::Loopback, "\"loopback\""),
            (AltIpRole::Vrrp, "\"vrrp\""),
            (AltIpRole::Hsrp, "\"hsrp\""),
            (AltIpRole::Carp, "\"carp\""),
            (AltIpRole::Anycast, "\"anycast\""),
            (AltIpRole::Vip, "\"vip\""),
        ] {
            let s = serde_json::to_string(&role).expect("serialize");
            assert_eq!(s, wire);
            let back: AltIpRole = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, role);
        }
    }

    #[test]
    fn alt_ip_omits_role_when_none_and_responded_via_when_empty() {
        let alt = AltIp::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
        let json = serde_json::to_value(&alt).expect("serialize");
        let obj = json.as_object().expect("object");
        assert!(obj.get("role").is_none(), "role must be omitted when None");
        assert!(
            obj.get("responded_via").is_none(),
            "responded_via must be omitted when empty"
        );
    }

    #[test]
    fn alt_ip_round_trips_with_role_and_responded_via() {
        let alt = AltIp {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
            role: Some(AltIpRole::Secondary),
            responded_via: vec![ProbeKind::TcpConnect, ProbeKind::Http],
        };
        let s = serde_json::to_string(&alt).expect("serialize");
        let back: AltIp = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, alt);
    }

    #[test]
    fn alt_ip_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AltIp>();
        assert_send_sync::<AltIpRole>();
    }

    #[test]
    fn json_schema_marks_last_seen_as_date_time_string() {
        let schema = schemars::schema_for!(DeviceRecord);
        let json = serde_json::to_value(&schema).expect("schema serializes");
        assert_eq!(
            json["properties"]["last_seen"]["type"], "string",
            "last_seen must be typed as string"
        );
        assert_eq!(
            json["properties"]["last_seen"]["format"], "date-time",
            "last_seen must carry format: date-time"
        );
    }
}
