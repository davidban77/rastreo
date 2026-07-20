use std::time::SystemTime;

use schemars::JsonSchema;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::config::DiscoverScenarioConfig;

/// Per-scan provenance stamped on every emitted `DeviceRecord`. `scan_id` is a ULID; consumers can sort and correlate records by it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ScanMetadata {
    pub scan_id: String,
    pub scenario_name: Option<String>,
    #[serde(with = "crate::model::serde_iso8601")]
    #[schemars(schema_with = "crate::model::serde_iso8601::date_time_schema")]
    pub initiated_at: SystemTime,
    pub source_config_hash: Option<String>,
}

impl ScanMetadata {
    /// Builds fresh scan metadata for a scan of the given scenario.
    pub fn new(scenario: &DiscoverScenarioConfig) -> Self {
        let scan_id = Ulid::new().to_string();
        let scenario_name = scenario.base.name.clone();
        let initiated_at = SystemTime::now();
        let source_config_hash = hash_scenario(scenario);
        Self {
            scan_id,
            scenario_name,
            initiated_at,
            source_config_hash,
        }
    }
}

impl Default for ScanMetadata {
    fn default() -> Self {
        Self {
            scan_id: String::new(),
            scenario_name: None,
            initiated_at: SystemTime::UNIX_EPOCH,
            source_config_hash: None,
        }
    }
}

// Canonical JSON serialization keeps the hash stable across Rust toolchain upgrades.
// Credentials (`Community`, `Password`) have hand-rolled `Serialize` impls emitting
// `<redacted:xxxxxxxx>` (sha256-derived), so credential rotation changes the hash
// without leaking plaintext. `expect` is defensible: every reachable type derives
// `Serialize` and none has a fallible impl on well-formed data. NaN / Inf floats
// round-trip through serde_json as `null`; downstream `create_fuser` validation
// rejects them before they can collide with a real `None`.
fn hash_scenario(scenario: &DiscoverScenarioConfig) -> Option<String> {
    let bytes =
        serde_json::to_vec(scenario).expect("DiscoverScenarioConfig serialization is infallible");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Some(format!("sha256:{}", hex_lower(&digest)))
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::config::BaseProbeConfig;
    use crate::model::Target;
    use crate::prober::ProberConfig;

    fn scenario_with_name(name: Option<&str>) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig {
                name: name.map(|s| s.to_string()),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        }
    }

    #[test]
    fn scan_metadata_generates_ulid_scan_id() {
        let meta = ScanMetadata::new(&scenario_with_name(None));
        assert_eq!(meta.scan_id.len(), 26, "ULID is 26 chars");
        Ulid::from_string(&meta.scan_id).expect("scan_id parses as ULID");
    }

    #[test]
    fn scan_metadata_captures_scenario_name_when_set() {
        let meta = ScanMetadata::new(&scenario_with_name(Some("foo")));
        assert_eq!(meta.scenario_name.as_deref(), Some("foo"));
    }

    #[test]
    fn scan_metadata_captures_scenario_name_none_when_unset() {
        let meta = ScanMetadata::new(&scenario_with_name(None));
        assert!(meta.scenario_name.is_none());
    }

    #[test]
    fn scan_metadata_source_config_hash_is_prefixed_sha256() {
        let meta = ScanMetadata::new(&scenario_with_name(Some("lab")));
        let hash = meta.source_config_hash.expect("hash present");
        assert!(hash.starts_with("sha256:"), "hash was: {hash}");
        assert_eq!(hash.len(), "sha256:".len() + 64, "sha256 hex is 64 chars");
    }

    #[test]
    fn scan_metadata_source_config_hash_is_stable_across_serializations() {
        let a = ScanMetadata::new(&scenario_with_name(Some("lab")));
        let b = ScanMetadata::new(&scenario_with_name(Some("lab")));
        assert_eq!(
            a.source_config_hash, b.source_config_hash,
            "same scenario -> same hash"
        );
    }

    #[test]
    fn scan_metadata_source_config_hash_differs_for_different_scenarios() {
        let a = ScanMetadata::new(&scenario_with_name(Some("lab-a")));
        let b = ScanMetadata::new(&scenario_with_name(Some("lab-b")));
        assert_ne!(a.source_config_hash, b.source_config_hash);
    }

    #[test]
    fn scan_metadata_default_is_all_zero() {
        let meta = ScanMetadata::default();
        assert!(meta.scan_id.is_empty());
        assert!(meta.scenario_name.is_none());
        assert_eq!(meta.initiated_at, SystemTime::UNIX_EPOCH);
        assert!(meta.source_config_hash.is_none());
    }

    #[test]
    fn scan_metadata_scan_ids_are_unique_across_calls() {
        let a = ScanMetadata::new(&scenario_with_name(None));
        let b = ScanMetadata::new(&scenario_with_name(None));
        assert_ne!(a.scan_id, b.scan_id, "ULIDs must be unique per call");
    }

    #[test]
    fn scan_metadata_round_trips_json() {
        let meta = ScanMetadata::new(&scenario_with_name(Some("lab")));
        let s = serde_json::to_string(&meta).expect("serialize");
        let back: ScanMetadata = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(meta, back);
    }

    #[test]
    fn scan_metadata_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ScanMetadata>();
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn source_config_hash_differs_when_snmp_community_differs() {
        use crate::prober::{Community, SnmpVersion, UsmCredentials};

        let scenario_a = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                name: Some("lab".to_string()),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::Snmp {
                ports: vec![161],
                version: SnmpVersion::V2c,
                community: Community("public".to_string()),
                credentials: UsmCredentials::default(),
            }],
        };
        let scenario_b = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                name: Some("lab".to_string()),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::Snmp {
                ports: vec![161],
                version: SnmpVersion::V2c,
                community: Community("prod-r0".to_string()),
                credentials: UsmCredentials::default(),
            }],
        };

        let a = ScanMetadata::new(&scenario_a);
        let b = ScanMetadata::new(&scenario_b);
        assert_ne!(
            a.source_config_hash, b.source_config_hash,
            "credential rotation must change source_config_hash"
        );
    }

    #[test]
    fn source_config_hash_is_stable_across_debug_impl_churn() {
        // Serde-based hashing does not include Rust struct/variant names in the byte
        // stream, unlike Debug output ("DiscoverScenarioConfig { base: BaseProbeConfig { ... } }").
        // If a hash still contained those strings, a Rust toolchain upgrade that tweaked
        // Debug formatting would rotate hashes; asserting their absence is the closest
        // in-process proxy for "not Debug-based".
        let meta = ScanMetadata::new(&scenario_with_name(Some("lab")));
        let hash = meta.source_config_hash.expect("hash present");
        for token in [
            "DiscoverScenarioConfig",
            "BaseProbeConfig",
            "ProberConfig",
            "TcpConnect",
        ] {
            assert!(
                !hash.contains(token),
                "hash unexpectedly contains {token}: {hash}"
            );
        }
    }

    #[test]
    fn source_config_hash_stable_for_equivalent_scenarios() {
        let a = ScanMetadata::new(&scenario_with_name(Some("lab")));
        let b = ScanMetadata::new(&scenario_with_name(Some("lab")));
        assert_eq!(a.source_config_hash, b.source_config_hash);
    }

    #[cfg(feature = "nats")]
    #[test]
    fn source_config_hash_differs_when_nats_password_differs() {
        use crate::prober::Password;
        use crate::sink::{NatsCredentials, SinkConfig};

        let mk = |pw: &str| DiscoverScenarioConfig {
            base: BaseProbeConfig {
                name: Some("lab".to_string()),
                sink: Some(SinkConfig::Nats {
                    servers: vec!["nats://nats:4222".to_string()],
                    subject: "rastreo.discovery.records.v1".to_string(),
                    stream: "rastreo".to_string(),
                    links_subject: None,
                    profiles_subject: None,
                    credentials: NatsCredentials::UserPass {
                        username: "admin".to_string(),
                        password: Password(pw.to_string()),
                    },
                    flush_mode: Default::default(),
                    dead_letter: None,
                    retry: Default::default(),
                }),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let a = ScanMetadata::new(&mk("password-a"));
        let b = ScanMetadata::new(&mk("password-b"));
        assert_ne!(
            a.source_config_hash, b.source_config_hash,
            "nats password rotation must change source_config_hash"
        );
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn source_config_hash_differs_when_snmpv3_auth_password_differs() {
        use crate::prober::{Community, Password, SnmpVersion, UsmAuth, UsmCredentials};

        let mk = |pw: &str| DiscoverScenarioConfig {
            base: BaseProbeConfig {
                name: Some("lab".to_string()),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::Snmp {
                ports: vec![161],
                version: SnmpVersion::V3,
                community: Community("public".to_string()),
                credentials: UsmCredentials {
                    username: "admin".to_string(),
                    auth: UsmAuth::Sha256 {
                        password: Password(pw.to_string()),
                    },
                    privacy: Default::default(),
                },
            }],
        };

        let a = ScanMetadata::new(&mk("authpass-a"));
        let b = ScanMetadata::new(&mk("authpass-b"));
        assert_ne!(
            a.source_config_hash, b.source_config_hash,
            "auth-password rotation must change source_config_hash"
        );
    }
}
