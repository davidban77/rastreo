#[cfg(feature = "config")]
pub(crate) mod secrets;

use schemars::JsonSchema;

use crate::classifier::ClassifierConfig;
use crate::encoder::EncoderConfig;
#[cfg(feature = "config")]
use crate::error::{ConfigError, RastreoError};
use crate::fuser::FuserConfig;
use crate::model::Target;
use crate::prober::ProberConfig;
use crate::sink::SinkConfig;

/// Parse a YAML scenario file from a UTF-8 string into a `ScenarioFile`. `${VAR}` env-var references and `!file <path>` tags are expanded before deserialization; missing vars or unreadable files fail here rather than surfacing at probe time.
#[cfg(feature = "config")]
pub fn parse_scenario_file(input: &str) -> Result<ScenarioFile, RastreoError> {
    let raw: serde_yaml_ng::Value = serde_yaml_ng::from_str(input)
        .map_err(|e| ConfigError::InvalidValue(format!("invalid YAML: {e}")))?;
    let expanded = secrets::expand(raw)?;
    let file: ScenarioFile = serde_yaml_ng::from_value(expanded).map_err(|e| {
        ConfigError::InvalidValue(format!(
            "scenario shape validation failed after secret expansion: {e}"
        ))
    })?;
    file.defaults.ensure_no_retired_fields()?;
    for entry in &file.scenarios {
        match entry {
            ScenarioEntry::Discover(cfg) => cfg.base.ensure_no_retired_fields()?,
        }
    }
    Ok(file)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
pub struct ScenarioFile {
    pub version: u8,
    pub kind: ScenarioKind,
    #[serde(default)]
    pub defaults: BaseProbeConfig,
    pub scenarios: Vec<ScenarioEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScenarioKind {
    Discovery,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct BaseProbeConfig {
    pub name: Option<String>,
    /// Maximum probes in flight at once.
    pub max_concurrent: Option<u32>,
    /// Maximum probes started per second; unset means no rate limit.
    pub probe_rate: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub encoder: Option<EncoderConfig>,
    pub fuser: Option<FuserConfig>,
    pub classifier: Option<ClassifierConfig>,
    pub sink: Option<SinkConfig>,
    // Retired: read old configs so validation can reject them with a migration hint.
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
    pub(crate) rate_limit: Option<u32>,
}

impl BaseProbeConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn ensure_no_retired_fields(&self) -> Result<(), crate::error::ConfigError> {
        if self.rate_limit.is_some() {
            return Err(crate::error::ConfigError::invalid(
                "`rate_limit` was renamed: use `max_concurrent` to keep the previous behavior (in-flight cap), or `probe_rate` for the new probes/sec pacing",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(tag = "signal_type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScenarioEntry {
    Discover(DiscoverScenarioConfig),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct DiscoverScenarioConfig {
    #[serde(flatten)]
    pub base: BaseProbeConfig,
    pub targets: Vec<Target>,
    #[serde(default)]
    pub probers: Vec<ProberConfig>,
}

impl DiscoverScenarioConfig {
    pub fn new(base: BaseProbeConfig, targets: Vec<Target>, probers: Vec<ProberConfig>) -> Self {
        Self {
            base,
            targets,
            probers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_kind_deserializes_snake_case() {
        let kind: ScenarioKind = serde_json::from_str("\"discovery\"").expect("deserialize");
        assert_eq!(kind, ScenarioKind::Discovery);
    }

    #[test]
    fn base_probe_config_default_is_all_none() {
        let cfg = BaseProbeConfig::default();
        assert!(cfg.name.is_none());
        assert!(cfg.max_concurrent.is_none());
        assert!(cfg.probe_rate.is_none());
        assert!(cfg.timeout_ms.is_none());
        assert!(cfg.encoder.is_none());
        assert!(cfg.fuser.is_none());
        assert!(cfg.classifier.is_none());
        assert!(cfg.sink.is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn base_probe_config_deserializes_with_classifier_from_yaml() {
        let yaml = "classifier:\n  type: noop\n";
        let cfg: BaseProbeConfig = serde_yaml_ng::from_str(yaml).expect("yaml");
        let classifier = cfg.classifier.expect("classifier present");
        assert!(matches!(classifier, ClassifierConfig::Noop));
    }

    #[cfg(feature = "config")]
    #[test]
    fn base_probe_config_deserializes_with_fuser_from_yaml() {
        let yaml = "fuser:\n  type: direct\n  confidence_baseline: 0.2\n";
        let cfg: BaseProbeConfig = serde_yaml_ng::from_str(yaml).expect("yaml");
        let fuser = cfg.fuser.expect("fuser present");
        match fuser {
            FuserConfig::Direct {
                include_unreachable,
                confidence_baseline,
                confidence_per_signal,
            } => {
                assert!(include_unreachable.is_none());
                assert_eq!(confidence_baseline, Some(0.2));
                assert!(confidence_per_signal.is_none());
            }
            #[allow(unreachable_patterns)]
            other => panic!("expected Direct fuser, got {other:?}"),
        }
    }

    #[test]
    fn base_probe_config_deserializes_from_empty_object() {
        let cfg: BaseProbeConfig = serde_json::from_str("{}").expect("empty object");
        assert!(cfg.name.is_none());
    }

    #[test]
    fn base_probe_config_deserializes_with_fields() {
        let json = r#"{"name":"lab","max_concurrent":50,"probe_rate":25,"timeout_ms":1000}"#;
        let cfg: BaseProbeConfig = serde_json::from_str(json).expect("with fields");
        assert_eq!(cfg.name.as_deref(), Some("lab"));
        assert_eq!(cfg.max_concurrent, Some(50));
        assert_eq!(cfg.probe_rate, Some(25));
        assert_eq!(cfg.timeout_ms, Some(1000));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_rejects_retired_rate_limit_with_migration_hint() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    rate_limit: 50\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let err = parse_scenario_file(yaml).expect_err("retired rate_limit must error");
        assert!(matches!(
            err,
            RastreoError::Config(ConfigError::InvalidValue(_))
        ));
        let msg = format!("{err}");
        assert!(msg.contains("max_concurrent"), "msg: {msg}");
        assert!(msg.contains("probe_rate"), "msg: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_rejects_retired_rate_limit_in_defaults() {
        let yaml = "version: 1\nkind: discovery\ndefaults:\n  rate_limit: 8\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let err = parse_scenario_file(yaml).expect_err("retired rate_limit in defaults must error");
        let msg = format!("{err}");
        assert!(msg.contains("max_concurrent"), "msg: {msg}");
        assert!(msg.contains("probe_rate"), "msg: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_accepts_max_concurrent_and_probe_rate() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    max_concurrent: 32\n    probe_rate: 100\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let file = parse_scenario_file(yaml).expect("parse");
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        assert_eq!(d.base.max_concurrent, Some(32));
        assert_eq!(d.base.probe_rate, Some(100));
    }

    #[test]
    fn scenario_file_deserializes_minimal_discover_entry() {
        let json = r#"{
            "version": 1,
            "kind": "discovery",
            "scenarios": [
                {
                    "signal_type": "discover",
                    "targets": [
                        {"Ip": "10.0.0.1"}
                    ]
                }
            ]
        }"#;
        let file: ScenarioFile = serde_json::from_str(json).expect("minimal file");
        assert_eq!(file.version, 1);
        assert_eq!(file.kind, ScenarioKind::Discovery);
        assert_eq!(file.scenarios.len(), 1);
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        assert_eq!(d.targets.len(), 1);
        assert!(d.probers.is_empty());
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_round_trips_minimal_yaml() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let file = parse_scenario_file(yaml).expect("parse");
        assert_eq!(file.version, 1);
        assert_eq!(file.kind, ScenarioKind::Discovery);
        assert_eq!(file.scenarios.len(), 1);
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_maps_serde_error_to_config_error() {
        let yaml = "version: 1\nkind: [invalid\n";
        let err = parse_scenario_file(yaml).expect_err("bad yaml");
        assert!(matches!(
            err,
            RastreoError::Config(ConfigError::InvalidValue(_))
        ));
        let msg = format!("{err}");
        assert!(msg.contains("invalid YAML"), "msg: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_expands_env_var_in_probe_field() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_PARSE_ENV_HOST", "10.9.8.7") };
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"${RASTREO_TEST_PARSE_ENV_HOST}\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let file = parse_scenario_file(yaml).expect("parse");
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        match &d.targets[0] {
            Target::Ip(ip) => assert_eq!(ip.to_string(), "10.9.8.7"),
            other => panic!("expected Ip target, got {other:?}"),
        }
        unsafe { std::env::remove_var("RASTREO_TEST_PARSE_ENV_HOST") };
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_expands_file_tag_in_probe_field() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(b"192.0.2.55\n").expect("write");
        let path = f.path().to_str().expect("utf-8 path");
        let yaml = format!(
            "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: !file {path}\n    probers:\n      - type: tcp_connect\n        ports: [22]\n"
        );
        let file = parse_scenario_file(&yaml).expect("parse");
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        match &d.targets[0] {
            Target::Ip(ip) => assert_eq!(ip.to_string(), "192.0.2.55"),
            other => panic!("expected Ip target, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_missing_env_var_returns_actionable_error() {
        unsafe { std::env::remove_var("RASTREO_TEST_PARSE_ENV_MISSING") };
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"${RASTREO_TEST_PARSE_ENV_MISSING}\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let err = parse_scenario_file(yaml).expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains("RASTREO_TEST_PARSE_ENV_MISSING"), "msg: {msg}");
        assert!(msg.contains("not set"), "msg: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_post_expansion_shape_error_is_labeled_distinctly() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_PARSE_ENV_BAD_IP", "not-an-ip") };
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"${RASTREO_TEST_PARSE_ENV_BAD_IP}\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let err = parse_scenario_file(yaml).expect_err("must error");
        assert!(matches!(
            err,
            RastreoError::Config(ConfigError::InvalidValue(_))
        ));
        let msg = format!("{err}");
        assert!(msg.contains("after secret expansion"), "msg: {msg}");
        assert!(!msg.contains("invalid YAML"), "msg: {msg}");
        unsafe { std::env::remove_var("RASTREO_TEST_PARSE_ENV_BAD_IP") };
    }

    #[cfg(all(feature = "config", feature = "snmp"))]
    #[test]
    fn parse_scenario_file_expands_env_var_into_snmp_community() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_SECRETS_COMMUNITY", "supersecret") };
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: snmp\n        version: v2c\n        community: \"${RASTREO_TEST_SECRETS_COMMUNITY}\"\n";
        let file = parse_scenario_file(yaml).expect("parse");
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        let community = match &d.probers[0] {
            ProberConfig::Snmp { community, .. } => community,
            other => panic!("expected SNMP prober, got {other:?}"),
        };
        assert_eq!(community.0, "supersecret");
        let debug = format!("{community:?}");
        assert!(debug.starts_with("<redacted:"), "debug: {debug}");
        assert!(!debug.contains("supersecret"), "plaintext leaked: {debug}");
        unsafe { std::env::remove_var("RASTREO_TEST_SECRETS_COMMUNITY") };
    }

    #[test]
    fn scenario_file_rejects_unknown_kind() {
        let json = r#"{
            "version": 1,
            "kind": "bogus",
            "scenarios": []
        }"#;
        let result: Result<ScenarioFile, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown kind must fail to deserialize");
    }
}
