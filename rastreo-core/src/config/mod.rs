#[cfg(feature = "config")]
pub(crate) mod secrets;

use schemars::JsonSchema;

use crate::classifier::ClassifierConfig;
use crate::encoder::EncoderConfig;
use crate::error::{ConfigError, RastreoError};
use crate::fuser::FuserConfig;
use crate::model::Target;
use crate::prober::ProberConfig;
use crate::sink::SinkConfig;

/// Upper bound on `BaseProbeConfig::retries`, mirroring the ICMP prober's `count` cap: past this a
/// larger value only shrinks each retransmit slice against the floor without extending the reach.
pub const MAX_RETRIES: u32 = 1024;

/// Parse a YAML scenario file from a UTF-8 string into a `ScenarioFile`. `${VAR}` env-var references and `!file <path>` tags are expanded before deserialization; missing vars or unreadable files fail here rather than surfacing at probe time.
#[cfg(feature = "config")]
pub fn parse_scenario_file(input: &str) -> Result<ScenarioFile, RastreoError> {
    let raw: serde_yaml_ng::Value = serde_yaml_ng::from_str(input)
        .map_err(|e| ConfigError::InvalidValue(format!("invalid YAML: {e}")))?;
    let expanded = secrets::expand(raw)?;
    ensure_no_retired_type_tags_yaml(&expanded)?;
    let file: ScenarioFile = serde_yaml_ng::from_value(expanded).map_err(|e| {
        ConfigError::InvalidValue(format!(
            "scenario shape validation failed after secret expansion: {e}"
        ))
    })?;
    file.defaults.ensure_no_retired_fields()?;
    file.defaults.ensure_retries_within_bound()?;
    for entry in &file.scenarios {
        match entry {
            ScenarioEntry::Discover(cfg) => {
                cfg.base.ensure_no_retired_fields()?;
                cfg.base.ensure_retries_within_bound()?;
            }
        }
    }
    Ok(file)
}

/// Parse the JSON body of a discovery scenario — the shape `POST /scans` accepts.
pub fn parse_discover_scenario_json(
    body: serde_json::Value,
) -> Result<DiscoverScenarioConfig, RastreoError> {
    ensure_no_retired_type_tags_json(&body)?;
    let scenario = serde_json::from_value(body)
        .map_err(|e| ConfigError::InvalidValue(format!("invalid scenario body: {e}")))?;
    Ok(scenario)
}

/// Parse a standalone YAML sink config — the shape `RASTREO_SINK_CONFIG_PATH` points at.
#[cfg(feature = "config")]
pub fn parse_sink_config(input: &str) -> Result<SinkConfig, RastreoError> {
    let raw: serde_yaml_ng::Value = serde_yaml_ng::from_str(input)
        .map_err(|e| ConfigError::InvalidValue(format!("invalid YAML: {e}")))?;
    ensure_no_retired_type_tags_yaml(&raw)?;
    let config = serde_yaml_ng::from_value(raw)
        .map_err(|e| ConfigError::InvalidValue(format!("sink shape validation failed: {e}")))?;
    Ok(config)
}

/// Removed `type:` discriminants, each paired with the message every config ingestion surface must reject it with. The match is position-blind: a tag retired in one position is rejected in every `type:` position.
pub(crate) const RETIRED_TYPE_TAGS: &[(&str, &str)] = &[(
    "oui_enrichment",
    "the `oui_enrichment` fuser was removed: vendor identity now comes from the `mib_enrichment` fuser, which matches an SNMP `sysObjectID` exactly instead of guessing from a MAC address prefix",
)];

fn retired_type_tag_message(tag: &str) -> Option<&'static str> {
    RETIRED_TYPE_TAGS
        .iter()
        .find_map(|(name, message)| (*name == tag).then_some(*message))
}

pub(crate) fn ensure_no_retired_type_tags_json(
    value: &serde_json::Value,
) -> Result<(), ConfigError> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(tag)) = map.get("type") {
                if let Some(message) = retired_type_tag_message(tag) {
                    return Err(ConfigError::invalid(message));
                }
            }
            map.values().try_for_each(ensure_no_retired_type_tags_json)
        }
        serde_json::Value::Array(items) => {
            items.iter().try_for_each(ensure_no_retired_type_tags_json)
        }
        _ => Ok(()),
    }
}

#[cfg(feature = "config")]
pub(crate) fn ensure_no_retired_type_tags_yaml(
    value: &serde_yaml_ng::Value,
) -> Result<(), ConfigError> {
    match value {
        serde_yaml_ng::Value::Mapping(map) => {
            if let Some(serde_yaml_ng::Value::String(tag)) = map.get("type") {
                if let Some(message) = retired_type_tag_message(tag) {
                    return Err(ConfigError::invalid(message));
                }
            }
            map.values().try_for_each(ensure_no_retired_type_tags_yaml)
        }
        serde_yaml_ng::Value::Sequence(items) => {
            items.iter().try_for_each(ensure_no_retired_type_tags_yaml)
        }
        _ => Ok(()),
    }
}

/// The YAML scenario file rastreo accepts via `rastreo discover --file`. Declares the shared
/// defaults and the list of discovery scenarios to run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
pub struct ScenarioFile {
    /// Scenario file format version.
    pub version: u8,
    pub kind: ScenarioKind,
    /// Defaults applied to every scenario unless the scenario overrides them.
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
    /// Retransmit attempts for connectionless probers that lack native retransmission (UDP, SNMP, DNS); 0 (default) issues a single request within the same total timeout.
    pub retries: Option<u32>,
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

    pub(crate) fn ensure_retries_within_bound(&self) -> Result<(), crate::error::ConfigError> {
        if let Some(retries) = self.retries {
            if retries > MAX_RETRIES {
                return Err(crate::error::ConfigError::invalid(format!(
                    "`retries` must be between 0 and {MAX_RETRIES}, got {retries}"
                )));
            }
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

/// A single discovery scenario: the targets to probe, the probers to run, and any per-scenario
/// overrides of the shared defaults.
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
        assert!(cfg.retries.is_none());
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
        let json =
            r#"{"name":"lab","max_concurrent":50,"probe_rate":25,"retries":3,"timeout_ms":1000}"#;
        let cfg: BaseProbeConfig = serde_json::from_str(json).expect("with fields");
        assert_eq!(cfg.name.as_deref(), Some("lab"));
        assert_eq!(cfg.max_concurrent, Some(50));
        assert_eq!(cfg.probe_rate, Some(25));
        assert_eq!(cfg.retries, Some(3));
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
    fn scenario_with_fuser_yaml(fuser: &str) -> String {
        format!("version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n    fuser:\n{fuser}")
    }

    // serde's own `unknown variant` message carries the tag name too, so asserting on the name alone would pass without the check under test.
    #[cfg(feature = "config")]
    fn retirement_message(yaml: &str) -> String {
        let err = parse_scenario_file(yaml).expect_err("a retired type tag must error");
        assert!(matches!(
            err,
            RastreoError::Config(ConfigError::InvalidValue(_))
        ));
        let msg = format!("{err}");
        assert!(
            !msg.contains("unknown variant"),
            "the retirement must be named, not left to serde: {msg}"
        );
        msg
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_rejects_the_retired_oui_enrichment_fuser() {
        let yaml = scenario_with_fuser_yaml(
            "      type: oui_enrichment\n      inner:\n        type: direct\n",
        );
        let msg = retirement_message(&yaml);
        assert!(msg.contains("oui_enrichment"), "msg: {msg}");
        assert!(msg.contains("mib_enrichment"), "msg: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_rejects_the_retired_fuser_nested_under_identity() {
        let yaml = scenario_with_fuser_yaml(
            "      type: identity\n      inner:\n        type: oui_enrichment\n        inner:\n          type: direct\n",
        );
        assert!(retirement_message(&yaml).contains("oui_enrichment"));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_rejects_the_retired_fuser_in_defaults() {
        let yaml = "version: 1\nkind: discovery\ndefaults:\n  fuser:\n    type: oui_enrichment\n    inner:\n      type: direct\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        assert!(retirement_message(yaml).contains("oui_enrichment"));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_accepts_a_direct_fuser() {
        let yaml = scenario_with_fuser_yaml("      type: direct\n      confidence_baseline: 0.2\n");
        let file = parse_scenario_file(&yaml).expect("a live fuser still parses");
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        assert!(d.base.fuser.is_some());
    }

    #[cfg(all(feature = "config", feature = "mib_enrichment"))]
    #[test]
    fn parse_scenario_file_accepts_the_mib_enrichment_fuser() {
        let yaml = scenario_with_fuser_yaml(
            "      type: mib_enrichment\n      inner:\n        type: direct\n",
        );
        let file = parse_scenario_file(&yaml).expect("mib_enrichment still parses");
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        assert!(matches!(
            d.base.fuser,
            Some(FuserConfig::MibEnrichment { .. })
        ));
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

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_accepts_retries() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    retries: 2\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let file = parse_scenario_file(yaml).expect("parse");
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        assert_eq!(d.base.retries, Some(2));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_accepts_retries_at_max() {
        let yaml = format!("version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    retries: {MAX_RETRIES}\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n");
        let file = parse_scenario_file(&yaml).expect("retries at the max parses");
        let ScenarioEntry::Discover(d) = &file.scenarios[0];
        assert_eq!(d.base.retries, Some(MAX_RETRIES));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_rejects_retries_over_max() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    retries: 99999\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let err = parse_scenario_file(yaml).expect_err("retries over the max must error");
        assert!(matches!(
            err,
            RastreoError::Config(ConfigError::InvalidValue(_))
        ));
        let msg = format!("{err}");
        assert!(msg.contains("retries"), "msg: {msg}");
        assert!(msg.contains("1024"), "msg: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_rejects_retries_over_max_in_defaults() {
        let yaml = "version: 1\nkind: discovery\ndefaults:\n  retries: 5000\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let err =
            parse_scenario_file(yaml).expect_err("retries over the max in defaults must error");
        let msg = format!("{err}");
        assert!(msg.contains("retries"), "msg: {msg}");
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

    #[cfg(feature = "config")]
    #[test]
    fn every_parse_entry_point_rejects_every_retired_type_tag_by_name() {
        for (tag, message) in RETIRED_TYPE_TAGS {
            let scenario_yaml = scenario_with_fuser_yaml(&format!(
                "      type: {tag}\n      inner:\n        type: direct\n"
            ));
            let scenario_json = serde_json::json!({
                "targets": [{"Ip": "10.0.0.1"}],
                "probers": [{"type": "tcp_connect", "ports": [22]}],
                "fuser": {"type": tag, "inner": {"type": "direct"}},
            });
            let sink_yaml = format!("type: {tag}\n");
            for (surface, rejection) in [
                (
                    "scenario file",
                    parse_scenario_file(&scenario_yaml).expect_err("rejected"),
                ),
                (
                    "scenario body",
                    parse_discover_scenario_json(scenario_json).expect_err("rejected"),
                ),
                (
                    "sink config",
                    parse_sink_config(&sink_yaml).expect_err("rejected"),
                ),
            ] {
                let msg = format!("{rejection}");
                assert!(
                    msg.contains(message),
                    "{surface} must name the retirement of `{tag}`: {msg}"
                );
                assert!(
                    !msg.contains("unknown variant"),
                    "{surface} left `{tag}` to serde: {msg}"
                );
            }
        }
    }

    #[test]
    fn parse_discover_scenario_json_accepts_a_minimal_body() {
        let body = serde_json::json!({
            "targets": [{"Ip": "10.0.0.1"}],
            "probers": [{"type": "tcp_connect", "ports": [22]}],
        });
        let scenario = parse_discover_scenario_json(body).expect("minimal body");
        assert_eq!(scenario.targets.len(), 1);
        assert_eq!(scenario.probers.len(), 1);
    }

    #[test]
    fn parse_discover_scenario_json_maps_a_shape_error_to_config_error() {
        let body = serde_json::json!({"targets": "not-a-list"});
        let err = parse_discover_scenario_json(body).expect_err("bad shape");
        assert!(matches!(
            err,
            RastreoError::Config(ConfigError::InvalidValue(_))
        ));
        assert!(format!("{err}").contains("invalid scenario body"));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_sink_config_accepts_a_live_sink() {
        let config = parse_sink_config("type: stdout\n").expect("sink config");
        assert!(matches!(config, SinkConfig::Stdout));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_sink_config_maps_malformed_yaml_to_config_error() {
        let err = parse_sink_config("type: [stdout\n").expect_err("bad yaml");
        assert!(matches!(
            err,
            RastreoError::Config(ConfigError::InvalidValue(_))
        ));
        assert!(format!("{err}").contains("invalid YAML"));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_sink_config_maps_an_unknown_sink_to_config_error() {
        let err = parse_sink_config("type: carrier_pigeon\n").expect_err("unknown sink");
        assert!(format!("{err}").contains("sink shape validation failed"));
    }

    #[test]
    fn json_walk_names_every_retired_tag_however_deeply_nested() {
        for (tag, message) in RETIRED_TYPE_TAGS {
            let value = serde_json::json!({
                "scenarios": [{"fuser": {"type": "identity", "inner": {"type": tag}}}]
            });
            let err = ensure_no_retired_type_tags_json(&value)
                .expect_err("a retired type tag must be rejected");
            assert_eq!(format!("{err}"), *message);
        }
    }

    #[test]
    fn json_walk_accepts_a_live_type_tag() {
        let value = serde_json::json!({"fuser": {"type": "direct"}});
        assert!(ensure_no_retired_type_tags_json(&value).is_ok());
    }

    #[test]
    fn json_walk_ignores_a_retired_name_that_is_not_a_type_tag() {
        for (tag, _) in RETIRED_TYPE_TAGS {
            let value = serde_json::json!({"name": tag, "type": "direct"});
            assert!(ensure_no_retired_type_tags_json(&value).is_ok());
        }
    }
}
