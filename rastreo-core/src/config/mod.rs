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
    let file: ScenarioFile = deserialize_expanded(raw, secrets::SecretSource::Scenario)?;
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

/// Parse the JSON body of a discovery scenario — the shape `POST /scans` accepts. Unlike the file-backed parsers, `${VAR}` references stay literal: the body is client-supplied, so expanding it would read the server's environment back to the caller.
pub fn parse_discover_scenario_json(
    body: serde_json::Value,
) -> Result<DiscoverScenarioConfig, RastreoError> {
    ensure_no_retired_type_tags_json(&body)?;
    let scenario = serde_json::from_value(body)
        .map_err(|e| ConfigError::InvalidValue(format!("invalid scenario body: {e}")))?;
    Ok(scenario)
}

/// Parse a standalone YAML sink config — the shape `RASTREO_SINK_CONFIG_PATH` points at. `${VAR}` env-var references and `!file <path>` tags are expanded before deserialization, so a broker credential can live in the environment or on a secret mount instead of in the file.
#[cfg(feature = "config")]
pub fn parse_sink_config(input: &str) -> Result<SinkConfig, RastreoError> {
    let raw: serde_yaml_ng::Value = serde_yaml_ng::from_str(input)
        .map_err(|e| ConfigError::InvalidValue(format!("invalid YAML: {e}")))?;
    let config = deserialize_expanded(raw, secrets::SecretSource::SinkConfig)?;
    Ok(config)
}

#[cfg(feature = "config")]
fn deserialize_expanded<T: serde::de::DeserializeOwned>(
    raw: serde_yaml_ng::Value,
    source: secrets::SecretSource,
) -> Result<T, ConfigError> {
    let expanded = secrets::expand(raw.clone(), source)?;
    ensure_no_retired_type_tags_yaml(&expanded)?;
    // The discarded error quotes the offending scalar verbatim, which for an expanded position is
    // the secret itself; `shape_failure_detail` re-derives it from the tree as written.
    serde_yaml_ng::from_value(expanded).map_err(|_| {
        ConfigError::InvalidValue(format!(
            "{} shape validation failed after secret expansion: {}",
            source.shape_label(),
            secrets::shape_failure_detail::<T>(&raw)
        ))
    })
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

    pub(crate) fn effective_fuser_config(&self) -> FuserConfig {
        self.base
            .fuser
            .clone()
            .unwrap_or_else(crate::fuser::default_fuser_config)
    }

    pub(crate) fn effective_classifier_config(&self) -> ClassifierConfig {
        self.base
            .classifier
            .clone()
            .unwrap_or_else(crate::classifier::default_classifier_config)
    }

    pub(crate) fn effective_encoder_config(&self) -> EncoderConfig {
        self.base.encoder.clone().unwrap_or(EncoderConfig::Ndjson)
    }

    /// Everything a run refuses this scenario for without touching the network.
    pub fn validate(&self) -> Result<(), RastreoError> {
        self.base.ensure_no_retired_fields()?;
        self.base.ensure_retries_within_bound()?;
        if self.targets.is_empty() {
            return Err(ConfigError::invalid("scenario.targets must not be empty").into());
        }
        if self.probers.is_empty() {
            return Err(ConfigError::invalid("scenario.probers must not be empty").into());
        }
        for target in &self.targets {
            crate::resolver::ensure_target_shape(target)?;
        }
        if let Some(sink) = &self.base.sink {
            sink.validate()?;
        }
        if let Some(encoder) = &self.base.encoder {
            let structured = self
                .base
                .sink
                .as_ref()
                .is_some_and(SinkConfig::requires_structured_records);
            crate::encoder::ensure_encoder_output_fits_sink(encoder, structured)?;
        }
        // Constructing is the pipeline's own check; a second implementation of it would be a second opinion.
        for prober in &self.probers {
            crate::prober::create_prober(prober)?;
        }
        crate::fuser::create_fuser(&self.effective_fuser_config())?;
        crate::classifier::create_classifier(&self.effective_classifier_config())?;
        Ok(())
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

    #[cfg(feature = "config")]
    #[test]
    fn parse_scenario_file_rejects_a_reference_in_a_numeric_field_holding_a_valid_number() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_PARSE_NUMERIC_REFERENCE", "500") };
        let yaml = "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: \"${RASTREO_TEST_PARSE_NUMERIC_REFERENCE}\"\nscenarios: []\n";
        let err = parse_scenario_file(yaml).expect_err("expansion cannot fill a numeric field");
        let msg = format!("{err}");
        assert!(
            msg.contains("${RASTREO_TEST_PARSE_NUMERIC_REFERENCE}"),
            "msg: {msg}"
        );
        assert!(msg.contains("references resolved"), "msg: {msg}");
        assert!(
            msg.contains("can only fill a field that accepts one"),
            "msg: {msg}"
        );
        unsafe { std::env::remove_var("RASTREO_TEST_PARSE_NUMERIC_REFERENCE") };
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

            // Delivered through expansion, the tag reaches the walk only if expansion ran first.
            for (delivery, reference, _keep) in
                secret_references_to("RASTREO_TEST_CONFIG_RETIRED_TAG_SOURCE", tag)
            {
                let scenario_yaml = scenario_with_fuser_yaml(&format!(
                    "      type: {reference}\n      inner:\n        type: direct\n"
                ));
                let sink_yaml = format!("type: {reference}\n");
                for (surface, rejection) in [
                    (
                        "scenario file",
                        parse_scenario_file(&scenario_yaml).expect_err("rejected"),
                    ),
                    (
                        "sink config",
                        parse_sink_config(&sink_yaml).expect_err("rejected"),
                    ),
                ] {
                    let msg = format!("{rejection}");
                    assert!(
                        msg.contains(message),
                        "{surface} must name the retirement of `{tag}` delivered via {delivery}: {msg}"
                    );
                    assert!(
                        !msg.contains("unknown variant"),
                        "{surface} left `{tag}` delivered via {delivery} to serde: {msg}"
                    );
                }
            }
        }
    }

    /// Each expansion syntax as the YAML text resolving to `plaintext`, with the tempfile the `!file` arm must outlive.
    #[cfg(feature = "config")]
    fn secret_references_to(
        var: &str,
        plaintext: &str,
    ) -> Vec<(&'static str, String, Option<tempfile::NamedTempFile>)> {
        use std::io::Write;

        // SAFETY: env var mutation is process-global; each caller passes its own unique name.
        unsafe { std::env::set_var(var, plaintext) };
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(plaintext.as_bytes()).expect("write");
        let path = file.path().to_str().expect("utf-8 path").to_string();
        vec![
            ("${VAR}", format!("\"${{{var}}}\""), None),
            ("!file", format!("!file {path}"), Some(file)),
        ]
    }

    #[cfg(feature = "config")]
    #[derive(Clone, Copy)]
    enum ExpandingSurface {
        ScenarioFile,
        SinkConfig,
    }

    #[cfg(feature = "config")]
    impl ExpandingSurface {
        fn parse(self, yaml: &str) -> Result<(), RastreoError> {
            match self {
                ExpandingSurface::ScenarioFile => parse_scenario_file(yaml).map(|_| ()),
                ExpandingSurface::SinkConfig => parse_sink_config(yaml).map(|_| ()),
            }
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn no_expanding_parse_entry_point_quotes_an_expanded_secret_in_a_shape_error() {
        const SECRET: &str = "hunter2-plaintext-must-never-surface";

        let mut positions: Vec<(&str, ExpandingSurface, &str)> = Vec::new();
        positions.push((
            "scenario `version`",
            ExpandingSurface::ScenarioFile,
            "version: REF\nkind: discovery\nscenarios: []\n",
        ));
        positions.push(("sink `type`", ExpandingSurface::SinkConfig, "type: REF\n"));
        #[cfg(feature = "nats")]
        positions.extend([
            (
                "sink `servers`",
                ExpandingSurface::SinkConfig,
                "type: nats\nservers: REF\nsubject: s\nstream: RASTREO\n",
            ),
            (
                "sink `flush_mode`",
                ExpandingSurface::SinkConfig,
                "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: RASTREO\nflush_mode: REF\n",
            ),
        ]);

        for (position, surface, template) in positions {
            for (delivery, reference, _keep) in
                secret_references_to("RASTREO_TEST_CONFIG_SHAPE_ERROR_SOURCE", SECRET)
            {
                let yaml = template.replace("REF", &reference);
                let err = surface
                    .parse(&yaml)
                    .expect_err("a secret in a non-string position must fail shape validation");
                let msg = format!("{err}");
                assert!(
                    !msg.contains(SECRET),
                    "{position} via {delivery} leaked the plaintext: {msg}"
                );
                assert!(
                    msg.contains("after secret expansion"),
                    "{position} via {delivery}: {msg}"
                );
                assert!(
                    msg.contains(reference.trim_matches('"')),
                    "{position} via {delivery} must still name the reference as written: {msg}"
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
    fn parse_discover_scenario_json_leaves_env_var_references_literal() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_SCANS_BODY_VAR", "internal.example.net") };
        let body = serde_json::json!({
            "targets": [{"DnsName": "${RASTREO_TEST_SCANS_BODY_VAR}"}],
            "probers": [{"type": "tcp_connect", "ports": [22]}],
        });
        let scenario = parse_discover_scenario_json(body).expect("body parses");
        match &scenario.targets[0] {
            Target::DnsName(name) => assert_eq!(
                name, "${RASTREO_TEST_SCANS_BODY_VAR}",
                "a client body must never read the server's environment"
            ),
            other => panic!("expected DnsName target, got {other:?}"),
        }
        unsafe { std::env::remove_var("RASTREO_TEST_SCANS_BODY_VAR") };
    }

    #[test]
    fn parse_discover_scenario_json_leaves_a_nested_sink_reference_literal() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_SCANS_BODY_SINK_PATH", "captured") };
        let body = serde_json::json!({
            "targets": [{"Ip": "10.0.0.1"}],
            "probers": [{"type": "tcp_connect", "ports": [22]}],
            "sink": {"type": "file", "path": "/var/lib/rastreo/${RASTREO_TEST_SCANS_BODY_SINK_PATH}.ndjson"},
        });
        let scenario = parse_discover_scenario_json(body).expect("body parses");
        match scenario.base.sink.as_ref().expect("sink present") {
            SinkConfig::File { path } => assert_eq!(
                path,
                &std::path::PathBuf::from(
                    "/var/lib/rastreo/${RASTREO_TEST_SCANS_BODY_SINK_PATH}.ndjson"
                ),
                "a sink nested in a client body must never read the server's environment"
            ),
            other => panic!("expected File sink, got {other:?}"),
        }
        unsafe { std::env::remove_var("RASTREO_TEST_SCANS_BODY_SINK_PATH") };
    }

    #[cfg(feature = "nats")]
    #[test]
    fn parse_discover_scenario_json_leaves_a_nested_sink_credential_literal() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_SCANS_BODY_SINK_PASS", "hunter2") };
        let body = serde_json::json!({
            "targets": [{"Ip": "10.0.0.1"}],
            "probers": [{"type": "tcp_connect", "ports": [22]}],
            "sink": {
                "type": "nats",
                "servers": ["nats://probe:${RASTREO_TEST_SCANS_BODY_SINK_PASS}@nats:4222"],
                "subject": "rastreo.discovery.records.v1",
                "stream": "RASTREO",
            },
        });
        let scenario = parse_discover_scenario_json(body).expect("body parses");
        match scenario.base.sink.as_ref().expect("sink present") {
            SinkConfig::Nats { servers, .. } => assert_eq!(
                servers[0], "nats://probe:${RASTREO_TEST_SCANS_BODY_SINK_PASS}@nats:4222",
                "a sink nested in a client body must never read the server's environment"
            ),
            other => panic!("expected Nats sink, got {other:?}"),
        }
        unsafe { std::env::remove_var("RASTREO_TEST_SCANS_BODY_SINK_PASS") };
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

    #[cfg(feature = "config")]
    #[test]
    fn parse_sink_config_expands_env_var_in_a_sink_field() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe {
            std::env::set_var(
                "RASTREO_TEST_SINK_ENV_PATH",
                "/var/lib/rastreo/records.ndjson",
            )
        };
        let config = parse_sink_config("type: file\npath: \"${RASTREO_TEST_SINK_ENV_PATH}\"\n")
            .expect("sink config");
        match config {
            SinkConfig::File { path } => assert_eq!(
                path,
                std::path::PathBuf::from("/var/lib/rastreo/records.ndjson")
            ),
            other => panic!("expected File sink, got {other:?}"),
        }
        unsafe { std::env::remove_var("RASTREO_TEST_SINK_ENV_PATH") };
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_sink_config_expands_file_tag_in_a_sink_field() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(b"/var/lib/rastreo/from-mount.ndjson\n")
            .expect("write");
        let secret_path = f.path().to_str().expect("utf-8 path");
        let config = parse_sink_config(&format!("type: file\npath: !file {secret_path}\n"))
            .expect("sink config");
        match config {
            SinkConfig::File { path } => assert_eq!(
                path,
                std::path::PathBuf::from("/var/lib/rastreo/from-mount.ndjson")
            ),
            other => panic!("expected File sink, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_sink_config_missing_env_var_names_the_sink_config() {
        unsafe { std::env::remove_var("RASTREO_TEST_SINK_ENV_MISSING") };
        let err = parse_sink_config("type: file\npath: \"${RASTREO_TEST_SINK_ENV_MISSING}\"\n")
            .expect_err("must error");
        assert!(matches!(
            err,
            RastreoError::Config(ConfigError::InvalidValue(_))
        ));
        let msg = format!("{err}");
        assert!(msg.contains("RASTREO_TEST_SINK_ENV_MISSING"), "msg: {msg}");
        assert!(msg.contains("not set"), "msg: {msg}");
        assert!(msg.contains("sink config"), "msg: {msg}");
        assert!(!msg.contains("scenario"), "msg: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_sink_config_empty_env_var_substitutes_as_empty_string() {
        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_SINK_ENV_EMPTY", "") };
        let config = parse_sink_config(
            "type: file\npath: \"/var/lib/rastreo/records${RASTREO_TEST_SINK_ENV_EMPTY}.ndjson\"\n",
        )
        .expect("an empty value is not an error");
        match config {
            SinkConfig::File { path } => assert_eq!(
                path,
                std::path::PathBuf::from("/var/lib/rastreo/records.ndjson")
            ),
            other => panic!("expected File sink, got {other:?}"),
        }
        unsafe { std::env::remove_var("RASTREO_TEST_SINK_ENV_EMPTY") };
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn parse_sink_config_expands_env_var_into_the_nats_password() {
        use crate::sink::NatsCredentials;

        // SAFETY: env var mutation is process-global; use a unique per-test name.
        unsafe { std::env::set_var("RASTREO_TEST_SINK_NATS_PASS", "broker-secret") };
        let yaml = "type: nats\nservers: [\"nats://nats:4222\"]\nsubject: rastreo.discovery.records.v1\nstream: RASTREO\ncredentials:\n  type: user_pass\n  username: probe\n  password: \"${RASTREO_TEST_SINK_NATS_PASS}\"\n";
        let config = parse_sink_config(yaml).expect("sink config");
        let credentials = match config {
            SinkConfig::Nats { credentials, .. } => credentials,
            other => panic!("expected Nats sink, got {other:?}"),
        };
        let password = match &credentials {
            NatsCredentials::UserPass { password, .. } => password,
            other => panic!("expected user_pass credentials, got {other:?}"),
        };
        assert_eq!(password.expose(), "broker-secret");
        let debug = format!("{password:?}");
        assert!(debug.starts_with("<redacted:"), "debug: {debug}");
        assert!(
            !debug.contains("broker-secret"),
            "plaintext leaked: {debug}"
        );
        unsafe { std::env::remove_var("RASTREO_TEST_SINK_NATS_PASS") };
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

    fn one_ip() -> Vec<Target> {
        vec![Target::Ip("10.0.0.1".parse().expect("ip"))]
    }

    fn tcp_prober() -> Vec<ProberConfig> {
        vec![ProberConfig::TcpConnect { ports: vec![22] }]
    }

    fn scenario(base: BaseProbeConfig) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig::new(base, one_ip(), tcp_prober())
    }

    fn direct_fuser(baseline: Option<f64>) -> FuserConfig {
        FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: baseline,
            confidence_per_signal: None,
        }
    }

    fn invalid_value(err: RastreoError) -> String {
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => msg,
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_targets_probers_and_an_explicit_sink() {
        let base = BaseProbeConfig {
            sink: Some(SinkConfig::Stdout),
            ..Default::default()
        };
        assert!(scenario(base).validate().is_ok());
    }

    #[test]
    fn validate_accepts_a_missing_sink_as_the_default() {
        assert!(scenario(BaseProbeConfig::new()).validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_targets() {
        let config = DiscoverScenarioConfig::new(BaseProbeConfig::new(), Vec::new(), tcp_prober());
        let msg = invalid_value(
            config
                .validate()
                .expect_err("empty targets must be invalid"),
        );
        assert_eq!(msg, "scenario.targets must not be empty");
    }

    #[test]
    fn validate_rejects_empty_probers() {
        let config = DiscoverScenarioConfig::new(BaseProbeConfig::new(), one_ip(), Vec::new());
        let msg = invalid_value(
            config
                .validate()
                .expect_err("empty probers must be invalid"),
        );
        assert_eq!(msg, "scenario.probers must not be empty");
    }

    #[test]
    fn validate_rejects_a_retired_rate_limit_field() {
        let base = BaseProbeConfig {
            rate_limit: Some(50),
            ..Default::default()
        };
        let msg = invalid_value(
            scenario(base)
                .validate()
                .expect_err("a retired field must be invalid"),
        );
        assert!(msg.contains("rate_limit"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_retries_above_the_bound() {
        let base = BaseProbeConfig {
            retries: Some(MAX_RETRIES + 1),
            ..Default::default()
        };
        let msg = invalid_value(
            scenario(base)
                .validate()
                .expect_err("retries over the bound must be invalid"),
        );
        assert!(msg.contains("retries"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_an_out_of_range_confidence_baseline() {
        let base = BaseProbeConfig {
            fuser: Some(direct_fuser(Some(2.0))),
            ..Default::default()
        };
        let msg = invalid_value(
            scenario(base)
                .validate()
                .expect_err("a confidence_baseline above 1.0 must be invalid"),
        );
        assert!(msg.contains("confidence_baseline"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_a_nested_identity_fuser() {
        let base = BaseProbeConfig {
            fuser: Some(FuserConfig::Identity {
                identity_hints: crate::fuser::IdentityHints::default(),
                inner: Box::new(FuserConfig::Identity {
                    identity_hints: crate::fuser::IdentityHints::default(),
                    inner: Box::new(direct_fuser(None)),
                }),
            }),
            ..Default::default()
        };
        let msg = invalid_value(
            scenario(base)
                .validate()
                .expect_err("a nested identity fuser must be invalid"),
        );
        assert!(msg.contains("outermost"), "msg: {msg}");
    }

    #[test]
    fn validate_accepts_the_table_encoder_when_the_sink_is_left_default() {
        let base = BaseProbeConfig {
            encoder: Some(EncoderConfig::Table { width: 100 }),
            ..Default::default()
        };
        assert!(scenario(base).validate().is_ok());
    }

    #[cfg(feature = "kafka")]
    fn kafka_sink(brokers: Vec<&str>) -> SinkConfig {
        SinkConfig::Kafka {
            brokers: brokers.into_iter().map(String::from).collect(),
            topic: "rastreo.devices".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: crate::sink::KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: None,
            retry: crate::sink::SinkRetry::default(),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_rejects_a_sink_config_the_factory_would_refuse() {
        let base = BaseProbeConfig {
            sink: Some(kafka_sink(Vec::new())),
            ..Default::default()
        };
        let msg = invalid_value(
            scenario(base)
                .validate()
                .expect_err("a broker-less kafka sink must be invalid"),
        );
        assert!(msg.contains("brokers"), "msg: {msg}");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_rejects_the_table_encoder_against_a_sink_that_carries_structured_records() {
        let base = BaseProbeConfig {
            sink: Some(kafka_sink(vec!["kafka:9092"])),
            encoder: Some(EncoderConfig::Table { width: 100 }),
            ..Default::default()
        };
        let msg = invalid_value(
            scenario(base)
                .validate()
                .expect_err("the table encoder must not reach a broker sink"),
        );
        assert!(msg.contains("table encoder"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_a_prober_the_factory_would_refuse() {
        let config = DiscoverScenarioConfig::new(
            BaseProbeConfig::new(),
            one_ip(),
            vec![ProberConfig::TcpConnect { ports: Vec::new() }],
        );
        let msg = invalid_value(
            config
                .validate()
                .expect_err("a port-less tcp_connect prober must be invalid"),
        );
        assert!(msg.contains("at least one port"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_a_second_prober_family_the_factory_would_refuse() {
        let config = DiscoverScenarioConfig::new(
            BaseProbeConfig::new(),
            one_ip(),
            vec![ProberConfig::Dns {
                ports: vec![53],
                query_names: Vec::new(),
                query_type: crate::prober::DnsQueryType::A,
                transport: crate::prober::DnsTransport::Udp,
                recursion_desired: true,
            }],
        );
        let msg = invalid_value(
            config
                .validate()
                .expect_err("a dns prober with no query_names must be invalid"),
        );
        assert!(msg.contains("query_name"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_a_prober_the_factory_would_refuse_behind_a_buildable_one() {
        let config = DiscoverScenarioConfig::new(
            BaseProbeConfig::new(),
            one_ip(),
            vec![
                ProberConfig::TcpConnect { ports: vec![22] },
                ProberConfig::Udp {
                    ports: Vec::new(),
                    protocol: crate::prober::UdpProtocol::Ntp,
                },
            ],
        );
        let msg = invalid_value(
            config
                .validate()
                .expect_err("every prober is built, not just the first"),
        );
        assert!(msg.contains("at least one port"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_a_classifier_the_factory_would_refuse() {
        let base = BaseProbeConfig {
            classifier: Some(ClassifierConfig::Rules {
                merge_mode: crate::classifier::MergeMode::Extend,
                platform_rules: vec![crate::classifier::PlatformRule {
                    signal: crate::classifier::SignalKind::SshBanner,
                    pattern: "([unclosed".to_string(),
                    platform: Some("broken".to_string()),
                    os_version_capture: None,
                    ssh_version_capture: None,
                    http_server_capture: None,
                    http_version_capture: None,
                }],
                role_rules: Vec::new(),
            }),
            ..Default::default()
        };
        let err = scenario(base)
            .validate()
            .expect_err("an uncompilable platform-rule pattern must be invalid");
        assert!(
            matches!(
                err,
                RastreoError::Classifier(crate::error::ClassifierError::InvalidRegex { .. })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_a_role_rule_the_factory_would_refuse() {
        let base = BaseProbeConfig {
            classifier: Some(ClassifierConfig::Rules {
                merge_mode: crate::classifier::MergeMode::Extend,
                platform_rules: Vec::new(),
                role_rules: vec![crate::classifier::RoleRule::SysObjectIdPrefix {
                    prefix: "not.an.oid".to_string(),
                    role: "router".to_string(),
                }],
            }),
            ..Default::default()
        };
        let err = scenario(base)
            .validate()
            .expect_err("a malformed sysObjectID prefix must be invalid");
        assert!(
            matches!(
                err,
                RastreoError::Classifier(crate::error::ClassifierError::InvalidRoleRule(_))
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_a_backwards_range_target() {
        let config = DiscoverScenarioConfig::new(
            BaseProbeConfig::new(),
            vec![Target::Range {
                start: "10.0.0.5".parse().expect("ip"),
                end: "10.0.0.1".parse().expect("ip"),
            }],
            tcp_prober(),
        );
        let err = config
            .validate()
            .expect_err("a range whose start exceeds its end must be invalid");
        assert!(
            matches!(
                err,
                RastreoError::Resolver(crate::error::ResolverError::InvalidRange { .. })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_a_mixed_family_range_target() {
        let config = DiscoverScenarioConfig::new(
            BaseProbeConfig::new(),
            vec![Target::Range {
                start: "10.0.0.1".parse().expect("ip"),
                end: "2001:db8::1".parse().expect("ip"),
            }],
            tcp_prober(),
        );
        let err = config
            .validate()
            .expect_err("a range spanning two address families must be invalid");
        assert!(
            matches!(
                err,
                RastreoError::Resolver(crate::error::ResolverError::MixedFamilyRange { .. })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_a_bad_target_behind_a_good_one() {
        let config = DiscoverScenarioConfig::new(
            BaseProbeConfig::new(),
            vec![
                Target::Ip("10.0.0.1".parse().expect("ip")),
                Target::Range {
                    start: "10.0.0.5".parse().expect("ip"),
                    end: "10.0.0.1".parse().expect("ip"),
                },
            ],
            tcp_prober(),
        );
        assert!(
            config.validate().is_err(),
            "every target is checked, not just the first"
        );
    }

    #[cfg(feature = "mib_enrichment")]
    #[test]
    fn validate_rejects_a_mib_enrichment_table_the_factory_cannot_read() {
        let base = BaseProbeConfig {
            fuser: Some(FuserConfig::MibEnrichment {
                data_path: Some("/nonexistent/rastreo-mib-identity.tsv".to_string()),
                inner: Box::new(direct_fuser(None)),
            }),
            ..Default::default()
        };
        let msg = invalid_value(
            scenario(base)
                .validate()
                .expect_err("an unreadable enrichment table must be invalid"),
        );
        assert!(msg.contains("rastreo-mib-identity.tsv"), "msg: {msg}");
    }
}
