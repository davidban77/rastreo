use crate::encoder::EncoderConfig;
use crate::fuser::FuserConfig;
use crate::model::Target;
use crate::prober::ProberConfig;
use crate::sink::SinkConfig;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ScenarioFile {
    pub version: u8,
    pub kind: ScenarioKind,
    #[serde(default)]
    pub defaults: BaseProbeConfig,
    pub scenarios: Vec<ScenarioEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScenarioKind {
    Discovery,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[non_exhaustive]
pub struct BaseProbeConfig {
    pub name: Option<String>,
    pub rate_limit: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub encoder: Option<EncoderConfig>,
    pub fuser: Option<FuserConfig>,
    pub sink: Option<SinkConfig>,
}

impl BaseProbeConfig {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "signal_type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScenarioEntry {
    Discover(DiscoverScenarioConfig),
}

#[derive(Debug, Clone, serde::Deserialize)]
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
        assert!(cfg.rate_limit.is_none());
        assert!(cfg.timeout_ms.is_none());
        assert!(cfg.encoder.is_none());
        assert!(cfg.fuser.is_none());
        assert!(cfg.sink.is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn base_probe_config_deserializes_with_fuser_from_yaml() {
        let yaml = "fuser:\n  type: direct\n  confidence_baseline: 0.2\n";
        let cfg: BaseProbeConfig = serde_yaml_ng::from_str(yaml).expect("yaml");
        let fuser = cfg.fuser.expect("fuser present");
        let FuserConfig::Direct {
            include_unreachable,
            confidence_baseline,
            confidence_per_signal,
        } = fuser;
        assert!(include_unreachable.is_none());
        assert_eq!(confidence_baseline, Some(0.2));
        assert!(confidence_per_signal.is_none());
    }

    #[test]
    fn base_probe_config_deserializes_from_empty_object() {
        let cfg: BaseProbeConfig = serde_json::from_str("{}").expect("empty object");
        assert!(cfg.name.is_none());
    }

    #[test]
    fn base_probe_config_deserializes_with_fields() {
        let json = r#"{"name":"lab","rate_limit":50,"timeout_ms":1000}"#;
        let cfg: BaseProbeConfig = serde_json::from_str(json).expect("with fields");
        assert_eq!(cfg.name.as_deref(), Some("lab"));
        assert_eq!(cfg.rate_limit, Some(50));
        assert_eq!(cfg.timeout_ms, Some(1000));
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
