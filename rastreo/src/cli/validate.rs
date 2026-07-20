#![cfg(feature = "config")]

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Parser;
use rastreo_core::config::{DiscoverScenarioConfig, ScenarioEntry, ScenarioKind};

use super::discover::{
    load_scenario_file, merge_defaults, resolve_scenario_source, scenario_label,
};

#[derive(Parser, Debug)]
pub struct ValidateArgs {
    /// Scenario file to validate: a path, or `@name` to resolve from the catalog directories.
    pub file: PathBuf,
}

pub fn run(args: ValidateArgs) -> Result<()> {
    let path = resolve_scenario_source(&args.file)?;
    let file = load_scenario_file(&path)?;

    if file.version != 1 {
        return Err(anyhow!(
            "unsupported scenario file version {}: only version 1 is supported",
            file.version
        ));
    }
    if file.kind != ScenarioKind::Discovery {
        return Err(anyhow!(
            "unsupported scenario kind: only 'discovery' is supported"
        ));
    }
    if file.scenarios.is_empty() {
        return Err(anyhow!(
            "scenario file '{}' has no scenarios",
            path.display()
        ));
    }

    let defaults = file.defaults.clone();
    let total = file.scenarios.len();
    let mut invalid = 0usize;

    for (idx, entry) in file.scenarios.into_iter().enumerate() {
        let mut cfg = match entry {
            ScenarioEntry::Discover(cfg) => cfg,
            #[allow(unreachable_patterns)]
            _ => return Err(anyhow!("unsupported scenario entry variant")),
        };
        merge_defaults(&mut cfg.base, &defaults);
        let label = scenario_label(&cfg.base, idx, total);
        match validate_scenario(&cfg) {
            Ok(()) => println!("{label}: ok"),
            Err(reason) => {
                invalid += 1;
                eprintln!("{label}: {reason}");
            }
        }
    }

    if invalid == 0 {
        println!("{total} scenario(s) validated: all valid");
        Ok(())
    } else {
        Err(anyhow!("{invalid} of {total} scenario(s) invalid"))
    }
}

fn validate_scenario(cfg: &DiscoverScenarioConfig) -> Result<(), String> {
    if cfg.targets.is_empty() {
        return Err("no targets configured".to_string());
    }
    if cfg.probers.is_empty() {
        return Err("no probers configured".to_string());
    }
    if let Some(sink) = &cfg.base.sink {
        sink.validate().map_err(|e| e.to_string())?;
    }
    if let Some(fuser) = &cfg.base.fuser {
        fuser.validate().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rastreo_core::config::BaseProbeConfig;
    use rastreo_core::{FuserConfig, IdentityHints, ProberConfig, SinkConfig, Target};
    use std::io::Write;

    fn scenario(
        targets: Vec<Target>,
        probers: Vec<ProberConfig>,
        sink: Option<SinkConfig>,
    ) -> DiscoverScenarioConfig {
        let mut base = BaseProbeConfig::new();
        base.sink = sink;
        DiscoverScenarioConfig::new(base, targets, probers)
    }

    fn scenario_with_fuser(fuser: FuserConfig) -> DiscoverScenarioConfig {
        let mut cfg = scenario(one_ip(), vec![tcp_prober()], None);
        cfg.base.fuser = Some(fuser);
        cfg
    }

    fn direct(baseline: Option<f64>, per_signal: Option<f64>) -> FuserConfig {
        FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: baseline,
            confidence_per_signal: per_signal,
        }
    }

    fn tcp_prober() -> ProberConfig {
        ProberConfig::TcpConnect { ports: vec![22] }
    }

    fn one_ip() -> Vec<Target> {
        vec![Target::Ip("10.0.0.1".parse().expect("ip"))]
    }

    fn write_scenario(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write");
        f
    }

    #[test]
    fn validate_scenario_accepts_targets_probers_and_valid_sink() {
        let cfg = scenario(one_ip(), vec![tcp_prober()], Some(SinkConfig::Stdout));
        assert!(validate_scenario(&cfg).is_ok());
    }

    #[test]
    fn validate_scenario_accepts_missing_sink_as_the_default() {
        let cfg = scenario(one_ip(), vec![tcp_prober()], None);
        assert!(validate_scenario(&cfg).is_ok());
    }

    #[test]
    fn validate_scenario_rejects_empty_targets() {
        let cfg = scenario(Vec::new(), vec![tcp_prober()], None);
        let err = validate_scenario(&cfg).expect_err("empty targets must be invalid");
        assert!(err.contains("targets"), "err was: {err}");
    }

    #[test]
    fn validate_scenario_rejects_empty_probers() {
        let cfg = scenario(one_ip(), Vec::new(), None);
        let err = validate_scenario(&cfg).expect_err("empty probers must be invalid");
        assert!(err.contains("probers"), "err was: {err}");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_scenario_rejects_invalid_sink_config() {
        let sink = SinkConfig::Kafka {
            brokers: Vec::new(),
            topic: "t".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: rastreo_core::KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: None,
            retry: rastreo_core::SinkRetry::default(),
        };
        let cfg = scenario(one_ip(), vec![tcp_prober()], Some(sink));
        let err = validate_scenario(&cfg).expect_err("invalid sink must be invalid");
        assert!(err.contains("brokers"), "err was: {err}");
    }

    #[test]
    fn validate_scenario_rejects_confidence_baseline_out_of_range() {
        let cfg = scenario_with_fuser(direct(Some(5.0), None));
        let err = validate_scenario(&cfg).expect_err("out-of-range confidence must be invalid");
        assert!(err.contains("confidence_baseline"), "err was: {err}");
    }

    #[test]
    fn validate_scenario_rejects_nested_identity_fuser() {
        let cfg = scenario_with_fuser(FuserConfig::Identity {
            identity_hints: IdentityHints::default(),
            inner: Box::new(FuserConfig::Identity {
                identity_hints: IdentityHints::default(),
                inner: Box::new(direct(None, None)),
            }),
        });
        let err = validate_scenario(&cfg).expect_err("nested identity must be invalid");
        assert!(err.contains("outermost"), "err was: {err}");
    }

    #[cfg(feature = "oui")]
    #[test]
    fn validate_scenario_rejects_identity_nested_in_oui() {
        let cfg = scenario_with_fuser(FuserConfig::OuiEnrichment {
            data_path: "data/manuf.gz".to_string(),
            inner: Box::new(FuserConfig::Identity {
                identity_hints: IdentityHints::default(),
                inner: Box::new(direct(None, None)),
            }),
        });
        let err = validate_scenario(&cfg).expect_err("identity nested in oui must be invalid");
        assert!(err.contains("outermost"), "err was: {err}");
    }

    #[test]
    fn validate_scenario_accepts_identity_over_direct() {
        let cfg = scenario_with_fuser(FuserConfig::Identity {
            identity_hints: IdentityHints::default(),
            inner: Box::new(direct(Some(0.5), Some(0.1))),
        });
        assert!(validate_scenario(&cfg).is_ok());
    }

    #[test]
    fn validate_scenario_accepts_direct_with_in_range_confidence() {
        let cfg = scenario_with_fuser(direct(Some(0.2), Some(0.05)));
        assert!(validate_scenario(&cfg).is_ok());
    }

    #[test]
    fn validate_args_parses_positional_file() {
        let parsed =
            ValidateArgs::try_parse_from(["validate", "/tmp/scenario.yml"]).expect("parses");
        assert_eq!(parsed.file, PathBuf::from("/tmp/scenario.yml"));
    }

    #[test]
    fn validate_args_requires_a_file() {
        let result = ValidateArgs::try_parse_from(["validate"]);
        assert!(result.is_err(), "validate without a file must be rejected");
    }

    #[test]
    fn run_returns_ok_for_a_valid_scenario_file() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        run(args).expect("valid scenario file must validate");
    }

    #[test]
    fn run_returns_err_for_empty_probers_scenario() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers: []\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args).expect_err("empty-probers scenario must be invalid");
        assert!(err.to_string().contains("invalid"), "err was: {err}");
    }

    #[test]
    fn run_returns_err_for_empty_targets_scenario() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets: []\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args).expect_err("empty-targets scenario must be invalid");
        assert!(err.to_string().contains("invalid"), "err was: {err}");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn run_returns_err_for_invalid_kafka_sink_without_connecting() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    sink:\n      type: kafka\n      brokers: []\n      topic: rastreo.devices\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args).expect_err("invalid kafka sink must be invalid");
        assert!(err.to_string().contains("invalid"), "err was: {err}");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn run_validates_secured_kafka_sink_offline() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    sink:\n      type: kafka\n      brokers: [\"kafka:9092\"]\n      topic: rastreo.devices\n      tls:\n        verify: true\n      sasl:\n        mechanism: scram_sha_256\n        username: svc\n        password: pw\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        run(args).expect("secured kafka scenario must validate offline");
    }

    #[test]
    fn run_returns_err_for_bad_fuser_without_probing() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    fuser:\n      type: direct\n      confidence_baseline: 5.0\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args).expect_err("bad-fuser scenario must be invalid");
        assert!(err.to_string().contains("invalid"), "err was: {err}");
    }

    #[test]
    fn run_returns_err_for_identity_fuser_with_bad_virtual_mac_without_probing() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    fuser:\n      type: identity\n      identity_hints:\n        vrrp_groups:\n          - virtual_ip: 10.0.0.1\n            virtual_mac: not-a-real-mac\n            members: []\n      inner:\n        type: direct\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args).expect_err("bad identity virtual_mac must be invalid");
        assert!(err.to_string().contains("invalid"), "err was: {err}");
    }

    #[test]
    fn run_returns_err_for_unsupported_version() {
        let yaml = "version: 2\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args).expect_err("unsupported version must error");
        assert!(err.to_string().contains("version"), "err was: {err}");
    }
}
