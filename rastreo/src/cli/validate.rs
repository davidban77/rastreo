#![cfg(feature = "config")]

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Parser;
use rastreo_core::config::{ScenarioEntry, ScenarioKind};

use super::discover::{
    load_scenario_file, merge_defaults, resolve_scenario_source, scenario_label,
};
use super::output::{print_scenario_invalid, OutputMode};

#[derive(Parser, Debug)]
pub struct ValidateArgs {
    /// Scenario file to validate: a path, or `@name` to resolve from the catalog directories.
    pub file: PathBuf,
}

pub fn run(args: ValidateArgs, mode: OutputMode) -> Result<()> {
    let path = resolve_scenario_source(&args.file)?;
    let file = load_scenario_file(&path).map_err(|e| e.report(mode))?;

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
        match cfg.validate() {
            Ok(()) => println!("{label}: ok"),
            Err(err) => {
                invalid += 1;
                print_scenario_invalid(&label, &err.to_string());
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

#[cfg(test)]
mod tests {
    use super::super::output::Verbosity;
    use super::*;
    use std::io::Write;

    fn parse_args<I, S>(argv: I) -> std::result::Result<ValidateArgs, clap::Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString> + Clone,
    {
        crate::cli::parse_without_env(argv)
    }

    fn write_scenario(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write");
        f
    }

    #[test]
    fn validate_args_parses_positional_file() {
        let parsed = parse_args(["validate", "/tmp/scenario.yml"]).expect("parses");
        assert_eq!(parsed.file, PathBuf::from("/tmp/scenario.yml"));
    }

    #[test]
    fn validate_args_requires_a_file() {
        let result = parse_args(["validate"]);
        assert!(result.is_err(), "validate without a file must be rejected");
    }

    #[test]
    fn run_returns_ok_for_a_valid_scenario_file() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        run(args, OutputMode::from(Verbosity::Normal)).expect("valid scenario file must validate");
    }

    #[test]
    fn run_returns_err_for_empty_probers_scenario() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers: []\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args, OutputMode::from(Verbosity::Normal))
            .expect_err("empty-probers scenario must be invalid");
        assert!(err.to_string().contains("invalid"), "err was: {err}");
    }

    #[test]
    fn run_returns_err_for_empty_targets_scenario() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets: []\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args, OutputMode::from(Verbosity::Normal))
            .expect_err("empty-targets scenario must be invalid");
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
        let err = run(args, OutputMode::from(Verbosity::Normal))
            .expect_err("invalid kafka sink must be invalid");
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
        run(args, OutputMode::from(Verbosity::Normal))
            .expect("secured kafka scenario must validate offline");
    }

    #[test]
    fn run_returns_err_for_bad_fuser_without_probing() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    fuser:\n      type: direct\n      confidence_baseline: 5.0\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args, OutputMode::from(Verbosity::Normal))
            .expect_err("bad-fuser scenario must be invalid");
        assert!(err.to_string().contains("invalid"), "err was: {err}");
    }

    #[test]
    fn run_returns_err_for_identity_fuser_with_bad_virtual_mac_without_probing() {
        let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    fuser:\n      type: identity\n      identity_hints:\n        vrrp_groups:\n          - virtual_ip: 10.0.0.1\n            virtual_mac: not-a-real-mac\n            members: []\n      inner:\n        type: direct\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args, OutputMode::from(Verbosity::Normal))
            .expect_err("bad identity virtual_mac must be invalid");
        assert!(err.to_string().contains("invalid"), "err was: {err}");
    }

    #[test]
    fn run_returns_err_for_unsupported_version() {
        let yaml = "version: 2\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
        let f = write_scenario(yaml);
        let args = ValidateArgs {
            file: f.path().to_path_buf(),
        };
        let err = run(args, OutputMode::from(Verbosity::Normal))
            .expect_err("unsupported version must error");
        assert!(err.to_string().contains("version"), "err was: {err}");
    }
}
