use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::config::DiscoverScenarioConfig;
use crate::error::ResumeError;
use crate::fuser::{subtree_contains_identity, FuserConfig};
use crate::model::scan::hex_lower;
use crate::model::Target;
use crate::prober::ProberConfig;
use crate::sink::SinkConfig;

/// Schema version of the on-disk checkpoint; [`Checkpoint::load`] refuses any other value.
pub const CHECKPOINT_VERSION: u32 = 1;

const FINGERPRINT_DOMAIN: &[u8] = b"rastreo.resume.fingerprint.v1";

/// Durable position of an in-progress scan: the contiguous prefix already flushed plus the pins
/// needed to replay the remainder identically. Written atomically after a durable flush and read
/// back at pre-flight to resume where the previous run stopped.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct Checkpoint {
    pub checkpoint_version: u32,
    pub scan_id: String,
    #[serde(with = "crate::model::serde_iso8601")]
    pub initiated_at: SystemTime,
    pub resume_fingerprint: String,
    pub source_config_hash: Option<String>,
    pub dns_pins: Vec<(Target, Vec<IpAddr>)>,
    pub highest_flushed_index: usize,
}

impl Checkpoint {
    /// Persist atomically: serialize to `<path>.tmp`, then rename onto `<path>` so a reader never
    /// observes a partially written file (atomic on POSIX within one filesystem).
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), ResumeError> {
        let path = path.as_ref();
        let tmp = tmp_path(path);
        // Infallible: no float/non-string-key field, and the sole `SystemTime` uses the total ISO8601 helper.
        let bytes = serde_json::to_vec(self).expect("Checkpoint serialization is infallible");
        std::fs::write(&tmp, &bytes).map_err(|source| ResumeError::Persist {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, path).map_err(|source| ResumeError::Persist {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    /// Read and validate a checkpoint. An unreadable or unparseable file yields
    /// [`ResumeError::CorruptCheckpoint`]; a foreign schema yields [`ResumeError::UnknownVersion`].
    /// Never silently returns a checkpoint this build cannot honor.
    pub fn load(path: impl AsRef<Path>) -> Result<Checkpoint, ResumeError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|_| ResumeError::CorruptCheckpoint {
            path: path.to_path_buf(),
        })?;
        let checkpoint: Checkpoint =
            serde_json::from_slice(&bytes).map_err(|_| ResumeError::CorruptCheckpoint {
                path: path.to_path_buf(),
            })?;
        if checkpoint.checkpoint_version != CHECKPOINT_VERSION {
            return Err(ResumeError::UnknownVersion {
                found: checkpoint.checkpoint_version,
                expected: CHECKPOINT_VERSION,
            });
        }
        Ok(checkpoint)
    }
}

/// `false` iff the tree contains an identity fuser, whose cross-scan correlation a partial-prefix resume cannot reconstruct.
pub fn fuser_supports_resume(config: &FuserConfig) -> bool {
    !subtree_contains_identity(config)
}

/// `false` iff any prober feeds a second stream (LLDP topology / gNMI collection profiles) a checkpoint cannot replay.
pub fn probers_support_resume(probers: &[ProberConfig]) -> bool {
    probers
        .iter()
        .all(|prober| second_stream_kind(prober).is_none())
}

/// Pre-flight verdict: refuse with the first blocking reason, in fuser → probers → sink order.
pub fn resume_eligibility(scenario: &DiscoverScenarioConfig) -> Result<(), ResumeError> {
    if let Some(fuser) = &scenario.base.fuser {
        if !fuser_supports_resume(fuser) {
            return Err(ResumeError::IdentityFuserNotResumable);
        }
    }
    if let Some(kind) = scenario.probers.iter().find_map(second_stream_kind) {
        return Err(ResumeError::SecondStreamProberNotResumable { kind });
    }
    match &scenario.base.sink {
        Some(sink) if sink.supports_resume() => Ok(()),
        other => Err(ResumeError::SinkNotResumable {
            sink: sink_label(other.as_ref()),
        }),
    }
}

/// The hard resume guard: a stable hash over only the ordered targets and the sink append
/// destination. Perf and prober tuning are excluded — at-least-once delivery tolerates them, so
/// they belong to the advisory `source_config_hash`, not this narrow must-match guard.
pub fn resume_fingerprint(scenario: &DiscoverScenarioConfig) -> String {
    let targets =
        serde_json::to_vec(&scenario.targets).expect("Target serialization is infallible");
    let destination = sink_destination_descriptor(scenario.base.sink.as_ref());

    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update((targets.len() as u64).to_le_bytes());
    hasher.update(&targets);
    hasher.update((destination.len() as u64).to_le_bytes());
    hasher.update(destination.as_bytes());
    let digest = hasher.finalize();
    format!("sha256:{}", hex_lower(&digest))
}

fn second_stream_kind(prober: &ProberConfig) -> Option<&'static str> {
    // Refuse on the gNMI variant itself: it always feeds the collection-profile assembler,
    // independent of its `lldp` flag, so inspecting `gnmi.lldp` would under-refuse.
    #[cfg(feature = "lldp")]
    if matches!(prober, ProberConfig::Lldp { .. }) {
        return Some("lldp");
    }
    #[cfg(feature = "gnmi")]
    if matches!(prober, ProberConfig::Gnmi { .. }) {
        return Some("gnmi");
    }
    let _ = prober;
    None
}

fn sink_destination_descriptor(sink: Option<&SinkConfig>) -> String {
    match sink {
        None => "sink:none".to_string(),
        Some(SinkConfig::Stdout) => "sink:stdout".to_string(),
        Some(SinkConfig::Memory) => "sink:memory".to_string(),
        Some(SinkConfig::File { path }) => format!("sink:file:{}", path.display()),
        #[cfg(feature = "kafka")]
        Some(SinkConfig::Kafka { brokers, topic, .. }) => {
            format!("sink:kafka:{}:{}", brokers.join(","), topic)
        }
        #[cfg(feature = "nats")]
        Some(SinkConfig::Nats {
            servers,
            subject,
            stream,
            ..
        }) => format!("sink:nats:{}:{}:{}", servers.join(","), subject, stream),
    }
}

fn sink_label(sink: Option<&SinkConfig>) -> String {
    match sink {
        None => "none".to_string(),
        Some(SinkConfig::Stdout) => "stdout".to_string(),
        Some(SinkConfig::File { .. }) => "file".to_string(),
        Some(SinkConfig::Memory) => "memory".to_string(),
        #[cfg(feature = "kafka")]
        Some(SinkConfig::Kafka { .. }) => "kafka".to_string(),
        #[cfg(feature = "nats")]
        Some(SinkConfig::Nats { .. }) => "nats".to_string(),
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_owned();
    raw.push(".tmp");
    PathBuf::from(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::config::BaseProbeConfig;
    use crate::fuser::IdentityHints;
    use crate::model::ScanMetadata;

    fn direct() -> Box<FuserConfig> {
        Box::new(FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: None,
            confidence_per_signal: None,
        })
    }

    fn identity_over(inner: Box<FuserConfig>) -> FuserConfig {
        FuserConfig::Identity {
            identity_hints: IdentityHints::default(),
            inner,
        }
    }

    fn ip(last: u8) -> Target {
        Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)))
    }

    fn scenario(
        fuser: Option<FuserConfig>,
        probers: Vec<ProberConfig>,
        sink: Option<SinkConfig>,
    ) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig {
                fuser,
                sink,
                ..Default::default()
            },
            targets: vec![ip(1)],
            probers,
        }
    }

    fn sample_checkpoint() -> Checkpoint {
        Checkpoint {
            checkpoint_version: CHECKPOINT_VERSION,
            scan_id: "01J000000000000000000000AA".to_string(),
            initiated_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            resume_fingerprint: "sha256:deadbeef".to_string(),
            source_config_hash: Some("sha256:cafef00d".to_string()),
            dns_pins: vec![(
                Target::DnsName("router-1.lab".to_string()),
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
            )],
            highest_flushed_index: 42,
        }
    }

    #[test]
    fn checkpoint_version_constant_is_one() {
        assert_eq!(CHECKPOINT_VERSION, 1);
    }

    #[test]
    fn checkpoint_round_trips_through_json() {
        let cp = sample_checkpoint();
        let bytes = serde_json::to_vec(&cp).expect("serialize");
        let back: Checkpoint = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(
            serde_json::to_value(&back).expect("value"),
            serde_json::to_value(&cp).expect("value"),
        );
    }

    #[test]
    fn checkpoint_round_trip_preserves_dns_pins_and_index() {
        let cp = sample_checkpoint();
        let bytes = serde_json::to_vec(&cp).expect("serialize");
        let back: Checkpoint = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back.highest_flushed_index, 42);
        assert_eq!(back.dns_pins.len(), 1);
        assert_eq!(
            back.dns_pins[0].0,
            Target::DnsName("router-1.lab".to_string())
        );
        assert_eq!(
            back.dns_pins[0].1,
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]
        );
    }

    #[test]
    fn write_then_load_recovers_the_checkpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let cp = sample_checkpoint();
        cp.write(&path).expect("write");
        let back = Checkpoint::load(&path).expect("load");
        assert_eq!(
            serde_json::to_value(&back).expect("value"),
            serde_json::to_value(&cp).expect("value"),
        );
    }

    #[test]
    fn write_is_atomic_and_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        sample_checkpoint().write(&path).expect("write");
        assert!(path.exists(), "the final checkpoint file must exist");
        assert!(
            !tmp_path(&path).exists(),
            "the .tmp staging file must be renamed away, not left behind"
        );
    }

    #[test]
    fn checkpoint_v1_golden_json_locks_the_wire_format() {
        let expected = r#"{"checkpoint_version":1,"scan_id":"01J000000000000000000000AA","initiated_at":"2023-11-14T22:13:20Z","resume_fingerprint":"sha256:deadbeef","source_config_hash":"sha256:cafef00d","dns_pins":[[{"DnsName":"router-1.lab"},["10.0.0.5"]]],"highest_flushed_index":42}"#;
        assert_eq!(
            serde_json::to_string(&sample_checkpoint()).expect("serialize"),
            expected,
        );
    }

    #[test]
    fn write_to_missing_parent_dir_yields_persist_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("no-such-dir").join("scan.checkpoint");
        match sample_checkpoint().write(&path) {
            Err(ResumeError::Persist { path: p, .. }) => assert_eq!(p, tmp_path(&path)),
            other => panic!("expected Persist, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_corrupt_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        std::fs::write(&path, b"{ this is not valid json ]").expect("write garbage");
        match Checkpoint::load(&path) {
            Err(ResumeError::CorruptCheckpoint { path: p }) => assert_eq!(p, path),
            other => panic!("expected CorruptCheckpoint, got {other:?}"),
        }
    }

    #[test]
    fn load_returns_corrupt_for_unreadable_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.checkpoint");
        assert!(matches!(
            Checkpoint::load(&path),
            Err(ResumeError::CorruptCheckpoint { .. })
        ));
    }

    #[test]
    fn load_rejects_unknown_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let mut cp = sample_checkpoint();
        cp.checkpoint_version = CHECKPOINT_VERSION + 1;
        cp.write(&path).expect("write");
        match Checkpoint::load(&path) {
            Err(ResumeError::UnknownVersion { found, expected }) => {
                assert_eq!(found, CHECKPOINT_VERSION + 1);
                assert_eq!(expected, CHECKPOINT_VERSION);
            }
            other => panic!("expected UnknownVersion, got {other:?}"),
        }
    }

    #[test]
    fn checkpoint_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Checkpoint>();
    }

    #[test]
    fn fuser_supports_resume_true_for_direct() {
        assert!(fuser_supports_resume(&direct()));
    }

    #[test]
    fn fuser_supports_resume_false_for_identity() {
        assert!(!fuser_supports_resume(&identity_over(direct())));
    }

    #[cfg(feature = "oui")]
    #[test]
    fn fuser_supports_resume_true_for_oui_over_direct() {
        let cfg = FuserConfig::OuiEnrichment {
            data_path: String::new(),
            inner: direct(),
        };
        assert!(fuser_supports_resume(&cfg));
    }

    #[cfg(feature = "oui")]
    #[test]
    fn fuser_supports_resume_false_for_identity_nested_under_oui() {
        let cfg = FuserConfig::OuiEnrichment {
            data_path: String::new(),
            inner: Box::new(identity_over(direct())),
        };
        assert!(
            !fuser_supports_resume(&cfg),
            "an identity fuser anywhere in the tree blocks resume"
        );
    }

    #[test]
    fn probers_support_resume_true_for_empty() {
        assert!(probers_support_resume(&[]));
    }

    #[test]
    fn probers_support_resume_true_for_tcp_only() {
        assert!(probers_support_resume(&[ProberConfig::TcpConnect {
            ports: vec![22]
        }]));
    }

    #[cfg(feature = "lldp")]
    #[test]
    fn probers_support_resume_false_for_lldp() {
        assert!(!probers_support_resume(&[lldp_prober()]));
    }

    #[cfg(feature = "gnmi")]
    #[test]
    fn probers_support_resume_false_for_gnmi() {
        assert!(!probers_support_resume(&[gnmi_prober(false)]));
    }

    #[cfg(feature = "gnmi")]
    #[test]
    fn probers_support_resume_false_for_gnmi_even_when_lldp_flag_off() {
        assert!(
            !probers_support_resume(&[gnmi_prober(false)]),
            "a gNMI prober feeds the collection-profile assembler regardless of its lldp flag"
        );
    }

    #[cfg(feature = "lldp")]
    fn lldp_prober() -> ProberConfig {
        ProberConfig::Lldp {
            ports: vec![161],
            version: crate::prober::SnmpVersion::V2c,
            community: crate::prober::Community("public".to_string()),
            credentials: crate::prober::UsmCredentials::default(),
            max_rows: 64,
        }
    }

    #[cfg(feature = "gnmi")]
    fn gnmi_prober(lldp: bool) -> ProberConfig {
        ProberConfig::Gnmi {
            ports: vec![57400],
            plaintext: true,
            username: String::new(),
            password: crate::prober::Password(String::new()),
            get_paths: Vec::new(),
            lldp,
        }
    }

    fn file_sink() -> SinkConfig {
        SinkConfig::File {
            path: PathBuf::from("/tmp/rastreo.ndjson"),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Expect {
        Ok,
        Fuser,
        Prober(&'static str),
        Sink,
    }

    #[test]
    fn resume_eligibility_matrix_classifies_every_combination() {
        struct FuserCase {
            label: &'static str,
            cfg: Option<FuserConfig>,
            resumable: bool,
        }
        struct ProberCase {
            label: &'static str,
            probers: Vec<ProberConfig>,
            kind: Option<&'static str>,
        }
        struct SinkCase {
            label: &'static str,
            cfg: Option<SinkConfig>,
            resumable: bool,
        }

        let base_fusers: Vec<FuserCase> = vec![
            FuserCase {
                label: "none",
                cfg: None,
                resumable: true,
            },
            FuserCase {
                label: "direct",
                cfg: Some(*direct()),
                resumable: true,
            },
            FuserCase {
                label: "identity",
                cfg: Some(identity_over(direct())),
                resumable: false,
            },
        ];
        #[cfg(feature = "oui")]
        let extra_fusers: Vec<FuserCase> = vec![
            FuserCase {
                label: "oui_over_direct",
                cfg: Some(FuserConfig::OuiEnrichment {
                    data_path: String::new(),
                    inner: direct(),
                }),
                resumable: true,
            },
            FuserCase {
                label: "identity_under_oui",
                cfg: Some(FuserConfig::OuiEnrichment {
                    data_path: String::new(),
                    inner: Box::new(identity_over(direct())),
                }),
                resumable: false,
            },
        ];
        #[cfg(not(feature = "oui"))]
        let extra_fusers: Vec<FuserCase> = Vec::new();
        let fusers: Vec<FuserCase> = base_fusers.into_iter().chain(extra_fusers).collect();

        let base_probers: Vec<ProberCase> = vec![
            ProberCase {
                label: "empty",
                probers: Vec::new(),
                kind: None,
            },
            ProberCase {
                label: "tcp",
                probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
                kind: None,
            },
        ];
        #[cfg(feature = "lldp")]
        let lldp_probers: Vec<ProberCase> = vec![ProberCase {
            label: "lldp",
            probers: vec![lldp_prober()],
            kind: Some("lldp"),
        }];
        #[cfg(not(feature = "lldp"))]
        let lldp_probers: Vec<ProberCase> = Vec::new();
        #[cfg(feature = "gnmi")]
        let gnmi_probers: Vec<ProberCase> = vec![
            ProberCase {
                label: "gnmi",
                probers: vec![gnmi_prober(false)],
                kind: Some("gnmi"),
            },
            ProberCase {
                label: "tcp_then_gnmi",
                probers: vec![
                    ProberConfig::TcpConnect { ports: vec![22] },
                    gnmi_prober(true),
                ],
                kind: Some("gnmi"),
            },
        ];
        #[cfg(not(feature = "gnmi"))]
        let gnmi_probers: Vec<ProberCase> = Vec::new();
        let probers: Vec<ProberCase> = base_probers
            .into_iter()
            .chain(lldp_probers)
            .chain(gnmi_probers)
            .collect();

        let base_sinks: Vec<SinkCase> = vec![
            SinkCase {
                label: "none",
                cfg: None,
                resumable: false,
            },
            SinkCase {
                label: "stdout",
                cfg: Some(SinkConfig::Stdout),
                resumable: false,
            },
            SinkCase {
                label: "memory",
                cfg: Some(SinkConfig::Memory),
                resumable: false,
            },
            SinkCase {
                label: "file",
                cfg: Some(file_sink()),
                resumable: true,
            },
        ];
        #[cfg(feature = "kafka")]
        let kafka_sinks: Vec<SinkCase> = vec![SinkCase {
            label: "kafka",
            cfg: Some(SinkConfig::Kafka {
                brokers: vec!["kafka:9092".to_string()],
                topic: "rastreo.devices".to_string(),
                links_topic: None,
                profiles_topic: None,
                flush_mode: Default::default(),
                dead_letter: None,
                tls: None,
                sasl: None,
                retry: Default::default(),
            }),
            resumable: true,
        }];
        #[cfg(not(feature = "kafka"))]
        let kafka_sinks: Vec<SinkCase> = Vec::new();
        #[cfg(feature = "nats")]
        let nats_sinks: Vec<SinkCase> = vec![SinkCase {
            label: "nats",
            cfg: Some(SinkConfig::Nats {
                servers: vec!["nats://n:4222".to_string()],
                subject: "rastreo.records".to_string(),
                stream: "rastreo".to_string(),
                links_subject: None,
                profiles_subject: None,
                credentials: Default::default(),
                flush_mode: Default::default(),
                dead_letter: None,
                retry: Default::default(),
            }),
            resumable: true,
        }];
        #[cfg(not(feature = "nats"))]
        let nats_sinks: Vec<SinkCase> = Vec::new();
        let sinks: Vec<SinkCase> = base_sinks
            .into_iter()
            .chain(kafka_sinks)
            .chain(nats_sinks)
            .collect();

        for f in &fusers {
            for p in &probers {
                for s in &sinks {
                    let expect = if !f.resumable {
                        Expect::Fuser
                    } else if let Some(kind) = p.kind {
                        Expect::Prober(kind)
                    } else if !s.resumable {
                        Expect::Sink
                    } else {
                        Expect::Ok
                    };

                    let scenario = scenario(f.cfg.clone(), p.probers.clone(), s.cfg.clone());
                    let label = format!("fuser={} prober={} sink={}", f.label, p.label, s.label);
                    let got = match resume_eligibility(&scenario) {
                        Ok(()) => Expect::Ok,
                        Err(ResumeError::IdentityFuserNotResumable) => Expect::Fuser,
                        Err(ResumeError::SecondStreamProberNotResumable { kind }) => {
                            Expect::Prober(kind)
                        }
                        Err(ResumeError::SinkNotResumable { .. }) => Expect::Sink,
                        Err(other) => panic!("[{label}] unexpected error: {other:?}"),
                    };
                    assert_eq!(got, expect, "[{label}] eligibility verdict mismatch");
                }
            }
        }
    }

    #[test]
    fn resume_eligibility_reports_sink_label_for_stdout() {
        let s = scenario(None, Vec::new(), Some(SinkConfig::Stdout));
        match resume_eligibility(&s) {
            Err(ResumeError::SinkNotResumable { sink }) => assert_eq!(sink, "stdout"),
            other => panic!("expected SinkNotResumable, got {other:?}"),
        }
    }

    #[test]
    fn resume_eligibility_reports_sink_label_none_when_unset() {
        let s = scenario(None, Vec::new(), None);
        match resume_eligibility(&s) {
            Err(ResumeError::SinkNotResumable { sink }) => assert_eq!(sink, "none"),
            other => panic!("expected SinkNotResumable, got {other:?}"),
        }
    }

    #[test]
    fn resume_fingerprint_is_stable_for_identical_scenarios() {
        let a = scenario(None, Vec::new(), Some(file_sink()));
        let b = scenario(None, Vec::new(), Some(file_sink()));
        assert_eq!(resume_fingerprint(&a), resume_fingerprint(&b));
    }

    #[test]
    fn resume_fingerprint_is_prefixed_sha256() {
        let fp = resume_fingerprint(&scenario(None, Vec::new(), Some(file_sink())));
        assert!(fp.starts_with("sha256:"), "fingerprint was: {fp}");
        assert_eq!(fp.len(), "sha256:".len() + 64);
    }

    #[test]
    fn resume_fingerprint_differs_when_targets_change() {
        let a = scenario(None, Vec::new(), Some(file_sink()));
        let mut b = scenario(None, Vec::new(), Some(file_sink()));
        b.targets = vec![ip(1), ip(2)];
        assert_ne!(resume_fingerprint(&a), resume_fingerprint(&b));
    }

    #[test]
    fn resume_fingerprint_differs_when_sink_destination_changes() {
        let a = scenario(None, Vec::new(), Some(file_sink()));
        let b = scenario(
            None,
            Vec::new(),
            Some(SinkConfig::File {
                path: PathBuf::from("/tmp/other.ndjson"),
            }),
        );
        assert_ne!(resume_fingerprint(&a), resume_fingerprint(&b));
    }

    #[test]
    fn resume_fingerprint_unchanged_when_only_perf_knob_changes() {
        let a = scenario(None, Vec::new(), Some(file_sink()));
        let mut b = scenario(None, Vec::new(), Some(file_sink()));
        b.base.max_concurrent = Some(999);
        b.base.probe_rate = Some(50);
        b.base.timeout_ms = Some(12_000);
        assert_eq!(
            resume_fingerprint(&a),
            resume_fingerprint(&b),
            "perf knobs are outside the hard guard"
        );
    }

    #[test]
    fn advisory_source_config_hash_changes_when_perf_knob_changes() {
        let a = scenario(
            None,
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
            Some(file_sink()),
        );
        let mut b = a.clone();
        b.base.max_concurrent = Some(999);
        assert_ne!(
            ScanMetadata::new(&a).source_config_hash,
            ScanMetadata::new(&b).source_config_hash,
            "the advisory whole-scenario hash DOES move on a perf knob, unlike the hard fingerprint"
        );
    }
}
