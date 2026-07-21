use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::config::DiscoverScenarioConfig;
use crate::error::{RastreoError, ResumeError};
use crate::fuser::{subtree_contains_identity, FuserConfig};
use crate::model::scan::hex_lower;
use crate::model::{ScanMetadata, Target};
use crate::prober::ProberConfig;
use crate::sink::{Sink, SinkConfig};

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

/// The caller's checkpoint request: where to write and the target-count cadence. Built from the CLI
/// flags, then finalized into a [`CheckpointWriter`] once the scan's identity and DNS pins are known.
#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    pub path: PathBuf,
    pub interval: usize,
    /// Consume an existing checkpoint at `path` and continue from it, rather than refusing to clobber it.
    pub resume: bool,
}

/// Writes resume checkpoints for one scan at a target-count cadence. Holds the immutable per-scan
/// template; each write stamps the current durable prefix onto it.
pub struct CheckpointWriter {
    path: PathBuf,
    interval: usize,
    scan_id: String,
    initiated_at: SystemTime,
    resume_fingerprint: String,
    source_config_hash: Option<String>,
    dns_pins: Vec<(Target, Vec<IpAddr>)>,
    resume_base: usize,
    last_checkpoint_at: usize,
}

impl CheckpointWriter {
    pub fn new(
        config: CheckpointConfig,
        scan_metadata: &ScanMetadata,
        resume_fingerprint: String,
        dns_pins: Vec<(Target, Vec<IpAddr>)>,
    ) -> Self {
        Self {
            path: config.path,
            interval: config.interval.max(1),
            scan_id: scan_metadata.scan_id.clone(),
            initiated_at: scan_metadata.initiated_at,
            resume_fingerprint,
            source_config_hash: scan_metadata.source_config_hash.clone(),
            dns_pins,
            resume_base: 0,
            last_checkpoint_at: 0,
        }
    }

    /// Offset recorded indices by the targets a prior run already made durable, so a resumed run's
    /// checkpoints record the global position even though its scheduler restarts `target_index` at 0.
    pub fn with_resume_base(mut self, base: usize) -> Self {
        self.resume_base = base;
        self
    }

    /// Global durable index for a local completed-count: the resumed run holds `resume_base` durable
    /// targets from the prior run before its own local `next_expected` begin.
    pub(crate) fn record_index(&self, local_next_expected: usize) -> usize {
        self.resume_base + local_next_expected - 1
    }

    fn due(&self, next_expected: usize) -> bool {
        next_expected.saturating_sub(self.last_checkpoint_at) >= self.interval
    }

    /// At the cadence boundary, flush the sink to durability BEFORE recording the reached index — a
    /// checkpoint ahead of the flushed records would drop a record on resume. No-op below the cadence.
    pub async fn maybe_checkpoint(
        &mut self,
        sink: &mut dyn Sink,
        next_expected: usize,
    ) -> Result<(), RastreoError> {
        if next_expected == 0 || !self.due(next_expected) {
            return Ok(());
        }
        sink.flush().await?;
        self.write_at(self.record_index(next_expected))?;
        self.last_checkpoint_at = next_expected;
        Ok(())
    }

    /// Persist a checkpoint recording `highest_flushed_index` as the last durably-flushed target.
    pub(crate) fn write_at(&self, highest_flushed_index: usize) -> Result<(), ResumeError> {
        Checkpoint {
            checkpoint_version: CHECKPOINT_VERSION,
            scan_id: self.scan_id.clone(),
            initiated_at: self.initiated_at,
            resume_fingerprint: self.resume_fingerprint.clone(),
            source_config_hash: self.source_config_hash.clone(),
            dns_pins: self.dns_pins.clone(),
            highest_flushed_index,
        }
        .write(&self.path)
    }

    /// Remove the checkpoint on full completion — nothing remains to resume, and a leftover file would
    /// refuse-to-clobber the next run. An already-absent file is the desired state.
    pub fn delete(&self) -> Result<(), ResumeError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(ResumeError::Persist {
                path: self.path.clone(),
                source,
            }),
        }
    }
}

/// Refuse a checkpoint request that would be a lie: a non-resumable scenario, or a path already
/// holding a checkpoint (valid or corrupt) this run must not clobber. Only a free path proceeds.
pub fn checkpoint_preflight(
    scenario: &DiscoverScenarioConfig,
    path: &Path,
) -> Result<(), ResumeError> {
    resume_eligibility(scenario)?;
    if path.exists() {
        // Loading validates it; either way a file is here and must not be overwritten.
        Checkpoint::load(path)?;
        return Err(ResumeError::CheckpointExists {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Load and validate the checkpoint at `path` for a resume: a missing checkpoint refuses (`--resume`
/// needs one), the scenario is re-vetted resume-safe, and the hard fingerprint must match the target
/// sequence and sink destination. A changed perf/prober knob only warns — at-least-once tolerates it.
pub fn resume_preflight(
    scenario: &DiscoverScenarioConfig,
    path: &Path,
) -> Result<Checkpoint, ResumeError> {
    if !path.exists() {
        return Err(ResumeError::NoCheckpointToResume {
            path: path.to_path_buf(),
        });
    }
    let checkpoint = Checkpoint::load(path)?;
    resume_eligibility(scenario)?;
    if resume_fingerprint(scenario) != checkpoint.resume_fingerprint {
        return Err(ResumeError::FingerprintMismatch);
    }
    if checkpoint.source_config_hash != crate::model::scan::hash_scenario(scenario) {
        tracing::warn!(
            path = %path.display(),
            "resuming with a changed scenario config; a prober, fuser, or timeout knob differs — tolerated by at-least-once delivery"
        );
    }
    Ok(checkpoint)
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

    fn test_writer(path: &Path, interval: usize) -> CheckpointWriter {
        let metadata = ScanMetadata {
            scan_id: "01J000000000000000000000AA".to_string(),
            scenario_name: None,
            initiated_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            source_config_hash: Some("sha256:cafef00d".to_string()),
        };
        CheckpointWriter::new(
            CheckpointConfig {
                path: path.to_path_buf(),
                interval,
                resume: false,
            },
            &metadata,
            "sha256:deadbeef".to_string(),
            vec![(
                Target::DnsName("router-1.lab".to_string()),
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
            )],
        )
    }

    struct FlushFailsSink;

    #[async_trait::async_trait]
    impl Sink for FlushFailsSink {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Err(RastreoError::Sink(crate::sink::SinkError::new(
                crate::sink::SinkErrorClass::FlushFailure,
                std::io::Error::other("flush boom"),
            )))
        }
    }

    #[derive(Default)]
    struct FlushCountingSink {
        flushes: usize,
    }

    #[async_trait::async_trait]
    impl Sink for FlushCountingSink {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn maybe_checkpoint_flushes_before_writing_so_a_failed_flush_leaves_no_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let mut writer = test_writer(&path, 1);
        let mut sink = FlushFailsSink;
        let err = writer
            .maybe_checkpoint(&mut sink, 3)
            .await
            .expect_err("the pre-write flush error must surface");
        assert!(matches!(err, RastreoError::Sink(_)));
        assert!(
            !path.exists(),
            "flush precedes the checkpoint write; a failed flush must leave nothing on disk"
        );
    }

    #[tokio::test]
    async fn maybe_checkpoint_records_reached_index_after_flushing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let mut writer = test_writer(&path, 1);
        let mut sink = FlushCountingSink::default();
        writer
            .maybe_checkpoint(&mut sink, 5)
            .await
            .expect("checkpoint");
        assert_eq!(sink.flushes, 1, "the sink is flushed once at the boundary");
        let cp = Checkpoint::load(&path).expect("load");
        assert_eq!(cp.highest_flushed_index, 4, "K is next_expected - 1");
        assert_eq!(cp.scan_id, "01J000000000000000000000AA");
        assert_eq!(cp.resume_fingerprint, "sha256:deadbeef");
        assert_eq!(cp.dns_pins.len(), 1);
    }

    #[tokio::test]
    async fn maybe_checkpoint_is_a_noop_below_the_interval() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let mut writer = test_writer(&path, 5);
        let mut sink = FlushCountingSink::default();
        for n in 1..=4 {
            writer.maybe_checkpoint(&mut sink, n).await.expect("noop");
        }
        assert_eq!(sink.flushes, 0, "no flush below the cadence");
        assert!(!path.exists(), "no checkpoint below the cadence");
        writer
            .maybe_checkpoint(&mut sink, 5)
            .await
            .expect("boundary");
        assert_eq!(
            Checkpoint::load(&path).expect("load").highest_flushed_index,
            4
        );
        writer
            .maybe_checkpoint(&mut sink, 6)
            .await
            .expect("still noop");
        assert_eq!(sink.flushes, 1, "6 is below the next boundary of 10");
    }

    #[test]
    fn delete_removes_the_checkpoint_and_is_ok_when_already_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let writer = test_writer(&path, 1);
        writer.write_at(7).expect("write");
        assert!(path.exists());
        writer.delete().expect("delete");
        assert!(!path.exists());
        writer
            .delete()
            .expect("delete on a missing file is a no-op");
    }

    #[test]
    fn checkpoint_preflight_refuses_identity_fuser() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let s = scenario(Some(identity_over(direct())), Vec::new(), Some(file_sink()));
        assert!(matches!(
            checkpoint_preflight(&s, &path),
            Err(ResumeError::IdentityFuserNotResumable)
        ));
    }

    #[test]
    fn checkpoint_preflight_refuses_non_durable_sink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let s = scenario(None, Vec::new(), Some(SinkConfig::Stdout));
        assert!(matches!(
            checkpoint_preflight(&s, &path),
            Err(ResumeError::SinkNotResumable { .. })
        ));
    }

    #[cfg(feature = "gnmi")]
    #[test]
    fn checkpoint_preflight_refuses_second_stream_prober() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let s = scenario(Some(*direct()), vec![gnmi_prober(false)], Some(file_sink()));
        assert!(matches!(
            checkpoint_preflight(&s, &path),
            Err(ResumeError::SecondStreamProberNotResumable { kind: "gnmi" })
        ));
    }

    #[test]
    fn checkpoint_preflight_allows_eligible_scenario_on_a_fresh_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let s = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        checkpoint_preflight(&s, &path).expect("eligible scenario on a fresh path proceeds");
    }

    #[test]
    fn checkpoint_preflight_refuses_to_clobber_an_existing_valid_checkpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        sample_checkpoint().write(&path).expect("seed checkpoint");
        let s = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        match checkpoint_preflight(&s, &path) {
            Err(ResumeError::CheckpointExists { path: p }) => assert_eq!(p, path),
            other => panic!("expected CheckpointExists, got {other:?}"),
        }
    }

    #[test]
    fn checkpoint_preflight_refuses_to_clobber_a_corrupt_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        std::fs::write(&path, b"not a checkpoint").expect("seed garbage");
        let s = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        assert!(matches!(
            checkpoint_preflight(&s, &path),
            Err(ResumeError::CorruptCheckpoint { .. })
        ));
    }

    #[test]
    fn checkpoint_writer_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CheckpointWriter>();
    }

    #[tokio::test]
    async fn with_resume_base_records_the_global_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let mut writer = test_writer(&path, 1).with_resume_base(10);
        let mut sink = FlushCountingSink::default();
        writer
            .maybe_checkpoint(&mut sink, 5)
            .await
            .expect("checkpoint");
        assert_eq!(
            Checkpoint::load(&path).expect("load").highest_flushed_index,
            14,
            "global index is resume_base + local_next_expected - 1 = 10 + 5 - 1"
        );
    }

    #[test]
    fn record_index_offsets_local_count_by_resume_base() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let writer = test_writer(&path, 1).with_resume_base(7);
        assert_eq!(
            writer.record_index(1),
            7,
            "the boundary target K re-emits at K"
        );
        assert_eq!(writer.record_index(4), 10);
    }

    fn write_matching_checkpoint(scenario: &DiscoverScenarioConfig, path: &Path, index: usize) {
        Checkpoint {
            checkpoint_version: CHECKPOINT_VERSION,
            scan_id: "01J000000000000000000000AA".to_string(),
            initiated_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            resume_fingerprint: resume_fingerprint(scenario),
            source_config_hash: crate::model::scan::hash_scenario(scenario),
            dns_pins: Vec::new(),
            highest_flushed_index: index,
        }
        .write(path)
        .expect("seed checkpoint");
    }

    #[test]
    fn resume_preflight_missing_checkpoint_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.checkpoint");
        let s = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        match resume_preflight(&s, &path) {
            Err(ResumeError::NoCheckpointToResume { path: p }) => assert_eq!(p, path),
            other => panic!("expected NoCheckpointToResume, got {other:?}"),
        }
    }

    #[test]
    fn resume_preflight_corrupt_checkpoint_yields_typed_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        std::fs::write(&path, b"not a checkpoint").expect("seed garbage");
        let s = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        assert!(matches!(
            resume_preflight(&s, &path),
            Err(ResumeError::CorruptCheckpoint { .. })
        ));
    }

    #[test]
    fn resume_preflight_unknown_version_yields_typed_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let mut cp = sample_checkpoint();
        cp.checkpoint_version = CHECKPOINT_VERSION + 1;
        cp.write(&path).expect("write");
        let s = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        assert!(matches!(
            resume_preflight(&s, &path),
            Err(ResumeError::UnknownVersion { .. })
        ));
    }

    #[test]
    fn resume_preflight_ineligible_scenario_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let s = scenario(Some(identity_over(direct())), Vec::new(), Some(file_sink()));
        write_matching_checkpoint(&s, &path, 3);
        assert!(matches!(
            resume_preflight(&s, &path),
            Err(ResumeError::IdentityFuserNotResumable)
        ));
    }

    #[test]
    fn resume_preflight_fingerprint_mismatch_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let original = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        write_matching_checkpoint(&original, &path, 3);

        let mut changed = original.clone();
        changed.targets = vec![ip(1), ip(2)];
        assert!(matches!(
            resume_preflight(&changed, &path),
            Err(ResumeError::FingerprintMismatch)
        ));
    }

    #[test]
    fn resume_preflight_perf_knob_change_proceeds_with_a_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let original = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        write_matching_checkpoint(&original, &path, 3);

        let mut changed = original.clone();
        changed.base.max_concurrent = Some(999);
        let checkpoint = resume_preflight(&changed, &path)
            .expect("a changed perf knob is advisory only; resume proceeds");
        assert_eq!(checkpoint.highest_flushed_index, 3);
    }

    #[test]
    fn resume_preflight_returns_the_checkpoint_on_a_clean_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scan.checkpoint");
        let s = scenario(Some(*direct()), Vec::new(), Some(file_sink()));
        write_matching_checkpoint(&s, &path, 41);
        let checkpoint = resume_preflight(&s, &path).expect("clean match resumes");
        assert_eq!(checkpoint.highest_flushed_index, 41);
        assert_eq!(checkpoint.scan_id, "01J000000000000000000000AA");
    }
}
