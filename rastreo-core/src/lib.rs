pub mod checkpoint;
pub mod classifier;
pub mod collection_profile;
pub mod config;
pub mod encoder;
pub mod error;
pub mod fuser;
pub mod hints;
pub mod model;
pub mod observability;
pub(crate) mod oid;
pub mod pipeline;
pub mod plan;
pub mod prober;
#[cfg(feature = "nats")]
pub(crate) mod redact;
pub mod resolver;
pub mod scheduler;
pub mod sink;
pub mod topology;

pub use checkpoint::{
    fuser_supports_resume, preflight_checkpoint_request, probers_support_resume,
    resume_eligibility, resume_fingerprint, Checkpoint, CheckpointConfig, CheckpointWriter,
    CHECKPOINT_VERSION,
};
pub use classifier::{
    create_classifier, Classifier, ClassifierConfig, ClassifierKind, ClassifierSelectionOptions,
    MergeMode, NoopClassifier, PlatformRule, RoleRule, RulesClassifier, SignalKind,
    CLASSIFIER_KIND_COUNT, SIGNAL_KIND_COUNT,
};
pub use collection_profile::CollectionProfileAssembler;
pub use encoder::{
    ensure_encoder_output_fits_sink, Encoder, EncoderConfig, NdjsonEncoder, TableEncoder,
};
pub use error::{
    ClassifierError, ConfigError, DnsFailure, EncoderError, ProbeError, ProbeErrorKind,
    RastreoError, ResolverError, ResumeError, RuntimeError,
};
pub use fuser::{
    DirectFuser, Fuser, FuserConfig, FuserKind, FuserSelectionOptions, IdentityFuser,
    IdentityHints, VrrpGroup, FUSER_KIND_COUNT,
};
pub use hints::hint_for_error_kind;
pub use model::{
    AltIp, AltIpRole, Collection, CollectionProfileRecord, Confidence, DeviceRecord, GnmiEndpoint,
    IdentityKey, LinkEndpoint, LinkRecord, LldpNeighbor, LldpObservation, ProbeCtx, ProbeFault,
    ProbeKind, ProbeOutcome, ProfileConfidence, ProfileEndpoint, ResolvedTarget, ScanMetadata,
    Signal, Subscription, Target, Transport, COLLECTION_PROFILE_CURRENT_SCHEMA_VERSION,
    COLLECTION_PROFILE_SCHEMA_ID, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
    LINK_CURRENT_SCHEMA_VERSION, LINK_SCHEMA_ID, PROBE_KIND_COUNT,
};
pub use pipeline::{
    resolve_scenario_targets, run_discovery, DiscoveryProgress, DiscoverySummary, ProbeKindSummary,
    ResolvedScenarioTarget, RunOptions,
};
pub use plan::{DiscoveryPlan, PlanKnobs, PlannedTarget, TargetResolution};
#[cfg(feature = "icmp")]
pub use prober::IcmpProber;
#[cfg(feature = "ssh")]
pub use prober::SshProber;
#[cfg(feature = "tls")]
pub use prober::TlsProber;
pub use prober::{
    ProbeSelection, ProbeSelectionOptions, Prober, ProberConfig, ReverseDnsProber, TcpConnectProber,
};
pub use resolver::{GuardedResolver, HickoryResolver, ResolvedPlan, Resolver};
pub use scheduler::{BoundedScheduler, Scheduler, TargetScan};
pub use sink::{
    FileSink, MemorySink, MemorySinkHandle, RecordKind, Sink, SinkConfig, SinkError,
    SinkErrorClass, SinkRetry, SinkType, StdoutSink, TeeChild, TeeSink, SINK_ERROR_CLASS_COUNT,
};
#[cfg(feature = "kafka")]
pub use sink::{KafkaFlushMode, KafkaSink};
#[cfg(feature = "nats")]
pub use sink::{NatsCredentials, NatsFlushMode, NatsSink};
pub use topology::TopologyAssembler;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_pkg_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
