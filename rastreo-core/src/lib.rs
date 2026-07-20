pub mod classifier;
pub mod collection_profile;
pub mod config;
pub mod encoder;
pub mod error;
pub mod fuser;
pub mod hints;
pub mod model;
pub mod observability;
pub mod pipeline;
pub mod plan;
pub mod prober;
pub mod resolver;
pub mod scheduler;
pub mod sink;
pub mod topology;

pub use classifier::{
    create_classifier, Classifier, ClassifierConfig, MergeMode, NoopClassifier, PlatformRule,
    PlatformSignal, RoleRule, RulesClassifier,
};
pub use collection_profile::CollectionProfileAssembler;
pub use encoder::{Encoder, EncoderConfig, NdjsonEncoder};
pub use error::{
    ClassifierError, ConfigError, EncoderError, ProbeError, ProbeErrorKind, RastreoError,
    ResolverError, RuntimeError,
};
pub use fuser::{DirectFuser, Fuser, FuserConfig, IdentityFuser, IdentityHints, VrrpGroup};
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
    resolve_scenario_targets, run_discovery, run_discovery_cancellable,
    run_discovery_cancellable_with_progress, run_discovery_with_components,
    run_discovery_with_components_cancellable, run_discovery_with_components_with_progress,
    DiscoveryProgress, DiscoverySummary, ProbeKindSummary, ResolvedScenarioTarget,
};
pub use plan::{DiscoveryPlan, PlanKnobs, PlannedTarget, TargetResolution};
#[cfg(feature = "icmp")]
pub use prober::IcmpProber;
#[cfg(feature = "ssh")]
pub use prober::SshProber;
#[cfg(feature = "tls")]
pub use prober::TlsProber;
pub use prober::{Prober, ProberConfig, ReverseDnsProber, TcpConnectProber};
pub use resolver::{GuardedResolver, HickoryResolver, Resolver};
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
