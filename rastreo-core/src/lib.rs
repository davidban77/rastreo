pub mod classifier;
pub mod config;
pub mod encoder;
pub mod error;
pub mod fuser;
pub mod model;
pub mod observability;
pub mod pipeline;
pub mod prober;
pub mod resolver;
pub mod scheduler;
pub mod sink;

pub use classifier::{
    create_classifier, Classifier, ClassifierConfig, MergeMode, NoopClassifier, PlatformRule,
    PlatformSignal, RoleRule, RulesClassifier,
};
pub use encoder::{Encoder, EncoderConfig, NdjsonEncoder};
pub use error::{
    ClassifierError, ConfigError, EncoderError, ProbeError, ProbeErrorKind, RastreoError,
    ResolverError, RuntimeError,
};
pub use fuser::{DirectFuser, Fuser, FuserConfig, IdentityFuser, IdentityHints, VrrpGroup};
pub use model::{
    AltIp, AltIpRole, Confidence, DeviceRecord, IdentityKey, ProbeCtx, ProbeFault, ProbeKind,
    ProbeOutcome, ResolvedTarget, ScanMetadata, Signal, Target, CURRENT_SCHEMA_ID,
    CURRENT_SCHEMA_VERSION, PROBE_KIND_COUNT,
};
pub use pipeline::{
    resolve_scenario_targets, run_discovery, run_discovery_cancellable,
    run_discovery_with_components, run_discovery_with_components_cancellable, DiscoverySummary,
    ProbeKindSummary, ResolvedScenarioTarget,
};
#[cfg(feature = "icmp")]
pub use prober::IcmpProber;
#[cfg(feature = "ssh")]
pub use prober::SshProber;
#[cfg(feature = "tls")]
pub use prober::TlsProber;
pub use prober::{Prober, ProberConfig, ReverseDnsProber, TcpConnectProber};
pub use resolver::{HickoryResolver, Resolver};
pub use scheduler::{BoundedScheduler, Scheduler};
pub use sink::{
    classify_sink_error, FileSink, MemorySink, MemorySinkHandle, Sink, SinkConfig, SinkErrorClass,
    SinkType, StdoutSink, TeeChild, TeeSink, SINK_ERROR_CLASS_COUNT,
};
#[cfg(feature = "kafka")]
pub use sink::{KafkaFlushMode, KafkaSink};
#[cfg(feature = "nats")]
pub use sink::{NatsCredentials, NatsDelivery, NatsSink};

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
