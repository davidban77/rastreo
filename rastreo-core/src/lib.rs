pub mod config;
pub mod encoder;
pub mod error;
pub mod fuser;
pub mod model;
pub mod pipeline;
pub mod prober;
pub mod resolver;
pub mod scheduler;
pub mod sink;

pub use encoder::{Encoder, EncoderConfig, NdjsonEncoder};
pub use error::{ConfigError, EncoderError, ProbeError, RastreoError, ResolverError, RuntimeError};
pub use fuser::{DirectFuser, Fuser, FuserConfig};
pub use model::{
    Confidence, DeviceRecord, IdentityKey, ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget,
    Signal, Target,
};
pub use pipeline::{run_discovery, run_discovery_with_components, DiscoverySummary};
pub use prober::{Prober, ProberConfig, TcpConnectProber};
pub use resolver::{HickoryResolver, Resolver};
pub use scheduler::{BoundedScheduler, Scheduler};
pub use sink::{FileSink, MemorySink, MemorySinkHandle, Sink, SinkConfig, StdoutSink};
#[cfg(feature = "kafka")]
pub use sink::{KafkaFlushMode, KafkaSink};

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
