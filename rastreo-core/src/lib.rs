pub mod config;
pub mod encoder;
pub mod error;
pub mod model;
pub mod prober;
pub mod resolver;
pub mod scheduler;
pub mod sink;

pub use error::{ConfigError, EncoderError, ProbeError, RastreoError, ResolverError, RuntimeError};
pub use model::{
    Confidence, DeviceRecord, IdentityKey, ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget,
    Signal, Target,
};
pub use resolver::{HickoryResolver, Resolver};
pub use scheduler::{BoundedScheduler, Scheduler};

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
