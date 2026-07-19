pub mod device;
pub mod link;
pub mod outcome;
pub mod scan;
pub(crate) mod serde_iso8601;
pub mod target;

pub use device::{
    AltIp, AltIpRole, Confidence, DeviceRecord, IdentityKey, CURRENT_SCHEMA_ID,
    CURRENT_SCHEMA_VERSION,
};
pub use link::{LinkEndpoint, LinkRecord, LINK_CURRENT_SCHEMA_VERSION, LINK_SCHEMA_ID};
pub use outcome::{
    LldpNeighbor, LldpObservation, ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, Signal,
    PROBE_KIND_COUNT,
};
pub use scan::ScanMetadata;
pub use target::{ResolvedTarget, Target};
