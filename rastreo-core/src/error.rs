use std::net::IpAddr;
use std::path::PathBuf;

use hickory_resolver::net::NetError;

// Every variant is transparent: a prefix here would restate the inner message that the
// error chain already carries, printing it twice.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RastreoError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Probe(#[from] ProbeError),

    #[error(transparent)]
    Resolver(#[from] ResolverError),

    #[error(transparent)]
    Encoder(#[from] EncoderError),

    // No blanket `#[from] std::io::Error` — call sites build the `SinkError` with its class.
    #[error(transparent)]
    Sink(#[from] crate::sink::SinkError),

    #[error(transparent)]
    Runtime(#[from] RuntimeError),

    #[error(transparent)]
    Classifier(#[from] ClassifierError),

    #[error(transparent)]
    Resume(#[from] ResumeError),
}

impl RastreoError {
    /// The carried [`crate::sink::SinkErrorClass`] when this is a sink failure; `None` otherwise.
    pub fn sink_error_class(&self) -> Option<crate::sink::SinkErrorClass> {
        match self {
            RastreoError::Sink(e) => Some(e.class),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("{0}")]
    InvalidValue(String),

    #[error("unknown probe kind '{name}'; available in this build: {available}")]
    UnknownProbeKind { name: String, available: String },

    #[error(
        "probe kind '{kind}' requires the '{feature}' Cargo feature, which this binary was not built with"
    )]
    ProbeKindNotCompiled {
        kind: &'static str,
        feature: &'static str,
    },

    #[error("probe kind '{kind}' requires {param}")]
    ProbeKindMissingParam {
        kind: &'static str,
        param: &'static str,
    },

    #[error("no probe kinds selected")]
    EmptyProbeSelection,

    #[error("unknown fuser '{name}'; available in this build: {available}")]
    UnknownFuserKind { name: String, available: String },

    #[error(
        "fuser '{kind}' requires the '{feature}' Cargo feature, which this binary was not built with"
    )]
    FuserKindNotCompiled {
        kind: &'static str,
        feature: &'static str,
    },

    #[error("unknown classifier '{name}'; available: {available}")]
    UnknownClassifierKind { name: String, available: String },
}

impl ConfigError {
    pub(crate) fn invalid(msg: impl Into<String>) -> Self {
        ConfigError::InvalidValue(msg.into())
    }
}

/// The named reason a probe faulted, carried as data on the outcome's [`crate::ProbeFault`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProbeErrorKind {
    AuthFailed,
    PermissionDenied,
    DnsFailed,
    DecodeFailed,
    Other,
}

impl ProbeErrorKind {
    /// snake_case label matching the serde wire form, for rendering fault tallies.
    pub const fn as_label(self) -> &'static str {
        match self {
            ProbeErrorKind::AuthFailed => "auth_failed",
            ProbeErrorKind::PermissionDenied => "permission_denied",
            ProbeErrorKind::DnsFailed => "dns_failed",
            ProbeErrorKind::DecodeFailed => "decode_failed",
            ProbeErrorKind::Other => "other",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    #[error("{0}")]
    Other(String),
}

/// A `hickory` lookup failure, presented at the first level that does not restate the one below.
#[derive(Debug)]
pub struct DnsFailure(NetError);

impl DnsFailure {
    pub fn net_error(&self) -> &NetError {
        &self.0
    }
}

fn first_non_restating_level<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> &'a (dyn std::error::Error + 'static) {
    let mut level = err;
    while let Some(below) = level.source() {
        if !level.to_string().contains(&below.to_string()) {
            break;
        }
        level = below;
    }
    level
}

impl From<NetError> for DnsFailure {
    fn from(err: NetError) -> Self {
        Self(err)
    }
}

impl std::fmt::Display for DnsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(first_non_restating_level(&self.0), f)
    }
}

impl std::error::Error for DnsFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        first_non_restating_level(&self.0).source()
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolverError {
    #[error("DNS lookup failed for {name}")]
    DnsLookupFailed {
        name: String,
        #[source]
        source: DnsFailure,
    },
    #[error("DNS lookup returned no records for {name}")]
    DnsNoRecords { name: String },
    #[error("CIDR {cidr} expands to {hosts} hosts; exceeds the configured limit of {limit}")]
    CidrTooLarge {
        cidr: String,
        hosts: u128,
        limit: usize,
    },
    #[error(
        "IP range {start}..={end} spans {hosts} addresses; exceeds the configured limit of {limit}"
    )]
    RangeTooLarge {
        start: String,
        end: String,
        hosts: u128,
        limit: usize,
    },
    #[error("IP range is invalid: start {start} > end {end}")]
    InvalidRange { start: String, end: String },
    #[error("IP range mixes IPv4 and IPv6: start {start} end {end}")]
    MixedFamilyRange { start: String, end: String },
    #[error("target {ip} is outside the configured allow-list")]
    TargetNotAllowed { ip: IpAddr },
    #[error("scan resolves to {hosts} hosts; exceeds the configured aggregate limit of {limit}")]
    AggregateHostCapExceeded { hosts: usize, limit: usize },
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncoderError {
    #[error("serialization failed")]
    SerializationFailed(#[source] serde_json::Error),
    #[error("{0}")]
    NotSupported(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    #[error("task panicked: {0}")]
    TaskPanicked(String),
    #[error("task aborted: {reason}")]
    TaskAborted { reason: &'static str },
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClassifierError {
    /// Fires when a `PlatformRule` carries a `pattern` that fails to compile as a regex.
    #[error("invalid regex `{pattern}`")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error("invalid platform rule: {0}")]
    InvalidPlatformRule(String),
    #[error("invalid role rule: {0}")]
    InvalidRoleRule(String),
}

/// Why a scan cannot be resumed from a checkpoint, or why an on-disk checkpoint was rejected.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResumeError {
    #[error(
        "scenario is not resume-safe: the identity fuser correlates records across the whole scan, which cannot be reconstructed from a partial checkpoint prefix"
    )]
    IdentityFuserNotResumable,

    #[error(
        "scenario is not resume-safe: the {kind} prober feeds a second stream that cannot be replayed from a checkpoint"
    )]
    SecondStreamProberNotResumable { kind: &'static str },

    #[error(
        "scenario is not resume-safe: the {sink} sink has no durable append destination to resume into"
    )]
    SinkNotResumable { sink: String },

    #[error(
        "checkpoint does not match the current scenario: the target sequence or append destination changed, so resuming would produce a different scan or append to the wrong destination"
    )]
    FingerprintMismatch,

    #[error(
        "no checkpoint to resume at {}; --resume requires an existing checkpoint at this path",
        .path.display()
    )]
    NoCheckpointToResume { path: PathBuf },

    #[error(
        "checkpoint at {} is unreadable or corrupt; delete it to restart the scan from zero",
        .path.display()
    )]
    CorruptCheckpoint { path: PathBuf },

    #[error(
        "checkpoint has version {found}, but this build understands version {expected}; delete the checkpoint file to restart the scan from zero"
    )]
    UnknownVersion { found: u32, expected: u32 },

    #[error(
        "a checkpoint already exists at {}; remove it to start a fresh scan",
        .path.display()
    )]
    CheckpointExists { path: PathBuf },

    #[error("checkpoint could not be written to {}", .path.display())]
    Persist {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sink::{SinkError, SinkErrorClass};

    // Mirrors how anyhow's `{:?}` renders a failure: the Display, then the source chain.
    fn rendered_chain(err: &dyn std::error::Error) -> String {
        let mut rendered = err.to_string();
        let mut next = err.source();
        while let Some(source) = next {
            rendered.push_str("\ncaused by: ");
            rendered.push_str(&source.to_string());
            next = source.source();
        }
        rendered
    }

    // One arm per variant, each arm carrying its own sample. The wildcard-free match makes a new
    // variant fail to compile until it is listed, and the grammar gives no way to list a variant
    // without the sample that goes with it.
    macro_rules! one_sample_per_variant {
        // `pat_param` rather than `pat`: it excludes top-level or-patterns at the grammar level,
        // so a row cannot be widened to swallow a new variant.
        ($ty:ty; $($pattern:pat_param => $sample:expr),+ $(,)?) => {{
            let _exhaustive = |value: &$ty| match value { $($pattern => {}),+ };
            let samples: Vec<$ty> = vec![$($sample),+];
            let mut listed = samples.iter();
            $(
                let sample = listed.next().expect("one sample per listed variant");
                assert!(
                    matches!(sample, $pattern),
                    "{sample:?} is not an instance of the variant it is listed under"
                );
                assert_eq!(
                    samples.iter().filter(|s| matches!(s, $pattern)).count(),
                    1,
                    "the pattern listed for {sample:?} also matches another sample; \
                     each row must name exactly one variant"
                );
            )+
            samples
        }};
    }

    fn config_error_samples() -> Vec<ConfigError> {
        one_sample_per_variant!(ConfigError;
            ConfigError::InvalidValue(_) => ConfigError::invalid("rate must be positive"),
            ConfigError::UnknownProbeKind { .. } => ConfigError::UnknownProbeKind {
                name: "snmpp".into(),
                available: "tcp_connect, udp, dns".into(),
            },
            ConfigError::ProbeKindNotCompiled { .. } => ConfigError::ProbeKindNotCompiled {
                kind: "snmp",
                feature: "snmp",
            },
            ConfigError::ProbeKindMissingParam { .. } => ConfigError::ProbeKindMissingParam {
                kind: "udp",
                param: "a udp protocol",
            },
            ConfigError::EmptyProbeSelection => ConfigError::EmptyProbeSelection,
            ConfigError::UnknownFuserKind { .. } => ConfigError::UnknownFuserKind {
                name: "identiy".into(),
                available: "direct, identity".into(),
            },
            ConfigError::FuserKindNotCompiled { .. } => ConfigError::FuserKindNotCompiled {
                kind: "mib_enrichment",
                feature: "mib_enrichment",
            },
            ConfigError::UnknownClassifierKind { .. } => ConfigError::UnknownClassifierKind {
                name: "rule".into(),
                available: "noop, rules".into(),
            },
        )
    }

    fn probe_error_samples() -> Vec<ProbeError> {
        one_sample_per_variant!(ProbeError;
            ProbeError::Other(_) => ProbeError::Other("snmp reply could not be decoded".into()),
        )
    }

    fn no_records(name: &str) -> NetError {
        use hickory_resolver::net::NoRecords;
        use hickory_resolver::proto::op::{Query, ResponseCode};
        use hickory_resolver::proto::rr::{Name, RecordType};

        let query = Query::query(
            Name::from_ascii(name).expect("test name parses"),
            RecordType::AAAA,
        );
        NetError::from(NoRecords::new(query, ResponseCode::NXDomain))
    }

    fn resolver_error_samples() -> Vec<ResolverError> {
        one_sample_per_variant!(ResolverError;
            ResolverError::DnsLookupFailed { .. } => ResolverError::DnsLookupFailed {
                name: "missing.lab".into(),
                source: no_records("missing.lab.").into(),
            },
            ResolverError::DnsNoRecords { .. } => ResolverError::DnsNoRecords {
                name: "missing.lab".into(),
            },
            ResolverError::CidrTooLarge { .. } => ResolverError::CidrTooLarge {
                cidr: "10.0.0.0/8".into(),
                hosts: 16_777_214,
                limit: 65_536,
            },
            ResolverError::RangeTooLarge { .. } => ResolverError::RangeTooLarge {
                start: "10.0.0.0".into(),
                end: "10.255.255.255".into(),
                hosts: 16_777_216,
                limit: 65_536,
            },
            ResolverError::InvalidRange { .. } => ResolverError::InvalidRange {
                start: "10.0.0.10".into(),
                end: "10.0.0.5".into(),
            },
            ResolverError::MixedFamilyRange { .. } => ResolverError::MixedFamilyRange {
                start: "10.0.0.0".into(),
                end: "::1".into(),
            },
            ResolverError::TargetNotAllowed { .. } => ResolverError::TargetNotAllowed {
                ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            },
            ResolverError::AggregateHostCapExceeded { .. } => {
                ResolverError::AggregateHostCapExceeded {
                    hosts: 300_000,
                    limit: 262_144,
                }
            },
        )
    }

    fn json_error() -> serde_json::Error {
        serde_json::from_str::<serde_json::Value>("{{bad}}").expect_err("must fail")
    }

    fn encoder_error_samples() -> Vec<EncoderError> {
        one_sample_per_variant!(EncoderError;
            EncoderError::SerializationFailed(_) => EncoderError::SerializationFailed(json_error()),
            EncoderError::NotSupported(_) => {
                EncoderError::NotSupported("link records need the ndjson encoder".into())
            },
            EncoderError::Other(_) => EncoderError::Other("encoder buffer exhausted".into()),
        )
    }

    fn runtime_error_samples() -> Vec<RuntimeError> {
        one_sample_per_variant!(RuntimeError;
            RuntimeError::TaskPanicked(_) => {
                RuntimeError::TaskPanicked("worker thread panicked".into())
            },
            RuntimeError::TaskAborted { .. } => RuntimeError::TaskAborted {
                reason: "shutdown requested",
            },
        )
    }

    fn classifier_error_samples() -> Vec<ClassifierError> {
        one_sample_per_variant!(ClassifierError;
            ClassifierError::InvalidRegex { .. } => ClassifierError::InvalidRegex {
                pattern: "(unclosed".into(),
                source: bad_regex_error(),
            },
            ClassifierError::InvalidPlatformRule(_) => {
                ClassifierError::InvalidPlatformRule("rule captures os_version but claims no platform".into())
            },
            ClassifierError::InvalidRoleRule(_) => {
                ClassifierError::InvalidRoleRule("role 'spine' matches on no ports".into())
            },
        )
    }

    fn checkpoint_path() -> PathBuf {
        PathBuf::from("/var/lib/rastreo/scan.checkpoint")
    }

    fn denied() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied")
    }

    fn resume_error_samples() -> Vec<ResumeError> {
        one_sample_per_variant!(ResumeError;
            ResumeError::IdentityFuserNotResumable => ResumeError::IdentityFuserNotResumable,
            ResumeError::SecondStreamProberNotResumable { .. } => {
                ResumeError::SecondStreamProberNotResumable { kind: "gnmi" }
            },
            ResumeError::SinkNotResumable { .. } => ResumeError::SinkNotResumable {
                sink: "stdout".into(),
            },
            ResumeError::FingerprintMismatch => ResumeError::FingerprintMismatch,
            ResumeError::NoCheckpointToResume { .. } => ResumeError::NoCheckpointToResume {
                path: checkpoint_path(),
            },
            ResumeError::CorruptCheckpoint { .. } => ResumeError::CorruptCheckpoint {
                path: checkpoint_path(),
            },
            ResumeError::UnknownVersion { .. } => ResumeError::UnknownVersion {
                found: 7,
                expected: 1,
            },
            ResumeError::CheckpointExists { .. } => ResumeError::CheckpointExists {
                path: checkpoint_path(),
            },
            ResumeError::Persist { .. } => ResumeError::Persist {
                path: checkpoint_path(),
                source: denied(),
            },
        )
    }

    fn sink_error(class: SinkErrorClass) -> SinkError {
        SinkError::new(
            class,
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broke"),
        )
    }

    fn sink_error_samples() -> Vec<SinkError> {
        one_sample_per_variant!(SinkError;
            SinkError { class: SinkErrorClass::PublishFailure, .. } => {
                sink_error(SinkErrorClass::PublishFailure)
            },
            SinkError { class: SinkErrorClass::AckRejection, .. } => {
                sink_error(SinkErrorClass::AckRejection)
            },
            SinkError { class: SinkErrorClass::ProduceFailure, .. } => {
                sink_error(SinkErrorClass::ProduceFailure)
            },
            SinkError { class: SinkErrorClass::WriteFailure, .. } => {
                sink_error(SinkErrorClass::WriteFailure)
            },
            SinkError { class: SinkErrorClass::FlushFailure, .. } => {
                sink_error(SinkErrorClass::FlushFailure)
            },
            SinkError { class: SinkErrorClass::Other, .. } => sink_error(SinkErrorClass::Other),
        )
    }

    fn otlp_env_error_samples() -> Vec<crate::observability::otlp_config::OtlpEnvError> {
        use crate::observability::otlp_config::OtlpEnvError;
        one_sample_per_variant!(OtlpEnvError;
            OtlpEnvError::UnknownProtocol { .. } => OtlpEnvError::UnknownProtocol {
                name: "RASTREO_OTLP_PROTOCOL".into(),
                value: "yaml".into(),
            },
            OtlpEnvError::NotBoolean { .. } => OtlpEnvError::NotBoolean {
                name: "RASTREO_OTLP_LOGS_ENABLED".into(),
                value: "maybe".into(),
            },
            OtlpEnvError::NotU64 { .. } => OtlpEnvError::NotU64 {
                name: "RASTREO_MAX_INFLIGHT_SCANS".into(),
                value: "abc".into(),
                source: "abc".parse::<u64>().expect_err("must fail"),
            },
            OtlpEnvError::MalformedHeaders { .. } => OtlpEnvError::MalformedHeaders {
                name: "RASTREO_OTLP_HEADERS".into(),
                position: 1,
            },
            OtlpEnvError::NotUtf8 { .. } => OtlpEnvError::NotUtf8 {
                name: "RASTREO_OTLP_ENDPOINT".into(),
            },
        )
    }

    #[cfg(feature = "snmp")]
    fn crypto_error_samples() -> Vec<crate::prober::snmp::crypto::CryptoError> {
        use crate::prober::snmp::crypto::CryptoError;
        one_sample_per_variant!(CryptoError;
            CryptoError::DesKeyTooShort(_) => CryptoError::DesKeyTooShort(8),
            CryptoError::AesKeyTooShort { .. } => CryptoError::AesKeyTooShort { have: 8, need: 16 },
            CryptoError::IvOutOfRange => CryptoError::IvOutOfRange,
            CryptoError::DesDecrypt => CryptoError::DesDecrypt,
        )
    }

    fn umbrella_samples() -> Vec<RastreoError> {
        one_sample_per_variant!(RastreoError;
            RastreoError::Config(_) => ConfigError::invalid("rate must be positive").into(),
            RastreoError::Probe(_) => {
                ProbeError::Other("snmp reply could not be decoded".into()).into()
            },
            RastreoError::Resolver(_) => ResolverError::DnsNoRecords {
                name: "missing.lab".into(),
            }
            .into(),
            RastreoError::Encoder(_) => EncoderError::SerializationFailed(json_error()).into(),
            RastreoError::Sink(_) => sink_error(SinkErrorClass::WriteFailure).into(),
            RastreoError::Runtime(_) => RuntimeError::TaskAborted {
                reason: "shutdown requested",
            }
            .into(),
            RastreoError::Classifier(_) => ClassifierError::InvalidRegex {
                pattern: "(unclosed".into(),
                source: bad_regex_error(),
            }
            .into(),
            RastreoError::Resume(_) => ResumeError::Persist {
                path: checkpoint_path(),
                source: denied(),
            }
            .into(),
        )
    }

    fn inner_error(err: &RastreoError) -> &(dyn std::error::Error + 'static) {
        match err {
            RastreoError::Config(inner) => inner,
            RastreoError::Probe(inner) => inner,
            RastreoError::Resolver(inner) => inner,
            RastreoError::Encoder(inner) => inner,
            RastreoError::Sink(inner) => inner,
            RastreoError::Runtime(inner) => inner,
            RastreoError::Classifier(inner) => inner,
            RastreoError::Resume(inner) => inner,
        }
    }

    fn boxed<E: std::error::Error + 'static>(err: E) -> Box<dyn std::error::Error> {
        Box::new(err)
    }

    fn every_error_sample() -> Vec<Box<dyn std::error::Error>> {
        let mut out: Vec<Box<dyn std::error::Error>> = Vec::new();
        out.extend(config_error_samples().into_iter().map(boxed));
        out.extend(probe_error_samples().into_iter().map(boxed));
        out.extend(resolver_error_samples().into_iter().map(boxed));
        out.extend(encoder_error_samples().into_iter().map(boxed));
        out.extend(runtime_error_samples().into_iter().map(boxed));
        out.extend(classifier_error_samples().into_iter().map(boxed));
        out.extend(resume_error_samples().into_iter().map(boxed));
        out.extend(sink_error_samples().into_iter().map(boxed));
        out.extend(otlp_env_error_samples().into_iter().map(boxed));
        #[cfg(feature = "snmp")]
        out.extend(crypto_error_samples().into_iter().map(boxed));
        out.extend(umbrella_samples().into_iter().map(boxed));
        out
    }

    #[test]
    fn the_sample_corpus_holds_one_instance_of_every_variant_of_every_error_type() {
        // Each builder asserts its own arm-to-sample pairing as it runs.
        assert!(!every_error_sample().is_empty());
    }

    #[test]
    fn umbrella_renders_exactly_what_the_inner_error_renders() {
        for err in umbrella_samples() {
            assert_eq!(
                rendered_chain(&err),
                rendered_chain(inner_error(&err)),
                "variant: {err:?}"
            );
        }
    }

    #[test]
    fn no_error_in_the_crate_restates_the_message_of_its_source() {
        for err in every_error_sample() {
            let mut level: &dyn std::error::Error = err.as_ref();
            while let Some(source) = level.source() {
                let (above, below) = (level.to_string(), source.to_string());
                assert!(
                    !above.contains(&below),
                    "`{above}` restates its source `{below}`"
                );
                level = source;
            }
        }
    }

    // The corpus above guards the enums it lists. This sweeps every `#[error(...)]` in
    // rastreo-core so a new error type cannot reintroduce the defect without a sample — though
    // only for the `{source}` spelling; a `{0}` over a `#[source]` field needs a corpus sample.
    #[test]
    fn no_error_display_in_the_crate_interpolates_its_source() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let attributes = error_attributes(&src);
        assert!(
            attributes.len() > 30,
            "expected to sweep every `#[error(...)]` under rastreo-core/src, found {}",
            attributes.len()
        );
        for (file, attribute) in attributes {
            assert!(
                !attribute.contains("{source"),
                "{}: `{attribute}` prints the source the error chain already carries",
                file.display()
            );
        }
    }

    fn error_attributes(dir: &std::path::Path) -> Vec<(std::path::PathBuf, String)> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                out.extend(error_attributes(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                let body = std::fs::read_to_string(&path).expect("read source");
                out.extend(
                    attributes_in(&body)
                        .into_iter()
                        .map(|attr| (path.clone(), attr)),
                );
            }
        }
        out
    }

    const OPEN: &str = "#[error(";

    fn attributes_in(body: &str) -> Vec<String> {
        body.match_indices(OPEN)
            .filter(|(start, _)| opens_its_own_line(body, *start))
            .map(|(start, _)| attribute_body(&body[start + OPEN.len()..]))
            .collect()
    }

    // Every real attribute starts its line; a needle mid-line is Rust source quoting one.
    fn opens_its_own_line(body: &str, start: usize) -> bool {
        body[..start]
            .rsplit('\n')
            .next()
            .is_some_and(|prefix| prefix.chars().all(char::is_whitespace))
    }

    // Balances parentheses from just past the opening `(`, treating string literals as opaque so
    // an unbalanced paren inside one cannot cut the attribute short.
    fn attribute_body(rest: &str) -> String {
        let mut depth = 1usize;
        let mut in_string = false;
        let mut escaped = false;
        for (index, ch) in rest.char_indices() {
            if escaped {
                escaped = false;
            } else if in_string && ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = !in_string;
            } else if !in_string {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            return rest[..index].to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
        rest.to_string()
    }

    #[test]
    fn the_attribute_sweep_ignores_a_needle_quoted_in_rust_source() {
        assert!(attributes_in("    const OPEN: &str = \"#[error(\";\n").is_empty());
    }

    #[test]
    fn the_attribute_sweep_keeps_parentheses_inside_the_format_string() {
        assert_eq!(
            attributes_in("    #[error(\"invalid regex (unclosed) here\")]\n"),
            vec!["\"invalid regex (unclosed) here\""]
        );
    }

    #[test]
    fn the_attribute_sweep_survives_an_unbalanced_parenthesis_in_the_format_string() {
        assert_eq!(
            attributes_in("    #[error(\"cannot parse )\")]\n    struct Next;\n"),
            vec!["\"cannot parse )\""]
        );
    }

    #[test]
    fn the_attribute_sweep_reads_a_multi_line_attribute() {
        assert_eq!(
            attributes_in("    #[error(\n        \"scan is too large\"\n    )]\n"),
            vec!["\n        \"scan is too large\"\n    "]
        );
    }

    #[derive(Debug)]
    struct Level(&'static str, Option<Box<Level>>);

    impl std::fmt::Display for Level {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Level {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|inner| inner as _)
        }
    }

    fn level(message: &'static str, below: Level) -> Level {
        Level(message, Some(Box::new(below)))
    }

    fn leaf(message: &'static str) -> Level {
        Level(message, None)
    }

    #[test]
    fn a_source_less_level_is_its_own_first_non_restating_level() {
        let err = leaf("request timed out");
        assert_eq!(
            first_non_restating_level(&err).to_string(),
            "request timed out"
        );
    }

    #[test]
    fn a_level_that_restates_its_source_is_skipped() {
        let err = level("DNS error: no records found", leaf("no records found"));
        assert_eq!(
            first_non_restating_level(&err).to_string(),
            "no records found"
        );
    }

    #[test]
    fn a_level_that_adds_to_its_source_is_kept() {
        let err = level("resolver pool exhausted", leaf("no records found"));
        assert_eq!(
            first_non_restating_level(&err).to_string(),
            "resolver pool exhausted"
        );
    }

    // Pins the rule's weak edge rather than endorsing it: a level that restates its source *and*
    // adds context is dropped, losing the context. No hickory variant does both — every
    // source-bearing one is a bare `"<prefix>: {0}"` wrapper — so this is a recorded boundary,
    // not a live defect. Revisit if one ever appears.
    #[test]
    fn a_level_that_both_restates_and_adds_context_is_dropped_with_its_context() {
        let err = level(
            "connecting to 10.0.0.1: connection refused",
            leaf("connection refused"),
        );
        assert_eq!(
            first_non_restating_level(&err).to_string(),
            "connection refused"
        );
    }

    #[test]
    fn consecutive_restating_levels_are_all_skipped() {
        let err = level(
            "outer: inner: leaf detail",
            level("inner: leaf detail", leaf("leaf detail")),
        );
        assert_eq!(first_non_restating_level(&err).to_string(), "leaf detail");
    }

    #[test]
    fn dns_lookup_failed_states_the_hickory_cause_once() {
        let err = RastreoError::Resolver(ResolverError::DnsLookupFailed {
            name: "does-not-exist.invalid".into(),
            source: no_records("does-not-exist.invalid.").into(),
        });
        let chain = rendered_chain(&err);
        assert_eq!(chain.matches("no records found").count(), 1, "{chain}");
        assert!(!chain.contains("DNS error:"), "{chain}");
    }

    #[test]
    fn dns_lookup_failed_keeps_a_hickory_level_that_carries_no_source() {
        let err = ResolverError::DnsLookupFailed {
            name: "missing.lab".into(),
            source: NetError::Timeout.into(),
        };
        let chain = rendered_chain(&err);
        assert!(chain.contains("request timed out"), "{chain}");
    }

    #[test]
    fn dns_lookup_failed_keeps_the_io_detail_hickory_hides_behind_its_own_display() {
        let io = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "resolver socket refused",
        );
        let err = ResolverError::DnsLookupFailed {
            name: "missing.lab".into(),
            source: NetError::from(io).into(),
        };
        let chain = rendered_chain(&err);
        assert!(chain.contains("resolver socket refused"), "{chain}");
    }

    #[test]
    fn dns_failure_keeps_the_typed_net_error_reachable() {
        let failure = DnsFailure::from(no_records("missing.lab."));
        assert!(failure.net_error().is_no_records_found());
    }

    #[test]
    fn umbrella_chain_states_the_config_message_once() {
        let err = RastreoError::Config(ConfigError::invalid("rate must be positive"));
        let chain = rendered_chain(&err);
        assert_eq!(chain.matches("rate must be positive").count(), 1, "{chain}");
    }

    #[test]
    fn umbrella_chain_states_the_resolver_message_once() {
        let err = RastreoError::Resolver(ResolverError::TargetNotAllowed {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
        });
        let chain = rendered_chain(&err);
        assert_eq!(chain.matches("192.168.1.1").count(), 1, "{chain}");
    }

    #[test]
    fn umbrella_chain_states_the_resume_message_once() {
        let err = RastreoError::Resume(ResumeError::UnknownVersion {
            found: 7,
            expected: 1,
        });
        let chain = rendered_chain(&err);
        assert_eq!(
            chain.matches("checkpoint has version 7").count(),
            1,
            "{chain}"
        );
    }

    #[test]
    fn umbrella_preserves_the_inner_errors_own_source() {
        let json_err = serde_json::from_str::<serde_json::Value>("{{bad}}").expect_err("must fail");
        let expected = json_err.to_string();
        let err = RastreoError::Encoder(EncoderError::SerializationFailed(json_err));
        let source = std::error::Error::source(&err).expect("serde source stays reachable");
        assert_eq!(source.to_string(), expected);
        assert!(source.downcast_ref::<serde_json::Error>().is_some());
    }

    #[test]
    fn sink_error_carries_the_class_through_the_umbrella() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err = RastreoError::Sink(SinkError::new(SinkErrorClass::WriteFailure, io_err));
        assert_eq!(err.sink_error_class(), Some(SinkErrorClass::WriteFailure));
    }

    #[test]
    fn sink_error_converts_via_from() {
        let sink = SinkError::new(
            SinkErrorClass::ProduceFailure,
            std::io::Error::other("boom"),
        );
        let err: RastreoError = sink.into();
        assert_eq!(err.sink_error_class(), Some(SinkErrorClass::ProduceFailure));
    }

    #[test]
    fn sink_error_class_is_none_for_non_sink_variants() {
        let err = RastreoError::Config(ConfigError::invalid("bad"));
        assert!(err.sink_error_class().is_none());
    }

    #[test]
    fn config_error_converts_via_from() {
        let cfg = ConfigError::invalid("bad value");
        let err: RastreoError = cfg.into();
        assert!(matches!(err, RastreoError::Config(_)));
    }

    #[test]
    fn probe_error_converts_via_from() {
        let p = ProbeError::Other("icmp: recv failed".into());
        let err: RastreoError = p.into();
        assert!(matches!(err, RastreoError::Probe(_)));
    }

    #[test]
    fn encoder_error_converts_via_from() {
        let e = EncoderError::NotSupported("not for this type".into());
        let err: RastreoError = e.into();
        assert!(matches!(err, RastreoError::Encoder(_)));
    }

    #[test]
    fn runtime_error_converts_via_from() {
        let r = RuntimeError::TaskPanicked("worker".into());
        let err: RastreoError = r.into();
        assert!(matches!(err, RastreoError::Runtime(_)));
    }

    #[test]
    fn resolver_error_converts_via_from() {
        let r = ResolverError::DnsNoRecords {
            name: "missing.lab".into(),
        };
        let err: RastreoError = r.into();
        assert!(matches!(err, RastreoError::Resolver(_)));
    }

    #[test]
    fn resolver_cidr_too_large_display_includes_fields() {
        let err = RastreoError::Resolver(ResolverError::CidrTooLarge {
            cidr: "10.0.0.0/8".into(),
            hosts: 16_777_214,
            limit: 65_536,
        });
        let msg = format!("{err}");
        assert!(msg.contains("10.0.0.0/8"));
        assert!(msg.contains("16777214"));
        assert!(msg.contains("65536"));
    }

    #[test]
    fn resolver_target_not_allowed_display_names_the_ip() {
        use std::net::Ipv4Addr;
        let err = RastreoError::Resolver(ResolverError::TargetNotAllowed {
            ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        });
        let msg = format!("{err}");
        assert!(msg.contains("192.168.1.1"));
        assert!(msg.contains("allow-list"));
    }

    #[test]
    fn resolver_aggregate_host_cap_exceeded_display_includes_counts() {
        let err = RastreoError::Resolver(ResolverError::AggregateHostCapExceeded {
            hosts: 300,
            limit: 100,
        });
        let msg = format!("{err}");
        assert!(msg.contains("300"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn config_display_is_the_inner_message() {
        let err = RastreoError::Config(ConfigError::invalid("rate must be positive"));
        assert_eq!(format!("{err}"), "rate must be positive");
    }

    #[test]
    fn probe_error_display_includes_message() {
        let err = RastreoError::Probe(ProbeError::Other("snmp reply could not be decoded".into()));
        let msg = format!("{err}");
        assert!(msg.contains("could not be decoded"));
    }

    #[test]
    fn probe_error_kind_serializes_snake_case() {
        let json = serde_json::to_string(&ProbeErrorKind::DecodeFailed).expect("serialize");
        assert_eq!(json, "\"decode_failed\"");
        let back: ProbeErrorKind = serde_json::from_str("\"permission_denied\"").expect("parse");
        assert_eq!(back, ProbeErrorKind::PermissionDenied);
    }

    #[test]
    fn unknown_probe_kind_display_names_the_input_and_the_alternatives() {
        let err = RastreoError::Config(ConfigError::UnknownProbeKind {
            name: "snmpp".into(),
            available: "tcp_connect, udp, dns".into(),
        });
        let msg = format!("{err}");
        assert!(msg.contains("snmpp"), "msg: {msg}");
        assert!(msg.contains("tcp_connect, udp, dns"), "msg: {msg}");
    }

    #[test]
    fn probe_kind_not_compiled_display_names_the_cargo_feature() {
        let err = ConfigError::ProbeKindNotCompiled {
            kind: "snmp",
            feature: "snmp",
        };
        let msg = format!("{err}");
        assert!(msg.contains("Cargo feature"), "msg: {msg}");
        assert!(msg.contains("'snmp'"), "msg: {msg}");
    }

    #[test]
    fn probe_kind_missing_param_display_names_the_kind_and_the_parameter() {
        let err = ConfigError::ProbeKindMissingParam {
            kind: "udp",
            param: "a udp protocol",
        };
        let msg = format!("{err}");
        assert!(msg.contains("'udp'"), "msg: {msg}");
        assert!(msg.contains("a udp protocol"), "msg: {msg}");
    }

    #[test]
    fn empty_probe_selection_display_is_stable() {
        assert_eq!(
            format!("{}", ConfigError::EmptyProbeSelection),
            "no probe kinds selected"
        );
    }

    #[test]
    fn probe_error_kind_as_label_matches_the_serde_wire_form() {
        for kind in [
            ProbeErrorKind::AuthFailed,
            ProbeErrorKind::PermissionDenied,
            ProbeErrorKind::DnsFailed,
            ProbeErrorKind::DecodeFailed,
            ProbeErrorKind::Other,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(json, format!("\"{}\"", kind.as_label()));
        }
    }

    #[test]
    fn probe_error_kind_labels_are_unique() {
        use std::collections::BTreeSet;
        let kinds = [
            ProbeErrorKind::AuthFailed,
            ProbeErrorKind::PermissionDenied,
            ProbeErrorKind::DnsFailed,
            ProbeErrorKind::DecodeFailed,
            ProbeErrorKind::Other,
        ];
        let labels: BTreeSet<&str> = kinds.iter().map(|k| k.as_label()).collect();
        assert_eq!(labels.len(), kinds.len());
    }

    #[test]
    fn probe_error_kind_orders_deterministically_for_btreemap_keys() {
        use std::collections::BTreeMap;
        let mut counts: BTreeMap<ProbeErrorKind, usize> = BTreeMap::new();
        counts.insert(ProbeErrorKind::Other, 1);
        counts.insert(ProbeErrorKind::AuthFailed, 1);
        let first = counts.keys().next().copied().expect("non-empty");
        assert_eq!(
            first,
            ProbeErrorKind::AuthFailed,
            "AuthFailed precedes Other in declaration order"
        );
    }

    #[test]
    fn encoder_serialization_preserves_serde_json_source() {
        use std::error::Error;

        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{{invalid}}").expect_err("must fail");
        let enc = EncoderError::SerializationFailed(json_err);
        let source = enc.source().expect("source present");
        assert!(source.downcast_ref::<serde_json::Error>().is_some());
    }

    #[test]
    fn sink_display_names_the_sink_and_leaves_the_io_detail_to_the_source() {
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broke");
        let err = RastreoError::Sink(SinkError::new(SinkErrorClass::FlushFailure, io));
        assert_eq!(format!("{err}"), "output sink failed");
        let source = std::error::Error::source(&err).expect("io detail stays reachable");
        assert_eq!(source.to_string(), "pipe broke");
    }

    #[test]
    fn classifier_invalid_regex_leaves_the_regex_detail_to_the_source() {
        let err = RastreoError::Classifier(ClassifierError::InvalidRegex {
            pattern: "(unclosed".into(),
            source: bad_regex_error(),
        });
        let source = std::error::Error::source(&err).expect("regex detail stays reachable");
        assert!(source.downcast_ref::<regex::Error>().is_some());
    }

    #[test]
    fn resume_persist_leaves_the_io_detail_to_the_source() {
        let err = RastreoError::Resume(ResumeError::Persist {
            path: PathBuf::from("/var/lib/rastreo/scan.checkpoint"),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        });
        assert!(format!("{err}").contains("/var/lib/rastreo/scan.checkpoint"));
        let source = std::error::Error::source(&err).expect("io detail stays reachable");
        assert_eq!(source.to_string(), "denied");
    }

    #[test]
    fn runtime_task_aborted_display_includes_reason() {
        let err = RastreoError::Runtime(RuntimeError::TaskAborted {
            reason: "shutdown requested",
        });
        let msg = format!("{err}");
        assert!(msg.contains("task aborted"));
        assert!(msg.contains("shutdown requested"));
    }

    #[test]
    fn error_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RastreoError>();
        assert_send_sync::<ConfigError>();
        assert_send_sync::<ProbeError>();
        assert_send_sync::<ProbeErrorKind>();
        assert_send_sync::<ResolverError>();
        assert_send_sync::<EncoderError>();
        assert_send_sync::<RuntimeError>();
        assert_send_sync::<ClassifierError>();
        assert_send_sync::<SinkError>();
        assert_send_sync::<ResumeError>();
    }

    #[test]
    fn resume_error_converts_via_from() {
        let r = ResumeError::IdentityFuserNotResumable;
        let err: RastreoError = r.into();
        assert!(matches!(err, RastreoError::Resume(_)));
    }

    #[test]
    fn resume_error_display_flows_through_umbrella() {
        let err =
            RastreoError::Resume(ResumeError::SecondStreamProberNotResumable { kind: "gnmi" });
        let msg = format!("{err}");
        assert!(msg.contains("gnmi"));
    }

    #[test]
    fn resume_unknown_version_display_names_both_versions() {
        let err = ResumeError::UnknownVersion {
            found: 7,
            expected: 1,
        };
        let msg = format!("{err}");
        assert!(msg.contains('7') && msg.contains('1'), "msg was: {msg}");
    }

    #[test]
    fn resume_corrupt_checkpoint_display_names_the_path() {
        let err = ResumeError::CorruptCheckpoint {
            path: PathBuf::from("/var/lib/rastreo/scan.checkpoint"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("/var/lib/rastreo/scan.checkpoint"),
            "msg: {msg}"
        );
        assert!(msg.contains("restart"), "msg: {msg}");
    }

    fn bad_regex_error() -> regex::Error {
        let bad = String::from("(unclosed");
        regex::Regex::new(&bad).expect_err("bad regex fails")
    }

    #[test]
    fn classifier_error_converts_via_from() {
        let c = ClassifierError::InvalidRegex {
            pattern: "(unclosed".into(),
            source: bad_regex_error(),
        };
        let err: RastreoError = c.into();
        assert!(matches!(err, RastreoError::Classifier(_)));
    }

    #[test]
    fn classifier_invalid_regex_display_includes_pattern() {
        let err = RastreoError::Classifier(ClassifierError::InvalidRegex {
            pattern: "(unclosed".into(),
            source: bad_regex_error(),
        });
        let msg = format!("{err}");
        assert!(msg.contains("(unclosed"));
    }
}
