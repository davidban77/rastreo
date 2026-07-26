use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RastreoError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("probe error: {0}")]
    Probe(#[from] ProbeError),

    #[error("resolver error: {0}")]
    Resolver(#[from] ResolverError),

    #[error("encoder error: {0}")]
    Encoder(#[from] EncoderError),

    // No blanket `#[from] std::io::Error` — call sites build the `SinkError` with its class.
    #[error("sink error: {0}")]
    Sink(#[from] crate::sink::SinkError),

    #[error("runtime error: {0}")]
    Runtime(#[from] RuntimeError),

    #[error("classifier error: {0}")]
    Classifier(#[from] ClassifierError),

    #[error("resume error: {0}")]
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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolverError {
    #[error("DNS lookup failed for {name}")]
    DnsLookupFailed {
        name: String,
        #[source]
        source: hickory_resolver::net::NetError,
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
    #[error("invalid regex `{pattern}`: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
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

    #[error("checkpoint could not be written to {}: {source}", .path.display())]
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
    fn config_display_includes_message() {
        let err = RastreoError::Config(ConfigError::invalid("rate must be positive"));
        let msg = format!("{err}");
        assert!(msg.contains("configuration error"));
        assert!(msg.contains("rate must be positive"));
    }

    #[test]
    fn probe_error_display_includes_message() {
        let err = RastreoError::Probe(ProbeError::Other("snmp reply could not be decoded".into()));
        let msg = format!("{err}");
        assert!(msg.contains("probe error"));
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
    fn sink_display_includes_io_message() {
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broke");
        let err = RastreoError::Sink(SinkError::new(SinkErrorClass::FlushFailure, io));
        let msg = format!("{err}");
        assert!(msg.contains("sink error"));
        assert!(msg.contains("pipe broke"));
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
        assert!(msg.contains("resume error"));
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
        assert!(msg.contains("classifier error"));
        assert!(msg.contains("(unclosed"));
    }
}
