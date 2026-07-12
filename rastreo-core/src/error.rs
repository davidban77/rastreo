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
