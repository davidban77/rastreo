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

    // No blanket `#[from] std::io::Error` — call sites must classify I/O failures explicitly.
    #[error("sink error: {0}")]
    Sink(std::io::Error),

    #[error("runtime error: {0}")]
    Runtime(#[from] RuntimeError),
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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    #[error("probe target unreachable: {target}")]
    Unreachable { target: String },
    #[error("probe timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_does_not_auto_convert_to_rastreo_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err = RastreoError::Sink(io_err);
        assert!(matches!(err, RastreoError::Sink(_)));
    }

    #[test]
    fn config_error_converts_via_from() {
        let cfg = ConfigError::invalid("bad value");
        let err: RastreoError = cfg.into();
        assert!(matches!(err, RastreoError::Config(_)));
    }

    #[test]
    fn probe_error_converts_via_from() {
        let p = ProbeError::Timeout { timeout_ms: 1500 };
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
    fn probe_unreachable_display_includes_target() {
        let err = RastreoError::Probe(ProbeError::Unreachable {
            target: "10.0.0.1".into(),
        });
        let msg = format!("{err}");
        assert!(msg.contains("probe error"));
        assert!(msg.contains("10.0.0.1"));
    }

    #[test]
    fn probe_timeout_display_includes_duration() {
        let err = RastreoError::Probe(ProbeError::Timeout { timeout_ms: 750 });
        let msg = format!("{err}");
        assert!(msg.contains("750"));
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
        let err = RastreoError::Sink(io);
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
        assert_send_sync::<ResolverError>();
        assert_send_sync::<EncoderError>();
        assert_send_sync::<RuntimeError>();
    }
}
