#[cfg(feature = "http")]
pub mod http;
pub mod tcp_connect;

#[cfg(feature = "http")]
pub use http::{HttpProber, HttpScheme};
pub use tcp_connect::TcpConnectProber;

use crate::error::RastreoError;
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget};

#[async_trait::async_trait]
pub trait Prober: Send + Sync {
    fn kind(&self) -> ProbeKind;

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError>;
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProberConfig {
    TcpConnect {
        ports: Vec<u16>,
    },
    #[cfg(feature = "http")]
    Http {
        ports: Vec<u16>,
        #[serde(default)]
        scheme: HttpScheme,
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        tls_verify: Option<bool>,
        #[serde(default)]
        user_agent: Option<String>,
    },
}

pub fn create_prober(config: &ProberConfig) -> Result<Box<dyn Prober>, RastreoError> {
    match config {
        ProberConfig::TcpConnect { ports } => Ok(Box::new(TcpConnectProber::new(ports.clone())?)),
        #[cfg(feature = "http")]
        ProberConfig::Http {
            ports,
            scheme,
            path,
            tls_verify,
            user_agent,
        } => Ok(Box::new(HttpProber::new(
            ports.clone(),
            *scheme,
            path.clone(),
            *tls_verify,
            user_agent.clone(),
        )?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use crate::model::{Signal, Target};

    struct MockProber;

    #[async_trait::async_trait]
    impl Prober for MockProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            Ok(ProbeOutcome {
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::OpenPort(22)],
            })
        }
    }

    #[test]
    fn mock_prober_is_usable_as_trait_object() {
        let p: Box<dyn Prober> = Box::new(MockProber);
        assert_eq!(p.kind(), ProbeKind::TcpConnect);
        let _ = ResolvedTarget {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            original: Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
    }

    #[test]
    fn prober_trait_object_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Prober>();
    }

    #[cfg(all(feature = "config", feature = "http"))]
    #[test]
    fn prober_config_deserializes_http_variant_from_yaml() {
        let yaml = "type: http\nports: [80, 443]\nscheme: auto\ntls_verify: false\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize http");
        match config {
            ProberConfig::Http {
                ports,
                scheme,
                path,
                tls_verify,
                user_agent,
            } => {
                assert_eq!(ports, vec![80, 443]);
                assert!(matches!(scheme, HttpScheme::Auto));
                assert!(path.is_none());
                assert_eq!(tls_verify, Some(false));
                assert!(user_agent.is_none());
            }
            other => panic!("expected Http variant, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "http"))]
    #[test]
    fn prober_config_deserializes_http_variant_with_defaults_only() {
        let yaml = "type: http\nports: [80]\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize http");
        match config {
            ProberConfig::Http {
                ports,
                scheme,
                path,
                tls_verify,
                user_agent,
            } => {
                assert_eq!(ports, vec![80]);
                assert!(matches!(scheme, HttpScheme::Auto));
                assert!(path.is_none());
                assert!(tls_verify.is_none());
                assert!(user_agent.is_none());
            }
            other => panic!("expected Http variant, got {other:?}"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn prober_config_http_empty_ports_errors_on_factory() {
        let config = ProberConfig::Http {
            ports: Vec::new(),
            scheme: HttpScheme::Auto,
            path: None,
            tls_verify: None,
            user_agent: None,
        };
        match create_prober(&config) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(_))) => {}
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty ports must error"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn prober_config_http_bad_path_errors_on_factory() {
        let config = ProberConfig::Http {
            ports: vec![80],
            scheme: HttpScheme::Auto,
            path: Some("no-leading-slash".into()),
            tls_verify: None,
            user_agent: None,
        };
        match create_prober(&config) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("path"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("bad path must error"),
        }
    }
}
