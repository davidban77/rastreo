pub mod dns;
#[cfg(feature = "http")]
pub mod http;
pub mod tcp_connect;

pub use dns::{DnsProber, DnsQueryType, DnsTransport};
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
        #[serde(default = "http::default_path")]
        path: String,
        #[serde(default = "http::default_tls_verify")]
        tls_verify: bool,
        #[serde(default = "http::default_user_agent")]
        user_agent: String,
    },
    Dns {
        #[serde(default = "dns::default_ports")]
        ports: Vec<u16>,
        query_names: Vec<String>,
        #[serde(default)]
        query_type: DnsQueryType,
        #[serde(default)]
        transport: DnsTransport,
        #[serde(default = "dns::default_recursion_desired")]
        recursion_desired: bool,
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
        ProberConfig::Dns {
            ports,
            query_names,
            query_type,
            transport,
            recursion_desired,
        } => Ok(Box::new(DnsProber::new(
            ports.clone(),
            query_names.clone(),
            *query_type,
            *transport,
            *recursion_desired,
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
        let yaml = "type: http\nports: [80, 443]\nscheme: auto\ntls_verify: true\npath: /health\nuser_agent: probe/1.0\n";
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
                assert_eq!(path, "/health");
                assert!(tls_verify);
                assert_eq!(user_agent, "probe/1.0");
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
                assert_eq!(path, "/");
                assert!(!tls_verify);
                assert_eq!(user_agent, format!("rastreo/{}", env!("CARGO_PKG_VERSION")));
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
            path: crate::prober::http::default_path(),
            tls_verify: crate::prober::http::default_tls_verify(),
            user_agent: crate::prober::http::default_user_agent(),
        };
        match create_prober(&config) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(_))) => {}
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty ports must error"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn prober_config_deserializes_dns_variant_with_defaults() {
        let yaml = "type: dns\nquery_names: [example.com.]\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize dns");
        match config {
            ProberConfig::Dns {
                ports,
                query_names,
                query_type,
                transport,
                recursion_desired,
            } => {
                assert_eq!(ports, vec![53]);
                assert_eq!(query_names, vec!["example.com.".to_string()]);
                assert_eq!(query_type, DnsQueryType::A);
                assert_eq!(transport, DnsTransport::Udp);
                assert!(recursion_desired);
            }
            other => panic!("expected Dns variant, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn prober_config_deserializes_dns_variant_fully_populated() {
        let yaml = "type: dns\nports: [53, 5353]\nquery_names: [a.example.com., b.example.com.]\nquery_type: mx\ntransport: tcp\nrecursion_desired: false\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize dns");
        match config {
            ProberConfig::Dns {
                ports,
                query_names,
                query_type,
                transport,
                recursion_desired,
            } => {
                assert_eq!(ports, vec![53, 5353]);
                assert_eq!(query_names.len(), 2);
                assert_eq!(query_type, DnsQueryType::Mx);
                assert_eq!(transport, DnsTransport::Tcp);
                assert!(!recursion_desired);
            }
            other => panic!("expected Dns variant, got {other:?}"),
        }
    }

    #[test]
    fn create_prober_dns_variant_produces_dns_prober() {
        let config = ProberConfig::Dns {
            ports: vec![53],
            query_names: vec!["example.com.".to_string()],
            query_type: DnsQueryType::A,
            transport: DnsTransport::Udp,
            recursion_desired: true,
        };
        let prober = create_prober(&config).expect("factory ok");
        assert_eq!(prober.kind(), ProbeKind::Dns);
    }

    #[test]
    fn create_prober_dns_variant_propagates_empty_query_names_error() {
        let config = ProberConfig::Dns {
            ports: vec![53],
            query_names: Vec::new(),
            query_type: DnsQueryType::A,
            transport: DnsTransport::Udp,
            recursion_desired: true,
        };
        match create_prober(&config) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(_))) => {}
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty query_names must error"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn prober_config_http_bad_path_errors_on_factory() {
        let config = ProberConfig::Http {
            ports: vec![80],
            scheme: HttpScheme::Auto,
            path: "no-leading-slash".to_string(),
            tls_verify: crate::prober::http::default_tls_verify(),
            user_agent: crate::prober::http::default_user_agent(),
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
