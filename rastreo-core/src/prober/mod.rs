#[cfg(feature = "arp")]
pub mod arp;
pub mod dns;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "ndp")]
pub mod ndp;
mod redacted;
#[cfg(feature = "snmp")]
pub mod snmp;
pub mod tcp_connect;
pub mod udp;

#[cfg(feature = "arp")]
pub use arp::ArpProber;
pub use dns::{DnsProber, DnsQueryType, DnsTransport};
#[cfg(feature = "http")]
pub use http::{HttpProber, HttpScheme};
#[cfg(feature = "ndp")]
pub use ndp::NdpProber;
#[cfg(feature = "snmp")]
pub use redacted::{Community, Password};
#[cfg(feature = "snmp")]
pub use snmp::{SnmpProber, SnmpVersion, UsmAuth, UsmCredentials, UsmPrivacy};
pub use tcp_connect::TcpConnectProber;
pub use udp::{UdpProber, UdpProtocol};

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
    Udp {
        ports: Vec<u16>,
        protocol: UdpProtocol,
    },
    #[cfg(feature = "snmp")]
    Snmp {
        #[serde(default = "snmp::default_ports")]
        ports: Vec<u16>,
        #[serde(default)]
        version: SnmpVersion,
        #[serde(default = "snmp::default_community")]
        community: Community,
        #[serde(default)]
        credentials: UsmCredentials,
    },
    #[cfg(feature = "arp")]
    Arp {
        #[serde(default = "arp::default_interface")]
        interface: String,
    },
    #[cfg(feature = "ndp")]
    Ndp {
        #[serde(default = "ndp::default_interface")]
        interface: String,
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
        ProberConfig::Udp { ports, protocol } => {
            Ok(Box::new(UdpProber::new(ports.clone(), *protocol)?))
        }
        #[cfg(feature = "snmp")]
        ProberConfig::Snmp {
            ports,
            version,
            community,
            credentials,
        } => Ok(Box::new(SnmpProber::new(
            ports.clone(),
            *version,
            community.0.clone(),
            credentials.clone(),
        )?)),
        #[cfg(feature = "arp")]
        ProberConfig::Arp { interface } => Ok(Box::new(ArpProber::new(interface.clone())?)),
        #[cfg(feature = "ndp")]
        ProberConfig::Ndp { interface } => Ok(Box::new(NdpProber::new(interface.clone())?)),
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

    #[cfg(feature = "config")]
    #[test]
    fn prober_config_deserializes_udp_variant_from_yaml() {
        let yaml = "type: udp\nports: [123]\nprotocol: ntp\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize udp");
        match config {
            ProberConfig::Udp { ports, protocol } => {
                assert_eq!(ports, vec![123]);
                assert_eq!(protocol, UdpProtocol::Ntp);
            }
            other => panic!("expected Udp variant, got {other:?}"),
        }
    }

    #[test]
    fn create_prober_udp_produces_udp_prober() {
        let config = ProberConfig::Udp {
            ports: vec![5060],
            protocol: UdpProtocol::SipOptions,
        };
        let prober = create_prober(&config).expect("factory ok");
        assert_eq!(prober.kind(), ProbeKind::Udp);
    }

    #[test]
    fn create_prober_udp_propagates_empty_ports_error() {
        let config = ProberConfig::Udp {
            ports: Vec::new(),
            protocol: UdpProtocol::Ntp,
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

    #[cfg(all(feature = "config", feature = "snmp"))]
    #[test]
    fn prober_config_deserializes_snmp_variant_from_yaml() {
        let yaml = "type: snmp\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize snmp");
        match config {
            ProberConfig::Snmp {
                ports,
                version,
                community,
                credentials,
            } => {
                assert_eq!(ports, vec![161]);
                assert_eq!(version, SnmpVersion::V2c);
                assert_eq!(&*community, "public");
                assert!(credentials.username.is_empty());
                assert!(matches!(credentials.auth, UsmAuth::None));
                assert!(matches!(credentials.privacy, UsmPrivacy::None));
            }
            other => panic!("expected Snmp variant, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "snmp"))]
    #[test]
    fn prober_config_deserializes_snmp_variant_fully_populated() {
        let yaml = "type: snmp\nports: [161, 1161]\nversion: v1\ncommunity: rocommunity\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize snmp");
        match config {
            ProberConfig::Snmp {
                ports,
                version,
                community,
                credentials: _,
            } => {
                assert_eq!(ports, vec![161, 1161]);
                assert_eq!(version, SnmpVersion::V1);
                assert_eq!(&*community, "rocommunity");
            }
            other => panic!("expected Snmp variant, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "snmp"))]
    #[test]
    fn prober_config_deserializes_snmp_v3_with_authpriv() {
        let yaml = "type: snmp\nversion: v3\ncredentials:\n  username: probe\n  auth:\n    algorithm: sha256\n    password: authpw\n  privacy:\n    algorithm: aes128\n    password: privpw\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize snmp v3");
        match config {
            ProberConfig::Snmp {
                version,
                credentials,
                ..
            } => {
                assert_eq!(version, SnmpVersion::V3);
                assert_eq!(credentials.username, "probe");
                assert!(matches!(credentials.auth, UsmAuth::Sha256 { .. }));
                assert!(matches!(credentials.privacy, UsmPrivacy::Aes128 { .. }));
            }
            other => panic!("expected Snmp variant, got {other:?}"),
        }
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn create_prober_snmp_produces_snmp_prober() {
        let config = ProberConfig::Snmp {
            ports: crate::prober::snmp::default_ports(),
            version: SnmpVersion::V2c,
            community: crate::prober::snmp::default_community(),
            credentials: UsmCredentials::default(),
        };
        let prober = create_prober(&config).expect("factory ok");
        assert_eq!(prober.kind(), ProbeKind::Snmp);
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn create_prober_snmp_propagates_empty_ports_error() {
        let config = ProberConfig::Snmp {
            ports: Vec::new(),
            version: SnmpVersion::V2c,
            community: crate::prober::snmp::default_community(),
            credentials: UsmCredentials::default(),
        };
        match create_prober(&config) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("port"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty ports must error"),
        }
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn create_prober_snmp_propagates_empty_community_error() {
        let config = ProberConfig::Snmp {
            ports: crate::prober::snmp::default_ports(),
            version: SnmpVersion::V2c,
            community: crate::prober::Community(String::new()),
            credentials: UsmCredentials::default(),
        };
        match create_prober(&config) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("community"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty community must error"),
        }
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn create_prober_snmp_v3_propagates_empty_username_error() {
        let config = ProberConfig::Snmp {
            ports: crate::prober::snmp::default_ports(),
            version: SnmpVersion::V3,
            community: crate::prober::snmp::default_community(),
            credentials: UsmCredentials::default(),
        };
        match create_prober(&config) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("username"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("v3 empty username must error"),
        }
    }

    #[cfg(all(feature = "config", feature = "snmp"))]
    #[test]
    fn prober_config_snmp_debug_redacts_community() {
        let yaml = "type: snmp\ncommunity: secret-community\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize snmp");
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("secret-community"),
            "community leaked in Debug: {debug_output}"
        );
        assert!(debug_output.contains("<redacted:"));
    }

    #[cfg(all(feature = "config", feature = "arp"))]
    #[test]
    fn prober_config_deserializes_arp_variant_with_defaults() {
        let yaml = "type: arp\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize arp");
        match config {
            ProberConfig::Arp { interface } => {
                assert!(interface.is_empty());
            }
            other => panic!("expected Arp variant, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "arp"))]
    #[test]
    fn prober_config_deserializes_arp_variant_with_explicit_interface() {
        let yaml = "type: arp\ninterface: eth0\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize arp");
        match config {
            ProberConfig::Arp { interface } => {
                assert_eq!(interface, "eth0");
            }
            other => panic!("expected Arp variant, got {other:?}"),
        }
    }

    #[cfg(feature = "arp")]
    #[test]
    fn create_prober_arp_variant_produces_arp_prober() {
        let config = ProberConfig::Arp {
            interface: crate::prober::arp::default_interface(),
        };
        let prober = create_prober(&config).expect("factory ok");
        assert_eq!(prober.kind(), ProbeKind::Arp);
    }

    #[cfg(all(feature = "config", feature = "ndp"))]
    #[test]
    fn prober_config_deserializes_ndp_variant_with_defaults() {
        let yaml = "type: ndp\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize ndp");
        match config {
            ProberConfig::Ndp { interface } => {
                assert!(interface.is_empty());
            }
            other => panic!("expected Ndp variant, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "ndp"))]
    #[test]
    fn prober_config_deserializes_ndp_variant_with_explicit_interface() {
        let yaml = "type: ndp\ninterface: eth1\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize ndp");
        match config {
            ProberConfig::Ndp { interface } => {
                assert_eq!(interface, "eth1");
            }
            other => panic!("expected Ndp variant, got {other:?}"),
        }
    }

    #[cfg(feature = "ndp")]
    #[test]
    fn create_prober_ndp_variant_produces_prober() {
        let config = ProberConfig::Ndp {
            interface: crate::prober::ndp::default_interface(),
        };
        let prober = create_prober(&config).expect("factory ok");
        assert_eq!(prober.kind(), ProbeKind::Ndp);
    }

    #[cfg(all(feature = "config", feature = "snmp"))]
    #[test]
    fn prober_config_snmp_v3_debug_redacts_password() {
        let yaml = "type: snmp\nversion: v3\ncredentials:\n  username: probe\n  auth:\n    algorithm: sha256\n    password: supersecretauth\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize v3");
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("supersecretauth"),
            "password leaked in Debug: {debug_output}"
        );
        assert!(debug_output.contains("<redacted:"));
    }
}
