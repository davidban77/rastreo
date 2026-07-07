use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::parse_x509_certificate;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

pub struct TlsProber {
    ports: Vec<u16>,
    tls_config: Arc<ClientConfig>,
}

impl TlsProber {
    pub fn new(ports: Vec<u16>) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("tls prober requires at least one port").into());
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Ok(Self {
            ports,
            tls_config: Arc::new(build_accept_any_config()),
        })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
}

pub fn default_ports() -> Vec<u16> {
    vec![443]
}

/// Accepts every server certificate without validation. The prober fingerprints what a server
/// calls itself, it does not authenticate the server; skipping trust-chain checks is required
/// to reach servers with self-signed, expired, or otherwise untrusted certificates.
#[derive(Debug)]
struct AcceptAnyVerifier;

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn build_accept_any_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
        .with_no_client_auth()
}

fn extract_subject_cn(der: &[u8]) -> Option<String> {
    let (_, cert) = parse_x509_certificate(der).ok()?;
    for attr in cert.subject().iter_common_name() {
        if let Ok(value) = attr.as_str() {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn extract_san_entries(der: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let (_, cert) = match parse_x509_certificate(der) {
        Ok(x) => x,
        Err(_) => return out,
    };
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => {
                        let trimmed = dns.trim();
                        if !trimmed.is_empty() {
                            out.push(trimmed.to_string());
                        }
                    }
                    GeneralName::IPAddress(bytes) => {
                        if let Some(addr) = ip_from_bytes(bytes) {
                            out.push(format!("ip:{addr}"));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => {
            let arr: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(arr)))
        }
        16 => {
            let arr: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(arr)))
        }
        _ => None,
    }
}

async fn handshake_and_extract(connector: &TlsConnector, addr: SocketAddr) -> Option<Vec<Signal>> {
    let stream = TcpStream::connect(addr).await.ok()?;
    let server_name = ServerName::IpAddress(addr.ip().into());
    let tls_stream = connector.connect(server_name, stream).await.ok()?;
    let (_, connection) = tls_stream.get_ref();
    let peer_certs = connection.peer_certificates()?;
    let leaf = peer_certs.first()?;
    let der = leaf.as_ref();

    let mut signals = Vec::new();
    if let Some(cn) = extract_subject_cn(der) {
        signals.push(Signal::TlsSubject(cn));
    }
    for entry in extract_san_entries(der) {
        signals.push(Signal::TlsSanName(entry));
    }
    Some(signals)
}

#[async_trait::async_trait]
impl Prober for TlsProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Tls
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let mut signals = Vec::new();
        let mut any_reachable = false;
        let connector = TlsConnector::from(Arc::clone(&self.tls_config));

        for &port in &self.ports {
            let addr = SocketAddr::new(target.ip, port);
            if let Ok(Some(port_signals)) =
                timeout(ctx.timeout, handshake_and_extract(&connector, addr)).await
            {
                any_reachable = true;
                signals.extend(port_signals);
            }
        }

        Ok(ProbeOutcome {
            kind: ProbeKind::Tls,
            target_ip: target.ip,
            timestamp: SystemTime::now(),
            reachable: any_reachable,
            signals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc as StdArc;
    use std::time::Duration;

    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use rustls::pki_types::{
        CertificateDer as PkiCertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer,
    };
    use rustls::ServerConfig;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use crate::error::ConfigError;
    use crate::model::Target;

    fn loopback_target(ip: Ipv4Addr) -> ResolvedTarget {
        let addr = IpAddr::V4(ip);
        ResolvedTarget {
            ip: addr,
            original: Target::Ip(addr),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn ctx_with_timeout(ms: u64) -> ProbeCtx {
        ProbeCtx {
            timeout: Duration::from_millis(ms),
            retries: 0,
        }
    }

    struct GeneratedCert {
        der: Vec<u8>,
        key_pkcs8_der: Vec<u8>,
    }

    fn generate_test_cert(cn: &str, sans: &[SanType]) -> GeneratedCert {
        let key_pair = KeyPair::generate().expect("keypair");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, cn.to_string());
        params.subject_alt_names = sans.to_vec();
        let cert = params.self_signed(&key_pair).expect("self-sign");
        GeneratedCert {
            der: cert.der().to_vec(),
            key_pkcs8_der: key_pair.serialize_der(),
        }
    }

    #[test]
    fn new_rejects_empty_ports() {
        match TlsProber::new(Vec::new()) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("at least one port"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty ports must error"),
        }
    }

    #[test]
    fn new_dedups_and_sorts_ports() {
        let p = TlsProber::new(vec![8443, 443, 8443, 443]).expect("valid");
        assert_eq!(p.ports(), &[443, 8443]);
    }

    #[test]
    fn default_ports_is_443() {
        assert_eq!(default_ports(), vec![443]);
    }

    #[test]
    fn ports_getter_returns_configured_ports() {
        let p = TlsProber::new(vec![443, 8443]).expect("valid");
        assert_eq!(p.ports(), &[443, 8443]);
    }

    #[test]
    fn probe_kind_returns_tls() {
        let p = TlsProber::new(vec![443]).expect("valid");
        assert_eq!(p.kind(), ProbeKind::Tls);
    }

    #[test]
    fn extract_subject_cn_returns_cn_from_self_signed_cert() {
        let generated = generate_test_cert("router.example.com", &[]);
        let cn = extract_subject_cn(&generated.der).expect("cn present");
        assert_eq!(cn, "router.example.com");
    }

    #[test]
    fn extract_subject_cn_returns_none_for_malformed_der() {
        assert!(extract_subject_cn(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn extract_san_entries_returns_dns_and_ip_names() {
        let sans = vec![
            SanType::DnsName("alt-1.example.com".try_into().expect("dns")),
            SanType::DnsName("alt-2.example.com".try_into().expect("dns")),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            SanType::IpAddress(IpAddr::V6("2001:db8::1".parse().expect("v6"))),
        ];
        let generated = generate_test_cert("primary.example.com", &sans);
        let entries = extract_san_entries(&generated.der);
        assert_eq!(
            entries,
            vec![
                "alt-1.example.com".to_string(),
                "alt-2.example.com".to_string(),
                "ip:10.0.0.1".to_string(),
                "ip:2001:db8::1".to_string(),
            ]
        );
    }

    #[test]
    fn extract_san_entries_returns_empty_when_no_extension() {
        let generated = generate_test_cert("router.example.com", &[]);
        assert!(extract_san_entries(&generated.der).is_empty());
    }

    #[test]
    fn extract_san_entries_returns_empty_for_malformed_der() {
        assert!(extract_san_entries(&[0x00, 0x01, 0x02]).is_empty());
    }

    #[test]
    fn ip_from_bytes_parses_ipv4_and_ipv6_lengths() {
        assert_eq!(
            ip_from_bytes(&[10, 0, 0, 1]),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        let v6_bytes: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        assert_eq!(
            ip_from_bytes(&v6_bytes),
            Some(IpAddr::V6("2001:db8::1".parse().unwrap()))
        );
        assert!(ip_from_bytes(&[1, 2, 3]).is_none());
        assert!(ip_from_bytes(&[]).is_none());
    }

    async fn spawn_tls_stub_server(cn: &str, sans: Vec<SanType>) -> u16 {
        let generated = generate_test_cert(cn, &sans);
        let cert_chain = vec![PkiCertificateDer::from(generated.der)];
        let key: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pkcs8_der));
        let provider = StdArc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider")
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server config");
        let acceptor = TlsAcceptor::from(StdArc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    let _ = tls_stream.shutdown().await;
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn probe_captures_subject_and_san_from_stub_server() {
        let sans = vec![
            SanType::DnsName("alt.example.com".try_into().expect("dns")),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        ];
        let port = spawn_tls_stub_server("router.example.com", sans).await;
        let prober = TlsProber::new(vec![port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(5_000),
            )
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.kind, ProbeKind::Tls);
        let subject = outcome
            .signals
            .iter()
            .find_map(|s| match s {
                Signal::TlsSubject(v) => Some(v.as_str()),
                _ => None,
            })
            .expect("subject captured");
        assert_eq!(subject, "router.example.com");
        let sans: Vec<&str> = outcome
            .signals
            .iter()
            .filter_map(|s| match s {
                Signal::TlsSanName(v) => Some(v.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(sans, vec!["alt.example.com", "ip:127.0.0.1"]);
    }

    #[tokio::test]
    async fn probe_reports_no_signal_for_closed_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let prober = TlsProber::new(vec![port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(500),
            )
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert_eq!(outcome.kind, ProbeKind::Tls);
    }

    #[tokio::test]
    async fn probe_reports_no_signal_when_server_speaks_plain_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                let _ = stream.shutdown().await;
            }
        });
        let prober = TlsProber::new(vec![port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(500),
            )
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[test]
    fn tls_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<TlsProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }
}
