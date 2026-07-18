use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CipherSuite, ClientConfig, DigitallySignedStruct, Error as RustlsError, ProtocolVersion,
    SignatureScheme,
};
use tokio::net::TcpStream;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::parse_x509_certificate;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::ports::{probe_ports, MAX_PORTS_IN_FLIGHT};
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
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
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

fn render_protocol_version(version: ProtocolVersion) -> String {
    match version.as_str() {
        Some(name) => name.replace('_', "."),
        None => format!("0x{:04x}", u16::from(version)),
    }
}

fn render_cipher_suite(suite: CipherSuite) -> String {
    // rustls tags TLS 1.3 suites `TLS13_…`; the IANA registry name drops the version.
    match suite.as_str() {
        Some(name) => name.replacen("TLS13_", "TLS_", 1),
        None => format!("0x{:04x}", u16::from(suite)),
    }
}

fn connection_signals(
    version: Option<ProtocolVersion>,
    cipher: Option<CipherSuite>,
    alpn: Option<&[u8]>,
    leaf_der: Option<&[u8]>,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    if let Some(version) = version {
        signals.push(Signal::TlsProtocolVersion(render_protocol_version(version)));
    }
    if let Some(cipher) = cipher {
        signals.push(Signal::TlsCipherSuite(render_cipher_suite(cipher)));
    }
    if let Some(proto) = alpn {
        signals.push(Signal::TlsAlpn(String::from_utf8_lossy(proto).into_owned()));
    }
    if let Some(der) = leaf_der {
        if let Some(cn) = extract_subject_cn(der) {
            signals.push(Signal::TlsSubject(cn));
        }
        for entry in extract_san_entries(der) {
            signals.push(Signal::TlsSanName(entry));
        }
    }
    signals
}

/// Connection-level and certificate signals from a completed handshake; empty when the
/// handshake never completes (plaintext, a fatal alert, or no cipher suite in common).
async fn handshake_and_extract(
    connector: &TlsConnector,
    stream: TcpStream,
    addr: SocketAddr,
) -> Vec<Signal> {
    let server_name = ServerName::IpAddress(addr.ip().into());
    let tls_stream = match connector.connect(server_name, stream).await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let (_, connection) = tls_stream.get_ref();
    let leaf = connection.peer_certificates().and_then(<[_]>::first);
    connection_signals(
        connection.protocol_version(),
        connection.negotiated_cipher_suite().map(|s| s.suite()),
        connection.alpn_protocol(),
        leaf.map(AsRef::as_ref),
    )
}

// A refused / unreachable port is a discovery result; a local socket failure (descriptor
// exhaustion, denied capability) is a broken probe.
fn connect_fault(port: u16, err: &io::Error) -> Option<ProbeFault> {
    match classify::io_error(err) {
        Disposition::Fault(kind) => Some(ProbeFault::new(
            kind,
            format!("tls connect failed on port {port}: {err}"),
        )),
        Disposition::Absence => None,
    }
}

fn fold_connect(
    port: u16,
    outcome: Result<io::Result<TcpStream>, Elapsed>,
    signals: &mut Vec<Signal>,
    last_fault: &mut Option<ProbeFault>,
) -> Option<TcpStream> {
    match outcome {
        Ok(Ok(stream)) => {
            signals.push(Signal::OpenPort(port));
            Some(stream)
        }
        Ok(Err(err)) => {
            if let Some(fault) = connect_fault(port, &err) {
                *last_fault = Some(fault);
            }
            None
        }
        Err(_) => None,
    }
}

fn build_outcome(
    target_ip: IpAddr,
    signals: Vec<Signal>,
    last_fault: Option<ProbeFault>,
) -> ProbeOutcome {
    // A successful connect emits `OpenPort`, so no signals means no port answered — the only state
    // in which a connect fault is all this probe has to report.
    let reachable = !signals.is_empty();
    let fault = if reachable { None } else { last_fault };
    ProbeOutcome {
        kind: ProbeKind::Tls,
        target_ip,
        timestamp: SystemTime::now(),
        reachable,
        signals,
        fault,
    }
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
        let per_port = probe_ports(
            &self.ports,
            MAX_PORTS_IN_FLIGHT,
            ctx.port_budget.as_ref(),
            |port| {
                let connector = TlsConnector::from(Arc::clone(&self.tls_config));
                let addr = SocketAddr::new(target.ip, port);
                async move {
                    let mut port_signals = Vec::new();
                    let mut port_fault: Option<ProbeFault> = None;

                    let outcome = timeout(ctx.timeout, TcpStream::connect(addr)).await;
                    if let Some(stream) =
                        fold_connect(port, outcome, &mut port_signals, &mut port_fault)
                    {
                        if let Ok(mut handshake_signals) =
                            timeout(ctx.timeout, handshake_and_extract(&connector, stream, addr))
                                .await
                        {
                            port_signals.append(&mut handshake_signals);
                        }
                    }
                    (port_signals, port_fault)
                }
            },
        )
        .await;

        let mut signals = Vec::new();
        let mut last_fault: Option<ProbeFault> = None;
        for (port_signals, port_fault) in per_port {
            signals.extend(port_signals);
            if port_fault.is_some() {
                last_fault = port_fault;
            }
        }

        Ok(build_outcome(target.ip, signals, last_fault))
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
        ProbeCtx::new(Duration::from_millis(ms), 0)
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
        spawn_tls_stub_server_with_alpn(cn, sans, Vec::new()).await
    }

    async fn spawn_tls_stub_server_with_alpn(
        cn: &str,
        sans: Vec<SanType>,
        alpn: Vec<Vec<u8>>,
    ) -> u16 {
        let generated = generate_test_cert(cn, &sans);
        let cert_chain = vec![PkiCertificateDer::from(generated.der)];
        let key: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pkcs8_der));
        let provider = StdArc::new(rustls::crypto::ring::default_provider());
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider")
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server config");
        server_config.alpn_protocols = alpn;
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
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::TlsProtocolVersion(v) if v == "TLSv1.3")));
        let cipher = outcome
            .signals
            .iter()
            .find_map(|s| match s {
                Signal::TlsCipherSuite(v) => Some(v.as_str()),
                _ => None,
            })
            .expect("cipher suite captured");
        assert!(
            cipher.starts_with("TLS_"),
            "well-formed suite name: {cipher}"
        );
        assert!(
            !outcome
                .signals
                .iter()
                .any(|s| matches!(s, Signal::TlsAlpn(_))),
            "a stub without alpn_protocols selects none"
        );
    }

    #[tokio::test]
    async fn probe_captures_alpn_when_stub_negotiates_h2() {
        let port =
            spawn_tls_stub_server_with_alpn("router.example.com", Vec::new(), vec![b"h2".to_vec()])
                .await;
        let prober = TlsProber::new(vec![port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(5_000),
            )
            .await
            .expect("probe ok");
        let alpn = outcome
            .signals
            .iter()
            .find_map(|s| match s {
                Signal::TlsAlpn(v) => Some(v.as_str()),
                _ => None,
            })
            .expect("alpn captured");
        assert_eq!(alpn, "h2");
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::TlsProtocolVersion(v) if v == "TLSv1.3")));
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::TlsCipherSuite(_))));
    }

    #[test]
    fn render_protocol_version_dots_the_known_versions() {
        assert_eq!(
            render_protocol_version(ProtocolVersion::from(0x0304)),
            "TLSv1.3"
        );
        assert_eq!(
            render_protocol_version(ProtocolVersion::from(0x0303)),
            "TLSv1.2"
        );
    }

    #[test]
    fn render_protocol_version_falls_back_to_hex_for_unknown() {
        assert_eq!(
            render_protocol_version(ProtocolVersion::from(0x9999)),
            "0x9999"
        );
    }

    #[test]
    fn render_cipher_suite_yields_iana_names() {
        assert_eq!(
            render_cipher_suite(CipherSuite::from(0x1301)),
            "TLS_AES_128_GCM_SHA256"
        );
        assert_eq!(
            render_cipher_suite(CipherSuite::from(0x1302)),
            "TLS_AES_256_GCM_SHA384"
        );
        assert_eq!(
            render_cipher_suite(CipherSuite::from(0xc02f)),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn render_cipher_suite_falls_back_to_hex_for_unknown() {
        assert_eq!(render_cipher_suite(CipherSuite::from(0xeeee)), "0xeeee");
    }

    #[test]
    fn connection_signals_capture_version_and_cipher_without_a_certificate() {
        let signals = connection_signals(
            Some(ProtocolVersion::from(0x0304)),
            Some(CipherSuite::from(0x1301)),
            Some(b"h2"),
            None,
        );
        assert_eq!(
            signals,
            vec![
                Signal::TlsProtocolVersion("TLSv1.3".to_string()),
                Signal::TlsCipherSuite("TLS_AES_128_GCM_SHA256".to_string()),
                Signal::TlsAlpn("h2".to_string()),
            ]
        );
    }

    #[test]
    fn connection_signals_omit_alpn_when_none_and_keep_cert_signals() {
        let generated = generate_test_cert("router.example.com", &[]);
        let signals = connection_signals(
            Some(ProtocolVersion::from(0x0303)),
            Some(CipherSuite::from(0xc02f)),
            None,
            Some(&generated.der),
        );
        assert_eq!(
            signals,
            vec![
                Signal::TlsProtocolVersion("TLSv1.2".to_string()),
                Signal::TlsCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string()),
                Signal::TlsSubject("router.example.com".to_string()),
            ]
        );
    }

    #[test]
    fn connection_signals_are_empty_when_nothing_negotiated() {
        assert!(connection_signals(None, None, None, None).is_empty());
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
    async fn probe_emits_open_port_but_no_tls_signals_on_non_tls_port() {
        let port = spawn_plaintext_stub_server().await;
        let prober = TlsProber::new(vec![port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(500),
            )
            .await
            .expect("a plaintext peer is an outcome, not an error");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(&outcome.signals[0], Signal::OpenPort(p) if *p == port));
    }

    async fn spawn_plaintext_stub_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                let _ = stream.shutdown().await;
            }
        });
        port
    }

    /// Answers a `ClientHello` with a fatal `handshake_failure` alert: a peer that speaks TLS
    /// but will not negotiate with us, as legacy gear with no cipher suite in common does.
    async fn spawn_alerting_tls_stub_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    const FATAL_HANDSHAKE_FAILURE: [u8; 7] =
                        [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
                    let _ = stream.write_all(&FATAL_HANDSHAKE_FAILURE).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn probe_emits_open_port_with_no_tls_signals_for_a_peer_that_refuses_to_negotiate() {
        let port = spawn_alerting_tls_stub_server().await;
        let prober = TlsProber::new(vec![port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(2_000),
            )
            .await
            .expect("a device we cannot fingerprint is still a device we found");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(&outcome.signals[0], Signal::OpenPort(p) if *p == port));
    }

    #[tokio::test]
    async fn a_fingerprinted_port_and_an_alerting_port_both_report_open() {
        let sans = vec![SanType::DnsName("alt.example.com".try_into().expect("dns"))];
        let good_port = spawn_tls_stub_server("router.example.com", sans).await;
        let alerting_port = spawn_alerting_tls_stub_server().await;
        let prober = TlsProber::new(vec![good_port, alerting_port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(5_000),
            )
            .await
            .expect("a peer that refuses to negotiate is not an error");
        assert!(outcome.reachable);
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::TlsSubject(v) if v == "router.example.com")));
        let open_ports: Vec<u16> = outcome
            .signals
            .iter()
            .filter_map(|s| match s {
                Signal::OpenPort(p) => Some(*p),
                _ => None,
            })
            .collect();
        assert_eq!(open_ports.len(), 2);
    }

    #[tokio::test]
    async fn a_plaintext_peer_and_an_alerting_peer_are_open_ports_without_tls_signals() {
        let plaintext_port = spawn_plaintext_stub_server().await;
        let alerting_port = spawn_alerting_tls_stub_server().await;
        let prober = TlsProber::new(vec![plaintext_port, alerting_port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(2_000),
            )
            .await
            .expect("legacy gear that will not negotiate still produces a record");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 2);
        assert!(outcome
            .signals
            .iter()
            .all(|s| matches!(s, Signal::OpenPort(_))));
    }

    #[tokio::test]
    async fn tls_probe_emits_open_port_on_successful_connect() {
        let sans = vec![SanType::DnsName("alt.example.com".try_into().expect("dns"))];
        let port = spawn_tls_stub_server("router.example.com", sans).await;
        let prober = TlsProber::new(vec![port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(5_000),
            )
            .await
            .expect("probe ok");
        let open_port = outcome
            .signals
            .iter()
            .find_map(|s| match s {
                Signal::OpenPort(p) => Some(*p),
                _ => None,
            })
            .expect("OpenPort emitted");
        assert_eq!(open_port, port);
    }

    #[tokio::test]
    async fn tls_probe_emits_open_port_before_protocol_signals() {
        let sans = vec![SanType::DnsName("alt.example.com".try_into().expect("dns"))];
        let port = spawn_tls_stub_server("router.example.com", sans).await;
        let prober = TlsProber::new(vec![port]).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(5_000),
            )
            .await
            .expect("probe ok");
        let open_port_idx = outcome
            .signals
            .iter()
            .position(|s| matches!(s, Signal::OpenPort(_)))
            .expect("OpenPort emitted");
        let subject_idx = outcome
            .signals
            .iter()
            .position(|s| matches!(s, Signal::TlsSubject(_)))
            .expect("TlsSubject emitted");
        assert!(
            open_port_idx < subject_idx,
            "OpenPort must precede TlsSubject"
        );
    }

    #[tokio::test]
    async fn tls_probe_does_not_emit_open_port_on_connect_failure() {
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
        assert!(!outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::OpenPort(_))));
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13));

    #[test]
    fn a_local_socket_failure_on_connect_latches_a_fault() {
        let fault = connect_fault(443, &io::Error::from(io::ErrorKind::PermissionDenied))
            .expect("a denied local socket is a broken probe");
        assert!(
            fault.detail.contains("tls connect failed on port 443"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn a_refused_connect_latches_no_fault() {
        assert!(connect_fault(443, &io::Error::from(io::ErrorKind::ConnectionRefused)).is_none());
    }

    async fn elapsed() -> Elapsed {
        timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("a zero deadline on a pending future always elapses")
    }

    #[tokio::test]
    async fn a_connect_that_succeeds_emits_an_open_port_and_yields_the_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let stream = TcpStream::connect(("127.0.0.1", port)).await;
        let mut signals = Vec::new();
        let mut last_fault = None;

        let held = fold_connect(port, Ok(stream), &mut signals, &mut last_fault);

        assert!(held.is_some(), "the handshake needs the connected stream");
        assert!(matches!(signals.as_slice(), [Signal::OpenPort(p)] if *p == port));
        assert!(last_fault.is_none());
    }

    #[tokio::test]
    async fn a_connect_that_is_refused_emits_nothing() {
        let mut signals = Vec::new();
        let mut last_fault = None;

        let held = fold_connect(
            443,
            Ok(Err(io::Error::from(io::ErrorKind::ConnectionRefused))),
            &mut signals,
            &mut last_fault,
        );

        assert!(held.is_none());
        assert!(signals.is_empty());
        assert!(last_fault.is_none());
    }

    #[tokio::test]
    async fn a_connect_that_fails_on_a_local_socket_latches_a_fault() {
        let mut signals = Vec::new();
        let mut last_fault = None;

        let held = fold_connect(
            443,
            Ok(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            &mut signals,
            &mut last_fault,
        );

        assert!(held.is_none());
        assert!(signals.is_empty());
        let fault = last_fault.expect("a denied local socket is a broken probe");
        assert!(
            fault.detail.contains("tls connect failed on port 443"),
            "got: {}",
            fault.detail
        );
    }

    #[tokio::test]
    async fn a_connect_that_times_out_emits_nothing() {
        let mut signals = Vec::new();
        let mut last_fault = None;

        let held = fold_connect(443, Err(elapsed().await), &mut signals, &mut last_fault);

        assert!(held.is_none());
        assert!(signals.is_empty());
        assert!(last_fault.is_none());
    }

    #[test]
    fn an_open_port_is_a_reachable_outcome() {
        let outcome = build_outcome(
            TARGET,
            vec![
                Signal::OpenPort(443),
                Signal::TlsSubject("router.example.com".to_string()),
            ],
            None,
        );
        assert!(outcome.reachable);
        assert_eq!(outcome.kind, ProbeKind::Tls);
        assert_eq!(outcome.signals.len(), 2);
        assert!(outcome.fault.is_none());
    }

    fn sample_fault(detail: &str) -> ProbeFault {
        ProbeFault::new(crate::error::ProbeErrorKind::Other, detail.to_string())
    }

    #[test]
    fn an_open_port_outranks_a_connect_fault_on_another_port() {
        let outcome = build_outcome(
            TARGET,
            vec![Signal::OpenPort(443)],
            Some(sample_fault(
                "tls connect failed on port 8443: too many open files",
            )),
        );
        assert!(outcome.reachable);
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn no_signals_and_no_fault_is_an_absent_target() {
        let outcome = build_outcome(TARGET, Vec::new(), None);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn no_open_port_and_a_connect_fault_is_a_kinded_fault_outcome() {
        let outcome = build_outcome(
            TARGET,
            Vec::new(),
            Some(sample_fault(
                "tls connect failed on port 443: too many open files",
            )),
        );
        assert!(!outcome.reachable);
        let fault = outcome.fault.expect("a broken probe surfaces its fault");
        assert!(
            fault.detail.contains("tls connect failed on port 443"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn tls_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<TlsProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    async fn spawn_hanging_tls_stub() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        tokio::spawn(async move {
                            let _hold = stream;
                            tokio::time::sleep(Duration::from_secs(60)).await;
                        });
                    }
                    Err(_) => return,
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn probe_collects_open_ports_in_ascending_port_order() {
        let mut ports = Vec::new();
        for _ in 0..3 {
            ports.push(spawn_tls_stub_server("router.example.com", Vec::new()).await);
        }
        let prober = TlsProber::new(ports.clone()).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(5_000),
            )
            .await
            .expect("probe ok");
        let open: Vec<u16> = outcome
            .signals
            .iter()
            .filter_map(|s| match s {
                Signal::OpenPort(p) => Some(*p),
                _ => None,
            })
            .collect();
        ports.sort_unstable();
        assert_eq!(open, ports, "OpenPort signals must follow port order");
    }

    #[tokio::test]
    async fn probe_multiple_hanging_ports_finish_near_one_timeout() {
        let mut ports = Vec::new();
        for _ in 0..4 {
            ports.push(spawn_hanging_tls_stub().await);
        }
        let prober = TlsProber::new(ports).expect("valid");
        let start = std::time::Instant::now();
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(150),
            )
            .await
            .expect("probe ok");
        let elapsed = start.elapsed();
        // Connect succeeds fast; the handshake times out, so every port reports open.
        assert!(outcome.reachable);
        assert!(
            elapsed < Duration::from_millis(400),
            "four hanging handshakes serially would be ~600ms; concurrent stays near 1x: {elapsed:?}"
        );
    }
}
