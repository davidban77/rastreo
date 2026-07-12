use std::net::IpAddr;
use std::time::SystemTime;

use crate::error::{ConfigError, ProbeErrorKind, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::Prober;

const BANNER_MAX_BYTES: usize = 256;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HttpScheme {
    #[default]
    Auto,
    Http,
    Https,
}

pub struct HttpProber {
    ports: Vec<u16>,
    scheme: HttpScheme,
    path: String,
    user_agent: String,
    client: reqwest::Client,
}

impl HttpProber {
    pub fn new(
        ports: Vec<u16>,
        scheme: HttpScheme,
        path: String,
        tls_verify: bool,
        user_agent: String,
    ) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("http prober requires at least one port").into());
        }
        if !path.starts_with('/') {
            return Err(ConfigError::invalid("http prober path must start with /").into());
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(!tls_verify)
            .build()
            .map_err(|e| ConfigError::invalid(format!("failed to build http client: {e}")))?;

        Ok(Self {
            ports,
            scheme,
            path,
            user_agent,
            client,
        })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
}

/// Serde default for `ProberConfig::Http.path` — `"/"`.
pub fn default_path() -> String {
    "/".to_string()
}

/// Serde default for `ProberConfig::Http.tls_verify` — `false`.
///
/// rastreo probes unknown networks where self-signed and expired certificates are common.
/// Users on trusted networks opt into strict verification via `tls_verify: true`.
pub fn default_tls_verify() -> bool {
    false
}

/// Serde default for `ProberConfig::Http.user_agent` — `"rastreo/<version>"`.
pub fn default_user_agent() -> String {
    format!("rastreo/{}", env!("CARGO_PKG_VERSION"))
}

/// JsonSchema-facing default: the literal `"rastreo/<version>"` placeholder,
/// not the version-baked runtime value. Keeps committed schemas stable across
/// release bumps that would otherwise re-derive the concrete version string.
pub fn default_user_agent_schema() -> &'static str {
    "rastreo/<version>"
}

fn scheme_for_port(port: u16, scheme: HttpScheme) -> &'static str {
    match scheme {
        HttpScheme::Http => "http",
        HttpScheme::Https => "https",
        HttpScheme::Auto => match port {
            443 | 8443 => "https",
            _ => "http",
        },
    }
}

fn classify_request_error(err: &reqwest::Error) -> Disposition {
    classify_error_chain(err, err.is_timeout(), err.is_connect())
}

fn classify_error_chain(
    err: &(dyn std::error::Error + 'static),
    is_timeout: bool,
    is_connect: bool,
) -> Disposition {
    if is_timeout {
        return Disposition::Absence;
    }
    // Only the connector's errno separates a refused peer from a denied or exhausted local socket.
    if let Some(io_err) = classify::io_error_in_chain(err) {
        return classify::io_error(io_err);
    }
    if is_connect {
        return Disposition::Absence;
    }
    Disposition::Fault(ProbeErrorKind::Other)
}

fn truncate_banner(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() <= BANNER_MAX_BYTES {
        return trimmed.to_string();
    }
    let mut end = BANNER_MAX_BYTES;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    trimmed[..end].to_string()
}

fn build_outcome(
    target_ip: IpAddr,
    signals: Vec<Signal>,
    last_fault: Option<ProbeFault>,
) -> ProbeOutcome {
    // A port that answered emits `OpenPort`, so no signals means nothing answered — the only state
    // in which a connect fault is all this probe has to report.
    let reachable = !signals.is_empty();
    let fault = if reachable { None } else { last_fault };
    ProbeOutcome {
        kind: ProbeKind::Http,
        target_ip,
        timestamp: SystemTime::now(),
        reachable,
        signals,
        fault,
    }
}

#[async_trait::async_trait]
impl Prober for HttpProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Http
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let mut signals = Vec::new();
        let mut last_fault: Option<ProbeFault> = None;

        for &port in &self.ports {
            let scheme = scheme_for_port(port, self.scheme);
            let host = if target.ip.is_ipv6() {
                format!("[{}]", target.ip)
            } else {
                target.ip.to_string()
            };
            let url = format!("{}://{}:{}{}", scheme, host, port, self.path);
            let request = self
                .client
                .get(&url)
                .header("User-Agent", &self.user_agent)
                .send();

            match tokio::time::timeout(ctx.timeout, request).await {
                Ok(Ok(response)) => {
                    signals.push(Signal::OpenPort(port));
                    if let Some(server) = response
                        .headers()
                        .get(reqwest::header::SERVER)
                        .and_then(|v| v.to_str().ok())
                    {
                        let banner = truncate_banner(server);
                        if !banner.is_empty() {
                            signals.push(Signal::HttpBanner(banner));
                        }
                    }
                }
                Ok(Err(reqwest_err)) => {
                    // A rustls error is only reachable once the connect completed: the port is open.
                    if classify::rustls_error_in_chain(&reqwest_err).is_some() {
                        signals.push(Signal::OpenPort(port));
                    } else if let Disposition::Fault(kind) = classify_request_error(&reqwest_err) {
                        last_fault = Some(ProbeFault::new(
                            kind,
                            format!("http probe failed on port {port}: {reqwest_err}"),
                        ));
                    }
                }
                Err(_) => {}
            }
        }

        Ok(build_outcome(target.ip, signals, last_fault))
    }
}

#[cfg(all(test, feature = "http"))]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use crate::model::Target;

    fn loopback_target() -> ResolvedTarget {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
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

    type Responder = Arc<
        dyn Fn(Request<hyper::body::Incoming>) -> Response<Full<Bytes>> + Send + Sync + 'static,
    >;

    async fn spawn_server_bound_to(
        bind: &str,
        responder: Responder,
    ) -> Result<u16, std::io::Error> {
        let listener = TcpListener::bind(bind).await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let responder = responder.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let responder = responder.clone();
                        async move { Ok::<_, Infallible>(responder(req)) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        Ok(port)
    }

    async fn spawn_server(responder: Responder) -> u16 {
        spawn_server_bound_to("127.0.0.1:0", responder)
            .await
            .expect("bind")
    }

    async fn spawn_hanging_server() -> u16 {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                // Hold the connection open and never write so the client times out.
                tokio::spawn(async move {
                    let _hold = stream;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn http_prober_captures_server_header_from_response() {
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .header("Server", "nginx/1.24.0")
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::OpenPort(p) if *p == port)));
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::HttpBanner(b) if b == "nginx/1.24.0")));
        assert_eq!(outcome.kind, ProbeKind::Http);
    }

    #[tokio::test]
    async fn http_prober_captures_banner_on_404_response() {
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(404)
                .header("Server", "Apache/2.4.62")
                .body(Full::new(Bytes::from("not found")))
                .expect("response")
        }))
        .await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::OpenPort(p) if *p == port)));
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::HttpBanner(b) if b == "Apache/2.4.62")));
    }

    #[tokio::test]
    async fn http_prober_no_server_header_still_emits_open_port() {
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(&outcome.signals[0], Signal::OpenPort(p) if *p == port));
    }

    #[tokio::test]
    async fn http_prober_maps_connection_refused_to_unreachable_outcome() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(500))
            .await
            .expect("a refused port is an outcome, not an error");
        assert_eq!(outcome.kind, ProbeKind::Http);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn http_prober_maps_timeout_to_unreachable_outcome() {
        let port = spawn_hanging_server().await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(100))
            .await
            .expect("a hanging server is an outcome, not an error");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn http_prober_truncates_long_server_header_to_256_bytes() {
        let responder: Responder = Arc::new(|_req| {
            Response::builder()
                .status(200)
                .header("Server", "a".repeat(500))
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        });
        let port = spawn_server(responder).await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        let banner = outcome
            .signals
            .iter()
            .find_map(|s| match s {
                Signal::HttpBanner(b) => Some(b),
                _ => None,
            })
            .expect("banner emitted");
        assert_eq!(banner.len(), 256, "banner: {banner}");
    }

    #[tokio::test]
    async fn http_prober_trims_whitespace_from_server_header() {
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .header("Server", "  nginx  ")
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::HttpBanner(b) if b == "nginx")));
    }

    #[tokio::test]
    async fn http_prober_captures_server_header_from_ipv6_target() {
        let responder: Responder = Arc::new(|_req| {
            Response::builder()
                .status(200)
                .header("Server", "nginx-v6/1.0")
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        });
        let port = match spawn_server_bound_to("[::1]:0", responder).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skipping IPv6 test: IPv6 loopback bind failed: {e}");
                return;
            }
        };
        let ip: IpAddr = "::1".parse().expect("parse ::1");
        let target = ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&target, &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::HttpBanner(v) if v == "nginx-v6/1.0")));
    }

    #[tokio::test]
    async fn http_probe_emits_open_port_on_successful_connect() {
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .header("Server", "nginx/1.24.0")
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
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
    async fn http_probe_does_not_emit_open_port_on_connect_failure() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(500))
            .await
            .expect("a closed port is an outcome, not an error");
        assert!(!outcome.reachable);
        assert!(outcome
            .signals
            .iter()
            .all(|s| !matches!(s, Signal::OpenPort(_))));
    }

    #[tokio::test]
    async fn http_probe_emits_open_port_per_successful_port_only() {
        let good_port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let closed_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let closed_port = closed_listener.local_addr().expect("addr").port();
        drop(closed_listener);
        let prober = HttpProber::new(
            vec![good_port, closed_port],
            HttpScheme::Http,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(500))
            .await
            .expect("at least one port reachable");
        let open_ports: Vec<u16> = outcome
            .signals
            .iter()
            .filter_map(|s| match s {
                Signal::OpenPort(p) => Some(*p),
                _ => None,
            })
            .collect();
        assert_eq!(open_ports, vec![good_port]);
    }

    #[tokio::test]
    async fn http_prober_emits_open_port_for_a_plaintext_peer_probed_as_https() {
        // Plain HTTP served, probed as HTTPS: rustls rejects the bytes, but the connect completed.
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Https,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("a peer that does not speak TLS is a device we found, not a broken probe");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(&outcome.signals[0], Signal::OpenPort(p) if *p == port));
    }

    async fn spawn_alerting_tls_server() -> u16 {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
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
    async fn http_prober_emits_open_port_for_a_tls_peer_that_refuses_to_negotiate() {
        let port = spawn_alerting_tls_server().await;
        let prober = HttpProber::new(
            vec![port],
            HttpScheme::Https,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("a device we cannot fingerprint is still a device we found");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(&outcome.signals[0], Signal::OpenPort(p) if *p == port));
    }

    #[tokio::test]
    async fn http_prober_keeps_the_open_port_of_a_tls_peer_alongside_a_plaintext_one() {
        let alerting_port = spawn_alerting_tls_server().await;
        let plaintext_port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let prober = HttpProber::new(
            vec![alerting_port, plaintext_port],
            HttpScheme::Https,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("legacy gear that will not negotiate still produces a record");
        assert!(outcome.reachable);
        let mut open_ports: Vec<u16> = outcome
            .signals
            .iter()
            .filter_map(|s| match s {
                Signal::OpenPort(p) => Some(*p),
                _ => None,
            })
            .collect();
        open_ports.sort_unstable();
        let mut expected = vec![alerting_port, plaintext_port];
        expected.sort_unstable();
        assert_eq!(open_ports, expected);
    }

    #[tokio::test]
    async fn reqwest_surfaces_the_rustls_error_for_a_plaintext_peer() {
        // The open port above holds only while the rustls error stays reachable through reqwest.
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("client");
        let err = client
            .get(format!("https://127.0.0.1:{port}/"))
            .send()
            .await
            .expect_err("TLS handshake against a plaintext port fails");
        let tls_err = classify::rustls_error_in_chain(&err)
            .expect("reqwest must expose the rustls error in its source chain");
        assert!(
            matches!(tls_err, rustls::Error::InvalidMessage(_)),
            "got: {tls_err:?}"
        );
    }

    #[tokio::test]
    async fn reqwest_surfaces_the_rustls_error_for_a_peer_that_refuses_to_negotiate() {
        let port = spawn_alerting_tls_server().await;
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("client");
        let err = client
            .get(format!("https://127.0.0.1:{port}/"))
            .send()
            .await
            .expect_err("a fatal alert fails the handshake");
        let tls_err = classify::rustls_error_in_chain(&err)
            .expect("reqwest must expose the rustls error in its source chain");
        assert!(
            matches!(tls_err, rustls::Error::AlertReceived(_)),
            "got: {tls_err:?}"
        );
    }

    #[tokio::test]
    async fn reqwest_surfaces_the_io_error_for_a_refused_port() {
        // The absence/fault split is only truthful while the connector's errno is reachable
        // through reqwest's source chain.
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let client = reqwest::Client::builder().build().expect("client");
        let err = client
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .expect_err("a connect to a closed port fails");
        let io_err = classify::io_error_in_chain(&err)
            .expect("reqwest must expose the connector io error in its source chain");
        assert_eq!(io_err.kind(), std::io::ErrorKind::ConnectionRefused);
        assert_eq!(classify_request_error(&err), Disposition::Absence);
    }

    #[derive(Debug)]
    struct Layer(Box<dyn std::error::Error + Send + Sync + 'static>);

    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "layer: {}", self.0)
        }
    }

    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[derive(Debug)]
    struct Opaque;

    impl std::fmt::Display for Opaque {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "opaque")
        }
    }

    impl std::error::Error for Opaque {}

    fn connector_error(kind: std::io::ErrorKind) -> Layer {
        Layer(Box::new(Layer(Box::new(std::io::Error::from(kind)))))
    }

    #[test]
    fn a_refused_connect_is_absence() {
        let err = connector_error(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(
            classify_error_chain(&err, false, true),
            Disposition::Absence
        );
    }

    #[test]
    fn a_denied_connect_is_a_fault() {
        let err = connector_error(std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            classify_error_chain(&err, false, true),
            Disposition::Fault(ProbeErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn a_connect_that_exhausted_local_descriptors_is_a_fault() {
        let emfile = Layer(Box::new(std::io::Error::from_raw_os_error(24)));
        assert_eq!(
            classify_error_chain(&emfile, false, true),
            Disposition::Fault(ProbeErrorKind::Other)
        );
    }

    #[test]
    fn a_timeout_is_absence_even_when_it_carries_an_io_error() {
        let err = connector_error(std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            classify_error_chain(&err, true, false),
            Disposition::Absence
        );
    }

    #[test]
    fn a_connect_failure_with_no_io_evidence_is_absence() {
        let err = Layer(Box::new(Opaque));
        assert_eq!(
            classify_error_chain(&err, false, true),
            Disposition::Absence
        );
    }

    #[test]
    fn a_request_failure_that_is_neither_connect_nor_timeout_nor_io_is_a_fault() {
        let err = Layer(Box::new(Opaque));
        assert_eq!(
            classify_error_chain(&err, false, false),
            Disposition::Fault(ProbeErrorKind::Other)
        );
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13));

    fn sample_fault(detail: &str) -> ProbeFault {
        ProbeFault::new(ProbeErrorKind::Other, detail.to_string())
    }

    #[test]
    fn an_open_port_is_a_reachable_outcome() {
        let outcome = build_outcome(
            TARGET,
            vec![
                Signal::OpenPort(443),
                Signal::HttpBanner("nginx".to_string()),
            ],
            None,
        );
        assert!(outcome.reachable);
        assert_eq!(outcome.kind, ProbeKind::Http);
        assert_eq!(outcome.signals.len(), 2);
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn an_open_port_outranks_a_connect_fault_on_another_port() {
        let outcome = build_outcome(
            TARGET,
            vec![Signal::OpenPort(443)],
            Some(sample_fault(
                "http probe failed on port 8443: too many open files",
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
                "http probe failed on port 443: too many open files",
            )),
        );
        assert!(!outcome.reachable);
        let fault = outcome.fault.expect("a broken probe surfaces its fault");
        assert!(
            fault.detail.contains("http probe failed on port 443"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn http_scheme_auto_resolves_by_port() {
        assert_eq!(scheme_for_port(443, HttpScheme::Auto), "https");
        assert_eq!(scheme_for_port(8443, HttpScheme::Auto), "https");
        assert_eq!(scheme_for_port(80, HttpScheme::Auto), "http");
        assert_eq!(scheme_for_port(8080, HttpScheme::Auto), "http");
        assert_eq!(scheme_for_port(9999, HttpScheme::Auto), "http");
    }

    #[test]
    fn http_scheme_explicit_http_overrides_auto() {
        assert_eq!(scheme_for_port(443, HttpScheme::Http), "http");
        assert_eq!(scheme_for_port(8443, HttpScheme::Http), "http");
    }

    #[test]
    fn http_scheme_explicit_https_overrides_auto() {
        assert_eq!(scheme_for_port(80, HttpScheme::Https), "https");
        assert_eq!(scheme_for_port(8080, HttpScheme::Https), "https");
    }

    #[test]
    fn new_rejects_empty_port_list() {
        match HttpProber::new(
            Vec::new(),
            HttpScheme::Auto,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("at least one port"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty port list must error"),
        }
    }

    #[test]
    fn new_rejects_path_missing_leading_slash() {
        match HttpProber::new(
            vec![80],
            HttpScheme::Auto,
            "no-slash".to_string(),
            default_tls_verify(),
            default_user_agent(),
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("start with /"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("bad path must error"),
        }
    }

    #[test]
    fn new_sorts_and_dedups_ports() {
        let p = HttpProber::new(
            vec![80, 22, 80, 443, 22],
            HttpScheme::Auto,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        assert_eq!(p.ports(), &[22, 80, 443]);
    }

    #[test]
    fn kind_returns_http() {
        let p = HttpProber::new(
            vec![80],
            HttpScheme::Auto,
            default_path(),
            default_tls_verify(),
            default_user_agent(),
        )
        .expect("valid");
        assert_eq!(p.kind(), ProbeKind::Http);
    }

    #[test]
    fn truncate_banner_handles_multibyte_boundary() {
        // 3-byte codepoints. Byte 256 lands inside the 3rd byte of the 86th
        // character (offsets 255..=257 belong to that char), so walkback must
        // step back to byte 255 — the previous char boundary.
        let input = "€".repeat(120);
        assert_eq!(input.len(), 360);
        assert!(!input.is_char_boundary(BANNER_MAX_BYTES));
        let out = truncate_banner(&input);
        assert!(
            out.len() < BANNER_MAX_BYTES,
            "walkback must have trimmed below 256 bytes, got {}",
            out.len()
        );
        assert_eq!(
            out.len(),
            255,
            "expected walkback to stop at the previous boundary"
        );
        assert!(
            std::str::from_utf8(out.as_bytes()).is_ok(),
            "output must be valid UTF-8"
        );
    }

    #[test]
    fn http_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<HttpProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }
}
