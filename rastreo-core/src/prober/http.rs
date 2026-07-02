use std::time::SystemTime;

use crate::error::{ConfigError, ProbeError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

const BANNER_MAX_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
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
        path: Option<String>,
        tls_verify: Option<bool>,
        user_agent: Option<String>,
    ) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("http prober requires at least one port").into());
        }
        let path = path.unwrap_or_else(|| "/".to_string());
        if !path.starts_with('/') {
            return Err(ConfigError::invalid("http prober path must start with /").into());
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();

        let user_agent =
            user_agent.unwrap_or_else(|| format!("rastreo/{}", env!("CARGO_PKG_VERSION")));
        let tls_verify = tls_verify.unwrap_or(false);

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

fn is_tls_error(err: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(current) = source {
        let msg = current.to_string().to_ascii_lowercase();
        if msg.contains("tls")
            || msg.contains("handshake")
            || msg.contains("certificate")
            || msg.contains("rustls")
            || msg.contains("corrupt message")
            || msg.contains("invalidcontenttype")
            || msg.contains("peer sent")
            || msg.contains("alert")
        {
            return true;
        }
        source = current.source();
    }
    false
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
        let mut any_reachable = false;
        let mut last_error: Option<ProbeError> = None;

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
                    any_reachable = true;
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
                    last_error = Some(if reqwest_err.is_timeout() {
                        ProbeError::Timeout {
                            timeout_ms: ctx.timeout.as_millis() as u64,
                        }
                    } else if reqwest_err.is_connect() && !is_tls_error(&reqwest_err) {
                        ProbeError::Unreachable {
                            target: target.ip.to_string(),
                        }
                    } else {
                        ProbeError::Other(format!(
                            "http probe failed on port {port}: {reqwest_err}"
                        ))
                    });
                }
                Err(_) => {
                    last_error = Some(ProbeError::Timeout {
                        timeout_ms: ctx.timeout.as_millis() as u64,
                    });
                }
            }
        }

        if !any_reachable {
            if let Some(err) = last_error {
                return Err(err.into());
            }
        }

        Ok(ProbeOutcome {
            kind: ProbeKind::Http,
            target_ip: target.ip,
            timestamp: SystemTime::now(),
            reachable: any_reachable,
            signals,
        })
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
        let prober =
            HttpProber::new(vec![port], HttpScheme::Http, None, None, None).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(&outcome.signals[0], Signal::HttpBanner(b) if b == "nginx/1.24.0"));
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
        let prober =
            HttpProber::new(vec![port], HttpScheme::Http, None, None, None).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(&outcome.signals[0], Signal::HttpBanner(b) if b == "Apache/2.4.62"));
    }

    #[tokio::test]
    async fn http_prober_no_server_header_emits_no_signal() {
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let prober =
            HttpProber::new(vec![port], HttpScheme::Http, None, None, None).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn http_prober_maps_connection_refused_to_unreachable_error() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let prober =
            HttpProber::new(vec![port], HttpScheme::Http, None, None, None).expect("valid");
        let err = prober
            .probe(&loopback_target(), &ctx_with_timeout(500))
            .await
            .expect_err("must error");
        match err {
            RastreoError::Probe(ProbeError::Unreachable { target }) => {
                assert_eq!(target, "127.0.0.1");
            }
            RastreoError::Probe(ProbeError::Timeout { timeout_ms }) => {
                assert_eq!(
                    timeout_ms, 500,
                    "if timeout fires, it must be the configured 500ms"
                );
            }
            other => panic!("expected Unreachable or Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_prober_maps_timeout_to_timeout_error() {
        let port = spawn_hanging_server().await;
        let prober =
            HttpProber::new(vec![port], HttpScheme::Http, None, None, None).expect("valid");
        let err = prober
            .probe(&loopback_target(), &ctx_with_timeout(100))
            .await
            .expect_err("must time out");
        match err {
            RastreoError::Probe(ProbeError::Timeout { timeout_ms }) => {
                assert_eq!(timeout_ms, 100);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
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
        let prober =
            HttpProber::new(vec![port], HttpScheme::Http, None, None, None).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert_eq!(outcome.signals.len(), 1);
        match &outcome.signals[0] {
            Signal::HttpBanner(b) => assert_eq!(b.len(), 256, "banner: {b}"),
            other => panic!("expected HttpBanner, got {other:?}"),
        }
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
        let prober =
            HttpProber::new(vec![port], HttpScheme::Http, None, None, None).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(&outcome.signals[0], Signal::HttpBanner(b) if b == "nginx"));
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
        let prober =
            HttpProber::new(vec![port], HttpScheme::Http, None, None, None).expect("valid");
        let outcome = prober
            .probe(&target, &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(matches!(
            outcome.signals.first(),
            Some(Signal::HttpBanner(s)) if s == "nginx-v6/1.0"
        ));
    }

    #[tokio::test]
    async fn http_prober_maps_tls_mismatch_to_other_error() {
        // Speak plain HTTP on the server; probe as HTTPS. The client attempts
        // a TLS handshake against a plaintext socket, which fails inside
        // rustls after the TCP connect succeeded. That's distinct from a
        // genuinely closed port.
        let port = spawn_server(Arc::new(|_req| {
            Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("ok")))
                .expect("response")
        }))
        .await;
        let prober =
            HttpProber::new(vec![port], HttpScheme::Https, None, None, None).expect("valid");
        let err = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect_err("TLS handshake against plain HTTP must fail");
        match err {
            RastreoError::Probe(ProbeError::Other(msg)) => {
                assert!(
                    msg.contains("http probe failed"),
                    "message should carry the probe context, got: {msg}"
                );
            }
            other => panic!("expected ProbeError::Other for TLS/protocol mismatch, got {other:?}"),
        }
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
        match HttpProber::new(Vec::new(), HttpScheme::Auto, None, None, None) {
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
            Some("no-slash".into()),
            None,
            None,
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
            None,
            None,
            None,
        )
        .expect("valid");
        assert_eq!(p.ports(), &[22, 80, 443]);
    }

    #[test]
    fn kind_returns_http() {
        let p = HttpProber::new(vec![80], HttpScheme::Auto, None, None, None).expect("valid");
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
