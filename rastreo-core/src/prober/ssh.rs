use std::borrow::Cow;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use russh::client::{Config, Handler};
use russh::keys::ssh_key::PublicKey;
use russh::{cipher, kex, mac, Preferred};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::ports::{probe_ports, MAX_PORTS_IN_FLIGHT};
use crate::prober::Prober;

const BANNER_MAX_BYTES: usize = 256;

pub struct SshProber {
    ports: Vec<u16>,
}

impl SshProber {
    pub fn new(ports: Vec<u16>) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("ssh prober requires at least one port").into());
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Ok(Self { ports })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
}

/// Serde default for `ProberConfig::Ssh.ports` — `[22]`.
pub fn default_ports() -> Vec<u16> {
    vec![22]
}

struct CaptureHandler {
    slot: Arc<Mutex<Option<String>>>,
}

impl Handler for CaptureHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        if let Ok(encoded) = server_public_key.to_openssh() {
            if let Ok(mut guard) = self.slot.lock() {
                *guard = Some(encoded);
            }
        }
        Ok(true)
    }
}

async fn read_banner_from_stream(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; BANNER_MAX_BYTES];
    let mut filled = 0usize;
    while filled < BANNER_MAX_BYTES {
        let n = stream.read(&mut buf[filled..]).await.ok()?;
        if n == 0 {
            break;
        }
        filled += n;
        if let Some(end) = find_line_terminator(&buf[..filled]) {
            let line = std::str::from_utf8(&buf[..end])
                .ok()?
                .trim_end_matches('\r');
            if line.starts_with("SSH-") {
                return Some(line.to_string());
            }
            return None;
        }
    }
    None
}

fn find_line_terminator(bytes: &[u8]) -> Option<usize> {
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            return Some(i);
        }
    }
    None
}

fn extend_offer<T: Copy + PartialEq>(base: Cow<'static, [T]>, legacy: &[T]) -> Cow<'static, [T]> {
    let mut offered = base.into_owned();
    for &name in legacy {
        if !offered.contains(&name) {
            offered.push(name);
        }
    }
    Cow::Owned(offered)
}

// Legacy KEX/cipher/MAC are offered last so a legacy-only SSH server completes this read-only, unauthenticated host-key handshake.
fn fingerprinting_preferred() -> Preferred {
    let base = Preferred::DEFAULT;
    Preferred {
        kex: extend_offer(
            base.kex,
            &[kex::DH_G14_SHA1, kex::DH_G1_SHA1, kex::DH_GEX_SHA1],
        ),
        cipher: extend_offer(
            base.cipher,
            &[
                cipher::AES_256_CBC,
                cipher::AES_192_CBC,
                cipher::AES_128_CBC,
            ],
        ),
        mac: extend_offer(base.mac, &[mac::HMAC_SHA1_ETM, mac::HMAC_SHA1]),
        key: base.key,
        compression: base.compression,
    }
}

async fn read_host_key(addr: SocketAddr) -> Option<String> {
    let config = Arc::new(Config {
        client_id: russh::SshId::Standard(
            concat!("SSH-2.0-rastreo_", env!("CARGO_PKG_VERSION")).into(),
        ),
        preferred: fingerprinting_preferred(),
        ..Config::default()
    });
    let slot: Arc<Mutex<Option<String>>> = Arc::default();
    let handler = CaptureHandler {
        slot: Arc::clone(&slot),
    };
    let handle = russh::client::connect(config, addr, handler).await.ok()?;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "en-US")
        .await;
    let mut guard = slot.lock().ok()?;
    guard.take()
}

// A peer that is not listening is absence; a local socket failure is a broken probe.
fn connect_fault(port: u16, err: &io::Error) -> Option<ProbeFault> {
    match classify::io_error(err) {
        Disposition::Fault(kind) => Some(ProbeFault::new(
            kind,
            format!("ssh connect failed on port {port}: {err}"),
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
    // An open port emits `OpenPort` before anything else, so signals are empty exactly when no
    // port answered. Silence on one port is not evidence against a fault on another.
    let reachable = !signals.is_empty();
    let fault = if reachable { None } else { last_fault };
    ProbeOutcome {
        kind: ProbeKind::Ssh,
        target_ip,
        timestamp: SystemTime::now(),
        reachable,
        signals,
        fault,
    }
}

#[async_trait::async_trait]
impl Prober for SshProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Ssh
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
                let addr = SocketAddr::new(target.ip, port);
                async move {
                    let mut port_signals = Vec::new();
                    let mut port_fault: Option<ProbeFault> = None;

                    let outcome = timeout(ctx.timeout, TcpStream::connect(addr)).await;
                    if let Some(mut stream) =
                        fold_connect(port, outcome, &mut port_signals, &mut port_fault)
                    {
                        if let Ok(Some(banner)) =
                            timeout(ctx.timeout, read_banner_from_stream(&mut stream)).await
                        {
                            port_signals.push(Signal::SshBanner(banner));
                        }
                        // russh opens its own stream: once we've consumed the peer SSH-ID
                        // above, this one cannot be reused for the key-exchange handshake.
                        drop(stream);

                        if let Ok(Some(host_key)) = timeout(ctx.timeout, read_host_key(addr)).await
                        {
                            port_signals.push(Signal::SshHostKey(host_key));
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
    use std::net::{IpAddr, Ipv4Addr};

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

    #[test]
    fn new_rejects_empty_ports() {
        match SshProber::new(Vec::new()) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("at least one port"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty ports must error"),
        }
    }

    #[test]
    fn new_dedups_and_sorts_ports() {
        let p = SshProber::new(vec![2222, 22, 2222, 22]).expect("valid");
        assert_eq!(p.ports(), &[22, 2222]);
    }

    #[test]
    fn default_ports_is_22() {
        assert_eq!(default_ports(), vec![22]);
    }

    #[test]
    fn ports_getter_returns_configured_ports() {
        let p = SshProber::new(vec![22, 2022]).expect("valid");
        assert_eq!(p.ports(), &[22, 2022]);
    }

    #[test]
    fn probe_kind_returns_ssh() {
        let p = SshProber::new(vec![22]).expect("valid");
        assert_eq!(p.kind(), ProbeKind::Ssh);
    }

    #[test]
    fn fingerprinting_offer_appends_legacy_algorithms_after_modern() {
        let offer = fingerprinting_preferred();
        let kex: Vec<&str> = offer.kex.iter().map(|n| n.as_ref()).collect();
        let cipher: Vec<&str> = offer.cipher.iter().map(|n| n.as_ref()).collect();
        let mac: Vec<&str> = offer.mac.iter().map(|n| n.as_ref()).collect();

        assert!(kex.contains(&"diffie-hellman-group14-sha1"), "kex: {kex:?}");
        assert!(cipher.contains(&"aes128-cbc"), "cipher: {cipher:?}");
        assert!(cipher.contains(&"aes256-cbc"), "cipher: {cipher:?}");
        assert!(mac.contains(&"hmac-sha1"), "mac: {mac:?}");

        let pos = |offer: &[&str], name: &str| {
            offer
                .iter()
                .position(|n| *n == name)
                .unwrap_or_else(|| panic!("{name} missing from {offer:?}"))
        };
        assert!(
            pos(&kex, "curve25519-sha256") < pos(&kex, "diffie-hellman-group14-sha1"),
            "modern KEX must be offered before legacy: {kex:?}"
        );
        assert!(
            pos(&cipher, "chacha20-poly1305@openssh.com") < pos(&cipher, "aes128-cbc"),
            "modern cipher must be offered before legacy: {cipher:?}"
        );
        assert!(
            pos(&mac, "hmac-sha2-256") < pos(&mac, "hmac-sha1"),
            "modern MAC must be offered before legacy: {mac:?}"
        );
    }

    #[test]
    fn find_line_terminator_locates_newline() {
        assert_eq!(find_line_terminator(b"SSH-2.0-OpenSSH\r\nrest"), Some(16));
        assert_eq!(find_line_terminator(b"SSH-2.0-Test\n"), Some(12));
        assert_eq!(find_line_terminator(b"no terminator here"), None);
    }

    #[tokio::test]
    async fn probe_reports_no_signal_for_closed_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let prober = SshProber::new(vec![port]).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(500), 0);
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert_eq!(outcome.kind, ProbeKind::Ssh);
    }

    #[tokio::test]
    async fn probe_captures_banner_from_stub_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(b"SSH-2.0-StubServer_1.0\r\n").await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let prober = SshProber::new(vec![port]).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(500), 0);
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        let banner = outcome
            .signals
            .iter()
            .find_map(|s| match s {
                Signal::SshBanner(b) => Some(b.as_str()),
                _ => None,
            })
            .expect("banner captured");
        assert_eq!(banner, "SSH-2.0-StubServer_1.0");
    }

    async fn spawn_ssh_banner_stub() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(b"SSH-2.0-StubServer_1.0\r\n").await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn ssh_probe_emits_open_port_on_successful_connect() {
        let port = spawn_ssh_banner_stub().await;
        let prober = SshProber::new(vec![port]).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(500), 0);
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
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
    async fn ssh_probe_emits_open_port_before_protocol_signals() {
        let port = spawn_ssh_banner_stub().await;
        let prober = SshProber::new(vec![port]).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(500), 0);
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        let open_port_idx = outcome
            .signals
            .iter()
            .position(|s| matches!(s, Signal::OpenPort(_)))
            .expect("OpenPort emitted");
        let banner_idx = outcome
            .signals
            .iter()
            .position(|s| matches!(s, Signal::SshBanner(_)));
        if let Some(idx) = banner_idx {
            assert!(open_port_idx < idx, "OpenPort must precede SshBanner");
        }
    }

    #[tokio::test]
    async fn ssh_probe_does_not_emit_open_port_on_connect_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let prober = SshProber::new(vec![port]).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(500), 0);
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(!outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::OpenPort(_))));
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));

    #[test]
    fn a_local_socket_failure_on_connect_latches_a_fault() {
        let fault = connect_fault(22, &io::Error::from(io::ErrorKind::PermissionDenied))
            .expect("a denied local socket is a broken probe");
        assert!(
            fault.detail.contains("ssh connect failed on port 22"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn a_refused_connect_latches_no_fault() {
        assert!(connect_fault(22, &io::Error::from(io::ErrorKind::ConnectionRefused)).is_none());
    }

    async fn elapsed() -> Elapsed {
        timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("a zero deadline on a pending future always elapses")
    }

    #[tokio::test]
    async fn a_connect_that_succeeds_emits_an_open_port_and_yields_the_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let stream = TcpStream::connect(("127.0.0.1", port)).await;
        let mut signals = Vec::new();
        let mut last_fault = None;

        let held = fold_connect(port, Ok(stream), &mut signals, &mut last_fault);

        assert!(held.is_some(), "the banner read needs the connected stream");
        assert!(matches!(signals.as_slice(), [Signal::OpenPort(p)] if *p == port));
        assert!(last_fault.is_none());
    }

    #[tokio::test]
    async fn a_connect_that_is_refused_emits_nothing() {
        let mut signals = Vec::new();
        let mut last_fault = None;

        let held = fold_connect(
            22,
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
            22,
            Ok(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            &mut signals,
            &mut last_fault,
        );

        assert!(held.is_none());
        assert!(signals.is_empty());
        let fault = last_fault.expect("a denied local socket is a broken probe");
        assert!(
            fault.detail.contains("ssh connect failed on port 22"),
            "got: {}",
            fault.detail
        );
    }

    #[tokio::test]
    async fn a_connect_that_times_out_emits_nothing() {
        let mut signals = Vec::new();
        let mut last_fault = None;

        let held = fold_connect(22, Err(elapsed().await), &mut signals, &mut last_fault);

        assert!(held.is_none());
        assert!(signals.is_empty());
        assert!(last_fault.is_none());
    }

    #[test]
    fn an_open_port_is_a_reachable_outcome() {
        let outcome = build_outcome(
            TARGET,
            vec![
                Signal::OpenPort(22),
                Signal::SshBanner("SSH-2.0-OpenSSH_9.6".to_string()),
            ],
            None,
        );
        assert!(outcome.reachable);
        assert_eq!(outcome.kind, ProbeKind::Ssh);
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
            vec![Signal::OpenPort(22)],
            Some(sample_fault(
                "ssh connect failed on port 2222: too many open files",
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
                "ssh connect failed on port 22: too many open files",
            )),
        );
        assert!(!outcome.reachable);
        let fault = outcome.fault.expect("a broken probe surfaces its fault");
        assert!(
            fault.detail.contains("ssh connect failed on port 22"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn ssh_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<SshProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[tokio::test]
    async fn probe_opens_at_most_two_tcp_connections_per_port() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                accepts_task.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(b"SSH-2.0-StubServer_1.0\r\n").await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let prober = SshProber::new(vec![port]).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(500), 0);
        let _ = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let n = accepts.load(Ordering::SeqCst);
        assert!(
            n <= 2,
            "SSH probe opened {n} TCP connections per port; contract is at most 2 \
             (one for banner, one for russh host-key exchange)"
        );
    }

    async fn spawn_hanging_ssh_stub() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        tokio::spawn(async move {
                            let _hold = stream;
                            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        });
                    }
                    Err(_) => return,
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn probe_reports_open_and_closed_ports_in_a_mix() {
        let open_port = spawn_ssh_banner_stub().await;
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let closed_port = closed_listener.local_addr().expect("addr").port();
        drop(closed_listener);
        let prober = SshProber::new(vec![open_port, closed_port]).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(500), 0);
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        let open: Vec<u16> = outcome
            .signals
            .iter()
            .filter_map(|s| match s {
                Signal::OpenPort(p) => Some(*p),
                _ => None,
            })
            .collect();
        assert_eq!(open, vec![open_port]);
    }

    #[tokio::test]
    async fn probe_collects_open_ports_in_ascending_port_order() {
        let mut ports = Vec::new();
        for _ in 0..3 {
            ports.push(spawn_ssh_banner_stub().await);
        }
        let prober = SshProber::new(ports.clone()).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(500), 0);
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
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
            ports.push(spawn_hanging_ssh_stub().await);
        }
        let prober = SshProber::new(ports).expect("valid");
        let ctx = ProbeCtx::new(std::time::Duration::from_millis(100), 0);
        let start = std::time::Instant::now();
        let _ = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "four hanging ports serially would be ~800ms; concurrent stays near 1x: {elapsed:?}"
        );
    }
}
