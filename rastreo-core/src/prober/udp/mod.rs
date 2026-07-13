//! UDP prober with protocol-specific payloads. Ships NTP, SIP OPTIONS, memcached stats, STUN.

pub mod memcached;
pub mod ntp;
pub mod sip;
pub mod stun;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use crate::error::{ConfigError, ProbeErrorKind, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::Prober;

const RECV_BUF_LEN: usize = 4096;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UdpProtocol {
    Ntp,
    SipOptions,
    MemcachedStats,
    StunBinding,
}

#[derive(Debug)]
pub struct UdpProber {
    ports: Vec<u16>,
    protocol: UdpProtocol,
}

impl UdpProber {
    pub fn new(ports: Vec<u16>, protocol: UdpProtocol) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("udp prober requires at least one port").into());
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Ok(Self { ports, protocol })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    pub fn protocol(&self) -> UdpProtocol {
        self.protocol
    }
}

enum PortOutcome {
    Reached(Option<Signal>),
    Timeout,
    Unreachable,
    Other(ProbeErrorKind, String),
}

async fn probe_port(target_addr: SocketAddr, protocol: UdpProtocol, ctx: &ProbeCtx) -> PortOutcome {
    let bind_addr = if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            return PortOutcome::Other(ProbeErrorKind::Other, format!("udp bind failed: {e}"))
        }
    };
    let stun_txid = new_stun_transaction_id(target_addr.port());
    let sip_call_id = new_sip_call_id(target_addr.port());
    let memcached_request_id = new_memcached_request_id(target_addr.port());
    let payload: Vec<u8> = match protocol {
        UdpProtocol::Ntp => ntp::build_request(),
        UdpProtocol::SipOptions => {
            sip::build_request(target_addr.ip(), target_addr.port(), sip_call_id)
        }
        UdpProtocol::MemcachedStats => memcached::build_request(memcached_request_id),
        UdpProtocol::StunBinding => stun::build_request(stun_txid),
    };
    let mut buf = vec![0u8; RECV_BUF_LEN];
    // Split the timeout across attempts so retransmits stay inside the same total per-probe deadline.
    let per_attempt = crate::prober::per_attempt_timeout(ctx.timeout, ctx.retries);
    let overall_deadline = tokio::time::Instant::now() + ctx.timeout;
    for _ in 0..=ctx.retries {
        if let Err(e) = socket.send_to(&payload, target_addr).await {
            return classify_io_error(&e);
        }
        let attempt_deadline = (tokio::time::Instant::now() + per_attempt).min(overall_deadline);
        loop {
            match tokio::time::timeout_at(attempt_deadline, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    if peer.ip() != target_addr.ip() {
                        continue;
                    }
                    let bytes = &buf[..n];
                    let signal = match protocol {
                        UdpProtocol::Ntp => ntp::parse_response(bytes),
                        UdpProtocol::SipOptions => sip::parse_response(bytes),
                        UdpProtocol::MemcachedStats => memcached::parse_response(bytes),
                        UdpProtocol::StunBinding => stun::parse_response(bytes, &stun_txid),
                    };
                    return PortOutcome::Reached(signal);
                }
                Ok(Err(e)) => return classify_io_error(&e),
                Err(_) => break,
            }
        }
        if tokio::time::Instant::now() >= overall_deadline {
            break;
        }
    }
    PortOutcome::Timeout
}

fn classify_io_error(err: &io::Error) -> PortOutcome {
    match classify::io_error(err) {
        Disposition::Absence if err.kind() == io::ErrorKind::TimedOut => PortOutcome::Timeout,
        Disposition::Absence => PortOutcome::Unreachable,
        Disposition::Fault(kind) => PortOutcome::Other(kind, err.to_string()),
    }
}

fn new_stun_transaction_id(port: u16) -> [u8; stun::TRANSACTION_ID_LEN] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut out = [0u8; stun::TRANSACTION_ID_LEN];
    let mixed = nanos ^ ((port as u128) << 96);
    let bytes = mixed.to_be_bytes();
    out.copy_from_slice(&bytes[0..stun::TRANSACTION_ID_LEN]);
    out
}

fn new_sip_call_id(port: u16) -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ ((port as u64) << 48)
}

fn new_memcached_request_id(port: u16) -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    (nanos as u16) ^ port
}

// A port that timed out or answered ICMP-unreachable is a discovery result; a local socket
// failure is a broken probe.
fn port_fault(port: u16, outcome: &PortOutcome) -> Option<ProbeFault> {
    match outcome {
        PortOutcome::Other(kind, msg) => Some(ProbeFault::new(
            *kind,
            format!("udp probe failed on port {port}: {msg}"),
        )),
        PortOutcome::Reached(_) | PortOutcome::Timeout | PortOutcome::Unreachable => None,
    }
}

fn build_outcome(
    target_ip: IpAddr,
    any_reachable: bool,
    signals: Vec<Signal>,
    last_fault: Option<ProbeFault>,
) -> ProbeOutcome {
    // Silence on one port is not evidence against a fault on another, but a port that answered is.
    let fault = if any_reachable { None } else { last_fault };
    ProbeOutcome {
        kind: ProbeKind::Udp,
        target_ip,
        timestamp: SystemTime::now(),
        reachable: any_reachable,
        signals,
        fault,
    }
}

#[async_trait::async_trait]
impl Prober for UdpProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Udp
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let mut signals = Vec::new();
        let mut any_reachable = false;
        let mut last_fault: Option<ProbeFault> = None;

        for &port in &self.ports {
            let addr = SocketAddr::new(target.ip, port);
            let outcome = probe_port(addr, self.protocol, ctx).await;
            if let Some(fault) = port_fault(port, &outcome) {
                last_fault = Some(fault);
            }
            if let PortOutcome::Reached(signal) = outcome {
                any_reachable = true;
                if let Some(s) = signal {
                    signals.push(s);
                }
            }
        }

        Ok(build_outcome(target.ip, any_reachable, signals, last_fault))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::model::Target;

    fn loopback_target() -> ResolvedTarget {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn ctx_with_timeout(ms: u64) -> ProbeCtx {
        ProbeCtx {
            timeout: Duration::from_millis(ms),
            retries: 0,
        }
    }

    type Responder = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static>;

    async fn spawn_server_bound_to(bind: &str, responder: Responder) -> io::Result<u16> {
        let socket = UdpSocket::bind(bind).await?;
        let port = socket.local_addr()?.port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_LEN];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                if let Some(resp) = responder(&buf[..n]) {
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });
        Ok(port)
    }

    fn ntp_response(stratum: u8, ref_id: [u8; 4]) -> Vec<u8> {
        let mut buf = vec![0u8; 48];
        buf[0] = (4 << 3) | 4; // VN=4, Mode=4 (server)
        buf[1] = stratum;
        buf[12..16].copy_from_slice(&ref_id);
        buf
    }

    #[tokio::test]
    async fn udp_prober_ntp_end_to_end_captures_stratum() {
        let port = spawn_server_bound_to(
            "127.0.0.1:0",
            Arc::new(|_req| Some(ntp_response(2, [203, 0, 113, 1]))),
        )
        .await
        .expect("bind");
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(
            &outcome.signals[0],
            Signal::NtpBanner(s) if s == "stratum=2 ref=203.0.113.1"
        ));
        assert_eq!(outcome.kind, ProbeKind::Udp);
    }

    #[tokio::test]
    async fn udp_prober_sip_end_to_end_captures_user_agent() {
        let port = spawn_server_bound_to(
            "127.0.0.1:0",
            Arc::new(|_req| {
                let body = "SIP/2.0 200 OK\r\nServer: Kamailio/5.6.5 (x86_64/linux)\r\nContent-Length: 0\r\n\r\n";
                Some(body.as_bytes().to_vec())
            }),
        )
        .await
        .expect("bind");
        let prober = UdpProber::new(vec![port], UdpProtocol::SipOptions).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(
            &outcome.signals[0],
            Signal::SipUserAgent(s) if s == "Kamailio/5.6.5 (x86_64/linux)"
        ));
    }

    #[tokio::test]
    async fn udp_prober_memcached_end_to_end_captures_version() {
        let port = spawn_server_bound_to(
            "127.0.0.1:0",
            Arc::new(|req| {
                if req.len() < memcached::FRAME_HEADER_LEN {
                    return None;
                }
                if &req[memcached::FRAME_HEADER_LEN..] != b"stats\r\n" {
                    return None;
                }
                let mut resp = Vec::new();
                resp.extend_from_slice(&req[0..2]); // echo request ID
                resp.extend_from_slice(&0u16.to_be_bytes()); // sequence
                resp.extend_from_slice(&1u16.to_be_bytes()); // total datagrams
                resp.extend_from_slice(&0u16.to_be_bytes()); // reserved
                resp.extend_from_slice(b"STAT pid 1\r\nSTAT version 1.6.24\r\nEND\r\n");
                Some(resp)
            }),
        )
        .await
        .expect("bind");
        let prober = UdpProber::new(vec![port], UdpProtocol::MemcachedStats).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(
            &outcome.signals[0],
            Signal::MemcachedVersion(s) if s == "1.6.24"
        ));
    }

    #[tokio::test]
    async fn udp_prober_stun_end_to_end_captures_mapped_address() {
        let port = spawn_server_bound_to(
            "127.0.0.1:0",
            Arc::new(|req| {
                if req.len() < stun::HEADER_LEN {
                    return None;
                }
                // Echo transaction ID from request; craft a Binding Success with XOR-MAPPED-ADDRESS.
                let mut tid = [0u8; stun::TRANSACTION_ID_LEN];
                tid.copy_from_slice(&req[8..20]);
                let port_out: u16 = 54321;
                let ip = Ipv4Addr::new(203, 0, 113, 42);
                let x_port = port_out ^ ((stun::MAGIC_COOKIE >> 16) as u16);
                let x_addr = u32::from(ip) ^ stun::MAGIC_COOKIE;
                let mut attr = Vec::new();
                attr.extend_from_slice(&0x0020u16.to_be_bytes());
                attr.extend_from_slice(&8u16.to_be_bytes());
                attr.push(0);
                attr.push(0x01);
                attr.extend_from_slice(&x_port.to_be_bytes());
                attr.extend_from_slice(&x_addr.to_be_bytes());

                let mut resp = Vec::new();
                resp.extend_from_slice(&0x0101u16.to_be_bytes());
                resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
                resp.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
                resp.extend_from_slice(&tid);
                resp.extend_from_slice(&attr);
                Some(resp)
            }),
        )
        .await
        .expect("bind");
        let prober = UdpProber::new(vec![port], UdpProtocol::StunBinding).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(
            &outcome.signals[0],
            Signal::StunMappedAddress(s) if s == "203.0.113.42:54321"
        ));
    }

    #[tokio::test]
    async fn udp_prober_maps_all_timeouts_to_unreachable_outcome() {
        // Bind a socket that swallows requests and never replies.
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let _hold = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let _ = socket.recv_from(&mut buf).await;
            }
        });
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(200))
            .await
            .expect("a silent host is an outcome, not an error");
        assert_eq!(outcome.kind, ProbeKind::Udp);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn udp_prober_maps_closed_port_to_unreachable_outcome() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        drop(socket);
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(500))
            .await
            .expect("a closed port is an outcome, not an error");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn udp_prober_marks_reachable_on_unrecognized_response() {
        let port = spawn_server_bound_to(
            "127.0.0.1:0",
            Arc::new(|_req| Some(vec![0xDE, 0xAD, 0xBE, 0xEF])),
        )
        .await
        .expect("bind");
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(1_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn udp_prober_ipv6_target() {
        let port = match spawn_server_bound_to(
            "[::1]:0",
            Arc::new(|_req| Some(ntp_response(3, [198, 51, 100, 5]))),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skipping IPv6 test: IPv6 loopback bind failed: {e}");
                return;
            }
        };
        let ip: IpAddr = "::1".parse().expect("::1");
        let target = ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&target, &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(matches!(
            outcome.signals.first(),
            Some(Signal::NtpBanner(s)) if s == "stratum=3 ref=198.51.100.5"
        ));
    }

    #[tokio::test]
    async fn udp_prober_multi_port_probes_all_ports() {
        let port_a = spawn_server_bound_to(
            "127.0.0.1:0",
            Arc::new(|_req| Some(ntp_response(1, *b"GPS "))),
        )
        .await
        .expect("bind a");
        let port_b = spawn_server_bound_to(
            "127.0.0.1:0",
            Arc::new(|_req| Some(ntp_response(2, [10, 0, 0, 1]))),
        )
        .await
        .expect("bind b");
        let prober = UdpProber::new(vec![port_a, port_b], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert_eq!(outcome.signals.len(), 2);
    }

    #[test]
    fn classify_io_error_maps_absence_kinds_to_absence_outcomes() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
        ] {
            let outcome = classify_io_error(&io::Error::from(kind));
            assert!(
                matches!(outcome, PortOutcome::Timeout | PortOutcome::Unreachable),
                "{kind:?} must be absence, not a fault"
            );
        }
    }

    #[test]
    fn classify_io_error_maps_unclassified_kinds_to_fault() {
        let outcome = classify_io_error(&io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(matches!(
            outcome,
            PortOutcome::Other(ProbeErrorKind::PermissionDenied, _)
        ));
    }

    #[test]
    fn new_rejects_empty_ports() {
        match UdpProber::new(Vec::new(), UdpProtocol::Ntp) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("port"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn new_sorts_and_dedups_ports() {
        let prober = UdpProber::new(vec![5060, 123, 5060, 3478], UdpProtocol::Ntp).expect("valid");
        assert_eq!(prober.ports(), &[123, 3478, 5060]);
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

    #[test]
    fn a_local_socket_failure_latches_a_fault() {
        let outcome = classify_io_error(&io::Error::from(io::ErrorKind::PermissionDenied));
        let fault = port_fault(123, &outcome).expect("a denied local socket is a broken probe");
        assert_eq!(fault.kind, ProbeErrorKind::PermissionDenied);
        assert!(
            fault.detail.contains("udp probe failed on port 123"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn a_silent_or_unreachable_port_latches_no_fault() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::HostUnreachable,
        ] {
            let outcome = classify_io_error(&io::Error::from(kind));
            assert!(port_fault(123, &outcome).is_none(), "{kind:?}");
        }
        assert!(port_fault(123, &PortOutcome::Reached(None)).is_none());
    }

    fn sample_fault(detail: &str) -> ProbeFault {
        ProbeFault::new(ProbeErrorKind::Other, detail.to_string())
    }

    #[test]
    fn a_port_that_answered_is_a_reachable_outcome() {
        let outcome = build_outcome(
            TARGET,
            true,
            vec![Signal::NtpBanner("stratum=2 ref=10.0.0.1".to_string())],
            None,
        );
        assert!(outcome.reachable);
        assert_eq!(outcome.kind, ProbeKind::Udp);
        assert_eq!(outcome.signals.len(), 1);
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn a_port_that_answered_outranks_a_socket_fault_on_another_port() {
        let outcome = build_outcome(
            TARGET,
            true,
            Vec::new(),
            Some(sample_fault(
                "udp probe failed on port 5060: permission denied",
            )),
        );
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn no_answer_and_no_fault_is_an_absent_target() {
        let outcome = build_outcome(TARGET, false, Vec::new(), None);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn no_answer_and_a_socket_fault_is_a_kinded_fault_outcome() {
        let outcome = build_outcome(
            TARGET,
            false,
            Vec::new(),
            Some(sample_fault(
                "udp probe failed on port 123: permission denied",
            )),
        );
        assert!(!outcome.reachable);
        let fault = outcome.fault.expect("a broken probe surfaces its fault");
        assert!(
            fault.detail.contains("udp probe failed on port 123"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn udp_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<UdpProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[test]
    fn kind_returns_udp() {
        let prober = UdpProber::new(vec![123], UdpProtocol::Ntp).expect("valid");
        assert_eq!(prober.kind(), ProbeKind::Udp);
    }

    #[test]
    fn udp_protocol_deserializes_snake_case() {
        for (input, expected) in [
            ("ntp", UdpProtocol::Ntp),
            ("sip_options", UdpProtocol::SipOptions),
            ("memcached_stats", UdpProtocol::MemcachedStats),
            ("stun_binding", UdpProtocol::StunBinding),
        ] {
            let parsed: UdpProtocol = serde_json::from_str(&format!("\"{input}\""))
                .unwrap_or_else(|e| panic!("deserialize {input}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn accessors_expose_configuration() {
        let prober = UdpProber::new(vec![5060], UdpProtocol::SipOptions).expect("valid");
        assert_eq!(prober.ports(), &[5060]);
        assert_eq!(prober.protocol(), UdpProtocol::SipOptions);
    }

    fn ctx_with_retries(ms: u64, retries: u32) -> ProbeCtx {
        ProbeCtx {
            timeout: Duration::from_millis(ms),
            retries,
        }
    }

    async fn spawn_ntp_server_dropping(drop_first: usize) -> (u16, Arc<AtomicUsize>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let received = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&received);
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_LEN];
            loop {
                let (_n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let count = seen.fetch_add(1, Ordering::SeqCst) + 1;
                if count <= drop_first {
                    continue;
                }
                let _ = socket
                    .send_to(&ntp_response(2, [203, 0, 113, 1]), peer)
                    .await;
            }
        });
        (port, received)
    }

    #[tokio::test]
    async fn udp_retries_zero_issues_exactly_one_datagram() {
        let (port, received) = spawn_ntp_server_dropping(usize::MAX).await;
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(200, 0))
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert_eq!(
            received.load(Ordering::SeqCst),
            1,
            "retries=0 must send a single datagram"
        );
    }

    #[tokio::test]
    async fn udp_retransmit_recovers_when_first_packets_are_dropped() {
        let (port, _received) = spawn_ntp_server_dropping(2).await;
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(900, 2))
            .await
            .expect("probe ok");
        assert!(
            outcome.reachable,
            "the third attempt reaches the server after two dropped datagrams"
        );
        assert_eq!(outcome.signals.len(), 1);
    }

    #[tokio::test]
    async fn udp_without_retries_reports_absent_when_first_packet_dropped() {
        let (port, _received) = spawn_ntp_server_dropping(1).await;
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(300, 0))
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.fault.is_none());
    }

    #[tokio::test]
    async fn udp_exhausted_retries_is_absence_not_fault() {
        let (port, received) = spawn_ntp_server_dropping(usize::MAX).await;
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(300, 2))
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.fault.is_none());
        assert_eq!(
            received.load(Ordering::SeqCst),
            3,
            "retries=2 sends the first datagram plus two retransmits"
        );
    }

    #[tokio::test]
    async fn udp_retries_u32_max_is_bounded_and_does_not_panic() {
        let (port, received) = spawn_ntp_server_dropping(usize::MAX).await;
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let start = std::time::Instant::now();
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(2, u32::MAX))
            .await
            .expect("u32::MAX retries must not panic");
        let elapsed = start.elapsed();
        assert!(!outcome.reachable);
        assert!(
            elapsed < Duration::from_millis(500),
            "u32::MAX retries must stay bounded near the timeout: {elapsed:?}"
        );
        assert!(
            received.load(Ordering::SeqCst) < 100,
            "the per-attempt floor and deadline break bound the send count: {}",
            received.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn udp_retransmit_stays_within_the_total_timeout() {
        let (port, _received) = spawn_ntp_server_dropping(usize::MAX).await;
        let prober = UdpProber::new(vec![port], UdpProtocol::Ntp).expect("valid");
        let start = std::time::Instant::now();
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(300, 2))
            .await
            .expect("probe ok");
        let elapsed = start.elapsed();
        assert!(!outcome.reachable);
        assert!(
            elapsed < Duration::from_millis(600),
            "split model keeps the total near timeout, not retries+1 times it: {elapsed:?}"
        );
    }
}
