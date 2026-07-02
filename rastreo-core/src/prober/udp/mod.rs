//! UDP prober with protocol-specific payloads. Ships NTP, SIP OPTIONS, memcached stats, STUN.

pub mod memcached;
pub mod ntp;
pub mod sip;
pub mod stun;

use std::io;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use crate::error::{ConfigError, ProbeError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

const RECV_BUF_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
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
    Other(String),
}

async fn probe_port(target_addr: SocketAddr, protocol: UdpProtocol, ctx: &ProbeCtx) -> PortOutcome {
    let bind_addr = if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => return PortOutcome::Other(format!("udp bind failed: {e}")),
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
    if let Err(e) = socket.send_to(&payload, target_addr).await {
        return classify_io_error(&e);
    }
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let deadline = tokio::time::Instant::now() + ctx.timeout;
    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
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
            Err(_) => return PortOutcome::Timeout,
        }
    }
}

fn classify_io_error(err: &io::Error) -> PortOutcome {
    match err.kind() {
        io::ErrorKind::TimedOut => PortOutcome::Timeout,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::ConnectionAborted => PortOutcome::Unreachable,
        _ => PortOutcome::Other(err.to_string()),
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
        let mut timeouts = 0usize;
        let mut unreachables = 0usize;
        let mut last_other: Option<String> = None;

        for &port in &self.ports {
            let addr = SocketAddr::new(target.ip, port);
            match probe_port(addr, self.protocol, ctx).await {
                PortOutcome::Reached(signal) => {
                    any_reachable = true;
                    if let Some(s) = signal {
                        signals.push(s);
                    }
                }
                PortOutcome::Timeout => timeouts += 1,
                PortOutcome::Unreachable => unreachables += 1,
                PortOutcome::Other(msg) => {
                    last_other = Some(format!("udp probe failed on port {port}: {msg}"));
                }
            }
        }

        if !any_reachable {
            let err = if unreachables > 0 && unreachables >= timeouts {
                ProbeError::Unreachable {
                    target: target.ip.to_string(),
                }
            } else if timeouts > 0 {
                ProbeError::Timeout {
                    timeout_ms: ctx.timeout.as_millis() as u64,
                }
            } else if let Some(msg) = last_other {
                ProbeError::Other(msg)
            } else {
                ProbeError::Timeout {
                    timeout_ms: ctx.timeout.as_millis() as u64,
                }
            };
            return Err(err.into());
        }

        Ok(ProbeOutcome {
            kind: ProbeKind::Udp,
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
    use std::net::{IpAddr, Ipv4Addr};
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
    async fn udp_prober_maps_all_timeouts_to_timeout_error() {
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
        let err = prober
            .probe(&loopback_target(), &ctx_with_timeout(200))
            .await
            .expect_err("must error");
        match err {
            RastreoError::Probe(ProbeError::Timeout { timeout_ms }) => {
                assert_eq!(timeout_ms, 200);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
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
}
