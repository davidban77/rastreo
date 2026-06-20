use std::net::SocketAddr;
use std::time::SystemTime;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

pub struct TcpConnectProber {
    ports: Vec<u16>,
}

impl TcpConnectProber {
    pub fn new(ports: Vec<u16>) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("TcpConnectProber requires at least one port").into());
        }
        // Sort and dedup at construction so probe order is deterministic and stable across runs.
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Ok(Self { ports })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
}

#[async_trait::async_trait]
impl Prober for TcpConnectProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::TcpConnect
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let mut signals = Vec::new();
        for &port in &self.ports {
            let addr = SocketAddr::new(target.ip, port);
            let connect = tokio::net::TcpStream::connect(addr);
            // A refused/unreachable/timed-out port is a discovery result, not an error.
            if let Ok(Ok(_stream)) = tokio::time::timeout(ctx.timeout, connect).await {
                signals.push(Signal::OpenPort(port));
            }
        }
        let reachable = !signals.is_empty();
        Ok(ProbeOutcome {
            kind: ProbeKind::TcpConnect,
            target_ip: target.ip,
            timestamp: SystemTime::now(),
            reachable,
            signals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use crate::model::Target;
    use crate::prober::{create_prober, ProberConfig};

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

    #[test]
    fn new_rejects_empty_port_list() {
        match TcpConnectProber::new(Vec::new()) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("at least one port"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty port list must error"),
        }
    }

    #[test]
    fn new_sorts_and_dedups_ports() {
        let p = TcpConnectProber::new(vec![80, 22, 80, 443, 22]).expect("valid");
        assert_eq!(p.ports(), &[22, 80, 443]);
    }

    #[test]
    fn new_preserves_single_port() {
        let p = TcpConnectProber::new(vec![22]).expect("valid");
        assert_eq!(p.ports(), &[22]);
    }

    #[test]
    fn kind_returns_tcp_connect() {
        let p = TcpConnectProber::new(vec![22]).expect("valid");
        assert_eq!(p.kind(), ProbeKind::TcpConnect);
    }

    #[tokio::test]
    async fn probe_reports_open_port_for_bound_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let prober = TcpConnectProber::new(vec![port]).expect("valid");
        let target = loopback_target(Ipv4Addr::LOCALHOST);
        let outcome = prober
            .probe(&target, &ctx_with_timeout(500))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(outcome.signals[0], Signal::OpenPort(p) if p == port));
        assert_eq!(outcome.target_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(outcome.kind, ProbeKind::TcpConnect);
    }

    #[tokio::test]
    async fn probe_reports_no_signal_for_closed_port() {
        // Bind a port and immediately drop it, then probe it — we cannot guarantee no
        // other process has snatched it, but the window is tiny on a dev host.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        drop(listener);
        let prober = TcpConnectProber::new(vec![port]).expect("valid");
        let target = loopback_target(Ipv4Addr::LOCALHOST);
        let outcome = prober
            .probe(&target, &ctx_with_timeout(500))
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn probe_reports_only_open_port_among_mixed_ports() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let open_port = listener.local_addr().expect("local_addr").port();
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind closed");
        let closed_port = closed_listener.local_addr().expect("local_addr").port();
        drop(closed_listener);

        let prober = TcpConnectProber::new(vec![open_port, closed_port]).expect("valid");
        let target = loopback_target(Ipv4Addr::LOCALHOST);
        let outcome = prober
            .probe(&target, &ctx_with_timeout(500))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 1);
        assert!(matches!(outcome.signals[0], Signal::OpenPort(p) if p == open_port));
    }

    #[tokio::test]
    async fn probe_times_out_against_non_routable_ip() {
        let prober = TcpConnectProber::new(vec![80]).expect("valid");
        // RFC 5737 TEST-NET-1: documentation address, never routes.
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let target = ResolvedTarget {
            ip: addr,
            original: Target::Ip(addr),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let start = Instant::now();
        let outcome = prober
            .probe(&target, &ctx_with_timeout(50))
            .await
            .expect("probe ok");
        let elapsed = start.elapsed();
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(
            elapsed < Duration::from_millis(500),
            "timeout took too long: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn factory_round_trip_returns_tcp_connect_kind() {
        let config = ProberConfig::TcpConnect {
            ports: vec![22, 80, 443],
        };
        let prober = create_prober(&config).expect("factory ok");
        assert_eq!(prober.kind(), ProbeKind::TcpConnect);
    }

    #[tokio::test]
    async fn factory_propagates_empty_ports_error() {
        let config = ProberConfig::TcpConnect { ports: Vec::new() };
        match create_prober(&config) {
            Err(RastreoError::Config(ConfigError::InvalidValue(_))) => {}
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty ports must error"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_tcp_connect_config_from_yaml() {
        let yaml = "type: tcp_connect\nports: [22, 80]\n";
        let config: ProberConfig = serde_yaml_ng::from_str(yaml).expect("deserialize tcp_connect");
        match config {
            ProberConfig::TcpConnect { ports } => {
                assert_eq!(ports, vec![22, 80]);
            }
        }
    }

    #[test]
    fn tcp_connect_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<TcpConnectProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }
}
