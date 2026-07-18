use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

use tokio::net::TcpStream;
use tokio::time::error::Elapsed;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::ports::{probe_ports, MAX_PORTS_IN_FLIGHT};
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

// A refused / unreachable port is a discovery result; a local socket failure (descriptor
// exhaustion, denied capability) is a broken probe.
fn connect_fault(port: u16, err: &io::Error) -> Option<ProbeFault> {
    match classify::io_error(err) {
        Disposition::Fault(kind) => Some(ProbeFault::new(
            kind,
            format!("tcp connect failed on port {port}: {err}"),
        )),
        Disposition::Absence => None,
    }
}

fn fold_connect(
    port: u16,
    outcome: Result<io::Result<TcpStream>, Elapsed>,
    signals: &mut Vec<Signal>,
    last_fault: &mut Option<ProbeFault>,
) {
    match outcome {
        Ok(Ok(_stream)) => signals.push(Signal::OpenPort(port)),
        Ok(Err(err)) => {
            if let Some(fault) = connect_fault(port, &err) {
                *last_fault = Some(fault);
            }
        }
        Err(_) => {}
    }
}

fn build_outcome(
    target_ip: IpAddr,
    signals: Vec<Signal>,
    last_fault: Option<ProbeFault>,
) -> ProbeOutcome {
    // Silence on one port is not evidence against a fault on another, but an open port is.
    let reachable = !signals.is_empty();
    let fault = if reachable { None } else { last_fault };
    ProbeOutcome {
        kind: ProbeKind::TcpConnect,
        target_ip,
        timestamp: SystemTime::now(),
        reachable,
        signals,
        fault,
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
        let per_port = probe_ports(
            &self.ports,
            MAX_PORTS_IN_FLIGHT,
            ctx.port_budget.as_ref(),
            |port| {
                let addr = SocketAddr::new(target.ip, port);
                async move {
                    let outcome = tokio::time::timeout(ctx.timeout, TcpStream::connect(addr)).await;
                    (port, outcome)
                }
            },
        )
        .await;

        let mut signals = Vec::new();
        let mut last_fault: Option<ProbeFault> = None;
        for (port, outcome) in per_port {
            fold_connect(port, outcome, &mut signals, &mut last_fault);
        }

        Ok(build_outcome(target.ip, signals, last_fault))
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
        ProbeCtx::new(Duration::from_millis(ms), 0)
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
            #[allow(unreachable_patterns)]
            _ => panic!("expected TcpConnect variant"),
        }
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    #[test]
    fn a_local_socket_failure_on_connect_latches_a_fault() {
        let fault = connect_fault(22, &io::Error::from(io::ErrorKind::PermissionDenied))
            .expect("a denied local socket is a broken probe");
        assert_eq!(fault.kind, crate::error::ProbeErrorKind::PermissionDenied);
        assert!(
            fault.detail.contains("tcp connect failed on port 22"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn a_refused_connect_latches_no_fault() {
        assert!(connect_fault(22, &io::Error::from(io::ErrorKind::ConnectionRefused)).is_none());
    }

    async fn connected_stream() -> (u16, io::Result<TcpStream>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let stream = TcpStream::connect(("127.0.0.1", port)).await;
        (port, stream)
    }

    async fn elapsed() -> Elapsed {
        tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("a zero deadline on a pending future always elapses")
    }

    #[tokio::test]
    async fn a_connect_that_succeeds_emits_an_open_port() {
        let (port, stream) = connected_stream().await;
        let mut signals = Vec::new();
        let mut last_fault = None;

        fold_connect(port, Ok(stream), &mut signals, &mut last_fault);

        assert!(matches!(signals.as_slice(), [Signal::OpenPort(p)] if *p == port));
        assert!(last_fault.is_none());
    }

    #[tokio::test]
    async fn a_connect_that_is_refused_emits_nothing() {
        let mut signals = Vec::new();
        let mut last_fault = None;

        fold_connect(
            22,
            Ok(Err(io::Error::from(io::ErrorKind::ConnectionRefused))),
            &mut signals,
            &mut last_fault,
        );

        assert!(signals.is_empty());
        assert!(last_fault.is_none());
    }

    #[tokio::test]
    async fn a_connect_that_fails_on_a_local_socket_latches_a_fault() {
        let mut signals = Vec::new();
        let mut last_fault = None;

        fold_connect(
            22,
            Ok(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            &mut signals,
            &mut last_fault,
        );

        assert!(signals.is_empty());
        let fault = last_fault.expect("a denied local socket is a broken probe");
        assert!(
            fault.detail.contains("tcp connect failed on port 22"),
            "got: {}",
            fault.detail
        );
    }

    #[tokio::test]
    async fn a_connect_that_times_out_emits_nothing() {
        let mut signals = Vec::new();
        let mut last_fault = None;

        fold_connect(22, Err(elapsed().await), &mut signals, &mut last_fault);

        assert!(signals.is_empty());
        assert!(last_fault.is_none());
    }

    fn sample_fault(detail: &str) -> ProbeFault {
        ProbeFault::new(crate::error::ProbeErrorKind::Other, detail.to_string())
    }

    #[test]
    fn an_open_port_is_a_reachable_outcome() {
        let outcome = build_outcome(TARGET, vec![Signal::OpenPort(22)], None);
        assert!(outcome.reachable);
        assert_eq!(outcome.target_ip, TARGET);
        assert!(matches!(outcome.signals[0], Signal::OpenPort(22)));
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn an_open_port_outranks_a_connect_fault_on_another_port() {
        let outcome = build_outcome(
            TARGET,
            vec![Signal::OpenPort(22)],
            Some(sample_fault(
                "tcp connect failed on port 80: too many open files",
            )),
        );
        assert!(outcome.reachable);
        assert!(
            outcome.fault.is_none(),
            "a port that answered makes the record truthful — the fault is dropped"
        );
    }

    #[test]
    fn no_signals_and_no_fault_is_an_absent_target() {
        let outcome = build_outcome(TARGET, Vec::new(), None);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn no_signals_and_a_connect_fault_is_a_kinded_fault_outcome() {
        let outcome = build_outcome(
            TARGET,
            Vec::new(),
            Some(sample_fault(
                "tcp connect failed on port 22: too many open files",
            )),
        );
        assert!(!outcome.reachable);
        let fault = outcome.fault.expect("a broken probe surfaces its fault");
        assert_eq!(fault.kind, crate::error::ProbeErrorKind::Other);
        assert!(
            fault.detail.contains("tcp connect failed on port 22"),
            "got: {}",
            fault.detail
        );
    }

    #[test]
    fn tcp_connect_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<TcpConnectProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[tokio::test]
    async fn probe_collects_open_ports_in_ascending_port_order() {
        let mut listeners = Vec::new();
        let mut ports = Vec::new();
        for _ in 0..4 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            ports.push(listener.local_addr().expect("addr").port());
            listeners.push(listener);
        }
        let prober = TcpConnectProber::new(ports.clone()).expect("valid");
        let outcome = prober
            .probe(
                &loopback_target(Ipv4Addr::LOCALHOST),
                &ctx_with_timeout(500),
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
    async fn probe_multiple_timeout_ports_finish_near_one_timeout() {
        // TEST-NET-1 blackholes the SYN; each port would consume the full timeout serially.
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let target = ResolvedTarget {
            ip: addr,
            original: Target::Ip(addr),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let prober = TcpConnectProber::new(vec![80, 81, 82, 83, 84, 85]).expect("valid");
        let start = Instant::now();
        let outcome = prober
            .probe(&target, &ctx_with_timeout(200))
            .await
            .expect("probe ok");
        let elapsed = start.elapsed();
        assert!(!outcome.reachable);
        assert!(
            elapsed < Duration::from_millis(500),
            "six timeout ports run serially would be ~1200ms; concurrent stays near 1x: {elapsed:?}"
        );
    }
}
