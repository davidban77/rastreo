use std::fmt::Display;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use pnet_datalink::{Channel, Config, MacAddr, NetworkInterface};

use crate::error::{ProbeErrorKind, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};

pub(crate) const ETH_HEADER_LEN: usize = 14;
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The per-protocol seam — address family, packet build/parse, interface/source selection — that the
/// shared `probe_link_layer` engine drives.
pub(crate) trait LinkLayerProtocol {
    type Addr: Copy + Eq + Display + Send + 'static;

    const NAME: &'static str;
    const NAME_UPPER: &'static str;
    const ADDRESS_FAMILY: &'static str;

    fn kind() -> ProbeKind;
    fn extract_target(ip: IpAddr) -> Option<Self::Addr>;
    fn wrong_family_detail() -> &'static str;
    fn select_interface(target: Self::Addr) -> Option<NetworkInterface>;
    fn source_address(iface: &NetworkInterface, target: Self::Addr) -> Option<Self::Addr>;
    fn build_request(src_mac: MacAddr, src_ip: Self::Addr, target: Self::Addr) -> Vec<u8>;
    fn parse_reply(frame: &[u8], target: Self::Addr) -> Option<MacAddr>;
}

pub(crate) fn lookup_interface(name: &str) -> Option<NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

pub(crate) fn format_mac(mac: MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    )
}

fn build_channel_config() -> Config {
    Config {
        read_timeout: Some(RECV_POLL_INTERVAL),
        promiscuous: false,
        ..Default::default()
    }
}

enum ProbeResolution {
    Reached(Signal),
    Timeout,
    Failed(String),
}

fn run_probe_blocking<P: LinkLayerProtocol>(
    iface: NetworkInterface,
    src_mac: MacAddr,
    src_ip: P::Addr,
    target: P::Addr,
    timeout: Duration,
) -> ProbeResolution {
    let (mut tx, mut rx) = match pnet_datalink::channel(&iface, build_channel_config()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return ProbeResolution::Failed(format!(
                "{} channel returned an unsupported backend",
                P::NAME
            ))
        }
        Err(err) => {
            let msg = if err.kind() == std::io::ErrorKind::PermissionDenied {
                format!(
                    "raw socket permission denied; {} requires CAP_NET_RAW",
                    P::NAME_UPPER
                )
            } else {
                format!("{} channel open failed: {err}", P::NAME)
            };
            return ProbeResolution::Failed(msg);
        }
    };

    let frame = P::build_request(src_mac, src_ip, target);
    match tx.send_to(&frame, None) {
        Some(Ok(())) => {}
        Some(Err(err)) => {
            return ProbeResolution::Failed(format!("{} send failed: {err}", P::NAME))
        }
        None => {
            return ProbeResolution::Failed(format!(
                "{} send returned None (packet too large for send buffer)",
                P::NAME
            ))
        }
    }

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match rx.next() {
            Ok(bytes) => {
                if let Some(mac) = P::parse_reply(bytes, target) {
                    return ProbeResolution::Reached(Signal::Mac(format_mac(mac)));
                }
            }
            Err(err) => match err.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => continue,
                _ => return ProbeResolution::Failed(format!("{} receive failed: {err}", P::NAME)),
            },
        }
    }
    ProbeResolution::Timeout
}

// A local resolution failure (privileged socket denied, no usable interface) is a broken probe,
// carried as a fault on an unreachable outcome — never discarded.
fn link_layer_fault(kind: ProbeKind, target_ip: IpAddr, detail: String) -> ProbeOutcome {
    ProbeOutcome {
        kind,
        target_ip,
        timestamp: SystemTime::now(),
        reachable: false,
        signals: Vec::new(),
        fault: Some(ProbeFault::new(ProbeErrorKind::Other, detail)),
    }
}

fn resolution_to_outcome<P: LinkLayerProtocol>(
    resolution: ProbeResolution,
    target_ip: IpAddr,
) -> ProbeOutcome {
    match resolution {
        ProbeResolution::Reached(signal) => ProbeOutcome {
            kind: P::kind(),
            target_ip,
            timestamp: SystemTime::now(),
            reachable: true,
            signals: vec![signal],
            fault: None,
        },
        // A silent host is a negative discovery result, not a probe fault.
        ProbeResolution::Timeout => ProbeOutcome {
            kind: P::kind(),
            target_ip,
            timestamp: SystemTime::now(),
            reachable: false,
            signals: Vec::new(),
            fault: None,
        },
        ProbeResolution::Failed(msg) => link_layer_fault(P::kind(), target_ip, msg),
    }
}

pub(crate) async fn probe_link_layer<P: LinkLayerProtocol>(
    interface: &str,
    target: &ResolvedTarget,
    ctx: &ProbeCtx,
) -> Result<ProbeOutcome, RastreoError> {
    let target_addr = match P::extract_target(target.ip) {
        Some(addr) => addr,
        None => {
            return Ok(link_layer_fault(
                P::kind(),
                target.ip,
                P::wrong_family_detail().to_string(),
            ))
        }
    };

    let iface = if interface.is_empty() {
        match P::select_interface(target_addr) {
            Some(iface) => iface,
            None => {
                return Ok(link_layer_fault(
                    P::kind(),
                    target.ip,
                    format!("no local interface reaches {target_addr}"),
                ))
            }
        }
    } else {
        match lookup_interface(interface) {
            Some(iface) => iface,
            None => {
                return Ok(link_layer_fault(
                    P::kind(),
                    target.ip,
                    format!("network interface '{interface}' not found"),
                ))
            }
        }
    };

    let Some(src_mac) = iface.mac else {
        return Ok(link_layer_fault(
            P::kind(),
            target.ip,
            format!("interface {} has no MAC address", iface.name),
        ));
    };
    let Some(src_ip) = P::source_address(&iface, target_addr) else {
        return Ok(link_layer_fault(
            P::kind(),
            target.ip,
            format!(
                "interface {} has no {} address",
                iface.name,
                P::ADDRESS_FAMILY
            ),
        ));
    };

    if src_ip == target_addr {
        return Ok(link_layer_fault(
            P::kind(),
            target.ip,
            format!(
                "{} target {target_addr} is a local interface address",
                P::NAME
            ),
        ));
    }

    let iface_for_task = iface.clone();
    let timeout = ctx.timeout;
    let result = tokio::task::spawn_blocking(move || {
        run_probe_blocking::<P>(iface_for_task, src_mac, src_ip, target_addr, timeout)
    })
    .await
    .map_err(|err| {
        RastreoError::Runtime(crate::error::RuntimeError::TaskPanicked(err.to_string()))
    })?;

    Ok(resolution_to_outcome::<P>(result, target.ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    struct TestProtocol;

    impl LinkLayerProtocol for TestProtocol {
        type Addr = Ipv4Addr;

        const NAME: &'static str = "test";
        const NAME_UPPER: &'static str = "TEST";
        const ADDRESS_FAMILY: &'static str = "ipv4";

        fn kind() -> ProbeKind {
            ProbeKind::Arp
        }

        fn extract_target(ip: IpAddr) -> Option<Ipv4Addr> {
            match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            }
        }

        fn wrong_family_detail() -> &'static str {
            "test protocol requires an ipv4 target"
        }

        fn select_interface(_target: Ipv4Addr) -> Option<NetworkInterface> {
            None
        }

        fn source_address(_iface: &NetworkInterface, _target: Ipv4Addr) -> Option<Ipv4Addr> {
            None
        }

        fn build_request(_src_mac: MacAddr, _src_ip: Ipv4Addr, _target: Ipv4Addr) -> Vec<u8> {
            Vec::new()
        }

        fn parse_reply(_frame: &[u8], _target: Ipv4Addr) -> Option<MacAddr> {
            None
        }
    }

    #[test]
    fn format_mac_is_lower_hex_colon_separated() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc);
        assert_eq!(format_mac(mac), "00:11:22:aa:bb:cc");
    }

    #[test]
    fn promiscuous_mode_is_disabled() {
        let config = build_channel_config();
        assert!(
            !config.promiscuous,
            "link-layer prober must not put the interface in promiscuous mode"
        );
        assert_eq!(config.read_timeout, Some(RECV_POLL_INTERVAL));
    }

    #[test]
    fn timeout_resolution_is_an_unreachable_outcome_not_an_error() {
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
        let outcome = resolution_to_outcome::<TestProtocol>(ProbeResolution::Timeout, target_ip);
        assert_eq!(outcome.kind, TestProtocol::kind());
        assert_eq!(outcome.target_ip, target_ip);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert!(
            outcome.fault.is_none(),
            "a silent host is absence, not a fault"
        );
    }

    #[test]
    fn reached_resolution_is_a_reachable_outcome_with_the_mac_signal() {
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
        let signal = Signal::Mac("aa:bb:cc:dd:ee:ff".to_string());
        let outcome =
            resolution_to_outcome::<TestProtocol>(ProbeResolution::Reached(signal), target_ip);
        assert!(outcome.reachable);
        assert!(matches!(&outcome.signals[0], Signal::Mac(m) if m == "aa:bb:cc:dd:ee:ff"));
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn failed_resolution_is_a_kinded_fault_outcome() {
        let outcome = resolution_to_outcome::<TestProtocol>(
            ProbeResolution::Failed("raw socket permission denied".to_string()),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)),
        );
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        let fault = outcome
            .fault
            .expect("a probe fault is recorded on the outcome");
        assert_eq!(fault.kind, ProbeErrorKind::Other);
        assert!(
            fault.detail.contains("permission denied"),
            "got: {}",
            fault.detail
        );
    }
}
