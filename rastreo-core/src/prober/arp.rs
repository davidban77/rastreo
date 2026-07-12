use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

use ipnetwork::IpNetwork;
use pnet_datalink::{Channel, Config, MacAddr, NetworkInterface};
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::Packet;

use crate::error::{ConfigError, ProbeErrorKind, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

const ETH_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;
const ARP_FRAME_LEN: usize = ETH_HEADER_LEN + ARP_PACKET_LEN;
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub fn default_interface() -> String {
    String::new()
}

#[derive(Debug)]
pub struct ArpProber {
    interface: String,
}

impl ArpProber {
    pub fn new(interface: String) -> Result<Self, RastreoError> {
        if !interface.is_empty() && lookup_interface(&interface).is_none() {
            return Err(
                ConfigError::invalid(format!("network interface '{interface}' not found")).into(),
            );
        }
        Ok(Self { interface })
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

fn lookup_interface(name: &str) -> Option<NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

fn select_interface_for(target: Ipv4Addr) -> Option<NetworkInterface> {
    let mut best: Option<(NetworkInterface, u8)> = None;
    for iface in pnet_datalink::interfaces() {
        for net in &iface.ips {
            if let IpNetwork::V4(v4) = net {
                if v4.contains(target) {
                    let prefix = v4.prefix();
                    match &best {
                        Some((_, best_prefix)) if *best_prefix >= prefix => {}
                        _ => best = Some((iface.clone(), prefix)),
                    }
                }
            }
        }
    }
    best.map(|(iface, _)| iface)
}

fn first_ipv4(iface: &NetworkInterface) -> Option<Ipv4Addr> {
    iface.ips.iter().find_map(|net| match net {
        IpNetwork::V4(v4) => Some(v4.ip()),
        _ => None,
    })
}

pub(crate) fn format_mac(mac: MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    )
}

pub(crate) fn build_arp_request(
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> [u8; ARP_FRAME_LEN] {
    let mut frame = [0u8; ARP_FRAME_LEN];
    {
        let mut eth = MutableEthernetPacket::new(&mut frame[..ETH_HEADER_LEN])
            .expect("ethernet buffer sized to header length");
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut frame[ETH_HEADER_LEN..])
            .expect("arp buffer sized to packet length");
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }
    frame
}

pub(crate) fn parse_arp_reply(frame: &[u8], target_ip: Ipv4Addr) -> Option<MacAddr> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    if arp.get_sender_proto_addr() != target_ip {
        return None;
    }
    Some(arp.get_sender_hw_addr())
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

fn run_probe_blocking(
    iface: NetworkInterface,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target: Ipv4Addr,
    timeout: Duration,
) -> ProbeResolution {
    let (mut tx, mut rx) = match pnet_datalink::channel(&iface, build_channel_config()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return ProbeResolution::Failed(
                "arp channel returned an unsupported backend".to_string(),
            )
        }
        Err(err) => {
            let msg = if err.kind() == std::io::ErrorKind::PermissionDenied {
                "raw socket permission denied; ARP requires CAP_NET_RAW".to_string()
            } else {
                format!("arp channel open failed: {err}")
            };
            return ProbeResolution::Failed(msg);
        }
    };

    let frame = build_arp_request(src_mac, src_ip, target);
    match tx.send_to(&frame, None) {
        Some(Ok(())) => {}
        Some(Err(err)) => return ProbeResolution::Failed(format!("arp send failed: {err}")),
        None => {
            return ProbeResolution::Failed(
                "arp send returned None (packet too large for send buffer)".to_string(),
            )
        }
    }

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match rx.next() {
            Ok(bytes) => {
                if let Some(mac) = parse_arp_reply(bytes, target) {
                    return ProbeResolution::Reached(Signal::Mac(format_mac(mac)));
                }
            }
            Err(err) => match err.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => continue,
                _ => return ProbeResolution::Failed(format!("arp receive failed: {err}")),
            },
        }
    }
    ProbeResolution::Timeout
}

// A local resolution failure (privileged socket denied, no usable interface) is a broken probe,
// carried as a fault on an unreachable outcome — never discarded.
fn arp_fault(target_ip: IpAddr, detail: String) -> ProbeOutcome {
    ProbeOutcome {
        kind: ProbeKind::Arp,
        target_ip,
        timestamp: SystemTime::now(),
        reachable: false,
        signals: Vec::new(),
        fault: Some(ProbeFault::new(ProbeErrorKind::Other, detail)),
    }
}

fn resolution_to_outcome(resolution: ProbeResolution, target_ip: IpAddr) -> ProbeOutcome {
    match resolution {
        ProbeResolution::Reached(signal) => ProbeOutcome {
            kind: ProbeKind::Arp,
            target_ip,
            timestamp: SystemTime::now(),
            reachable: true,
            signals: vec![signal],
            fault: None,
        },
        // A silent host is a negative discovery result, not a probe fault.
        ProbeResolution::Timeout => ProbeOutcome {
            kind: ProbeKind::Arp,
            target_ip,
            timestamp: SystemTime::now(),
            reachable: false,
            signals: Vec::new(),
            fault: None,
        },
        ProbeResolution::Failed(msg) => arp_fault(target_ip, msg),
    }
}

#[async_trait::async_trait]
impl Prober for ArpProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Arp
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let target_v4 = match target.ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return Ok(arp_fault(
                    target.ip,
                    "arp prober requires an IPv4 target; use ndp for IPv6".to_string(),
                ));
            }
        };

        let iface = if self.interface.is_empty() {
            match select_interface_for(target_v4) {
                Some(iface) => iface,
                None => {
                    return Ok(arp_fault(
                        target.ip,
                        format!("no local interface reaches {target_v4}"),
                    ))
                }
            }
        } else {
            match lookup_interface(&self.interface) {
                Some(iface) => iface,
                None => {
                    return Ok(arp_fault(
                        target.ip,
                        format!("network interface '{}' not found", self.interface),
                    ))
                }
            }
        };

        let Some(src_mac) = iface.mac else {
            return Ok(arp_fault(
                target.ip,
                format!("interface {} has no MAC address", iface.name),
            ));
        };
        let Some(src_ip) = first_ipv4(&iface) else {
            return Ok(arp_fault(
                target.ip,
                format!("interface {} has no ipv4 address", iface.name),
            ));
        };

        if src_ip == target_v4 {
            return Ok(arp_fault(
                target.ip,
                format!("arp target {target_v4} is a local interface address"),
            ));
        }

        let iface_for_task = iface.clone();
        let timeout = ctx.timeout;
        let result = tokio::task::spawn_blocking(move || {
            run_probe_blocking(iface_for_task, src_mac, src_ip, target_v4, timeout)
        })
        .await
        .map_err(|err| {
            RastreoError::Runtime(crate::error::RuntimeError::TaskPanicked(err.to_string()))
        })?;

        Ok(resolution_to_outcome(result, target.ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_mac() -> MacAddr {
        MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    }

    #[test]
    fn format_mac_is_lower_hex_colon_separated() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc);
        assert_eq!(format_mac(mac), "00:11:22:aa:bb:cc");
    }

    #[test]
    fn arp_request_frame_has_correct_ethertype_and_opcode() {
        let src_mac = sample_mac();
        let src_ip = Ipv4Addr::new(10, 0, 0, 5);
        let target_ip = Ipv4Addr::new(10, 0, 0, 42);
        let frame = build_arp_request(src_mac, src_ip, target_ip);
        let eth = EthernetPacket::new(&frame).expect("ethernet header parses");
        assert_eq!(eth.get_ethertype(), EtherTypes::Arp);
        assert_eq!(eth.get_destination(), MacAddr::broadcast());
        assert_eq!(eth.get_source(), src_mac);
        let arp = ArpPacket::new(eth.payload()).expect("arp packet parses");
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_hardware_type(), ArpHardwareTypes::Ethernet);
        assert_eq!(arp.get_protocol_type(), EtherTypes::Ipv4);
        assert_eq!(arp.get_hw_addr_len(), 6);
        assert_eq!(arp.get_proto_addr_len(), 4);
    }

    #[test]
    fn arp_request_frame_target_ip_bytes_are_big_endian() {
        let frame = build_arp_request(
            sample_mac(),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(192, 0, 2, 42),
        );
        let target_bytes = &frame[38..42];
        assert_eq!(target_bytes, &[192, 0, 2, 42]);
        let sender_bytes = &frame[28..32];
        assert_eq!(sender_bytes, &[10, 0, 0, 5]);
    }

    #[test]
    fn arp_request_target_hw_addr_is_zero() {
        let frame = build_arp_request(
            sample_mac(),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 42),
        );
        let arp = ArpPacket::new(&frame[ETH_HEADER_LEN..]).expect("arp packet");
        assert_eq!(arp.get_target_hw_addr(), MacAddr::zero());
    }

    fn build_reply_frame(sender_mac: MacAddr, sender_ip: Ipv4Addr) -> Vec<u8> {
        let mut frame = vec![0u8; ARP_FRAME_LEN];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame[..ETH_HEADER_LEN]).expect("eth");
            eth.set_destination(MacAddr::new(0x02, 0, 0, 0, 0, 2));
            eth.set_source(sender_mac);
            eth.set_ethertype(EtherTypes::Arp);
        }
        {
            let mut arp = MutableArpPacket::new(&mut frame[ETH_HEADER_LEN..]).expect("arp");
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Reply);
            arp.set_sender_hw_addr(sender_mac);
            arp.set_sender_proto_addr(sender_ip);
            arp.set_target_hw_addr(MacAddr::new(0x02, 0, 0, 0, 0, 2));
            arp.set_target_proto_addr(Ipv4Addr::new(10, 0, 0, 1));
        }
        frame
    }

    #[test]
    fn arp_reply_parser_extracts_sender_mac() {
        let expected = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let target = Ipv4Addr::new(10, 0, 0, 42);
        let frame = build_reply_frame(expected, target);
        let parsed = parse_arp_reply(&frame, target).expect("reply parsed");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn arp_reply_parser_rejects_request_opcode() {
        let frame = build_arp_request(
            sample_mac(),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 42),
        );
        assert!(parse_arp_reply(&frame, Ipv4Addr::new(10, 0, 0, 42)).is_none());
    }

    #[test]
    fn arp_reply_parser_rejects_mismatched_sender_ip() {
        let frame = build_reply_frame(sample_mac(), Ipv4Addr::new(10, 0, 0, 99));
        assert!(parse_arp_reply(&frame, Ipv4Addr::new(10, 0, 0, 42)).is_none());
    }

    #[test]
    fn arp_reply_parser_rejects_non_arp_ethertype() {
        let mut frame = vec![0u8; ARP_FRAME_LEN];
        let mut eth = MutableEthernetPacket::new(&mut frame[..ETH_HEADER_LEN]).expect("eth");
        eth.set_ethertype(EtherTypes::Ipv4);
        assert!(parse_arp_reply(&frame, Ipv4Addr::new(10, 0, 0, 42)).is_none());
    }

    #[test]
    fn arp_prober_new_accepts_empty_interface() {
        let prober = ArpProber::new(String::new()).expect("empty interface allowed");
        assert!(prober.interface().is_empty());
    }

    #[test]
    fn arp_prober_new_rejects_unknown_interface_name() {
        let err = ArpProber::new("definitely-not-a-real-iface".to_string())
            .expect_err("unknown interface must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("definitely-not-a-real-iface"), "got: {msg}");
                assert!(msg.contains("not found"), "got: {msg}");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn arp_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<ArpProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[test]
    fn kind_returns_arp() {
        let prober = ArpProber::new(String::new()).expect("valid");
        assert_eq!(prober.kind(), ProbeKind::Arp);
    }

    #[test]
    fn default_interface_is_empty_string() {
        assert!(default_interface().is_empty());
    }

    fn synthesize_interface(name: &str, mac: MacAddr, ips: Vec<IpNetwork>) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: String::new(),
            index: 0,
            mac: Some(mac),
            ips,
            flags: 0,
        }
    }

    #[test]
    fn auto_select_prefers_most_specific_prefix() {
        let iface_wide = synthesize_interface(
            "wide",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            vec![IpNetwork::V4("10.0.0.0/8".parse().unwrap())],
        );
        let iface_narrow = synthesize_interface(
            "narrow",
            MacAddr::new(0x02, 0, 0, 0, 0, 2),
            vec![IpNetwork::V4("10.0.0.0/24".parse().unwrap())],
        );
        let target = Ipv4Addr::new(10, 0, 0, 42);
        let mut best: Option<(NetworkInterface, u8)> = None;
        for iface in [iface_wide, iface_narrow] {
            for net in &iface.ips {
                if let IpNetwork::V4(v4) = net {
                    if v4.contains(target) {
                        let prefix = v4.prefix();
                        match &best {
                            Some((_, p)) if *p >= prefix => {}
                            _ => best = Some((iface.clone(), prefix)),
                        }
                    }
                }
            }
        }
        assert_eq!(best.expect("match").0.name, "narrow");
    }

    #[test]
    fn first_ipv4_finds_the_ipv4_address() {
        let iface = synthesize_interface(
            "test",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            vec![
                IpNetwork::V6("fe80::1/64".parse().unwrap()),
                IpNetwork::V4("10.0.0.5/24".parse().unwrap()),
            ],
        );
        assert_eq!(first_ipv4(&iface), Some(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn promiscuous_mode_is_disabled() {
        let config = build_channel_config();
        assert!(
            !config.promiscuous,
            "ARP prober must not put the interface in promiscuous mode"
        );
        assert_eq!(config.read_timeout, Some(RECV_POLL_INTERVAL));
    }

    #[test]
    fn timeout_resolution_is_an_unreachable_outcome_not_an_error() {
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
        let outcome = resolution_to_outcome(ProbeResolution::Timeout, target_ip);
        assert_eq!(outcome.kind, ProbeKind::Arp);
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
        let outcome = resolution_to_outcome(ProbeResolution::Reached(signal), target_ip);
        assert!(outcome.reachable);
        assert!(matches!(&outcome.signals[0], Signal::Mac(m) if m == "aa:bb:cc:dd:ee:ff"));
        assert!(outcome.fault.is_none());
    }

    #[test]
    fn failed_resolution_is_a_kinded_fault_outcome() {
        let outcome = resolution_to_outcome(
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

    #[test]
    fn first_ipv4_returns_none_on_ipv6_only_interface() {
        let iface = synthesize_interface(
            "v6only",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            vec![IpNetwork::V6("fe80::1/64".parse().unwrap())],
        );
        assert!(first_ipv4(&iface).is_none());
    }
}
