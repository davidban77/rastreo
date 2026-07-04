use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime};

use ipnetwork::IpNetwork;
use pnet_datalink::{Channel, Config, MacAddr, NetworkInterface};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::icmpv6::ndp::{
    MutableNeighborSolicitPacket, NdpOption, NdpOptionTypes, NeighborAdvertPacket,
};
use pnet_packet::icmpv6::{checksum as icmpv6_checksum, Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet_packet::Packet;

use crate::error::{ConfigError, ProbeError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

const ETH_HEADER_LEN: usize = 14;
const IPV6_HEADER_LEN: usize = 40;
const NS_ICMPV6_LEN: usize = 32;
const NS_FRAME_LEN: usize = ETH_HEADER_LEN + IPV6_HEADER_LEN + NS_ICMPV6_LEN;
const NDP_HOP_LIMIT: u8 = 255;
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub fn default_interface() -> String {
    String::new()
}

#[derive(Debug)]
pub struct NdpProber {
    interface: String,
}

impl NdpProber {
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

fn select_interface_for(target: Ipv6Addr) -> Option<NetworkInterface> {
    let want_link_local = is_link_local(target);
    let mut best: Option<(NetworkInterface, u8, bool)> = None;
    for iface in pnet_datalink::interfaces() {
        for net in &iface.ips {
            if let IpNetwork::V6(v6) = net {
                if v6.contains(target) {
                    let prefix = v6.prefix();
                    let has_link_local = iface
                        .ips
                        .iter()
                        .any(|n| matches!(n, IpNetwork::V6(v) if is_link_local(v.ip())));
                    let is_candidate = if want_link_local {
                        has_link_local
                    } else {
                        !iface.is_loopback()
                    };
                    if !is_candidate {
                        continue;
                    }
                    match &best {
                        Some((_, best_prefix, _)) if *best_prefix >= prefix => {}
                        _ => best = Some((iface.clone(), prefix, has_link_local)),
                    }
                }
            }
        }
    }
    best.map(|(iface, _, _)| iface)
}

fn first_ipv6_source(iface: &NetworkInterface, target: Ipv6Addr) -> Option<Ipv6Addr> {
    let target_link_local = is_link_local(target);
    let mut chosen: Option<Ipv6Addr> = None;
    for net in &iface.ips {
        if let IpNetwork::V6(v6) = net {
            let ip = v6.ip();
            if target_link_local {
                if is_link_local(ip) {
                    return Some(ip);
                }
            } else if !is_link_local(ip) {
                return Some(ip);
            } else if chosen.is_none() {
                chosen = Some(ip);
            }
        }
    }
    chosen
}

fn is_link_local(ip: Ipv6Addr) -> bool {
    let segs = ip.segments();
    segs[0] & 0xffc0 == 0xfe80
}

pub(crate) fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let octets = target.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(octets[13]),
        (u16::from(octets[14]) << 8) | u16::from(octets[15]),
    )
}

pub(crate) fn solicited_node_multicast_mac(target: Ipv6Addr) -> MacAddr {
    let octets = target.octets();
    MacAddr::new(0x33, 0x33, 0xff, octets[13], octets[14], octets[15])
}

pub(crate) fn format_mac(mac: MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    )
}

pub(crate) fn build_neighbor_solicitation(
    src_mac: MacAddr,
    src_ip: Ipv6Addr,
    target: Ipv6Addr,
) -> [u8; NS_FRAME_LEN] {
    let mut frame = [0u8; NS_FRAME_LEN];
    let dst_ip = solicited_node_multicast(target);
    let dst_mac = solicited_node_multicast_mac(target);
    {
        let mut eth = MutableEthernetPacket::new(&mut frame[..ETH_HEADER_LEN])
            .expect("ethernet buffer sized to header length");
        eth.set_destination(dst_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Ipv6);
    }
    {
        let mut ipv6 =
            MutableIpv6Packet::new(&mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN])
                .expect("ipv6 buffer sized to header length");
        ipv6.set_version(6);
        ipv6.set_traffic_class(0);
        ipv6.set_flow_label(0);
        ipv6.set_payload_length(NS_ICMPV6_LEN as u16);
        ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ipv6.set_hop_limit(NDP_HOP_LIMIT);
        ipv6.set_source(src_ip);
        ipv6.set_destination(dst_ip);
    }
    {
        let ns_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let mut ns = MutableNeighborSolicitPacket::new(&mut frame[ns_start..])
            .expect("neighbor solicit buffer sized");
        ns.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        ns.set_icmpv6_code(Icmpv6Code(0));
        ns.set_reserved(0);
        ns.set_target_addr(target);
        ns.set_options(&[NdpOption {
            option_type: NdpOptionTypes::SourceLLAddr,
            length: 1,
            data: vec![
                src_mac.0, src_mac.1, src_mac.2, src_mac.3, src_mac.4, src_mac.5,
            ],
        }]);
    }
    let ns_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let checksum = {
        let icmp = Icmpv6Packet::new(&frame[ns_start..]).expect("icmpv6 view");
        icmpv6_checksum(&icmp, &src_ip, &dst_ip)
    };
    let cksum_bytes = checksum.to_be_bytes();
    frame[ns_start + 2] = cksum_bytes[0];
    frame[ns_start + 3] = cksum_bytes[1];
    frame
}

pub(crate) fn parse_neighbor_advertisement(frame: &[u8], target: Ipv6Addr) -> Option<MacAddr> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }
    let ipv6 = Ipv6Packet::new(eth.payload())?;
    if ipv6.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
        return None;
    }
    let icmp = Icmpv6Packet::new(ipv6.payload())?;
    if icmp.get_icmpv6_type() != Icmpv6Types::NeighborAdvert {
        return None;
    }
    let na = NeighborAdvertPacket::new(ipv6.payload())?;
    if na.get_target_addr() != target {
        return None;
    }
    for option in na.get_options() {
        if option.option_type == NdpOptionTypes::TargetLLAddr && option.data.len() >= 6 {
            return Some(MacAddr::new(
                option.data[0],
                option.data[1],
                option.data[2],
                option.data[3],
                option.data[4],
                option.data[5],
            ));
        }
    }
    None
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
    src_ip: Ipv6Addr,
    target: Ipv6Addr,
    timeout: Duration,
) -> ProbeResolution {
    let (mut tx, mut rx) = match pnet_datalink::channel(&iface, build_channel_config()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return ProbeResolution::Failed(
                "ndp channel returned an unsupported backend".to_string(),
            )
        }
        Err(err) => {
            let msg = if err.kind() == std::io::ErrorKind::PermissionDenied {
                "raw socket permission denied; NDP requires CAP_NET_RAW".to_string()
            } else {
                format!("ndp channel open failed: {err}")
            };
            return ProbeResolution::Failed(msg);
        }
    };

    let frame = build_neighbor_solicitation(src_mac, src_ip, target);
    match tx.send_to(&frame, None) {
        Some(Ok(())) => {}
        Some(Err(err)) => return ProbeResolution::Failed(format!("ndp send failed: {err}")),
        None => {
            return ProbeResolution::Failed(
                "ndp send returned None (packet too large for send buffer)".to_string(),
            )
        }
    }

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match rx.next() {
            Ok(bytes) => {
                if let Some(mac) = parse_neighbor_advertisement(bytes, target) {
                    return ProbeResolution::Reached(Signal::Mac(format_mac(mac)));
                }
            }
            Err(err) => match err.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => continue,
                _ => return ProbeResolution::Failed(format!("ndp receive failed: {err}")),
            },
        }
    }
    ProbeResolution::Timeout
}

#[async_trait::async_trait]
impl Prober for NdpProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Ndp
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let target_v6 = match target.ip {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => {
                return Err(ProbeError::Other(
                    "ndp prober requires an IPv6 target; use arp for IPv4".to_string(),
                )
                .into());
            }
        };

        let iface = if self.interface.is_empty() {
            select_interface_for(target_v6).ok_or_else(|| {
                ProbeError::Other(format!("no local interface reaches {target_v6}"))
            })?
        } else {
            lookup_interface(&self.interface).ok_or_else(|| {
                ProbeError::Other(format!("network interface '{}' not found", self.interface))
            })?
        };

        let src_mac = iface.mac.ok_or_else(|| {
            ProbeError::Other(format!("interface {} has no MAC address", iface.name))
        })?;
        let src_ip = first_ipv6_source(&iface, target_v6).ok_or_else(|| {
            ProbeError::Other(format!("interface {} has no ipv6 address", iface.name))
        })?;

        if src_ip == target_v6 {
            return Err(ProbeError::Other(format!(
                "ndp target {target_v6} is a local interface address"
            ))
            .into());
        }

        let iface_for_task = iface.clone();
        let timeout = ctx.timeout;
        let result = tokio::task::spawn_blocking(move || {
            run_probe_blocking(iface_for_task, src_mac, src_ip, target_v6, timeout)
        })
        .await
        .map_err(|err| {
            RastreoError::Runtime(crate::error::RuntimeError::TaskPanicked(err.to_string()))
        })?;

        match result {
            ProbeResolution::Reached(signal) => Ok(ProbeOutcome {
                kind: ProbeKind::Ndp,
                target_ip: target.ip,
                timestamp: SystemTime::now(),
                reachable: true,
                signals: vec![signal],
            }),
            ProbeResolution::Timeout => Err(ProbeError::Timeout {
                timeout_ms: ctx.timeout.as_millis() as u64,
            }
            .into()),
            ProbeResolution::Failed(msg) => Err(ProbeError::Other(msg).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::icmpv6::ndp::MutableNeighborAdvertPacket;

    fn sample_src_mac() -> MacAddr {
        MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    }

    fn sample_src_ip() -> Ipv6Addr {
        "2001:db8::1".parse().expect("valid ipv6")
    }

    fn sample_target() -> Ipv6Addr {
        "2001:db8::abcd:ef12".parse().expect("valid ipv6")
    }

    #[test]
    fn ndp_solicited_node_multicast_address_computation() {
        let target: Ipv6Addr = "2001:db8::1:2:3".parse().unwrap();
        assert_eq!(
            solicited_node_multicast(target),
            "ff02::1:ff02:0003".parse::<Ipv6Addr>().unwrap()
        );
        let target: Ipv6Addr = "fe80::abcd:ef12:3456:789a".parse().unwrap();
        assert_eq!(
            solicited_node_multicast(target),
            "ff02::1:ff56:789a".parse::<Ipv6Addr>().unwrap()
        );
        let target: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert_eq!(
            solicited_node_multicast(target),
            "ff02::1:ff00:0000".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn ndp_solicited_node_multicast_mac_uses_last_three_target_octets() {
        let target: Ipv6Addr = "fe80::abcd:ef12:3456:789a".parse().unwrap();
        assert_eq!(
            solicited_node_multicast_mac(target),
            MacAddr::new(0x33, 0x33, 0xff, 0x56, 0x78, 0x9a)
        );
    }

    #[test]
    fn ndp_neighbor_solicitation_has_type_135() {
        let frame = build_neighbor_solicitation(sample_src_mac(), sample_src_ip(), sample_target());
        let ns_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        assert_eq!(frame[ns_start], 135);
        assert_eq!(frame[ns_start + 1], 0);
    }

    #[test]
    fn ndp_neighbor_solicitation_includes_source_link_layer_option() {
        let frame = build_neighbor_solicitation(sample_src_mac(), sample_src_ip(), sample_target());
        let ns_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let options_start = ns_start + 24;
        assert_eq!(frame[options_start], 1);
        assert_eq!(frame[options_start + 1], 1);
        let mac_bytes = &frame[options_start + 2..options_start + 8];
        let src = sample_src_mac();
        assert_eq!(mac_bytes, &[src.0, src.1, src.2, src.3, src.4, src.5]);
    }

    #[test]
    fn ndp_neighbor_solicitation_target_address_in_header() {
        let target = sample_target();
        let frame = build_neighbor_solicitation(sample_src_mac(), sample_src_ip(), target);
        let ns_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let target_bytes = &frame[ns_start + 8..ns_start + 24];
        assert_eq!(target_bytes, &target.octets());
    }

    #[test]
    fn ndp_ipv6_header_uses_hop_limit_255() {
        let frame = build_neighbor_solicitation(sample_src_mac(), sample_src_ip(), sample_target());
        let hop_limit_byte = frame[ETH_HEADER_LEN + 7];
        assert_eq!(hop_limit_byte, 255);
    }

    #[test]
    fn ndp_ethernet_destination_is_solicited_node_multicast_mac() {
        let target = sample_target();
        let frame = build_neighbor_solicitation(sample_src_mac(), sample_src_ip(), target);
        let dst_mac = &frame[..6];
        let expected = solicited_node_multicast_mac(target);
        assert_eq!(
            dst_mac,
            &[expected.0, expected.1, expected.2, expected.3, expected.4, expected.5]
        );
    }

    #[test]
    fn ndp_icmpv6_checksum_matches_rfc_4443_pseudo_header_expectation() {
        let frame = build_neighbor_solicitation(sample_src_mac(), sample_src_ip(), sample_target());
        let ns_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let cksum_from_frame = u16::from_be_bytes([frame[ns_start + 2], frame[ns_start + 3]]);
        let mut recomputed = frame[ns_start..].to_vec();
        recomputed[2] = 0;
        recomputed[3] = 0;
        let icmp = Icmpv6Packet::new(&recomputed).expect("icmpv6 view");
        let dst = solicited_node_multicast(sample_target());
        let recomputed_cksum = icmpv6_checksum(&icmp, &sample_src_ip(), &dst);
        assert_eq!(cksum_from_frame, recomputed_cksum);
        assert_ne!(cksum_from_frame, 0);
    }

    fn build_advertisement_frame(target: Ipv6Addr, target_mac: MacAddr) -> Vec<u8> {
        const NA_LEN: usize = 32;
        let mut frame = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + NA_LEN];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame[..ETH_HEADER_LEN]).expect("eth");
            eth.set_destination(sample_src_mac());
            eth.set_source(target_mac);
            eth.set_ethertype(EtherTypes::Ipv6);
        }
        {
            let mut ipv6 = MutableIpv6Packet::new(
                &mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN],
            )
            .expect("ipv6");
            ipv6.set_version(6);
            ipv6.set_payload_length(NA_LEN as u16);
            ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
            ipv6.set_hop_limit(NDP_HOP_LIMIT);
            ipv6.set_source(target);
            ipv6.set_destination(sample_src_ip());
        }
        {
            let na_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
            let mut na = MutableNeighborAdvertPacket::new(&mut frame[na_start..]).expect("na view");
            na.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
            na.set_icmpv6_code(Icmpv6Code(0));
            na.set_flags(0x60);
            na.set_reserved(0);
            na.set_target_addr(target);
            na.set_options(&[NdpOption {
                option_type: NdpOptionTypes::TargetLLAddr,
                length: 1,
                data: vec![
                    target_mac.0,
                    target_mac.1,
                    target_mac.2,
                    target_mac.3,
                    target_mac.4,
                    target_mac.5,
                ],
            }]);
        }
        frame
    }

    #[test]
    fn ndp_advertisement_parser_extracts_target_link_layer_address() {
        let target = sample_target();
        let mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let frame = build_advertisement_frame(target, mac);
        let parsed = parse_neighbor_advertisement(&frame, target).expect("parsed");
        assert_eq!(parsed, mac);
    }

    #[test]
    fn ndp_advertisement_parser_rejects_wrong_target_address() {
        let target = sample_target();
        let other: Ipv6Addr = "2001:db8::9999".parse().unwrap();
        let frame =
            build_advertisement_frame(other, MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        assert!(parse_neighbor_advertisement(&frame, target).is_none());
    }

    #[test]
    fn ndp_advertisement_parser_rejects_non_ipv6_ethertype() {
        let mut frame = vec![0u8; 64];
        let mut eth = MutableEthernetPacket::new(&mut frame[..ETH_HEADER_LEN]).expect("eth");
        eth.set_ethertype(EtherTypes::Ipv4);
        assert!(parse_neighbor_advertisement(&frame, sample_target()).is_none());
    }

    #[test]
    fn ndp_advertisement_parser_rejects_solicitation_type() {
        let target = sample_target();
        let frame = build_neighbor_solicitation(sample_src_mac(), sample_src_ip(), target);
        assert!(parse_neighbor_advertisement(&frame, target).is_none());
    }

    #[test]
    fn ndp_prober_new_accepts_empty_interface() {
        let prober = NdpProber::new(String::new()).expect("empty allowed");
        assert!(prober.interface().is_empty());
    }

    #[test]
    fn ndp_prober_new_rejects_unknown_interface_name() {
        let err = NdpProber::new("no-such-iface-anywhere".to_string()).expect_err("must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("no-such-iface-anywhere"), "got: {msg}");
                assert!(msg.contains("not found"), "got: {msg}");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn ndp_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<NdpProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[test]
    fn kind_returns_ndp_for_ndp_variant() {
        let prober = NdpProber::new(String::new()).expect("valid");
        assert_eq!(prober.kind(), ProbeKind::Ndp);
    }

    #[test]
    fn default_interface_is_empty_string() {
        assert!(default_interface().is_empty());
    }

    #[test]
    fn format_mac_is_lower_hex_colon_separated() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc);
        assert_eq!(format_mac(mac), "00:11:22:aa:bb:cc");
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
    fn first_ipv6_source_prefers_matching_scope_link_local() {
        let iface = synthesize_interface(
            "test",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            vec![
                IpNetwork::V6("2001:db8::1/64".parse().unwrap()),
                IpNetwork::V6("fe80::1/64".parse().unwrap()),
            ],
        );
        let target: Ipv6Addr = "fe80::abcd".parse().unwrap();
        assert_eq!(
            first_ipv6_source(&iface, target),
            Some("fe80::1".parse().unwrap())
        );
    }

    #[test]
    fn first_ipv6_source_prefers_global_for_global_target() {
        let iface = synthesize_interface(
            "test",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            vec![
                IpNetwork::V6("fe80::1/64".parse().unwrap()),
                IpNetwork::V6("2001:db8::1/64".parse().unwrap()),
            ],
        );
        let target: Ipv6Addr = "2001:db8::abcd".parse().unwrap();
        assert_eq!(
            first_ipv6_source(&iface, target),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn promiscuous_mode_is_disabled() {
        let config = build_channel_config();
        assert!(
            !config.promiscuous,
            "NDP prober must not put the interface in promiscuous mode"
        );
        assert_eq!(config.read_timeout, Some(RECV_POLL_INTERVAL));
    }

    #[test]
    fn is_link_local_detects_fe80_prefix() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(is_link_local("fe80::abcd:ef12".parse().unwrap()));
        assert!(!is_link_local("2001:db8::1".parse().unwrap()));
        assert!(!is_link_local("::1".parse().unwrap()));
    }
}
