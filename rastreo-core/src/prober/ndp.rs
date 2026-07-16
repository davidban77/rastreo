use std::net::{IpAddr, Ipv6Addr};

use ipnetwork::IpNetwork;
use pnet_datalink::{MacAddr, NetworkInterface};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::icmpv6::ndp::{
    MutableNeighborSolicitPacket, NdpOption, NdpOptionTypes, NeighborAdvertPacket,
};
use pnet_packet::icmpv6::{checksum as icmpv6_checksum, Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet_packet::Packet;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget};
use crate::prober::link_layer::{
    lookup_interface, probe_link_layer, LinkLayerProtocol, ETH_HEADER_LEN,
};
use crate::prober::Prober;

const IPV6_HEADER_LEN: usize = 40;
const NS_ICMPV6_LEN: usize = 32;
const NS_FRAME_LEN: usize = ETH_HEADER_LEN + IPV6_HEADER_LEN + NS_ICMPV6_LEN;
const NDP_HOP_LIMIT: u8 = 255;

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

pub(crate) struct Ndp;

impl LinkLayerProtocol for Ndp {
    type Addr = Ipv6Addr;

    const NAME: &'static str = "ndp";
    const NAME_UPPER: &'static str = "NDP";
    const ADDRESS_FAMILY: &'static str = "ipv6";

    fn kind() -> ProbeKind {
        ProbeKind::Ndp
    }

    fn extract_target(ip: IpAddr) -> Option<Ipv6Addr> {
        match ip {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        }
    }

    fn wrong_family_detail() -> &'static str {
        "ndp prober requires an IPv6 target; use arp for IPv4"
    }

    fn select_interface(target: Ipv6Addr) -> Option<NetworkInterface> {
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

    fn source_address(iface: &NetworkInterface, target: Ipv6Addr) -> Option<Ipv6Addr> {
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

    fn build_request(src_mac: MacAddr, src_ip: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
        let mut frame = vec![0u8; NS_FRAME_LEN];
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
            let mut ipv6 = MutableIpv6Packet::new(
                &mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN],
            )
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

    fn parse_reply(frame: &[u8], target: Ipv6Addr) -> Option<MacAddr> {
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
        probe_link_layer::<Ndp>(&self.interface, target, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProbeErrorKind;
    use crate::model::Target;
    use pnet_packet::icmpv6::ndp::MutableNeighborAdvertPacket;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

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
        let frame = Ndp::build_request(sample_src_mac(), sample_src_ip(), sample_target());
        let ns_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        assert_eq!(frame[ns_start], 135);
        assert_eq!(frame[ns_start + 1], 0);
    }

    #[test]
    fn ndp_neighbor_solicitation_includes_source_link_layer_option() {
        let frame = Ndp::build_request(sample_src_mac(), sample_src_ip(), sample_target());
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
        let frame = Ndp::build_request(sample_src_mac(), sample_src_ip(), target);
        let ns_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let target_bytes = &frame[ns_start + 8..ns_start + 24];
        assert_eq!(target_bytes, &target.octets());
    }

    #[test]
    fn ndp_ipv6_header_uses_hop_limit_255() {
        let frame = Ndp::build_request(sample_src_mac(), sample_src_ip(), sample_target());
        let hop_limit_byte = frame[ETH_HEADER_LEN + 7];
        assert_eq!(hop_limit_byte, 255);
    }

    #[test]
    fn ndp_ethernet_destination_is_solicited_node_multicast_mac() {
        let target = sample_target();
        let frame = Ndp::build_request(sample_src_mac(), sample_src_ip(), target);
        let dst_mac = &frame[..6];
        let expected = solicited_node_multicast_mac(target);
        assert_eq!(
            dst_mac,
            &[expected.0, expected.1, expected.2, expected.3, expected.4, expected.5]
        );
    }

    #[test]
    fn ndp_icmpv6_checksum_matches_rfc_4443_pseudo_header_expectation() {
        let frame = Ndp::build_request(sample_src_mac(), sample_src_ip(), sample_target());
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
        let parsed = Ndp::parse_reply(&frame, target).expect("parsed");
        assert_eq!(parsed, mac);
    }

    #[test]
    fn ndp_advertisement_parser_rejects_wrong_target_address() {
        let target = sample_target();
        let other: Ipv6Addr = "2001:db8::9999".parse().unwrap();
        let frame =
            build_advertisement_frame(other, MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        assert!(Ndp::parse_reply(&frame, target).is_none());
    }

    #[test]
    fn ndp_advertisement_parser_rejects_non_ipv6_ethertype() {
        let mut frame = vec![0u8; 64];
        let mut eth = MutableEthernetPacket::new(&mut frame[..ETH_HEADER_LEN]).expect("eth");
        eth.set_ethertype(EtherTypes::Ipv4);
        assert!(Ndp::parse_reply(&frame, sample_target()).is_none());
    }

    #[test]
    fn ndp_advertisement_parser_rejects_solicitation_type() {
        let target = sample_target();
        let frame = Ndp::build_request(sample_src_mac(), sample_src_ip(), target);
        assert!(Ndp::parse_reply(&frame, target).is_none());
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

    #[tokio::test]
    async fn probe_rejects_ipv4_target_as_wrong_family_fault() {
        let prober = NdpProber::new(String::new()).expect("valid");
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let target = ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let ctx = ProbeCtx::new(Duration::from_millis(100), 0);
        let outcome = prober
            .probe(&target, &ctx)
            .await
            .expect("returns an Ok outcome, not Err");
        assert_eq!(outcome.kind, ProbeKind::Ndp);
        assert!(!outcome.reachable);
        let fault = outcome.fault.expect("wrong-family is a fault");
        assert_eq!(fault.kind, ProbeErrorKind::Other);
        assert!(
            fault.detail.contains("requires an IPv6 target"),
            "got: {}",
            fault.detail
        );
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
            Ndp::source_address(&iface, target),
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
            Ndp::source_address(&iface, target),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn is_link_local_detects_fe80_prefix() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(is_link_local("fe80::abcd:ef12".parse().unwrap()));
        assert!(!is_link_local("2001:db8::1".parse().unwrap()));
        assert!(!is_link_local("::1".parse().unwrap()));
    }
}
