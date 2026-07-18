use std::net::{IpAddr, Ipv4Addr};

use ipnetwork::IpNetwork;
use pnet_datalink::{MacAddr, NetworkInterface};
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::Packet;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget};
use crate::prober::link_layer::{
    lookup_interface, probe_link_layer, LinkLayerEngines, LinkLayerProtocol, ETH_HEADER_LEN,
};
use crate::prober::Prober;

const ARP_PACKET_LEN: usize = 28;
const ARP_FRAME_LEN: usize = ETH_HEADER_LEN + ARP_PACKET_LEN;

pub fn default_interface() -> String {
    String::new()
}

#[derive(Debug)]
pub struct ArpProber {
    interface: String,
    engines: LinkLayerEngines<Arp>,
}

impl ArpProber {
    pub fn new(interface: String) -> Result<Self, RastreoError> {
        if !interface.is_empty() && lookup_interface(&interface).is_none() {
            return Err(
                ConfigError::invalid(format!("network interface '{interface}' not found")).into(),
            );
        }
        Ok(Self {
            interface,
            engines: LinkLayerEngines::new(),
        })
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

pub(crate) struct Arp;

impl LinkLayerProtocol for Arp {
    type Addr = Ipv4Addr;

    const NAME: &'static str = "arp";
    const NAME_UPPER: &'static str = "ARP";
    const ADDRESS_FAMILY: &'static str = "ipv4";

    fn kind() -> ProbeKind {
        ProbeKind::Arp
    }

    fn extract_target(ip: IpAddr) -> Option<Ipv4Addr> {
        match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        }
    }

    fn wrong_family_detail() -> &'static str {
        "arp prober requires an IPv4 target; use ndp for IPv6"
    }

    fn select_interface(target: Ipv4Addr) -> Option<NetworkInterface> {
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

    fn source_address(iface: &NetworkInterface, _target: Ipv4Addr) -> Option<Ipv4Addr> {
        iface.ips.iter().find_map(|net| match net {
            IpNetwork::V4(v4) => Some(v4.ip()),
            _ => None,
        })
    }

    fn build_request(src_mac: MacAddr, src_ip: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
        let mut frame = vec![0u8; ARP_FRAME_LEN];
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
            arp.set_target_proto_addr(target);
        }
        frame
    }

    fn parse_reply_source(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
        let eth = EthernetPacket::new(frame)?;
        if eth.get_ethertype() != EtherTypes::Arp {
            return None;
        }
        let arp = ArpPacket::new(eth.payload())?;
        if arp.get_operation() != ArpOperations::Reply {
            return None;
        }
        Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
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
        probe_link_layer::<Arp>(&self.engines, &self.interface, target, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProbeErrorKind;
    use crate::model::Target;
    use std::time::{Duration, SystemTime};

    fn sample_mac() -> MacAddr {
        MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    }

    #[test]
    fn arp_request_frame_has_correct_ethertype_and_opcode() {
        let src_mac = sample_mac();
        let src_ip = Ipv4Addr::new(10, 0, 0, 5);
        let target_ip = Ipv4Addr::new(10, 0, 0, 42);
        let frame = Arp::build_request(src_mac, src_ip, target_ip);
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
        let frame = Arp::build_request(
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
        let frame = Arp::build_request(
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
    fn arp_reply_parser_extracts_sender_ip_and_mac() {
        let expected_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let sender_ip = Ipv4Addr::new(10, 0, 0, 42);
        let frame = build_reply_frame(expected_mac, sender_ip);
        let (ip, mac) = Arp::parse_reply_source(&frame).expect("reply parsed");
        assert_eq!(ip, sender_ip);
        assert_eq!(mac, expected_mac);
    }

    #[test]
    fn arp_reply_parser_rejects_request_opcode() {
        let frame = Arp::build_request(
            sample_mac(),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 42),
        );
        assert!(Arp::parse_reply_source(&frame).is_none());
    }

    #[test]
    fn arp_reply_parser_rejects_non_arp_ethertype() {
        let mut frame = vec![0u8; ARP_FRAME_LEN];
        let mut eth = MutableEthernetPacket::new(&mut frame[..ETH_HEADER_LEN]).expect("eth");
        eth.set_ethertype(EtherTypes::Ipv4);
        assert!(Arp::parse_reply_source(&frame).is_none());
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

    #[tokio::test]
    async fn probe_rejects_ipv6_target_as_wrong_family_fault() {
        let prober = ArpProber::new(String::new()).expect("valid");
        let ip = IpAddr::V6("2001:db8::1".parse().unwrap());
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
        assert_eq!(outcome.kind, ProbeKind::Arp);
        assert!(!outcome.reachable);
        let fault = outcome.fault.expect("wrong-family is a fault");
        assert_eq!(fault.kind, ProbeErrorKind::Other);
        assert!(
            fault.detail.contains("requires an IPv4 target"),
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
        assert_eq!(
            Arp::source_address(&iface, Ipv4Addr::new(10, 0, 0, 42)),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[test]
    fn first_ipv4_returns_none_on_ipv6_only_interface() {
        let iface = synthesize_interface(
            "v6only",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            vec![IpNetwork::V6("fe80::1/64".parse().unwrap())],
        );
        assert!(Arp::source_address(&iface, Ipv4Addr::new(10, 0, 0, 42)).is_none());
    }
}
