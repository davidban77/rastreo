#[cfg(feature = "snmp")]
use rastreo_core::prober::SnmpVersion;
use rastreo_core::prober::{parse_probe_selection, DnsQueryType, UdpProtocol};
use rastreo_core::ProbeKind;

pub(crate) const PROBE_LONG_HELP: &str = "\
Probe kinds to run, comma-separated or repeated. Omit the flag to run the default set.

Kinds, and the build feature each one needs:
  tcp_connect (alias tcp)  always available
  udp                      always available   needs --udp-protocol
  dns                      always available   needs --dns-query
  reverse_dns              always available
  http                     --features http
  snmp                     --features snmp
  ssh                      --features ssh
  icmp                     --features icmp
  tls                      --features tls
  arp                      --features arp     sends from --interface
  ndp                      --features ndp     sends from --interface
  gnmi                     --features gnmi
  lldp                     --features lldp

  default                  every kind this build carries that needs no parameter, is not
                           link-layer, and emits no second stream

Naming a kind explicitly runs it even where the default set would skip it: --probe icmp
attempts an ICMP socket on a host that cannot open one and reports the fault.

--port feeds tcp_connect, http, and udp. Every other kind keeps its protocol port unless
--probe-ports <kind>=<port>[,<port>...] overrides it.";

pub(crate) fn parse_probe_ports(raw: &str) -> Result<(ProbeKind, Vec<u16>), String> {
    let (name, ports) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected <kind>=<port>[,<port>...], got {raw:?}"))?;
    let kind = probe_kind_from_token(name.trim())?;
    let ports = ports
        .split(',')
        .map(|port| {
            let port = port.trim();
            port.parse::<u16>()
                .map_err(|err| format!("invalid port {port:?}: {err}"))
        })
        .collect::<Result<Vec<u16>, String>>()?;
    Ok((kind, ports))
}

fn probe_kind_from_token(token: &str) -> Result<ProbeKind, String> {
    let values = [token.to_string()];
    let selection = parse_probe_selection(&values).map_err(|err| err.to_string())?;
    selection
        .named
        .first()
        .copied()
        .ok_or_else(|| format!("'{token}' names no single probe kind"))
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpProtocolArg {
    #[value(name = "ntp")]
    Ntp,
    #[value(name = "sip_options")]
    SipOptions,
    #[value(name = "memcached_stats")]
    MemcachedStats,
    #[value(name = "stun_binding")]
    StunBinding,
}

impl From<UdpProtocolArg> for UdpProtocol {
    fn from(value: UdpProtocolArg) -> Self {
        match value {
            UdpProtocolArg::Ntp => UdpProtocol::Ntp,
            UdpProtocolArg::SipOptions => UdpProtocol::SipOptions,
            UdpProtocolArg::MemcachedStats => UdpProtocol::MemcachedStats,
            UdpProtocolArg::StunBinding => UdpProtocol::StunBinding,
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsQueryTypeArg {
    #[value(name = "a")]
    A,
    #[value(name = "aaaa")]
    Aaaa,
    #[value(name = "mx")]
    Mx,
    #[value(name = "txt")]
    Txt,
    #[value(name = "ptr")]
    Ptr,
    #[value(name = "ns")]
    Ns,
    #[value(name = "cname")]
    Cname,
}

impl From<DnsQueryTypeArg> for DnsQueryType {
    fn from(value: DnsQueryTypeArg) -> Self {
        match value {
            DnsQueryTypeArg::A => DnsQueryType::A,
            DnsQueryTypeArg::Aaaa => DnsQueryType::Aaaa,
            DnsQueryTypeArg::Mx => DnsQueryType::Mx,
            DnsQueryTypeArg::Txt => DnsQueryType::Txt,
            DnsQueryTypeArg::Ptr => DnsQueryType::Ptr,
            DnsQueryTypeArg::Ns => DnsQueryType::Ns,
            DnsQueryTypeArg::Cname => DnsQueryType::Cname,
        }
    }
}

#[cfg(feature = "snmp")]
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnmpVersionArg {
    #[value(name = "v1")]
    V1,
    #[value(name = "v2c")]
    V2c,
    #[value(name = "v3")]
    V3,
}

#[cfg(feature = "snmp")]
impl From<SnmpVersionArg> for SnmpVersion {
    fn from(value: SnmpVersionArg) -> Self {
        match value {
            SnmpVersionArg::V1 => SnmpVersion::V1,
            SnmpVersionArg::V2c => SnmpVersion::V2c,
            SnmpVersionArg::V3 => SnmpVersion::V3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum as _;
    use rstest::rstest;

    // Exhaustive over the core enum: a new core variant with no mirror fails to compile here.
    fn mirror_udp(protocol: UdpProtocol) -> UdpProtocolArg {
        match protocol {
            UdpProtocol::Ntp => UdpProtocolArg::Ntp,
            UdpProtocol::SipOptions => UdpProtocolArg::SipOptions,
            UdpProtocol::MemcachedStats => UdpProtocolArg::MemcachedStats,
            UdpProtocol::StunBinding => UdpProtocolArg::StunBinding,
        }
    }

    fn mirror_dns(query_type: DnsQueryType) -> DnsQueryTypeArg {
        match query_type {
            DnsQueryType::A => DnsQueryTypeArg::A,
            DnsQueryType::Aaaa => DnsQueryTypeArg::Aaaa,
            DnsQueryType::Mx => DnsQueryTypeArg::Mx,
            DnsQueryType::Txt => DnsQueryTypeArg::Txt,
            DnsQueryType::Ptr => DnsQueryTypeArg::Ptr,
            DnsQueryType::Ns => DnsQueryTypeArg::Ns,
            DnsQueryType::Cname => DnsQueryTypeArg::Cname,
        }
    }

    #[test]
    fn every_udp_protocol_arg_round_trips_through_core() {
        for arg in UdpProtocolArg::value_variants() {
            assert_eq!(mirror_udp(UdpProtocol::from(*arg)), *arg);
        }
    }

    #[test]
    fn every_dns_query_type_arg_round_trips_through_core() {
        for arg in DnsQueryTypeArg::value_variants() {
            assert_eq!(mirror_dns(DnsQueryType::from(*arg)), *arg);
        }
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn every_snmp_version_arg_maps_to_a_distinct_core_version() {
        let mapped: Vec<SnmpVersion> = SnmpVersionArg::value_variants()
            .iter()
            .map(|arg| SnmpVersion::from(*arg))
            .collect();
        assert_eq!(
            mapped,
            vec![SnmpVersion::V1, SnmpVersion::V2c, SnmpVersion::V3]
        );
    }

    #[rstest]
    #[case("ntp", UdpProtocolArg::Ntp)]
    #[case("sip_options", UdpProtocolArg::SipOptions)]
    #[case("memcached_stats", UdpProtocolArg::MemcachedStats)]
    #[case("stun_binding", UdpProtocolArg::StunBinding)]
    fn udp_protocol_parses_the_yaml_spelling(
        #[case] token: &str,
        #[case] expected: UdpProtocolArg,
    ) {
        assert_eq!(
            UdpProtocolArg::from_str(token, true).expect("parses"),
            expected
        );
    }

    #[rstest]
    #[case("a", DnsQueryTypeArg::A)]
    #[case("aaaa", DnsQueryTypeArg::Aaaa)]
    #[case("cname", DnsQueryTypeArg::Cname)]
    fn dns_query_type_parses_the_yaml_spelling(
        #[case] token: &str,
        #[case] expected: DnsQueryTypeArg,
    ) {
        assert_eq!(
            DnsQueryTypeArg::from_str(token, true).expect("parses"),
            expected
        );
    }

    #[cfg(feature = "snmp")]
    #[rstest]
    #[case("v1", SnmpVersionArg::V1)]
    #[case("v2c", SnmpVersionArg::V2c)]
    #[case("v3", SnmpVersionArg::V3)]
    fn snmp_version_parses_the_yaml_spelling(
        #[case] token: &str,
        #[case] expected: SnmpVersionArg,
    ) {
        assert_eq!(
            SnmpVersionArg::from_str(token, true).expect("parses"),
            expected
        );
    }

    #[test]
    fn udp_protocol_rejects_the_kebab_spelling() {
        assert!(UdpProtocolArg::from_str("sip-options", true).is_err());
    }

    #[test]
    fn probe_ports_parses_a_single_port() {
        assert_eq!(
            parse_probe_ports("dns=5353").expect("parses"),
            (ProbeKind::Dns, vec![5353])
        );
    }

    #[test]
    fn probe_ports_parses_a_comma_separated_list() {
        assert_eq!(
            parse_probe_ports("tcp_connect=80,443,8080").expect("parses"),
            (ProbeKind::TcpConnect, vec![80, 443, 8080])
        );
    }

    #[test]
    fn probe_ports_accepts_the_tcp_alias() {
        assert_eq!(
            parse_probe_ports("tcp=2222").expect("parses"),
            (ProbeKind::TcpConnect, vec![2222])
        );
    }

    #[test]
    fn probe_ports_trims_whitespace_around_the_kind_and_the_ports() {
        assert_eq!(
            parse_probe_ports(" dns = 53 , 5353 ").expect("parses"),
            (ProbeKind::Dns, vec![53, 5353])
        );
    }

    #[test]
    fn probe_ports_without_an_equals_names_the_expected_shape() {
        let err = parse_probe_ports("dns").expect_err("no separator");
        assert!(err.contains("<kind>=<port>"), "err: {err}");
    }

    #[test]
    fn probe_ports_with_an_unknown_kind_lists_what_this_build_offers() {
        let err = parse_probe_ports("snmpp=1161").expect_err("unknown kind");
        assert!(err.contains("unknown probe kind 'snmpp'"), "err: {err}");
        assert!(err.contains("tcp_connect"), "err: {err}");
    }

    #[test]
    fn probe_ports_rejects_the_default_keyword_as_a_kind() {
        let err = parse_probe_ports("default=80").expect_err("not a single kind");
        assert!(err.contains("no single probe kind"), "err: {err}");
    }

    #[test]
    fn probe_ports_rejects_a_non_numeric_port() {
        let err = parse_probe_ports("dns=http").expect_err("bad port");
        assert!(err.contains("invalid port"), "err: {err}");
    }

    #[test]
    fn probe_ports_rejects_an_out_of_range_port() {
        assert!(parse_probe_ports("dns=70000").is_err());
    }

    #[test]
    fn probe_ports_rejects_an_empty_port_list() {
        assert!(parse_probe_ports("dns=").is_err());
    }

    #[test]
    fn probe_long_help_names_every_probe_kind() {
        for kind in ProbeKind::all() {
            assert!(
                PROBE_LONG_HELP.contains(kind.label()),
                "--probe long help omits {}",
                kind.label()
            );
        }
    }

    #[test]
    fn probe_long_help_names_the_cargo_feature_every_gated_kind_needs() {
        for kind in ProbeKind::all() {
            let Some(feature) = rastreo_core::prober::required_feature(*kind) else {
                continue;
            };
            assert!(
                PROBE_LONG_HELP.contains(&format!("--features {feature}")),
                "--probe long help must tell a {} user which feature to rebuild with",
                kind.label()
            );
        }
    }
}
