//! Probe-kind selection: name parsing, the zero-config default set, and expansion into `ProberConfig`s.

use std::collections::BTreeMap;

use crate::error::{ConfigError, RastreoError};
use crate::model::ProbeKind;
use crate::prober::udp;
#[cfg(feature = "http")]
use crate::prober::{http, HttpScheme};
#[cfg(feature = "snmp")]
use crate::prober::{snmp, Community, SnmpVersion};
use crate::prober::{DnsQueryType, DnsTransport, ProberConfig, UdpProtocol};

pub const DEFAULT_TCP_PORTS: &[u16] = &[22, 23, 80, 443, 830, 8080];
pub const DEFAULT_HTTP_PORTS: &[u16] = &[80, 443, 8080, 8443];

const DEFAULT_ORDER: &[ProbeKind] = &[
    ProbeKind::Icmp,
    ProbeKind::TcpConnect,
    ProbeKind::Http,
    ProbeKind::Ssh,
    ProbeKind::Tls,
    ProbeKind::Snmp,
    ProbeKind::ReverseDns,
];

const DEFAULT_KEYWORD: &str = "default";
const TCP_ALIAS: &str = "tcp";
const UDP_PROTOCOL_PARAM: &str =
    "a udp protocol (ntp | sip_options | memcached_stats | stun_binding)";
const DNS_QUERY_PARAM: &str = "at least one dns query name";

impl ProbeKind {
    pub const fn is_compiled_in(self) -> bool {
        match self {
            ProbeKind::TcpConnect | ProbeKind::Udp | ProbeKind::Dns | ProbeKind::ReverseDns => true,
            ProbeKind::Http => cfg!(feature = "http"),
            ProbeKind::Snmp => cfg!(feature = "snmp"),
            ProbeKind::Lldp => cfg!(feature = "lldp"),
            ProbeKind::Arp => cfg!(feature = "arp"),
            ProbeKind::Ndp => cfg!(feature = "ndp"),
            ProbeKind::Ssh => cfg!(feature = "ssh"),
            ProbeKind::Icmp => cfg!(feature = "icmp"),
            ProbeKind::Tls => cfg!(feature = "tls"),
            ProbeKind::Gnmi => cfg!(feature = "gnmi"),
        }
    }

    pub const fn required_feature(self) -> Option<&'static str> {
        match self {
            ProbeKind::TcpConnect | ProbeKind::Udp | ProbeKind::Dns | ProbeKind::ReverseDns => None,
            ProbeKind::Http => Some("http"),
            ProbeKind::Snmp => Some("snmp"),
            ProbeKind::Lldp => Some("lldp"),
            ProbeKind::Arp => Some("arp"),
            ProbeKind::Ndp => Some("ndp"),
            ProbeKind::Ssh => Some("ssh"),
            ProbeKind::Icmp => Some("icmp"),
            ProbeKind::Tls => Some("tls"),
            ProbeKind::Gnmi => Some("gnmi"),
        }
    }

    /// Whether the kind draws from [`ProbeSelectionOptions::ports`] — true for the kinds whose
    /// `ProberConfig` requires an explicit port list, false for those carrying a protocol default.
    pub const fn consumes_shared_ports(self) -> bool {
        match self {
            ProbeKind::TcpConnect | ProbeKind::Http | ProbeKind::Udp => true,
            ProbeKind::Dns
            | ProbeKind::Snmp
            | ProbeKind::Lldp
            | ProbeKind::Arp
            | ProbeKind::Ndp
            | ProbeKind::Ssh
            | ProbeKind::Icmp
            | ProbeKind::Tls
            | ProbeKind::Gnmi
            | ProbeKind::ReverseDns => false,
        }
    }

    /// Whether the kind feeds a second record stream, which makes a scenario containing it
    /// resume-ineligible.
    pub const fn emits_second_stream(self) -> bool {
        match self {
            ProbeKind::Lldp | ProbeKind::Gnmi => true,
            ProbeKind::TcpConnect
            | ProbeKind::Udp
            | ProbeKind::Http
            | ProbeKind::Dns
            | ProbeKind::Snmp
            | ProbeKind::Arp
            | ProbeKind::Ndp
            | ProbeKind::Ssh
            | ProbeKind::Icmp
            | ProbeKind::Tls
            | ProbeKind::ReverseDns => false,
        }
    }
}

const fn requires_explicit_param(kind: ProbeKind) -> bool {
    match kind {
        ProbeKind::Udp | ProbeKind::Dns => true,
        ProbeKind::TcpConnect
        | ProbeKind::Http
        | ProbeKind::Snmp
        | ProbeKind::Lldp
        | ProbeKind::Arp
        | ProbeKind::Ndp
        | ProbeKind::Ssh
        | ProbeKind::Icmp
        | ProbeKind::Tls
        | ProbeKind::Gnmi
        | ProbeKind::ReverseDns => false,
    }
}

const fn is_link_layer(kind: ProbeKind) -> bool {
    match kind {
        ProbeKind::Arp | ProbeKind::Ndp => true,
        ProbeKind::TcpConnect
        | ProbeKind::Udp
        | ProbeKind::Http
        | ProbeKind::Dns
        | ProbeKind::Snmp
        | ProbeKind::Lldp
        | ProbeKind::Ssh
        | ProbeKind::Icmp
        | ProbeKind::Tls
        | ProbeKind::Gnmi
        | ProbeKind::ReverseDns => false,
    }
}

const fn has_runnability_precondition(kind: ProbeKind) -> bool {
    match kind {
        ProbeKind::Icmp => true,
        ProbeKind::TcpConnect
        | ProbeKind::Udp
        | ProbeKind::Http
        | ProbeKind::Dns
        | ProbeKind::Snmp
        | ProbeKind::Lldp
        | ProbeKind::Arp
        | ProbeKind::Ndp
        | ProbeKind::Ssh
        | ProbeKind::Tls
        | ProbeKind::Gnmi
        | ProbeKind::ReverseDns => false,
    }
}

const fn is_default_eligible(kind: ProbeKind) -> bool {
    kind.is_compiled_in()
        && !requires_explicit_param(kind)
        && !is_link_layer(kind)
        && !kind.emits_second_stream()
}

pub fn available_probe_kinds() -> Vec<ProbeKind> {
    ProbeKind::all()
        .iter()
        .copied()
        .filter(|kind| kind.is_compiled_in())
        .collect()
}

/// The kinds a scan runs when the operator names none: compiled in, runnable with no parameter,
/// not link-layer, and feeding no second stream.
pub fn default_probe_kinds() -> Vec<ProbeKind> {
    DEFAULT_ORDER
        .iter()
        .copied()
        .filter(|kind| is_default_eligible(*kind))
        .collect()
}

/// Parses canonical [`ProbeKind::label`] values, the `tcp` alias, and the `default` keyword.
pub fn parse_probe_selection(values: &[String]) -> Result<ProbeSelection, RastreoError> {
    let mut named: Vec<ProbeKind> = Vec::new();
    let mut defaulted: Vec<ProbeKind> = Vec::new();

    for value in values {
        match value.trim() {
            DEFAULT_KEYWORD => {
                for kind in default_probe_kinds() {
                    push_unique(&mut defaulted, kind);
                }
            }
            TCP_ALIAS => push_unique(&mut named, ProbeKind::TcpConnect),
            other => match ProbeKind::from_label(other) {
                Some(kind) => push_unique(&mut named, kind),
                None => return Err(unknown_probe_kind(other)),
            },
        }
    }

    defaulted.retain(|kind| !named.contains(kind));
    Ok(ProbeSelection { named, defaulted })
}

/// Drops defaulted kinds whose runtime precondition `predicate` rejects; named kinds always survive.
pub fn apply_runnability_filter(
    selection: ProbeSelection,
    predicate: impl Fn(ProbeKind) -> bool,
) -> Vec<ProbeKind> {
    let mut kinds = selection.named;
    for kind in selection.defaulted {
        if !has_runnability_precondition(kind) || predicate(kind) {
            kinds.push(kind);
        }
    }
    kinds
}

/// Builds one `ProberConfig` per kind, resolving ports as per-kind override → shared ports →
/// protocol default.
pub fn expand_probe_selection(
    kinds: &[ProbeKind],
    options: &ProbeSelectionOptions,
) -> Result<Vec<ProberConfig>, RastreoError> {
    if kinds.is_empty() {
        return Err(ConfigError::EmptyProbeSelection.into());
    }

    let mut unique: Vec<ProbeKind> = Vec::with_capacity(kinds.len());
    for kind in kinds.iter().copied() {
        push_unique(&mut unique, kind);
    }

    let mut configs = Vec::with_capacity(unique.len());
    for kind in unique {
        match kind {
            ProbeKind::TcpConnect => configs.push(ProberConfig::TcpConnect {
                ports: resolve_ports(kind, options, DEFAULT_TCP_PORTS),
            }),
            ProbeKind::Http => {
                #[cfg(feature = "http")]
                configs.push(ProberConfig::Http {
                    ports: resolve_ports(kind, options, DEFAULT_HTTP_PORTS),
                    scheme: options.http_scheme,
                    path: options.http_path.clone(),
                    tls_verify: http::default_tls_verify(),
                    user_agent: http::default_user_agent(),
                });
                #[cfg(not(feature = "http"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::Dns => {
                if options.dns_query_names.is_empty() {
                    return Err(missing_param(kind, DNS_QUERY_PARAM));
                }
                configs.push(ProberConfig::Dns {
                    ports: resolve_ports(kind, options, &crate::prober::dns::default_ports()),
                    query_names: options.dns_query_names.clone(),
                    query_type: options.dns_query_type,
                    transport: DnsTransport::default(),
                    recursion_desired: crate::prober::dns::default_recursion_desired(),
                });
            }
            ProbeKind::Udp => {
                let Some(protocol) = options.udp_protocol else {
                    return Err(missing_param(kind, UDP_PROTOCOL_PARAM));
                };
                configs.push(ProberConfig::Udp {
                    ports: resolve_ports(kind, options, udp::default_ports_for(protocol)),
                    protocol,
                });
            }
            ProbeKind::Snmp => {
                #[cfg(feature = "snmp")]
                configs.push(ProberConfig::Snmp {
                    ports: resolve_ports(kind, options, &snmp::default_ports()),
                    version: options.snmp_version,
                    community: options.snmp_community.clone(),
                    credentials: crate::prober::UsmCredentials::default(),
                });
                #[cfg(not(feature = "snmp"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::Lldp => {
                #[cfg(feature = "lldp")]
                configs.push(ProberConfig::Lldp {
                    ports: resolve_ports(kind, options, &snmp::default_ports()),
                    version: options.snmp_version,
                    community: options.snmp_community.clone(),
                    credentials: crate::prober::UsmCredentials::default(),
                    max_rows: crate::prober::lldp::default_max_rows(),
                });
                #[cfg(not(feature = "lldp"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::Arp => {
                #[cfg(feature = "arp")]
                configs.push(ProberConfig::Arp {
                    interface: options.interface.clone(),
                });
                #[cfg(not(feature = "arp"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::Ndp => {
                #[cfg(feature = "ndp")]
                configs.push(ProberConfig::Ndp {
                    interface: options.interface.clone(),
                });
                #[cfg(not(feature = "ndp"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::Ssh => {
                #[cfg(feature = "ssh")]
                configs.push(ProberConfig::Ssh {
                    ports: resolve_ports(kind, options, &crate::prober::ssh::default_ports()),
                });
                #[cfg(not(feature = "ssh"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::Icmp => {
                #[cfg(feature = "icmp")]
                configs.push(ProberConfig::Icmp {
                    count: options.icmp_count,
                    interval_ms: crate::prober::icmp::default_interval_ms(),
                });
                #[cfg(not(feature = "icmp"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::Tls => {
                #[cfg(feature = "tls")]
                configs.push(ProberConfig::Tls {
                    ports: resolve_ports(kind, options, &crate::prober::tls::default_ports()),
                });
                #[cfg(not(feature = "tls"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::Gnmi => {
                #[cfg(feature = "gnmi")]
                configs.push(ProberConfig::Gnmi {
                    ports: resolve_ports(kind, options, &crate::prober::gnmi::default_ports()),
                    plaintext: crate::prober::gnmi::default_plaintext(),
                    username: String::new(),
                    password: crate::prober::Password::default(),
                    get_paths: crate::prober::gnmi::default_get_paths(),
                    lldp: crate::prober::gnmi::default_lldp(),
                });
                #[cfg(not(feature = "gnmi"))]
                return Err(not_compiled(kind));
            }
            ProbeKind::ReverseDns => configs.push(ProberConfig::ReverseDns {
                resolvers: crate::prober::reverse_dns::default_resolvers(),
            }),
        }
    }

    Ok(configs)
}

/// A parsed selection split by provenance, so an explicitly named kind can outlive a runnability
/// filter that drops the same kind when it only arrived via `default`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ProbeSelection {
    pub named: Vec<ProbeKind>,
    pub defaulted: Vec<ProbeKind>,
}

/// Per-kind parameters [`expand_probe_selection`] reads when building each `ProberConfig`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProbeSelectionOptions {
    /// Ports applied to every selected kind for which [`ProbeKind::consumes_shared_ports`] holds; empty means absent.
    pub ports: Vec<u16>,
    pub ports_by_kind: BTreeMap<ProbeKind, Vec<u16>>,
    /// Empty means absent, which makes `dns` un-expandable.
    pub dns_query_names: Vec<String>,
    pub dns_query_type: DnsQueryType,
    #[cfg(feature = "snmp")]
    pub snmp_community: Community,
    #[cfg(feature = "snmp")]
    pub snmp_version: SnmpVersion,
    #[cfg(feature = "http")]
    pub http_scheme: HttpScheme,
    pub http_path: String,
    pub icmp_count: u32,
    pub interface: String,
    /// Absence is an error — a UDP probe must name a service.
    pub udp_protocol: Option<UdpProtocol>,
}

impl Default for ProbeSelectionOptions {
    fn default() -> Self {
        Self {
            ports: Vec::new(),
            ports_by_kind: BTreeMap::new(),
            dns_query_names: Vec::new(),
            dns_query_type: DnsQueryType::default(),
            #[cfg(feature = "snmp")]
            snmp_community: snmp::default_community(),
            #[cfg(feature = "snmp")]
            snmp_version: SnmpVersion::default(),
            #[cfg(feature = "http")]
            http_scheme: HttpScheme::default(),
            #[cfg(feature = "http")]
            http_path: http::default_path(),
            #[cfg(not(feature = "http"))]
            http_path: "/".to_string(),
            #[cfg(feature = "icmp")]
            icmp_count: crate::prober::icmp::default_count(),
            #[cfg(not(feature = "icmp"))]
            icmp_count: 3,
            #[cfg(feature = "arp")]
            interface: crate::prober::arp::default_interface(),
            #[cfg(not(feature = "arp"))]
            interface: String::new(),
            udp_protocol: None,
        }
    }
}

fn resolve_ports(kind: ProbeKind, options: &ProbeSelectionOptions, intrinsic: &[u16]) -> Vec<u16> {
    if let Some(explicit) = options
        .ports_by_kind
        .get(&kind)
        .filter(|ports| !ports.is_empty())
    {
        return explicit.clone();
    }
    if kind.consumes_shared_ports() && !options.ports.is_empty() {
        return options.ports.clone();
    }
    intrinsic.to_vec()
}

fn push_unique(kinds: &mut Vec<ProbeKind>, kind: ProbeKind) {
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
}

fn unknown_probe_kind(name: &str) -> RastreoError {
    let mut available: Vec<&'static str> = available_probe_kinds()
        .iter()
        .map(|kind| kind.label())
        .collect();
    available.push(DEFAULT_KEYWORD);
    available.push(TCP_ALIAS);
    ConfigError::UnknownProbeKind {
        name: name.to_string(),
        available: available.join(", "),
    }
    .into()
}

fn missing_param(kind: ProbeKind, param: &'static str) -> RastreoError {
    ConfigError::ProbeKindMissingParam {
        kind: kind.label(),
        param,
    }
    .into()
}

#[allow(
    dead_code,
    reason = "every call site is a #[cfg(not(feature = ...))] expansion arm"
)]
fn not_compiled(kind: ProbeKind) -> RastreoError {
    let feature = match kind.required_feature() {
        Some(feature) => feature,
        None => kind.label(),
    };
    ConfigError::ProbeKindNotCompiled {
        kind: kind.label(),
        feature,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    const DNS_QUERY_NAME: &str = "example.com.";
    #[cfg(feature = "config")]
    const EXPLICIT_PORTS: &[u16] = &[4242];

    fn tokens(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn expandable_options() -> ProbeSelectionOptions {
        ProbeSelectionOptions {
            dns_query_names: vec![DNS_QUERY_NAME.to_string()],
            udp_protocol: Some(UdpProtocol::Ntp),
            ..Default::default()
        }
    }

    /// What a YAML author gets from `type:` plus only the fields that carry no serde default.
    #[cfg(feature = "config")]
    fn yaml_default_config(kind: ProbeKind) -> ProberConfig {
        let mut yaml = format!("type: {}\n", kind.label());
        if kind.consumes_shared_ports() {
            yaml.push_str(&format!("ports: {EXPLICIT_PORTS:?}\n"));
        }
        match kind {
            ProbeKind::Udp => yaml.push_str("protocol: ntp\n"),
            ProbeKind::Dns => yaml.push_str(&format!("query_names: [{DNS_QUERY_NAME:?}]\n")),
            ProbeKind::TcpConnect
            | ProbeKind::Http
            | ProbeKind::ReverseDns
            | ProbeKind::Snmp
            | ProbeKind::Lldp
            | ProbeKind::Arp
            | ProbeKind::Ndp
            | ProbeKind::Ssh
            | ProbeKind::Icmp
            | ProbeKind::Tls
            | ProbeKind::Gnmi => {}
        }
        serde_yaml_ng::from_str(&yaml).unwrap_or_else(|err| {
            panic!("{} minimal YAML must parse:\n{yaml}\n{err}", kind.label())
        })
    }

    #[cfg(feature = "config")]
    fn as_json(config: &ProberConfig) -> serde_json::Value {
        serde_json::to_value(config).expect("prober config serializes")
    }

    fn expand_one(kind: ProbeKind, options: &ProbeSelectionOptions) -> ProberConfig {
        let mut configs = expand_probe_selection(&[kind], options).expect("expands");
        assert_eq!(configs.len(), 1);
        configs.remove(0)
    }

    fn ports_of(config: &ProberConfig) -> Option<Vec<u16>> {
        match config {
            ProberConfig::TcpConnect { ports } => Some(ports.clone()),
            #[cfg(feature = "http")]
            ProberConfig::Http { ports, .. } => Some(ports.clone()),
            ProberConfig::Dns { ports, .. } => Some(ports.clone()),
            ProberConfig::Udp { ports, .. } => Some(ports.clone()),
            #[cfg(feature = "snmp")]
            ProberConfig::Snmp { ports, .. } => Some(ports.clone()),
            #[cfg(feature = "lldp")]
            ProberConfig::Lldp { ports, .. } => Some(ports.clone()),
            #[cfg(feature = "ssh")]
            ProberConfig::Ssh { ports } => Some(ports.clone()),
            #[cfg(feature = "tls")]
            ProberConfig::Tls { ports } => Some(ports.clone()),
            #[cfg(feature = "gnmi")]
            ProberConfig::Gnmi { ports, .. } => Some(ports.clone()),
            #[cfg(feature = "arp")]
            ProberConfig::Arp { .. } => None,
            #[cfg(feature = "ndp")]
            ProberConfig::Ndp { .. } => None,
            #[cfg(feature = "icmp")]
            ProberConfig::Icmp { .. } => None,
            ProberConfig::ReverseDns { .. } => None,
        }
    }

    fn ports_for(kind: ProbeKind, options: &ProbeSelectionOptions) -> Vec<u16> {
        ports_of(&expand_one(kind, options)).expect("kind carries ports")
    }

    fn config_error(err: RastreoError) -> ConfigError {
        match err {
            RastreoError::Config(err) => err,
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    #[test]
    fn required_feature_is_none_only_for_kinds_present_in_every_build() {
        for kind in ProbeKind::all().iter().copied() {
            if kind.required_feature().is_none() {
                assert!(
                    kind.is_compiled_in(),
                    "{} names no feature yet is absent from this build",
                    kind.label()
                );
            }
        }
    }

    #[test]
    fn available_probe_kinds_lists_only_compiled_kinds_in_canonical_order() {
        let available = available_probe_kinds();
        for kind in &available {
            assert!(kind.is_compiled_in(), "{} is not compiled in", kind.label());
        }
        let indexes: Vec<usize> = available.iter().map(|kind| kind.index()).collect();
        let mut sorted = indexes.clone();
        sorted.sort_unstable();
        assert_eq!(indexes, sorted);
        assert!(available.contains(&ProbeKind::TcpConnect));
        assert!(available.contains(&ProbeKind::ReverseDns));
    }

    #[test]
    fn default_probe_kinds_is_a_subset_of_available_probe_kinds() {
        let available = available_probe_kinds();
        for kind in default_probe_kinds() {
            assert!(
                available.contains(&kind),
                "{} defaults on but is not available",
                kind.label()
            );
        }
    }

    #[test]
    fn default_order_lists_exactly_the_kinds_the_eligibility_rule_admits() {
        for kind in ProbeKind::all().iter().copied() {
            let admitted = !requires_explicit_param(kind)
                && !is_link_layer(kind)
                && !kind.emits_second_stream();
            assert_eq!(
                DEFAULT_ORDER.contains(&kind),
                admitted,
                "{} is classified against the rule",
                kind.label()
            );
        }
    }

    #[test]
    fn default_probe_kinds_drops_only_what_this_build_left_out() {
        let defaults = default_probe_kinds();
        for kind in ProbeKind::all().iter().copied() {
            assert_eq!(
                defaults.contains(&kind),
                DEFAULT_ORDER.contains(&kind) && kind.is_compiled_in(),
                "{} classified wrong",
                kind.label()
            );
        }
    }

    #[test]
    fn requires_explicit_param_agrees_with_what_expansion_rejects() {
        let bare = ProbeSelectionOptions::default();
        for kind in available_probe_kinds() {
            let rejected = matches!(
                expand_probe_selection(&[kind], &bare),
                Err(RastreoError::Config(
                    ConfigError::ProbeKindMissingParam { .. }
                ))
            );
            assert_eq!(
                rejected,
                requires_explicit_param(kind),
                "{} disagrees with its own expansion",
                kind.label()
            );
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn consumes_shared_ports_marks_the_kinds_whose_ports_have_no_serde_default() {
        for kind in available_probe_kinds() {
            let yaml = format!("type: {}\n", kind.label());
            let type_alone_suffices = serde_yaml_ng::from_str::<ProberConfig>(&yaml).is_ok();
            assert_eq!(
                !type_alone_suffices,
                kind.consumes_shared_ports() || requires_explicit_param(kind),
                "{} needs more than `type:` in YAML but is classified otherwise",
                kind.label()
            );
        }
    }

    #[test]
    fn emits_second_stream_agrees_with_the_checkpoint_resume_verdict() {
        let options = expandable_options();
        for kind in available_probe_kinds() {
            let configs = expand_probe_selection(&[kind], &options).expect("expands");
            assert_eq!(
                !crate::checkpoint::probers_support_resume(&configs),
                kind.emits_second_stream(),
                "{} disagrees with the checkpoint's second-stream verdict",
                kind.label()
            );
        }
    }

    #[test]
    fn parse_accepts_every_canonical_label_even_when_the_feature_is_absent() {
        for kind in ProbeKind::all().iter().copied() {
            let selection =
                parse_probe_selection(&tokens(&[kind.label()])).expect("labels always parse");
            assert_eq!(selection.named, vec![kind]);
            assert!(selection.defaulted.is_empty());
        }
    }

    #[rstest]
    #[case("tcp", ProbeKind::TcpConnect)]
    #[case("tcp_connect", ProbeKind::TcpConnect)]
    #[case("reverse_dns", ProbeKind::ReverseDns)]
    #[case("gnmi", ProbeKind::Gnmi)]
    fn parse_maps_a_token_to_its_kind(#[case] token: &str, #[case] expected: ProbeKind) {
        let selection = parse_probe_selection(&tokens(&[token])).expect("parses");
        assert_eq!(selection.named, vec![expected]);
    }

    #[cfg(feature = "config")]
    #[test]
    fn every_expansion_default_matches_the_yaml_default_for_the_same_kind() {
        let ports_by_kind = available_probe_kinds()
            .into_iter()
            .filter(|kind| kind.consumes_shared_ports())
            .map(|kind| (kind, EXPLICIT_PORTS.to_vec()))
            .collect();
        let options = ProbeSelectionOptions {
            ports_by_kind,
            ..expandable_options()
        };
        for kind in available_probe_kinds() {
            assert_eq!(
                as_json(&expand_one(kind, &options)),
                as_json(&yaml_default_config(kind)),
                "{} expands with a default its YAML form does not agree with",
                kind.label()
            );
        }
    }

    #[test]
    fn parse_rejects_an_unknown_name_and_lists_what_this_build_offers() {
        let err = parse_probe_selection(&tokens(&["snmpp"])).expect_err("unknown name");
        match config_error(err) {
            ConfigError::UnknownProbeKind { name, available } => {
                assert_eq!(name, "snmpp");
                for kind in ProbeKind::all().iter().copied() {
                    assert_eq!(
                        available.split(", ").any(|label| label == kind.label()),
                        kind.is_compiled_in(),
                        "{} listed against its compilation state",
                        kind.label()
                    );
                }
            }
            other => panic!("expected UnknownProbeKind, got {other:?}"),
        }
    }

    #[test]
    fn the_unknown_kind_error_offers_the_default_keyword_and_the_tcp_alias() {
        let err = parse_probe_selection(&tokens(&["defualt"])).expect_err("unknown name");
        match config_error(err) {
            ConfigError::UnknownProbeKind { available, .. } => {
                let offered: Vec<&str> = available.split(", ").collect();
                assert!(offered.contains(&DEFAULT_KEYWORD), "available: {available}");
                assert!(offered.contains(&TCP_ALIAS), "available: {available}");
            }
            other => panic!("expected UnknownProbeKind, got {other:?}"),
        }
    }

    #[test]
    fn parse_trims_whitespace_around_each_token() {
        let selection = parse_probe_selection(&tokens(&[" tcp ", "\tdns"])).expect("parses");
        assert_eq!(selection.named, vec![ProbeKind::TcpConnect, ProbeKind::Dns]);

        let padded = parse_probe_selection(&tokens(&[" default "])).expect("parses");
        assert_eq!(padded.defaulted, default_probe_kinds());
    }

    #[test]
    fn parse_of_no_values_yields_an_empty_selection() {
        let selection = parse_probe_selection(&[]).expect("parses");
        assert!(selection.named.is_empty());
        assert!(selection.defaulted.is_empty());
    }

    #[test]
    fn parse_default_keyword_fills_the_defaulted_bucket_only() {
        let selection = parse_probe_selection(&tokens(&["default"])).expect("parses");
        assert!(selection.named.is_empty());
        assert_eq!(selection.defaulted, default_probe_kinds());
    }

    #[test]
    fn an_explicitly_named_kind_leaves_the_defaulted_bucket() {
        let selection =
            parse_probe_selection(&tokens(&["default", "reverse_dns"])).expect("parses");
        assert_eq!(selection.named, vec![ProbeKind::ReverseDns]);
        assert!(
            !selection.defaulted.contains(&ProbeKind::ReverseDns),
            "explicit wins: {:?}",
            selection.defaulted
        );
    }

    #[test]
    fn default_before_or_after_a_name_yields_the_same_selection() {
        let before = parse_probe_selection(&tokens(&["default", "reverse_dns"])).expect("parses");
        let after = parse_probe_selection(&tokens(&["reverse_dns", "default"])).expect("parses");
        assert_eq!(before.named, after.named);
        assert_eq!(before.defaulted, after.defaulted);
    }

    #[test]
    fn parse_dedups_within_each_bucket_keeping_first_occurrence() {
        let selection =
            parse_probe_selection(&tokens(&["dns", "tcp", "dns", "tcp_connect"])).expect("parses");
        assert_eq!(selection.named, vec![ProbeKind::Dns, ProbeKind::TcpConnect]);

        let twice = parse_probe_selection(&tokens(&["default", "default"])).expect("parses");
        assert_eq!(twice.defaulted, default_probe_kinds());
    }

    #[test]
    fn the_runnability_filter_never_drops_a_named_kind() {
        let selection = parse_probe_selection(&tokens(&["default", "icmp"])).expect("parses");
        let kinds = apply_runnability_filter(selection, |_| false);
        assert!(
            kinds.contains(&ProbeKind::Icmp),
            "named icmp must survive a rejecting predicate: {kinds:?}"
        );
    }

    #[test]
    fn the_runnability_filter_drops_a_defaulted_kind_the_predicate_rejects() {
        let selection = ProbeSelection {
            named: Vec::new(),
            defaulted: vec![ProbeKind::Icmp, ProbeKind::TcpConnect],
        };
        let kinds = apply_runnability_filter(selection, |_| false);
        assert!(!kinds.contains(&ProbeKind::Icmp), "{kinds:?}");
    }

    #[test]
    fn the_runnability_filter_only_consults_the_predicate_where_a_precondition_exists() {
        let selection = ProbeSelection {
            named: Vec::new(),
            defaulted: vec![ProbeKind::TcpConnect, ProbeKind::ReverseDns],
        };
        assert_eq!(
            apply_runnability_filter(selection, |_| false),
            vec![ProbeKind::TcpConnect, ProbeKind::ReverseDns]
        );
    }

    #[test]
    fn the_runnability_filter_keeps_everything_when_the_predicate_accepts() {
        let selection = parse_probe_selection(&tokens(&["default"])).expect("parses");
        let expected = selection.defaulted.clone();
        assert_eq!(apply_runnability_filter(selection, |_| true), expected);
    }

    #[test]
    fn the_runnability_filter_puts_named_kinds_ahead_of_defaulted_ones() {
        let selection = ProbeSelection {
            named: vec![ProbeKind::Dns],
            defaulted: vec![ProbeKind::TcpConnect],
        };
        assert_eq!(
            apply_runnability_filter(selection, |_| true),
            vec![ProbeKind::Dns, ProbeKind::TcpConnect]
        );
    }

    #[test]
    fn expanding_nothing_is_an_error_rather_than_an_empty_scan() {
        let err = expand_probe_selection(&[], &ProbeSelectionOptions::default())
            .expect_err("empty selection");
        assert!(matches!(
            config_error(err),
            ConfigError::EmptyProbeSelection
        ));
    }

    #[test]
    fn a_kind_named_twice_expands_into_one_config() {
        let configs = expand_probe_selection(
            &[ProbeKind::TcpConnect, ProbeKind::TcpConnect],
            &ProbeSelectionOptions::default(),
        )
        .expect("expands");
        assert_eq!(configs.len(), 1, "{configs:?}");
    }

    #[test]
    fn a_repeated_kind_keeps_the_position_of_its_first_occurrence() {
        let kinds = [
            ProbeKind::ReverseDns,
            ProbeKind::TcpConnect,
            ProbeKind::ReverseDns,
        ];
        let configs =
            expand_probe_selection(&kinds, &ProbeSelectionOptions::default()).expect("expands");
        assert_eq!(configs.len(), 2, "{configs:?}");
        assert!(matches!(configs[0], ProberConfig::ReverseDns { .. }));
        assert!(matches!(configs[1], ProberConfig::TcpConnect { .. }));
    }

    #[test]
    fn every_compiled_kind_survives_being_named_twice() {
        let options = expandable_options();
        for kind in available_probe_kinds() {
            let configs = expand_probe_selection(&[kind, kind], &options).expect("expands");
            assert_eq!(configs.len(), 1, "{} expanded twice", kind.label());
        }
    }

    #[test]
    fn expansion_preserves_the_requested_order() {
        let kinds = [ProbeKind::ReverseDns, ProbeKind::TcpConnect];
        let configs =
            expand_probe_selection(&kinds, &ProbeSelectionOptions::default()).expect("expands");
        assert!(matches!(configs[0], ProberConfig::ReverseDns { .. }));
        assert!(matches!(configs[1], ProberConfig::TcpConnect { .. }));
    }

    #[test]
    fn every_compiled_kind_expands_into_a_prober_the_factory_accepts() {
        let options = expandable_options();
        for kind in available_probe_kinds() {
            let config = expand_one(kind, &options);
            let prober = crate::prober::create_prober(&config).expect("factory accepts the config");
            assert_eq!(
                prober.kind(),
                kind,
                "{} built the wrong prober",
                kind.label()
            );
        }
    }

    #[test]
    fn udp_without_a_protocol_names_the_missing_parameter_not_a_cli_flag() {
        let err = expand_probe_selection(&[ProbeKind::Udp], &ProbeSelectionOptions::default())
            .expect_err("udp needs a protocol");
        match config_error(err) {
            ConfigError::ProbeKindMissingParam { kind, param } => {
                assert_eq!(kind, "udp");
                assert!(param.contains("udp protocol"), "param: {param}");
                assert!(param.contains("ntp"), "param: {param}");
                assert!(!param.contains("--"), "param: {param}");
            }
            other => panic!("expected ProbeKindMissingParam, got {other:?}"),
        }
    }

    #[test]
    fn dns_without_query_names_names_the_missing_parameter_not_a_cli_flag() {
        let err = expand_probe_selection(&[ProbeKind::Dns], &ProbeSelectionOptions::default())
            .expect_err("dns needs a query name");
        match config_error(err) {
            ConfigError::ProbeKindMissingParam { kind, param } => {
                assert_eq!(kind, "dns");
                assert!(param.contains("dns query name"), "param: {param}");
                assert!(!param.contains("--"), "param: {param}");
            }
            other => panic!("expected ProbeKindMissingParam, got {other:?}"),
        }
    }

    #[test]
    fn tcp_connect_defaults_to_the_management_port_list() {
        assert_eq!(
            ports_for(ProbeKind::TcpConnect, &ProbeSelectionOptions::default()),
            DEFAULT_TCP_PORTS.to_vec()
        );
    }

    #[test]
    fn shared_ports_reach_the_kinds_that_consume_them() {
        let options = ProbeSelectionOptions {
            ports: vec![9100],
            ..expandable_options()
        };
        for kind in available_probe_kinds() {
            if !kind.consumes_shared_ports() {
                continue;
            }
            assert_eq!(
                ports_for(kind, &options),
                vec![9100],
                "{} ignored the shared ports",
                kind.label()
            );
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn shared_ports_leave_protocol_pinned_kinds_on_their_own_defaults() {
        let with_shared = ProbeSelectionOptions {
            ports: vec![9100],
            ..expandable_options()
        };
        for kind in available_probe_kinds() {
            if kind.consumes_shared_ports() {
                continue;
            }
            let Some(yaml_ports) = ports_of(&yaml_default_config(kind)) else {
                continue;
            };
            assert_eq!(
                ports_for(kind, &with_shared),
                yaml_ports,
                "{} took the shared ports instead of its own default",
                kind.label()
            );
        }
    }

    #[test]
    fn an_empty_per_kind_override_falls_back_like_an_absent_one() {
        let mut ports_by_kind = BTreeMap::new();
        ports_by_kind.insert(ProbeKind::TcpConnect, Vec::new());
        ports_by_kind.insert(ProbeKind::Dns, Vec::new());
        let options = ProbeSelectionOptions {
            ports: vec![9100],
            ports_by_kind,
            ..expandable_options()
        };
        assert_eq!(ports_for(ProbeKind::TcpConnect, &options), vec![9100]);
        assert_eq!(
            ports_for(ProbeKind::Dns, &options),
            crate::prober::dns::default_ports()
        );
    }

    #[test]
    fn a_per_kind_override_beats_both_the_shared_ports_and_the_protocol_default() {
        let mut ports_by_kind = BTreeMap::new();
        ports_by_kind.insert(ProbeKind::TcpConnect, vec![2222]);
        ports_by_kind.insert(ProbeKind::Dns, vec![5353]);
        let options = ProbeSelectionOptions {
            ports: vec![9100],
            ports_by_kind,
            ..expandable_options()
        };
        assert_eq!(ports_for(ProbeKind::TcpConnect, &options), vec![2222]);
        assert_eq!(ports_for(ProbeKind::Dns, &options), vec![5353]);
    }

    #[test]
    fn udp_defaults_to_the_well_known_port_of_the_named_protocol() {
        let options = ProbeSelectionOptions {
            udp_protocol: Some(UdpProtocol::MemcachedStats),
            ..Default::default()
        };
        assert_eq!(ports_for(ProbeKind::Udp, &options), vec![11211]);
    }

    #[test]
    fn dns_carries_the_requested_names_and_type() {
        let options = ProbeSelectionOptions {
            dns_query_names: vec!["a.example.com.".to_string(), "b.example.com.".to_string()],
            dns_query_type: DnsQueryType::Mx,
            ..Default::default()
        };
        match expand_one(ProbeKind::Dns, &options) {
            ProberConfig::Dns {
                ports,
                query_names,
                query_type,
                ..
            } => {
                assert_eq!(ports, vec![53]);
                assert_eq!(query_names.len(), 2);
                assert_eq!(query_type, DnsQueryType::Mx);
            }
            other => panic!("expected Dns, got {other:?}"),
        }
    }

    #[test]
    fn reverse_dns_expands_to_the_system_resolvers() {
        match expand_one(ProbeKind::ReverseDns, &ProbeSelectionOptions::default()) {
            ProberConfig::ReverseDns { resolvers } => assert!(resolvers.is_empty()),
            other => panic!("expected ReverseDns, got {other:?}"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_defaults_to_web_ports_rather_than_inheriting_the_tcp_list() {
        let ports = ports_for(ProbeKind::Http, &ProbeSelectionOptions::default());
        assert_eq!(ports, DEFAULT_HTTP_PORTS.to_vec());
        assert!(!ports.contains(&22), "ssh is not an http port");
        assert!(!ports.contains(&830), "netconf is not an http port");
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_carries_the_requested_scheme_and_path() {
        let options = ProbeSelectionOptions {
            http_scheme: HttpScheme::Https,
            http_path: "/health".to_string(),
            ..Default::default()
        };
        match expand_one(ProbeKind::Http, &options) {
            ProberConfig::Http {
                scheme,
                path,
                tls_verify,
                ..
            } => {
                assert!(matches!(scheme, HttpScheme::Https));
                assert_eq!(path, "/health");
                assert_eq!(tls_verify, http::default_tls_verify());
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn snmp_stays_on_its_own_port_and_carries_the_configured_community() {
        let options = ProbeSelectionOptions {
            ports: vec![1161],
            snmp_community: Community("lab-ro".to_string()),
            ..Default::default()
        };
        match expand_one(ProbeKind::Snmp, &options) {
            ProberConfig::Snmp {
                ports,
                version,
                community,
                ..
            } => {
                assert_eq!(ports, vec![161], "shared ports must not retarget snmp");
                assert_eq!(version, SnmpVersion::default());
                assert_eq!(&*community, "lab-ro");
            }
            other => panic!("expected Snmp, got {other:?}"),
        }
    }

    #[cfg(feature = "lldp")]
    #[test]
    fn lldp_reuses_the_snmp_transport_options() {
        let options = ProbeSelectionOptions {
            snmp_community: Community("lab-ro".to_string()),
            ..Default::default()
        };
        match expand_one(ProbeKind::Lldp, &options) {
            ProberConfig::Lldp {
                ports,
                community,
                max_rows,
                ..
            } => {
                assert_eq!(ports, vec![161]);
                assert_eq!(&*community, "lab-ro");
                assert_eq!(max_rows, crate::prober::lldp::default_max_rows());
            }
            other => panic!("expected Lldp, got {other:?}"),
        }
    }

    #[cfg(feature = "icmp")]
    #[test]
    fn icmp_carries_the_configured_echo_count() {
        let options = ProbeSelectionOptions {
            icmp_count: 7,
            ..Default::default()
        };
        match expand_one(ProbeKind::Icmp, &options) {
            ProberConfig::Icmp { count, interval_ms } => {
                assert_eq!(count, 7);
                assert_eq!(interval_ms, crate::prober::icmp::default_interval_ms());
            }
            other => panic!("expected Icmp, got {other:?}"),
        }
    }

    #[cfg(feature = "arp")]
    #[test]
    fn arp_carries_the_configured_interface() {
        let options = ProbeSelectionOptions {
            interface: "eth0".to_string(),
            ..Default::default()
        };
        match expand_one(ProbeKind::Arp, &options) {
            ProberConfig::Arp { interface } => assert_eq!(interface, "eth0"),
            other => panic!("expected Arp, got {other:?}"),
        }
    }

    #[cfg(feature = "ndp")]
    #[test]
    fn ndp_carries_the_configured_interface() {
        let options = ProbeSelectionOptions {
            interface: "eth1".to_string(),
            ..Default::default()
        };
        match expand_one(ProbeKind::Ndp, &options) {
            ProberConfig::Ndp { interface } => assert_eq!(interface, "eth1"),
            other => panic!("expected Ndp, got {other:?}"),
        }
    }

    #[cfg(feature = "gnmi")]
    #[test]
    fn gnmi_expands_with_its_capability_defaults() {
        match expand_one(ProbeKind::Gnmi, &ProbeSelectionOptions::default()) {
            ProberConfig::Gnmi {
                ports,
                plaintext,
                get_paths,
                lldp,
                ..
            } => {
                assert_eq!(ports, crate::prober::gnmi::default_ports());
                assert_eq!(plaintext, crate::prober::gnmi::default_plaintext());
                assert_eq!(get_paths, crate::prober::gnmi::default_get_paths());
                assert_eq!(lldp, crate::prober::gnmi::default_lldp());
            }
            other => panic!("expected Gnmi, got {other:?}"),
        }
    }

    #[cfg(not(feature = "snmp"))]
    #[test]
    fn a_kind_left_out_of_the_build_fails_at_expansion_not_at_parse() {
        let selection = parse_probe_selection(&tokens(&["snmp"])).expect("the name still parses");
        let err = expand_probe_selection(&selection.named, &ProbeSelectionOptions::default())
            .expect_err("snmp is not compiled in");
        match config_error(err) {
            ConfigError::ProbeKindNotCompiled { kind, feature } => {
                assert_eq!(kind, "snmp");
                assert_eq!(feature, "snmp");
            }
            other => panic!("expected ProbeKindNotCompiled, got {other:?}"),
        }
    }

    #[test]
    fn every_uncompiled_kind_reports_its_missing_feature_rather_than_a_bad_name() {
        for kind in ProbeKind::all().iter().copied() {
            if kind.is_compiled_in() {
                continue;
            }
            let err = expand_probe_selection(&[kind], &expandable_options())
                .expect_err("uncompiled kinds cannot expand");
            match config_error(err) {
                ConfigError::ProbeKindNotCompiled {
                    kind: named,
                    feature,
                } => {
                    assert_eq!(named, kind.label());
                    assert_eq!(Some(feature), kind.required_feature());
                }
                other => panic!(
                    "expected ProbeKindNotCompiled for {}, got {other:?}",
                    kind.label()
                ),
            }
        }
    }

    #[cfg(feature = "icmp")]
    #[test]
    fn default_options_mirror_the_icmp_prober_default() {
        assert_eq!(
            ProbeSelectionOptions::default().icmp_count,
            crate::prober::icmp::default_count()
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn default_options_mirror_the_http_prober_default() {
        assert_eq!(
            ProbeSelectionOptions::default().http_path,
            http::default_path()
        );
    }

    #[cfg(feature = "arp")]
    #[test]
    fn default_options_mirror_the_arp_prober_default() {
        assert_eq!(
            ProbeSelectionOptions::default().interface,
            crate::prober::arp::default_interface()
        );
    }

    #[cfg(feature = "ndp")]
    #[test]
    fn default_options_mirror_the_ndp_prober_default() {
        assert_eq!(
            ProbeSelectionOptions::default().interface,
            crate::prober::ndp::default_interface()
        );
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn default_options_mirror_the_snmp_prober_default() {
        assert_eq!(
            &*ProbeSelectionOptions::default().snmp_community,
            &*snmp::default_community()
        );
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn debug_output_does_not_leak_the_community() {
        let options = ProbeSelectionOptions {
            snmp_community: Community("secret-community".to_string()),
            ..Default::default()
        };
        let rendered = format!("{options:?}");
        assert!(!rendered.contains("secret-community"), "{rendered}");
        assert!(rendered.contains("<redacted:"), "{rendered}");
    }

    #[test]
    fn selection_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProbeSelection>();
        assert_send_sync::<ProbeSelectionOptions>();
    }
}
