use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use schemars::JsonSchema;
use tokio::sync::Semaphore;

use crate::error::ProbeErrorKind;
use crate::kind_vocabulary::kind_vocabulary;

kind_vocabulary! {
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        serde::Serialize,
        serde::Deserialize,
        JsonSchema,
    )]
    #[non_exhaustive]
    pub enum ProbeKind {
        // Labels are the `probe_kind` metric attribute; a rename breaks consumer queries.
        #[default]
        TcpConnect => "tcp_connect",
        Udp => "udp",
        Http => "http",
        Dns => "dns",
        Snmp => "snmp",
        Arp => "arp",
        Ndp => "ndp",
        Ssh => "ssh",
        Icmp => "icmp",
        Tls => "tls",
        ReverseDns => "reverse_dns",
        Gnmi => "gnmi",
        Lldp => "lldp",
    }

    /// Number of `ProbeKind` variants — indexes fixed-size counter arrays without heap allocation.
    pub const PROBE_KIND_COUNT;
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum Signal {
    OpenPort(u16),
    HttpBanner(String),
    SnmpSysObjectId(String),
    SnmpSysDescr(String),
    Mac(String),
    DnsHost(String),
    NtpBanner(String),
    SipUserAgent(String),
    MemcachedVersion(String),
    StunMappedAddress(String),
    SnmpSysName(String),
    SshBanner(String),
    SshHostKey(String),
    IcmpEchoRttMicros(u64),
    TlsSubject(String),
    TlsSanName(String),
    TlsProtocolVersion(String),
    TlsCipherSuite(String),
    TlsAlpn(String),
    ReverseDnsName(String),
    GnmiVersion(String),
    GnmiSupportedModel(String),
    GnmiSupportedEncoding(String),
    GnmiState { path: String, value: String },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProbeCtx {
    pub timeout: Duration,
    pub retries: u32,
    /// Shared socket-op permit pool bounding total in-flight file descriptors across every target; `None` bounds only per target.
    pub port_budget: Option<Arc<Semaphore>>,
}

impl ProbeCtx {
    pub fn new(timeout: Duration, retries: u32) -> Self {
        Self {
            timeout,
            retries,
            port_budget: None,
        }
    }

    pub fn with_port_budget(mut self, port_budget: Option<Arc<Semaphore>>) -> Self {
        self.port_budget = port_budget;
        self
    }
}

/// A typed probe fault carried on the outcome: the probe attempted a target and learned that
/// something broke, without discarding the signals it may have gathered on other ports.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ProbeFault {
    pub kind: ProbeErrorKind,
    pub detail: String,
}

impl ProbeFault {
    pub fn new(kind: ProbeErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// LLDP neighbor observation collected by the `lldp` prober: the probed device's own chassis-id
/// plus the neighbors it reports. Carried on the outcome — not folded into signals — so a switch
/// with many neighbors does not inflate its device confidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct LldpObservation {
    pub local_chassis_id: String,
    pub local_chassis_subtype: u32,
    pub neighbors: Vec<LldpNeighbor>,
    /// Source that collected the observation (`lldp` for the SNMP prober, `gnmi` for gNMI); the
    /// assembler merges both into a link's `discovered_via`.
    pub discovered_via: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct LldpNeighbor {
    pub local_port: String,
    pub remote_chassis_id: String,
    pub remote_chassis_subtype: u32,
    pub remote_port_id: String,
    pub remote_port_subtype: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port_desc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_sys_name: Option<String>,
}

/// Wire transport an endpoint answered over: `tls` for an encrypted channel, `plaintext` for `http`/2.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Transport {
    Tls,
    Plaintext,
}

/// The gNMI endpoint that answered a probe: the port, its transport, and the encodings it advertised.
/// Carried on the outcome so the collection-profile assembler describes a real endpoint rather than
/// a fabricated default.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct GnmiEndpoint {
    pub port: u16,
    pub transport: Transport,
    pub advertised_encodings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ProbeOutcome {
    pub kind: ProbeKind,
    pub target_ip: IpAddr,
    pub timestamp: SystemTime,
    pub reachable: bool,
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<ProbeFault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lldp: Option<LldpObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gnmi_endpoint: Option<GnmiEndpoint>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn probe_kind_round_trips_json() {
        for kind in ProbeKind::all() {
            let s = serde_json::to_string(kind).expect("serialize");
            let back: ProbeKind = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn gnmi_signal_variants_round_trip_json() {
        for signal in [
            Signal::GnmiVersion("0.10.0".into()),
            Signal::GnmiSupportedModel("openconfig-interfaces 3.0.0".into()),
            Signal::GnmiSupportedEncoding("JSON_IETF".into()),
            Signal::GnmiState {
                path: "/system/state/hostname".into(),
                value: "srlinux".into(),
            },
        ] {
            let s = serde_json::to_string(&signal).expect("serialize");
            let back: Signal = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(signal, back);
        }
    }

    #[test]
    fn probe_outcome_round_trips_json() {
        let outcome = ProbeOutcome {
            lldp: None,
            gnmi_endpoint: None,
            kind: ProbeKind::TcpConnect,
            target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals: vec![
                Signal::OpenPort(22),
                Signal::HttpBanner("nginx/1.25".into()),
            ],
            fault: None,
        };
        let s = serde_json::to_string(&outcome).expect("serialize");
        let back: ProbeOutcome = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back.kind, ProbeKind::TcpConnect);
        assert_eq!(back.target_ip, outcome.target_ip);
        assert!(back.reachable);
        assert_eq!(back.signals.len(), 2);
        assert!(back.fault.is_none());
    }

    #[test]
    fn probe_outcome_round_trips_a_reachable_fault() {
        let outcome = ProbeOutcome {
            lldp: None,
            gnmi_endpoint: None,
            kind: ProbeKind::Snmp,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals: Vec::new(),
            fault: Some(ProbeFault::new(
                ProbeErrorKind::DecodeFailed,
                "snmp reply on port 161 could not be decoded",
            )),
        };
        let s = serde_json::to_string(&outcome).expect("serialize");
        let back: ProbeOutcome = serde_json::from_str(&s).expect("deserialize");
        assert!(back.reachable);
        let fault = back.fault.expect("fault survives the round trip");
        assert_eq!(fault.kind, ProbeErrorKind::DecodeFailed);
        assert!(fault.detail.contains("could not be decoded"));
    }

    #[test]
    fn probe_outcome_omits_fault_from_wire_when_none() {
        let outcome = ProbeOutcome {
            lldp: None,
            gnmi_endpoint: None,
            kind: ProbeKind::TcpConnect,
            target_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: false,
            signals: Vec::new(),
            fault: None,
        };
        let json: serde_json::Value = serde_json::to_value(&outcome).expect("serialize");
        assert!(
            json.get("fault").is_none(),
            "fault must be skipped when None: {json}"
        );
    }

    #[test]
    fn probe_ctx_constructible() {
        let ctx = ProbeCtx {
            timeout: Duration::from_millis(500),
            retries: 3,
            port_budget: None,
        };
        assert_eq!(ctx.retries, 3);
        assert_eq!(ctx.timeout, Duration::from_millis(500));
    }

    #[test]
    fn probe_ctx_new_defaults_port_budget_to_none() {
        let ctx = ProbeCtx::new(Duration::from_millis(500), 0);
        assert!(ctx.port_budget.is_none());
    }

    #[test]
    fn with_port_budget_shares_the_permit_pool() {
        let sem = Arc::new(Semaphore::new(4));
        let ctx =
            ProbeCtx::new(Duration::from_millis(500), 0).with_port_budget(Some(Arc::clone(&sem)));
        let budget = ctx.port_budget.expect("budget set");
        assert!(
            Arc::ptr_eq(&budget, &sem),
            "the builder shares the same pool"
        );
        assert_eq!(budget.available_permits(), 4);
    }

    #[test]
    fn signal_partial_eq_distinguishes_variants() {
        assert_eq!(Signal::OpenPort(80), Signal::OpenPort(80));
        assert_ne!(Signal::OpenPort(80), Signal::OpenPort(443));
        assert_ne!(Signal::OpenPort(80), Signal::HttpBanner("80".into()));
        assert_eq!(
            Signal::Mac("aa:bb:cc:dd:ee:ff".into()),
            Signal::Mac("aa:bb:cc:dd:ee:ff".into())
        );
    }

    #[test]
    fn udp_signal_variants_round_trip_json() {
        for signal in [
            Signal::NtpBanner("stratum=2 ref=203.0.113.1".into()),
            Signal::SipUserAgent("Kamailio/5.6.5 (x86_64/linux)".into()),
            Signal::MemcachedVersion("1.6.24".into()),
            Signal::StunMappedAddress("203.0.113.42:54321".into()),
        ] {
            let s = serde_json::to_string(&signal).expect("serialize");
            let back: Signal = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(signal, back);
        }
    }

    #[test]
    fn snmp_signal_variants_round_trip_json() {
        for signal in [
            Signal::SnmpSysDescr("Linux zeus 4.8.6.5-smp".to_string()),
            Signal::SnmpSysObjectId("1.3.6.1.4.1.8072.3.2.10".to_string()),
            Signal::SnmpSysName("zeus.snmplabs.com".to_string()),
        ] {
            let json = serde_json::to_string(&signal).expect("serialize");
            let round_trip: Signal = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(signal, round_trip);
        }
    }

    #[test]
    fn outcome_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProbeKind>();
        assert_send_sync::<Signal>();
        assert_send_sync::<ProbeCtx>();
        assert_send_sync::<ProbeOutcome>();
        assert_send_sync::<ProbeFault>();
    }

    #[test]
    fn icmp_signal_round_trips_json() {
        let signal = Signal::IcmpEchoRttMicros(987_654);
        let json = serde_json::to_string(&signal).expect("serialize");
        let back: Signal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(signal, back);
    }

    #[test]
    fn reverse_dns_signal_round_trips_json() {
        let signal = Signal::ReverseDnsName("router.example.com".into());
        let json = serde_json::to_string(&signal).expect("serialize");
        let back: Signal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(signal, back);
    }

    #[test]
    fn tls_signal_variants_round_trip_json() {
        for signal in [
            Signal::TlsSubject("router.example.com".into()),
            Signal::TlsSanName("router.example.com".into()),
            Signal::TlsSanName("ip:10.0.0.1".into()),
            Signal::TlsProtocolVersion("TLSv1.3".into()),
            Signal::TlsCipherSuite("TLS_AES_128_GCM_SHA256".into()),
            Signal::TlsAlpn("h2".into()),
        ] {
            let s = serde_json::to_string(&signal).expect("serialize");
            let back: Signal = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(signal, back);
        }
    }

    #[test]
    fn probe_kind_labels_are_unique_snake_case() {
        let mut labels: Vec<&'static str> = ProbeKind::all().iter().map(|k| k.label()).collect();
        labels.sort();
        for pair in labels.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate label {}", pair[0]);
        }
        for label in ProbeKind::all().iter().map(|k| k.label()) {
            assert!(!label.is_empty(), "empty label");
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "label {label} not snake_case"
            );
        }
    }

    #[test]
    fn probe_kind_from_label_round_trips_every_variant() {
        for kind in ProbeKind::all() {
            assert_eq!(
                ProbeKind::from_label(kind.label()),
                Some(*kind),
                "label {} does not round-trip",
                kind.label()
            );
        }
    }

    #[test]
    fn probe_kind_from_label_rejects_non_canonical_spellings() {
        for label in ["", "tcp", "TcpConnect", "Http", "reverse-dns", "nope"] {
            assert_eq!(ProbeKind::from_label(label), None, "accepted {label:?}");
        }
    }

    #[test]
    fn probe_kind_orders_by_declaration_for_btreemap_keys() {
        use std::collections::BTreeMap;
        let mut ports: BTreeMap<ProbeKind, u16> = BTreeMap::new();
        ports.insert(ProbeKind::Lldp, 161);
        ports.insert(ProbeKind::TcpConnect, 22);
        let first = ports.keys().next().copied().expect("non-empty");
        assert_eq!(first, ProbeKind::TcpConnect);
        let ordered: Vec<usize> = ProbeKind::all().iter().map(|k| k.index()).collect();
        let mut sorted = ProbeKind::all().to_vec();
        sorted.sort();
        assert_eq!(
            sorted.iter().map(|k| k.index()).collect::<Vec<_>>(),
            ordered,
            "Ord must agree with index order"
        );
    }

    #[test]
    fn probe_kind_label_matches_serde_shape_for_known_variants() {
        assert_eq!(ProbeKind::TcpConnect.label(), "tcp_connect");
        assert_eq!(ProbeKind::ReverseDns.label(), "reverse_dns");
        assert_eq!(ProbeKind::Http.label(), "http");
    }

    #[test]
    fn ssh_signal_variants_round_trip_json() {
        for signal in [
            Signal::SshBanner("SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3".into()),
            Signal::SshHostKey(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ"
                    .into(),
            ),
        ] {
            let s = serde_json::to_string(&signal).expect("serialize");
            let back: Signal = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(signal, back);
        }
    }
}
