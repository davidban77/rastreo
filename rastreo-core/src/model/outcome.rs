use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use schemars::JsonSchema;

use crate::error::ProbeErrorKind;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    JsonSchema,
)]
#[non_exhaustive]
pub enum ProbeKind {
    #[default]
    TcpConnect,
    Udp,
    Http,
    Dns,
    Snmp,
    Arp,
    Ndp,
    Ssh,
    Icmp,
    Tls,
    ReverseDns,
}

/// Number of `ProbeKind` variants — indexes fixed-size counter arrays without heap allocation.
///
/// Adding a variant to `ProbeKind` requires bumping this constant and extending
/// `ProbeKind::all()` in the same change; the compiler surfaces the miss via the
/// array-size mismatch.
pub const PROBE_KIND_COUNT: usize = 11;

impl ProbeKind {
    /// Every variant in a stable, deterministic order — used for iterating fixed-size counter arrays.
    pub const fn all() -> &'static [ProbeKind; PROBE_KIND_COUNT] {
        &[
            ProbeKind::TcpConnect,
            ProbeKind::Udp,
            ProbeKind::Http,
            ProbeKind::Dns,
            ProbeKind::Snmp,
            ProbeKind::Arp,
            ProbeKind::Ndp,
            ProbeKind::Ssh,
            ProbeKind::Icmp,
            ProbeKind::Tls,
            ProbeKind::ReverseDns,
        ]
    }

    /// Stable index for use in fixed-size `[T; PROBE_KIND_COUNT]` arrays.
    pub const fn index(self) -> usize {
        match self {
            ProbeKind::TcpConnect => 0,
            ProbeKind::Udp => 1,
            ProbeKind::Http => 2,
            ProbeKind::Dns => 3,
            ProbeKind::Snmp => 4,
            ProbeKind::Arp => 5,
            ProbeKind::Ndp => 6,
            ProbeKind::Ssh => 7,
            ProbeKind::Icmp => 8,
            ProbeKind::Tls => 9,
            ProbeKind::ReverseDns => 10,
        }
    }

    /// snake_case label used in `/metrics` and OTLP attribute values.
    pub const fn label(self) -> &'static str {
        match self {
            ProbeKind::TcpConnect => "tcp_connect",
            ProbeKind::Udp => "udp",
            ProbeKind::Http => "http",
            ProbeKind::Dns => "dns",
            ProbeKind::Snmp => "snmp",
            ProbeKind::Arp => "arp",
            ProbeKind::Ndp => "ndp",
            ProbeKind::Ssh => "ssh",
            ProbeKind::Icmp => "icmp",
            ProbeKind::Tls => "tls",
            ProbeKind::ReverseDns => "reverse_dns",
        }
    }
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
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProbeCtx {
    pub timeout: Duration,
    pub retries: u32,
}

impl ProbeCtx {
    pub fn new(timeout: Duration, retries: u32) -> Self {
        Self { timeout, retries }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn probe_kind_round_trips_json() {
        for kind in [
            ProbeKind::TcpConnect,
            ProbeKind::Udp,
            ProbeKind::Http,
            ProbeKind::Dns,
            ProbeKind::Snmp,
            ProbeKind::Arp,
            ProbeKind::Ndp,
            ProbeKind::Ssh,
            ProbeKind::Icmp,
            ProbeKind::Tls,
            ProbeKind::ReverseDns,
        ] {
            let s = serde_json::to_string(&kind).expect("serialize");
            let back: ProbeKind = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn probe_outcome_round_trips_json() {
        let outcome = ProbeOutcome {
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
        };
        assert_eq!(ctx.retries, 3);
        assert_eq!(ctx.timeout, Duration::from_millis(500));
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
    fn probe_kind_all_lists_every_variant_in_index_order() {
        let all = ProbeKind::all();
        assert_eq!(all.len(), PROBE_KIND_COUNT);
        for (i, kind) in all.iter().enumerate() {
            assert_eq!(kind.index(), i, "kind {kind:?} index mismatch");
        }
    }

    #[test]
    fn probe_kind_indexes_are_unique_and_bounded() {
        let mut seen = [false; PROBE_KIND_COUNT];
        for kind in ProbeKind::all() {
            let idx = kind.index();
            assert!(idx < PROBE_KIND_COUNT, "index {idx} out of bounds");
            assert!(!seen[idx], "duplicate index {idx}");
            seen[idx] = true;
        }
        assert!(seen.iter().all(|s| *s), "not every index visited");
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
