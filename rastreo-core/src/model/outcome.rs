use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use schemars::JsonSchema;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, JsonSchema,
)]
#[non_exhaustive]
pub enum ProbeKind {
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
}

impl Signal {
    /// Which prober kind produced this signal. Deterministic mapping; useful for downstream analytics and for populating `AltIp::responded_via`.
    pub fn probe_kind(&self) -> ProbeKind {
        match self {
            Self::OpenPort(_) => ProbeKind::TcpConnect,
            Self::HttpBanner(_) => ProbeKind::Http,
            Self::SnmpSysObjectId(_) | Self::SnmpSysDescr(_) | Self::SnmpSysName(_) => {
                ProbeKind::Snmp
            }
            // NDP also emits Signal::Mac; ARP wins the tie because the variant carries no address-family info.
            Self::Mac(_) => ProbeKind::Arp,
            Self::DnsHost(_) => ProbeKind::Dns,
            Self::NtpBanner(_)
            | Self::SipUserAgent(_)
            | Self::MemcachedVersion(_)
            | Self::StunMappedAddress(_) => ProbeKind::Udp,
            Self::SshBanner(_) | Self::SshHostKey(_) => ProbeKind::Ssh,
            Self::IcmpEchoRttMicros(_) => ProbeKind::Icmp,
            Self::TlsSubject(_) | Self::TlsSanName(_) => ProbeKind::Tls,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeCtx {
    pub timeout: Duration,
    pub retries: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
pub struct ProbeOutcome {
    pub kind: ProbeKind,
    pub target_ip: IpAddr,
    pub timestamp: SystemTime,
    pub reachable: bool,
    pub signals: Vec<Signal>,
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
        };
        let s = serde_json::to_string(&outcome).expect("serialize");
        let back: ProbeOutcome = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back.kind, ProbeKind::TcpConnect);
        assert_eq!(back.target_ip, outcome.target_ip);
        assert!(back.reachable);
        assert_eq!(back.signals.len(), 2);
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
    }

    #[test]
    fn probe_kind_open_port_maps_to_tcp_connect() {
        assert_eq!(Signal::OpenPort(22).probe_kind(), ProbeKind::TcpConnect);
    }

    #[test]
    fn probe_kind_http_banner_maps_to_http() {
        assert_eq!(
            Signal::HttpBanner("nginx/1.25".into()).probe_kind(),
            ProbeKind::Http
        );
    }

    #[test]
    fn probe_kind_snmp_sys_object_id_maps_to_snmp() {
        assert_eq!(
            Signal::SnmpSysObjectId("1.3.6.1".into()).probe_kind(),
            ProbeKind::Snmp
        );
    }

    #[test]
    fn probe_kind_snmp_sys_descr_maps_to_snmp() {
        assert_eq!(
            Signal::SnmpSysDescr("Linux".into()).probe_kind(),
            ProbeKind::Snmp
        );
    }

    #[test]
    fn probe_kind_snmp_sys_name_maps_to_snmp() {
        assert_eq!(
            Signal::SnmpSysName("core-sw01".into()).probe_kind(),
            ProbeKind::Snmp
        );
    }

    #[test]
    fn probe_kind_mac_maps_to_arp() {
        assert_eq!(
            Signal::Mac("aa:bb:cc:dd:ee:ff".into()).probe_kind(),
            ProbeKind::Arp
        );
    }

    #[test]
    fn probe_kind_dns_host_maps_to_dns() {
        assert_eq!(
            Signal::DnsHost("router.example.".into()).probe_kind(),
            ProbeKind::Dns
        );
    }

    #[test]
    fn probe_kind_ntp_banner_maps_to_udp() {
        assert_eq!(
            Signal::NtpBanner("stratum=2".into()).probe_kind(),
            ProbeKind::Udp
        );
    }

    #[test]
    fn probe_kind_sip_user_agent_maps_to_udp() {
        assert_eq!(
            Signal::SipUserAgent("Kamailio/5.6.5".into()).probe_kind(),
            ProbeKind::Udp
        );
    }

    #[test]
    fn probe_kind_memcached_version_maps_to_udp() {
        assert_eq!(
            Signal::MemcachedVersion("1.6.24".into()).probe_kind(),
            ProbeKind::Udp
        );
    }

    #[test]
    fn probe_kind_stun_mapped_address_maps_to_udp() {
        assert_eq!(
            Signal::StunMappedAddress("203.0.113.42:5432".into()).probe_kind(),
            ProbeKind::Udp
        );
    }

    #[test]
    fn probe_kind_ssh_banner_maps_to_ssh() {
        assert_eq!(
            Signal::SshBanner("SSH-2.0-OpenSSH_9.3p1".into()).probe_kind(),
            ProbeKind::Ssh
        );
    }

    #[test]
    fn probe_kind_ssh_host_key_maps_to_ssh() {
        assert_eq!(
            Signal::SshHostKey("ssh-ed25519 AAAAC3Nz".into()).probe_kind(),
            ProbeKind::Ssh
        );
    }

    #[test]
    fn probe_kind_icmp_echo_rtt_micros_maps_to_icmp() {
        assert_eq!(
            Signal::IcmpEchoRttMicros(1234).probe_kind(),
            ProbeKind::Icmp
        );
    }

    #[test]
    fn icmp_signal_round_trips_json() {
        let signal = Signal::IcmpEchoRttMicros(987_654);
        let json = serde_json::to_string(&signal).expect("serialize");
        let back: Signal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(signal, back);
    }

    #[test]
    fn probe_kind_tls_subject_maps_to_tls() {
        assert_eq!(
            Signal::TlsSubject("router.example.com".into()).probe_kind(),
            ProbeKind::Tls
        );
    }

    #[test]
    fn probe_kind_tls_san_name_maps_to_tls() {
        assert_eq!(
            Signal::TlsSanName("router.example.com".into()).probe_kind(),
            ProbeKind::Tls
        );
    }

    #[test]
    fn tls_signal_variants_round_trip_json() {
        for signal in [
            Signal::TlsSubject("router.example.com".into()),
            Signal::TlsSanName("router.example.com".into()),
            Signal::TlsSanName("ip:10.0.0.1".into()),
        ] {
            let s = serde_json::to_string(&signal).expect("serialize");
            let back: Signal = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(signal, back);
        }
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
