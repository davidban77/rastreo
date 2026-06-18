use std::net::IpAddr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ProbeKind {
    TcpConnect,
    Udp,
    Http,
    Dns,
    Snmp,
    Arp,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Signal {
    OpenPort(u16),
    HttpBanner(String),
    SnmpSysObjectId(String),
    SnmpSysDescr(String),
    Mac(String),
    DnsHost(String),
}

#[derive(Debug, Clone)]
pub struct ProbeCtx {
    pub timeout: Duration,
    pub retries: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    fn outcome_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProbeKind>();
        assert_send_sync::<Signal>();
        assert_send_sync::<ProbeCtx>();
        assert_send_sync::<ProbeOutcome>();
    }
}
