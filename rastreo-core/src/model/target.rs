use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Target {
    Ip(IpAddr),
    // Source form for CIDR notation; parsed by the resolver, not stored as a typed network.
    Cidr(String),
    Range { start: IpAddr, end: IpAddr },
    DnsName(String),
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub ip: IpAddr,
    pub original: Target,
    pub resolved_at: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn target_ip_round_trips_json() {
        let t = Target::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let s = serde_json::to_string(&t).expect("serialize");
        let back: Target = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(t, back);
    }

    #[test]
    fn target_cidr_round_trips_json() {
        let t = Target::Cidr("10.0.0.0/24".into());
        let s = serde_json::to_string(&t).expect("serialize");
        let back: Target = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(t, back);
    }

    #[test]
    fn target_range_round_trips_json() {
        let t = Target::Range {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
        };
        let s = serde_json::to_string(&t).expect("serialize");
        let back: Target = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(t, back);
    }

    #[test]
    fn target_dns_round_trips_json() {
        let t = Target::DnsName("router-1.lab.local".into());
        let s = serde_json::to_string(&t).expect("serialize");
        let back: Target = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(t, back);
    }

    #[test]
    fn target_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Target>();
        assert_send_sync::<ResolvedTarget>();
    }
}
