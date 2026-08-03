use std::net::IpAddr;
use std::time::SystemTime;

use ipnet::IpNet;
use schemars::JsonSchema;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum Target {
    Ip(IpAddr),
    Cidr(IpNet),
    Range { start: IpAddr, end: IpAddr },
    DnsName(String),
}

// The one spelling every surface reports a target by; exhaustive here, so a new variant fails to compile until someone writes its form.
impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(ip) => write!(f, "{ip}"),
            Target::Cidr(net) => write!(f, "{net}"),
            Target::Range { start, end } => write!(f, "{start}-{end}"),
            Target::DnsName(name) => f.write_str(name),
        }
    }
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
    fn display_uses_the_form_the_target_was_written_in() {
        assert_eq!(
            Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).to_string(),
            "10.0.0.1"
        );
        assert_eq!(
            Target::Cidr("10.0.0.0/24".parse().expect("cidr")).to_string(),
            "10.0.0.0/24"
        );
        assert_eq!(
            Target::Range {
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            }
            .to_string(),
            "10.0.0.1-10.0.0.5"
        );
        assert_eq!(
            Target::DnsName("example.com".into()).to_string(),
            "example.com"
        );
    }

    #[test]
    fn target_ip_round_trips_json() {
        let t = Target::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let s = serde_json::to_string(&t).expect("serialize");
        let back: Target = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(t, back);
    }

    #[test]
    fn target_cidr_round_trips_json() {
        let t = Target::Cidr("10.0.0.0/24".parse().expect("valid cidr"));
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
