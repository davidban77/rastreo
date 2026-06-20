pub mod tcp_connect;

pub use tcp_connect::TcpConnectProber;

use crate::error::RastreoError;
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget};

#[async_trait::async_trait]
pub trait Prober: Send + Sync {
    fn kind(&self) -> ProbeKind;

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError>;
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProberConfig {
    TcpConnect { ports: Vec<u16> },
}

pub fn create_prober(config: &ProberConfig) -> Result<Box<dyn Prober>, RastreoError> {
    match config {
        ProberConfig::TcpConnect { ports } => Ok(Box::new(TcpConnectProber::new(ports.clone())?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use crate::model::{Signal, Target};

    struct MockProber;

    #[async_trait::async_trait]
    impl Prober for MockProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            Ok(ProbeOutcome {
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::OpenPort(22)],
            })
        }
    }

    #[test]
    fn mock_prober_is_usable_as_trait_object() {
        let p: Box<dyn Prober> = Box::new(MockProber);
        assert_eq!(p.kind(), ProbeKind::TcpConnect);
        let _ = ResolvedTarget {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            original: Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
    }

    #[test]
    fn prober_trait_object_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Prober>();
    }
}
