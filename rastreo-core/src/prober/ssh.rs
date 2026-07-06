use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use russh::client::{Config, Handler};
use russh::keys::ssh_key::PublicKey;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

const BANNER_MAX_BYTES: usize = 256;

pub struct SshProber {
    ports: Vec<u16>,
}

impl SshProber {
    pub fn new(ports: Vec<u16>) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("ssh prober requires at least one port").into());
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Ok(Self { ports })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
}

/// Serde default for `ProberConfig::Ssh.ports` — `[22]`.
pub fn default_ports() -> Vec<u16> {
    vec![22]
}

struct CaptureHandler {
    slot: Arc<Mutex<Option<String>>>,
}

impl Handler for CaptureHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        if let Ok(encoded) = server_public_key.to_openssh() {
            if let Ok(mut guard) = self.slot.lock() {
                *guard = Some(encoded);
            }
        }
        Ok(true)
    }
}

async fn read_banner(addr: SocketAddr) -> Option<String> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    let mut buf = [0u8; BANNER_MAX_BYTES];
    let mut filled = 0usize;
    while filled < BANNER_MAX_BYTES {
        let n = stream.read(&mut buf[filled..]).await.ok()?;
        if n == 0 {
            break;
        }
        filled += n;
        if let Some(end) = find_line_terminator(&buf[..filled]) {
            let line = std::str::from_utf8(&buf[..end])
                .ok()?
                .trim_end_matches('\r');
            if line.starts_with("SSH-") {
                return Some(line.to_string());
            }
            return None;
        }
    }
    None
}

fn find_line_terminator(bytes: &[u8]) -> Option<usize> {
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            return Some(i);
        }
    }
    None
}

async fn read_host_key(addr: SocketAddr) -> Option<String> {
    let config = Arc::new(Config {
        client_id: russh::SshId::Standard(
            concat!("SSH-2.0-rastreo_", env!("CARGO_PKG_VERSION")).into(),
        ),
        ..Config::default()
    });
    let slot: Arc<Mutex<Option<String>>> = Arc::default();
    let handler = CaptureHandler {
        slot: Arc::clone(&slot),
    };
    let handle = russh::client::connect(config, addr, handler).await.ok()?;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "en-US")
        .await;
    let mut guard = slot.lock().ok()?;
    guard.take()
}

#[async_trait::async_trait]
impl Prober for SshProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Ssh
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let mut signals = Vec::new();
        let mut any_reachable = false;

        for &port in &self.ports {
            let addr = SocketAddr::new(target.ip, port);

            if let Ok(Some(banner)) = timeout(ctx.timeout, read_banner(addr)).await {
                any_reachable = true;
                signals.push(Signal::SshBanner(banner));
            }

            if let Ok(Some(host_key)) = timeout(ctx.timeout, read_host_key(addr)).await {
                any_reachable = true;
                signals.push(Signal::SshHostKey(host_key));
            }
        }

        Ok(ProbeOutcome {
            kind: ProbeKind::Ssh,
            target_ip: target.ip,
            timestamp: SystemTime::now(),
            reachable: any_reachable,
            signals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::error::ConfigError;
    use crate::model::Target;

    fn loopback_target(ip: Ipv4Addr) -> ResolvedTarget {
        let addr = IpAddr::V4(ip);
        ResolvedTarget {
            ip: addr,
            original: Target::Ip(addr),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn new_rejects_empty_ports() {
        match SshProber::new(Vec::new()) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("at least one port"), "got: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("empty ports must error"),
        }
    }

    #[test]
    fn new_dedups_and_sorts_ports() {
        let p = SshProber::new(vec![2222, 22, 2222, 22]).expect("valid");
        assert_eq!(p.ports(), &[22, 2222]);
    }

    #[test]
    fn default_ports_is_22() {
        assert_eq!(default_ports(), vec![22]);
    }

    #[test]
    fn ports_getter_returns_configured_ports() {
        let p = SshProber::new(vec![22, 2022]).expect("valid");
        assert_eq!(p.ports(), &[22, 2022]);
    }

    #[test]
    fn probe_kind_returns_ssh() {
        let p = SshProber::new(vec![22]).expect("valid");
        assert_eq!(p.kind(), ProbeKind::Ssh);
    }

    #[test]
    fn find_line_terminator_locates_newline() {
        assert_eq!(find_line_terminator(b"SSH-2.0-OpenSSH\r\nrest"), Some(16));
        assert_eq!(find_line_terminator(b"SSH-2.0-Test\n"), Some(12));
        assert_eq!(find_line_terminator(b"no terminator here"), None);
    }

    #[tokio::test]
    async fn probe_reports_no_signal_for_closed_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let prober = SshProber::new(vec![port]).expect("valid");
        let ctx = ProbeCtx {
            timeout: std::time::Duration::from_millis(500),
            retries: 0,
        };
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
        assert_eq!(outcome.kind, ProbeKind::Ssh);
    }

    #[tokio::test]
    async fn probe_captures_banner_from_stub_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(b"SSH-2.0-StubServer_1.0\r\n").await;
                let _ = stream.shutdown().await;
            }
        });
        let prober = SshProber::new(vec![port]).expect("valid");
        let ctx = ProbeCtx {
            timeout: std::time::Duration::from_millis(500),
            retries: 0,
        };
        let outcome = prober
            .probe(&loopback_target(Ipv4Addr::LOCALHOST), &ctx)
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        let banner = outcome
            .signals
            .iter()
            .find_map(|s| match s {
                Signal::SshBanner(b) => Some(b.as_str()),
                _ => None,
            })
            .expect("banner captured");
        assert_eq!(banner, "SSH-2.0-StubServer_1.0");
    }

    #[test]
    fn ssh_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<SshProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }
}
