#![cfg(feature = "ssh")]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use rastreo_core::{ProbeCtx, Prober, ResolvedTarget, Signal, SshProber, Target};
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const LEGACY_SSHD_BOOTSTRAP: &str = r#"apk add --no-cache openssh-server openssh-keygen >/dev/null 2>&1
ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key -N "" >/dev/null
cat > /etc/ssh/sshd_config <<EOF
Port 22
HostKey /etc/ssh/ssh_host_rsa_key
KexAlgorithms diffie-hellman-group14-sha1
Ciphers aes128-cbc
MACs hmac-sha1
HostKeyAlgorithms ssh-rsa
PubkeyAcceptedAlgorithms ssh-rsa
PermitRootLogin yes
EOF
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e"#;

#[tokio::test]
#[ignore]
async fn legacy_only_sshd_host_key_is_captured() {
    let container = GenericImage::new("alpine", "3.22")
        .with_exposed_port(ContainerPort::Tcp(22))
        .with_wait_for(WaitFor::message_on_either_std(
            "Server listening on 0.0.0.0 port 22",
        ))
        .with_entrypoint("/bin/sh")
        .with_cmd(["-c", LEGACY_SSHD_BOOTSTRAP])
        .start()
        .await
        .expect("start legacy-only sshd container");

    let port = container
        .get_host_port_ipv4(ContainerPort::Tcp(22))
        .await
        .expect("mapped ssh port");

    let prober = SshProber::new(vec![port]).expect("valid prober");
    let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let target = ResolvedTarget {
        ip: localhost,
        original: Target::Ip(localhost),
        resolved_at: SystemTime::UNIX_EPOCH,
    };
    let ctx = ProbeCtx::new(Duration::from_secs(15), 0);

    let outcome = prober.probe(&target, &ctx).await.expect("probe ok");

    assert!(
        outcome.reachable,
        "legacy sshd must be reachable: {outcome:?}"
    );
    let host_key = outcome.signals.iter().find_map(|s| match s {
        Signal::SshHostKey(k) => Some(k.as_str()),
        _ => None,
    });
    let host_key = host_key.unwrap_or_else(|| {
        panic!(
            "legacy-only sshd host key must be captured; signals: {:?}",
            outcome.signals
        )
    });
    assert!(
        host_key.starts_with("ssh-rsa "),
        "captured host key should be the RSA key negotiated over ssh-rsa: {host_key:?}"
    );
}
