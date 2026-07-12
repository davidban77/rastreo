pub mod crypto;
pub mod usm;
pub mod v1_v2c;
pub mod v3;

pub use usm::{AuthAlgo, PrivAlgo, SecurityLevel, UsmAuth, UsmCredentials, UsmPrivacy};
pub use v1_v2c::{
    default_community, default_community_plaintext, default_ports, MAX_STRING_BYTES, OID_SYS_DESCR,
    OID_SYS_NAME, OID_SYS_OBJECT_ID,
};

use std::net::SocketAddr;
use std::time::SystemTime;

use rasn::types::ObjectIdentifier;
use tokio::net::UdpSocket;

use crate::error::{ConfigError, ProbeErrorKind, RastreoError};
use crate::model::{ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::classify::{self, Disposition};
use crate::prober::Prober;

const RECV_BUF_LEN: usize = 8192;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SnmpVersion {
    #[serde(rename = "v1")]
    V1,
    #[default]
    #[serde(rename = "v2c")]
    V2c,
    #[serde(rename = "v3")]
    V3,
}

pub struct SnmpProber {
    ports: Vec<u16>,
    version: SnmpVersion,
    community: String,
    credentials: UsmCredentials,
    oid_sys_descr: ObjectIdentifier,
    oid_sys_object_id: ObjectIdentifier,
    oid_sys_name: ObjectIdentifier,
}

impl std::fmt::Debug for SnmpProber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnmpProber")
            .field("ports", &self.ports)
            .field("version", &self.version)
            .field("community", &"<redacted>")
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl SnmpProber {
    pub fn new(
        ports: Vec<u16>,
        version: SnmpVersion,
        community: String,
        credentials: UsmCredentials,
    ) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("snmp prober requires at least one port").into());
        }
        if matches!(version, SnmpVersion::V1 | SnmpVersion::V2c) && community.is_empty() {
            return Err(ConfigError::invalid("snmp community string must not be empty").into());
        }
        if version == SnmpVersion::V3 && credentials.username.is_empty() {
            return Err(ConfigError::invalid(
                "snmp v3 requires a non-empty username in credentials",
            )
            .into());
        }
        if version == SnmpVersion::V3 {
            let auth = credentials.auth.resolve();
            let privacy = credentials.privacy.resolve();
            if let Err(msg) = usm::derive_security_level(&auth, &privacy) {
                return Err(ConfigError::invalid(msg).into());
            }
            if let Some(password) = credentials.auth.password() {
                if password.is_empty() {
                    return Err(
                        ConfigError::invalid("snmp v3 auth password must not be empty").into(),
                    );
                }
            }
            if let Some(password) = credentials.privacy.password() {
                if password.is_empty() {
                    return Err(
                        ConfigError::invalid("snmp v3 privacy password must not be empty").into(),
                    );
                }
            }
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Ok(Self {
            ports,
            version,
            community,
            credentials,
            oid_sys_descr: ObjectIdentifier::new_unchecked(OID_SYS_DESCR.into()),
            oid_sys_object_id: ObjectIdentifier::new_unchecked(OID_SYS_OBJECT_ID.into()),
            oid_sys_name: ObjectIdentifier::new_unchecked(OID_SYS_NAME.into()),
        })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    pub fn version(&self) -> SnmpVersion {
        self.version
    }

    pub(super) fn oids(&self) -> [&ObjectIdentifier; 3] {
        [
            &self.oid_sys_descr,
            &self.oid_sys_object_id,
            &self.oid_sys_name,
        ]
    }

    pub(super) fn oid_sys_descr(&self) -> &ObjectIdentifier {
        &self.oid_sys_descr
    }

    pub(super) fn oid_sys_object_id(&self) -> &ObjectIdentifier {
        &self.oid_sys_object_id
    }

    pub(super) fn oid_sys_name(&self) -> &ObjectIdentifier {
        &self.oid_sys_name
    }

    pub(super) fn community(&self) -> &str {
        &self.community
    }

    pub(super) fn credentials(&self) -> &UsmCredentials {
        &self.credentials
    }
}

pub(super) enum PortOutcome {
    Reached(Vec<Signal>),
    Timeout,
    Unreachable,
    DecodeFailed,
    Other(String),
}

pub(super) async fn bind_socket(target_addr: SocketAddr) -> Result<UdpSocket, PortOutcome> {
    let bind_addr = if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| PortOutcome::Other(format!("snmp bind failed: {e}")))
}

pub(super) fn classify_io_error(err: &std::io::Error) -> PortOutcome {
    match classify::io_error(err) {
        Disposition::Absence if err.kind() == std::io::ErrorKind::TimedOut => PortOutcome::Timeout,
        Disposition::Absence => PortOutcome::Unreachable,
        Disposition::Fault(_) => PortOutcome::Other(err.to_string()),
    }
}

async fn probe_port(target_addr: SocketAddr, prober: &SnmpProber, ctx: &ProbeCtx) -> PortOutcome {
    match prober.version {
        SnmpVersion::V1 | SnmpVersion::V2c => v1_v2c::probe_port(target_addr, prober, ctx).await,
        SnmpVersion::V3 => v3::probe_port(target_addr, prober, ctx).await,
    }
}

#[async_trait::async_trait]
impl Prober for SnmpProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Snmp
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let mut signals = Vec::new();
        let mut any_reachable = false;
        let mut decode_failed_port: Option<u16> = None;
        let mut last_fault: Option<String> = None;

        for &port in &self.ports {
            let addr = SocketAddr::new(target.ip, port);
            match probe_port(addr, self, ctx).await {
                PortOutcome::Reached(mut new_signals) => {
                    any_reachable = true;
                    signals.append(&mut new_signals);
                }
                PortOutcome::Timeout | PortOutcome::Unreachable => {}
                PortOutcome::DecodeFailed => {
                    decode_failed_port.get_or_insert(port);
                }
                PortOutcome::Other(msg) => {
                    last_fault = Some(format!("snmp probe failed on port {port}: {msg}"));
                }
            }
        }

        if !any_reachable {
            // Silence on one port is not evidence against a fault on another, but an answer is:
            // an agent that answered with something we cannot parse answered — the device is kept
            // (reachable) with the decode fault recorded and no signals.
            if let Some(port) = decode_failed_port {
                return Ok(ProbeOutcome {
                    kind: ProbeKind::Snmp,
                    target_ip: target.ip,
                    timestamp: SystemTime::now(),
                    reachable: true,
                    signals: Vec::new(),
                    fault: Some(ProbeFault::new(
                        ProbeErrorKind::DecodeFailed,
                        format!("snmp reply on port {port} could not be decoded"),
                    )),
                });
            }
            return Ok(ProbeOutcome {
                kind: ProbeKind::Snmp,
                target_ip: target.ip,
                timestamp: SystemTime::now(),
                reachable: false,
                signals: Vec::new(),
                fault: last_fault.map(|detail| ProbeFault::new(ProbeErrorKind::Other, detail)),
            });
        }

        Ok(ProbeOutcome {
            kind: ProbeKind::Snmp,
            target_ip: target.ip,
            timestamp: SystemTime::now(),
            reachable: any_reachable,
            signals,
            fault: None,
        })
    }
}

pub(super) fn oid_eq(lhs: &ObjectIdentifier, rhs: &ObjectIdentifier) -> bool {
    let a: &[u32] = lhs.as_ref();
    let b: &[u32] = rhs.as_ref();
    a == b
}

pub(super) fn oid_to_dotted(oid: &ObjectIdentifier) -> String {
    let arcs: &[u32] = oid.as_ref();
    let mut out = String::with_capacity(arcs.len() * 4);
    for (i, arc) in arcs.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(&arc.to_string());
    }
    out
}

pub(super) fn sanitize_octets(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let trimmed = s.trim();
    if trimmed.len() <= MAX_STRING_BYTES {
        trimmed.to_string()
    } else {
        let mut end = MAX_STRING_BYTES;
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        trimmed[..end].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::model::Target;

    fn loopback_target() -> ResolvedTarget {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn ctx_with_timeout(ms: u64) -> ProbeCtx {
        ProbeCtx {
            timeout: Duration::from_millis(ms),
            retries: 0,
        }
    }

    #[test]
    fn snmp_prober_new_rejects_empty_ports() {
        match SnmpProber::new(
            Vec::new(),
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("port"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn snmp_prober_new_rejects_empty_community() {
        match SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            String::new(),
            UsmCredentials::default(),
        ) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("community"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn snmp_prober_new_sorts_and_dedups_ports() {
        let p = SnmpProber::new(
            vec![161, 1161, 161, 9161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        assert_eq!(p.ports(), &[161, 1161, 9161]);
    }

    #[test]
    fn snmp_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<SnmpProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[test]
    fn kind_returns_snmp() {
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        assert_eq!(p.kind(), ProbeKind::Snmp);
    }

    #[test]
    fn snmp_prober_debug_redacts_community() {
        let prober = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "secret".to_string(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let debug_output = format!("{prober:?}");
        assert!(
            !debug_output.contains("secret"),
            "community leaked in Debug: {debug_output}"
        );
        assert!(debug_output.contains("<redacted>"));
    }

    #[test]
    fn snmp_version_deserializes_from_yaml() {
        let v1: SnmpVersion = serde_json::from_str("\"v1\"").expect("v1");
        assert_eq!(v1, SnmpVersion::V1);
        let v2c: SnmpVersion = serde_json::from_str("\"v2c\"").expect("v2c");
        assert_eq!(v2c, SnmpVersion::V2c);
        let v3: SnmpVersion = serde_json::from_str("\"v3\"").expect("v3");
        assert_eq!(v3, SnmpVersion::V3);
    }

    #[test]
    fn snmp_version_default_is_v2c() {
        assert_eq!(SnmpVersion::default(), SnmpVersion::V2c);
    }

    #[test]
    fn default_ports_is_snmp_161() {
        assert_eq!(default_ports(), vec![161]);
    }

    #[test]
    fn default_community_is_public() {
        assert_eq!(&*default_community(), "public");
    }

    #[test]
    fn oid_to_dotted_formats_expected_arcs() {
        let o = ObjectIdentifier::new_unchecked(vec![1, 3, 6, 1, 4, 1, 9].into());
        assert_eq!(oid_to_dotted(&o), "1.3.6.1.4.1.9");
    }

    #[test]
    fn sanitize_octets_trims_and_bounds_length() {
        assert_eq!(sanitize_octets(b"  hello  "), "hello");
        let long = vec![b'x'; MAX_STRING_BYTES + 32];
        assert!(sanitize_octets(&long).len() <= MAX_STRING_BYTES);
    }

    #[test]
    fn constructor_rejects_v3_without_username() {
        let creds = UsmCredentials {
            username: String::new(),
            auth: UsmAuth::None,
            privacy: UsmPrivacy::None,
        };
        match SnmpProber::new(vec![161], SnmpVersion::V3, String::new(), creds) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("username"), "got: {msg}");
            }
            other => panic!("expected InvalidValue about username, got {other:?}"),
        }
    }

    #[test]
    fn constructor_rejects_priv_without_auth() {
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::None,
            privacy: UsmPrivacy::Aes128 {
                password: crate::prober::redacted::Password("privpass".into()),
            },
        };
        match SnmpProber::new(vec![161], SnmpVersion::V3, String::new(), creds) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("auth"), "got: {msg}");
            }
            other => panic!("expected InvalidValue about auth, got {other:?}"),
        }
    }

    #[test]
    fn constructor_accepts_v3_with_only_username_noauthnopriv() {
        let creds = UsmCredentials {
            username: "discoveryonly".into(),
            auth: UsmAuth::None,
            privacy: UsmPrivacy::None,
        };
        SnmpProber::new(vec![161], SnmpVersion::V3, String::new(), creds).expect("valid v3");
    }

    #[test]
    fn constructor_rejects_v3_with_empty_auth_password() {
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha256 {
                password: crate::prober::redacted::Password(String::new()),
            },
            privacy: UsmPrivacy::None,
        };
        match SnmpProber::new(vec![161], SnmpVersion::V3, String::new(), creds) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("auth password"), "got: {msg}");
            }
            other => panic!("expected InvalidValue about auth password, got {other:?}"),
        }
    }

    #[test]
    fn constructor_rejects_v3_with_empty_priv_password() {
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha256 {
                password: crate::prober::redacted::Password("authpass".into()),
            },
            privacy: UsmPrivacy::Aes128 {
                password: crate::prober::redacted::Password(String::new()),
            },
        };
        match SnmpProber::new(vec![161], SnmpVersion::V3, String::new(), creds) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("privacy password"), "got: {msg}");
            }
            other => panic!("expected InvalidValue about privacy password, got {other:?}"),
        }
    }

    #[test]
    fn constructor_accepts_v3_authpriv_sha256_aes128() {
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha256 {
                password: crate::prober::redacted::Password("authpass".into()),
            },
            privacy: UsmPrivacy::Aes128 {
                password: crate::prober::redacted::Password("privpass".into()),
            },
        };
        SnmpProber::new(vec![161], SnmpVersion::V3, String::new(), creds).expect("valid v3");
    }

    #[tokio::test]
    async fn snmp_prober_returns_unreachable_outcome_when_no_agent_bound() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let _hold = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let _ = socket.recv_from(&mut buf).await;
            }
        });
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(200))
            .await
            .expect("a silent agent is an outcome, not an error");
        assert_eq!(outcome.kind, ProbeKind::Snmp);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    async fn spawn_undecodable_agent() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((_, peer)) = socket.recv_from(&mut buf).await {
                    let _ = socket.send_to(&[0xff, 0xfe, 0xfd, 0xfc], peer).await;
                }
            }
        });
        port
    }

    async fn dark_port() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let _ = socket.recv_from(&mut buf).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn snmp_decode_failure_keeps_the_device_with_a_decode_fault() {
        let port = spawn_undecodable_agent().await;
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(500))
            .await
            .expect("an undecodable reply keeps the device, it is not an Err");
        assert!(
            outcome.reachable,
            "the agent answered on the port, so the device is reachable"
        );
        assert!(
            outcome.signals.is_empty(),
            "an undecodable reply yields no signals"
        );
        let fault = outcome
            .fault
            .expect("the decode failure is recorded on the outcome");
        assert_eq!(fault.kind, ProbeErrorKind::DecodeFailed);
        assert!(fault.detail.contains("decode"), "got: {}", fault.detail);
        assert!(
            fault.detail.contains(&port.to_string()),
            "got: {}",
            fault.detail
        );
    }

    #[tokio::test]
    async fn snmp_decode_failure_wins_even_when_other_ports_are_dark() {
        let undecodable = spawn_undecodable_agent().await;
        let silent_a = dark_port().await;
        let silent_b = dark_port().await;

        let prober = SnmpProber::new(
            vec![undecodable, silent_a, silent_b],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(200))
            .await
            .expect("two dark ports must not mask an undecodable agent on a third");
        assert!(outcome.reachable);
        let fault = outcome
            .fault
            .expect("the decode failure is recorded on the outcome");
        assert_eq!(fault.kind, ProbeErrorKind::DecodeFailed);
        assert!(fault.detail.contains("decode"), "got: {}", fault.detail);
    }
}
