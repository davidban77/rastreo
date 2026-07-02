use std::io;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1 as smi_v1;
use rasn_smi::v2 as smi_v2;
use rasn_snmp::{v1 as snmp_v1, v2 as snmp_v2, v2c};
use tokio::net::UdpSocket;

use crate::error::{ConfigError, ProbeError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

const RECV_BUF_LEN: usize = 4096;
const MAX_STRING_BYTES: usize = 256;

const OID_SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const OID_SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
const OID_SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnmpVersion {
    #[serde(rename = "v1")]
    V1,
    #[default]
    #[serde(rename = "v2c")]
    V2c,
}

pub struct SnmpProber {
    ports: Vec<u16>,
    version: SnmpVersion,
    community: String,
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
            .finish()
    }
}

impl SnmpProber {
    pub fn new(
        ports: Vec<u16>,
        version: SnmpVersion,
        community: String,
    ) -> Result<Self, RastreoError> {
        if ports.is_empty() {
            return Err(ConfigError::invalid("snmp prober requires at least one port").into());
        }
        if community.is_empty() {
            return Err(ConfigError::invalid("snmp community string must not be empty").into());
        }
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Ok(Self {
            ports,
            version,
            community,
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
}

/// Serde default for `ProberConfig::Snmp.ports` — `[161]`.
pub fn default_ports() -> Vec<u16> {
    vec![161]
}

/// Serde default for `ProberConfig::Snmp.community` — `"public"`.
pub fn default_community() -> crate::prober::redacted::Community {
    crate::prober::redacted::Community("public".to_string())
}

enum PortOutcome {
    Reached(Vec<Signal>),
    Timeout,
    Unreachable,
    DecodeFailed,
    Other(String),
}

fn new_request_id(port: u16) -> i32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = nanos ^ ((port as u64) << 32);
    mixed as i32
}

impl SnmpProber {
    fn oids(&self) -> [&ObjectIdentifier; 3] {
        [
            &self.oid_sys_descr,
            &self.oid_sys_object_id,
            &self.oid_sys_name,
        ]
    }

    fn build_get_request(&self, request_id: i32) -> Result<Vec<u8>, RastreoError> {
        match self.version {
            SnmpVersion::V1 => {
                let variable_bindings = self
                    .oids()
                    .into_iter()
                    .map(|oid| snmp_v1::VarBind {
                        name: oid.clone(),
                        value: smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Empty),
                    })
                    .collect();
                let msg: snmp_v1::Message<snmp_v1::Pdus> = snmp_v1::Message {
                    version: Integer::from(snmp_v1::Message::<()>::VERSION_1),
                    community: OctetString::from_slice(self.community.as_bytes()),
                    data: snmp_v1::Pdus::GetRequest(snmp_v1::GetRequest(snmp_v1::Pdu {
                        request_id: Integer::from(request_id),
                        error_status: Integer::from(0),
                        error_index: Integer::from(0),
                        variable_bindings,
                    })),
                };
                rasn::ber::encode(&msg)
                    .map_err(|e| ProbeError::Other(format!("snmp v1 encode failed: {e}")).into())
            }
            SnmpVersion::V2c => {
                let variable_bindings = self
                    .oids()
                    .into_iter()
                    .map(|oid| snmp_v2::VarBind {
                        name: oid.clone(),
                        value: snmp_v2::VarBindValue::Unspecified,
                    })
                    .collect();
                let msg: v2c::Message<snmp_v2::Pdus> = v2c::Message {
                    version: Integer::from(v2c::Message::<()>::VERSION),
                    community: OctetString::from_slice(self.community.as_bytes()),
                    data: snmp_v2::Pdus::GetRequest(snmp_v2::GetRequest(snmp_v2::Pdu {
                        request_id,
                        error_status: 0,
                        error_index: 0,
                        variable_bindings,
                    })),
                };
                rasn::ber::encode(&msg)
                    .map_err(|e| ProbeError::Other(format!("snmp v2c encode failed: {e}")).into())
            }
        }
    }

    fn parse_response(&self, bytes: &[u8], expected_request_id: i32) -> ResponseVerdict {
        match self.version {
            SnmpVersion::V1 => match rasn::ber::decode::<snmp_v1::Message<snmp_v1::Pdus>>(bytes) {
                Ok(msg) => self.parse_v1(msg, expected_request_id),
                Err(_) => ResponseVerdict::Malformed,
            },
            SnmpVersion::V2c => match rasn::ber::decode::<v2c::Message<snmp_v2::Pdus>>(bytes) {
                Ok(msg) => self.parse_v2c(msg, expected_request_id),
                Err(_) => ResponseVerdict::Malformed,
            },
        }
    }

    fn parse_v1(
        &self,
        msg: snmp_v1::Message<snmp_v1::Pdus>,
        expected_request_id: i32,
    ) -> ResponseVerdict {
        let pdu = match msg.data {
            snmp_v1::Pdus::GetResponse(snmp_v1::GetResponse(pdu)) => pdu,
            _ => return ResponseVerdict::UnexpectedPdu,
        };
        if !integer_matches_i32(&pdu.request_id, expected_request_id) {
            return ResponseVerdict::MismatchedRequestId;
        }
        if !integer_matches_i32(&pdu.error_status, 0) {
            return ResponseVerdict::Ok(Vec::new());
        }
        let mut signals = Vec::new();
        for binding in pdu.variable_bindings {
            if let Some(signal) = self.map_v1_varbind(&binding.name, &binding.value) {
                signals.push(signal);
            }
        }
        ResponseVerdict::Ok(signals)
    }

    fn parse_v2c(
        &self,
        msg: v2c::Message<snmp_v2::Pdus>,
        expected_request_id: i32,
    ) -> ResponseVerdict {
        let pdu = match msg.data {
            snmp_v2::Pdus::Response(snmp_v2::Response(pdu)) => pdu,
            _ => return ResponseVerdict::UnexpectedPdu,
        };
        if pdu.request_id != expected_request_id {
            return ResponseVerdict::MismatchedRequestId;
        }
        if pdu.error_status != 0 {
            return ResponseVerdict::Ok(Vec::new());
        }
        let mut signals = Vec::new();
        for binding in pdu.variable_bindings {
            let syntax = match binding.value {
                snmp_v2::VarBindValue::Value(s) => s,
                _ => continue,
            };
            if let Some(signal) = self.map_v2_varbind(&binding.name, &syntax) {
                signals.push(signal);
            }
        }
        ResponseVerdict::Ok(signals)
    }

    fn map_v1_varbind(
        &self,
        name: &ObjectIdentifier,
        value: &smi_v1::ObjectSyntax,
    ) -> Option<Signal> {
        let simple = match value {
            smi_v1::ObjectSyntax::Simple(s) => s,
            _ => return None,
        };
        if oid_eq(name, &self.oid_sys_descr) {
            if let smi_v1::SimpleSyntax::String(bytes) = simple {
                return Some(Signal::SnmpSysDescr(sanitize_octets(bytes.as_ref())));
            }
        } else if oid_eq(name, &self.oid_sys_object_id) {
            if let smi_v1::SimpleSyntax::Object(oid) = simple {
                return Some(Signal::SnmpSysObjectId(oid_to_dotted(oid)));
            }
        } else if oid_eq(name, &self.oid_sys_name) {
            if let smi_v1::SimpleSyntax::String(bytes) = simple {
                return Some(Signal::SnmpSysName(sanitize_octets(bytes.as_ref())));
            }
        }
        None
    }

    fn map_v2_varbind(
        &self,
        name: &ObjectIdentifier,
        value: &smi_v2::ObjectSyntax,
    ) -> Option<Signal> {
        let simple = match value {
            smi_v2::ObjectSyntax::Simple(s) => s,
            _ => return None,
        };
        if oid_eq(name, &self.oid_sys_descr) {
            if let smi_v2::SimpleSyntax::String(bytes) = simple {
                return Some(Signal::SnmpSysDescr(sanitize_octets(bytes.as_ref())));
            }
        } else if oid_eq(name, &self.oid_sys_object_id) {
            if let smi_v2::SimpleSyntax::ObjectId(oid) = simple {
                return Some(Signal::SnmpSysObjectId(oid_to_dotted(oid)));
            }
        } else if oid_eq(name, &self.oid_sys_name) {
            if let smi_v2::SimpleSyntax::String(bytes) = simple {
                return Some(Signal::SnmpSysName(sanitize_octets(bytes.as_ref())));
            }
        }
        None
    }
}

enum ResponseVerdict {
    Ok(Vec<Signal>),
    UnexpectedPdu,
    MismatchedRequestId,
    Malformed,
}

fn integer_matches_i32(value: &Integer, expected: i32) -> bool {
    i32::try_from(value).map(|v| v == expected).unwrap_or(false)
}

fn oid_eq(lhs: &ObjectIdentifier, rhs: &ObjectIdentifier) -> bool {
    let a: &[u32] = lhs.as_ref();
    let b: &[u32] = rhs.as_ref();
    a == b
}

fn oid_to_dotted(oid: &ObjectIdentifier) -> String {
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

fn sanitize_octets(bytes: &[u8]) -> String {
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

async fn probe_port(target_addr: SocketAddr, prober: &SnmpProber, ctx: &ProbeCtx) -> PortOutcome {
    let bind_addr = if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => return PortOutcome::Other(format!("snmp bind failed: {e}")),
    };
    let request_id = new_request_id(target_addr.port());
    let payload = match prober.build_get_request(request_id) {
        Ok(p) => p,
        Err(e) => return PortOutcome::Other(format!("snmp encode failed: {e}")),
    };
    if let Err(e) = socket.send_to(&payload, target_addr).await {
        return classify_io_error(&e);
    }
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let deadline = tokio::time::Instant::now() + ctx.timeout;
    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, peer))) => {
                if peer.ip() != target_addr.ip() {
                    continue;
                }
                let bytes = &buf[..n];
                match prober.parse_response(bytes, request_id) {
                    ResponseVerdict::Ok(signals) => return PortOutcome::Reached(signals),
                    ResponseVerdict::UnexpectedPdu | ResponseVerdict::MismatchedRequestId => {
                        continue;
                    }
                    ResponseVerdict::Malformed => return PortOutcome::DecodeFailed,
                }
            }
            Ok(Err(e)) => return classify_io_error(&e),
            Err(_) => return PortOutcome::Timeout,
        }
    }
}

fn classify_io_error(err: &io::Error) -> PortOutcome {
    match err.kind() {
        io::ErrorKind::TimedOut => PortOutcome::Timeout,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::ConnectionAborted => PortOutcome::Unreachable,
        _ => PortOutcome::Other(err.to_string()),
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
        let mut timeouts = 0usize;
        let mut unreachables = 0usize;
        let mut decode_failures = 0usize;
        let mut last_other: Option<String> = None;

        for &port in &self.ports {
            let addr = SocketAddr::new(target.ip, port);
            match probe_port(addr, self, ctx).await {
                PortOutcome::Reached(mut new_signals) => {
                    any_reachable = true;
                    signals.append(&mut new_signals);
                }
                PortOutcome::Timeout => timeouts += 1,
                PortOutcome::Unreachable => unreachables += 1,
                PortOutcome::DecodeFailed => decode_failures += 1,
                PortOutcome::Other(msg) => {
                    last_other = Some(format!("snmp probe failed on port {port}: {msg}"));
                }
            }
        }

        if !any_reachable {
            let err = if decode_failures > 0
                && decode_failures >= timeouts
                && decode_failures >= unreachables
            {
                ProbeError::Other("snmp decode failed on all ports".to_string())
            } else if unreachables > 0 && unreachables >= timeouts {
                ProbeError::Unreachable {
                    target: target.ip.to_string(),
                }
            } else if timeouts > 0 {
                ProbeError::Timeout {
                    timeout_ms: ctx.timeout.as_millis() as u64,
                }
            } else if let Some(msg) = last_other {
                ProbeError::Other(msg)
            } else {
                ProbeError::Timeout {
                    timeout_ms: ctx.timeout.as_millis() as u64,
                }
            };
            return Err(err.into());
        }

        Ok(ProbeOutcome {
            kind: ProbeKind::Snmp,
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
    use std::sync::Arc;
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

    fn oid(arcs: &[u32]) -> ObjectIdentifier {
        ObjectIdentifier::new_unchecked(arcs.to_vec().into())
    }

    #[test]
    fn snmp_prober_new_rejects_empty_ports() {
        match SnmpProber::new(Vec::new(), SnmpVersion::V2c, "public".into()) {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("port"), "got: {msg}");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("must error"),
        }
    }

    #[test]
    fn snmp_prober_new_rejects_empty_community() {
        match SnmpProber::new(vec![161], SnmpVersion::V2c, String::new()) {
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
        let p = SnmpProber::new(vec![161], SnmpVersion::V2c, "public".into()).expect("valid");
        assert_eq!(p.kind(), ProbeKind::Snmp);
    }

    #[test]
    fn snmp_prober_debug_redacts_community() {
        let prober =
            SnmpProber::new(vec![161], SnmpVersion::V2c, "secret".to_string()).expect("valid");
        let debug_output = format!("{prober:?}");
        assert!(
            !debug_output.contains("secret"),
            "community leaked in Debug: {debug_output}"
        );
        assert!(debug_output.contains("<redacted>"));
    }

    #[test]
    fn snmp_version_deserializes_from_yaml_v1_and_v2c() {
        let v1: SnmpVersion = serde_json::from_str("\"v1\"").expect("v1");
        assert_eq!(v1, SnmpVersion::V1);
        let v2c: SnmpVersion = serde_json::from_str("\"v2c\"").expect("v2c");
        assert_eq!(v2c, SnmpVersion::V2c);
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
    fn build_get_request_v2c_produces_valid_message_bytes() {
        let p = SnmpProber::new(vec![161], SnmpVersion::V2c, "public".into()).expect("valid");
        let bytes = p.build_get_request(0x1234_5678).expect("encode");
        let msg: v2c::Message<snmp_v2::Pdus> =
            rasn::ber::decode(&bytes).expect("round-trip decode");
        assert_eq!(msg.version, Integer::from(v2c::Message::<()>::VERSION));
        assert_eq!(msg.community.as_ref(), b"public");
        let pdu = match msg.data {
            snmp_v2::Pdus::GetRequest(snmp_v2::GetRequest(pdu)) => pdu,
            other => panic!("expected GetRequest, got {other:?}"),
        };
        assert_eq!(pdu.request_id, 0x1234_5678);
        assert_eq!(pdu.variable_bindings.len(), 3);
        let names: Vec<&[u32]> = pdu
            .variable_bindings
            .iter()
            .map(|b| b.name.as_ref())
            .collect();
        assert!(names.contains(&OID_SYS_DESCR));
        assert!(names.contains(&OID_SYS_OBJECT_ID));
        assert!(names.contains(&OID_SYS_NAME));
    }

    #[test]
    fn build_get_request_v1_produces_valid_message_bytes() {
        let p = SnmpProber::new(vec![161], SnmpVersion::V1, "public".into()).expect("valid");
        let bytes = p.build_get_request(42).expect("encode");
        let msg: snmp_v1::Message<snmp_v1::Pdus> =
            rasn::ber::decode(&bytes).expect("round-trip decode");
        assert_eq!(
            msg.version,
            Integer::from(snmp_v1::Message::<()>::VERSION_1)
        );
        assert_eq!(msg.community.as_ref(), b"public");
        let pdu = match msg.data {
            snmp_v1::Pdus::GetRequest(snmp_v1::GetRequest(pdu)) => pdu,
            other => panic!("expected GetRequest, got {other:?}"),
        };
        assert_eq!(pdu.request_id, Integer::from(42));
        assert_eq!(pdu.variable_bindings.len(), 3);
    }

    fn v2c_response_bytes(
        request_id: i32,
        error_status: u32,
        varbinds: Vec<snmp_v2::VarBind>,
    ) -> Vec<u8> {
        let msg: v2c::Message<snmp_v2::Pdus> = v2c::Message {
            version: Integer::from(v2c::Message::<()>::VERSION),
            community: OctetString::from_slice(b"public"),
            data: snmp_v2::Pdus::Response(snmp_v2::Response(snmp_v2::Pdu {
                request_id,
                error_status,
                error_index: 0,
                variable_bindings: varbinds,
            })),
        };
        rasn::ber::encode(&msg).expect("encode v2c response")
    }

    fn v2c_full_varbinds() -> Vec<snmp_v2::VarBind> {
        vec![
            snmp_v2::VarBind {
                name: oid(OID_SYS_DESCR),
                value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                    smi_v2::SimpleSyntax::String(OctetString::from_slice(b"Linux router-1 6.6")),
                )),
            },
            snmp_v2::VarBind {
                name: oid(OID_SYS_OBJECT_ID),
                value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                    smi_v2::SimpleSyntax::ObjectId(oid(&[1, 3, 6, 1, 4, 1, 8072, 3, 2, 10])),
                )),
            },
            snmp_v2::VarBind {
                name: oid(OID_SYS_NAME),
                value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                    smi_v2::SimpleSyntax::String(OctetString::from_slice(b"router-1")),
                )),
            },
        ]
    }

    #[test]
    fn parse_response_extracts_all_three_signals_when_all_varbinds_present() {
        let p = SnmpProber::new(vec![161], SnmpVersion::V2c, "public".into()).expect("valid");
        let bytes = v2c_response_bytes(7, 0, v2c_full_varbinds());
        let verdict = p.parse_response(&bytes, 7);
        let signals = match verdict {
            ResponseVerdict::Ok(s) => s,
            _ => panic!("expected Ok verdict"),
        };
        assert!(signals.contains(&Signal::SnmpSysDescr("Linux router-1 6.6".into())));
        assert!(signals.contains(&Signal::SnmpSysObjectId("1.3.6.1.4.1.8072.3.2.10".into())));
        assert!(signals.contains(&Signal::SnmpSysName("router-1".into())));
    }

    #[test]
    fn parse_response_extracts_partial_signals_when_agent_omits_sysname() {
        let p = SnmpProber::new(vec![161], SnmpVersion::V2c, "public".into()).expect("valid");
        let mut varbinds = v2c_full_varbinds();
        varbinds.pop(); // drop sysName
        let bytes = v2c_response_bytes(7, 0, varbinds);
        let signals = match p.parse_response(&bytes, 7) {
            ResponseVerdict::Ok(s) => s,
            _ => panic!("expected Ok verdict"),
        };
        assert_eq!(signals.len(), 2);
        assert!(!signals.iter().any(|s| matches!(s, Signal::SnmpSysName(_))));
    }

    #[test]
    fn parse_response_returns_no_signals_on_auth_error() {
        let p = SnmpProber::new(vec![161], SnmpVersion::V2c, "public".into()).expect("valid");
        let bytes = v2c_response_bytes(
            7,
            snmp_v2::Pdu::ERROR_STATUS_AUTHORIZATION_ERROR,
            v2c_full_varbinds(),
        );
        match p.parse_response(&bytes, 7) {
            ResponseVerdict::Ok(signals) => assert!(signals.is_empty()),
            _ => panic!("expected Ok verdict with empty signals"),
        }
    }

    #[test]
    fn parse_response_skips_wrong_type_varbind() {
        let p = SnmpProber::new(vec![161], SnmpVersion::V2c, "public".into()).expect("valid");
        let varbinds = vec![
            snmp_v2::VarBind {
                name: oid(OID_SYS_DESCR),
                value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                    smi_v2::SimpleSyntax::Integer(Integer::from(42)),
                )),
            },
            snmp_v2::VarBind {
                name: oid(OID_SYS_NAME),
                value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                    smi_v2::SimpleSyntax::String(OctetString::from_slice(b"switch-42")),
                )),
            },
        ];
        let bytes = v2c_response_bytes(9, 0, varbinds);
        let signals = match p.parse_response(&bytes, 9) {
            ResponseVerdict::Ok(s) => s,
            _ => panic!("expected Ok verdict"),
        };
        assert_eq!(signals.len(), 1);
        assert!(signals.contains(&Signal::SnmpSysName("switch-42".into())));
    }

    #[test]
    fn parse_response_rejects_mismatched_request_id() {
        let p = SnmpProber::new(vec![161], SnmpVersion::V2c, "public".into()).expect("valid");
        let bytes = v2c_response_bytes(1, 0, v2c_full_varbinds());
        assert!(matches!(
            p.parse_response(&bytes, 2),
            ResponseVerdict::MismatchedRequestId
        ));
    }

    #[test]
    fn parse_response_rejects_non_response_pdu() {
        let p = SnmpProber::new(vec![161], SnmpVersion::V2c, "public".into()).expect("valid");
        let msg: v2c::Message<snmp_v2::Pdus> = v2c::Message {
            version: Integer::from(v2c::Message::<()>::VERSION),
            community: OctetString::from_slice(b"public"),
            data: snmp_v2::Pdus::Report(snmp_v2::Report(snmp_v2::Pdu {
                request_id: 7,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![],
            })),
        };
        let bytes = rasn::ber::encode(&msg).expect("encode report");
        assert!(matches!(
            p.parse_response(&bytes, 7),
            ResponseVerdict::UnexpectedPdu
        ));
    }

    #[test]
    fn oid_to_dotted_formats_expected_arcs() {
        assert_eq!(oid_to_dotted(&oid(&[1, 3, 6, 1, 4, 1, 9])), "1.3.6.1.4.1.9");
    }

    #[test]
    fn sanitize_octets_trims_and_bounds_length() {
        assert_eq!(sanitize_octets(b"  hello  "), "hello");
        let long = vec![b'x'; MAX_STRING_BYTES + 32];
        assert!(sanitize_octets(&long).len() <= MAX_STRING_BYTES);
    }

    type Responder = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static>;

    async fn spawn_agent(bind: &str, responder: Responder) -> io::Result<u16> {
        let socket = UdpSocket::bind(bind).await?;
        let port = socket.local_addr()?.port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_LEN];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                if let Some(resp) = responder(&buf[..n]) {
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });
        Ok(port)
    }

    fn mirror_v2c_response(req: &[u8]) -> Option<Vec<u8>> {
        let msg: v2c::Message<snmp_v2::Pdus> = rasn::ber::decode(req).ok()?;
        let pdu = match msg.data {
            snmp_v2::Pdus::GetRequest(snmp_v2::GetRequest(pdu)) => pdu,
            _ => return None,
        };
        let resp: v2c::Message<snmp_v2::Pdus> = v2c::Message {
            version: msg.version,
            community: msg.community,
            data: snmp_v2::Pdus::Response(snmp_v2::Response(snmp_v2::Pdu {
                request_id: pdu.request_id,
                error_status: 0,
                error_index: 0,
                variable_bindings: v2c_full_varbinds(),
            })),
        };
        rasn::ber::encode(&resp).ok()
    }

    fn v1_full_varbinds() -> Vec<snmp_v1::VarBind> {
        vec![
            snmp_v1::VarBind {
                name: oid(OID_SYS_DESCR),
                value: smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::String(
                    OctetString::from_slice(b"IOS software"),
                )),
            },
            snmp_v1::VarBind {
                name: oid(OID_SYS_OBJECT_ID),
                value: smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Object(oid(&[
                    1, 3, 6, 1, 4, 1, 9,
                ]))),
            },
            snmp_v1::VarBind {
                name: oid(OID_SYS_NAME),
                value: smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::String(
                    OctetString::from_slice(b"core-01"),
                )),
            },
        ]
    }

    fn mirror_v1_response(req: &[u8]) -> Option<Vec<u8>> {
        let msg: snmp_v1::Message<snmp_v1::Pdus> = rasn::ber::decode(req).ok()?;
        let pdu = match msg.data {
            snmp_v1::Pdus::GetRequest(snmp_v1::GetRequest(pdu)) => pdu,
            _ => return None,
        };
        let resp: snmp_v1::Message<snmp_v1::Pdus> = snmp_v1::Message {
            version: msg.version,
            community: msg.community,
            data: snmp_v1::Pdus::GetResponse(snmp_v1::GetResponse(snmp_v1::Pdu {
                request_id: pdu.request_id,
                error_status: Integer::from(0),
                error_index: Integer::from(0),
                variable_bindings: v1_full_varbinds(),
            })),
        };
        rasn::ber::encode(&resp).ok()
    }

    #[tokio::test]
    async fn snmp_prober_v2c_captures_all_three_signals_end_to_end() {
        let port = spawn_agent("127.0.0.1:0", Arc::new(mirror_v2c_response))
            .await
            .expect("bind");
        let prober = SnmpProber::new(vec![port], SnmpVersion::V2c, "public".into()).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysDescr(v) if v == "Linux router-1 6.6")));
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysObjectId(v) if v == "1.3.6.1.4.1.8072.3.2.10")));
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysName(v) if v == "router-1")));
    }

    #[tokio::test]
    async fn snmp_prober_v1_captures_all_three_signals_end_to_end() {
        let port = spawn_agent("127.0.0.1:0", Arc::new(mirror_v1_response))
            .await
            .expect("bind");
        let prober = SnmpProber::new(vec![port], SnmpVersion::V1, "public".into()).expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysDescr(v) if v == "IOS software")));
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysObjectId(v) if v == "1.3.6.1.4.1.9")));
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysName(v) if v == "core-01")));
    }

    #[tokio::test]
    async fn snmp_prober_returns_timeout_when_no_agent_bound() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let _hold = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let _ = socket.recv_from(&mut buf).await;
            }
        });
        let prober = SnmpProber::new(vec![port], SnmpVersion::V2c, "public".into()).expect("valid");
        let err = prober
            .probe(&loopback_target(), &ctx_with_timeout(200))
            .await
            .expect_err("must error");
        match err {
            RastreoError::Probe(ProbeError::Timeout { timeout_ms }) => {
                assert_eq!(timeout_ms, 200);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn snmp_prober_v6_target() {
        let port = match spawn_agent("[::1]:0", Arc::new(mirror_v2c_response)).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skipping IPv6 test: IPv6 loopback bind failed: {e}");
                return;
            }
        };
        let ip: IpAddr = "::1".parse().expect("::1");
        let target = ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let prober = SnmpProber::new(vec![port], SnmpVersion::V2c, "public".into()).expect("valid");
        let outcome = prober
            .probe(&target, &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
    }
}
