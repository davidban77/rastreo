use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1 as smi_v1;
use rasn_smi::v2 as smi_v2;
use rasn_snmp::{v1 as snmp_v1, v2 as snmp_v2, v2c};
use tokio::net::UdpSocket;

#[cfg(test)]
use crate::error::{ProbeError, RastreoError};
use crate::model::{ProbeCtx, Signal};

use super::request::{
    snmp_io_error, snmp_request, RequestPdu, SnmpError, SnmpResponse, SnmpSession, VarBind,
    VarValue,
};
use super::{
    bind_socket, oid_eq, oid_to_dotted, sanitize_octets, PortOutcome, SnmpProber, SnmpVersion,
    RECV_BUF_LEN,
};

pub const MAX_STRING_BYTES: usize = 256;

pub const OID_SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
pub const OID_SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
pub const OID_SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];

/// Serde default for `ProberConfig::Snmp.ports` — `[161]`.
pub fn default_ports() -> Vec<u16> {
    vec![161]
}

/// Serde default for `ProberConfig::Snmp.community` — `"public"`.
pub fn default_community() -> crate::prober::redacted::Community {
    crate::prober::redacted::Community("public".to_string())
}

/// JsonSchema-facing default: the plaintext community, not the redacted
/// `Serialize` output. Used via `#[schemars(default = ...)]` so IDE autocomplete
/// suggests `public` rather than an opaque `<redacted:...>` token.
#[cfg(feature = "snmp")]
pub fn default_community_plaintext() -> &'static str {
    "public"
}

pub(super) fn new_request_id(port: u16) -> i32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = nanos ^ ((port as u64) << 32);
    mixed as i32
}

impl SnmpProber {
    #[cfg(test)]
    pub(super) fn build_v1_v2c_request(&self, request_id: i32) -> Result<Vec<u8>, RastreoError> {
        let names: Vec<ObjectIdentifier> = self.oids().into_iter().cloned().collect();
        encode_community_message(
            self.version(),
            self.community(),
            &RequestPdu::Get(names),
            request_id,
        )
        .map_err(|e| ProbeError::Other(e).into())
    }

    #[cfg(test)]
    pub(super) fn parse_v1_v2c_response(
        &self,
        bytes: &[u8],
        expected_request_id: i32,
    ) -> ResponseVerdict {
        match decode_community_response(self.version(), bytes, expected_request_id) {
            CommunityVerdict::Response(resp) if resp.error_status != 0 => {
                ResponseVerdict::Ok(Vec::new())
            }
            CommunityVerdict::Response(resp) => {
                ResponseVerdict::Ok(map_varbinds_to_signals(self, &resp.var_binds))
            }
            CommunityVerdict::WrongRequestId => ResponseVerdict::MismatchedRequestId,
            CommunityVerdict::UnexpectedPdu => ResponseVerdict::UnexpectedPdu,
            CommunityVerdict::Malformed => ResponseVerdict::Malformed,
        }
    }
}

/// Encode a v1/v2c request message from a version-agnostic PDU. GETBULK is v2c-only.
pub(super) fn encode_community_message(
    version: SnmpVersion,
    community: &str,
    pdu: &RequestPdu,
    request_id: i32,
) -> Result<Vec<u8>, String> {
    match version {
        SnmpVersion::V1 => {
            let variable_bindings = pdu
                .names()
                .iter()
                .map(|oid| snmp_v1::VarBind {
                    name: oid.clone(),
                    value: smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Empty),
                })
                .collect();
            let inner = snmp_v1::Pdu {
                request_id: Integer::from(request_id),
                error_status: Integer::from(0),
                error_index: Integer::from(0),
                variable_bindings,
            };
            let data = match pdu {
                RequestPdu::Get(_) => snmp_v1::Pdus::GetRequest(snmp_v1::GetRequest(inner)),
                #[cfg(feature = "lldp")]
                RequestPdu::GetNext(_) => {
                    snmp_v1::Pdus::GetNextRequest(snmp_v1::GetNextRequest(inner))
                }
                #[cfg(feature = "lldp")]
                RequestPdu::GetBulk { .. } => return Err("snmp v1 has no GetBulkRequest".into()),
            };
            let msg: snmp_v1::Message<snmp_v1::Pdus> = snmp_v1::Message {
                version: Integer::from(snmp_v1::Message::<()>::VERSION_1),
                community: OctetString::from_slice(community.as_bytes()),
                data,
            };
            rasn::ber::encode(&msg).map_err(|e| format!("snmp v1 encode failed: {e}"))
        }
        SnmpVersion::V2c => {
            let data = match pdu {
                RequestPdu::Get(names) => {
                    snmp_v2::Pdus::GetRequest(snmp_v2::GetRequest(simple_v2_pdu(request_id, names)))
                }
                #[cfg(feature = "lldp")]
                RequestPdu::GetNext(names) => snmp_v2::Pdus::GetNextRequest(
                    snmp_v2::GetNextRequest(simple_v2_pdu(request_id, names)),
                ),
                #[cfg(feature = "lldp")]
                RequestPdu::GetBulk {
                    non_repeaters,
                    max_repetitions,
                    names,
                } => snmp_v2::Pdus::GetBulkRequest(snmp_v2::GetBulkRequest(snmp_v2::BulkPdu {
                    request_id,
                    non_repeaters: *non_repeaters,
                    max_repetitions: *max_repetitions,
                    variable_bindings: unspecified_v2_varbinds(names),
                })),
            };
            let msg: v2c::Message<snmp_v2::Pdus> = v2c::Message {
                version: Integer::from(v2c::Message::<()>::VERSION),
                community: OctetString::from_slice(community.as_bytes()),
                data,
            };
            rasn::ber::encode(&msg).map_err(|e| format!("snmp v2c encode failed: {e}"))
        }
        SnmpVersion::V3 => Err("encode_community_message called for v3".into()),
    }
}

fn simple_v2_pdu(request_id: i32, names: &[ObjectIdentifier]) -> snmp_v2::Pdu {
    snmp_v2::Pdu {
        request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: unspecified_v2_varbinds(names),
    }
}

pub(super) fn unspecified_v2_varbinds(names: &[ObjectIdentifier]) -> Vec<snmp_v2::VarBind> {
    names
        .iter()
        .map(|oid| snmp_v2::VarBind {
            name: oid.clone(),
            value: snmp_v2::VarBindValue::Unspecified,
        })
        .collect()
}

pub(super) enum CommunityVerdict {
    Response(SnmpResponse),
    UnexpectedPdu,
    WrongRequestId,
    Malformed,
}

pub(super) fn decode_community_response(
    version: SnmpVersion,
    bytes: &[u8],
    expected_request_id: i32,
) -> CommunityVerdict {
    match version {
        SnmpVersion::V1 => match rasn::ber::decode::<snmp_v1::Message<snmp_v1::Pdus>>(bytes) {
            Ok(msg) => decode_v1_pdu(msg, expected_request_id),
            Err(_) => CommunityVerdict::Malformed,
        },
        SnmpVersion::V2c => match rasn::ber::decode::<v2c::Message<snmp_v2::Pdus>>(bytes) {
            Ok(msg) => decode_v2c_pdu(msg, expected_request_id),
            Err(_) => CommunityVerdict::Malformed,
        },
        SnmpVersion::V3 => CommunityVerdict::Malformed,
    }
}

fn decode_v1_pdu(
    msg: snmp_v1::Message<snmp_v1::Pdus>,
    expected_request_id: i32,
) -> CommunityVerdict {
    let pdu = match msg.data {
        snmp_v1::Pdus::GetResponse(snmp_v1::GetResponse(pdu)) => pdu,
        _ => return CommunityVerdict::UnexpectedPdu,
    };
    if !integer_matches_i32(&pdu.request_id, expected_request_id) {
        return CommunityVerdict::WrongRequestId;
    }
    // A nonzero status that does not fit i32 still means "not success" — coerce to a nonzero marker.
    let error_status = i32::try_from(&pdu.error_status)
        .map(|v| v as u32)
        .unwrap_or(1);
    let var_binds = pdu
        .variable_bindings
        .into_iter()
        .map(normalize_v1_varbind)
        .collect();
    CommunityVerdict::Response(SnmpResponse {
        error_status,
        var_binds,
    })
}

fn decode_v2c_pdu(msg: v2c::Message<snmp_v2::Pdus>, expected_request_id: i32) -> CommunityVerdict {
    let pdu = match msg.data {
        snmp_v2::Pdus::Response(snmp_v2::Response(pdu)) => pdu,
        _ => return CommunityVerdict::UnexpectedPdu,
    };
    if pdu.request_id != expected_request_id {
        return CommunityVerdict::WrongRequestId;
    }
    let var_binds = pdu
        .variable_bindings
        .into_iter()
        .map(normalize_v2_varbind)
        .collect();
    CommunityVerdict::Response(SnmpResponse {
        error_status: pdu.error_status,
        var_binds,
    })
}

pub(super) fn normalize_v1_varbind(vb: snmp_v1::VarBind) -> VarBind {
    let value = match vb.value {
        smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Number(i)) => {
            VarValue::Int(i32::try_from(&i).map(i64::from).unwrap_or(0))
        }
        smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::String(s)) => {
            VarValue::Bytes(s.to_vec())
        }
        smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Object(o)) => VarValue::Oid(o),
        smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Empty) => VarValue::Unspecified,
        _ => VarValue::Other,
    };
    VarBind {
        name: vb.name,
        value,
    }
}

pub(super) fn normalize_v2_varbind(vb: snmp_v2::VarBind) -> VarBind {
    let value = match vb.value {
        snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(simple)) => match simple {
            smi_v2::SimpleSyntax::Integer(i) => {
                VarValue::Int(i32::try_from(&i).map(i64::from).unwrap_or(0))
            }
            smi_v2::SimpleSyntax::String(s) => VarValue::Bytes(s.to_vec()),
            smi_v2::SimpleSyntax::ObjectId(o) => VarValue::Oid(o),
        },
        snmp_v2::VarBindValue::Value(_) => VarValue::Other,
        snmp_v2::VarBindValue::Unspecified => VarValue::Unspecified,
        snmp_v2::VarBindValue::NoSuchObject => VarValue::NoSuchObject,
        snmp_v2::VarBindValue::NoSuchInstance => VarValue::NoSuchInstance,
        snmp_v2::VarBindValue::EndOfMibView => VarValue::EndOfMibView,
    };
    VarBind {
        name: vb.name,
        value,
    }
}

pub(super) fn map_varbinds_to_signals(prober: &SnmpProber, var_binds: &[VarBind]) -> Vec<Signal> {
    var_binds
        .iter()
        .filter_map(|vb| map_varbind_to_signal(prober, vb))
        .collect()
}

fn map_varbind_to_signal(prober: &SnmpProber, vb: &VarBind) -> Option<Signal> {
    if oid_eq(&vb.name, prober.oid_sys_descr()) {
        if let VarValue::Bytes(bytes) = &vb.value {
            return Some(Signal::SnmpSysDescr(sanitize_octets(bytes)));
        }
    } else if oid_eq(&vb.name, prober.oid_sys_object_id()) {
        if let VarValue::Oid(oid) = &vb.value {
            return Some(Signal::SnmpSysObjectId(oid_to_dotted(oid)));
        }
    } else if oid_eq(&vb.name, prober.oid_sys_name()) {
        if let VarValue::Bytes(bytes) = &vb.value {
            return Some(Signal::SnmpSysName(sanitize_octets(bytes)));
        }
    }
    None
}

#[cfg(test)]
pub(super) enum ResponseVerdict {
    Ok(Vec<Signal>),
    UnexpectedPdu,
    MismatchedRequestId,
    Malformed,
}

fn integer_matches_i32(value: &Integer, expected: i32) -> bool {
    i32::try_from(value).map(|v| v == expected).unwrap_or(false)
}

/// Send + retry loop for a community request: retransmits within a per-attempt slice of the total
/// deadline, ignores replies from the wrong peer or with a stale request-id, and stops when the
/// deadline lapses. `Absent` is exhausted silence, not a fault.
pub(super) async fn community_exchange(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    version: SnmpVersion,
    community: &str,
    pdu: &RequestPdu,
    ctx: &ProbeCtx,
) -> Result<SnmpResponse, SnmpError> {
    let request_id = new_request_id(target_addr.port());
    let payload = match encode_community_message(version, community, pdu, request_id) {
        Ok(p) => p,
        Err(e) => return Err(SnmpError::Other(format!("snmp encode failed: {e}"))),
    };
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let per_attempt = crate::prober::per_attempt_timeout(ctx.timeout, ctx.retries);
    let overall_deadline = tokio::time::Instant::now() + ctx.timeout;
    for _ in 0..=ctx.retries {
        if let Err(e) = socket.send_to(&payload, target_addr).await {
            return Err(snmp_io_error(&e));
        }
        let attempt_deadline = (tokio::time::Instant::now() + per_attempt).min(overall_deadline);
        loop {
            match tokio::time::timeout_at(attempt_deadline, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    if peer.ip() != target_addr.ip() {
                        continue;
                    }
                    match decode_community_response(version, &buf[..n], request_id) {
                        CommunityVerdict::Response(resp) => return Ok(resp),
                        CommunityVerdict::UnexpectedPdu | CommunityVerdict::WrongRequestId => {
                            continue
                        }
                        CommunityVerdict::Malformed => return Err(SnmpError::Decode),
                    }
                }
                Ok(Err(e)) => return Err(snmp_io_error(&e)),
                Err(_) => break,
            }
        }
        if tokio::time::Instant::now() >= overall_deadline {
            break;
        }
    }
    Err(SnmpError::Absent)
}

pub(super) async fn probe_port(
    target_addr: SocketAddr,
    prober: &SnmpProber,
    ctx: &ProbeCtx,
) -> PortOutcome {
    let socket = match bind_socket(target_addr).await {
        Ok(s) => s,
        Err(e) => return e,
    };
    let session = SnmpSession::community(
        socket,
        target_addr,
        prober.version(),
        prober.community().to_string(),
    );
    let get = RequestPdu::Get(prober.oids().into_iter().cloned().collect());
    match snmp_request(&session, &get, ctx).await {
        Ok(resp) if resp.error_status == 0 => {
            PortOutcome::Reached(map_varbinds_to_signals(prober, &resp.var_binds))
        }
        Ok(_) => PortOutcome::Reached(Vec::new()),
        Err(SnmpError::Absent) => PortOutcome::Timeout,
        Err(SnmpError::Decode) => PortOutcome::DecodeFailed,
        Err(SnmpError::Fault(kind, msg)) => PortOutcome::Fault(kind, msg),
        Err(SnmpError::Other(msg)) => PortOutcome::Other(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProbeKind, ProbeOutcome, ResolvedTarget, Target};
    use crate::prober::snmp::UsmCredentials;
    use crate::prober::Prober;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use tokio::net::UdpSocket;

    fn loopback_target() -> ResolvedTarget {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn ctx_with_timeout(ms: u64) -> ProbeCtx {
        ProbeCtx::new(Duration::from_millis(ms), 0)
    }

    fn oid(arcs: &[u32]) -> ObjectIdentifier {
        ObjectIdentifier::new_unchecked(arcs.to_vec().into())
    }

    #[test]
    fn build_get_request_v2c_produces_valid_message_bytes() {
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let bytes = p.build_v1_v2c_request(0x1234_5678).expect("encode");
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
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V1,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let bytes = p.build_v1_v2c_request(42).expect("encode");
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
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let bytes = v2c_response_bytes(7, 0, v2c_full_varbinds());
        let verdict = p.parse_v1_v2c_response(&bytes, 7);
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
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let mut varbinds = v2c_full_varbinds();
        varbinds.pop();
        let bytes = v2c_response_bytes(7, 0, varbinds);
        let signals = match p.parse_v1_v2c_response(&bytes, 7) {
            ResponseVerdict::Ok(s) => s,
            _ => panic!("expected Ok verdict"),
        };
        assert_eq!(signals.len(), 2);
        assert!(!signals.iter().any(|s| matches!(s, Signal::SnmpSysName(_))));
    }

    #[test]
    fn parse_response_returns_no_signals_on_auth_error() {
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let bytes = v2c_response_bytes(
            7,
            snmp_v2::Pdu::ERROR_STATUS_AUTHORIZATION_ERROR,
            v2c_full_varbinds(),
        );
        match p.parse_v1_v2c_response(&bytes, 7) {
            ResponseVerdict::Ok(signals) => assert!(signals.is_empty()),
            _ => panic!("expected Ok verdict with empty signals"),
        }
    }

    #[test]
    fn parse_response_skips_wrong_type_varbind() {
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
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
        let signals = match p.parse_v1_v2c_response(&bytes, 9) {
            ResponseVerdict::Ok(s) => s,
            _ => panic!("expected Ok verdict"),
        };
        assert_eq!(signals.len(), 1);
        assert!(signals.contains(&Signal::SnmpSysName("switch-42".into())));
    }

    #[test]
    fn parse_response_rejects_mismatched_request_id() {
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let bytes = v2c_response_bytes(1, 0, v2c_full_varbinds());
        assert!(matches!(
            p.parse_v1_v2c_response(&bytes, 2),
            ResponseVerdict::MismatchedRequestId
        ));
    }

    #[test]
    fn parse_response_rejects_non_response_pdu() {
        let p = SnmpProber::new(
            vec![161],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
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
            p.parse_v1_v2c_response(&bytes, 7),
            ResponseVerdict::UnexpectedPdu
        ));
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
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
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
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V1,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
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
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let outcome: ProbeOutcome = prober
            .probe(&target, &ctx_with_timeout(2_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
        let _ = ProbeKind::Snmp;
    }

    fn ctx_with_retries(ms: u64, retries: u32) -> ProbeCtx {
        ProbeCtx::new(Duration::from_millis(ms), retries)
    }

    async fn spawn_v2c_agent_dropping(drop_first: usize) -> (u16, Arc<AtomicUsize>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        let received = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&received);
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_LEN];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let count = seen.fetch_add(1, Ordering::SeqCst) + 1;
                if count <= drop_first {
                    continue;
                }
                if let Some(resp) = mirror_v2c_response(&buf[..n]) {
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });
        (port, received)
    }

    #[tokio::test]
    async fn snmp_v2c_retransmit_recovers_when_first_packets_are_dropped() {
        let (port, _received) = spawn_v2c_agent_dropping(2).await;
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(900, 2))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
    }

    #[tokio::test]
    async fn snmp_v2c_without_retries_reports_absent_when_first_packet_dropped() {
        let (port, _received) = spawn_v2c_agent_dropping(1).await;
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(300, 0))
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.fault.is_none());
    }

    #[tokio::test]
    async fn snmp_v2c_retries_u32_max_is_bounded_and_does_not_panic() {
        let (port, received) = spawn_v2c_agent_dropping(usize::MAX).await;
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let start = std::time::Instant::now();
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(2, u32::MAX))
            .await
            .expect("u32::MAX retries must not panic");
        let elapsed = start.elapsed();
        assert!(!outcome.reachable);
        assert!(
            elapsed < Duration::from_millis(500),
            "u32::MAX retries must stay bounded near the timeout: {elapsed:?}"
        );
        assert!(
            received.load(Ordering::SeqCst) < 100,
            "the per-attempt floor and deadline break bound the send count: {}",
            received.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn snmp_v2c_exhausted_retries_is_absence_not_fault() {
        let (port, received) = spawn_v2c_agent_dropping(usize::MAX).await;
        let prober = SnmpProber::new(
            vec![port],
            SnmpVersion::V2c,
            "public".into(),
            UsmCredentials::default(),
        )
        .expect("valid");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(300, 2))
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.fault.is_none());
        assert_eq!(
            received.load(Ordering::SeqCst),
            3,
            "retries=2 sends the first datagram plus two retransmits"
        );
    }
}
