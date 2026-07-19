use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::{Integer, OctetString};
use rasn_snmp::{v2 as snmp_v2, v3};
use tokio::net::UdpSocket;

use crate::model::ProbeCtx;

use super::crypto::{
    ct_eq, decrypt_scoped_pdu, derive_priv_key, encrypt_scoped_pdu, hmac_truncated, localize_key,
};
use super::request::{snmp_io_error, RequestPdu, SnmpError, SnmpResponse};
use super::usm::{ResolvedAuth, ResolvedPriv, SecurityLevel, UsmCredentials};
use super::v1_v2c::{new_request_id, normalize_v2_varbind, unspecified_v2_varbinds};
use super::{bind_socket, PortOutcome, SnmpProber, RECV_BUF_LEN};

const MSG_ID_LIMIT: i64 = 0x7fff_ffff;
const MAX_SIZE_DEFAULT: i64 = 65_507;
const USM_SECURITY_MODEL: i64 = 3;
const REPORTABLE_FLAG: u8 = 0b100;
const SNMP_V3_VERSION: i64 = 3;

/// USM report OIDs that signal specific counter conditions per RFC 3414 §3.1.2.
const OID_STATS_UNKNOWN_ENGINE_IDS: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0];
const OID_STATS_NOT_IN_TIME_WINDOW: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0];

static MSG_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
static SALT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_msg_id() -> i32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = MSG_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = (nanos ^ seq) as i64 & MSG_ID_LIMIT;
    if mixed == 0 {
        1
    } else {
        mixed as i32
    }
}

fn next_salt() -> [u8; 8] {
    let seq = SALT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    (seq ^ nanos).to_be_bytes()
}

/// Snapshot of the authoritative engine's state for a scan-scoped exchange.
#[derive(Debug, Clone)]
pub(super) struct EngineSnapshot {
    pub engine_id: Vec<u8>,
    pub engine_boots: u32,
    pub engine_time: u32,
}

/// A v3 session that has completed engine discovery and key derivation. The engine snapshot is
/// held behind a mutex so a `notInTimeWindow` correction persists across requests in a walk.
pub(crate) struct V3Session {
    username: String,
    security_level: SecurityLevel,
    auth: ResolvedAuth,
    privacy: ResolvedPriv,
    auth_key: Vec<u8>,
    priv_key: Vec<u8>,
    engine: Mutex<EngineSnapshot>,
}

pub(super) async fn discover_and_derive(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    credentials: &UsmCredentials,
    ctx: &ProbeCtx,
    deadline: tokio::time::Instant,
) -> Result<V3Session, SnmpError> {
    let auth = credentials.auth.resolve();
    let privacy = credentials.privacy.resolve();
    let security_level = super::usm::derive_security_level(&auth, &privacy)
        .map_err(|msg| SnmpError::Other(msg.to_string()))?;
    let engine = discover_engine(socket, target_addr, &credentials.username, ctx, deadline).await?;
    let (auth_key, priv_key) = derive_keys(&engine, &auth, &privacy);
    Ok(V3Session {
        username: credentials.username.clone(),
        security_level,
        auth,
        privacy,
        auth_key,
        priv_key,
        engine: Mutex::new(engine),
    })
}

pub(super) async fn authenticated_exchange(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    state: &V3Session,
    pdu: &RequestPdu,
    ctx: &ProbeCtx,
) -> Result<SnmpResponse, SnmpError> {
    let deadline = tokio::time::Instant::now() + ctx.timeout;
    let mut retried_time_window = false;
    loop {
        let engine = state.engine.lock().expect("v3 engine mutex").clone();
        match one_authenticated_exchange(socket, target_addr, state, &engine, pdu, deadline).await {
            AuthExchange::Response(resp) => return Ok(resp),
            // The engine answered but the fingerprint is unusable (auth/report/bad digest): the
            // device is reachable — the caller keeps it with no data, not a fault.
            AuthExchange::Empty | AuthExchange::Report => {
                return Ok(SnmpResponse {
                    error_status: 0,
                    var_binds: Vec::new(),
                })
            }
            AuthExchange::NotInTimeWindow(new_engine) if !retried_time_window => {
                retried_time_window = true;
                *state.engine.lock().expect("v3 engine mutex") = new_engine;
                continue;
            }
            AuthExchange::NotInTimeWindow(_) => {
                return Ok(SnmpResponse {
                    error_status: 0,
                    var_binds: Vec::new(),
                })
            }
            AuthExchange::Absent => return Err(SnmpError::Absent),
            AuthExchange::Decode => return Err(SnmpError::Decode),
            AuthExchange::Other(msg) => return Err(SnmpError::Other(msg)),
        }
    }
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
    let overall_deadline = tokio::time::Instant::now() + ctx.timeout;
    let session = match super::request::SnmpSession::establish_v3(
        socket,
        target_addr,
        prober.credentials(),
        ctx,
        overall_deadline,
    )
    .await
    {
        Ok(s) => s,
        Err(SnmpError::Absent) => return PortOutcome::Timeout,
        Err(SnmpError::Decode) => return PortOutcome::DecodeFailed,
        Err(SnmpError::Fault(kind, msg)) => return PortOutcome::Fault(kind, msg),
        Err(SnmpError::Other(msg)) => return PortOutcome::Other(msg),
    };

    let mut req_ctx = ctx.clone();
    req_ctx.timeout = overall_deadline.saturating_duration_since(tokio::time::Instant::now());
    let get = RequestPdu::Get(prober.oids().into_iter().cloned().collect());
    match super::request::snmp_request(&session, &get, &req_ctx).await {
        // Discovery already proved the engine answered, so silence on the fetch keeps the device.
        Ok(resp) if resp.error_status == 0 => PortOutcome::Reached(
            super::v1_v2c::map_varbinds_to_signals(prober, &resp.var_binds),
        ),
        Ok(_) | Err(SnmpError::Absent) => PortOutcome::Reached(Vec::new()),
        Err(SnmpError::Decode) => PortOutcome::DecodeFailed,
        Err(SnmpError::Fault(_, msg)) | Err(SnmpError::Other(msg)) => PortOutcome::Other(msg),
    }
}

fn derive_keys(
    engine: &EngineSnapshot,
    auth: &ResolvedAuth,
    privacy: &ResolvedPriv,
) -> (Vec<u8>, Vec<u8>) {
    let auth_key = match auth {
        ResolvedAuth::None => Vec::new(),
        ResolvedAuth::Some { algo, password } => localize_key(password, &engine.engine_id, *algo),
    };
    let priv_key = match (auth, privacy) {
        (ResolvedAuth::None, _) | (_, ResolvedPriv::None) => Vec::new(),
        (
            ResolvedAuth::Some {
                algo: auth_algo,
                password: _,
            },
            ResolvedPriv::Some {
                algo: priv_algo,
                password: priv_pw,
            },
        ) => derive_priv_key(
            &auth_key,
            priv_pw,
            &engine.engine_id,
            *auth_algo,
            *priv_algo,
        ),
    };
    (auth_key, priv_key)
}

async fn discover_engine(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    username: &str,
    ctx: &ProbeCtx,
    overall_deadline: tokio::time::Instant,
) -> Result<EngineSnapshot, SnmpError> {
    let msg_id = next_msg_id();
    let scoped_pdu = v3::ScopedPdu {
        engine_id: OctetString::from_static(&[]),
        name: OctetString::from_static(&[]),
        data: snmp_v2::Pdus::GetRequest(snmp_v2::GetRequest(snmp_v2::Pdu {
            request_id: new_request_id(target_addr.port()),
            error_status: 0,
            error_index: 0,
            variable_bindings: Vec::new(),
        })),
    };
    let usm_params = v3::USMSecurityParameters {
        authoritative_engine_id: OctetString::from_static(&[]),
        authoritative_engine_boots: Integer::from(0),
        authoritative_engine_time: Integer::from(0),
        user_name: OctetString::from_slice(username.as_bytes()),
        authentication_parameters: OctetString::from_static(&[]),
        privacy_parameters: OctetString::from_static(&[]),
    };
    let msg =
        build_message(msg_id, REPORTABLE_FLAG, usm_params, scoped_pdu).map_err(SnmpError::Other)?;
    let payload = rasn::ber::encode(&msg)
        .map_err(|e| SnmpError::Other(format!("snmp v3 discovery encode failed: {e}")))?;

    let mut buf = vec![0u8; RECV_BUF_LEN];
    // Split the timeout across attempts so a dropped discovery packet is retransmitted inside the same total per-probe deadline.
    let per_attempt = crate::prober::per_attempt_timeout(ctx.timeout, ctx.retries);
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
                    let reply: v3::Message = match rasn::ber::decode(&buf[..n]) {
                        Ok(m) => m,
                        Err(_) => return Err(SnmpError::Decode),
                    };
                    let params: v3::USMSecurityParameters =
                        match reply.decode_security_parameters(rasn::Codec::Ber) {
                            Ok(p) => p,
                            Err(_) => return Err(SnmpError::Decode),
                        };
                    let engine_id: Vec<u8> = params.authoritative_engine_id.to_vec();
                    if engine_id.is_empty() {
                        return Err(SnmpError::Other(
                            "snmp v3 discovery response missing engine id".to_string(),
                        ));
                    }
                    let boots = integer_to_u32(&params.authoritative_engine_boots);
                    let time = integer_to_u32(&params.authoritative_engine_time);
                    return Ok(EngineSnapshot {
                        engine_id,
                        engine_boots: boots,
                        engine_time: time,
                    });
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

fn integer_to_u32(v: &Integer) -> u32 {
    u32::try_from(v).unwrap_or_else(|_| i64::try_from(v).unwrap_or(0) as u32)
}

fn build_message(
    msg_id: i32,
    flags: u8,
    usm_params: v3::USMSecurityParameters,
    scoped_pdu: v3::ScopedPdu,
) -> Result<v3::Message, String> {
    let mut msg = v3::Message {
        version: Integer::from(SNMP_V3_VERSION),
        global_data: v3::HeaderData {
            message_id: Integer::from(msg_id),
            max_size: Integer::from(MAX_SIZE_DEFAULT),
            flags: OctetString::from_slice(&[flags]),
            security_model: Integer::from(USM_SECURITY_MODEL),
        },
        security_parameters: OctetString::from_static(&[]),
        scoped_data: v3::ScopedPduData::CleartextPdu(scoped_pdu),
    };
    msg.encode_security_parameters(rasn::Codec::Ber, &usm_params)
        .map_err(|e| format!("snmp v3 security parameters encode failed: {e}"))?;
    Ok(msg)
}

enum AuthExchange {
    Response(SnmpResponse),
    /// The engine answered but the fingerprint is unusable (auth fail, bad response digest, or a
    /// non-response PDU): reachable, no data.
    Empty,
    Report,
    NotInTimeWindow(EngineSnapshot),
    Absent,
    Decode,
    Other(String),
}

enum ReportKind {
    NotInTimeWindow(EngineSnapshot),
    Other,
}

async fn one_authenticated_exchange(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    state: &V3Session,
    engine: &EngineSnapshot,
    pdu: &RequestPdu,
    deadline: tokio::time::Instant,
) -> AuthExchange {
    let msg_id = next_msg_id();
    let request_id = new_request_id(target_addr.port());
    let security_level = state.security_level;
    let auth = &state.auth;
    let auth_key = &state.auth_key;
    let privacy = &state.privacy;
    let priv_key = &state.priv_key;
    let username = state.username.as_str();

    let scoped_pdu = build_scoped_pdu(engine, pdu, request_id);
    let scoped_plaintext = match rasn::ber::encode(&scoped_pdu) {
        Ok(b) => b,
        Err(e) => return AuthExchange::Other(format!("snmp v3 scoped encode failed: {e}")),
    };

    let (scoped_data, privacy_parameters) = match (security_level, privacy) {
        (SecurityLevel::AuthPriv, ResolvedPriv::Some { algo, .. }) => {
            let salt = next_salt();
            match encrypt_scoped_pdu(
                *algo,
                priv_key,
                engine.engine_boots,
                engine.engine_time,
                salt,
                &scoped_plaintext,
            ) {
                Ok(enc) => (
                    v3::ScopedPduData::EncryptedPdu(OctetString::from(enc.ciphertext)),
                    enc.privacy_parameters,
                ),
                Err(e) => return AuthExchange::Other(format!("snmp v3 encrypt failed: {e}")),
            }
        }
        _ => (v3::ScopedPduData::CleartextPdu(scoped_pdu), Vec::new()),
    };

    let flags = REPORTABLE_FLAG | security_level.flag_bits();
    let auth_placeholder_len = match (security_level, auth) {
        (SecurityLevel::NoAuthNoPriv, _) => 0,
        (_, ResolvedAuth::Some { algo, .. }) => algo.hmac_trunc_len(),
        _ => 0,
    };
    let placeholder_auth = vec![0u8; auth_placeholder_len];
    let usm_params = v3::USMSecurityParameters {
        authoritative_engine_id: OctetString::from_slice(&engine.engine_id),
        authoritative_engine_boots: Integer::from(engine.engine_boots),
        authoritative_engine_time: Integer::from(engine.engine_time),
        user_name: OctetString::from_slice(username.as_bytes()),
        authentication_parameters: OctetString::from(placeholder_auth.clone()),
        privacy_parameters: OctetString::from(privacy_parameters),
    };

    let mut msg = v3::Message {
        version: Integer::from(SNMP_V3_VERSION),
        global_data: v3::HeaderData {
            message_id: Integer::from(msg_id),
            max_size: Integer::from(MAX_SIZE_DEFAULT),
            flags: OctetString::from_slice(&[flags]),
            security_model: Integer::from(USM_SECURITY_MODEL),
        },
        security_parameters: OctetString::from_static(&[]),
        scoped_data,
    };
    if let Err(e) = msg.encode_security_parameters(rasn::Codec::Ber, &usm_params) {
        return AuthExchange::Other(format!("snmp v3 params encode failed: {e}"));
    }

    let payload = match (security_level, auth) {
        (SecurityLevel::NoAuthNoPriv, _) => match rasn::ber::encode(&msg) {
            Ok(b) => b,
            Err(e) => return AuthExchange::Other(format!("snmp v3 encode failed: {e}")),
        },
        (_, ResolvedAuth::Some { algo, .. }) => {
            let encoded_zeroed = match rasn::ber::encode(&msg) {
                Ok(b) => b,
                Err(e) => return AuthExchange::Other(format!("snmp v3 encode failed: {e}")),
            };
            let hmac = hmac_truncated(*algo, auth_key, &encoded_zeroed);
            let usm_params_real = v3::USMSecurityParameters {
                authoritative_engine_id: OctetString::from_slice(&engine.engine_id),
                authoritative_engine_boots: Integer::from(engine.engine_boots),
                authoritative_engine_time: Integer::from(engine.engine_time),
                user_name: OctetString::from_slice(username.as_bytes()),
                authentication_parameters: OctetString::from(hmac),
                privacy_parameters: usm_params.privacy_parameters.clone(),
            };
            if let Err(e) = msg.encode_security_parameters(rasn::Codec::Ber, &usm_params_real) {
                return AuthExchange::Other(format!("snmp v3 params re-encode failed: {e}"));
            }
            match rasn::ber::encode(&msg) {
                Ok(b) => b,
                Err(e) => {
                    return AuthExchange::Other(format!("snmp v3 encode with auth failed: {e}"))
                }
            }
        }
        _ => {
            return AuthExchange::Other(
                "snmp v3 invariant broken: authPriv without auth algorithm".to_string(),
            )
        }
    };

    if let Err(e) = socket.send_to(&payload, target_addr).await {
        return io_error_to_exchange(&e);
    }

    let mut buf = vec![0u8; RECV_BUF_LEN];
    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, peer))) => {
                if peer.ip() != target_addr.ip() {
                    continue;
                }
                let reply: v3::Message = match rasn::ber::decode(&buf[..n]) {
                    Ok(m) => m,
                    Err(_) => return AuthExchange::Decode,
                };

                let params: v3::USMSecurityParameters =
                    match reply.decode_security_parameters(rasn::Codec::Ber) {
                        Ok(p) => p,
                        Err(_) => return AuthExchange::Decode,
                    };

                let response_engine = EngineSnapshot {
                    engine_id: params.authoritative_engine_id.to_vec(),
                    engine_boots: integer_to_u32(&params.authoritative_engine_boots),
                    engine_time: integer_to_u32(&params.authoritative_engine_time),
                };

                let response_flags = reply.global_data.flags.first().copied().unwrap_or(0);
                let response_is_authenticated = response_flags & 0b01 != 0;

                if response_is_authenticated
                    && !verify_response_auth(&reply, auth, auth_key, &params)
                {
                    return AuthExchange::Empty;
                }

                let scoped = match extract_scoped_pdu(
                    &reply,
                    privacy,
                    priv_key,
                    &response_engine,
                    &params,
                ) {
                    Ok(s) => s,
                    Err(_) => return AuthExchange::Decode,
                };

                if scoped_pdu_is_report(&scoped) {
                    return match classify_report(&scoped, response_engine) {
                        ReportKind::NotInTimeWindow(e) => AuthExchange::NotInTimeWindow(e),
                        ReportKind::Other => AuthExchange::Report,
                    };
                }

                if !response_is_authenticated && matches!(auth, ResolvedAuth::Some { .. }) {
                    return AuthExchange::Empty;
                }

                return match extract_response(&scoped, request_id) {
                    Some(resp) => AuthExchange::Response(resp),
                    None => AuthExchange::Empty,
                };
            }
            Ok(Err(e)) => return io_error_to_exchange(&e),
            Err(_) => return AuthExchange::Absent,
        }
    }
}

fn io_error_to_exchange(err: &std::io::Error) -> AuthExchange {
    match snmp_io_error(err) {
        SnmpError::Absent | SnmpError::Decode => AuthExchange::Absent,
        SnmpError::Fault(_, msg) | SnmpError::Other(msg) => AuthExchange::Other(msg),
    }
}

fn build_scoped_pdu(engine: &EngineSnapshot, pdu: &RequestPdu, request_id: i32) -> v3::ScopedPdu {
    let simple_pdu = |names: &[rasn::types::ObjectIdentifier]| snmp_v2::Pdu {
        request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: unspecified_v2_varbinds(names),
    };
    let data = match pdu {
        RequestPdu::Get(names) => snmp_v2::Pdus::GetRequest(snmp_v2::GetRequest(simple_pdu(names))),
        #[cfg(feature = "lldp")]
        RequestPdu::GetNext(names) => {
            snmp_v2::Pdus::GetNextRequest(snmp_v2::GetNextRequest(simple_pdu(names)))
        }
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
    v3::ScopedPdu {
        engine_id: OctetString::from_slice(&engine.engine_id),
        name: OctetString::from_static(&[]),
        data,
    }
}

fn scoped_pdu_is_report(scoped: &v3::ScopedPdu) -> bool {
    matches!(scoped.data, snmp_v2::Pdus::Report(_))
}

fn verify_response_auth(
    reply: &v3::Message,
    auth: &ResolvedAuth,
    auth_key: &[u8],
    params: &v3::USMSecurityParameters,
) -> bool {
    let algo = match auth {
        ResolvedAuth::None => return true,
        ResolvedAuth::Some { algo, .. } => *algo,
    };
    let received_hmac = params.authentication_parameters.to_vec();
    let expected_len = algo.hmac_trunc_len();
    if received_hmac.len() != expected_len {
        return false;
    }
    let placeholder = vec![0u8; expected_len];
    let mut msg_for_verify = reply.clone();
    let params_zeroed = v3::USMSecurityParameters {
        authoritative_engine_id: params.authoritative_engine_id.clone(),
        authoritative_engine_boots: params.authoritative_engine_boots.clone(),
        authoritative_engine_time: params.authoritative_engine_time.clone(),
        user_name: params.user_name.clone(),
        authentication_parameters: OctetString::from(placeholder),
        privacy_parameters: params.privacy_parameters.clone(),
    };
    if msg_for_verify
        .encode_security_parameters(rasn::Codec::Ber, &params_zeroed)
        .is_err()
    {
        return false;
    }
    let encoded = match rasn::ber::encode(&msg_for_verify) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let computed = hmac_truncated(algo, auth_key, &encoded);
    ct_eq(&computed, &received_hmac)
}

fn extract_scoped_pdu(
    reply: &v3::Message,
    privacy: &ResolvedPriv,
    priv_key: &[u8],
    response_engine: &EngineSnapshot,
    params: &v3::USMSecurityParameters,
) -> Result<v3::ScopedPdu, ()> {
    match &reply.scoped_data {
        v3::ScopedPduData::CleartextPdu(pdu) => Ok(pdu.clone()),
        v3::ScopedPduData::EncryptedPdu(bytes) => {
            let algo = match privacy {
                ResolvedPriv::Some { algo, .. } => *algo,
                ResolvedPriv::None => return Err(()),
            };
            let plaintext = decrypt_scoped_pdu(
                algo,
                priv_key,
                response_engine.engine_boots,
                response_engine.engine_time,
                &params.privacy_parameters,
                bytes,
            )
            .map_err(|_| ())?;
            rasn::ber::decode::<v3::ScopedPdu>(&plaintext).map_err(|_| ())
        }
    }
}

fn classify_report(scoped: &v3::ScopedPdu, engine: EngineSnapshot) -> ReportKind {
    let pdu = match &scoped.data {
        snmp_v2::Pdus::Report(snmp_v2::Report(pdu)) => pdu,
        _ => return ReportKind::Other,
    };
    for vb in &pdu.variable_bindings {
        let arcs: &[u32] = vb.name.as_ref();
        if arcs == OID_STATS_UNKNOWN_ENGINE_IDS {
            return ReportKind::Other;
        }
        if arcs == OID_STATS_NOT_IN_TIME_WINDOW {
            return ReportKind::NotInTimeWindow(engine);
        }
    }
    ReportKind::Other
}

fn extract_response(scoped: &v3::ScopedPdu, expected_request_id: i32) -> Option<SnmpResponse> {
    let pdu = match &scoped.data {
        snmp_v2::Pdus::Response(snmp_v2::Response(pdu)) => pdu,
        _ => return None,
    };
    if pdu.request_id != expected_request_id {
        return None;
    }
    let var_binds = pdu
        .variable_bindings
        .iter()
        .cloned()
        .map(normalize_v2_varbind)
        .collect();
    Some(SnmpResponse {
        error_status: pdu.error_status,
        var_binds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProbeCtx, ResolvedTarget, Signal, Target};
    use crate::prober::redacted::Password;
    use crate::prober::snmp::usm::{UsmAuth, UsmCredentials, UsmPrivacy};
    use crate::prober::snmp::SnmpVersion;
    use crate::prober::Prober;
    use rasn::types::ObjectIdentifier;
    use rasn_smi::v2 as smi_v2;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

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

    fn full_varbinds() -> Vec<snmp_v2::VarBind> {
        vec![
            snmp_v2::VarBind {
                name: oid(super::super::v1_v2c::OID_SYS_DESCR),
                value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                    smi_v2::SimpleSyntax::String(OctetString::from_slice(b"v3-router 1.0")),
                )),
            },
            snmp_v2::VarBind {
                name: oid(super::super::v1_v2c::OID_SYS_OBJECT_ID),
                value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                    smi_v2::SimpleSyntax::ObjectId(oid(&[1, 3, 6, 1, 4, 1, 8072, 3, 2, 10])),
                )),
            },
            snmp_v2::VarBind {
                name: oid(super::super::v1_v2c::OID_SYS_NAME),
                value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                    smi_v2::SimpleSyntax::String(OctetString::from_slice(b"v3-router")),
                )),
            },
        ]
    }

    #[derive(Clone)]
    struct MockV3Agent {
        engine_id: Vec<u8>,
        engine_boots: u32,
        engine_time: u32,
        username: String,
        auth: Option<super::super::usm::AuthAlgo>,
        auth_password: String,
        privacy: Option<super::super::usm::PrivAlgo>,
        privacy_password: String,
        behavior: MockBehavior,
        state: Arc<Mutex<MockState>>,
    }

    #[derive(Clone, PartialEq, Eq)]
    enum MockBehavior {
        Normal,
        AlwaysNotInTimeWindow,
        NotInTimeWindowThenNormal { correct_time: u32 },
        WrongDigestReport,
        CorruptResponseHmac,
        SilentAfterDiscovery,
    }

    #[derive(Default)]
    struct MockState {
        discovery_seen: bool,
        auth_attempts: u32,
    }

    impl MockV3Agent {
        fn new(username: &str) -> Self {
            Self {
                engine_id: b"\x80\x00\x1f\x88\x80\x12\x34".to_vec(),
                engine_boots: 5,
                engine_time: 4242,
                username: username.to_string(),
                auth: None,
                auth_password: String::new(),
                privacy: None,
                privacy_password: String::new(),
                behavior: MockBehavior::Normal,
                state: Arc::new(Mutex::new(MockState::default())),
            }
        }

        fn with_auth(mut self, algo: super::super::usm::AuthAlgo, password: &str) -> Self {
            self.auth = Some(algo);
            self.auth_password = password.to_string();
            self
        }

        fn with_privacy(mut self, algo: super::super::usm::PrivAlgo, password: &str) -> Self {
            self.privacy = Some(algo);
            self.privacy_password = password.to_string();
            self
        }

        fn with_behavior(mut self, behavior: MockBehavior) -> Self {
            self.behavior = behavior;
            self
        }

        fn auth_key(&self) -> Vec<u8> {
            match self.auth {
                Some(algo) => localize_key(&self.auth_password, &self.engine_id, algo),
                None => Vec::new(),
            }
        }

        fn priv_key(&self) -> Vec<u8> {
            match (self.auth, self.privacy) {
                (Some(auth_algo), Some(priv_algo)) => {
                    let auth_key = self.auth_key();
                    derive_priv_key(
                        &auth_key,
                        &self.privacy_password,
                        &self.engine_id,
                        auth_algo,
                        priv_algo,
                    )
                }
                _ => Vec::new(),
            }
        }

        fn respond(&self, req: &[u8]) -> Option<Vec<u8>> {
            let msg: v3::Message = rasn::ber::decode(req).ok()?;
            let params: v3::USMSecurityParameters =
                msg.decode_security_parameters(rasn::Codec::Ber).ok()?;
            let is_discovery = params.authoritative_engine_id.is_empty();
            let mut state = self.state.lock().expect("mock lock");
            if is_discovery {
                state.discovery_seen = true;
                drop(state);
                return Some(self.discovery_response(&msg, &params));
            }
            state.auth_attempts += 1;
            let attempt = state.auth_attempts;
            drop(state);
            if !self.verify_request_auth(&msg, &params) {
                return Some(self.wrong_digest_report_response(&msg, &params));
            }
            match &self.behavior {
                MockBehavior::AlwaysNotInTimeWindow => {
                    Some(self.not_in_time_window_response(&msg, &params))
                }
                MockBehavior::NotInTimeWindowThenNormal { correct_time } if attempt == 1 => {
                    Some(self.not_in_time_window_response_with_time(&msg, &params, *correct_time))
                }
                MockBehavior::WrongDigestReport => {
                    Some(self.wrong_digest_report_response(&msg, &params))
                }
                MockBehavior::CorruptResponseHmac => {
                    let mut resp = self.build_signal_response(&msg, &params)?;
                    if let Some(last) = resp.last_mut() {
                        *last ^= 0xff;
                    }
                    Some(resp)
                }
                MockBehavior::SilentAfterDiscovery => None,
                _ => self.build_signal_response(&msg, &params),
            }
        }

        fn verify_request_auth(
            &self,
            msg: &v3::Message,
            params: &v3::USMSecurityParameters,
        ) -> bool {
            let flags = msg.global_data.flags.first().copied().unwrap_or(0);
            let auth_flag = flags & 0b01 != 0;
            if !auth_flag {
                return true;
            }
            let algo = match self.auth {
                Some(a) => a,
                None => return false,
            };
            let received = params.authentication_parameters.to_vec();
            if received.len() != algo.hmac_trunc_len() {
                return false;
            }
            let placeholder = vec![0u8; algo.hmac_trunc_len()];
            let params_zeroed = v3::USMSecurityParameters {
                authoritative_engine_id: params.authoritative_engine_id.clone(),
                authoritative_engine_boots: params.authoritative_engine_boots.clone(),
                authoritative_engine_time: params.authoritative_engine_time.clone(),
                user_name: params.user_name.clone(),
                authentication_parameters: OctetString::from(placeholder),
                privacy_parameters: params.privacy_parameters.clone(),
            };
            let mut msg_zeroed = msg.clone();
            if msg_zeroed
                .encode_security_parameters(rasn::Codec::Ber, &params_zeroed)
                .is_err()
            {
                return false;
            }
            let encoded = match rasn::ber::encode(&msg_zeroed) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let computed = hmac_truncated(algo, &self.auth_key(), &encoded);
            ct_eq(&computed, &received)
        }

        fn discovery_response(
            &self,
            req_msg: &v3::Message,
            _params: &v3::USMSecurityParameters,
        ) -> Vec<u8> {
            let report_pdu = snmp_v2::Pdus::Report(snmp_v2::Report(snmp_v2::Pdu {
                request_id: 0,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![snmp_v2::VarBind {
                    name: oid(OID_STATS_UNKNOWN_ENGINE_IDS),
                    value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::ApplicationWide(
                        smi_v2::ApplicationSyntax::Counter(rasn_smi::v1::Counter(1)),
                    )),
                }],
            }));
            let scoped = v3::ScopedPdu {
                engine_id: OctetString::from_slice(&self.engine_id),
                name: OctetString::from_static(&[]),
                data: report_pdu,
            };
            let usm_params = v3::USMSecurityParameters {
                authoritative_engine_id: OctetString::from_slice(&self.engine_id),
                authoritative_engine_boots: Integer::from(self.engine_boots),
                authoritative_engine_time: Integer::from(self.engine_time),
                user_name: OctetString::from_static(&[]),
                authentication_parameters: OctetString::from_static(&[]),
                privacy_parameters: OctetString::from_static(&[]),
            };
            let mut msg = v3::Message {
                version: Integer::from(SNMP_V3_VERSION),
                global_data: v3::HeaderData {
                    message_id: req_msg.global_data.message_id.clone(),
                    max_size: Integer::from(MAX_SIZE_DEFAULT),
                    flags: OctetString::from_slice(&[0]),
                    security_model: Integer::from(USM_SECURITY_MODEL),
                },
                security_parameters: OctetString::from_static(&[]),
                scoped_data: v3::ScopedPduData::CleartextPdu(scoped),
            };
            msg.encode_security_parameters(rasn::Codec::Ber, &usm_params)
                .unwrap_or_else(|e| panic!("encode discovery params: {e}"));
            rasn::ber::encode(&msg).expect("encode discovery response")
        }

        fn not_in_time_window_response(
            &self,
            req: &v3::Message,
            params: &v3::USMSecurityParameters,
        ) -> Vec<u8> {
            self.not_in_time_window_response_with_time(req, params, self.engine_time)
        }

        fn not_in_time_window_response_with_time(
            &self,
            req: &v3::Message,
            _params: &v3::USMSecurityParameters,
            time: u32,
        ) -> Vec<u8> {
            let report_pdu = snmp_v2::Pdus::Report(snmp_v2::Report(snmp_v2::Pdu {
                request_id: 0,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![snmp_v2::VarBind {
                    name: oid(OID_STATS_NOT_IN_TIME_WINDOW),
                    value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::ApplicationWide(
                        smi_v2::ApplicationSyntax::Counter(rasn_smi::v1::Counter(1)),
                    )),
                }],
            }));
            let scoped = v3::ScopedPdu {
                engine_id: OctetString::from_slice(&self.engine_id),
                name: OctetString::from_static(&[]),
                data: report_pdu,
            };
            let usm_params = v3::USMSecurityParameters {
                authoritative_engine_id: OctetString::from_slice(&self.engine_id),
                authoritative_engine_boots: Integer::from(self.engine_boots),
                authoritative_engine_time: Integer::from(time),
                user_name: OctetString::from_slice(self.username.as_bytes()),
                authentication_parameters: OctetString::from_static(&[]),
                privacy_parameters: OctetString::from_static(&[]),
            };
            let mut msg = v3::Message {
                version: Integer::from(SNMP_V3_VERSION),
                global_data: v3::HeaderData {
                    message_id: req.global_data.message_id.clone(),
                    max_size: Integer::from(MAX_SIZE_DEFAULT),
                    flags: OctetString::from_slice(&[0]),
                    security_model: Integer::from(USM_SECURITY_MODEL),
                },
                security_parameters: OctetString::from_static(&[]),
                scoped_data: v3::ScopedPduData::CleartextPdu(scoped),
            };
            msg.encode_security_parameters(rasn::Codec::Ber, &usm_params)
                .unwrap_or_else(|e| panic!("encode report params: {e}"));
            rasn::ber::encode(&msg).expect("encode report response")
        }

        fn wrong_digest_report_response(
            &self,
            req: &v3::Message,
            _params: &v3::USMSecurityParameters,
        ) -> Vec<u8> {
            let oid_wrong_digest: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0];
            let report_pdu = snmp_v2::Pdus::Report(snmp_v2::Report(snmp_v2::Pdu {
                request_id: 0,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![snmp_v2::VarBind {
                    name: oid(oid_wrong_digest),
                    value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::ApplicationWide(
                        smi_v2::ApplicationSyntax::Counter(rasn_smi::v1::Counter(1)),
                    )),
                }],
            }));
            let scoped = v3::ScopedPdu {
                engine_id: OctetString::from_slice(&self.engine_id),
                name: OctetString::from_static(&[]),
                data: report_pdu,
            };
            let usm_params = v3::USMSecurityParameters {
                authoritative_engine_id: OctetString::from_slice(&self.engine_id),
                authoritative_engine_boots: Integer::from(self.engine_boots),
                authoritative_engine_time: Integer::from(self.engine_time),
                user_name: OctetString::from_slice(self.username.as_bytes()),
                authentication_parameters: OctetString::from_static(&[]),
                privacy_parameters: OctetString::from_static(&[]),
            };
            let mut msg = v3::Message {
                version: Integer::from(SNMP_V3_VERSION),
                global_data: v3::HeaderData {
                    message_id: req.global_data.message_id.clone(),
                    max_size: Integer::from(MAX_SIZE_DEFAULT),
                    flags: OctetString::from_slice(&[0]),
                    security_model: Integer::from(USM_SECURITY_MODEL),
                },
                security_parameters: OctetString::from_static(&[]),
                scoped_data: v3::ScopedPduData::CleartextPdu(scoped),
            };
            msg.encode_security_parameters(rasn::Codec::Ber, &usm_params)
                .unwrap_or_else(|e| panic!("encode report params: {e}"));
            rasn::ber::encode(&msg).expect("encode report response")
        }

        fn build_signal_response(
            &self,
            req: &v3::Message,
            _params: &v3::USMSecurityParameters,
        ) -> Option<Vec<u8>> {
            let scoped = self.decrypt_scoped(req)?;
            let request_id = match &scoped.data {
                snmp_v2::Pdus::GetRequest(snmp_v2::GetRequest(pdu)) => pdu.request_id,
                _ => return None,
            };

            let response_pdu = snmp_v2::Pdus::Response(snmp_v2::Response(snmp_v2::Pdu {
                request_id,
                error_status: 0,
                error_index: 0,
                variable_bindings: full_varbinds(),
            }));
            let response_scoped = v3::ScopedPdu {
                engine_id: OctetString::from_slice(&self.engine_id),
                name: OctetString::from_static(&[]),
                data: response_pdu,
            };
            let plaintext = rasn::ber::encode(&response_scoped).ok()?;

            let (scoped_data, privacy_params) = if let Some(algo) = self.privacy {
                let salt = [11u8; 8];
                let priv_key = self.priv_key();
                let enc = encrypt_scoped_pdu(
                    algo,
                    &priv_key,
                    self.engine_boots,
                    self.engine_time,
                    salt,
                    &plaintext,
                )
                .ok()?;
                (
                    v3::ScopedPduData::EncryptedPdu(OctetString::from(enc.ciphertext)),
                    enc.privacy_parameters,
                )
            } else {
                (v3::ScopedPduData::CleartextPdu(response_scoped), Vec::new())
            };

            let flags = self.flags_for_response();
            let placeholder_len = self.auth.map(|a| a.hmac_trunc_len()).unwrap_or(0);
            let usm_params = v3::USMSecurityParameters {
                authoritative_engine_id: OctetString::from_slice(&self.engine_id),
                authoritative_engine_boots: Integer::from(self.engine_boots),
                authoritative_engine_time: Integer::from(self.engine_time),
                user_name: OctetString::from_slice(self.username.as_bytes()),
                authentication_parameters: OctetString::from(vec![0u8; placeholder_len]),
                privacy_parameters: OctetString::from(privacy_params.clone()),
            };
            let mut msg = v3::Message {
                version: Integer::from(SNMP_V3_VERSION),
                global_data: v3::HeaderData {
                    message_id: req.global_data.message_id.clone(),
                    max_size: Integer::from(MAX_SIZE_DEFAULT),
                    flags: OctetString::from_slice(&[flags]),
                    security_model: Integer::from(USM_SECURITY_MODEL),
                },
                security_parameters: OctetString::from_static(&[]),
                scoped_data,
            };
            msg.encode_security_parameters(rasn::Codec::Ber, &usm_params)
                .ok()?;

            if let Some(algo) = self.auth {
                let encoded_zeroed = rasn::ber::encode(&msg).ok()?;
                let auth_key = self.auth_key();
                let hmac = hmac_truncated(algo, &auth_key, &encoded_zeroed);
                let usm_params_real = v3::USMSecurityParameters {
                    authoritative_engine_id: OctetString::from_slice(&self.engine_id),
                    authoritative_engine_boots: Integer::from(self.engine_boots),
                    authoritative_engine_time: Integer::from(self.engine_time),
                    user_name: OctetString::from_slice(self.username.as_bytes()),
                    authentication_parameters: OctetString::from(hmac),
                    privacy_parameters: OctetString::from(privacy_params.clone()),
                };
                msg.encode_security_parameters(rasn::Codec::Ber, &usm_params_real)
                    .ok()?;
            }

            rasn::ber::encode(&msg).ok()
        }

        fn flags_for_response(&self) -> u8 {
            match (self.auth.is_some(), self.privacy.is_some()) {
                (false, false) => 0,
                (true, false) => 0b01,
                (true, true) => 0b11,
                (false, true) => 0,
            }
        }

        fn decrypt_scoped(&self, req: &v3::Message) -> Option<v3::ScopedPdu> {
            let params: v3::USMSecurityParameters =
                req.decode_security_parameters(rasn::Codec::Ber).ok()?;
            match &req.scoped_data {
                v3::ScopedPduData::CleartextPdu(pdu) => Some(pdu.clone()),
                v3::ScopedPduData::EncryptedPdu(bytes) => {
                    let algo = self.privacy?;
                    let priv_key = self.priv_key();
                    let plaintext = decrypt_scoped_pdu(
                        algo,
                        &priv_key,
                        self.engine_boots,
                        self.engine_time,
                        &params.privacy_parameters,
                        bytes,
                    )
                    .ok()?;
                    rasn::ber::decode::<v3::ScopedPdu>(&plaintext).ok()
                }
            }
        }
    }

    async fn spawn_mock_v3(agent: MockV3Agent) -> std::io::Result<u16> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_LEN];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                if let Some(resp) = agent.respond(&buf[..n]) {
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });
        Ok(port)
    }

    async fn spawn_mock_v3_dropping(
        agent: MockV3Agent,
        drop_first: usize,
    ) -> std::io::Result<(u16, Arc<AtomicUsize>)> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
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
                if let Some(resp) = agent.respond(&buf[..n]) {
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });
        Ok((port, received))
    }

    fn ctx_with_retries(ms: u64, retries: u32) -> ProbeCtx {
        ProbeCtx::new(Duration::from_millis(ms), retries)
    }

    fn noauth_creds() -> UsmCredentials {
        UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::None,
            privacy: UsmPrivacy::None,
        }
    }

    #[tokio::test]
    async fn snmpv3_retransmit_recovers_when_discovery_packets_are_dropped() {
        let (port, _received) = spawn_mock_v3_dropping(MockV3Agent::new("probe"), 2)
            .await
            .expect("bind");
        let prober = SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), noauth_creds())
            .expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(1_500, 2))
            .await
            .expect("probe ok");
        assert!(
            outcome.reachable,
            "the third discovery attempt reaches the engine after two dropped datagrams"
        );
        assert_eq!(outcome.signals.len(), 3);
    }

    #[tokio::test]
    async fn snmpv3_without_retries_reports_absent_when_discovery_dropped() {
        let (port, _received) = spawn_mock_v3_dropping(MockV3Agent::new("probe"), 1)
            .await
            .expect("bind");
        let prober = SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), noauth_creds())
            .expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(300, 0))
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.fault.is_none());
    }

    #[tokio::test]
    async fn snmpv3_retries_u32_max_is_bounded_and_does_not_panic() {
        let (port, received) = spawn_mock_v3_dropping(MockV3Agent::new("probe"), usize::MAX)
            .await
            .expect("bind");
        let prober = SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), noauth_creds())
            .expect("valid v3");
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
    async fn snmpv3_exhausted_retries_is_absence_not_fault() {
        let (port, received) = spawn_mock_v3_dropping(MockV3Agent::new("probe"), usize::MAX)
            .await
            .expect("bind");
        let prober = SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), noauth_creds())
            .expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_retries(300, 2))
            .await
            .expect("probe ok");
        assert!(!outcome.reachable);
        assert!(outcome.fault.is_none());
        assert_eq!(
            received.load(Ordering::SeqCst),
            3,
            "retries=2 sends the first discovery datagram plus two retransmits"
        );
    }

    #[tokio::test]
    async fn snmpv3_noauthnopriv_captures_all_three_signals_end_to_end() {
        let agent = MockV3Agent::new("probe");
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::None,
            privacy: UsmPrivacy::None,
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysName(v) if v == "v3-router")));
    }

    #[tokio::test]
    async fn snmpv3_authnopriv_captures_all_three_signals_end_to_end() {
        let agent =
            MockV3Agent::new("probe").with_auth(super::super::usm::AuthAlgo::Sha1, "authpassword");
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha1 {
                password: Password("authpassword".into()),
            },
            privacy: UsmPrivacy::None,
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
    }

    #[tokio::test]
    async fn snmpv3_authpriv_captures_all_three_signals_end_to_end() {
        let agent = MockV3Agent::new("probe")
            .with_auth(super::super::usm::AuthAlgo::Sha256, "authpassword")
            .with_privacy(super::super::usm::PrivAlgo::Aes128, "privpassword");
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha256 {
                password: Password("authpassword".into()),
            },
            privacy: UsmPrivacy::Aes128 {
                password: Password("privpassword".into()),
            },
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
        assert!(outcome
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysDescr(v) if v == "v3-router 1.0")));
    }

    #[tokio::test]
    async fn snmpv3_authpriv_with_des_captures_signals() {
        let agent = MockV3Agent::new("probe")
            .with_auth(super::super::usm::AuthAlgo::Sha1, "authpassword")
            .with_privacy(super::super::usm::PrivAlgo::Des, "privpassword");
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha1 {
                password: Password("authpassword".into()),
            },
            privacy: UsmPrivacy::Des {
                password: Password("privpassword".into()),
            },
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
    }

    #[tokio::test]
    async fn snmpv3_handles_not_in_time_window_report_by_retrying_once() {
        let agent = MockV3Agent::new("probe")
            .with_auth(super::super::usm::AuthAlgo::Sha1, "authpassword")
            .with_behavior(MockBehavior::NotInTimeWindowThenNormal { correct_time: 4242 });
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha1 {
                password: Password("authpassword".into()),
            },
            privacy: UsmPrivacy::None,
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
    }

    #[tokio::test]
    async fn snmpv3_handles_persistent_not_in_time_window_by_reporting_reachable_no_signals() {
        let agent = MockV3Agent::new("probe")
            .with_auth(super::super::usm::AuthAlgo::Sha1, "authpassword")
            .with_behavior(MockBehavior::AlwaysNotInTimeWindow);
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha1 {
                password: Password("authpassword".into()),
            },
            privacy: UsmPrivacy::None,
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn snmpv3_handles_wrong_digest_report_gracefully() {
        let agent = MockV3Agent::new("probe")
            .with_auth(super::super::usm::AuthAlgo::Sha1, "authpassword")
            .with_behavior(MockBehavior::WrongDigestReport);
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha1 {
                password: Password("authpassword".into()),
            },
            privacy: UsmPrivacy::None,
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn snmpv3_agent_that_answers_discovery_then_goes_silent_is_reachable_without_signals() {
        let agent = MockV3Agent::new("probe").with_behavior(MockBehavior::SilentAfterDiscovery);
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::None,
            privacy: UsmPrivacy::None,
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(300))
            .await
            .expect("an engine that answered discovery is a device we found");
        assert!(
            outcome.reachable,
            "a v3 engine that completed discovery has provably answered"
        );
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn snmpv3_rejects_response_with_bad_hmac() {
        let agent = MockV3Agent::new("probe")
            .with_auth(super::super::usm::AuthAlgo::Sha1, "authpassword")
            .with_behavior(MockBehavior::CorruptResponseHmac);
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha1 {
                password: Password("authpassword".into()),
            },
            privacy: UsmPrivacy::None,
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn mockv3_agent_rejects_request_with_wrong_hmac() {
        let agent = MockV3Agent::new("probe")
            .with_auth(super::super::usm::AuthAlgo::Sha256, "authpassword");
        let agent_state = agent.state.clone();
        let mock_port = spawn_mock_v3(agent).await.expect("bind mock");

        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind proxy");
        let proxy_port = proxy_socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut down_buf = vec![0u8; RECV_BUF_LEN];
            let mut up_buf = vec![0u8; RECV_BUF_LEN];
            let mut auth_seen = false;
            let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
            let mock_addr: SocketAddr = format!("127.0.0.1:{mock_port}").parse().unwrap();
            let mut client_addr: Option<SocketAddr> = None;
            loop {
                tokio::select! {
                    Ok((n, peer)) = proxy_socket.recv_from(&mut down_buf) => {
                        client_addr = Some(peer);
                        let payload = if auth_seen {
                            down_buf[..n].to_vec()
                        } else {
                            let msg: v3::Message = match rasn::ber::decode(&down_buf[..n]) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let params: v3::USMSecurityParameters =
                                match msg.decode_security_parameters(rasn::Codec::Ber) {
                                    Ok(p) => p,
                                    Err(_) => continue,
                                };
                            if !params.authoritative_engine_id.is_empty() {
                                auth_seen = true;
                                let mut tampered = down_buf[..n].to_vec();
                                let hmac = params.authentication_parameters.to_vec();
                                if !hmac.is_empty() {
                                    if let Some(pos) = find_subslice(&tampered, &hmac) {
                                        tampered[pos] ^= 0xff;
                                    }
                                }
                                tampered
                            } else {
                                down_buf[..n].to_vec()
                            }
                        };
                        let _ = upstream.send_to(&payload, mock_addr).await;
                    }
                    Ok((n, _peer)) = upstream.recv_from(&mut up_buf) => {
                        if let Some(addr) = client_addr {
                            let _ = proxy_socket.send_to(&up_buf[..n], addr).await;
                        }
                    }
                }
            }
        });

        let creds = UsmCredentials {
            username: "probe".into(),
            auth: UsmAuth::Sha256 {
                password: Password("authpassword".into()),
            },
            privacy: UsmPrivacy::None,
        };
        let prober = SnmpProber::new(vec![proxy_port], SnmpVersion::V3, String::new(), creds)
            .expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert!(outcome.signals.is_empty());
        let final_state = agent_state.lock().expect("mock lock");
        assert!(final_state.auth_attempts >= 1);
    }

    fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || hay.len() < needle.len() {
            return None;
        }
        hay.windows(needle.len()).position(|w| w == needle)
    }

    async fn run_algo_round_trip(algo: super::super::usm::AuthAlgo, auth_variant: UsmAuth) {
        let password = "authpassword";
        let agent = MockV3Agent::new("probe").with_auth(algo, password);
        let port = spawn_mock_v3(agent).await.expect("bind");
        let creds = UsmCredentials {
            username: "probe".into(),
            auth: auth_variant,
            privacy: UsmPrivacy::None,
        };
        let prober =
            SnmpProber::new(vec![port], SnmpVersion::V3, String::new(), creds).expect("valid v3");
        let outcome = prober
            .probe(&loopback_target(), &ctx_with_timeout(3_000))
            .await
            .expect("probe ok");
        assert!(outcome.reachable);
        assert_eq!(outcome.signals.len(), 3);
    }

    #[tokio::test]
    async fn mockv3_agent_own_hmac_matches_client_side_md5() {
        run_algo_round_trip(
            super::super::usm::AuthAlgo::Md5,
            UsmAuth::Md5 {
                password: Password("authpassword".into()),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn mockv3_agent_own_hmac_matches_client_side_sha1() {
        run_algo_round_trip(
            super::super::usm::AuthAlgo::Sha1,
            UsmAuth::Sha1 {
                password: Password("authpassword".into()),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn mockv3_agent_own_hmac_matches_client_side_sha224() {
        run_algo_round_trip(
            super::super::usm::AuthAlgo::Sha224,
            UsmAuth::Sha224 {
                password: Password("authpassword".into()),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn mockv3_agent_own_hmac_matches_client_side_sha256() {
        run_algo_round_trip(
            super::super::usm::AuthAlgo::Sha256,
            UsmAuth::Sha256 {
                password: Password("authpassword".into()),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn mockv3_agent_own_hmac_matches_client_side_sha384() {
        run_algo_round_trip(
            super::super::usm::AuthAlgo::Sha384,
            UsmAuth::Sha384 {
                password: Password("authpassword".into()),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn mockv3_agent_own_hmac_matches_client_side_sha512() {
        run_algo_round_trip(
            super::super::usm::AuthAlgo::Sha512,
            UsmAuth::Sha512 {
                password: Password("authpassword".into()),
            },
        )
        .await;
    }
}
