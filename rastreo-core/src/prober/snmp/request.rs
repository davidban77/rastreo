use std::net::SocketAddr;

use rasn::types::ObjectIdentifier;
use tokio::net::UdpSocket;

use crate::error::ProbeErrorKind;
use crate::model::ProbeCtx;

use super::usm::UsmCredentials;
use super::{PortOutcome, SnmpVersion};

/// A request PDU independent of SNMP version: the walk engine and the scalar prober describe what
/// they want, and the session encodes it for v1/v2c (community) or v3 (USM).
pub(crate) enum RequestPdu {
    Get(Vec<ObjectIdentifier>),
    #[cfg(feature = "lldp")]
    GetNext(Vec<ObjectIdentifier>),
    #[cfg(feature = "lldp")]
    GetBulk {
        non_repeaters: u32,
        max_repetitions: u32,
        names: Vec<ObjectIdentifier>,
    },
}

impl RequestPdu {
    pub(crate) fn names(&self) -> &[ObjectIdentifier] {
        match self {
            RequestPdu::Get(names) => names,
            #[cfg(feature = "lldp")]
            RequestPdu::GetNext(names) => names,
            #[cfg(feature = "lldp")]
            RequestPdu::GetBulk { names, .. } => names,
        }
    }
}

/// One VarBind decoded from a response, normalized across v1 and v2/v3 syntaxes. Exception markers
/// (`NoSuchObject`/`NoSuchInstance`/`EndOfMibView`) are the ones a table walk keys off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VarBind {
    pub(crate) name: ObjectIdentifier,
    pub(crate) value: VarValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VarValue {
    Int(i64),
    Bytes(Vec<u8>),
    Oid(ObjectIdentifier),
    /// Any concrete syntax we do not decode further (Counter, TimeTicks, IpAddress, Opaque, …).
    Other,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    Unspecified,
}

pub(crate) struct SnmpResponse {
    pub(crate) error_status: u32,
    pub(crate) var_binds: Vec<VarBind>,
}

/// The reachability-relevant outcome of a single request. `Absent` is silence for THIS request;
/// for a v3 session, reachability is already established by discovery, so the caller keeps the
/// device even on `Absent`.
#[derive(Debug)]
pub(crate) enum SnmpError {
    Absent,
    Decode,
    Fault(ProbeErrorKind, String),
    Other(String),
}

pub(crate) enum SessionAuth {
    Community {
        version: SnmpVersion,
        community: String,
    },
    V3(super::v3::V3Session),
}

/// A resolved SNMP transport: a bound socket plus the version/auth needed to encode a request and
/// decode its reply. A v3 session has already completed engine discovery and key derivation.
pub(crate) struct SnmpSession {
    pub(crate) socket: UdpSocket,
    pub(crate) target_addr: SocketAddr,
    pub(crate) auth: SessionAuth,
}

impl SnmpSession {
    pub(crate) fn community(
        socket: UdpSocket,
        target_addr: SocketAddr,
        version: SnmpVersion,
        community: String,
    ) -> Self {
        Self {
            socket,
            target_addr,
            auth: SessionAuth::Community { version, community },
        }
    }

    pub(crate) async fn establish_v3(
        socket: UdpSocket,
        target_addr: SocketAddr,
        credentials: &UsmCredentials,
        ctx: &ProbeCtx,
        deadline: tokio::time::Instant,
    ) -> Result<Self, SnmpError> {
        let state =
            super::v3::discover_and_derive(&socket, target_addr, credentials, ctx, deadline)
                .await?;
        Ok(Self {
            socket,
            target_addr,
            auth: SessionAuth::V3(state),
        })
    }

    /// v2c and v3 support GETBULK; v1 must walk with GETNEXT.
    #[cfg(feature = "lldp")]
    pub(crate) fn supports_getbulk(&self) -> bool {
        !matches!(
            &self.auth,
            SessionAuth::Community {
                version: SnmpVersion::V1,
                ..
            }
        )
    }
}

/// Send one PDU on the session and return the decoded response, owning retry (community) and the
/// authenticated exchange with its time-window retry (v3).
pub(crate) async fn snmp_request(
    session: &SnmpSession,
    pdu: &RequestPdu,
    ctx: &ProbeCtx,
) -> Result<SnmpResponse, SnmpError> {
    match &session.auth {
        SessionAuth::Community { version, community } => {
            super::v1_v2c::community_exchange(
                &session.socket,
                session.target_addr,
                *version,
                community,
                pdu,
                ctx,
            )
            .await
        }
        SessionAuth::V3(state) => {
            super::v3::authenticated_exchange(&session.socket, session.target_addr, state, pdu, ctx)
                .await
        }
    }
}

pub(super) fn snmp_io_error(err: &std::io::Error) -> SnmpError {
    match super::classify_io_error(err) {
        PortOutcome::Timeout | PortOutcome::Unreachable => SnmpError::Absent,
        PortOutcome::Fault(kind, msg) => SnmpError::Fault(kind, msg),
        PortOutcome::Other(msg) => SnmpError::Other(msg),
        _ => SnmpError::Absent,
    }
}
