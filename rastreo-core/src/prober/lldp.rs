use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;

use rasn::types::ObjectIdentifier;

use crate::error::{ProbeErrorKind, RastreoError};
use crate::fuser::keys::normalize_mac;
use crate::model::{
    LldpNeighbor, LldpObservation, ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget,
};
use crate::prober::ports::{probe_ports, MAX_PORTS_IN_FLIGHT};
use crate::prober::Prober;

use super::snmp::request::{
    snmp_request, RequestPdu, SnmpError, SnmpResponse, SnmpSession, VarValue,
};
use super::snmp::walk::{walk, WalkBounds};
use super::snmp::{
    bind_socket, sanitize_octets, validate_transport, PortOutcome, SnmpVersion, UsmCredentials,
};

// LLDP-MIB, base OID 1.0.8802.1.1.2.1.
const OID_LLDP_LOC_CHASSIS_ID_SUBTYPE: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 3, 1, 0];
const OID_LLDP_LOC_CHASSIS_ID: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 3, 2, 0];
const OID_LLDP_REM_ENTRY: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 4, 1, 1];
const OID_LLDP_LOC_PORT_ENTRY: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 3, 7, 1];

const REM_COL_CHASSIS_SUBTYPE: u32 = 4;
const REM_COL_CHASSIS_ID: u32 = 5;
const REM_COL_PORT_SUBTYPE: u32 = 6;
const REM_COL_PORT_ID: u32 = 7;
const REM_COL_PORT_DESC: u32 = 8;
const REM_COL_SYS_NAME: u32 = 9;
const LOC_COL_PORT_ID: u32 = 3;
const LOC_COL_PORT_DESC: u32 = 4;

const CHASSIS_SUBTYPE_MAC: u32 = 4;
const CHASSIS_SUBTYPE_NETWORK_ADDRESS: u32 = 5;
const PORT_SUBTYPE_MAC: u32 = 3;
const PORT_SUBTYPE_NETWORK_ADDRESS: u32 = 4;

/// Serde default for `ProberConfig::Lldp.max_rows` — the walk row bound.
pub fn default_max_rows() -> usize {
    4096
}

pub struct LldpProber {
    ports: Vec<u16>,
    version: SnmpVersion,
    community: String,
    credentials: UsmCredentials,
    max_rows: usize,
    oid_chassis_id_subtype: ObjectIdentifier,
    oid_chassis_id: ObjectIdentifier,
    oid_rem_entry: ObjectIdentifier,
    oid_loc_port_entry: ObjectIdentifier,
}

impl std::fmt::Debug for LldpProber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LldpProber")
            .field("ports", &self.ports)
            .field("version", &self.version)
            .field("community", &"<redacted>")
            .field("credentials", &self.credentials)
            .field("max_rows", &self.max_rows)
            .finish()
    }
}

impl LldpProber {
    pub fn new(
        ports: Vec<u16>,
        version: SnmpVersion,
        community: String,
        credentials: UsmCredentials,
        max_rows: usize,
    ) -> Result<Self, RastreoError> {
        validate_transport(&ports, version, &community, &credentials)?;
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        Ok(Self {
            ports,
            version,
            community,
            credentials,
            max_rows,
            oid_chassis_id_subtype: ObjectIdentifier::new_unchecked(
                OID_LLDP_LOC_CHASSIS_ID_SUBTYPE.into(),
            ),
            oid_chassis_id: ObjectIdentifier::new_unchecked(OID_LLDP_LOC_CHASSIS_ID.into()),
            oid_rem_entry: ObjectIdentifier::new_unchecked(OID_LLDP_REM_ENTRY.into()),
            oid_loc_port_entry: ObjectIdentifier::new_unchecked(OID_LLDP_LOC_PORT_ENTRY.into()),
        })
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    pub fn version(&self) -> SnmpVersion {
        self.version
    }
}

enum LldpPortOutcome {
    Reached(LldpObservation),
    Absent,
    DecodeFailed,
    Fault(ProbeErrorKind, String),
    Other(String),
}

#[async_trait::async_trait]
impl Prober for LldpProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Lldp
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let per_port = probe_ports(
            &self.ports,
            MAX_PORTS_IN_FLIGHT,
            ctx.port_budget.as_ref(),
            |port| {
                let addr = SocketAddr::new(target.ip, port);
                async move { (port, self.probe_port(addr, ctx).await) }
            },
        )
        .await;

        let mut observation: Option<LldpObservation> = None;
        let mut decode_failed_port: Option<u16> = None;
        let mut last_fault: Option<ProbeFault> = None;

        for (port, outcome) in per_port {
            match outcome {
                LldpPortOutcome::Reached(obs) => {
                    if observation.is_none() {
                        observation = Some(obs);
                    }
                }
                LldpPortOutcome::Absent => {}
                LldpPortOutcome::DecodeFailed => {
                    decode_failed_port.get_or_insert(port);
                }
                LldpPortOutcome::Fault(kind, msg) => {
                    last_fault = Some(ProbeFault::new(
                        kind,
                        format!("lldp probe failed on port {port}: {msg}"),
                    ));
                }
                LldpPortOutcome::Other(msg) => {
                    last_fault = Some(ProbeFault::new(
                        ProbeErrorKind::Other,
                        format!("lldp probe failed on port {port}: {msg}"),
                    ));
                }
            }
        }

        Ok(assemble_outcome(
            target.ip,
            observation,
            decode_failed_port,
            last_fault,
        ))
    }
}

impl LldpProber {
    async fn probe_port(&self, target_addr: SocketAddr, ctx: &ProbeCtx) -> LldpPortOutcome {
        let socket = match bind_socket(target_addr).await {
            Ok(s) => s,
            Err(PortOutcome::Other(msg)) => return LldpPortOutcome::Other(msg),
            Err(_) => return LldpPortOutcome::Absent,
        };
        let overall_deadline = tokio::time::Instant::now() + ctx.timeout;

        // A v3 engine that completed discovery has provably answered; a community session proves
        // nothing until the first request returns.
        let (session, reachable_from_session) = match self.version {
            SnmpVersion::V1 | SnmpVersion::V2c => (
                SnmpSession::community(socket, target_addr, self.version, self.community.clone()),
                false,
            ),
            SnmpVersion::V3 => {
                match SnmpSession::establish_v3(
                    socket,
                    target_addr,
                    &self.credentials,
                    ctx,
                    overall_deadline,
                )
                .await
                {
                    Ok(s) => (s, true),
                    Err(SnmpError::Absent) => return LldpPortOutcome::Absent,
                    Err(SnmpError::Decode) => return LldpPortOutcome::DecodeFailed,
                    Err(SnmpError::Fault(kind, msg)) => return LldpPortOutcome::Fault(kind, msg),
                    Err(SnmpError::Other(msg)) => return LldpPortOutcome::Other(msg),
                }
            }
        };

        let chassis_get = RequestPdu::Get(vec![
            self.oid_chassis_id_subtype.clone(),
            self.oid_chassis_id.clone(),
        ]);
        let chassis = match snmp_request(
            &session,
            &chassis_get,
            &self.ctx_until(overall_deadline, ctx),
        )
        .await
        {
            Ok(resp) => parse_local_chassis(&resp),
            Err(SnmpError::Decode) => return LldpPortOutcome::DecodeFailed,
            Err(SnmpError::Absent) if reachable_from_session => LocalChassis::default(),
            Err(SnmpError::Absent) => return LldpPortOutcome::Absent,
            Err(SnmpError::Fault(kind, msg)) if !reachable_from_session => {
                return LldpPortOutcome::Fault(kind, msg)
            }
            Err(SnmpError::Fault(_, msg)) | Err(SnmpError::Other(msg)) => {
                return LldpPortOutcome::Other(msg)
            }
        };

        // Reachable — an empty neighbor table is reachable-with-no-neighbors, never absence.
        let bounds = WalkBounds::new(self.max_rows);
        let rem_rows = walk(
            &session,
            &self.oid_rem_entry,
            &bounds,
            &self.ctx_until(overall_deadline, ctx),
        )
        .await
        .unwrap_or_default();
        let loc_rows = walk(
            &session,
            &self.oid_loc_port_entry,
            &bounds,
            &self.ctx_until(overall_deadline, ctx),
        )
        .await
        .unwrap_or_default();

        LldpPortOutcome::Reached(assemble_observation(chassis, &rem_rows, &loc_rows))
    }

    fn ctx_until(&self, deadline: tokio::time::Instant, ctx: &ProbeCtx) -> ProbeCtx {
        let mut sub = ctx.clone();
        sub.timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        sub
    }
}

fn assemble_outcome(
    target_ip: IpAddr,
    observation: Option<LldpObservation>,
    decode_failed_port: Option<u16>,
    last_fault: Option<ProbeFault>,
) -> ProbeOutcome {
    if let Some(observation) = observation {
        return ProbeOutcome {
            kind: ProbeKind::Lldp,
            target_ip,
            timestamp: SystemTime::now(),
            reachable: true,
            signals: Vec::new(),
            fault: None,
            lldp: Some(observation),
        };
    }
    if let Some(port) = decode_failed_port {
        return ProbeOutcome {
            kind: ProbeKind::Lldp,
            target_ip,
            timestamp: SystemTime::now(),
            reachable: true,
            signals: Vec::new(),
            fault: Some(ProbeFault::new(
                ProbeErrorKind::DecodeFailed,
                format!("lldp reply on port {port} could not be decoded"),
            )),
            lldp: None,
        };
    }
    ProbeOutcome {
        kind: ProbeKind::Lldp,
        target_ip,
        timestamp: SystemTime::now(),
        reachable: false,
        signals: Vec::new(),
        fault: last_fault,
        lldp: None,
    }
}

#[derive(Default)]
struct LocalChassis {
    id: String,
    subtype: u32,
}

fn parse_local_chassis(resp: &SnmpResponse) -> LocalChassis {
    let mut subtype = 0u32;
    let mut id_bytes: Option<Vec<u8>> = None;
    for vb in &resp.var_binds {
        let arcs: &[u32] = vb.name.as_ref();
        if arcs == OID_LLDP_LOC_CHASSIS_ID_SUBTYPE {
            if let VarValue::Int(i) = &vb.value {
                subtype = u32::try_from(*i).unwrap_or(0);
            }
        } else if arcs == OID_LLDP_LOC_CHASSIS_ID {
            if let VarValue::Bytes(bytes) = &vb.value {
                id_bytes = Some(bytes.clone());
            }
        }
    }
    let id = id_bytes
        .as_deref()
        .map(|b| render_chassis_id(subtype, b))
        .unwrap_or_default();
    LocalChassis { id, subtype }
}

#[derive(Default)]
struct NeighborColumns {
    chassis_subtype: Option<u32>,
    chassis_id: Option<Vec<u8>>,
    port_subtype: Option<u32>,
    port_id: Option<Vec<u8>>,
    port_desc: Option<Vec<u8>>,
    sys_name: Option<Vec<u8>>,
}

fn assemble_observation(
    local: LocalChassis,
    rem_rows: &[(ObjectIdentifier, VarValue)],
    loc_rows: &[(ObjectIdentifier, VarValue)],
) -> LldpObservation {
    let loc_names = local_port_names(loc_rows);

    let mut groups: BTreeMap<Vec<u32>, NeighborColumns> = BTreeMap::new();
    for (oid, value) in rem_rows {
        let Some((col, index)) = rem_cell(oid) else {
            continue;
        };
        let entry = groups.entry(index).or_default();
        match col {
            REM_COL_CHASSIS_SUBTYPE => entry.chassis_subtype = as_u32(value),
            REM_COL_CHASSIS_ID => entry.chassis_id = as_bytes(value),
            REM_COL_PORT_SUBTYPE => entry.port_subtype = as_u32(value),
            REM_COL_PORT_ID => entry.port_id = as_bytes(value),
            REM_COL_PORT_DESC => entry.port_desc = as_bytes(value),
            REM_COL_SYS_NAME => entry.sys_name = as_bytes(value),
            _ => {}
        }
    }

    let mut neighbors = Vec::with_capacity(groups.len());
    for (index, cols) in groups {
        let local_port_num = index.get(1).copied();
        let local_port = local_port_num
            .and_then(|n| loc_names.get(&n).cloned())
            .or_else(|| local_port_num.map(|n| n.to_string()))
            .unwrap_or_default();
        let chassis_subtype = cols.chassis_subtype.unwrap_or(0);
        let port_subtype = cols.port_subtype.unwrap_or(0);
        neighbors.push(LldpNeighbor {
            local_port,
            remote_chassis_id: cols
                .chassis_id
                .as_deref()
                .map(|b| render_chassis_id(chassis_subtype, b))
                .unwrap_or_default(),
            remote_chassis_subtype: chassis_subtype,
            remote_port_id: cols
                .port_id
                .as_deref()
                .map(|b| render_port_id(port_subtype, b))
                .unwrap_or_default(),
            remote_port_subtype: port_subtype,
            remote_port_desc: cols.port_desc.as_deref().and_then(bytes_to_opt_string),
            remote_sys_name: cols.sys_name.as_deref().and_then(bytes_to_opt_string),
        });
    }

    LldpObservation {
        local_chassis_id: local.id,
        local_chassis_subtype: local.subtype,
        neighbors,
        discovered_via: "lldp".to_string(),
    }
}

fn local_port_names(loc_rows: &[(ObjectIdentifier, VarValue)]) -> BTreeMap<u32, String> {
    let mut ids: BTreeMap<u32, String> = BTreeMap::new();
    let mut descs: BTreeMap<u32, String> = BTreeMap::new();
    for (oid, value) in loc_rows {
        let Some((col, port_num)) = loc_cell(oid) else {
            continue;
        };
        if let VarValue::Bytes(bytes) = value {
            let name = sanitize_octets(bytes);
            match col {
                LOC_COL_PORT_ID => {
                    ids.insert(port_num, name);
                }
                LOC_COL_PORT_DESC => {
                    descs.insert(port_num, name);
                }
                _ => {}
            }
        }
    }
    let mut names = descs;
    // lldpLocPortId (the interface name) wins over the free-text description.
    names.extend(ids);
    names
}

fn rem_cell(oid: &ObjectIdentifier) -> Option<(u32, Vec<u32>)> {
    let arcs: &[u32] = oid.as_ref();
    let base = OID_LLDP_REM_ENTRY.len();
    if arcs.len() <= base + 1 || &arcs[..base] != OID_LLDP_REM_ENTRY {
        return None;
    }
    Some((arcs[base], arcs[base + 1..].to_vec()))
}

fn loc_cell(oid: &ObjectIdentifier) -> Option<(u32, u32)> {
    let arcs: &[u32] = oid.as_ref();
    let base = OID_LLDP_LOC_PORT_ENTRY.len();
    if arcs.len() != base + 2 || &arcs[..base] != OID_LLDP_LOC_PORT_ENTRY {
        return None;
    }
    Some((arcs[base], arcs[base + 1]))
}

fn as_u32(value: &VarValue) -> Option<u32> {
    match value {
        VarValue::Int(i) => u32::try_from(*i).ok(),
        _ => None,
    }
}

fn as_bytes(value: &VarValue) -> Option<Vec<u8>> {
    match value {
        VarValue::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    }
}

fn bytes_to_opt_string(bytes: &[u8]) -> Option<String> {
    let s = sanitize_octets(bytes);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn render_chassis_id(subtype: u32, bytes: &[u8]) -> String {
    match subtype {
        CHASSIS_SUBTYPE_MAC => mac_or_hex(bytes),
        CHASSIS_SUBTYPE_NETWORK_ADDRESS => render_network_address(bytes),
        _ => sanitize_octets(bytes),
    }
}

fn render_port_id(subtype: u32, bytes: &[u8]) -> String {
    match subtype {
        PORT_SUBTYPE_MAC => mac_or_hex(bytes),
        PORT_SUBTYPE_NETWORK_ADDRESS => render_network_address(bytes),
        _ => sanitize_octets(bytes),
    }
}

fn mac_or_hex(bytes: &[u8]) -> String {
    if bytes.len() == 6 {
        let colon = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        );
        // Shared normalizer so the chassis-MAC matches the identity fuser's MAC key.
        normalize_mac(&colon)
    } else {
        hex_string(bytes)
    }
}

fn render_network_address(bytes: &[u8]) -> String {
    // lldpNetworkAddress = [IANA address-family, address...]; 1 = IPv4, 2 = IPv6.
    match bytes.split_first() {
        Some((1, rest)) if rest.len() == 4 => {
            Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]).to_string()
        }
        Some((2, rest)) if rest.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rest);
            Ipv6Addr::from(octets).to_string()
        }
        _ => hex_string(bytes),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Target;
    use crate::prober::snmp::request::VarBind;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    fn oid(arcs: &[u32]) -> ObjectIdentifier {
        ObjectIdentifier::new_unchecked(arcs.to_vec().into())
    }

    fn creds() -> UsmCredentials {
        UsmCredentials::default()
    }

    #[test]
    fn new_rejects_empty_ports() {
        match LldpProber::new(Vec::new(), SnmpVersion::V2c, "public".into(), creds(), 4096) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("port"), "got: {msg}");
            }
            other => panic!("expected InvalidValue about port, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_empty_community() {
        match LldpProber::new(vec![161], SnmpVersion::V2c, String::new(), creds(), 4096) {
            Err(RastreoError::Config(crate::error::ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("community"), "got: {msg}");
            }
            other => panic!("expected InvalidValue about community, got {other:?}"),
        }
    }

    #[test]
    fn new_sorts_and_dedups_ports() {
        let p = LldpProber::new(
            vec![161, 1161, 161],
            SnmpVersion::V2c,
            "public".into(),
            creds(),
            4096,
        )
        .expect("valid");
        assert_eq!(p.ports(), &[161, 1161]);
    }

    #[test]
    fn debug_redacts_community() {
        let p = LldpProber::new(vec![161], SnmpVersion::V2c, "secret".into(), creds(), 4096)
            .expect("valid");
        let out = format!("{p:?}");
        assert!(!out.contains("secret"), "community leaked: {out}");
        assert!(out.contains("<redacted>"));
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<LldpProber>();
    }

    #[test]
    fn kind_is_lldp() {
        let p = LldpProber::new(vec![161], SnmpVersion::V2c, "public".into(), creds(), 4096)
            .expect("v");
        assert_eq!(p.kind(), ProbeKind::Lldp);
    }

    #[test]
    fn mac_subtype_renders_normalized_mac() {
        let bytes = [0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33];
        assert_eq!(
            render_chassis_id(CHASSIS_SUBTYPE_MAC, &bytes),
            "aabbcc112233"
        );
        assert_eq!(render_port_id(PORT_SUBTYPE_MAC, &bytes), "aabbcc112233");
    }

    #[test]
    fn string_subtype_renders_utf8() {
        assert_eq!(render_port_id(5, b"Ethernet1/1"), "Ethernet1/1");
    }

    #[test]
    fn network_address_subtype_renders_ipv4() {
        // family 1 (IPv4) + 4 octets
        assert_eq!(render_chassis_id(5, &[1, 10, 0, 0, 1]), "10.0.0.1");
    }

    fn rem(col: u32, index: &[u32], value: VarValue) -> (ObjectIdentifier, VarValue) {
        let mut arcs = OID_LLDP_REM_ENTRY.to_vec();
        arcs.push(col);
        arcs.extend_from_slice(index);
        (oid(&arcs), value)
    }

    fn loc(col: u32, port_num: u32, value: VarValue) -> (ObjectIdentifier, VarValue) {
        let mut arcs = OID_LLDP_LOC_PORT_ENTRY.to_vec();
        arcs.push(col);
        arcs.push(port_num);
        (oid(&arcs), value)
    }

    #[test]
    fn assemble_observation_builds_a_neighbor_with_resolved_local_port() {
        let local = LocalChassis {
            id: "aabbccddeeff".into(),
            subtype: CHASSIS_SUBTYPE_MAC,
        };
        // one neighbor on local port num 7 (index = timeMark 100, lpn 7, remIndex 1)
        let idx = [100u32, 7, 1];
        let rem_rows = vec![
            rem(
                REM_COL_CHASSIS_SUBTYPE,
                &idx,
                VarValue::Int(CHASSIS_SUBTYPE_MAC as i64),
            ),
            rem(
                REM_COL_CHASSIS_ID,
                &idx,
                VarValue::Bytes(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ),
            rem(
                REM_COL_PORT_SUBTYPE,
                &idx,
                VarValue::Int(PORT_SUBTYPE_MAC as i64),
            ),
            rem(
                REM_COL_PORT_ID,
                &idx,
                VarValue::Bytes(vec![0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]),
            ),
            rem(
                REM_COL_PORT_DESC,
                &idx,
                VarValue::Bytes(b"GigabitEthernet0/1".to_vec()),
            ),
            rem(REM_COL_SYS_NAME, &idx, VarValue::Bytes(b"peer-sw".to_vec())),
        ];
        let loc_rows = vec![loc(
            LOC_COL_PORT_ID,
            7,
            VarValue::Bytes(b"Ethernet1/7".to_vec()),
        )];

        let obs = assemble_observation(local, &rem_rows, &loc_rows);
        assert_eq!(obs.local_chassis_id, "aabbccddeeff");
        assert_eq!(obs.local_chassis_subtype, CHASSIS_SUBTYPE_MAC);
        assert_eq!(obs.neighbors.len(), 1);
        let n = &obs.neighbors[0];
        assert_eq!(n.local_port, "Ethernet1/7");
        assert_eq!(n.remote_chassis_id, "001122334455");
        assert_eq!(n.remote_chassis_subtype, CHASSIS_SUBTYPE_MAC);
        assert_eq!(n.remote_port_id, "66778899aabb");
        assert_eq!(n.remote_port_subtype, PORT_SUBTYPE_MAC);
        assert_eq!(n.remote_port_desc.as_deref(), Some("GigabitEthernet0/1"));
        assert_eq!(n.remote_sys_name.as_deref(), Some("peer-sw"));
    }

    #[test]
    fn parse_local_chassis_renders_mac_for_subtype_four() {
        let resp = SnmpResponse {
            error_status: 0,
            var_binds: vec![
                VarBind {
                    name: oid(OID_LLDP_LOC_CHASSIS_ID_SUBTYPE),
                    value: VarValue::Int(CHASSIS_SUBTYPE_MAC as i64),
                },
                VarBind {
                    name: oid(OID_LLDP_LOC_CHASSIS_ID),
                    value: VarValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]),
                },
            ],
        };
        let chassis = parse_local_chassis(&resp);
        assert_eq!(chassis.subtype, CHASSIS_SUBTYPE_MAC);
        assert_eq!(chassis.id, "deadbeef0001");
    }

    #[test]
    fn empty_tables_yield_observation_with_no_neighbors() {
        let local = LocalChassis {
            id: "aabbccddeeff".into(),
            subtype: CHASSIS_SUBTYPE_MAC,
        };
        let obs = assemble_observation(local, &[], &[]);
        assert!(obs.neighbors.is_empty());
        assert_eq!(obs.local_chassis_id, "aabbccddeeff");
    }

    #[test]
    fn neighbor_local_port_falls_back_to_port_number_when_unresolved() {
        let idx = [1u32, 42, 1];
        let rem_rows = vec![rem(
            REM_COL_SYS_NAME,
            &idx,
            VarValue::Bytes(b"peer".to_vec()),
        )];
        let obs = assemble_observation(LocalChassis::default(), &rem_rows, &[]);
        assert_eq!(obs.neighbors.len(), 1);
        assert_eq!(obs.neighbors[0].local_port, "42");
        assert_eq!(obs.neighbors[0].remote_sys_name.as_deref(), Some("peer"));
    }

    fn loopback_target() -> ResolvedTarget {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn silent_target_is_absence_not_reachable() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let _ = socket.recv_from(&mut buf).await;
            }
        });
        let p = LldpProber::new(vec![port], SnmpVersion::V2c, "public".into(), creds(), 4096)
            .expect("valid");
        let outcome = p
            .probe(
                &loopback_target(),
                &ProbeCtx::new(Duration::from_millis(200), 0),
            )
            .await
            .expect("a silent agent is an outcome");
        assert!(!outcome.reachable);
        assert!(outcome.lldp.is_none());
        assert!(outcome.fault.is_none());
    }

    // A v2c agent that answers the chassis GET and reports an empty neighbor table.
    fn empty_table_response(req: &[u8]) -> Option<Vec<u8>> {
        use rasn::types::{Integer, OctetString};
        use rasn_smi::v2 as smi_v2;
        use rasn_snmp::{v2 as snmp_v2, v2c};

        let msg: v2c::Message<snmp_v2::Pdus> = rasn::ber::decode(req).ok()?;
        let (request_id, varbinds) = match msg.data {
            snmp_v2::Pdus::GetRequest(snmp_v2::GetRequest(pdu)) => (
                pdu.request_id,
                vec![
                    snmp_v2::VarBind {
                        name: oid(OID_LLDP_LOC_CHASSIS_ID_SUBTYPE),
                        value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                            smi_v2::SimpleSyntax::Integer(Integer::from(CHASSIS_SUBTYPE_MAC)),
                        )),
                    },
                    snmp_v2::VarBind {
                        name: oid(OID_LLDP_LOC_CHASSIS_ID),
                        value: snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
                            smi_v2::SimpleSyntax::String(OctetString::from_slice(&[
                                0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22,
                            ])),
                        )),
                    },
                ],
            ),
            // Any GETBULK answers with an OID outside the walked subtree → empty table.
            snmp_v2::Pdus::GetBulkRequest(snmp_v2::GetBulkRequest(pdu)) => (
                pdu.request_id,
                vec![snmp_v2::VarBind {
                    name: oid(&[2, 0, 0]),
                    value: snmp_v2::VarBindValue::EndOfMibView,
                }],
            ),
            _ => return None,
        };
        let resp: v2c::Message<snmp_v2::Pdus> = v2c::Message {
            version: Integer::from(v2c::Message::<()>::VERSION),
            community: msg.community,
            data: snmp_v2::Pdus::Response(snmp_v2::Response(snmp_v2::Pdu {
                request_id,
                error_status: 0,
                error_index: 0,
                variable_bindings: varbinds,
            })),
        };
        rasn::ber::encode(&resp).ok()
    }

    #[tokio::test]
    async fn agent_with_empty_neighbor_table_is_reachable_with_no_neighbors() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                if let Some(resp) = empty_table_response(&buf[..n]) {
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });
        let p = LldpProber::new(vec![port], SnmpVersion::V2c, "public".into(), creds(), 4096)
            .expect("valid");
        let outcome = p
            .probe(
                &loopback_target(),
                &ProbeCtx::new(Duration::from_secs(2), 0),
            )
            .await
            .expect("probe ok");
        assert!(outcome.reachable, "an answering agent is reachable");
        let obs = outcome
            .lldp
            .expect("observation present even with no neighbors");
        assert_eq!(obs.local_chassis_id, "aabbcc001122");
        assert_eq!(obs.local_chassis_subtype, CHASSIS_SUBTYPE_MAC);
        assert!(obs.neighbors.is_empty(), "no neighbors, not absence");
    }
}
