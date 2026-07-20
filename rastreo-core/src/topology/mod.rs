use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::fuser::keys::{normalize_mac, normalize_sys_name};
use crate::model::device::DeviceRecord;
use crate::model::link::{LinkEndpoint, LinkRecord, LINK_SCHEMA_ID};
use crate::model::outcome::{LldpNeighbor, ProbeOutcome, Signal};
use crate::model::scan::ScanMetadata;

const CHASSIS_SUBTYPE_MAC: u32 = 4;
const CHASSIS_SUBTYPE_NETWORK_ADDRESS: u32 = 5;

/// Assembles collected LLDP neighbor observations into deduplicated [`LinkRecord`]s.
///
/// A physical link is identified by the unordered pair of LLDP chassis-ids, so both ends collapse
/// to one record when both are probed. Endpoint-to-device correlation (`identity_key`) is a
/// separate step layered on top and never affects the deduplication key. The assembler stamps its
/// own `scan_metadata` because the pipeline's stamping and classifier are `DeviceRecord`-only.
pub struct TopologyAssembler {
    scan_metadata: Arc<ScanMetadata>,
    observations: Vec<DeviceObservation>,
    mac_index: HashMap<String, String>,
    sys_name_index: HashMap<String, String>,
    addr_index: HashMap<IpAddr, String>,
}

struct DeviceObservation {
    local_ip: IpAddr,
    local_chassis_id: String,
    local_chassis_subtype: u32,
    observed_at: SystemTime,
    discovered_via: String,
    neighbors: Vec<LldpNeighbor>,
}

impl TopologyAssembler {
    pub fn new(scan_metadata: Arc<ScanMetadata>) -> Self {
        Self {
            scan_metadata,
            observations: Vec::new(),
            mac_index: HashMap::new(),
            sys_name_index: HashMap::new(),
            addr_index: HashMap::new(),
        }
    }

    /// Pulls each outcome's LLDP observation (local chassis-id + neighbors) for later assembly.
    pub fn observe_outcomes(&mut self, outcomes: &[ProbeOutcome]) {
        for outcome in outcomes {
            let Some(lldp) = &outcome.lldp else { continue };
            self.observations.push(DeviceObservation {
                local_ip: outcome.target_ip,
                local_chassis_id: lldp.local_chassis_id.clone(),
                local_chassis_subtype: lldp.local_chassis_subtype,
                observed_at: outcome.timestamp,
                discovered_via: lldp.discovered_via.clone(),
                neighbors: lldp.neighbors.clone(),
            });
        }
    }

    /// Indexes an emitted device record's identity signals (MAC, sys-name, addresses) so endpoints
    /// can later be correlated back to it.
    pub fn observe_record(&mut self, record: &DeviceRecord) {
        let identity = record.identity_key.as_str();
        if let Some(mac) = record.mac.as_deref() {
            self.index_mac(mac, identity);
        }
        for signal in &record.signals {
            match signal {
                Signal::Mac(mac) => self.index_mac(mac, identity),
                Signal::SnmpSysName(name) | Signal::ReverseDnsName(name) => {
                    self.index_sys_name(name, identity)
                }
                _ => {}
            }
        }
        if let Some(ip) = record.mgmt_ip {
            self.addr_index.entry(ip).or_insert_with(|| identity.into());
        }
        for alt in &record.alt_ips {
            self.addr_index
                .entry(alt.address)
                .or_insert_with(|| identity.into());
        }
    }

    fn index_mac(&mut self, mac: &str, identity: &str) {
        let key = normalize_mac(mac);
        if !key.is_empty() {
            self.mac_index.entry(key).or_insert_with(|| identity.into());
        }
    }

    fn index_sys_name(&mut self, name: &str, identity: &str) {
        let key = normalize_sys_name(name);
        if !key.is_empty() {
            self.sys_name_index
                .entry(key)
                .or_insert_with(|| identity.into());
        }
    }

    pub fn finish(&mut self) -> Vec<LinkRecord> {
        if self.observations.is_empty() {
            return Vec::new();
        }

        // A probed device's own chassis-id maps to its identity via the IP it was probed on; this
        // is what lets both endpoints of a both-ends-probed link resolve to a real device.
        let mut chassis_to_identity: HashMap<String, String> = HashMap::new();
        for obs in &self.observations {
            if let Some(identity) = self.addr_index.get(&obs.local_ip) {
                let key = normalize_chassis(obs.local_chassis_subtype, &obs.local_chassis_id);
                if !key.is_empty() {
                    chassis_to_identity
                        .entry(key)
                        .or_insert_with(|| identity.clone());
                }
            }
        }

        let mut edges: HashMap<(String, String), Edge> = HashMap::new();
        for obs in &self.observations {
            let local_norm = normalize_chassis(obs.local_chassis_subtype, &obs.local_chassis_id);
            if local_norm.is_empty() {
                continue;
            }
            for neighbor in &obs.neighbors {
                let remote_norm =
                    normalize_chassis(neighbor.remote_chassis_subtype, &neighbor.remote_chassis_id);
                if remote_norm.is_empty() || remote_norm == local_norm {
                    continue;
                }
                let key = edge_key(&local_norm, &remote_norm);
                let edge = edges
                    .entry(key)
                    .or_insert_with(|| Edge::new(obs.observed_at));
                edge.observed_at = edge.observed_at.max(obs.observed_at);
                edge.sources.insert(obs.discovered_via.clone());
                edge.merge(EndpointObservation {
                    chassis_norm: local_norm.clone(),
                    chassis_id: &obs.local_chassis_id,
                    subtype: obs.local_chassis_subtype,
                    port: non_empty(&neighbor.local_port),
                    port_authoritative: true,
                    sys_name: None,
                });
                edge.merge(EndpointObservation {
                    chassis_norm: remote_norm.clone(),
                    chassis_id: &neighbor.remote_chassis_id,
                    subtype: neighbor.remote_chassis_subtype,
                    port: non_empty(&neighbor.remote_port_id),
                    port_authoritative: false,
                    sys_name: neighbor.remote_sys_name.clone(),
                });
            }
        }

        let mut keyed: Vec<((String, String), Edge)> = edges.into_iter().collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0));

        keyed
            .into_iter()
            .map(|((ka, kb), edge)| LinkRecord {
                schema_version: LinkRecord::SCHEMA_VERSION.to_string(),
                schema_id: LINK_SCHEMA_ID.to_string(),
                a: self.finalize_endpoint(&ka, &edge, &chassis_to_identity),
                b: self.finalize_endpoint(&kb, &edge, &chassis_to_identity),
                discovered_via: join_sources(&edge.sources),
                observed_at: edge.observed_at,
                scan_metadata: (*self.scan_metadata).clone(),
            })
            .collect()
    }

    fn finalize_endpoint(
        &self,
        chassis_norm: &str,
        edge: &Edge,
        chassis_to_identity: &HashMap<String, String>,
    ) -> LinkEndpoint {
        let info = edge
            .endpoints
            .get(chassis_norm)
            .expect("edge key names an endpoint the edge holds");
        LinkEndpoint {
            identity_key: self.resolve_identity(
                chassis_norm,
                info.subtype,
                info.sys_name.as_deref(),
                chassis_to_identity,
            ),
            chassis_id: info.chassis_id.clone(),
            sys_name: info.sys_name.clone(),
            port: info.port.clone().unwrap_or_default(),
        }
    }

    fn resolve_identity(
        &self,
        chassis_norm: &str,
        subtype: u32,
        sys_name: Option<&str>,
        chassis_to_identity: &HashMap<String, String>,
    ) -> Option<String> {
        if let Some(id) = chassis_to_identity.get(chassis_norm) {
            return Some(id.clone());
        }
        match subtype {
            CHASSIS_SUBTYPE_MAC => {
                if let Some(id) = self.mac_index.get(chassis_norm) {
                    return Some(id.clone());
                }
            }
            CHASSIS_SUBTYPE_NETWORK_ADDRESS => {
                if let Ok(ip) = chassis_norm.parse::<IpAddr>() {
                    if let Some(id) = self.addr_index.get(&ip) {
                        return Some(id.clone());
                    }
                }
            }
            _ => {}
        }
        // The chassis-MAC is often the switch base MAC while ARP sees a per-interface MAC, so a
        // sys-name match recovers a device the MAC index missed.
        if let Some(name) = sys_name {
            let key = normalize_sys_name(name);
            if !key.is_empty() {
                if let Some(id) = self.sys_name_index.get(&key) {
                    return Some(id.clone());
                }
            }
        }
        None
    }
}

struct Edge {
    observed_at: SystemTime,
    sources: BTreeSet<String>,
    endpoints: HashMap<String, EndpointInfo>,
}

impl Edge {
    fn new(observed_at: SystemTime) -> Self {
        Self {
            observed_at,
            sources: BTreeSet::new(),
            endpoints: HashMap::new(),
        }
    }

    fn merge(&mut self, obs: EndpointObservation<'_>) {
        let entry = self
            .endpoints
            .entry(obs.chassis_norm)
            .or_insert_with(|| EndpointInfo {
                chassis_id: obs.chassis_id.to_string(),
                subtype: obs.subtype,
                port: None,
                port_authoritative: false,
                sys_name: None,
            });
        if let Some(port) = obs.port {
            let upgrade = obs.port_authoritative && !entry.port_authoritative;
            if upgrade || entry.port.is_none() {
                entry.port = Some(port);
                entry.port_authoritative = obs.port_authoritative;
            }
        }
        if entry.sys_name.is_none() {
            if let Some(name) = obs.sys_name {
                entry.sys_name = Some(name);
            }
        }
    }
}

struct EndpointInfo {
    chassis_id: String,
    subtype: u32,
    port: Option<String>,
    port_authoritative: bool,
    sys_name: Option<String>,
}

struct EndpointObservation<'a> {
    chassis_norm: String,
    chassis_id: &'a str,
    subtype: u32,
    port: Option<String>,
    port_authoritative: bool,
    sys_name: Option<String>,
}

/// Deterministic `discovered_via`: the sorted source set joined with commas, so a link seen `lldp`
/// from one end and `gnmi` from the other emits `gnmi,lldp` regardless of scan-completion order.
fn join_sources(sources: &BTreeSet<String>) -> String {
    sources
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

/// Unordered pair of chassis-ids: both directions of a physical link produce the same key.
fn edge_key(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

fn normalize_chassis(subtype: u32, id: &str) -> String {
    match subtype {
        CHASSIS_SUBTYPE_MAC => normalize_mac(id),
        _ => id.trim().to_ascii_lowercase(),
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.trim().is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::model::device::{AltIp, Confidence, IdentityKey, CURRENT_SCHEMA_ID};
    use crate::model::outcome::{LldpObservation, ProbeKind};

    fn assembler() -> TopologyAssembler {
        TopologyAssembler::new(Arc::new(ScanMetadata::default()))
    }

    fn neighbor(local_port: &str, remote_chassis: &str, subtype: u32) -> LldpNeighbor {
        LldpNeighbor {
            local_port: local_port.to_string(),
            remote_chassis_id: remote_chassis.to_string(),
            remote_chassis_subtype: subtype,
            remote_port_id: "remote-port".to_string(),
            remote_port_subtype: 5,
            remote_port_desc: None,
            remote_sys_name: None,
        }
    }

    fn lldp_outcome(
        ip: u8,
        local_chassis: &str,
        local_subtype: u32,
        neighbors: Vec<LldpNeighbor>,
    ) -> ProbeOutcome {
        sourced_outcome(ip, local_chassis, local_subtype, "lldp", neighbors)
    }

    fn sourced_outcome(
        ip: u8,
        local_chassis: &str,
        local_subtype: u32,
        discovered_via: &str,
        neighbors: Vec<LldpNeighbor>,
    ) -> ProbeOutcome {
        ProbeOutcome {
            kind: ProbeKind::Lldp,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals: Vec::new(),
            fault: None,
            lldp: Some(LldpObservation {
                local_chassis_id: local_chassis.to_string(),
                local_chassis_subtype: local_subtype,
                neighbors,
                discovered_via: discovered_via.to_string(),
            }),
        }
    }

    fn record(ip: u8, mac: Option<&str>, signals: Vec<Signal>) -> DeviceRecord {
        let identity = match mac {
            Some(m) => format!("mac:{m}"),
            None => format!("ip:10.0.0.{ip}"),
        };
        DeviceRecord {
            identity_key: IdentityKey::new(identity).expect("identity"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip))),
            mac: mac.map(str::to_string),
            manufacturer: None,
            platform: None,
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: None,
            confidence: Confidence::new(0.5).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals,
            probe_kinds: Vec::new(),
            schema_version: LinkRecord::SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    #[test]
    fn no_observations_emits_no_links() {
        let mut a = assembler();
        a.observe_record(&record(1, Some("aabbccddeeff"), vec![]));
        assert!(a.finish().is_empty(), "no lldp data means no links");
    }

    #[test]
    fn two_mutually_lldp_devices_collapse_to_one_link() {
        let cx = "aaaaaaaaaaaa";
        let cy = "bbbbbbbbbbbb";
        let mut a = assembler();
        a.observe_outcomes(&[lldp_outcome(
            1,
            cx,
            CHASSIS_SUBTYPE_MAC,
            vec![neighbor("Gi0/1", cy, CHASSIS_SUBTYPE_MAC)],
        )]);
        a.observe_outcomes(&[lldp_outcome(
            2,
            cy,
            CHASSIS_SUBTYPE_MAC,
            vec![neighbor("Gi0/2", cx, CHASSIS_SUBTYPE_MAC)],
        )]);
        a.observe_record(&record(1, Some(cx), vec![Signal::Mac(cx.into())]));
        a.observe_record(&record(2, Some(cy), vec![Signal::Mac(cy.into())]));

        let links = a.finish();
        assert_eq!(
            links.len(),
            1,
            "an edge is one unordered chassis-id pair; both ends collapse to one link"
        );
        let link = &links[0];
        assert_eq!(
            link.a.chassis_id, cx,
            "endpoints sort by normalized chassis"
        );
        assert_eq!(link.b.chassis_id, cy);
        assert_eq!(link.a.identity_key.as_deref(), Some("mac:aaaaaaaaaaaa"));
        assert_eq!(link.b.identity_key.as_deref(), Some("mac:bbbbbbbbbbbb"));
    }

    #[test]
    fn both_ends_probed_merges_authoritative_ports_and_advertised_sysname() {
        let cx = "aaaaaaaaaaaa";
        let cy = "bbbbbbbbbbbb";
        let mut x_neighbor = neighbor("Gi0/1", cy, CHASSIS_SUBTYPE_MAC);
        x_neighbor.remote_sys_name = Some("device-y".to_string());
        let mut y_neighbor = neighbor("Gi0/2", cx, CHASSIS_SUBTYPE_MAC);
        y_neighbor.remote_sys_name = Some("device-x".to_string());

        let mut a = assembler();
        a.observe_outcomes(&[lldp_outcome(1, cx, CHASSIS_SUBTYPE_MAC, vec![x_neighbor])]);
        a.observe_outcomes(&[lldp_outcome(2, cy, CHASSIS_SUBTYPE_MAC, vec![y_neighbor])]);
        a.observe_record(&record(1, Some(cx), vec![Signal::Mac(cx.into())]));
        a.observe_record(&record(2, Some(cy), vec![Signal::Mac(cy.into())]));

        let link = &a.finish()[0];
        assert_eq!(
            link.a.port, "Gi0/1",
            "each endpoint keeps its own local port"
        );
        assert_eq!(link.b.port, "Gi0/2");
        assert_eq!(link.a.sys_name.as_deref(), Some("device-x"));
        assert_eq!(link.b.sys_name.as_deref(), Some("device-y"));
    }

    #[test]
    fn unprobed_neighbor_keeps_raw_chassis_and_has_no_identity() {
        let cx = "aaaaaaaaaaaa";
        let mut n = neighbor("Gi0/1", "cccccccccccc", CHASSIS_SUBTYPE_MAC);
        n.remote_sys_name = Some("unknown-peer".to_string());
        let mut a = assembler();
        a.observe_outcomes(&[lldp_outcome(1, cx, CHASSIS_SUBTYPE_MAC, vec![n])]);
        a.observe_record(&record(1, Some(cx), vec![Signal::Mac(cx.into())]));

        let link = &a.finish()[0];
        let peer = if link.a.chassis_id == "cccccccccccc" {
            &link.a
        } else {
            &link.b
        };
        assert!(
            peer.identity_key.is_none(),
            "unprobed neighbor stays unknown"
        );
        assert_eq!(peer.chassis_id, "cccccccccccc");
        assert_eq!(peer.sys_name.as_deref(), Some("unknown-peer"));
    }

    #[test]
    fn chassis_mac_correlates_to_probed_device_by_normalized_mac() {
        let cx = "aaaaaaaaaaaa";
        // Peer runs no LLDP, but was probed and reports its MAC; the chassis-MAC matches it.
        let peer_mac = "001122334455";
        let mut a = assembler();
        a.observe_outcomes(&[lldp_outcome(
            1,
            cx,
            CHASSIS_SUBTYPE_MAC,
            vec![neighbor("Gi0/1", peer_mac, CHASSIS_SUBTYPE_MAC)],
        )]);
        a.observe_record(&record(1, Some(cx), vec![Signal::Mac(cx.into())]));
        a.observe_record(&record(
            2,
            Some("00:11:22:33:44:55"),
            vec![Signal::Mac("00:11:22:33:44:55".into())],
        ));

        let link = &a.finish()[0];
        let peer = if link.a.chassis_id == peer_mac {
            &link.a
        } else {
            &link.b
        };
        assert_eq!(peer.identity_key.as_deref(), Some("mac:00:11:22:33:44:55"));
    }

    #[test]
    fn endpoint_correlates_by_sys_name_when_mac_differs() {
        let cx = "aaaaaaaaaaaa";
        // The neighbor's chassis-MAC is the base MAC; ARP saw a different per-interface MAC.
        let mut n = neighbor("Gi0/1", "0000deadbeef", CHASSIS_SUBTYPE_MAC);
        n.remote_sys_name = Some("Peer-SW".to_string());
        let mut a = assembler();
        a.observe_outcomes(&[lldp_outcome(1, cx, CHASSIS_SUBTYPE_MAC, vec![n])]);
        a.observe_record(&record(1, Some(cx), vec![Signal::Mac(cx.into())]));
        a.observe_record(&record(
            2,
            Some("aa:aa:bb:bb:cc:cc"),
            vec![Signal::SnmpSysName("peer-sw".into())],
        ));

        let link = &a.finish()[0];
        let peer = if link.a.chassis_id == "0000deadbeef" {
            &link.a
        } else {
            &link.b
        };
        assert_eq!(peer.identity_key.as_deref(), Some("mac:aa:aa:bb:bb:cc:cc"));
    }

    #[test]
    fn network_address_chassis_correlates_to_alt_ip() {
        let cx = "aaaaaaaaaaaa";
        let mut a = assembler();
        a.observe_outcomes(&[lldp_outcome(
            1,
            cx,
            CHASSIS_SUBTYPE_MAC,
            vec![neighbor(
                "Gi0/1",
                "10.0.0.9",
                CHASSIS_SUBTYPE_NETWORK_ADDRESS,
            )],
        )]);
        a.observe_record(&record(1, Some(cx), vec![Signal::Mac(cx.into())]));
        let mut peer = record(2, Some("dd:ee:ff:00:11:22"), vec![]);
        peer.alt_ips = vec![AltIp::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)))];
        a.observe_record(&peer);

        let link = &a.finish()[0];
        let endpoint = if link.a.chassis_id == "10.0.0.9" {
            &link.a
        } else {
            &link.b
        };
        assert_eq!(
            endpoint.identity_key.as_deref(),
            Some("mac:dd:ee:ff:00:11:22")
        );
    }

    #[test]
    fn observed_at_takes_the_latest_contributing_observation() {
        let cx = "aaaaaaaaaaaa";
        let cy = "bbbbbbbbbbbb";
        let late = SystemTime::UNIX_EPOCH + Duration::from_secs(500);
        let mut early = lldp_outcome(
            1,
            cx,
            CHASSIS_SUBTYPE_MAC,
            vec![neighbor("Gi0/1", cy, CHASSIS_SUBTYPE_MAC)],
        );
        early.timestamp = SystemTime::UNIX_EPOCH;
        let mut later = lldp_outcome(
            2,
            cy,
            CHASSIS_SUBTYPE_MAC,
            vec![neighbor("Gi0/2", cx, CHASSIS_SUBTYPE_MAC)],
        );
        later.timestamp = late;

        let mut a = assembler();
        a.observe_outcomes(&[early]);
        a.observe_outcomes(&[later]);
        assert_eq!(a.finish()[0].observed_at, late);
    }

    #[test]
    fn scan_metadata_is_stamped_on_every_link() {
        let scenario_scan = ScanMetadata {
            scan_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            ..ScanMetadata::default()
        };
        let cx = "aaaaaaaaaaaa";
        let cy = "bbbbbbbbbbbb";
        let mut a = TopologyAssembler::new(Arc::new(scenario_scan));
        a.observe_outcomes(&[lldp_outcome(
            1,
            cx,
            CHASSIS_SUBTYPE_MAC,
            vec![neighbor("Gi0/1", cy, CHASSIS_SUBTYPE_MAC)],
        )]);
        a.observe_record(&record(1, Some(cx), vec![Signal::Mac(cx.into())]));

        let link = &a.finish()[0];
        assert_eq!(link.scan_metadata.scan_id, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }

    #[test]
    fn single_source_link_reports_that_source() {
        let cx = "aaaaaaaaaaaa";
        let cy = "bbbbbbbbbbbb";
        let mut a = assembler();
        a.observe_outcomes(&[lldp_outcome(
            1,
            cx,
            CHASSIS_SUBTYPE_MAC,
            vec![neighbor("Gi0/1", cy, CHASSIS_SUBTYPE_MAC)],
        )]);
        assert_eq!(a.finish()[0].discovered_via, "lldp");
    }

    #[test]
    fn discovered_via_merges_both_sources_regardless_of_scan_order() {
        let cx = "aaaaaaaaaaaa";
        let cy = "bbbbbbbbbbbb";
        let gnmi = || {
            sourced_outcome(
                1,
                cx,
                CHASSIS_SUBTYPE_MAC,
                "gnmi",
                vec![neighbor("Gi0/1", cy, CHASSIS_SUBTYPE_MAC)],
            )
        };
        let lldp = || {
            sourced_outcome(
                2,
                cy,
                CHASSIS_SUBTYPE_MAC,
                "lldp",
                vec![neighbor("Gi0/2", cx, CHASSIS_SUBTYPE_MAC)],
            )
        };

        let mut forward = assembler();
        forward.observe_outcomes(&[gnmi()]);
        forward.observe_outcomes(&[lldp()]);
        let mut reverse = assembler();
        reverse.observe_outcomes(&[lldp()]);
        reverse.observe_outcomes(&[gnmi()]);

        assert_eq!(forward.finish()[0].discovered_via, "gnmi,lldp");
        assert_eq!(reverse.finish()[0].discovered_via, "gnmi,lldp");
    }

    #[test]
    fn assembler_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TopologyAssembler>();
    }
}
