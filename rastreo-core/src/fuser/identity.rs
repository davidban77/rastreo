use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use schemars::JsonSchema;

use crate::error::{ConfigError, RastreoError};
use crate::fuser::Fuser;
use crate::model::device::{AltIp, AltIpRole, Confidence, DeviceRecord};
use crate::model::outcome::{ProbeKind, ProbeOutcome, Signal};

const HIGH_BAND_THRESHOLD: f64 = 0.8;
const MEDIUM_BAND_THRESHOLD: f64 = 0.4;
const MERGE_CONFIDENCE_BONUS: f64 = 0.1;

const WEIGHT_SHARED_MAC: f64 = 0.5;
const WEIGHT_SHARED_SYSNAME: f64 = 0.5;
const WEIGHT_SHARED_HOST_KEY: f64 = 0.8;
const WEIGHT_SHARED_TLS_SUBJECT: f64 = 0.3;
const WEIGHT_SHARED_TLS_SAN: f64 = 0.5;
const WEIGHT_SHARED_REVERSE_DNS: f64 = 0.5;
const PENALTY_CONFLICTING_MANUFACTURER: f64 = 0.3;
const VRRP_MEMBER_WEIGHT_CAP: f64 = 0.4;

const VRRP_V2_IPV4_PREFIX: [u8; 5] = [0x00, 0x00, 0x5E, 0x00, 0x01];
const VRRP_V3_IPV6_PREFIX: [u8; 5] = [0x00, 0x00, 0x5E, 0x00, 0x02];
const HSRP_PREFIX: [u8; 5] = [0x00, 0x00, 0x0C, 0x07, 0xAC];

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct IdentityHints {
    #[serde(default)]
    pub vrrp_groups: Vec<VrrpGroup>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct VrrpGroup {
    pub virtual_ip: IpAddr,
    pub virtual_mac: String,
    #[serde(default)]
    pub members: Vec<IpAddr>,
}

impl IdentityHints {
    pub fn new(vrrp_groups: Vec<VrrpGroup>) -> Self {
        Self { vrrp_groups }
    }
}

impl VrrpGroup {
    pub fn new(
        virtual_ip: IpAddr,
        virtual_mac: String,
        members: Vec<IpAddr>,
    ) -> Result<Self, RastreoError> {
        if parse_mac_prefix(&virtual_mac).is_none() {
            return Err(ConfigError::invalid(format!(
                "vrrp_groups virtual_mac '{virtual_mac}' is not a valid MAC address"
            ))
            .into());
        }
        Ok(Self {
            virtual_ip,
            virtual_mac,
            members,
        })
    }
}

/// Wraps another `Fuser`, delegates per-IP fusion, then merges records that share identity signals.
pub struct IdentityFuser {
    inner: Box<dyn Fuser>,
    hints: IdentityHints,
    buffer: Vec<DeviceRecord>,
}

impl IdentityFuser {
    pub fn new(inner: Box<dyn Fuser>, hints: IdentityHints) -> Result<Self, RastreoError> {
        for group in &hints.vrrp_groups {
            if parse_mac_prefix(&group.virtual_mac).is_none() {
                return Err(ConfigError::invalid(format!(
                    "vrrp_groups virtual_mac '{}' is not a valid MAC address",
                    group.virtual_mac
                ))
                .into());
            }
        }
        Ok(Self {
            inner,
            hints,
            buffer: Vec::new(),
        })
    }

    fn correlate(&self, records: Vec<DeviceRecord>) -> Vec<DeviceRecord> {
        if records.len() <= 1 {
            return records;
        }
        let n = records.len();
        let weights = self.compute_pair_weights(&records);
        let mut uf = UnionFind::new(n);
        for (i, j, w) in weights.iter().copied() {
            if w >= HIGH_BAND_THRESHOLD {
                uf.union(i, j);
            }
        }
        let medium_peers = collect_medium_peers(n, &weights, &uf);
        let components = uf.components();
        merge_components(records, &components, &medium_peers)
    }

    fn compute_pair_weights(&self, records: &[DeviceRecord]) -> Vec<(usize, usize, f64)> {
        let mut buckets: HashMap<BucketKey, Vec<usize>> = HashMap::new();
        for (idx, record) in records.iter().enumerate() {
            for key in self.bucket_keys(record) {
                buckets.entry(key).or_default().push(idx);
            }
        }

        let mut candidates: HashSet<(usize, usize)> = HashSet::new();
        for indices in buckets.values() {
            for a in 0..indices.len() {
                for b in (a + 1)..indices.len() {
                    candidates.insert((indices[a], indices[b]));
                }
            }
        }

        let mut out = Vec::new();
        for (i, j) in candidates {
            let w = self.pair_weight(&records[i], &records[j]);
            if w > 0.0 {
                out.push((i, j, w));
            }
        }
        out
    }

    fn bucket_keys(&self, record: &DeviceRecord) -> HashSet<BucketKey> {
        let mut keys = HashSet::new();
        if let Some(mac) = record.mac.as_deref() {
            // Virtual/VRRP MACs are shared by every group member: bucketing on one would
            // collapse the whole group into a single O(n²) bucket and diverge from contribute_mac.
            if !is_virtual_mac(mac) && !hint_says_virtual(&self.hints, mac) {
                keys.insert(BucketKey::Mac(normalize_mac(mac)));
            }
        }
        if let Some(name) = find_sysname(&record.signals) {
            if !name.is_empty() {
                keys.insert(BucketKey::SysName(name.to_ascii_lowercase()));
            }
        }
        if let Some(host_key) = find_ssh_host_key(&record.signals) {
            if !host_key.is_empty() {
                keys.insert(BucketKey::SshHostKey(host_key.to_string()));
            }
        }
        if let Some(subject) = find_tls_subject(&record.signals) {
            if !subject.is_empty() {
                keys.insert(BucketKey::TlsSubject(subject.to_string()));
            }
        }
        for name in collect_tls_san_names(&record.signals) {
            if !name.is_empty() {
                keys.insert(BucketKey::TlsSanName(name.to_string()));
            }
        }
        for name in collect_reverse_dns_names(&record.signals) {
            if !name.is_empty() {
                keys.insert(BucketKey::ReverseDnsName(name.to_ascii_lowercase()));
            }
        }
        keys
    }

    fn pair_weight(&self, a: &DeviceRecord, b: &DeviceRecord) -> f64 {
        let mut w: f64 = CONTRIBUTIONS.iter().map(|f| f(&self.hints, a, b)).sum();

        if let (Some(mfa), Some(mfb)) = (a.manufacturer.as_deref(), b.manufacturer.as_deref()) {
            if !mfa.eq_ignore_ascii_case(mfb) {
                w -= PENALTY_CONFLICTING_MANUFACTURER;
            }
        }

        if self.pair_is_declared_vrrp_members(a, b) && w > VRRP_MEMBER_WEIGHT_CAP {
            w = VRRP_MEMBER_WEIGHT_CAP;
        }

        w
    }

    fn pair_is_declared_vrrp_members(&self, a: &DeviceRecord, b: &DeviceRecord) -> bool {
        let ip_a = match a.mgmt_ip {
            Some(ip) => ip,
            None => return false,
        };
        let ip_b = match b.mgmt_ip {
            Some(ip) => ip,
            None => return false,
        };
        self.hints
            .vrrp_groups
            .iter()
            .any(|g| g.members.contains(&ip_a) && g.members.contains(&ip_b))
    }
}

#[cfg(test)]
impl IdentityFuser {
    fn compute_pair_weights_bruteforce(
        &self,
        records: &[DeviceRecord],
    ) -> Vec<(usize, usize, f64)> {
        let mut out = Vec::new();
        for i in 0..records.len() {
            for j in (i + 1)..records.len() {
                let w = self.pair_weight(&records[i], &records[j]);
                if w > 0.0 {
                    out.push((i, j, w));
                }
            }
        }
        out
    }

    fn correlate_bruteforce(&self, records: Vec<DeviceRecord>) -> Vec<DeviceRecord> {
        if records.len() <= 1 {
            return records;
        }
        let n = records.len();
        let weights = self.compute_pair_weights_bruteforce(&records);
        let mut uf = UnionFind::new(n);
        for (i, j, w) in weights.iter().copied() {
            if w >= HIGH_BAND_THRESHOLD {
                uf.union(i, j);
            }
        }
        let medium_peers = collect_medium_peers(n, &weights, &uf);
        let components = uf.components();
        merge_components(records, &components, &medium_peers)
    }
}

impl Fuser for IdentityFuser {
    // Correlation needs the whole record set, so hold inner records until finish.
    fn ingest(&mut self, outcomes: Vec<ProbeOutcome>) -> Result<Vec<DeviceRecord>, RastreoError> {
        let records = self.inner.ingest(outcomes)?;
        self.buffer.extend(records);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> Result<Vec<DeviceRecord>, RastreoError> {
        let tail = self.inner.finish()?;
        self.buffer.extend(tail);
        let buffered = std::mem::take(&mut self.buffer);
        Ok(self.correlate(buffered))
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum BucketKey {
    Mac(String),
    SysName(String),
    SshHostKey(String),
    TlsSubject(String),
    TlsSanName(String),
    ReverseDnsName(String),
}

type ContributionFn = fn(&IdentityHints, &DeviceRecord, &DeviceRecord) -> f64;

const CONTRIBUTIONS: &[ContributionFn] = &[
    contribute_mac,
    contribute_sysname,
    contribute_ssh_host_key,
    contribute_tls_subject,
    contribute_tls_san,
    contribute_reverse_dns,
];

fn contribute_mac(hints: &IdentityHints, a: &DeviceRecord, b: &DeviceRecord) -> f64 {
    let (Some(ma), Some(mb)) = (a.mac.as_deref(), b.mac.as_deref()) else {
        return 0.0;
    };
    if mac_equal(ma, mb) && !is_virtual_mac(ma) && !hint_says_virtual(hints, ma) {
        WEIGHT_SHARED_MAC
    } else {
        0.0
    }
}

fn contribute_sysname(_hints: &IdentityHints, a: &DeviceRecord, b: &DeviceRecord) -> f64 {
    let (Some(sa), Some(sb)) = (find_sysname(&a.signals), find_sysname(&b.signals)) else {
        return 0.0;
    };
    if !sa.is_empty() && sa.eq_ignore_ascii_case(sb) {
        WEIGHT_SHARED_SYSNAME
    } else {
        0.0
    }
}

fn contribute_ssh_host_key(_hints: &IdentityHints, a: &DeviceRecord, b: &DeviceRecord) -> f64 {
    let (Some(ka), Some(kb)) = (find_ssh_host_key(&a.signals), find_ssh_host_key(&b.signals))
    else {
        return 0.0;
    };
    if !ka.is_empty() && ka == kb {
        WEIGHT_SHARED_HOST_KEY
    } else {
        0.0
    }
}

fn contribute_tls_subject(_hints: &IdentityHints, a: &DeviceRecord, b: &DeviceRecord) -> f64 {
    let (Some(sa), Some(sb)) = (find_tls_subject(&a.signals), find_tls_subject(&b.signals)) else {
        return 0.0;
    };
    if !sa.is_empty() && sa == sb {
        WEIGHT_SHARED_TLS_SUBJECT
    } else {
        0.0
    }
}

fn contribute_tls_san(_hints: &IdentityHints, a: &DeviceRecord, b: &DeviceRecord) -> f64 {
    let sans_a = collect_tls_san_names(&a.signals);
    let sans_b = collect_tls_san_names(&b.signals);
    if !sans_a.is_empty() && !sans_b.is_empty() && any_tls_san_overlap(&sans_a, &sans_b) {
        WEIGHT_SHARED_TLS_SAN
    } else {
        0.0
    }
}

fn contribute_reverse_dns(_hints: &IdentityHints, a: &DeviceRecord, b: &DeviceRecord) -> f64 {
    let rdns_a = collect_reverse_dns_names(&a.signals);
    let rdns_b = collect_reverse_dns_names(&b.signals);
    if !rdns_a.is_empty() && !rdns_b.is_empty() && any_reverse_dns_overlap(&rdns_a, &rdns_b) {
        WEIGHT_SHARED_REVERSE_DNS
    } else {
        0.0
    }
}

fn hint_says_virtual(hints: &IdentityHints, mac: &str) -> bool {
    hints
        .vrrp_groups
        .iter()
        .any(|g| mac_equal(&g.virtual_mac, mac))
}

fn find_sysname(signals: &[Signal]) -> Option<&str> {
    signals.iter().find_map(|s| match s {
        Signal::SnmpSysName(n) => Some(n.as_str()),
        _ => None,
    })
}

fn find_ssh_host_key(signals: &[Signal]) -> Option<&str> {
    signals.iter().find_map(|s| match s {
        Signal::SshHostKey(k) => Some(k.as_str()),
        _ => None,
    })
}

fn find_tls_subject(signals: &[Signal]) -> Option<&str> {
    signals.iter().find_map(|s| match s {
        Signal::TlsSubject(v) => Some(v.as_str()),
        _ => None,
    })
}

fn collect_tls_san_names(signals: &[Signal]) -> Vec<&str> {
    signals
        .iter()
        .filter_map(|s| match s {
            Signal::TlsSanName(v) => Some(v.as_str()),
            _ => None,
        })
        .collect()
}

fn any_tls_san_overlap(a: &[&str], b: &[&str]) -> bool {
    a.iter().any(|name| !name.is_empty() && b.contains(name))
}

fn collect_reverse_dns_names(signals: &[Signal]) -> Vec<&str> {
    signals
        .iter()
        .filter_map(|s| match s {
            Signal::ReverseDnsName(v) => Some(v.as_str()),
            _ => None,
        })
        .collect()
}

fn any_reverse_dns_overlap(a: &[&str], b: &[&str]) -> bool {
    a.iter()
        .any(|name| !name.is_empty() && b.iter().any(|other| name.eq_ignore_ascii_case(other)))
}

fn collect_medium_peers(
    n: usize,
    weights: &[(usize, usize, f64)],
    uf: &UnionFind,
) -> Vec<Vec<MediumPeer>> {
    let mut out: Vec<Vec<MediumPeer>> = vec![Vec::new(); n];
    for &(i, j, w) in weights {
        if w >= HIGH_BAND_THRESHOLD {
            continue;
        }
        if w < MEDIUM_BAND_THRESHOLD {
            continue;
        }
        // Skip peers that end up in the same merged component anyway.
        if uf.find(i) == uf.find(j) {
            continue;
        }
        out[i].push(MediumPeer {
            peer_index: j,
            weight: w,
        });
        out[j].push(MediumPeer {
            peer_index: i,
            weight: w,
        });
    }
    out
}

fn merge_components(
    records: Vec<DeviceRecord>,
    components: &[usize],
    medium_peers: &[Vec<MediumPeer>],
) -> Vec<DeviceRecord> {
    let n = records.len();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut root_to_group: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();

    for (i, &root) in components.iter().enumerate().take(n) {
        let idx = *root_to_group.entry(root).or_insert_with(|| {
            let g = groups.len();
            groups.push(Vec::new());
            g
        });
        groups[idx].push(i);
    }

    // Snapshot identity keys + confidences up-front: merges consume records, so peer
    // lookups later in the loop would otherwise see holes.
    let snapshot: Vec<(crate::model::device::IdentityKey, f64)> = records
        .iter()
        .map(|r| (r.identity_key.clone(), r.confidence.value()))
        .collect();

    let mut opt_records: Vec<Option<DeviceRecord>> = records.into_iter().map(Some).collect();

    let mut out = Vec::with_capacity(groups.len());
    for members in &groups {
        if members.len() == 1 {
            let idx = members[0];
            let mut r = opt_records[idx].take().expect("record present");
            if let Some(peer) = pick_best_medium_peer(&medium_peers[idx], &snapshot) {
                r.possible_alias_of = Some(peer);
            }
            out.push(r);
        } else {
            let merged = merge_group(&mut opt_records, members);
            out.push(merged);
        }
    }
    out
}

fn pick_best_medium_peer(
    peers: &[MediumPeer],
    snapshot: &[(crate::model::device::IdentityKey, f64)],
) -> Option<crate::model::device::IdentityKey> {
    let mut best: Option<(usize, f64, f64)> = None;
    for peer in peers {
        let (_, peer_conf) = &snapshot[peer.peer_index];
        let peer_conf = *peer_conf;
        let candidate = (peer.peer_index, peer_conf, peer.weight);
        best = Some(match best {
            None => candidate,
            Some(current) => {
                let (_, cur_conf, cur_weight) = current;
                let take = peer_conf > cur_conf
                    || (peer_conf == cur_conf && peer.weight > cur_weight)
                    || (peer_conf == cur_conf
                        && peer.weight == cur_weight
                        && candidate.0 < current.0);
                if take {
                    candidate
                } else {
                    current
                }
            }
        });
    }
    best.map(|(idx, _, _)| snapshot[idx].0.clone())
}

fn merge_group(records: &mut [Option<DeviceRecord>], member_indices: &[usize]) -> DeviceRecord {
    // Highest-confidence record wins on non-list fields; ties broken by first-appearance order.
    let mut best_idx = member_indices[0];
    let mut best_conf = records[best_idx]
        .as_ref()
        .expect("record present")
        .confidence
        .value();
    for &i in &member_indices[1..] {
        let c = records[i]
            .as_ref()
            .expect("record present")
            .confidence
            .value();
        if c > best_conf {
            best_conf = c;
            best_idx = i;
        }
    }

    let first_idx = member_indices[0];
    let mgmt_ip = records[first_idx].as_ref().and_then(|r| r.mgmt_ip);

    let mut alt_ips: Vec<AltIp> = Vec::new();
    let mut seen_ips: HashSet<IpAddr> = HashSet::new();
    if let Some(ip) = mgmt_ip {
        seen_ips.insert(ip);
    }
    for &i in member_indices {
        if i == first_idx {
            continue;
        }
        if let Some(r) = records[i].as_ref() {
            let Some(ip) = r.mgmt_ip else { continue };
            if !seen_ips.contains(&ip) {
                seen_ips.insert(ip);
                let role = altip_role_from_mac(r.mac.as_deref());
                let responded_via = r.probe_kinds.clone();
                alt_ips.push(AltIp {
                    address: ip,
                    role,
                    responded_via,
                });
            }
        }
    }

    let mac = records[best_idx]
        .as_ref()
        .and_then(|r| r.mac.clone())
        .or_else(|| {
            for &i in member_indices {
                if let Some(r) = records[i].as_ref() {
                    if r.mac.is_some() {
                        return r.mac.clone();
                    }
                }
            }
            None
        });

    let (manufacturer, platform, os_version, ssh_version, http_server, http_version, role) = {
        let best = records[best_idx].as_ref().expect("record present");
        (
            best.manufacturer
                .clone()
                .or_else(|| first_non_none(records, member_indices, |r| r.manufacturer.clone())),
            best.platform
                .clone()
                .or_else(|| first_non_none(records, member_indices, |r| r.platform.clone())),
            best.os_version
                .clone()
                .or_else(|| first_non_none(records, member_indices, |r| r.os_version.clone())),
            best.ssh_version
                .clone()
                .or_else(|| first_non_none(records, member_indices, |r| r.ssh_version.clone())),
            best.http_server
                .clone()
                .or_else(|| first_non_none(records, member_indices, |r| r.http_server.clone())),
            best.http_version
                .clone()
                .or_else(|| first_non_none(records, member_indices, |r| r.http_version.clone())),
            best.role
                .clone()
                .or_else(|| first_non_none(records, member_indices, |r| r.role.clone())),
        )
    };

    let raw_conf = (best_conf + MERGE_CONFIDENCE_BONUS).clamp(0.0, 1.0);
    let confidence = Confidence::new(raw_conf).expect("clamped confidence is valid");

    let mut last_seen = records[best_idx]
        .as_ref()
        .expect("record present")
        .last_seen;
    for &i in member_indices {
        if let Some(r) = records[i].as_ref() {
            if r.last_seen > last_seen {
                last_seen = r.last_seen;
            }
        }
    }

    let mut signals: Vec<Signal> = Vec::new();
    for &i in member_indices {
        if let Some(r) = records[i].as_ref() {
            for s in &r.signals {
                if !signals.iter().any(|existing| existing == s) {
                    signals.push(s.clone());
                }
            }
        }
    }

    let mut probe_kinds: Vec<ProbeKind> = Vec::new();
    for &i in member_indices {
        if let Some(r) = records[i].as_ref() {
            for k in &r.probe_kinds {
                if !probe_kinds.contains(k) {
                    probe_kinds.push(*k);
                }
            }
        }
    }

    let best = records[best_idx].take().expect("record present");

    DeviceRecord {
        identity_key: best.identity_key,
        mgmt_ip,
        mac,
        manufacturer,
        platform,
        os_version,
        ssh_version,
        http_server,
        http_version,
        role,
        confidence,
        last_seen,
        signals,
        probe_kinds,
        schema_version: best.schema_version,
        schema_id: best.schema_id,
        alt_ips,
        possible_alias_of: None,
        scan_metadata: best.scan_metadata,
    }
}

fn first_non_none<F>(
    records: &[Option<DeviceRecord>],
    member_indices: &[usize],
    f: F,
) -> Option<String>
where
    F: Fn(&DeviceRecord) -> Option<String>,
{
    for &i in member_indices {
        if let Some(r) = records[i].as_ref() {
            if let Some(v) = f(r) {
                return Some(v);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
struct MediumPeer {
    peer_index: usize,
    weight: f64,
}

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&self, x: usize) -> usize {
        let mut cur = x;
        while self.parent[cur] != cur {
            cur = self.parent[cur];
        }
        cur
    }

    fn find_mut(&mut self, x: usize) -> usize {
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut cur = x;
        while self.parent[cur] != root {
            let next = self.parent[cur];
            self.parent[cur] = root;
            cur = next;
        }
        root
    }

    fn union(&mut self, a: usize, b: usize) {
        let ra = self.find_mut(a);
        let rb = self.find_mut(b);
        if ra == rb {
            return;
        }
        if self.rank[ra] < self.rank[rb] {
            self.parent[ra] = rb;
        } else if self.rank[ra] > self.rank[rb] {
            self.parent[rb] = ra;
        } else {
            self.parent[rb] = ra;
            self.rank[ra] += 1;
        }
    }

    fn components(&self) -> Vec<usize> {
        (0..self.parent.len()).map(|i| self.find(i)).collect()
    }
}

pub(crate) fn is_virtual_mac(mac: &str) -> bool {
    let bytes = match parse_mac_prefix(mac) {
        Some(b) => b,
        None => return false,
    };
    bytes == VRRP_V2_IPV4_PREFIX || bytes == VRRP_V3_IPV6_PREFIX || bytes == HSRP_PREFIX
}

fn altip_role_from_mac(mac: Option<&str>) -> Option<AltIpRole> {
    let bytes = match mac.and_then(parse_mac_prefix) {
        Some(b) => b,
        // An IP that merged into another device is a secondary by definition, even without a MAC.
        None => return Some(AltIpRole::Secondary),
    };
    if bytes == VRRP_V2_IPV4_PREFIX || bytes == VRRP_V3_IPV6_PREFIX {
        // CARP shares the VRRPv2 prefix; MAC alone can't distinguish them.
        Some(AltIpRole::Vrrp)
    } else if bytes == HSRP_PREFIX {
        Some(AltIpRole::Hsrp)
    } else {
        Some(AltIpRole::Secondary)
    }
}

fn parse_mac_prefix(mac: &str) -> Option<[u8; 5]> {
    let hex_count = mac.chars().filter(|ch| *ch != ':' && *ch != '-').count();
    if hex_count != 12 {
        return None;
    }
    let mut bytes = [0u8; 5];
    let mut hi: Option<u8> = None;
    let mut byte_idx = 0;
    for c in mac.chars() {
        if c == ':' || c == '-' {
            continue;
        }
        let nibble = c.to_digit(16)? as u8;
        match hi {
            None => hi = Some(nibble),
            Some(h) => {
                if byte_idx == 5 {
                    return Some(bytes);
                }
                bytes[byte_idx] = (h << 4) | nibble;
                byte_idx += 1;
                hi = None;
            }
        }
    }
    if byte_idx != 5 || hi.is_some() {
        return None;
    }
    Some(bytes)
}

fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| *c != ':' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn mac_equal(a: &str, b: &str) -> bool {
    normalize_mac(a) == normalize_mac(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use crate::fuser::DirectFuser;
    use crate::model::device::{IdentityKey, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION};
    use crate::model::scan::ScanMetadata;

    fn base_record(
        ip_last_octet: u8,
        mac: Option<&str>,
        signals: Vec<Signal>,
        confidence: f64,
    ) -> DeviceRecord {
        base_record_with_kinds(ip_last_octet, mac, signals, confidence, Vec::new())
    }

    fn base_record_with_kinds(
        ip_last_octet: u8,
        mac: Option<&str>,
        signals: Vec<Signal>,
        confidence: f64,
        probe_kinds: Vec<ProbeKind>,
    ) -> DeviceRecord {
        let identity_value = match mac {
            Some(m) => format!("mac:{m}"),
            None => format!("ip:10.0.0.{ip_last_octet}"),
        };
        DeviceRecord {
            identity_key: IdentityKey::new(identity_value).expect("valid key"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip_last_octet))),
            mac: mac.map(str::to_string),
            manufacturer: None,
            platform: None,
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: None,
            confidence: Confidence::new(confidence).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals,
            probe_kinds,
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    fn make_fuser(hints: IdentityHints) -> IdentityFuser {
        IdentityFuser::new(Box::new(DirectFuser::new()), hints).expect("new fuser")
    }

    fn correlate(records: Vec<DeviceRecord>) -> Vec<DeviceRecord> {
        let f = make_fuser(IdentityHints::default());
        f.correlate(records)
    }

    #[test]
    fn is_virtual_mac_detects_prefix_case_insensitive() {
        assert!(is_virtual_mac("00:00:5e:00:01:0A"));
        assert!(is_virtual_mac("00:00:5E:00:01:0a"));
        assert!(is_virtual_mac("00-00-5E-00-01-0A"));
        assert!(is_virtual_mac("00005E00010A"));
        assert!(!is_virtual_mac("aa:bb:cc:dd:ee:ff"));
        assert!(!is_virtual_mac("not-a-mac"));
    }

    #[test]
    fn vrrp_ipv4_virtual_mac_detected_and_ignored() {
        let records = vec![
            base_record(
                1,
                Some("00:00:5e:00:01:0a"),
                vec![Signal::Mac("00:00:5e:00:01:0a".into())],
                0.2,
            ),
            base_record(
                2,
                Some("00:00:5e:00:01:0a"),
                vec![Signal::Mac("00:00:5e:00:01:0a".into())],
                0.2,
            ),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2, "virtual MAC alone must not merge");
        assert!(out.iter().all(|r| r.possible_alias_of.is_none()));
    }

    #[test]
    fn vrrp_ipv6_virtual_mac_detected_and_ignored() {
        let records = vec![
            base_record(1, Some("00:00:5e:00:02:0a"), vec![], 0.2),
            base_record(2, Some("00:00:5e:00:02:0a"), vec![], 0.2),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn hsrp_virtual_mac_detected_and_ignored() {
        let records = vec![
            base_record(1, Some("00:00:0c:07:ac:01"), vec![], 0.2),
            base_record(2, Some("00:00:0c:07:ac:01"), vec![], 0.2),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn single_record_pass_through() {
        let records = vec![base_record(1, Some("aa:bb:cc:dd:ee:ff"), vec![], 0.3)];
        let out = correlate(records);
        assert_eq!(out.len(), 1);
        assert!(out[0].alt_ips.is_empty());
        assert!(out[0].possible_alias_of.is_none());
    }

    #[test]
    fn two_records_shared_mac_and_sysname_merge() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let records = vec![
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.4,
            ),
            base_record(
                2,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1, "high band should merge");
        let r = &out[0];
        assert_eq!(r.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(r.alt_ips.len(), 1);
        assert_eq!(r.alt_ips[0].address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(r.alt_ips[0].role, Some(AltIpRole::Secondary));
        assert!(r.possible_alias_of.is_none());
    }

    #[test]
    fn two_records_shared_mac_only_stays_separate() {
        let mac = "aa:bb:cc:11:22:33";
        let records = vec![
            base_record(1, Some(mac), vec![Signal::Mac(mac.into())], 0.3),
            base_record(2, Some(mac), vec![Signal::Mac(mac.into())], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2, "shared MAC alone: medium band, not merged");
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn two_records_shared_sysname_only_stays_separate() {
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let records = vec![
            base_record(1, None, vec![sysname.clone()], 0.3),
            base_record(2, None, vec![sysname.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2);
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn two_records_virtual_vrrp_mac_stays_separate() {
        let mac = "00:00:5e:00:01:0a";
        let records = vec![
            base_record(1, Some(mac), vec![Signal::Mac(mac.into())], 0.3),
            base_record(2, Some(mac), vec![Signal::Mac(mac.into())], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| r.possible_alias_of.is_none()));
    }

    #[test]
    fn two_records_virtual_vrrp_mac_plus_sysname_medium_band() {
        let mac = "00:00:5e:00:01:0a";
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let records = vec![
            base_record(1, Some(mac), vec![sysname.clone()], 0.3),
            base_record(2, Some(mac), vec![sysname.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2, "sysName alone = 0.5, medium band");
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn two_records_shared_mac_but_conflicting_manufacturer_stays_separate() {
        let mac = "aa:bb:cc:11:22:33";
        let mut a = base_record(1, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        a.manufacturer = Some("Cisco Systems, Inc".into());
        let mut b = base_record(2, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        b.manufacturer = Some("Juniper Networks".into());
        let out = correlate(vec![a, b]);
        assert_eq!(out.len(), 2);
        assert!(
            out.iter().all(|r| r.possible_alias_of.is_none()),
            "0.5 - 0.3 = 0.2, below medium band"
        );
    }

    #[test]
    fn two_records_shared_mac_and_sysname_but_conflicting_manufacturer_medium_band() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let mut a = base_record(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        a.manufacturer = Some("Cisco Systems, Inc".into());
        let mut b = base_record(
            2,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        b.manufacturer = Some("Juniper Networks".into());
        let out = correlate(vec![a, b]);
        assert_eq!(out.len(), 2, "1.0 - 0.3 = 0.7, medium band, no merge");
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn three_records_transitive_merge() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let a = base_record(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let b = base_record(
            2,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let c = base_record(
            3,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let out = correlate(vec![a, b, c]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].alt_ips.len(), 2);
    }

    #[test]
    fn merged_record_takes_first_target_ip_as_mgmt_ip() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core".into());
        let out = correlate(vec![
            base_record(
                7,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mgmt_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))));
    }

    #[test]
    fn merged_record_populates_alt_ips_in_source_order() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core".into());
        let out = correlate(vec![
            base_record(
                7,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
            base_record(
                5,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
        ]);
        let addresses: Vec<IpAddr> = out[0].alt_ips.iter().map(|a| a.address).collect();
        assert_eq!(
            addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            ]
        );
    }

    #[test]
    fn merged_record_gets_confidence_bonus() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core".into());
        let out = correlate(vec![
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
            base_record(
                2,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.5,
            ),
        ]);
        assert!((out[0].confidence.value() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn merged_record_confidence_clamps_at_one() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core".into());
        let out = correlate(vec![
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.95,
            ),
            base_record(
                2,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.95,
            ),
        ]);
        assert_eq!(out[0].confidence.value(), 1.0);
    }

    #[test]
    fn merged_record_merges_signals_deduplicated() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core".into());
        let a = base_record(
            1,
            Some(mac),
            vec![
                Signal::Mac(mac.into()),
                sysname.clone(),
                Signal::OpenPort(22),
            ],
            0.3,
        );
        let b = base_record(
            2,
            Some(mac),
            vec![
                Signal::Mac(mac.into()),
                sysname.clone(),
                Signal::OpenPort(80),
            ],
            0.3,
        );
        let out = correlate(vec![a, b]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].signals.len(), 4);
    }

    #[test]
    fn merged_record_takes_max_last_seen() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core".into());
        let mut a = base_record(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let mut b = base_record(
            2,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let t_late = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        a.last_seen = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        b.last_seen = t_late;
        let out = correlate(vec![a, b]);
        assert_eq!(out[0].last_seen, t_late);
    }

    #[test]
    fn medium_band_pair_populates_possible_alias_of_bidirectionally() {
        let mac = "aa:bb:cc:11:22:33";
        let records = vec![
            base_record(1, Some(mac), vec![Signal::Mac(mac.into())], 0.3),
            base_record(2, Some(mac), vec![Signal::Mac(mac.into())], 0.3),
        ];
        let out = correlate(records);
        let key0 = &out[0].possible_alias_of.as_ref().expect("bi-directional");
        let key1 = &out[1].possible_alias_of.as_ref().expect("bi-directional");
        assert_eq!(key0.as_str(), out[1].identity_key.as_str());
        assert_eq!(key1.as_str(), out[0].identity_key.as_str());
    }

    #[test]
    fn possible_alias_of_picks_highest_confidence_peer_on_ties() {
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let low = base_record(1, None, vec![sysname.clone()], 0.2);
        let peer_high = base_record(
            2,
            Some("aa:bb:cc:11:22:33"),
            vec![Signal::Mac("aa:bb:cc:11:22:33".into()), sysname.clone()],
            0.7,
        );
        let peer_low = base_record(
            3,
            Some("dd:ee:ff:44:55:66"),
            vec![Signal::Mac("dd:ee:ff:44:55:66".into()), sysname.clone()],
            0.5,
        );
        let out = correlate(vec![low, peer_high, peer_low]);
        assert_eq!(out.len(), 3);
        let identities: Vec<&str> = out.iter().map(|r| r.identity_key.as_str()).collect();
        assert_eq!(
            identities,
            vec![
                "ip:10.0.0.1",
                "mac:aa:bb:cc:11:22:33",
                "mac:dd:ee:ff:44:55:66"
            ],
            "peers must have distinct identity keys so the tiebreak is observable",
        );
        let alias_low = out[0].possible_alias_of.as_ref().expect("some");
        assert_eq!(alias_low.as_str(), "mac:aa:bb:cc:11:22:33");
    }

    #[test]
    fn user_declared_vrrp_virtual_mac_ignored_via_hints() {
        let mac = "de:ad:be:ef:00:01";
        let sysname = Signal::SnmpSysName("core".into());
        let hints = IdentityHints {
            vrrp_groups: vec![VrrpGroup {
                virtual_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
                virtual_mac: mac.into(),
                members: vec![],
            }],
        };
        let f = IdentityFuser::new(Box::new(DirectFuser::new()), hints).expect("new");
        let records = vec![
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
            base_record(
                2,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
        ];
        let out = f.correlate(records);
        assert_eq!(out.len(), 2, "user-declared virtual MAC contributes 0");
        assert!(
            out[0].possible_alias_of.is_some(),
            "sysName alone = 0.5, medium band"
        );
    }

    #[test]
    fn user_declared_vrrp_members_stay_separate_via_hints_even_with_matching_mac() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core".into());
        let hints = IdentityHints {
            vrrp_groups: vec![VrrpGroup {
                virtual_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
                virtual_mac: "00:00:5e:00:01:0a".into(),
                members: vec![
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                ],
            }],
        };
        let f = IdentityFuser::new(Box::new(DirectFuser::new()), hints).expect("new");
        let records = vec![
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
            base_record(
                2,
                Some(mac),
                vec![Signal::Mac(mac.into()), sysname.clone()],
                0.3,
            ),
        ];
        let out = f.correlate(records);
        assert_eq!(out.len(), 2, "member cap keeps them below medium");
    }

    #[test]
    fn constructor_rejects_invalid_virtual_mac_hint() {
        let hints = IdentityHints {
            vrrp_groups: vec![VrrpGroup {
                virtual_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
                virtual_mac: "not-a-mac".into(),
                members: vec![],
            }],
        };
        match IdentityFuser::new(Box::new(DirectFuser::new()), hints) {
            Ok(_) => panic!("must reject invalid MAC"),
            Err(e) => {
                let msg = format!("{e}");
                assert!(msg.contains("virtual_mac"), "msg was: {msg}");
            }
        }
    }

    #[test]
    fn zero_records_returns_empty_vec() {
        let out = correlate(vec![]);
        assert!(out.is_empty());
    }

    #[test]
    fn records_without_mac_or_sysname_stay_separate() {
        let out = correlate(vec![
            base_record(1, None, vec![Signal::OpenPort(22)], 0.2),
            base_record(2, None, vec![Signal::OpenPort(80)], 0.2),
        ]);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| r.possible_alias_of.is_none()));
    }

    #[test]
    fn identity_fuser_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IdentityFuser>();
        assert_send_sync::<IdentityHints>();
        assert_send_sync::<VrrpGroup>();
    }

    #[test]
    fn parse_mac_prefix_rejects_ten_hex_chars() {
        assert!(parse_mac_prefix("00:00:5e:00:01").is_none());
        assert!(parse_mac_prefix("0000:5e00:01").is_none());
        assert!(parse_mac_prefix("0000-5e00-01").is_none());
        assert!(parse_mac_prefix("00005e0001").is_none());
    }

    #[test]
    fn parse_mac_prefix_rejects_eleven_hex_chars() {
        assert!(parse_mac_prefix("00:00:5e:00:01:0").is_none());
        assert!(parse_mac_prefix("0000-5e0001-0").is_none());
        assert!(parse_mac_prefix("00005e00010").is_none());
    }

    #[test]
    fn parse_mac_prefix_accepts_twelve_hex_chars() {
        assert_eq!(
            parse_mac_prefix("00:00:5e:00:01:0a"),
            Some([0x00, 0x00, 0x5e, 0x00, 0x01])
        );
        assert_eq!(
            parse_mac_prefix("00-00-5e-00-01-0a"),
            Some([0x00, 0x00, 0x5e, 0x00, 0x01])
        );
        assert_eq!(
            parse_mac_prefix("00005e00010a"),
            Some([0x00, 0x00, 0x5e, 0x00, 0x01])
        );
    }

    #[test]
    fn constructor_rejects_short_virtual_mac_hint() {
        let hints = IdentityHints {
            vrrp_groups: vec![VrrpGroup {
                virtual_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                virtual_mac: "00:00:5e:00:01".to_string(),
                members: Vec::new(),
            }],
        };
        let result = IdentityFuser::new(Box::new(DirectFuser::new()), hints);
        match result {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("virtual_mac"), "msg was: {msg}");
            }
            Err(other) => panic!("expected ConfigError::InvalidValue, got {other:?}"),
            Ok(_) => panic!("expected ConfigError::InvalidValue, got Ok"),
        }
    }

    #[test]
    fn is_virtual_mac_rejects_short_input() {
        assert!(!is_virtual_mac("00:00:5e:00:01"));
        assert!(!is_virtual_mac("00:00:5e:00:01:0"));
        assert!(!is_virtual_mac("00005e0001"));
    }

    #[test]
    fn vrrp_group_new_rejects_invalid_mac() {
        let err = VrrpGroup::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "not-a-mac".to_string(),
            Vec::new(),
        )
        .expect_err("must reject");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("virtual_mac"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn vrrp_group_new_accepts_valid_mac() {
        let group = VrrpGroup::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "00:00:5e:00:01:0a".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        )
        .expect("valid");
        assert_eq!(group.virtual_mac, "00:00:5e:00:01:0a");
    }

    #[test]
    fn identity_hints_new_accepts_empty_vec() {
        let hints = IdentityHints::new(Vec::new());
        assert!(hints.vrrp_groups.is_empty());
    }

    #[test]
    fn merge_output_preserves_first_constituent_position() {
        let mac_ac = "aa:bb:cc:11:22:33";
        let sysname_ac = Signal::SnmpSysName("core-sw01".into());
        let a = base_record(
            1,
            Some(mac_ac),
            vec![Signal::Mac(mac_ac.into()), sysname_ac.clone()],
            0.3,
        );
        let b = base_record(
            2,
            Some("dd:ee:ff:44:55:66"),
            vec![
                Signal::Mac("dd:ee:ff:44:55:66".into()),
                Signal::SnmpSysName("other-host".into()),
            ],
            0.3,
        );
        let mut c = base_record(
            9,
            Some(mac_ac),
            vec![Signal::Mac(mac_ac.into()), sysname_ac.clone()],
            0.3,
        );
        c.mgmt_ip = Some("1.1.1.1".parse().unwrap());

        let out = correlate(vec![a, b, c]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].mgmt_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        let addresses: Vec<IpAddr> = out[0].alt_ips.iter().map(|a| a.address).collect();
        assert_eq!(addresses, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(out[1].mgmt_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    fn merge_two(a: DeviceRecord, b: DeviceRecord) -> DeviceRecord {
        let mut opts: Vec<Option<DeviceRecord>> = vec![Some(a), Some(b)];
        merge_group(&mut opts, &[0, 1])
    }

    #[test]
    fn altip_role_is_vrrp_when_merged_mac_matches_vrrp_prefix() {
        let real_mac = "aa:bb:cc:11:22:33";
        let primary = base_record(1, Some(real_mac), vec![Signal::Mac(real_mac.into())], 0.4);
        let vrrp_member = base_record(
            2,
            Some("00:00:5e:00:01:0a"),
            vec![Signal::Mac("00:00:5e:00:01:0a".into())],
            0.3,
        );
        let merged = merge_two(primary, vrrp_member);
        assert_eq!(merged.alt_ips.len(), 1);
        assert_eq!(merged.alt_ips[0].role, Some(AltIpRole::Vrrp));
    }

    #[test]
    fn altip_role_is_hsrp_when_merged_mac_matches_hsrp_prefix() {
        let real_mac = "aa:bb:cc:11:22:33";
        let primary = base_record(1, Some(real_mac), vec![Signal::Mac(real_mac.into())], 0.4);
        let hsrp_member = base_record(
            2,
            Some("00:00:0c:07:ac:01"),
            vec![Signal::Mac("00:00:0c:07:ac:01".into())],
            0.3,
        );
        let merged = merge_two(primary, hsrp_member);
        assert_eq!(merged.alt_ips.len(), 1);
        assert_eq!(merged.alt_ips[0].role, Some(AltIpRole::Hsrp));
    }

    #[test]
    fn altip_role_defaults_to_secondary_for_non_virtual_mac() {
        let mac = "aa:bb:cc:11:22:33";
        let primary = base_record(1, Some(mac), vec![Signal::Mac(mac.into())], 0.4);
        let secondary = base_record(2, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        let merged = merge_two(primary, secondary);
        assert_eq!(merged.alt_ips.len(), 1);
        assert_eq!(merged.alt_ips[0].role, Some(AltIpRole::Secondary));
    }

    #[test]
    fn altip_role_defaults_to_secondary_when_merged_record_has_no_mac() {
        let primary = base_record(
            1,
            Some("aa:bb:cc:11:22:33"),
            vec![Signal::Mac("aa:bb:cc:11:22:33".into())],
            0.4,
        );
        let no_mac_member = base_record(2, None, vec![], 0.3);
        let merged = merge_two(primary, no_mac_member);
        assert_eq!(merged.alt_ips.len(), 1);
        assert_eq!(merged.alt_ips[0].role, Some(AltIpRole::Secondary));
    }

    #[test]
    fn altip_responded_via_dedups_probe_kinds() {
        let mac = "aa:bb:cc:11:22:33";
        let primary = base_record_with_kinds(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into())],
            0.4,
            vec![ProbeKind::Arp],
        );
        let secondary = base_record_with_kinds(
            2,
            Some(mac),
            vec![
                Signal::Mac(mac.into()),
                Signal::SnmpSysName("core-sw01".into()),
                Signal::OpenPort(22),
                Signal::OpenPort(80),
            ],
            0.3,
            vec![ProbeKind::Arp, ProbeKind::Snmp, ProbeKind::TcpConnect],
        );
        let merged = merge_two(primary, secondary);
        assert_eq!(merged.alt_ips.len(), 1);
        assert_eq!(
            merged.alt_ips[0].responded_via,
            vec![ProbeKind::Arp, ProbeKind::Snmp, ProbeKind::TcpConnect],
        );
    }

    #[test]
    fn two_records_shared_ssh_host_key_alone_merge() {
        let key = Signal::SshHostKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI".into());
        let records = vec![
            base_record(1, None, vec![key.clone()], 0.3),
            base_record(2, None, vec![key.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1, "shared host key alone hits high band");
        assert_eq!(out[0].alt_ips.len(), 1);
        assert_eq!(
            out[0].alt_ips[0].address,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert!(out[0].possible_alias_of.is_none());
    }

    #[test]
    fn two_records_shared_ssh_host_key_and_mac_merge_high_confidence() {
        let mac = "aa:bb:cc:11:22:33";
        let key = Signal::SshHostKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI".into());
        let records = vec![
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), key.clone()],
                0.3,
            ),
            base_record(
                2,
                Some(mac),
                vec![Signal::Mac(mac.into()), key.clone()],
                0.3,
            ),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].alt_ips.len(), 1);
    }

    #[test]
    fn two_records_shared_ssh_host_key_but_conflicting_manufacturer_medium_band() {
        let key = Signal::SshHostKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI".into());
        let mut a = base_record(1, None, vec![key.clone()], 0.3);
        a.manufacturer = Some("Cisco Systems, Inc".into());
        let mut b = base_record(2, None, vec![key.clone()], 0.3);
        b.manufacturer = Some("Juniper Networks".into());
        let out = correlate(vec![a, b]);
        assert_eq!(out.len(), 2, "0.8 - 0.3 = 0.5, medium band");
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn two_records_different_ssh_host_keys_stay_separate() {
        let records = vec![
            base_record(
                1,
                None,
                vec![Signal::SshHostKey("ssh-ed25519 AAAA1111".into())],
                0.3,
            ),
            base_record(
                2,
                None,
                vec![Signal::SshHostKey("ssh-ed25519 AAAA2222".into())],
                0.3,
            ),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| r.possible_alias_of.is_none()));
    }

    #[test]
    fn two_records_one_empty_ssh_host_key_stays_separate() {
        let records = vec![
            base_record(
                1,
                None,
                vec![Signal::SshHostKey("ssh-ed25519 AAAAC3Nz".into())],
                0.3,
            ),
            base_record(2, None, vec![Signal::SshHostKey(String::new())], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| r.possible_alias_of.is_none()));
    }

    #[test]
    fn three_records_all_share_ssh_host_key_merge_into_one() {
        let key = Signal::SshHostKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI".into());
        let records = vec![
            base_record(1, None, vec![key.clone()], 0.3),
            base_record(2, None, vec![key.clone()], 0.3),
            base_record(3, None, vec![key.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].alt_ips.len(), 2);
    }

    #[test]
    fn altip_responded_via_preserves_source_order() {
        let mac = "aa:bb:cc:11:22:33";
        let primary = base_record_with_kinds(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into())],
            0.4,
            vec![ProbeKind::Arp],
        );
        let secondary = base_record_with_kinds(
            2,
            Some(mac),
            vec![
                Signal::OpenPort(22),
                Signal::Mac(mac.into()),
                Signal::SnmpSysName("core-sw01".into()),
            ],
            0.3,
            vec![ProbeKind::TcpConnect, ProbeKind::Arp, ProbeKind::Snmp],
        );
        let merged = merge_two(primary, secondary);
        assert_eq!(
            merged.alt_ips[0].responded_via,
            vec![ProbeKind::TcpConnect, ProbeKind::Arp, ProbeKind::Snmp],
        );
    }

    #[test]
    fn altip_responded_via_uses_probe_kinds_not_signal_inference() {
        let primary = base_record_with_kinds(
            1,
            Some("aa:bb:cc:11:22:33"),
            vec![Signal::Mac("aa:bb:cc:11:22:33".into())],
            0.4,
            vec![ProbeKind::Arp],
        );
        let http_only = base_record_with_kinds(
            2,
            Some("aa:bb:cc:11:22:33"),
            vec![
                Signal::Mac("aa:bb:cc:11:22:33".into()),
                Signal::OpenPort(80),
                Signal::HttpBanner("nginx/1.27".into()),
            ],
            0.3,
            vec![ProbeKind::Http],
        );
        let merged = merge_two(primary, http_only);
        assert_eq!(merged.alt_ips.len(), 1);
        assert_eq!(
            merged.alt_ips[0].responded_via,
            vec![ProbeKind::Http],
            "attribution must come from probe_kinds, not from signal inference",
        );
    }

    #[test]
    fn altip_responded_via_excludes_silent_probers() {
        let mac = "aa:bb:cc:11:22:33";
        let host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI";
        let outcome =
            |octet: u8, kind: ProbeKind, reachable: bool, signals: Vec<Signal>| ProbeOutcome {
                kind,
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable,
                signals,
                fault: None,
            };
        let mut f = make_fuser(IdentityHints::default());
        let outcomes = vec![
            outcome(1, ProbeKind::Arp, true, vec![Signal::Mac(mac.into())]),
            outcome(
                1,
                ProbeKind::Ssh,
                true,
                vec![Signal::SshHostKey(host_key.into())],
            ),
            outcome(2, ProbeKind::Arp, true, vec![Signal::Mac(mac.into())]),
            outcome(
                2,
                ProbeKind::Ssh,
                true,
                vec![Signal::SshHostKey(host_key.into())],
            ),
            outcome(2, ProbeKind::Snmp, false, vec![]),
        ];
        let records = crate::fuser::drive_fuser(&mut f, outcomes).expect("drive");
        assert_eq!(records.len(), 1, "shared MAC + host key merges both IPs");
        assert_eq!(records[0].alt_ips.len(), 1);
        assert_eq!(
            records[0].alt_ips[0].responded_via,
            vec![ProbeKind::Arp, ProbeKind::Ssh],
            "a silent snmp probe must not claim the device responded via snmp",
        );
    }

    #[test]
    fn identity_fuser_merges_probe_kinds_across_constituent_records() {
        let mac = "aa:bb:cc:11:22:33";
        let a = base_record_with_kinds(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into())],
            0.4,
            vec![ProbeKind::Http],
        );
        let b = base_record_with_kinds(
            2,
            Some(mac),
            vec![Signal::Mac(mac.into())],
            0.3,
            vec![ProbeKind::Snmp],
        );
        let merged = merge_two(a, b);
        assert_eq!(merged.probe_kinds, vec![ProbeKind::Http, ProbeKind::Snmp]);
    }

    #[test]
    fn two_records_shared_tls_subject_and_san_merge() {
        let subject = Signal::TlsSubject("router.example.com".into());
        let san = Signal::TlsSanName("router.example.com".into());
        let records = vec![
            base_record(1, None, vec![subject.clone(), san.clone()], 0.3),
            base_record(2, None, vec![subject.clone(), san.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1, "0.3 + 0.5 = 0.8, high band");
        assert_eq!(out[0].alt_ips.len(), 1);
        assert_eq!(
            out[0].alt_ips[0].address,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert!(out[0].possible_alias_of.is_none());
    }

    #[test]
    fn two_records_shared_tls_subject_only_stays_separate() {
        let subject = Signal::TlsSubject("router.example.com".into());
        let records = vec![
            base_record(1, None, vec![subject.clone()], 0.3),
            base_record(2, None, vec![subject.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2, "subject alone = 0.3, below medium band");
        assert!(out.iter().all(|r| r.possible_alias_of.is_none()));
    }

    #[test]
    fn two_records_shared_tls_san_only_medium_band() {
        let san = Signal::TlsSanName("router.example.com".into());
        let records = vec![
            base_record(1, None, vec![san.clone()], 0.3),
            base_record(2, None, vec![san.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2, "san alone = 0.5, medium band");
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn two_records_different_tls_subjects_and_sans_stay_separate() {
        let records = vec![
            base_record(
                1,
                None,
                vec![
                    Signal::TlsSubject("router-a.example.com".into()),
                    Signal::TlsSanName("router-a.example.com".into()),
                ],
                0.3,
            ),
            base_record(
                2,
                None,
                vec![
                    Signal::TlsSubject("router-b.example.com".into()),
                    Signal::TlsSanName("router-b.example.com".into()),
                ],
                0.3,
            ),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| r.possible_alias_of.is_none()));
    }

    #[test]
    fn two_records_shared_tls_ip_san_merges() {
        let subject = Signal::TlsSubject("router.example.com".into());
        let san = Signal::TlsSanName("ip:10.0.0.1".into());
        let records = vec![
            base_record(1, None, vec![subject.clone(), san.clone()], 0.3),
            base_record(2, None, vec![subject.clone(), san.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1, "IP SAN matches by byte-exact equality");
        assert_eq!(out[0].alt_ips.len(), 1);
    }

    #[test]
    fn two_records_shared_tls_subject_and_san_but_conflicting_manufacturer_medium_band() {
        let subject = Signal::TlsSubject("router.example.com".into());
        let san = Signal::TlsSanName("router.example.com".into());
        let mut a = base_record(1, None, vec![subject.clone(), san.clone()], 0.3);
        a.manufacturer = Some("Cisco Systems, Inc".into());
        let mut b = base_record(2, None, vec![subject.clone(), san.clone()], 0.3);
        b.manufacturer = Some("Juniper Networks".into());
        let out = correlate(vec![a, b]);
        assert_eq!(out.len(), 2, "0.3 + 0.5 - 0.3 = 0.5, medium band");
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn two_records_shared_reverse_dns_name_only_medium_band() {
        let rdns = Signal::ReverseDnsName("router.example.com".into());
        let records = vec![
            base_record(1, None, vec![rdns.clone()], 0.3),
            base_record(2, None, vec![rdns.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2, "reverse DNS alone = 0.5, medium band");
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn two_records_shared_reverse_dns_name_and_mac_merge() {
        let mac = "aa:bb:cc:11:22:33";
        let rdns = Signal::ReverseDnsName("router.example.com".into());
        let records = vec![
            base_record(
                1,
                Some(mac),
                vec![Signal::Mac(mac.into()), rdns.clone()],
                0.3,
            ),
            base_record(
                2,
                Some(mac),
                vec![Signal::Mac(mac.into()), rdns.clone()],
                0.3,
            ),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1, "0.5 + 0.5 = 1.0, high band");
        assert_eq!(out[0].alt_ips.len(), 1);
        assert_eq!(
            out[0].alt_ips[0].address,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert!(out[0].possible_alias_of.is_none());
    }

    #[test]
    fn two_records_shared_reverse_dns_name_and_sysname_merge() {
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let rdns = Signal::ReverseDnsName("core-sw01.example.com".into());
        let records = vec![
            base_record(1, None, vec![sysname.clone(), rdns.clone()], 0.3),
            base_record(2, None, vec![sysname.clone(), rdns.clone()], 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1, "0.5 + 0.5 = 1.0, high band");
        assert_eq!(out[0].alt_ips.len(), 1);
        assert!(out[0].possible_alias_of.is_none());
    }

    #[test]
    fn two_records_different_reverse_dns_names_stay_separate() {
        let records = vec![
            base_record(
                1,
                None,
                vec![Signal::ReverseDnsName("router-a.example.com".into())],
                0.3,
            ),
            base_record(
                2,
                None,
                vec![Signal::ReverseDnsName("router-b.example.com".into())],
                0.3,
            ),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| r.possible_alias_of.is_none()));
    }

    #[test]
    fn two_records_shared_reverse_dns_with_multiple_ptrs_any_overlap() {
        let mac = "aa:bb:cc:11:22:33";
        let a_signals = vec![
            Signal::Mac(mac.into()),
            Signal::ReverseDnsName("router.example.com".into()),
            Signal::ReverseDnsName("edge-01.example.com".into()),
        ];
        let b_signals = vec![
            Signal::Mac(mac.into()),
            Signal::ReverseDnsName("core-sw01.example.com".into()),
            Signal::ReverseDnsName("edge-01.example.com".into()),
            Signal::ReverseDnsName("mgmt-01.example.com".into()),
        ];
        let records = vec![
            base_record(1, Some(mac), a_signals, 0.3),
            base_record(2, Some(mac), b_signals, 0.3),
        ];
        let out = correlate(records);
        assert_eq!(out.len(), 1, "shared MAC 0.5 + any-overlap 0.5 = 1.0");
        assert_eq!(out[0].alt_ips.len(), 1);
    }

    #[test]
    fn two_records_shared_reverse_dns_matches_case_insensitively() {
        let mac = "aa:bb:cc:11:22:33";
        let a_signals = vec![
            Signal::Mac(mac.into()),
            Signal::ReverseDnsName("Router.Example.Com".into()),
        ];
        let b_signals = vec![
            Signal::Mac(mac.into()),
            Signal::ReverseDnsName("router.example.com".into()),
        ];
        let records = vec![
            base_record(1, Some(mac), a_signals, 0.3),
            base_record(2, Some(mac), b_signals, 0.3),
        ];
        let out = correlate(records);
        assert_eq!(
            out.len(),
            1,
            "case-insensitive PTR match + shared MAC merges"
        );
        assert_eq!(out[0].alt_ips.len(), 1);
    }

    #[test]
    fn two_records_shared_reverse_dns_and_mac_but_conflicting_manufacturer_medium_band() {
        let mac = "aa:bb:cc:11:22:33";
        let rdns = Signal::ReverseDnsName("router.example.com".into());
        let mut a = base_record(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into()), rdns.clone()],
            0.3,
        );
        a.manufacturer = Some("Cisco Systems, Inc".into());
        let mut b = base_record(
            2,
            Some(mac),
            vec![Signal::Mac(mac.into()), rdns.clone()],
            0.3,
        );
        b.manufacturer = Some("Juniper Networks".into());
        let out = correlate(vec![a, b]);
        assert_eq!(out.len(), 2, "0.5 + 0.5 - 0.3 = 0.7, medium band");
        assert!(out[0].possible_alias_of.is_some());
        assert!(out[1].possible_alias_of.is_some());
    }

    #[test]
    fn contributions_slice_covers_every_identity_signal() {
        assert_eq!(
            CONTRIBUTIONS.len(),
            6,
            "MAC, sysName, SSH host key, TLS subject, TLS SAN, reverse DNS",
        );
    }

    #[test]
    fn pair_weight_iterator_matches_pre_refactor_output_for_high_band_ssh_key() {
        let key = Signal::SshHostKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI".into());
        let a = base_record(1, None, vec![key.clone()], 0.3);
        let b = base_record(2, None, vec![key.clone()], 0.3);
        let f = make_fuser(IdentityHints::default());
        assert!((f.pair_weight(&a, &b) - WEIGHT_SHARED_HOST_KEY).abs() < 1e-9);
    }

    #[test]
    fn pair_weight_sums_mac_and_sysname_contributions() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let a = base_record(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let b = base_record(
            2,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let f = make_fuser(IdentityHints::default());
        let expected = WEIGHT_SHARED_MAC + WEIGHT_SHARED_SYSNAME;
        assert!((f.pair_weight(&a, &b) - expected).abs() < 1e-9);
    }

    #[test]
    fn pair_weight_subtracts_manufacturer_penalty_after_summing_contributions() {
        let mac = "aa:bb:cc:11:22:33";
        let mut a = base_record(1, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        a.manufacturer = Some("Cisco Systems, Inc".into());
        let mut b = base_record(2, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        b.manufacturer = Some("Juniper Networks".into());
        let f = make_fuser(IdentityHints::default());
        let expected = WEIGHT_SHARED_MAC - PENALTY_CONFLICTING_MANUFACTURER;
        assert!((f.pair_weight(&a, &b) - expected).abs() < 1e-9);
    }

    #[test]
    fn pair_weight_caps_declared_vrrp_members_at_medium_band_edge() {
        let mac = "aa:bb:cc:11:22:33";
        let sysname = Signal::SnmpSysName("core".into());
        let hints = IdentityHints {
            vrrp_groups: vec![VrrpGroup {
                virtual_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
                virtual_mac: "00:00:5e:00:01:0a".into(),
                members: vec![
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                ],
            }],
        };
        let a = base_record(
            1,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let b = base_record(
            2,
            Some(mac),
            vec![Signal::Mac(mac.into()), sysname.clone()],
            0.3,
        );
        let f = IdentityFuser::new(Box::new(DirectFuser::new()), hints).expect("fuser");
        assert!((f.pair_weight(&a, &b) - VRRP_MEMBER_WEIGHT_CAP).abs() < 1e-9);
    }

    #[test]
    fn contribute_mac_returns_zero_for_virtual_prefix() {
        let mac = "00:00:5e:00:01:0a";
        let a = base_record(1, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        let b = base_record(2, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        assert_eq!(contribute_mac(&IdentityHints::default(), &a, &b), 0.0);
    }

    #[test]
    fn contribute_mac_returns_zero_for_hint_declared_virtual() {
        let mac = "de:ad:be:ef:00:01";
        let hints = IdentityHints {
            vrrp_groups: vec![VrrpGroup {
                virtual_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
                virtual_mac: mac.into(),
                members: vec![],
            }],
        };
        let a = base_record(1, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        let b = base_record(2, Some(mac), vec![Signal::Mac(mac.into())], 0.3);
        assert_eq!(contribute_mac(&hints, &a, &b), 0.0);
    }

    #[test]
    fn contribute_sysname_returns_zero_for_empty_string() {
        let a = base_record(1, None, vec![Signal::SnmpSysName(String::new())], 0.3);
        let b = base_record(2, None, vec![Signal::SnmpSysName(String::new())], 0.3);
        assert_eq!(contribute_sysname(&IdentityHints::default(), &a, &b), 0.0);
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() >> 33) as usize % n
        }

        fn chance(&mut self, num: u64, den: u64) -> bool {
            self.next() % den < num
        }
    }

    const MAC_POOL: &[Option<&str>] = &[
        Some("aa:bb:cc:11:22:33"),
        Some("AA-BB-CC-11-22-33"),
        Some("dd:ee:ff:44:55:66"),
        Some("00:00:5e:00:01:0a"),
        Some("00:00:0c:07:ac:01"),
        Some("de:ad:be:ef:00:01"),
        None,
        None,
    ];
    const SYSNAME_POOL: &[&str] = &["core-sw01", "CORE-SW01", "edge-rtr02", "", "leaf-03"];
    const SSH_POOL: &[&str] = &["ssh-ed25519 AAAAKEY1", "ssh-rsa AAAAKEY2", ""];
    const TLS_SUBJECT_POOL: &[&str] = &["router.example.com", "sw.example.com", ""];
    const TLS_SAN_POOL: &[&str] = &["router.example.com", "vip.example.com", "ip:10.0.0.1", ""];
    const RDNS_POOL: &[&str] = &[
        "router.example.com",
        "Router.Example.Com",
        "host-a.example.com",
        "",
    ];
    const MFR_POOL: &[Option<&str>] = &[
        Some("Cisco Systems, Inc"),
        Some("Juniper Networks"),
        Some("cisco systems, inc"),
        None,
        None,
    ];

    fn random_record(lcg: &mut Lcg, octet: u8) -> DeviceRecord {
        let mac = MAC_POOL[lcg.below(MAC_POOL.len())];
        let mut signals = Vec::new();
        if let Some(m) = mac {
            signals.push(Signal::Mac(m.to_string()));
        }
        if lcg.chance(3, 4) {
            signals.push(Signal::SnmpSysName(
                SYSNAME_POOL[lcg.below(SYSNAME_POOL.len())].to_string(),
            ));
        }
        if lcg.chance(1, 2) {
            signals.push(Signal::SshHostKey(
                SSH_POOL[lcg.below(SSH_POOL.len())].to_string(),
            ));
        }
        if lcg.chance(1, 2) {
            signals.push(Signal::TlsSubject(
                TLS_SUBJECT_POOL[lcg.below(TLS_SUBJECT_POOL.len())].to_string(),
            ));
        }
        for _ in 0..lcg.below(3) {
            signals.push(Signal::TlsSanName(
                TLS_SAN_POOL[lcg.below(TLS_SAN_POOL.len())].to_string(),
            ));
        }
        for _ in 0..lcg.below(3) {
            signals.push(Signal::ReverseDnsName(
                RDNS_POOL[lcg.below(RDNS_POOL.len())].to_string(),
            ));
        }
        if lcg.chance(1, 2) {
            signals.push(Signal::OpenPort(22));
        }
        let confidence = 0.1 + (lcg.below(8) as f64) * 0.1;
        let mut record = base_record(octet, mac, signals, confidence);
        record.manufacturer = MFR_POOL[lcg.below(MFR_POOL.len())].map(str::to_string);
        record
    }

    fn hinted_fuser() -> IdentityFuser {
        make_fuser(IdentityHints {
            vrrp_groups: vec![VrrpGroup {
                virtual_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 250)),
                virtual_mac: "de:ad:be:ef:00:01".into(),
                members: vec![
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                ],
            }],
        })
    }

    fn assert_bucketed_matches_bruteforce(
        f: &IdentityFuser,
        records: &[DeviceRecord],
        label: &str,
    ) {
        let mut got = f.compute_pair_weights(records);
        let mut want = f.compute_pair_weights_bruteforce(records);
        got.sort_by_key(|t| (t.0, t.1));
        want.sort_by_key(|t| (t.0, t.1));
        assert_eq!(got, want, "{label}: pair-weight set diverged");

        let bucketed = f.correlate(records.to_vec());
        let brute = f.correlate_bruteforce(records.to_vec());
        assert_eq!(
            serde_json::to_string(&bucketed).expect("serialize bucketed"),
            serde_json::to_string(&brute).expect("serialize bruteforce"),
            "{label}: correlate output diverged",
        );
    }

    fn single_signal_corpus() -> Vec<DeviceRecord> {
        vec![
            base_record(
                1,
                Some("aa:bb:cc:11:22:33"),
                vec![Signal::Mac("aa:bb:cc:11:22:33".into())],
                0.3,
            ),
            base_record(
                2,
                Some("AA-BB-CC-11-22-33"),
                vec![Signal::Mac("AA-BB-CC-11-22-33".into())],
                0.3,
            ),
            base_record(3, None, vec![Signal::SnmpSysName("Core-SW01".into())], 0.3),
            base_record(4, None, vec![Signal::SnmpSysName("core-sw01".into())], 0.3),
            base_record(
                5,
                None,
                vec![Signal::SshHostKey("ssh-ed25519 AAAAKEY".into())],
                0.3,
            ),
            base_record(
                6,
                None,
                vec![Signal::SshHostKey("ssh-ed25519 AAAAKEY".into())],
                0.3,
            ),
            base_record(
                7,
                None,
                vec![Signal::TlsSubject("router.example.com".into())],
                0.3,
            ),
            base_record(
                8,
                None,
                vec![Signal::TlsSubject("router.example.com".into())],
                0.3,
            ),
            base_record(
                9,
                None,
                vec![Signal::TlsSanName("vip.example.com".into())],
                0.3,
            ),
            base_record(
                10,
                None,
                vec![Signal::TlsSanName("vip.example.com".into())],
                0.3,
            ),
            base_record(
                11,
                None,
                vec![Signal::ReverseDnsName("Host-A.example.com".into())],
                0.3,
            ),
            base_record(
                12,
                None,
                vec![Signal::ReverseDnsName("host-a.example.com".into())],
                0.3,
            ),
            base_record(13, None, vec![Signal::OpenPort(22)], 0.3),
            base_record(
                14,
                Some("99:99:99:99:99:99"),
                vec![Signal::Mac("99:99:99:99:99:99".into())],
                0.3,
            ),
        ]
    }

    #[test]
    fn bucketed_pair_weights_match_bruteforce_on_single_signal_corpus() {
        let records = single_signal_corpus();
        assert_bucketed_matches_bruteforce(
            &make_fuser(IdentityHints::default()),
            &records,
            "single-signal corpus",
        );
    }

    #[test]
    fn bucketed_pair_weights_match_bruteforce_over_random_corpora() {
        for seed in 0..300u64 {
            let mut lcg = Lcg(seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0xD1B5_4A32_D192_ED03));
            let n = 12 + lcg.below(30);
            let records: Vec<DeviceRecord> = (0..n)
                .map(|idx| random_record(&mut lcg, (idx + 1) as u8))
                .collect();
            assert_bucketed_matches_bruteforce(
                &make_fuser(IdentityHints::default()),
                &records,
                &format!("seed {seed} (default hints)"),
            );
            assert_bucketed_matches_bruteforce(
                &hinted_fuser(),
                &records,
                &format!("seed {seed} (vrrp hints)"),
            );
        }
    }

    mod differential {
        use super::*;
        use crate::error::ProbeErrorKind;
        use crate::fuser::{create_fuser, drive_fuser, group_outcomes_by_ip, FuserConfig};
        use crate::model::outcome::ProbeFault;

        fn fuse_many_batch(
            config: &FuserConfig,
            outcomes: Vec<ProbeOutcome>,
        ) -> Result<Vec<DeviceRecord>, RastreoError> {
            config.validate()?;
            match config {
                FuserConfig::Direct {
                    include_unreachable,
                    confidence_baseline,
                    confidence_per_signal,
                } => {
                    let mut f = DirectFuser::new();
                    if let Some(v) = include_unreachable {
                        f = f.with_include_unreachable(*v);
                    }
                    if let Some(v) = confidence_baseline {
                        f = f.with_confidence_baseline(*v);
                    }
                    if let Some(v) = confidence_per_signal {
                        f = f.with_confidence_per_signal(*v);
                    }
                    let mut out = Vec::new();
                    for group in group_outcomes_by_ip(outcomes) {
                        if let Some(record) = f.fuse_one(&group)? {
                            out.push(record);
                        }
                    }
                    Ok(out)
                }
                #[cfg(feature = "oui")]
                FuserConfig::OuiEnrichment { data_path, inner } => {
                    let mut records = fuse_many_batch(inner, outcomes)?;
                    let table = if data_path.is_empty() {
                        crate::fuser::OuiTable::from_bundled()?
                    } else {
                        crate::fuser::OuiTable::from_path(data_path)?
                    };
                    for record in &mut records {
                        if record.manufacturer.is_none() {
                            if let Some(mac) = &record.mac {
                                if let Some(vendor) = table.lookup(mac) {
                                    record.manufacturer = Some(vendor.to_string());
                                }
                            }
                        }
                    }
                    Ok(records)
                }
                FuserConfig::Identity {
                    identity_hints,
                    inner,
                } => {
                    let inner_records = fuse_many_batch(inner, outcomes)?;
                    let f = IdentityFuser::new(create_fuser(inner)?, identity_hints.clone())?;
                    Ok(f.correlate(inner_records))
                }
            }
        }

        fn assert_matches_batch(config: &FuserConfig, outcomes: Vec<ProbeOutcome>, label: &str) {
            let mut fuser = create_fuser(config).expect("create fuser");
            let streamed = drive_fuser(fuser.as_mut(), outcomes.clone()).expect("drive");
            let batched = fuse_many_batch(config, outcomes).expect("batch reference");
            assert_eq!(
                serde_json::to_string(&streamed).expect("serialize streamed"),
                serde_json::to_string(&batched).expect("serialize batched"),
                "{label}: ingest/finish output diverged from batch reference",
            );
        }

        fn oc(
            octet: u8,
            kind: ProbeKind,
            reachable: bool,
            signals: Vec<Signal>,
            fault: Option<ProbeFault>,
        ) -> ProbeOutcome {
            ProbeOutcome {
                kind,
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable,
                signals,
                fault,
            }
        }

        fn named_corpora() -> Vec<(&'static str, Vec<ProbeOutcome>)> {
            let mac_a = "aa:bb:cc:11:22:33";
            let mac_b = "dd:ee:ff:44:55:66";
            let oui_mac = "00:04:AC:11:22:33";
            let host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI";
            let sysname = Signal::SnmpSysName("core-sw01".into());
            let fault = || Some(ProbeFault::new(ProbeErrorKind::Other, "boom"));
            vec![
                ("empty", vec![]),
                (
                    "single_reachable",
                    vec![oc(
                        1,
                        ProbeKind::TcpConnect,
                        true,
                        vec![Signal::Mac(mac_a.into()), Signal::OpenPort(22)],
                        None,
                    )],
                ),
                (
                    "single_unreachable",
                    vec![oc(1, ProbeKind::TcpConnect, false, vec![], None)],
                ),
                (
                    "single_faulted_plus_reachable",
                    vec![
                        oc(1, ProbeKind::Snmp, false, vec![], fault()),
                        oc(
                            1,
                            ProbeKind::TcpConnect,
                            true,
                            vec![Signal::OpenPort(22)],
                            None,
                        ),
                    ],
                ),
                (
                    "multi_distinct_targets",
                    vec![
                        oc(
                            1,
                            ProbeKind::TcpConnect,
                            true,
                            vec![Signal::Mac(mac_a.into()), Signal::OpenPort(22)],
                            None,
                        ),
                        oc(
                            2,
                            ProbeKind::TcpConnect,
                            true,
                            vec![Signal::Mac(mac_b.into()), Signal::OpenPort(80)],
                            None,
                        ),
                        oc(
                            3,
                            ProbeKind::TcpConnect,
                            true,
                            vec![Signal::OpenPort(443)],
                            None,
                        ),
                    ],
                ),
                (
                    "multi_ip_shared_mac_and_sysname_high_band",
                    vec![
                        oc(
                            2,
                            ProbeKind::Snmp,
                            true,
                            vec![Signal::Mac(mac_a.into()), sysname.clone()],
                            None,
                        ),
                        oc(
                            1,
                            ProbeKind::Snmp,
                            true,
                            vec![Signal::Mac(mac_a.into()), sysname.clone()],
                            None,
                        ),
                        oc(
                            3,
                            ProbeKind::Snmp,
                            true,
                            vec![Signal::Mac(mac_a.into()), sysname.clone()],
                            None,
                        ),
                    ],
                ),
                (
                    "shared_ssh_host_key_high_band",
                    vec![
                        oc(
                            1,
                            ProbeKind::Ssh,
                            true,
                            vec![Signal::SshHostKey(host_key.into())],
                            None,
                        ),
                        oc(
                            2,
                            ProbeKind::Ssh,
                            true,
                            vec![Signal::SshHostKey(host_key.into())],
                            None,
                        ),
                    ],
                ),
                (
                    "shared_mac_only_medium_band",
                    vec![
                        oc(
                            1,
                            ProbeKind::Arp,
                            true,
                            vec![Signal::Mac(mac_a.into())],
                            None,
                        ),
                        oc(
                            2,
                            ProbeKind::Arp,
                            true,
                            vec![Signal::Mac(mac_a.into())],
                            None,
                        ),
                    ],
                ),
                (
                    "mixed_reachable_unreachable_faulted_and_correlated",
                    vec![
                        oc(
                            1,
                            ProbeKind::Snmp,
                            true,
                            vec![Signal::Mac(mac_a.into()), sysname.clone()],
                            None,
                        ),
                        oc(
                            1,
                            ProbeKind::TcpConnect,
                            true,
                            vec![Signal::OpenPort(22)],
                            None,
                        ),
                        oc(
                            2,
                            ProbeKind::Snmp,
                            true,
                            vec![Signal::Mac(mac_a.into()), sysname.clone()],
                            None,
                        ),
                        oc(3, ProbeKind::TcpConnect, false, vec![], fault()),
                        oc(4, ProbeKind::TcpConnect, false, vec![], None),
                    ],
                ),
                (
                    "oui_enrichable_mac",
                    vec![oc(
                        1,
                        ProbeKind::TcpConnect,
                        true,
                        vec![Signal::Mac(oui_mac.into()), Signal::OpenPort(22)],
                        None,
                    )],
                ),
            ]
        }

        fn direct_config() -> FuserConfig {
            FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: None,
                confidence_per_signal: None,
            }
        }

        // OUI-free configs; the random test avoids reloading the bundled OUI table per seed.
        fn core_matrix() -> Vec<(String, FuserConfig)> {
            vec![
                ("direct".to_string(), direct_config()),
                (
                    "direct_include_unreachable".to_string(),
                    FuserConfig::Direct {
                        include_unreachable: Some(true),
                        confidence_baseline: None,
                        confidence_per_signal: None,
                    },
                ),
                (
                    "identity(direct)".to_string(),
                    FuserConfig::Identity {
                        identity_hints: IdentityHints::default(),
                        inner: Box::new(direct_config()),
                    },
                ),
            ]
        }

        fn matrix() -> Vec<(String, FuserConfig)> {
            #[allow(unused_mut)]
            let mut out = core_matrix();
            #[cfg(feature = "oui")]
            {
                out.push((
                    "oui(direct)".to_string(),
                    FuserConfig::OuiEnrichment {
                        data_path: String::new(),
                        inner: Box::new(direct_config()),
                    },
                ));
                out.push((
                    "identity(oui(direct))".to_string(),
                    FuserConfig::Identity {
                        identity_hints: IdentityHints::default(),
                        inner: Box::new(FuserConfig::OuiEnrichment {
                            data_path: String::new(),
                            inner: Box::new(direct_config()),
                        }),
                    },
                ));
            }
            out
        }

        #[test]
        fn ingest_finish_matches_batch_over_named_corpora() {
            for (cfg_label, config) in matrix() {
                for (corpus_label, outcomes) in named_corpora() {
                    assert_matches_batch(
                        &config,
                        outcomes,
                        &format!("{cfg_label} / {corpus_label}"),
                    );
                }
            }
        }

        fn random_outcomes(lcg: &mut Lcg) -> Vec<ProbeOutcome> {
            let count = lcg.below(14);
            let mut out = Vec::new();
            for _ in 0..count {
                let octet = (1 + lcg.below(5)) as u8;
                let reachable = lcg.chance(3, 4);
                let mut signals = Vec::new();
                if reachable {
                    if let Some(m) = MAC_POOL[lcg.below(MAC_POOL.len())] {
                        signals.push(Signal::Mac(m.to_string()));
                    }
                    if lcg.chance(1, 2) {
                        signals.push(Signal::SnmpSysName(
                            SYSNAME_POOL[lcg.below(SYSNAME_POOL.len())].to_string(),
                        ));
                    }
                    if lcg.chance(1, 3) {
                        signals.push(Signal::SshHostKey(
                            SSH_POOL[lcg.below(SSH_POOL.len())].to_string(),
                        ));
                    }
                    if lcg.chance(1, 2) {
                        signals.push(Signal::OpenPort(22));
                    }
                }
                let fault = if !reachable && lcg.chance(1, 3) {
                    Some(ProbeFault::new(ProbeErrorKind::Other, "boom"))
                } else {
                    None
                };
                out.push(oc(octet, ProbeKind::TcpConnect, reachable, signals, fault));
            }
            out
        }

        #[test]
        fn ingest_finish_matches_batch_over_random_corpora() {
            let configs = core_matrix();
            for seed in 0..200u64 {
                let mut lcg = Lcg(seed
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(0xD1B5_4A32_D192_ED03));
                let outcomes = random_outcomes(&mut lcg);
                for (cfg_label, config) in &configs {
                    assert_matches_batch(
                        config,
                        outcomes.clone(),
                        &format!("seed {seed} / {cfg_label}"),
                    );
                }
            }
        }
    }
}
