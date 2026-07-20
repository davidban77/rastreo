pub(crate) mod openconfig_paths;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::model::collection_profile::{
    Collection, CollectionProfileRecord, ProfileConfidence, ProfileEndpoint,
    COLLECTION_PROFILE_SCHEMA_ID,
};
use crate::model::device::DeviceRecord;
use crate::model::outcome::{GnmiEndpoint, ProbeKind, ProbeOutcome, Signal};
use crate::model::scan::ScanMetadata;

const RECOMMENDED_ENCODING_FALLBACK: &str = "JSON_IETF";

/// Assembles per-IP gNMI capability observations into one [`CollectionProfileRecord`] per endpoint.
///
/// Built from per-IP [`ProbeOutcome`]s, not the merged [`DeviceRecord`]: the identity fuser dedups
/// signals across a device's IPs, which would destroy per-endpoint model attribution. Endpoints
/// correlate to a device by the same address index the topology assembler uses, so a device with
/// two gNMI endpoints yields two profiles sharing an `identity_key`.
pub struct CollectionProfileAssembler {
    scan_metadata: Arc<ScanMetadata>,
    observations: Vec<GnmiObservation>,
    addr_index: HashMap<IpAddr, String>,
}

struct GnmiObservation {
    target_ip: IpAddr,
    endpoint: GnmiEndpoint,
    gnmi_version: Option<String>,
    supported_models: Vec<String>,
    observed_at: SystemTime,
}

impl CollectionProfileAssembler {
    pub fn new(scan_metadata: Arc<ScanMetadata>) -> Self {
        Self {
            scan_metadata,
            observations: Vec::new(),
            addr_index: HashMap::new(),
        }
    }

    /// Captures each gNMI outcome that returned capability data. Draws ONLY from the capability
    /// signals (`GnmiVersion` / `GnmiSupportedModel`) and the surfaced endpoint — never `GnmiState`,
    /// whose values carry device state that must not leak into an advisory profile.
    pub fn observe_outcomes(&mut self, outcomes: &[ProbeOutcome]) {
        for outcome in outcomes {
            if outcome.kind != ProbeKind::Gnmi {
                continue;
            }
            let Some(endpoint) = &outcome.gnmi_endpoint else {
                continue;
            };
            let mut gnmi_version = None;
            let mut supported_models = Vec::new();
            for signal in &outcome.signals {
                match signal {
                    Signal::GnmiVersion(v) => {
                        gnmi_version.get_or_insert_with(|| v.clone());
                    }
                    Signal::GnmiSupportedModel(m) => supported_models.push(m.clone()),
                    _ => {}
                }
            }
            // Emit only on capability presence: a reachable-but-capability-less endpoint (an auth
            // failure, say) would otherwise ship an empty advisory.
            let has_capability = gnmi_version.is_some()
                || !supported_models.is_empty()
                || !endpoint.advertised_encodings.is_empty();
            if !has_capability {
                continue;
            }
            self.observations.push(GnmiObservation {
                target_ip: outcome.target_ip,
                endpoint: endpoint.clone(),
                gnmi_version,
                supported_models,
                observed_at: outcome.timestamp,
            });
        }
    }

    /// Indexes an emitted device record's addresses (`mgmt_ip` + `alt_ips`) so endpoints can later
    /// resolve their `identity_key`.
    pub fn observe_record(&mut self, record: &DeviceRecord) {
        let identity = record.identity_key.as_str();
        if let Some(ip) = record.mgmt_ip {
            self.addr_index.entry(ip).or_insert_with(|| identity.into());
        }
        for alt in &record.alt_ips {
            self.addr_index
                .entry(alt.address)
                .or_insert_with(|| identity.into());
        }
    }

    pub fn finish(&mut self) -> Vec<CollectionProfileRecord> {
        let mut seen: HashSet<(String, IpAddr)> = HashSet::new();
        let mut out = Vec::new();
        for obs in &self.observations {
            let Some(identity) = self.addr_index.get(&obs.target_ip) else {
                continue;
            };
            if !seen.insert((identity.clone(), obs.target_ip)) {
                continue;
            }
            out.push(CollectionProfileRecord {
                schema_version: CollectionProfileRecord::SCHEMA_VERSION.to_string(),
                schema_id: COLLECTION_PROFILE_SCHEMA_ID.to_string(),
                identity_key: identity.clone(),
                endpoint: ProfileEndpoint {
                    address: obs.target_ip.to_string(),
                    port: obs.endpoint.port,
                    transport: obs.endpoint.transport,
                },
                confidence: ProfileConfidence::AdvertisedOnly,
                note: None,
                collection: Collection::Gnmi {
                    gnmi_version: obs.gnmi_version.clone(),
                    encoding: recommended_encoding(&obs.endpoint.advertised_encodings),
                    supported_models: obs.supported_models.clone(),
                    suggested_subscriptions: openconfig_paths::suggested_subscriptions(
                        &obs.supported_models,
                    ),
                },
                observed_at: obs.observed_at,
                scan_metadata: (*self.scan_metadata).clone(),
            });
        }
        out.sort_by(|a, b| {
            (a.identity_key.as_str(), a.endpoint.address.as_str())
                .cmp(&(b.identity_key.as_str(), b.endpoint.address.as_str()))
        });
        out
    }
}

/// Recommended encoding drawn from the advertised set: `JSON_IETF` when advertised (or nothing is
/// advertised), else the first renderable advertised encoding — mirroring the prober's `Get` pick.
fn recommended_encoding(advertised: &[String]) -> String {
    if advertised.is_empty()
        || advertised
            .iter()
            .any(|e| e == RECOMMENDED_ENCODING_FALLBACK)
    {
        return RECOMMENDED_ENCODING_FALLBACK.to_string();
    }
    advertised
        .iter()
        .find(|e| is_renderable(e))
        .cloned()
        .unwrap_or_else(|| RECOMMENDED_ENCODING_FALLBACK.to_string())
}

fn is_renderable(encoding: &str) -> bool {
    matches!(encoding, "JSON" | "PROTO" | "ASCII" | "JSON_IETF")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use crate::model::device::{AltIp, Confidence, IdentityKey, CURRENT_SCHEMA_ID};
    use crate::model::outcome::Transport;

    fn assembler() -> CollectionProfileAssembler {
        CollectionProfileAssembler::new(Arc::new(ScanMetadata::default()))
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn gnmi_outcome(last: u8, signals: Vec<Signal>, endpoint: GnmiEndpoint) -> ProbeOutcome {
        ProbeOutcome {
            kind: ProbeKind::Gnmi,
            target_ip: ip(last),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable: true,
            signals,
            fault: None,
            lldp: None,
            gnmi_endpoint: Some(endpoint),
        }
    }

    fn endpoint(port: u16, transport: Transport, encodings: &[&str]) -> GnmiEndpoint {
        GnmiEndpoint {
            port,
            transport,
            advertised_encodings: encodings.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn record(identity: &str, mgmt: u8, alt: &[u8]) -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new(identity).expect("identity"),
            mgmt_ip: Some(ip(mgmt)),
            mac: None,
            manufacturer: None,
            model: None,
            product_family: None,
            platform: None,
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: None,
            confidence: Confidence::new(0.5).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: Vec::new(),
            probe_kinds: Vec::new(),
            schema_version: CollectionProfileRecord::SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: alt.iter().map(|a| AltIp::new(ip(*a))).collect(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    #[test]
    fn capability_bearing_endpoint_emits_one_profile() {
        let mut a = assembler();
        a.observe_outcomes(&[gnmi_outcome(
            1,
            vec![
                Signal::GnmiVersion("0.10.0".into()),
                Signal::GnmiSupportedModel("openconfig-interfaces 3.0.0 (OpenConfig)".into()),
                Signal::GnmiSupportedEncoding("JSON_IETF".into()),
            ],
            endpoint(57400, Transport::Tls, &["JSON_IETF", "PROTO"]),
        )]);
        a.observe_record(&record("dev-a", 1, &[]));

        let profiles = a.finish();
        assert_eq!(profiles.len(), 1);
        let p = &profiles[0];
        assert_eq!(p.identity_key, "dev-a");
        assert_eq!(p.endpoint.address, "10.0.0.1");
        assert_eq!(p.endpoint.port, 57400);
        assert_eq!(p.endpoint.transport, Transport::Tls);
        assert_eq!(p.confidence, ProfileConfidence::AdvertisedOnly);
        let Collection::Gnmi {
            gnmi_version,
            encoding,
            supported_models,
            suggested_subscriptions,
        } = &p.collection;
        assert_eq!(gnmi_version.as_deref(), Some("0.10.0"));
        assert_eq!(encoding, "JSON_IETF");
        assert_eq!(
            supported_models,
            &vec!["openconfig-interfaces 3.0.0 (OpenConfig)".to_string()]
        );
        let paths: Vec<&str> = suggested_subscriptions
            .iter()
            .map(|s| s.path.as_str())
            .collect();
        assert!(paths.contains(&"/interfaces/interface/state/counters"));
        assert!(paths.contains(&"/interfaces/interface/state/oper-status"));
        for sub in suggested_subscriptions {
            assert_eq!(sub.origin, "openconfig");
            assert_eq!(
                sub.matched_model,
                "openconfig-interfaces 3.0.0 (OpenConfig)"
            );
        }
    }

    #[test]
    fn a_native_only_model_lists_the_model_but_suggests_nothing() {
        let mut a = assembler();
        a.observe_outcomes(&[gnmi_outcome(
            1,
            vec![Signal::GnmiSupportedModel(
                "srl_nokia-interfaces 2024-03-31".into(),
            )],
            endpoint(57400, Transport::Tls, &["JSON_IETF"]),
        )]);
        a.observe_record(&record("dev-a", 1, &[]));

        let profiles = a.finish();
        assert_eq!(profiles.len(), 1);
        let Collection::Gnmi {
            supported_models,
            suggested_subscriptions,
            ..
        } = &profiles[0].collection;
        assert_eq!(
            supported_models,
            &vec!["srl_nokia-interfaces 2024-03-31".to_string()]
        );
        assert!(
            suggested_subscriptions.is_empty(),
            "native models are carried but not curated"
        );
    }

    #[test]
    fn two_endpoints_on_one_device_emit_two_profiles_with_shared_identity_and_own_models() {
        let mut a = assembler();
        a.observe_outcomes(&[gnmi_outcome(
            1,
            vec![Signal::GnmiSupportedModel("model-a".into())],
            endpoint(57400, Transport::Tls, &["JSON_IETF"]),
        )]);
        a.observe_outcomes(&[gnmi_outcome(
            2,
            vec![Signal::GnmiSupportedModel("model-b".into())],
            endpoint(6030, Transport::Plaintext, &["PROTO"]),
        )]);
        // The identity fuser merged 10.0.0.2 into the same device as an alt IP.
        a.observe_record(&record("dev-a", 1, &[2]));

        let profiles = a.finish();
        assert_eq!(profiles.len(), 2, "one profile per gNMI endpoint");
        for p in &profiles {
            assert_eq!(
                p.identity_key, "dev-a",
                "both share the device identity_key"
            );
        }
        let by_addr: HashMap<&str, &CollectionProfileRecord> = profiles
            .iter()
            .map(|p| (p.endpoint.address.as_str(), p))
            .collect();
        let a1 = by_addr.get("10.0.0.1").expect("endpoint on .1");
        let a2 = by_addr.get("10.0.0.2").expect("endpoint on .2");
        let Collection::Gnmi {
            supported_models: m1,
            ..
        } = &a1.collection;
        let Collection::Gnmi {
            supported_models: m2,
            ..
        } = &a2.collection;
        assert_eq!(m1, &vec!["model-a".to_string()], "per-IP model attribution");
        assert_eq!(m2, &vec!["model-b".to_string()], "not the merged union");
    }

    #[test]
    fn capability_less_answered_endpoint_emits_no_profile() {
        let mut a = assembler();
        // The port answered a Get (a GnmiState) but Capabilities failed: no advertised capability.
        a.observe_outcomes(&[gnmi_outcome(
            1,
            vec![Signal::GnmiState {
                path: "/system/state/hostname".into(),
                value: "srlinux".into(),
            }],
            endpoint(57400, Transport::Tls, &[]),
        )]);
        a.observe_record(&record("dev-a", 1, &[]));
        assert!(
            a.finish().is_empty(),
            "reachability alone is not a collection profile; gate on capability data"
        );
    }

    #[test]
    fn gnmi_state_values_never_appear_in_a_profile() {
        let secret = "super-secret-hostname-xyz";
        let mut a = assembler();
        a.observe_outcomes(&[gnmi_outcome(
            1,
            vec![
                Signal::GnmiVersion("0.10.0".into()),
                Signal::GnmiState {
                    path: "/system/state/hostname".into(),
                    value: secret.into(),
                },
            ],
            endpoint(57400, Transport::Tls, &["JSON_IETF"]),
        )]);
        a.observe_record(&record("dev-a", 1, &[]));

        let profiles = a.finish();
        assert_eq!(profiles.len(), 1);
        let json = serde_json::to_string(&profiles[0]).expect("serialize");
        assert!(
            !json.contains(secret),
            "a GnmiState value must never surface in a profile: {json}"
        );
    }

    #[test]
    fn an_uncorrelated_endpoint_emits_no_profile() {
        let mut a = assembler();
        a.observe_outcomes(&[gnmi_outcome(
            9,
            vec![Signal::GnmiSupportedModel("model-a".into())],
            endpoint(57400, Transport::Tls, &["JSON_IETF"]),
        )]);
        // No record indexes 10.0.0.9, so the endpoint has no identity_key.
        a.observe_record(&record("dev-a", 1, &[]));
        assert!(a.finish().is_empty());
    }

    #[test]
    fn non_gnmi_outcomes_are_ignored() {
        let mut a = assembler();
        let mut tcp = gnmi_outcome(
            1,
            Vec::new(),
            endpoint(57400, Transport::Tls, &["JSON_IETF"]),
        );
        tcp.kind = ProbeKind::TcpConnect;
        tcp.gnmi_endpoint = None;
        tcp.signals = vec![Signal::OpenPort(57400)];
        a.observe_outcomes(&[tcp]);
        a.observe_record(&record("dev-a", 1, &[]));
        assert!(a.finish().is_empty());
    }

    #[test]
    fn scan_metadata_is_stamped_on_every_profile() {
        let scan = ScanMetadata {
            scan_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            ..ScanMetadata::default()
        };
        let mut a = CollectionProfileAssembler::new(Arc::new(scan));
        a.observe_outcomes(&[gnmi_outcome(
            1,
            vec![Signal::GnmiSupportedModel("model-a".into())],
            endpoint(57400, Transport::Tls, &["JSON_IETF"]),
        )]);
        a.observe_record(&record("dev-a", 1, &[]));
        assert_eq!(
            a.finish()[0].scan_metadata.scan_id,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        );
    }

    #[test]
    fn recommended_encoding_prefers_json_ietf() {
        assert_eq!(
            recommended_encoding(&["PROTO".into(), "JSON_IETF".into()]),
            "JSON_IETF"
        );
    }

    #[test]
    fn recommended_encoding_picks_first_renderable_when_no_json_ietf() {
        assert_eq!(recommended_encoding(&["PROTO".into()]), "PROTO");
        assert_eq!(
            recommended_encoding(&["BYTES".into(), "ASCII".into()]),
            "ASCII"
        );
    }

    #[test]
    fn recommended_encoding_falls_back_when_empty_or_unrenderable() {
        assert_eq!(recommended_encoding(&[]), "JSON_IETF");
        assert_eq!(recommended_encoding(&["BYTES".into()]), "JSON_IETF");
    }

    #[test]
    fn assembler_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CollectionProfileAssembler>();
    }
}
