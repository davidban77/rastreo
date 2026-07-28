//! Curated OpenConfig telemetry paths matched against a device's advertised gNMI models.
//!
//! Every entry is a hand-authored fact from the Apache-2.0 OpenConfig models — universal `/state`
//! telemetry leaves an OpenConfig-speaking device exposes. No upstream catalog is copied. Vendor-native
//! models (`srl_nokia-*`, `Cisco-IOS-XR-*`, `arista-*`, `Juniper-*`) are intentionally absent: their
//! paths are device-specific and not openly bundleable, so they carry in `supported_models` but
//! produce no suggestions.

use crate::model::collection_profile::Subscription;

const SAMPLE: &str = "sample";
const ON_CHANGE: &str = "on_change";

const INTERVAL_10S: u64 = 10_000_000_000;
const INTERVAL_30S: u64 = 30_000_000_000;

struct CuratedPath {
    model_key: &'static str,
    name: &'static str,
    origin: &'static str,
    path: &'static str,
    mode: &'static str,
    sample_interval_ns: Option<u64>,
}

const OPENCONFIG_PATHS: &[CuratedPath] = &[
    CuratedPath {
        model_key: "openconfig-interfaces",
        name: "if_counters",
        origin: "openconfig",
        path: "/interfaces/interface/state/counters",
        mode: SAMPLE,
        sample_interval_ns: Some(INTERVAL_10S),
    },
    CuratedPath {
        model_key: "openconfig-interfaces",
        name: "if_oper_status",
        origin: "openconfig",
        path: "/interfaces/interface/state/oper-status",
        mode: ON_CHANGE,
        sample_interval_ns: None,
    },
    CuratedPath {
        model_key: "openconfig-interfaces",
        name: "if_admin_status",
        origin: "openconfig",
        path: "/interfaces/interface/state/admin-status",
        mode: ON_CHANGE,
        sample_interval_ns: None,
    },
    CuratedPath {
        model_key: "openconfig-system",
        name: "system_cpu_utilization",
        origin: "openconfig",
        path: "/system/cpus/cpu/state/total/instant",
        mode: SAMPLE,
        sample_interval_ns: Some(INTERVAL_10S),
    },
    CuratedPath {
        model_key: "openconfig-system",
        name: "system_memory",
        origin: "openconfig",
        path: "/system/memory/state",
        mode: SAMPLE,
        sample_interval_ns: Some(INTERVAL_30S),
    },
    CuratedPath {
        model_key: "openconfig-platform",
        name: "component_state",
        origin: "openconfig",
        path: "/components/component/state",
        mode: SAMPLE,
        sample_interval_ns: Some(INTERVAL_30S),
    },
    CuratedPath {
        model_key: "openconfig-network-instance",
        name: "bgp_neighbor_session_state",
        origin: "openconfig",
        path: "/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state/session-state",
        mode: ON_CHANGE,
        sample_interval_ns: None,
    },
    CuratedPath {
        model_key: "openconfig-network-instance",
        name: "bgp_neighbor_established_transitions",
        origin: "openconfig",
        path: "/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state/established-transitions",
        mode: SAMPLE,
        sample_interval_ns: Some(INTERVAL_30S),
    },
];

/// One [`Subscription`] per curated path whose model an advertised model matches, tagged with the
/// advertised model string (including version) verbatim so a version-skewed device keeps its own version.
pub(crate) fn suggested_subscriptions(supported_models: &[String]) -> Vec<Subscription> {
    let mut out = Vec::new();
    for advertised in supported_models {
        let key = model_key(advertised);
        for entry in OPENCONFIG_PATHS {
            if entry.model_key == key {
                out.push(Subscription {
                    name: entry.name.to_string(),
                    origin: entry.origin.to_string(),
                    path: entry.path.to_string(),
                    mode: entry.mode.to_string(),
                    sample_interval_ns: entry.sample_interval_ns,
                    matched_model: advertised.clone(),
                });
            }
        }
    }
    out
}

// A device may namespace-qualify the model name ("http://openconfig.net/yang/interfaces:openconfig-interfaces"); the table keys on the bare name.
fn model_key(rendered_model: &str) -> &str {
    let name = rendered_model
        .split_whitespace()
        .next()
        .unwrap_or(rendered_model);
    match name.rsplit_once(':') {
        Some((_, bare)) => bare,
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn models(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn openconfig_interfaces_yields_its_curated_paths() {
        let subs = suggested_subscriptions(&models(&["openconfig-interfaces 3.0.0 (OpenConfig)"]));
        let by_path: std::collections::HashMap<&str, &Subscription> =
            subs.iter().map(|s| (s.path.as_str(), s)).collect();

        let counters = by_path
            .get("/interfaces/interface/state/counters")
            .expect("counters path");
        assert_eq!(counters.mode, "sample");
        assert_eq!(counters.sample_interval_ns, Some(10_000_000_000));
        assert_eq!(counters.origin, "openconfig");

        let oper = by_path
            .get("/interfaces/interface/state/oper-status")
            .expect("oper-status path");
        assert_eq!(oper.mode, "on_change");
        assert_eq!(oper.sample_interval_ns, None);

        for sub in &subs {
            assert_eq!(
                sub.matched_model,
                "openconfig-interfaces 3.0.0 (OpenConfig)"
            );
        }
    }

    #[test]
    fn native_only_model_yields_no_subscriptions() {
        let subs = suggested_subscriptions(&models(&["srl_nokia-interfaces 2024-03-31"]));
        assert!(subs.is_empty());
    }

    #[test]
    fn multiple_models_union_each_tagged_with_its_own_matched_model() {
        let subs = suggested_subscriptions(&models(&[
            "openconfig-interfaces 3.0.0 (OpenConfig)",
            "openconfig-system 0.9.0 (OpenConfig)",
        ]));
        assert!(subs
            .iter()
            .any(|s| s.path == "/interfaces/interface/state/counters"
                && s.matched_model == "openconfig-interfaces 3.0.0 (OpenConfig)"));
        assert!(subs
            .iter()
            .any(|s| s.path == "/system/cpus/cpu/state/total/instant"
                && s.matched_model == "openconfig-system 0.9.0 (OpenConfig)"));
    }

    #[test]
    fn matched_model_preserves_the_advertised_version_verbatim() {
        let subs = suggested_subscriptions(&models(&["openconfig-interfaces 2.5.0 (OpenConfig)"]));
        assert!(!subs.is_empty());
        for sub in &subs {
            assert_eq!(
                sub.matched_model,
                "openconfig-interfaces 2.5.0 (OpenConfig)"
            );
        }
    }

    #[test]
    fn sample_interval_is_set_only_for_sample_mode() {
        for entry in OPENCONFIG_PATHS {
            match entry.mode {
                "sample" => assert!(
                    entry.sample_interval_ns.is_some(),
                    "sample path {} needs an interval",
                    entry.path
                ),
                "on_change" => assert!(
                    entry.sample_interval_ns.is_none(),
                    "on_change path {} must omit the interval",
                    entry.path
                ),
                other => panic!("unexpected mode {other} on {}", entry.path),
            }
        }
    }

    #[test]
    fn every_curated_path_is_absolute_and_openconfig_origin() {
        for entry in OPENCONFIG_PATHS {
            assert!(
                entry.path.starts_with('/'),
                "path must be absolute: {}",
                entry.path
            );
            assert_eq!(entry.origin, "openconfig");
            assert!(
                entry.model_key.starts_with("openconfig-"),
                "native model leaked into table"
            );
        }
    }

    #[test]
    fn model_key_takes_the_leading_whitespace_token() {
        assert_eq!(
            model_key("openconfig-interfaces 3.0.0 (OpenConfig)"),
            "openconfig-interfaces"
        );
        assert_eq!(model_key("openconfig-system"), "openconfig-system");
    }

    #[test]
    fn model_key_drops_the_namespace_a_real_device_qualifies_the_name_with() {
        assert_eq!(
            model_key(
                "http://openconfig.net/yang/interfaces:openconfig-interfaces 2024-12-05 (OpenConfig working group)"
            ),
            "openconfig-interfaces"
        );
        assert_eq!(
            model_key(
                "https://github.com/openconfig/yang/gnsi/acctz:openconfig-gnsi-acctz 2024-12-24 (OpenConfig Working Group)"
            ),
            "openconfig-gnsi-acctz"
        );
        assert_eq!(
            model_key("urn:nokia.com:srlinux:aaa:aaa:srl_nokia-aaa 2026-03-31 (Nokia)"),
            "srl_nokia-aaa"
        );
    }

    #[test]
    fn a_namespace_qualified_openconfig_model_yields_its_curated_paths() {
        let advertised =
            "http://openconfig.net/yang/system:openconfig-system 2024-09-24 (OpenConfig working group)";
        let subs = suggested_subscriptions(&models(&[advertised]));
        assert!(subs
            .iter()
            .any(|s| s.path == "/system/cpus/cpu/state/total/instant"));
        for sub in &subs {
            assert_eq!(sub.matched_model, advertised);
        }
    }

    #[test]
    fn a_namespace_qualified_native_model_still_yields_no_subscriptions() {
        let subs = suggested_subscriptions(&models(&[
            "urn:nokia.com:srlinux:interfaces:srl_nokia-interfaces 2026-03-31 (Nokia)",
        ]));
        assert!(subs.is_empty());
    }
}
