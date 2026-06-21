use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::error::{ConfigError, RastreoError};
use crate::model::device::{Confidence, DeviceRecord, IdentityKey};
use crate::model::outcome::{ProbeOutcome, Signal};

pub trait Fuser: Send + Sync {
    fn fuse(&self, outcomes: &[ProbeOutcome]) -> Result<Option<DeviceRecord>, RastreoError>;

    fn fuse_many(&self, outcomes: Vec<ProbeOutcome>) -> Result<Vec<DeviceRecord>, RastreoError> {
        // Preserve first-occurrence IP order so consumers see deterministic record order.
        let mut groups: HashMap<IpAddr, Vec<ProbeOutcome>> = HashMap::new();
        let mut order: Vec<IpAddr> = Vec::new();
        for outcome in outcomes {
            let ip = outcome.target_ip;
            if !groups.contains_key(&ip) {
                order.push(ip);
            }
            groups.entry(ip).or_default().push(outcome);
        }
        let mut out = Vec::with_capacity(order.len());
        for ip in order {
            let group = groups.remove(&ip).expect("ip in order is in groups");
            if let Some(record) = self.fuse(&group)? {
                out.push(record);
            }
        }
        Ok(out)
    }
}

pub struct DirectFuser {
    confidence_per_signal: f64,
    confidence_baseline: f64,
    include_unreachable: bool,
}

impl DirectFuser {
    pub const DEFAULT_CONFIDENCE_BASELINE: f64 = 0.1;
    pub const DEFAULT_CONFIDENCE_PER_SIGNAL: f64 = 0.1;

    pub fn new() -> Self {
        Self {
            confidence_per_signal: Self::DEFAULT_CONFIDENCE_PER_SIGNAL,
            confidence_baseline: Self::DEFAULT_CONFIDENCE_BASELINE,
            include_unreachable: false,
        }
    }

    pub fn with_confidence_baseline(mut self, v: f64) -> Self {
        self.confidence_baseline = v;
        self
    }

    pub fn with_confidence_per_signal(mut self, v: f64) -> Self {
        self.confidence_per_signal = v;
        self
    }

    pub fn with_include_unreachable(mut self, v: bool) -> Self {
        self.include_unreachable = v;
        self
    }
}

impl Default for DirectFuser {
    fn default() -> Self {
        Self::new()
    }
}

impl Fuser for DirectFuser {
    fn fuse(&self, outcomes: &[ProbeOutcome]) -> Result<Option<DeviceRecord>, RastreoError> {
        if outcomes.is_empty() {
            return Ok(None);
        }

        let any_reachable = outcomes.iter().any(|o| o.reachable);
        if !any_reachable && !self.include_unreachable {
            return Ok(None);
        }

        let mgmt_ip = outcomes[0].target_ip;

        let first_mac: Option<String> =
            outcomes
                .iter()
                .flat_map(|o| o.signals.iter())
                .find_map(|s| match s {
                    Signal::Mac(m) => Some(m.clone()),
                    _ => None,
                });

        // `mac:` vs `ip:` prefix separates real device identity from scan-anchor identity.
        let identity_value = match &first_mac {
            Some(m) => format!("mac:{m}"),
            None => format!("ip:{mgmt_ip}"),
        };
        let identity_key = IdentityKey::new(identity_value)?;

        // Linear-search dedup: Signal lacks Hash and signal count per device is small (~10).
        let mut signals: Vec<Signal> = Vec::new();
        for outcome in outcomes {
            for signal in &outcome.signals {
                if !signals.iter().any(|existing| existing == signal) {
                    signals.push(signal.clone());
                }
            }
        }

        let raw = self.confidence_baseline + (signals.len() as f64) * self.confidence_per_signal;
        let confidence = Confidence::new(raw.min(1.0))?;

        let last_seen = outcomes
            .iter()
            .map(|o| o.timestamp)
            .max()
            .unwrap_or(SystemTime::UNIX_EPOCH);

        Ok(Some(DeviceRecord {
            identity_key,
            mgmt_ip: Some(mgmt_ip),
            mac: first_mac,
            manufacturer: None,
            platform: None,
            role: None,
            confidence,
            last_seen,
            signals,
        }))
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FuserConfig {
    Direct {
        #[serde(default)]
        include_unreachable: Option<bool>,
        #[serde(default)]
        confidence_baseline: Option<f64>,
        #[serde(default)]
        confidence_per_signal: Option<f64>,
    },
}

impl FuserConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self {
            FuserConfig::Direct {
                confidence_baseline,
                confidence_per_signal,
                include_unreachable: _,
            } => {
                if let Some(v) = confidence_baseline {
                    if !v.is_finite() || !(0.0..=1.0).contains(v) {
                        return Err(ConfigError::invalid(format!(
                            "confidence_baseline must be finite and in [0.0, 1.0], got {v}"
                        )));
                    }
                }
                if let Some(v) = confidence_per_signal {
                    if !v.is_finite() || *v < 0.0 {
                        return Err(ConfigError::invalid(format!(
                            "confidence_per_signal must be finite and non-negative, got {v}"
                        )));
                    }
                }
                Ok(())
            }
        }
    }
}

// `validate()` runs at the YAML-to-impl boundary; builder methods are programmatic and skip it.
pub fn create_fuser(config: &FuserConfig) -> Result<Box<dyn Fuser>, RastreoError> {
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
            Ok(Box::new(f))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::model::outcome::ProbeKind;

    fn outcome(last_octet: u8, reachable: bool, signals: Vec<Signal>) -> ProbeOutcome {
        ProbeOutcome {
            kind: ProbeKind::TcpConnect,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)),
            timestamp: SystemTime::UNIX_EPOCH,
            reachable,
            signals,
        }
    }

    fn outcome_at(
        last_octet: u8,
        reachable: bool,
        signals: Vec<Signal>,
        ts: SystemTime,
    ) -> ProbeOutcome {
        ProbeOutcome {
            kind: ProbeKind::TcpConnect,
            target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)),
            timestamp: ts,
            reachable,
            signals,
        }
    }

    #[test]
    fn fuse_empty_outcomes_returns_none() {
        let f = DirectFuser::new();
        let out = f.fuse(&[]).expect("ok");
        assert!(out.is_none());
    }

    #[test]
    fn fuse_all_unreachable_default_returns_none() {
        let f = DirectFuser::new();
        let outcomes = vec![outcome(1, false, vec![]), outcome(1, false, vec![])];
        let out = f.fuse(&outcomes).expect("ok");
        assert!(out.is_none());
    }

    #[test]
    fn fuse_all_unreachable_with_include_returns_record() {
        let f = DirectFuser::new().with_include_unreachable(true);
        let outcomes = vec![outcome(1, false, vec![])];
        let out = f.fuse(&outcomes).expect("ok");
        assert!(out.is_some());
    }

    #[test]
    fn fuse_one_reachable_with_one_port_signal_uses_ip_identity() {
        let f = DirectFuser::new();
        let outcomes = vec![outcome(1, true, vec![Signal::OpenPort(80)])];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert_eq!(record.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(record.identity_key.as_str(), "ip:10.0.0.1");
        assert!(record.mac.is_none());
        assert_eq!(record.signals.len(), 1);
    }

    #[test]
    fn fuse_mac_signal_dominates_identity_key() {
        let f = DirectFuser::new();
        let outcomes = vec![outcome(
            1,
            true,
            vec![
                Signal::OpenPort(22),
                Signal::Mac("AA:BB:CC:DD:EE:FF".into()),
            ],
        )];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert_eq!(record.identity_key.as_str(), "mac:aa:bb:cc:dd:ee:ff");
        assert_eq!(record.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn fuse_multiple_outcomes_aggregates_signals_across_outcomes() {
        let f = DirectFuser::new();
        let outcomes = vec![
            outcome(1, true, vec![Signal::OpenPort(80)]),
            outcome(
                1,
                true,
                vec![
                    Signal::OpenPort(443),
                    Signal::HttpBanner("nginx/1.27".into()),
                ],
            ),
        ];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert_eq!(record.signals.len(), 3);
    }

    #[test]
    fn fuse_dedups_identical_signals() {
        let f = DirectFuser::new();
        let outcomes = vec![outcome(
            1,
            true,
            vec![Signal::OpenPort(80), Signal::OpenPort(80)],
        )];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert_eq!(record.signals.len(), 1);
    }

    #[test]
    fn fuse_confidence_default_with_three_signals_is_zero_point_four() {
        let f = DirectFuser::new();
        let outcomes = vec![outcome(
            1,
            true,
            vec![
                Signal::OpenPort(22),
                Signal::OpenPort(80),
                Signal::OpenPort(443),
            ],
        )];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert!((record.confidence.value() - 0.4).abs() < 1e-9);
    }

    #[test]
    fn fuse_confidence_clamps_at_one() {
        let f = DirectFuser::new();
        let mut sigs = Vec::new();
        for port in 1u16..=15 {
            sigs.push(Signal::OpenPort(port));
        }
        let outcomes = vec![outcome(1, true, sigs)];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert_eq!(record.confidence.value(), 1.0);
    }

    #[test]
    fn fuse_confidence_uses_custom_knobs() {
        let f = DirectFuser::new()
            .with_confidence_baseline(0.5)
            .with_confidence_per_signal(0.05);
        let outcomes = vec![outcome(
            1,
            true,
            vec![Signal::OpenPort(22), Signal::OpenPort(80)],
        )];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert!((record.confidence.value() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn fuse_last_seen_is_max_timestamp() {
        let f = DirectFuser::new();
        let t0 = SystemTime::UNIX_EPOCH;
        let t1 = t0 + Duration::from_secs(10);
        let t2 = t0 + Duration::from_secs(5);
        let outcomes = vec![
            outcome_at(1, true, vec![Signal::OpenPort(22)], t1),
            outcome_at(1, true, vec![Signal::OpenPort(80)], t2),
        ];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert_eq!(record.last_seen, t1);
    }

    #[test]
    fn fuse_many_groups_by_ip_preserving_first_occurrence_order() {
        let f = DirectFuser::new();
        let outcomes = vec![
            outcome(2, true, vec![Signal::OpenPort(22)]),
            outcome(1, true, vec![Signal::OpenPort(80)]),
            outcome(2, true, vec![Signal::OpenPort(443)]),
            outcome(3, true, vec![Signal::OpenPort(53)]),
        ];
        let records = f.fuse_many(outcomes).expect("ok");
        let ips: Vec<IpAddr> = records.iter().filter_map(|r| r.mgmt_ip).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            ]
        );
    }

    #[test]
    fn fuse_many_skips_groups_with_no_reachable_outcomes() {
        let f = DirectFuser::new();
        let outcomes = vec![
            outcome(1, false, vec![]),
            outcome(1, false, vec![]),
            outcome(2, true, vec![Signal::OpenPort(22)]),
        ];
        let records = f.fuse_many(outcomes).expect("ok");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].mgmt_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
    }

    #[test]
    fn create_fuser_direct_with_custom_baseline_applies_knob() {
        let cfg = FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: Some(0.3),
            confidence_per_signal: None,
        };
        let f = create_fuser(&cfg).expect("create");
        let outcomes = vec![outcome(1, true, vec![Signal::OpenPort(22)])];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert!((record.confidence.value() - 0.4).abs() < 1e-9);
    }

    #[test]
    fn create_fuser_direct_default_knobs_uses_constants() {
        let cfg = FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: None,
            confidence_per_signal: None,
        };
        let f = create_fuser(&cfg).expect("create");
        let outcomes = vec![outcome(1, true, vec![Signal::OpenPort(22)])];
        let record = f.fuse(&outcomes).expect("ok").expect("some");
        assert!((record.confidence.value() - 0.2).abs() < 1e-9);
    }

    #[test]
    fn create_fuser_direct_include_unreachable_propagates() {
        let cfg = FuserConfig::Direct {
            include_unreachable: Some(true),
            confidence_baseline: None,
            confidence_per_signal: None,
        };
        let f = create_fuser(&cfg).expect("create");
        let outcomes = vec![outcome(1, false, vec![])];
        let record = f.fuse(&outcomes).expect("ok");
        assert!(record.is_some());
    }

    fn err_msg(cfg: &FuserConfig) -> String {
        match create_fuser(cfg) {
            Ok(_) => panic!("expected validation error"),
            Err(e) => {
                assert!(matches!(
                    e,
                    RastreoError::Config(crate::error::ConfigError::InvalidValue(_))
                ));
                format!("{e}")
            }
        }
    }

    #[test]
    fn create_fuser_rejects_negative_confidence_baseline() {
        let msg = err_msg(&FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: Some(-0.5),
            confidence_per_signal: None,
        });
        assert!(msg.contains("confidence_baseline"));
        assert!(msg.contains("-0.5"));
    }

    #[test]
    fn create_fuser_rejects_confidence_baseline_above_one() {
        let msg = err_msg(&FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: Some(1.5),
            confidence_per_signal: None,
        });
        assert!(msg.contains("1.5"));
    }

    #[test]
    fn create_fuser_rejects_nan_confidence_baseline() {
        let msg = err_msg(&FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: Some(f64::NAN),
            confidence_per_signal: None,
        });
        assert!(msg.contains("confidence_baseline"));
    }

    #[test]
    fn create_fuser_rejects_negative_confidence_per_signal() {
        let msg = err_msg(&FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: None,
            confidence_per_signal: Some(-0.1),
        });
        assert!(msg.contains("confidence_per_signal"));
        assert!(msg.contains("-0.1"));
    }

    #[test]
    fn create_fuser_rejects_infinity_confidence_per_signal() {
        let msg = err_msg(&FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: None,
            confidence_per_signal: Some(f64::INFINITY),
        });
        assert!(msg.contains("confidence_per_signal"));
    }

    #[test]
    fn create_fuser_accepts_zero_confidence_per_signal() {
        let cfg = FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: Some(0.3),
            confidence_per_signal: Some(0.0),
        };
        assert!(create_fuser(&cfg).is_ok(), "zero per_signal is valid");
    }

    #[test]
    fn create_fuser_accepts_baseline_one_and_per_signal_zero() {
        let cfg = FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: Some(1.0),
            confidence_per_signal: Some(0.0),
        };
        assert!(
            create_fuser(&cfg).is_ok(),
            "baseline 1.0 with per_signal 0.0 is valid"
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_direct_fuser_config_from_yaml() {
        let yaml = "type: direct\ninclude_unreachable: true\n";
        let cfg: FuserConfig = serde_yaml_ng::from_str(yaml).expect("deserialize");
        let FuserConfig::Direct {
            include_unreachable,
            confidence_baseline,
            confidence_per_signal,
        } = cfg;
        assert_eq!(include_unreachable, Some(true));
        assert!(confidence_baseline.is_none());
        assert!(confidence_per_signal.is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_direct_fuser_config_full_yaml() {
        let yaml = "type: direct\ninclude_unreachable: false\nconfidence_baseline: 0.2\nconfidence_per_signal: 0.15\n";
        let cfg: FuserConfig = serde_yaml_ng::from_str(yaml).expect("deserialize");
        let FuserConfig::Direct {
            include_unreachable,
            confidence_baseline,
            confidence_per_signal,
        } = cfg;
        assert_eq!(include_unreachable, Some(false));
        assert_eq!(confidence_baseline, Some(0.2));
        assert_eq!(confidence_per_signal, Some(0.15));
    }

    #[test]
    fn direct_fuser_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<DirectFuser>();
        assert_send_sync::<dyn Fuser>();
        assert_send_sync::<Box<dyn Fuser>>();
    }
}
