pub mod platform_rules;
pub mod role_rules;

use regex::Regex;
use schemars::JsonSchema;

use crate::error::{ClassifierError, RastreoError};
use crate::model::device::DeviceRecord;
use crate::model::outcome::Signal;

/// Assigns canonical `platform` / `role` values on a `DeviceRecord` based on the signals fused into it.
///
/// Runs after per-IP fusion and identity correlation, before `scan_metadata` stamping and encoding.
/// Implementations mutate the record in place. The classifier sees the fully-fused record but does
/// not see `scan_metadata` — classifiers must not depend on scan-level metadata.
pub trait Classifier: Send + Sync {
    fn classify(&self, record: &mut DeviceRecord) -> Result<(), RastreoError>;
}

/// Default classifier that leaves every record untouched. Used when no classifier is configured.
pub struct NoopClassifier;

impl Classifier for NoopClassifier {
    fn classify(&self, _record: &mut DeviceRecord) -> Result<(), RastreoError> {
        Ok(())
    }
}

/// Which probe-emitted signal a `PlatformRule` matches against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PlatformSignal {
    SnmpSysDescr,
    SshBanner,
    HttpBanner,
    SnmpSysName,
}

/// How user-supplied rules combine with the baked-in default rules.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MergeMode {
    /// User rules PREPEND the baked-in list. First-match wins across the combined list.
    #[default]
    Extend,
    /// Only user rules run; baked-in rules are ignored.
    Replace,
}

/// A single regex-based platform-detection rule.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlatformRule {
    pub signal: PlatformSignal,
    pub pattern: String,
    pub platform: String,
    /// Named regex capture group (e.g. `version` for `(?P<version>\d+\.\d+)`) whose matched text populates `DeviceRecord::os_version`. When absent, or when the group is not present in the actual match, `os_version` stays `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version_capture: Option<String>,
    /// Named regex capture group whose matched text populates `DeviceRecord::ssh_version`. Only meaningful for `signal: SshBanner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_version_capture: Option<String>,
    /// Named regex capture group whose matched text populates `DeviceRecord::http_server`. Only meaningful for `signal: HttpBanner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_server_capture: Option<String>,
    /// Named regex capture group whose matched text populates `DeviceRecord::http_version`. Only meaningful for `signal: HttpBanner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version_capture: Option<String>,
}

/// A single role-detection rule. Two match strategies are supported: exact byte-prefix on `SnmpSysObjectId` and all-of set membership over `OpenPort` signals.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RoleRule {
    /// Matches when the record carries any `Signal::SnmpSysObjectId(oid)` whose dotted string starts with `prefix`. Case-sensitive byte comparison.
    SysObjectIdPrefix { prefix: String, role: String },
    /// Matches when the record carries a `Signal::OpenPort(p)` for every `p` in `ports`. Empty `ports` is rejected at classifier construction.
    PortsOpen { ports: Vec<u16>, role: String },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClassifierConfig {
    Noop,
    Rules {
        #[serde(default)]
        merge_mode: MergeMode,
        #[serde(default)]
        platform_rules: Vec<PlatformRule>,
        #[serde(default)]
        role_rules: Vec<RoleRule>,
    },
}

pub fn create_classifier(config: &ClassifierConfig) -> Result<Box<dyn Classifier>, RastreoError> {
    match config {
        ClassifierConfig::Noop => Ok(Box::new(NoopClassifier)),
        ClassifierConfig::Rules {
            merge_mode,
            platform_rules,
            role_rules,
        } => Ok(Box::new(RulesClassifier::new(
            *merge_mode,
            platform_rules.clone(),
            role_rules.clone(),
        )?)),
    }
}

struct CompiledRule {
    signal: PlatformSignal,
    regex: Regex,
    platform: String,
    os_version_capture: Option<String>,
    ssh_version_capture: Option<String>,
    http_server_capture: Option<String>,
    http_version_capture: Option<String>,
}

struct PlatformMatch {
    os_version: Option<String>,
    ssh_version: Option<String>,
    http_server: Option<String>,
    http_version: Option<String>,
}

/// Classifier that walks a device's `signals` and assigns `platform` + `os_version` from the first matching platform rule, then `role` from the first matching role rule.
pub struct RulesClassifier {
    platform_rules: Vec<CompiledRule>,
    role_rules: Vec<RoleRule>,
}

impl RulesClassifier {
    /// Builds a classifier by resolving `merge_mode` into an effective platform + role rule list, compiling each platform pattern, and validating each role rule.
    /// Returns `ClassifierError::InvalidRegex` if any pattern fails to compile, or `ClassifierError::InvalidRoleRule` if a role rule fails validation.
    pub fn new(
        merge_mode: MergeMode,
        user_platform_rules: Vec<PlatformRule>,
        user_role_rules: Vec<RoleRule>,
    ) -> Result<Self, ClassifierError> {
        let effective_platform = match merge_mode {
            MergeMode::Extend => {
                let mut merged = user_platform_rules;
                merged.extend(platform_rules::baked_platform_rules());
                merged
            }
            MergeMode::Replace => user_platform_rules,
        };

        let mut compiled = Vec::with_capacity(effective_platform.len());
        for rule in effective_platform {
            let regex =
                Regex::new(&rule.pattern).map_err(|source| ClassifierError::InvalidRegex {
                    pattern: rule.pattern.clone(),
                    source,
                })?;
            compiled.push(CompiledRule {
                signal: rule.signal,
                regex,
                platform: rule.platform,
                os_version_capture: rule.os_version_capture,
                ssh_version_capture: rule.ssh_version_capture,
                http_server_capture: rule.http_server_capture,
                http_version_capture: rule.http_version_capture,
            });
        }

        let effective_role = match merge_mode {
            MergeMode::Extend => {
                let mut merged = user_role_rules;
                merged.extend(role_rules::baked_role_rules());
                merged
            }
            MergeMode::Replace => user_role_rules,
        };
        for rule in &effective_role {
            match rule {
                RoleRule::PortsOpen { ports, role } if ports.is_empty() => {
                    return Err(ClassifierError::InvalidRoleRule(format!(
                        "ports_open rule for role `{role}` has an empty ports list"
                    )));
                }
                RoleRule::SysObjectIdPrefix { prefix, role } if prefix.is_empty() => {
                    return Err(ClassifierError::InvalidRoleRule(format!(
                        "sys_object_id_prefix rule for role `{role}` has an empty prefix"
                    )));
                }
                _ => {}
            }
        }

        Ok(Self {
            platform_rules: compiled,
            role_rules: effective_role,
        })
    }
}

impl Classifier for RulesClassifier {
    fn classify(&self, record: &mut DeviceRecord) -> Result<(), RastreoError> {
        if record.platform.is_none() {
            for rule in &self.platform_rules {
                if let Some(matched) = platform_rule_match(rule, record) {
                    record.platform = Some(rule.platform.clone());
                    if let Some(v) = matched.os_version {
                        record.os_version = Some(v);
                    }
                    if let Some(v) = matched.ssh_version {
                        record.ssh_version = Some(v);
                    }
                    if let Some(v) = matched.http_server {
                        record.http_server = Some(v);
                    }
                    if let Some(v) = matched.http_version {
                        record.http_version = Some(v);
                    }
                    break;
                }
            }
        }

        if record.role.is_none() {
            for rule in &self.role_rules {
                if role_rule_matches(rule, record) {
                    record.role = Some(role_of(rule).to_string());
                    break;
                }
            }
        }

        Ok(())
    }
}

fn platform_rule_match(rule: &CompiledRule, record: &DeviceRecord) -> Option<PlatformMatch> {
    for signal in &record.signals {
        let Some(text) = signal_text_for(signal, rule.signal) else {
            continue;
        };
        if let Some(caps) = rule.regex.captures(text) {
            let capture_by = |name: Option<&str>| -> Option<String> {
                name.and_then(|n| caps.name(n))
                    .map(|m| m.as_str().to_string())
            };
            return Some(PlatformMatch {
                os_version: capture_by(rule.os_version_capture.as_deref()),
                ssh_version: capture_by(rule.ssh_version_capture.as_deref()),
                http_server: capture_by(rule.http_server_capture.as_deref()),
                http_version: capture_by(rule.http_version_capture.as_deref()),
            });
        }
    }
    None
}

fn role_rule_matches(rule: &RoleRule, record: &DeviceRecord) -> bool {
    match rule {
        RoleRule::SysObjectIdPrefix { prefix, .. } => record
            .signals
            .iter()
            .any(|s| matches!(s, Signal::SnmpSysObjectId(oid) if oid.starts_with(prefix.as_str()))),
        RoleRule::PortsOpen { ports, .. } => ports.iter().all(|want| {
            record
                .signals
                .iter()
                .any(|s| matches!(s, Signal::OpenPort(p) if p == want))
        }),
    }
}

fn role_of(rule: &RoleRule) -> &str {
    match rule {
        RoleRule::SysObjectIdPrefix { role, .. } | RoleRule::PortsOpen { role, .. } => {
            role.as_str()
        }
    }
}

fn signal_text_for(signal: &Signal, want: PlatformSignal) -> Option<&str> {
    match (signal, want) {
        (Signal::SnmpSysDescr(s), PlatformSignal::SnmpSysDescr) => Some(s.as_str()),
        (Signal::SshBanner(s), PlatformSignal::SshBanner) => Some(s.as_str()),
        (Signal::HttpBanner(s), PlatformSignal::HttpBanner) => Some(s.as_str()),
        (Signal::SnmpSysName(s), PlatformSignal::SnmpSysName) => Some(s.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use crate::model::device::{
        Confidence, IdentityKey, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
    };
    use crate::model::scan::ScanMetadata;

    fn empty_record() -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new("ip:10.0.0.1").expect("identity"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            mac: None,
            manufacturer: None,
            platform: None,
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: None,
            confidence: Confidence::new(0.1).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: Vec::new(),
            probe_kinds: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: ScanMetadata::default(),
        }
    }

    fn cisco_ios_sys_descr() -> Signal {
        Signal::SnmpSysDescr(
            "Cisco IOS Software, C3560E Software (C3560E-UNIVERSALK9-M), Version 15.7(3)M, RELEASE"
                .to_string(),
        )
    }

    fn extend_rules(user: Vec<PlatformRule>) -> ClassifierConfig {
        ClassifierConfig::Rules {
            merge_mode: MergeMode::Extend,
            platform_rules: user,
            role_rules: Vec::new(),
        }
    }

    fn replace_rules(user: Vec<PlatformRule>) -> ClassifierConfig {
        ClassifierConfig::Rules {
            merge_mode: MergeMode::Replace,
            platform_rules: user,
            role_rules: Vec::new(),
        }
    }

    fn extend_role_rules(user: Vec<RoleRule>) -> ClassifierConfig {
        ClassifierConfig::Rules {
            merge_mode: MergeMode::Extend,
            platform_rules: Vec::new(),
            role_rules: user,
        }
    }

    fn replace_role_rules(user: Vec<RoleRule>) -> ClassifierConfig {
        ClassifierConfig::Rules {
            merge_mode: MergeMode::Replace,
            platform_rules: Vec::new(),
            role_rules: user,
        }
    }

    #[test]
    fn noop_classifier_leaves_record_unchanged() {
        let mut record = empty_record();
        let before = record.clone();
        NoopClassifier
            .classify(&mut record)
            .expect("noop is infallible");
        assert!(record.platform.is_none());
        assert!(record.role.is_none());
        assert_eq!(record.identity_key.as_str(), before.identity_key.as_str());
        assert_eq!(record.mgmt_ip, before.mgmt_ip);
        assert_eq!(record.confidence.value(), before.confidence.value());
        assert_eq!(record.signals.len(), before.signals.len());
    }

    #[test]
    fn noop_classifier_does_not_overwrite_prepopulated_platform_or_role() {
        let mut record = empty_record();
        record.platform = Some("cisco_ios".into());
        record.role = Some("router".into());
        NoopClassifier
            .classify(&mut record)
            .expect("noop is infallible");
        assert_eq!(record.platform.as_deref(), Some("cisco_ios"));
        assert_eq!(record.role.as_deref(), Some("router"));
    }

    #[test]
    fn create_classifier_produces_noop_for_noop_config() {
        let c = create_classifier(&ClassifierConfig::Noop).expect("create");
        let mut record = empty_record();
        c.classify(&mut record).expect("noop is infallible");
        assert!(record.platform.is_none());
        assert!(record.role.is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn classifier_config_deserializes_noop_from_yaml() {
        let yaml = "type: noop\n";
        let cfg: ClassifierConfig = serde_yaml_ng::from_str(yaml).expect("deserialize");
        assert!(matches!(cfg, ClassifierConfig::Noop));
    }

    #[test]
    fn classifier_config_deserializes_noop_from_json() {
        let json = r#"{"type":"noop"}"#;
        let cfg: ClassifierConfig = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(cfg, ClassifierConfig::Noop));
    }

    #[test]
    fn classifier_config_serializes_noop_with_type_tag() {
        let json = serde_json::to_value(ClassifierConfig::Noop).expect("serialize");
        assert_eq!(json["type"], "noop");
    }

    #[test]
    fn classifier_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<NoopClassifier>();
        assert_send_sync::<RulesClassifier>();
        assert_send_sync::<dyn Classifier>();
        assert_send_sync::<Box<dyn Classifier>>();
        assert_send_sync::<ClassifierConfig>();
        assert_send_sync::<PlatformRule>();
        assert_send_sync::<PlatformSignal>();
        assert_send_sync::<MergeMode>();
        assert_send_sync::<RoleRule>();
    }

    #[test]
    fn rules_classifier_populates_platform_from_snmp_sys_descr() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(cisco_ios_sys_descr());
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("cisco_ios"));
    }

    #[test]
    fn rules_classifier_captures_os_version() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(cisco_ios_sys_descr());
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.os_version.as_deref(), Some("15.7"));
    }

    #[test]
    fn rules_classifier_preserves_prepopulated_platform() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.platform = Some("manual_override".into());
        record.signals.push(cisco_ios_sys_descr());
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("manual_override"));
        assert!(record.os_version.is_none());
    }

    #[test]
    fn rules_classifier_first_matching_rule_wins() {
        let user = vec![PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"Cisco".to_string(),
            platform: "user_cisco".to_string(),
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        }];
        let c = create_classifier(&extend_rules(user)).expect("create");
        let mut record = empty_record();
        record.signals.push(cisco_ios_sys_descr());
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("user_cisco"));
    }

    #[test]
    fn rules_classifier_skips_when_no_signal_matches() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::OpenPort(22));
        record
            .signals
            .push(Signal::SnmpSysDescr("mystery-vendor v1".into()));
        c.classify(&mut record).expect("classify ok");
        assert!(record.platform.is_none());
        assert!(record.os_version.is_none());
    }

    #[test]
    fn rules_classifier_ssh_banner_infers_linux() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::SshBanner(
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13".into(),
        ));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("linux"));
        assert_eq!(record.os_version.as_deref(), Some("Ubuntu"));
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_9.6p1"));
    }

    #[test]
    fn baked_ssh_rule_populates_platform_linux_os_version_ubuntu_and_ssh_version() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::SshBanner(
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".into(),
        ));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("linux"));
        assert_eq!(record.os_version.as_deref(), Some("Ubuntu"));
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_8.9p1"));
        assert!(record.http_server.is_none());
        assert!(record.http_version.is_none());
    }

    #[test]
    fn baked_ssh_rule_populates_debian_os_version_and_ssh_version() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SshBanner("SSH-2.0-OpenSSH_9.2p1 Debian-1".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("linux"));
        assert_eq!(record.os_version.as_deref(), Some("Debian"));
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_9.2p1"));
    }

    #[test]
    fn baked_http_rule_populates_platform_linux_and_http_server_and_http_version() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::HttpBanner("nginx/1.24.0".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("linux"));
        assert_eq!(record.http_server.as_deref(), Some("nginx"));
        assert_eq!(record.http_version.as_deref(), Some("1.24.0"));
        assert!(record.os_version.is_none());
        assert!(record.ssh_version.is_none());
    }

    #[test]
    fn baked_http_rule_populates_apache_server_and_version() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::HttpBanner("Apache/2.4.58".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("linux"));
        assert_eq!(record.http_server.as_deref(), Some("Apache"));
        assert_eq!(record.http_version.as_deref(), Some("2.4.58"));
        assert!(record.os_version.is_none());
    }

    #[test]
    fn prepopulated_platform_skips_classifier_and_preserves_ssh_version_none() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.platform = Some("manual_override".into());
        record.ssh_version = Some("manual".into());
        record
            .signals
            .push(Signal::SshBanner("SSH-2.0-OpenSSH_9.2p1 Debian-1".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("manual_override"));
        assert_eq!(record.ssh_version.as_deref(), Some("manual"));
    }

    #[test]
    fn rules_classifier_merge_mode_extend_prepends_user_rules() {
        let user = vec![PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"^Cisco IOS Software".to_string(),
            platform: "user_defined".to_string(),
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        }];
        let c = create_classifier(&extend_rules(user)).expect("create");
        let mut record = empty_record();
        record.signals.push(cisco_ios_sys_descr());
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("user_defined"));
    }

    #[test]
    fn rules_classifier_merge_mode_replace_uses_only_user_rules() {
        let user = vec![PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"^SomethingElse".to_string(),
            platform: "user_only".to_string(),
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        }];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record.signals.push(cisco_ios_sys_descr());
        c.classify(&mut record).expect("classify ok");
        assert!(
            record.platform.is_none(),
            "baked-in cisco_ios rule must not run under Replace"
        );
    }

    #[test]
    fn rules_classifier_invalid_regex_fails_at_construction() {
        let user = vec![PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"(unclosed".to_string(),
            platform: "irrelevant".to_string(),
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        }];
        let result = create_classifier(&extend_rules(user));
        let err = match result {
            Ok(_) => panic!("invalid regex must fail"),
            Err(e) => e,
        };
        assert!(matches!(err, RastreoError::Classifier(_)));
    }

    #[test]
    fn rules_classifier_missing_capture_group_soft_fails_version() {
        let user = vec![PlatformRule {
            signal: PlatformSignal::SshBanner,
            pattern: r"^SSH-2\.0-OpenSSH".to_string(),
            platform: "openssh".to_string(),
            os_version_capture: Some("nonexistent".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        }];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SshBanner("SSH-2.0-OpenSSH_9.6".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("openssh"));
        assert!(record.os_version.is_none());
    }

    #[test]
    fn rules_classifier_snmp_sys_name_signal_kind_matches() {
        let user = vec![PlatformRule {
            signal: PlatformSignal::SnmpSysName,
            pattern: r"^Cisco-Nexus-(?P<version>\d+)".to_string(),
            platform: "cisco_nxos".to_string(),
            os_version_capture: Some("version".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        }];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysName("Cisco-Nexus-9000".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("cisco_nxos"));
        assert_eq!(record.os_version.as_deref(), Some("9000"));
    }

    #[test]
    fn baked_platform_rules_snapshot_matches_expected_count() {
        assert_eq!(
            platform_rules::baked_platform_rules().len(),
            11,
            "if you added or removed a baked-in rule, update docs/site/docs/discover/classification.md AND this count"
        );
    }

    #[test]
    fn baked_rules_match_realistic_fixtures() {
        struct Case {
            signal_kind: PlatformSignal,
            input: &'static str,
            platform: &'static str,
            os_version: Option<&'static str>,
            ssh_version: Option<&'static str>,
            http_server: Option<&'static str>,
            http_version: Option<&'static str>,
        }

        let cases: &[Case] = &[
            Case {
                signal_kind: PlatformSignal::SnmpSysDescr,
                input: "Cisco IOS Software, C3560CX Software (C3560CX-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE",
                platform: "cisco_ios",
                os_version: Some("15.2"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::SnmpSysDescr,
                input: "Cisco IOS XR Software, Version 7.5.2, RELEASE SOFTWARE",
                platform: "cisco_ios_xr",
                os_version: Some("7.5.2"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::SnmpSysDescr,
                input: "Cisco NX-OS(tm) n9000, Software (nxos), Version 9.3(10), RELEASE SOFTWARE",
                platform: "cisco_nxos",
                os_version: Some("9.3"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::SnmpSysDescr,
                input: "Juniper Networks, Inc. mx240 internet router, kernel JUNOS 21.4R3-S4.9",
                platform: "junos",
                os_version: Some("21.4"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::SnmpSysDescr,
                input: "Arista Networks EOS version 4.29.3M running on an Arista Networks DCS-7060CX2-32S",
                platform: "arista_eos",
                os_version: Some("4.29.3"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::SnmpSysDescr,
                input: "Linux hostname 5.15.0-91-generic #101-Ubuntu SMP Wed Nov 15 20:12:47 UTC 2023",
                platform: "linux",
                os_version: Some("5.15.0"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::SshBanner,
                input: "SSH-2.0-OpenSSH_9.0p1 Ubuntu-3ubuntu0.1",
                platform: "linux",
                os_version: Some("Ubuntu"),
                ssh_version: Some("OpenSSH_9.0p1"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::SshBanner,
                input: "SSH-2.0-OpenSSH_9.2p1 Debian-1",
                platform: "linux",
                os_version: Some("Debian"),
                ssh_version: Some("OpenSSH_9.2p1"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::SshBanner,
                input: "SSH-2.0-OpenSSH_9.5 FreeBSD-20231016",
                platform: "freebsd",
                os_version: Some("FreeBSD"),
                ssh_version: Some("OpenSSH_9.5"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: PlatformSignal::HttpBanner,
                input: "nginx/1.24.0",
                platform: "linux",
                os_version: None,
                ssh_version: None,
                http_server: Some("nginx"),
                http_version: Some("1.24.0"),
            },
            Case {
                signal_kind: PlatformSignal::HttpBanner,
                input: "Apache/2.4.58 (Ubuntu)",
                platform: "linux",
                os_version: None,
                ssh_version: None,
                http_server: Some("Apache"),
                http_version: Some("2.4.58"),
            },
        ];

        let classifier = create_classifier(&extend_rules(vec![])).expect("create");
        for case in cases {
            let mut record = empty_record();
            let signal = match case.signal_kind {
                PlatformSignal::SnmpSysDescr => Signal::SnmpSysDescr(case.input.to_string()),
                PlatformSignal::SshBanner => Signal::SshBanner(case.input.to_string()),
                PlatformSignal::HttpBanner => Signal::HttpBanner(case.input.to_string()),
                PlatformSignal::SnmpSysName => Signal::SnmpSysName(case.input.to_string()),
            };
            record.signals.push(signal);
            classifier.classify(&mut record).expect("classify ok");
            let input = case.input;
            assert_eq!(
                record.platform.as_deref(),
                Some(case.platform),
                "input `{input}` should classify as `{}`",
                case.platform
            );
            assert_eq!(
                record.os_version.as_deref(),
                case.os_version,
                "input `{input}` should capture os_version {:?}",
                case.os_version
            );
            assert_eq!(
                record.ssh_version.as_deref(),
                case.ssh_version,
                "input `{input}` should capture ssh_version {:?}",
                case.ssh_version
            );
            assert_eq!(
                record.http_server.as_deref(),
                case.http_server,
                "input `{input}` should capture http_server {:?}",
                case.http_server
            );
            assert_eq!(
                record.http_version.as_deref(),
                case.http_version,
                "input `{input}` should capture http_version {:?}",
                case.http_version
            );
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn classifier_config_deserializes_rules_variant_with_defaults() {
        let yaml = "type: rules\n";
        let cfg: ClassifierConfig = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match cfg {
            ClassifierConfig::Rules {
                merge_mode,
                platform_rules,
                role_rules,
            } => {
                assert_eq!(merge_mode, MergeMode::Extend);
                assert!(platform_rules.is_empty());
                assert!(role_rules.is_empty());
            }
            _ => panic!("expected Rules variant"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn classifier_config_deserializes_rules_variant_fully_populated() {
        let yaml = r#"
type: rules
merge_mode: replace
platform_rules:
  - signal: snmp_sys_descr
    pattern: "^Cisco IOS Software.*Version (?P<version>15\\.\\d+)"
    platform: cisco_ios
    os_version_capture: version
  - signal: ssh_banner
    pattern: "^SSH-2\\.0-OpenSSH_.*Ubuntu"
    platform: linux
"#;
        let cfg: ClassifierConfig = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match cfg {
            ClassifierConfig::Rules {
                merge_mode,
                platform_rules,
                role_rules,
            } => {
                assert_eq!(merge_mode, MergeMode::Replace);
                assert_eq!(platform_rules.len(), 2);
                assert_eq!(platform_rules[0].platform, "cisco_ios");
                assert_eq!(
                    platform_rules[0].os_version_capture.as_deref(),
                    Some("version")
                );
                assert_eq!(platform_rules[1].platform, "linux");
                assert!(platform_rules[1].os_version_capture.is_none());
                assert!(role_rules.is_empty());
            }
            _ => panic!("expected Rules variant"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn classifier_config_deserializes_rules_variant_with_role_rules() {
        let yaml = r#"
type: rules
platform_rules:
  - signal: snmp_sys_descr
    pattern: "^Cisco IOS Software"
    platform: cisco_ios
role_rules:
  - type: sys_object_id_prefix
    prefix: "1.3.6.1.4.1.9.1"
    role: router
  - type: ports_open
    ports: [22, 179]
    role: router
"#;
        let cfg: ClassifierConfig = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match cfg {
            ClassifierConfig::Rules {
                platform_rules,
                role_rules,
                ..
            } => {
                assert_eq!(platform_rules.len(), 1);
                assert_eq!(role_rules.len(), 2);
                assert!(matches!(role_rules[0], RoleRule::SysObjectIdPrefix { .. }));
                assert!(matches!(role_rules[1], RoleRule::PortsOpen { .. }));
            }
            _ => panic!("expected Rules variant"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn role_rule_sys_object_id_prefix_deserializes_from_yaml() {
        let yaml = r#"
type: sys_object_id_prefix
prefix: "1.3.6.1.4.1.9.1"
role: router
"#;
        let rule: RoleRule = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match rule {
            RoleRule::SysObjectIdPrefix { prefix, role } => {
                assert_eq!(prefix, "1.3.6.1.4.1.9.1");
                assert_eq!(role, "router");
            }
            _ => panic!("expected SysObjectIdPrefix"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn role_rule_ports_open_deserializes_from_yaml() {
        let yaml = r#"
type: ports_open
ports: [22, 179]
role: router
"#;
        let rule: RoleRule = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match rule {
            RoleRule::PortsOpen { ports, role } => {
                assert_eq!(ports, vec![22, 179]);
                assert_eq!(role, "router");
            }
            _ => panic!("expected PortsOpen"),
        }
    }

    #[test]
    fn platform_signal_serializes_snake_case() {
        for (variant, wire) in [
            (PlatformSignal::SnmpSysDescr, "\"snmp_sys_descr\""),
            (PlatformSignal::SshBanner, "\"ssh_banner\""),
            (PlatformSignal::HttpBanner, "\"http_banner\""),
            (PlatformSignal::SnmpSysName, "\"snmp_sys_name\""),
        ] {
            let s = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(s, wire);
            let back: PlatformSignal = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn merge_mode_default_is_extend() {
        assert_eq!(MergeMode::default(), MergeMode::Extend);
    }

    #[test]
    fn merge_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&MergeMode::Extend).expect("serialize"),
            "\"extend\""
        );
        assert_eq!(
            serde_json::to_string(&MergeMode::Replace).expect("serialize"),
            "\"replace\""
        );
    }

    #[test]
    fn rules_classifier_populates_role_from_sys_object_id_prefix() {
        let user = vec![RoleRule::SysObjectIdPrefix {
            prefix: "1.3.6.1.4.1.9.1".into(),
            role: "router".into(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysObjectId("1.3.6.1.4.1.9.1.2050".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("router"));
    }

    #[test]
    fn rules_classifier_populates_role_from_ports_open() {
        let c = create_classifier(&extend_role_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::OpenPort(22));
        record.signals.push(Signal::OpenPort(179));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("router"));
    }

    #[test]
    fn rules_classifier_ports_open_requires_all_ports() {
        let user = vec![RoleRule::PortsOpen {
            ports: vec![22, 179],
            role: "router".into(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::OpenPort(22));
        c.classify(&mut record).expect("classify ok");
        assert!(record.role.is_none());
    }

    #[test]
    fn rules_classifier_preserves_prepopulated_role() {
        let user = vec![RoleRule::SysObjectIdPrefix {
            prefix: "1.3.6.1.4.1.9.1".into(),
            role: "router".into(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record.role = Some("manual_override".into());
        record
            .signals
            .push(Signal::SnmpSysObjectId("1.3.6.1.4.1.9.1.2050".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("manual_override"));
    }

    #[test]
    fn rules_classifier_role_first_matching_rule_wins() {
        let user = vec![
            RoleRule::PortsOpen {
                ports: vec![22],
                role: "user_first".into(),
            },
            RoleRule::PortsOpen {
                ports: vec![22],
                role: "user_second".into(),
            },
        ];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::OpenPort(22));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("user_first"));
    }

    #[test]
    fn rules_classifier_role_skips_when_no_signal_matches() {
        let c = create_classifier(&extend_role_rules(vec![])).expect("create");
        let mut record = empty_record();
        c.classify(&mut record).expect("classify ok");
        assert!(record.role.is_none());
    }

    #[test]
    fn rules_classifier_snmp_oid_trumps_port_heuristic() {
        let user = vec![
            RoleRule::SysObjectIdPrefix {
                prefix: "1.3.6.1.4.1.9.1".into(),
                role: "snmp_router".into(),
            },
            RoleRule::PortsOpen {
                ports: vec![22, 179],
                role: "port_router".into(),
            },
        ];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysObjectId("1.3.6.1.4.1.9.1.2050".into()));
        record.signals.push(Signal::OpenPort(22));
        record.signals.push(Signal::OpenPort(179));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("snmp_router"));
    }

    #[test]
    fn rules_classifier_role_merge_mode_extend_prepends_user_rules() {
        let user = vec![RoleRule::PortsOpen {
            ports: vec![22, 179],
            role: "user_router".into(),
        }];
        let c = create_classifier(&extend_role_rules(user)).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::OpenPort(22));
        record.signals.push(Signal::OpenPort(179));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("user_router"));
    }

    #[test]
    fn rules_classifier_role_merge_mode_replace_uses_only_user_rules() {
        let user = vec![RoleRule::PortsOpen {
            ports: vec![8080],
            role: "user_only".into(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::OpenPort(22));
        record.signals.push(Signal::OpenPort(179));
        c.classify(&mut record).expect("classify ok");
        assert!(
            record.role.is_none(),
            "baked router heuristic must not run under Replace"
        );
    }

    #[test]
    fn role_rule_ports_open_with_empty_ports_fails_construction() {
        let user = vec![RoleRule::PortsOpen {
            ports: vec![],
            role: "invalid".into(),
        }];
        let result = create_classifier(&replace_role_rules(user));
        let err = match result {
            Ok(_) => panic!("empty ports must fail construction"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            RastreoError::Classifier(ClassifierError::InvalidRoleRule(_))
        ));
    }

    #[test]
    fn role_rule_sys_object_id_prefix_with_empty_prefix_fails_construction() {
        let user = vec![RoleRule::SysObjectIdPrefix {
            prefix: String::new(),
            role: "invalid".into(),
        }];
        let result = create_classifier(&replace_role_rules(user));
        let err = match result {
            Ok(_) => panic!("empty prefix must fail construction"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            RastreoError::Classifier(ClassifierError::InvalidRoleRule(_))
        ));
    }

    #[test]
    fn baked_role_rules_snapshot_matches_expected_count() {
        assert_eq!(
            role_rules::baked_role_rules().len(),
            5,
            "if you added or removed a baked-in role rule, update docs/site/docs/discover/classification.md AND this count"
        );
    }

    #[test]
    fn baked_role_rules_match_realistic_fixtures() {
        let cases: &[(&[u16], &str)] = &[
            (&[22, 179], "router"),
            (&[22, 443, 830], "router"),
            (&[443], "web_server"),
            (&[80], "web_server"),
            (&[22], "host"),
        ];

        let classifier = create_classifier(&extend_role_rules(vec![])).expect("create");
        for (ports, expected_role) in cases {
            let mut record = empty_record();
            for p in *ports {
                record.signals.push(Signal::OpenPort(*p));
            }
            classifier.classify(&mut record).expect("classify ok");
            assert_eq!(
                record.role.as_deref(),
                Some(*expected_role),
                "fixture ports {ports:?} should classify to `{expected_role}`"
            );
        }
    }
}
