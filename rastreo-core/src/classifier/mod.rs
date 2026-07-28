pub mod platform_rules;
pub mod role_rules;

use regex::Regex;
use schemars::JsonSchema;

use crate::error::{ClassifierError, RastreoError};
use crate::model::device::DeviceRecord;
use crate::model::outcome::Signal;
use crate::oid;

/// Assigns canonical `platform` / `role` values on a `DeviceRecord` based on the signals fused into it.
///
/// Runs after per-IP fusion and identity correlation, before `scan_metadata` stamping and encoding.
/// Implementations mutate the record in place. The classifier sees the fully-fused record but does
/// not see `scan_metadata` — classifiers must not depend on scan-level metadata.
pub trait Classifier: Send + Sync {
    fn classify(&self, record: &mut DeviceRecord) -> Result<(), RastreoError>;
}

/// Pass-through classifier that leaves every record untouched.
pub struct NoopClassifier;

impl Classifier for NoopClassifier {
    fn classify(&self, _record: &mut DeviceRecord) -> Result<(), RastreoError> {
        Ok(())
    }
}

/// Which probe-emitted signal a classifier rule matches against. Shared by `PlatformRule` and `RoleRule::SignalMatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignalKind {
    SnmpSysDescr,
    SshBanner,
    HttpBanner,
    SnmpSysName,
    SnmpSysObjectId,
}

/// Number of `SignalKind` variants — sizes fixed-size arrays indexed by [`SignalKind::index`].
pub const SIGNAL_KIND_COUNT: usize = 5;

impl SignalKind {
    /// Every variant in a stable, deterministic order.
    pub const fn all() -> &'static [SignalKind; SIGNAL_KIND_COUNT] {
        &[
            SignalKind::SnmpSysDescr,
            SignalKind::SshBanner,
            SignalKind::HttpBanner,
            SignalKind::SnmpSysName,
            SignalKind::SnmpSysObjectId,
        ]
    }

    /// Stable index for use in fixed-size `[T; SIGNAL_KIND_COUNT]` arrays.
    pub const fn index(self) -> usize {
        // Const-evaluated per arm, so an index past the count fails to build even
        // when the arm is never reached.
        const fn slot(index: usize) -> usize {
            assert!(index < SIGNAL_KIND_COUNT);
            index
        }
        match self {
            SignalKind::SnmpSysDescr => const { slot(0) },
            SignalKind::SshBanner => const { slot(1) },
            SignalKind::HttpBanner => const { slot(2) },
            SignalKind::SnmpSysName => const { slot(3) },
            SignalKind::SnmpSysObjectId => const { slot(4) },
        }
    }
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
    pub signal: SignalKind,
    pub pattern: String,
    /// Platform label assigned on match. Omit it for a rule that only extracts `ssh_version`, `http_server`, or `http_version` from a service banner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Named regex capture group (e.g. `version` for `(?P<version>\d+\.\d+)`) whose matched text populates the record's `os_version`. Requires `platform`, and is rejected at classifier construction without it. When absent, or when the group is not present in the actual match, `os_version` stays null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version_capture: Option<String>,
    /// Named regex capture group whose matched text populates the record's `ssh_version`. Only meaningful for `signal: ssh_banner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_version_capture: Option<String>,
    /// Named regex capture group whose matched text populates the record's `http_server`. Only meaningful for `signal: http_banner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_server_capture: Option<String>,
    /// Named regex capture group whose matched text populates the record's `http_version`. Requires `http_server_capture`, and is rejected at classifier construction without it. Only meaningful for `signal: http_banner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version_capture: Option<String>,
}

/// A single role-detection rule. Three match strategies are supported: OID-subtree containment on `SnmpSysObjectId`, regex over any signal kind, and all-of set membership over `OpenPort` signals.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RoleRule {
    /// Matches when the record carries a `Signal::SnmpSysObjectId` equal to `prefix` or inside its subtree. Whole arcs are compared, so `1.3.6.1.4.1.9.1` does not match `1.3.6.1.4.1.9.15`. `prefix` must be dotted-decimal with no leading dot, and is rejected at classifier construction otherwise.
    SysObjectIdPrefix { prefix: String, role: String },
    /// Matches when `pattern` matches the text of any `signal`-kind signal on the record.
    SignalMatch {
        signal: SignalKind,
        pattern: String,
        role: String,
    },
    /// Matches when the record carries a `Signal::OpenPort(p)` for every `p` in `ports`. Empty `ports` is rejected at classifier construction.
    PortsOpen { ports: Vec<u16>, role: String },
}

/// Rules that assign `platform` and `role` to a record.
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
    signal: SignalKind,
    regex: Regex,
    platform: Option<String>,
    os_version_capture: Option<String>,
    ssh_version_capture: Option<String>,
    http_server_capture: Option<String>,
    http_version_capture: Option<String>,
}

enum CompiledRoleRule {
    SysObjectIdPrefix {
        prefix: String,
        role: String,
    },
    SignalMatch {
        signal: SignalKind,
        regex: Regex,
        role: String,
    },
    PortsOpen {
        ports: Vec<u16>,
        role: String,
    },
}

struct PlatformMatch {
    os_version: Option<String>,
    ssh_version: Option<String>,
    http_server: Option<String>,
    http_version: Option<String>,
}

/// Classifier that assigns `platform` + `os_version` from the first matching rule that claims a platform, `ssh_version` from the first matching rule that captures it, `http_server` + `http_version` from the first matching rule that captures a server, and `role` from the first matching role rule.
pub struct RulesClassifier {
    platform_rules: Vec<CompiledRule>,
    role_rules: Vec<CompiledRoleRule>,
}

impl RulesClassifier {
    /// Builds a classifier by resolving `merge_mode` into an effective rule list per phase, compiling every pattern, and validating each role rule.
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
            if rule.platform.is_none() {
                if let Some(group) = &rule.os_version_capture {
                    return Err(ClassifierError::InvalidPlatformRule(format!(
                        "platform rule `{}` captures os_version from `{group}` but claims no platform; os_version is the version of the platform, so a rule without one can never write it",
                        rule.pattern
                    )));
                }
            }
            if rule.http_server_capture.is_none() {
                if let Some(group) = &rule.http_version_capture {
                    return Err(ClassifierError::InvalidPlatformRule(format!(
                        "platform rule `{}` captures http_version from `{group}` but captures no http_server; http_version is the version of the http_server, so a rule without one can never write it",
                        rule.pattern
                    )));
                }
            }
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
        let mut compiled_roles = Vec::with_capacity(effective_role.len());
        for rule in effective_role {
            compiled_roles.push(compile_role_rule(rule)?);
        }

        Ok(Self {
            platform_rules: compiled,
            role_rules: compiled_roles,
        })
    }
}

fn compile_role_rule(rule: RoleRule) -> Result<CompiledRoleRule, ClassifierError> {
    match rule {
        RoleRule::SysObjectIdPrefix { prefix, role } => {
            if prefix.is_empty() {
                return Err(ClassifierError::InvalidRoleRule(format!(
                    "sys_object_id_prefix rule for role `{role}` has an empty prefix"
                )));
            }
            if !oid::is_dotted_decimal(&prefix) {
                return Err(ClassifierError::InvalidRoleRule(format!(
                    "sys_object_id_prefix rule for role `{role}` has prefix `{prefix}`, which is not a dotted-decimal OID: expected two or more digit arcs joined by `.` with no leading dot, as in `1.3.6.1.4.1.9.1`"
                )));
            }
            Ok(CompiledRoleRule::SysObjectIdPrefix { prefix, role })
        }
        RoleRule::SignalMatch {
            signal,
            pattern,
            role,
        } => {
            let regex = Regex::new(&pattern)
                .map_err(|source| ClassifierError::InvalidRegex { pattern, source })?;
            Ok(CompiledRoleRule::SignalMatch {
                signal,
                regex,
                role,
            })
        }
        RoleRule::PortsOpen { ports, role } => {
            if ports.is_empty() {
                return Err(ClassifierError::InvalidRoleRule(format!(
                    "ports_open rule for role `{role}` has an empty ports list"
                )));
            }
            Ok(CompiledRoleRule::PortsOpen { ports, role })
        }
    }
}

impl RulesClassifier {
    fn apply_platform_rules(&self, record: &mut DeviceRecord) {
        let mut want_platform = record.platform.is_none();
        let mut want_ssh_version = record.ssh_version.is_none();
        let mut want_http_server = record.http_server.is_none();

        for rule in &self.platform_rules {
            if !(want_platform || want_ssh_version || want_http_server) {
                return;
            }
            let claims_platform = want_platform && rule.platform.is_some();
            let claims_ssh_version = want_ssh_version && rule.ssh_version_capture.is_some();
            let claims_http_server = want_http_server && rule.http_server_capture.is_some();
            if !(claims_platform || claims_ssh_version || claims_http_server) {
                continue;
            }
            let Some(matched) = platform_rule_match(rule, record) else {
                continue;
            };
            if claims_platform {
                record.platform = rule.platform.clone();
                if let Some(v) = matched.os_version {
                    record.os_version = Some(v);
                }
                want_platform = false;
            }
            if claims_ssh_version {
                if let Some(v) = matched.ssh_version {
                    record.ssh_version = Some(v);
                }
                want_ssh_version = false;
            }
            if claims_http_server {
                if let Some(server) = matched.http_server {
                    record.http_server = Some(server);
                    if let Some(version) = matched.http_version {
                        record.http_version = Some(version);
                    }
                }
                want_http_server = false;
            }
        }
    }

    fn apply_role_rules(&self, record: &mut DeviceRecord) {
        if record.role.is_some() {
            return;
        }
        for rule in &self.role_rules {
            if role_rule_matches(rule, record) {
                record.role = Some(role_of(rule).to_string());
                return;
            }
        }
    }
}

impl Classifier for RulesClassifier {
    fn classify(&self, record: &mut DeviceRecord) -> Result<(), RastreoError> {
        self.apply_platform_rules(record);
        self.apply_role_rules(record);
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

fn role_rule_matches(rule: &CompiledRoleRule, record: &DeviceRecord) -> bool {
    match rule {
        CompiledRoleRule::SysObjectIdPrefix { prefix, .. } => record.signals.iter().any(
            |s| matches!(s, Signal::SnmpSysObjectId(value) if oid::has_arc_prefix(value, prefix)),
        ),
        CompiledRoleRule::SignalMatch { signal, regex, .. } => record
            .signals
            .iter()
            .filter_map(|s| signal_text_for(s, *signal))
            .any(|text| regex.is_match(text)),
        CompiledRoleRule::PortsOpen { ports, .. } => ports.iter().all(|want| {
            record
                .signals
                .iter()
                .any(|s| matches!(s, Signal::OpenPort(p) if p == want))
        }),
    }
}

fn role_of(rule: &CompiledRoleRule) -> &str {
    match rule {
        CompiledRoleRule::SysObjectIdPrefix { role, .. }
        | CompiledRoleRule::SignalMatch { role, .. }
        | CompiledRoleRule::PortsOpen { role, .. } => role.as_str(),
    }
}

fn signal_text_for(signal: &Signal, want: SignalKind) -> Option<&str> {
    match want {
        SignalKind::SnmpSysDescr => match signal {
            Signal::SnmpSysDescr(s) => Some(s.as_str()),
            _ => None,
        },
        SignalKind::SshBanner => match signal {
            Signal::SshBanner(s) => Some(s.as_str()),
            _ => None,
        },
        SignalKind::HttpBanner => match signal {
            Signal::HttpBanner(s) => Some(s.as_str()),
            _ => None,
        },
        SignalKind::SnmpSysName => match signal {
            Signal::SnmpSysName(s) => Some(s.as_str()),
            _ => None,
        },
        SignalKind::SnmpSysObjectId => match signal {
            Signal::SnmpSysObjectId(s) => Some(s.as_str()),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::model::device::{
        Confidence, IdentityKey, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
    };
    use crate::model::scan::ScanMetadata;

    fn wire_name(kind: SignalKind) -> &'static str {
        match kind {
            SignalKind::SnmpSysDescr => "snmp_sys_descr",
            SignalKind::SshBanner => "ssh_banner",
            SignalKind::HttpBanner => "http_banner",
            SignalKind::SnmpSysName => "snmp_sys_name",
            SignalKind::SnmpSysObjectId => "snmp_sys_object_id",
        }
    }

    fn empty_record() -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new("ip:10.0.0.1").expect("identity"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
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
            confidence: Confidence::new(0.1).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: Vec::new(),
            probe_kinds: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    fn cisco_ios_sys_descr() -> Signal {
        Signal::SnmpSysDescr(
            "Cisco IOS Software, C3560E Software (C3560E-UNIVERSALK9-M), Version 15.7(3)M, RELEASE"
                .to_string(),
        )
    }

    fn srlinux_sys_descr() -> Signal {
        Signal::SnmpSysDescr(
            "SRLinux-v26.3.3-392-g480f5fa2d04 7220 IXR-D2L Copyright (c) 2000-2026 Nokia. Kernel 7.0.11-orbstack-00360-gc9bc4d96ac70 #1 SMP PREEMPT Thu Jun  4 16:40:25 UTC 2026"
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
        record.signals.push(cisco_ios_sys_descr());
        record.signals.push(Signal::OpenPort(22));
        record.signals.push(Signal::OpenPort(179));
        c.classify(&mut record).expect("noop is infallible");
        assert!(
            record.platform.is_none(),
            "signals the baked platform table matches must stay unclassified under noop"
        );
        assert!(
            record.role.is_none(),
            "signals the baked role table matches must stay unclassified under noop"
        );
        assert!(record.os_version.is_none());
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
        assert_send_sync::<SignalKind>();
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
            signal: SignalKind::SnmpSysDescr,
            pattern: r"Cisco".to_string(),
            platform: Some("user_cisco".to_string()),
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
    fn baked_ssh_rule_captures_ssh_version_and_claims_no_platform() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::SshBanner(
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".into(),
        ));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_8.9p1"));
        assert!(record.platform.is_none());
        assert!(record.os_version.is_none());
        assert!(record.http_server.is_none());
        assert!(record.http_version.is_none());
    }

    #[test]
    fn baked_ssh_rule_captures_ssh_version_from_a_debian_banner() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SshBanner("SSH-2.0-OpenSSH_9.2p1 Debian-1".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_9.2p1"));
        assert!(record.platform.is_none());
        assert!(record.os_version.is_none());
    }

    #[test]
    fn baked_http_rule_captures_server_and_version_and_claims_no_platform() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::HttpBanner("nginx/1.24.0".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.http_server.as_deref(), Some("nginx"));
        assert_eq!(record.http_version.as_deref(), Some("1.24.0"));
        assert!(record.platform.is_none());
        assert!(record.os_version.is_none());
        assert!(record.ssh_version.is_none());
    }

    #[test]
    fn baked_http_rule_captures_apache_server_and_version() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::HttpBanner("Apache/2.4.58".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.http_server.as_deref(), Some("Apache"));
        assert_eq!(record.http_version.as_deref(), Some("2.4.58"));
        assert!(record.platform.is_none());
        assert!(record.os_version.is_none());
    }

    #[test]
    fn baked_srlinux_rule_populates_platform_and_os_version_from_sys_descr() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(srlinux_sys_descr());
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("nokia_srlinux"));
        assert_eq!(record.os_version.as_deref(), Some("26.3.3"));
    }

    #[test]
    fn srlinux_sys_descr_does_not_match_the_generic_linux_rule() {
        let linux_rules: Vec<PlatformRule> = platform_rules::baked_platform_rules()
            .into_iter()
            .filter(|r| r.platform.as_deref() == Some("linux"))
            .collect();
        let c = create_classifier(&replace_rules(linux_rules)).expect("create");
        let mut record = empty_record();
        record.signals.push(srlinux_sys_descr());
        c.classify(&mut record).expect("classify ok");
        assert!(record.platform.is_none());
    }

    #[test]
    fn an_srlinux_device_keeps_its_platform_and_still_reports_ssh_version() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(srlinux_sys_descr());
        record.signals.push(Signal::SshBanner(
            "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2".into(),
        ));
        record
            .signals
            .push(Signal::HttpBanner("gunicorn".to_string()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("nokia_srlinux"));
        assert_eq!(record.os_version.as_deref(), Some("26.3.3"));
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_10.0p2"));
    }

    #[test]
    fn a_platform_win_on_sys_descr_does_not_suppress_the_ssh_version_capture() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.signals.push(cisco_ios_sys_descr());
        record.signals.push(Signal::SshBanner(
            "SSH-2.0-OpenSSH_9.2p1 Debian-1".to_string(),
        ));
        record
            .signals
            .push(Signal::HttpBanner("nginx/1.24.0".to_string()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("cisco_ios"));
        assert_eq!(record.os_version.as_deref(), Some("15.7"));
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_9.2p1"));
        assert_eq!(record.http_server.as_deref(), Some("nginx"));
        assert_eq!(record.http_version.as_deref(), Some("1.24.0"));
    }

    #[test]
    fn each_attribute_is_taken_from_the_first_rule_that_captures_it() {
        let user = vec![
            PlatformRule {
                signal: SignalKind::SshBanner,
                pattern: r"(?P<v>OpenSSH_[\d\.p]+)".to_string(),
                platform: None,
                os_version_capture: None,
                ssh_version_capture: Some("v".to_string()),
                http_server_capture: None,
                http_version_capture: None,
            },
            PlatformRule {
                signal: SignalKind::SshBanner,
                pattern: r"^SSH-(?P<v>2\.0)".to_string(),
                platform: None,
                os_version_capture: None,
                ssh_version_capture: Some("v".to_string()),
                http_server_capture: None,
                http_version_capture: None,
            },
        ];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SshBanner("SSH-2.0-OpenSSH_9.2p1 Debian-1".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.ssh_version.as_deref(), Some("OpenSSH_9.2p1"));
    }

    #[test]
    fn a_rule_that_claims_no_platform_never_writes_one() {
        let user = vec![PlatformRule {
            signal: SignalKind::HttpBanner,
            pattern: r"^(?P<server>gunicorn)".to_string(),
            platform: None,
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: Some("server".to_string()),
            http_version_capture: None,
        }];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::HttpBanner("gunicorn".to_string()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.http_server.as_deref(), Some("gunicorn"));
        assert!(record.platform.is_none());
    }

    #[test]
    fn a_rule_capturing_os_version_without_a_platform_fails_construction() {
        let user = vec![PlatformRule {
            signal: SignalKind::SshBanner,
            pattern: r"^SSH-2\.0-OpenSSH.*(?P<osv>Debian)".to_string(),
            platform: None,
            os_version_capture: Some("osv".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        }];
        let err = match create_classifier(&replace_rules(user)) {
            Ok(_) => panic!("os_version without a platform can never fire and must fail"),
            Err(e) => e,
        };
        let RastreoError::Classifier(ClassifierError::InvalidPlatformRule(message)) = err else {
            panic!("expected InvalidPlatformRule, got {err:?}");
        };
        assert!(message.contains("os_version"), "message was: {message}");
    }

    #[test]
    fn a_rule_capturing_http_version_without_an_http_server_fails_construction() {
        let user = vec![PlatformRule {
            signal: SignalKind::HttpBanner,
            pattern: r"(?P<version>[0-9.]+)$".to_string(),
            platform: None,
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: Some("version".to_string()),
        }];
        let err = match create_classifier(&replace_rules(user)) {
            Ok(_) => panic!("http_version without an http_server can never fire and must fail"),
            Err(e) => e,
        };
        let RastreoError::Classifier(ClassifierError::InvalidPlatformRule(message)) = err else {
            panic!("expected InvalidPlatformRule, got {err:?}");
        };
        assert!(message.contains("http_version"), "message was: {message}");
    }

    #[test]
    fn http_version_never_comes_from_a_different_banner_than_http_server() {
        let user = vec![
            PlatformRule {
                signal: SignalKind::HttpBanner,
                pattern: r"^(?P<server>nginx)$".to_string(),
                platform: None,
                os_version_capture: None,
                ssh_version_capture: None,
                http_server_capture: Some("server".to_string()),
                http_version_capture: None,
            },
            PlatformRule {
                signal: SignalKind::HttpBanner,
                pattern: r"^(?P<server>Apache)/(?P<version>[\d\.]+)".to_string(),
                platform: None,
                os_version_capture: None,
                ssh_version_capture: None,
                http_server_capture: Some("server".to_string()),
                http_version_capture: Some("version".to_string()),
            },
        ];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record.signals.push(Signal::HttpBanner("nginx".into()));
        record
            .signals
            .push(Signal::HttpBanner("Apache/2.4.58".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.http_server.as_deref(), Some("nginx"));
        assert!(
            record.http_version.is_none(),
            "http_version is the version of http_server; it must not be stamped from another server's banner"
        );
    }

    #[test]
    fn http_version_is_not_written_when_the_server_group_did_not_participate() {
        let user = vec![PlatformRule {
            signal: SignalKind::HttpBanner,
            pattern: r"^(?:(?P<server>nginx)|Apache)/(?P<version>[\d\.]+)".to_string(),
            platform: None,
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: Some("server".to_string()),
            http_version_capture: Some("version".to_string()),
        }];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::HttpBanner("Apache/2.4.58".into()));
        c.classify(&mut record).expect("classify ok");
        assert!(record.http_server.is_none());
        assert!(
            record.http_version.is_none(),
            "http_version is the version of http_server; it must not be written without one"
        );
    }

    #[test]
    fn a_matching_http_rule_spends_its_slot_even_when_its_server_group_did_not_participate() {
        let user = vec![
            PlatformRule {
                signal: SignalKind::HttpBanner,
                pattern: r"^(?:(?P<server>nginx)|Apache)/[\d\.]+".to_string(),
                platform: None,
                os_version_capture: None,
                ssh_version_capture: None,
                http_server_capture: Some("server".to_string()),
                http_version_capture: None,
            },
            PlatformRule {
                signal: SignalKind::HttpBanner,
                pattern: r"^(?P<server>Apache)/(?P<version>[\d\.]+)".to_string(),
                platform: None,
                os_version_capture: None,
                ssh_version_capture: None,
                http_server_capture: Some("server".to_string()),
                http_version_capture: Some("version".to_string()),
            },
        ];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::HttpBanner("Apache/2.4.58".into()));
        c.classify(&mut record).expect("classify ok");
        assert!(record.http_server.is_none());
        assert!(record.http_version.is_none());
    }

    #[test]
    fn a_matching_rule_spends_its_slot_even_when_its_capture_group_did_not_participate() {
        let user = vec![
            PlatformRule {
                signal: SignalKind::SshBanner,
                pattern: r"^SSH-2\.0(?:-(?P<v>OpenSSH_[\d\.p]+))?".to_string(),
                platform: None,
                os_version_capture: None,
                ssh_version_capture: Some("v".to_string()),
                http_server_capture: None,
                http_version_capture: None,
            },
            PlatformRule {
                signal: SignalKind::SshBanner,
                pattern: r"-(?P<v>Cisco-[\d\.]+)".to_string(),
                platform: None,
                os_version_capture: None,
                ssh_version_capture: Some("v".to_string()),
                http_server_capture: None,
                http_version_capture: None,
            },
        ];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SshBanner("SSH-2.0-Cisco-1.25".into()));
        c.classify(&mut record).expect("classify ok");
        assert!(record.ssh_version.is_none());
    }

    #[test]
    fn prepopulated_values_are_preserved_field_by_field() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.platform = Some("manual_override".into());
        record.ssh_version = Some("manual".into());
        record.signals.push(cisco_ios_sys_descr());
        record
            .signals
            .push(Signal::SshBanner("SSH-2.0-OpenSSH_9.2p1 Debian-1".into()));
        record
            .signals
            .push(Signal::HttpBanner("nginx/1.24.0".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("manual_override"));
        assert_eq!(record.ssh_version.as_deref(), Some("manual"));
        assert!(record.os_version.is_none());
        assert_eq!(record.http_server.as_deref(), Some("nginx"));
    }

    #[test]
    fn a_prepopulated_http_server_keeps_its_value_and_receives_no_http_version() {
        let c = create_classifier(&extend_rules(vec![])).expect("create");
        let mut record = empty_record();
        record.http_server = Some("manual_override".into());
        record
            .signals
            .push(Signal::HttpBanner("nginx/1.24.0".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.http_server.as_deref(), Some("manual_override"));
        assert!(record.http_version.is_none());
    }

    #[test]
    fn rules_classifier_merge_mode_extend_prepends_user_rules() {
        let user = vec![PlatformRule {
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^Cisco IOS Software".to_string(),
            platform: Some("user_defined".to_string()),
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
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^SomethingElse".to_string(),
            platform: Some("user_only".to_string()),
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
            signal: SignalKind::SnmpSysDescr,
            pattern: r"(unclosed".to_string(),
            platform: Some("irrelevant".to_string()),
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
            signal: SignalKind::SshBanner,
            pattern: r"^SSH-2\.0-OpenSSH".to_string(),
            platform: Some("openssh".to_string()),
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
            signal: SignalKind::SnmpSysName,
            pattern: r"^Cisco-Nexus-(?P<version>\d+)".to_string(),
            platform: Some("cisco_nxos".to_string()),
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
            12,
            "if you added or removed a baked-in rule, update docs/site/docs/discover/classification.md AND this count"
        );
        assert_eq!(
            platform_rules::baked_platform_rules_with_banner_heuristics().len(),
            12,
            "the banner heuristics enrich the default rules rather than appending to them"
        );
    }

    struct Case {
        signal_kind: SignalKind,
        input: &'static str,
        platform: Option<&'static str>,
        os_version: Option<&'static str>,
        ssh_version: Option<&'static str>,
        http_server: Option<&'static str>,
        http_version: Option<&'static str>,
    }

    fn assert_cases(classifier: &dyn Classifier, cases: &[Case]) {
        for case in cases {
            let mut record = empty_record();
            let signal = match case.signal_kind {
                SignalKind::SnmpSysDescr => Signal::SnmpSysDescr(case.input.to_string()),
                SignalKind::SshBanner => Signal::SshBanner(case.input.to_string()),
                SignalKind::HttpBanner => Signal::HttpBanner(case.input.to_string()),
                SignalKind::SnmpSysName => Signal::SnmpSysName(case.input.to_string()),
                SignalKind::SnmpSysObjectId => Signal::SnmpSysObjectId(case.input.to_string()),
            };
            record.signals.push(signal);
            classifier.classify(&mut record).expect("classify ok");
            let input = case.input;
            assert_eq!(
                record.platform.as_deref(),
                case.platform,
                "input `{input}` should classify as {:?}",
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

    #[test]
    fn baked_rules_match_realistic_fixtures() {
        let cases: &[Case] = &[
            Case {
                signal_kind: SignalKind::SnmpSysDescr,
                input: "Cisco IOS Software, C3560CX Software (C3560CX-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE",
                platform: Some("cisco_ios"),
                os_version: Some("15.2"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SnmpSysDescr,
                input: "Cisco IOS XR Software, Version 7.5.2, RELEASE SOFTWARE",
                platform: Some("cisco_ios_xr"),
                os_version: Some("7.5.2"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SnmpSysDescr,
                input: "Cisco NX-OS(tm) n9000, Software (nxos), Version 9.3(10), RELEASE SOFTWARE",
                platform: Some("cisco_nxos"),
                os_version: Some("9.3"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SnmpSysDescr,
                input: "Juniper Networks, Inc. mx240 internet router, kernel JUNOS 21.4R3-S4.9",
                platform: Some("junos"),
                os_version: Some("21.4"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SnmpSysDescr,
                input: "Arista Networks EOS version 4.29.3M running on an Arista Networks DCS-7060CX2-32S",
                platform: Some("arista_eos"),
                os_version: Some("4.29.3"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SnmpSysDescr,
                input: "SRLinux-v26.3.3-392-g480f5fa2d04 7220 IXR-D2L Copyright (c) 2000-2026 Nokia. Kernel 7.0.11-orbstack-00360-gc9bc4d96ac70 #1 SMP PREEMPT Thu Jun  4 16:40:25 UTC 2026",
                platform: Some("nokia_srlinux"),
                os_version: Some("26.3.3"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SnmpSysDescr,
                input: "Linux hostname 5.15.0-91-generic #101-Ubuntu SMP Wed Nov 15 20:12:47 UTC 2023",
                platform: Some("linux"),
                os_version: Some("5.15.0"),
                ssh_version: None,
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SshBanner,
                input: "SSH-2.0-OpenSSH_9.0p1 Ubuntu-3ubuntu0.1",
                platform: None,
                os_version: None,
                ssh_version: Some("OpenSSH_9.0p1"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SshBanner,
                input: "SSH-2.0-OpenSSH_9.2p1 Debian-1",
                platform: None,
                os_version: None,
                ssh_version: Some("OpenSSH_9.2p1"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SshBanner,
                input: "SSH-2.0-OpenSSH_9.5 FreeBSD-20231016",
                platform: None,
                os_version: None,
                ssh_version: Some("OpenSSH_9.5"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::HttpBanner,
                input: "nginx/1.24.0",
                platform: None,
                os_version: None,
                ssh_version: None,
                http_server: Some("nginx"),
                http_version: Some("1.24.0"),
            },
            Case {
                signal_kind: SignalKind::HttpBanner,
                input: "Apache/2.4.58 (Ubuntu)",
                platform: None,
                os_version: None,
                ssh_version: None,
                http_server: Some("Apache"),
                http_version: Some("2.4.58"),
            },
        ];

        let classifier = create_classifier(&extend_rules(vec![])).expect("create");
        assert_cases(classifier.as_ref(), cases);
    }

    #[test]
    fn banner_heuristics_restore_platform_on_the_same_fixtures() {
        let cases: &[Case] = &[
            Case {
                signal_kind: SignalKind::SshBanner,
                input: "SSH-2.0-OpenSSH_9.0p1 Ubuntu-3ubuntu0.1",
                platform: Some("linux"),
                os_version: Some("Ubuntu"),
                ssh_version: Some("OpenSSH_9.0p1"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SshBanner,
                input: "SSH-2.0-OpenSSH_9.2p1 Debian-1",
                platform: Some("linux"),
                os_version: Some("Debian"),
                ssh_version: Some("OpenSSH_9.2p1"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::SshBanner,
                input: "SSH-2.0-OpenSSH_9.5 FreeBSD-20231016",
                platform: Some("freebsd"),
                os_version: Some("FreeBSD"),
                ssh_version: Some("OpenSSH_9.5"),
                http_server: None,
                http_version: None,
            },
            Case {
                signal_kind: SignalKind::HttpBanner,
                input: "nginx/1.24.0",
                platform: Some("linux"),
                os_version: None,
                ssh_version: None,
                http_server: Some("nginx"),
                http_version: Some("1.24.0"),
            },
            Case {
                signal_kind: SignalKind::HttpBanner,
                input: "Apache/2.4.58 (Ubuntu)",
                platform: Some("linux"),
                os_version: None,
                ssh_version: None,
                http_server: Some("Apache"),
                http_version: Some("2.4.58"),
            },
        ];

        let classifier = create_classifier(&replace_rules(
            platform_rules::baked_platform_rules_with_banner_heuristics(),
        ))
        .expect("create");
        assert_cases(classifier.as_ref(), cases);
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
                assert_eq!(platform_rules[0].platform.as_deref(), Some("cisco_ios"));
                assert_eq!(
                    platform_rules[0].os_version_capture.as_deref(),
                    Some("version")
                );
                assert_eq!(platform_rules[1].platform.as_deref(), Some("linux"));
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
    fn signal_kind_all_lists_every_variant_exactly_once() {
        let mut covered = [false; SIGNAL_KIND_COUNT];
        for kind in *SignalKind::all() {
            let index = kind.index();
            assert!(
                index < SIGNAL_KIND_COUNT,
                "{kind:?} indexes past SIGNAL_KIND_COUNT; bump the constant"
            );
            assert!(
                !covered[index],
                "{kind:?} appears twice in SignalKind::all()"
            );
            covered[index] = true;
        }
        assert!(
            covered.iter().all(|seen| *seen),
            "a SignalKind variant is missing from SignalKind::all()"
        );
    }

    #[test]
    fn signal_kind_serializes_snake_case() {
        let mut wires = std::collections::HashSet::new();
        for kind in *SignalKind::all() {
            let s = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(s, format!("\"{}\"", wire_name(kind)));
            assert!(wires.insert(s.clone()), "duplicate wire name {s}");
            let back: SignalKind = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, kind);
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
        let RastreoError::Classifier(ClassifierError::InvalidRoleRule(message)) = err else {
            panic!("expected InvalidRoleRule, got {err:?}");
        };
        assert!(message.contains("empty prefix"), "message was: {message}");
    }

    #[test]
    fn baked_role_rules_snapshot_matches_expected_count() {
        assert_eq!(
            role_rules::baked_role_rules().len(),
            2,
            "if you added or removed a baked-in role rule, update docs/site/docs/discover/classification.md AND this count"
        );
        assert_eq!(
            role_rules::baked_role_rules_with_port_heuristics().len(),
            5,
            "if you added or removed a port heuristic, update docs/site/docs/discover/classification.md AND this count"
        );
    }

    #[test]
    fn baked_role_rules_match_realistic_fixtures() {
        let cases: &[(&[u16], Option<&str>)] = &[
            (&[22, 179], Some("router")),
            (&[22, 443, 830], Some("router")),
            (&[443], None),
            (&[80], None),
            (&[22], None),
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
                *expected_role,
                "fixture ports {ports:?} should classify to `{expected_role:?}`"
            );
        }
    }

    #[test]
    fn port_heuristics_classify_single_port_records_once_opted_in() {
        let cases: &[(&[u16], &str)] = &[
            (&[22, 179], "router"),
            (&[443], "web_server"),
            (&[80], "web_server"),
            (&[22], "host"),
        ];

        let classifier = create_classifier(&replace_role_rules(
            role_rules::baked_role_rules_with_port_heuristics(),
        ))
        .expect("create");
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

    #[test]
    fn sys_object_id_prefix_matches_the_exact_oid() {
        let user = vec![RoleRule::SysObjectIdPrefix {
            prefix: "1.3.6.1.4.1.6527.1.20.26".into(),
            role: "switch".into(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysObjectId("1.3.6.1.4.1.6527.1.20.26".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("switch"));
    }

    #[test]
    fn sys_object_id_prefix_does_not_match_a_sibling_subtree() {
        let user = vec![RoleRule::SysObjectIdPrefix {
            prefix: "1.3.6.1.4.1.9.1".into(),
            role: "router".into(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        for sibling in ["1.3.6.1.4.1.9.15.2", "1.3.6.1.4.1.9.12", "1.3.6.1.4.1.9.1x"] {
            let mut record = empty_record();
            record
                .signals
                .push(Signal::SnmpSysObjectId(sibling.to_string()));
            c.classify(&mut record).expect("classify ok");
            assert_eq!(
                record.role, None,
                "`{sibling}` is outside the 1.3.6.1.4.1.9.1 subtree"
            );
        }
    }

    #[test]
    fn sys_object_id_prefix_with_a_leading_dot_fails_construction() {
        let user = vec![RoleRule::SysObjectIdPrefix {
            prefix: ".1.3.6.1.4.1.9.1".into(),
            role: "router".into(),
        }];
        let err = match create_classifier(&replace_role_rules(user)) {
            Ok(_) => panic!("a leading-dot prefix matches nothing and must fail construction"),
            Err(e) => e,
        };
        let RastreoError::Classifier(ClassifierError::InvalidRoleRule(message)) = err else {
            panic!("expected InvalidRoleRule, got {err:?}");
        };
        assert!(message.contains("dotted-decimal"), "message was: {message}");
    }

    #[test]
    fn sys_object_id_prefix_with_a_malformed_arc_fails_construction() {
        for prefix in ["1.3.6.1.4.1.9.", "1.3.6 .1", "iso.3.6.1", "1"] {
            let user = vec![RoleRule::SysObjectIdPrefix {
                prefix: prefix.into(),
                role: "router".into(),
            }];
            assert!(
                matches!(
                    create_classifier(&replace_role_rules(user)),
                    Err(RastreoError::Classifier(ClassifierError::InvalidRoleRule(
                        _
                    )))
                ),
                "`{prefix}` is not a dotted-decimal OID and must fail construction"
            );
        }
    }

    #[test]
    fn signal_match_role_rule_reads_snmp_sys_object_id() {
        let user = vec![RoleRule::SignalMatch {
            signal: SignalKind::SnmpSysObjectId,
            pattern: r"^1\.3\.6\.1\.4\.1\.6527\.".to_string(),
            role: "switch".to_string(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysObjectId("1.3.6.1.4.1.6527.1.20.26".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("switch"));
    }

    #[test]
    fn signal_match_role_rule_reads_snmp_sys_name() {
        let user = vec![RoleRule::SignalMatch {
            signal: SignalKind::SnmpSysName,
            pattern: r"-spine\d+$".to_string(),
            role: "spine".to_string(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysName("dc1-spine01".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role.as_deref(), Some("spine"));
    }

    #[test]
    fn signal_match_role_rule_ignores_other_signal_kinds() {
        let user = vec![RoleRule::SignalMatch {
            signal: SignalKind::SnmpSysName,
            pattern: r"spine".to_string(),
            role: "spine".to_string(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysDescr("spine switch, Version 1.0".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role, None);
    }

    #[test]
    fn signal_match_role_rule_leaves_role_null_when_the_pattern_misses() {
        let user = vec![RoleRule::SignalMatch {
            signal: SignalKind::SnmpSysName,
            pattern: r"^edge-".to_string(),
            role: "edge".to_string(),
        }];
        let c = create_classifier(&replace_role_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysName("dc1-spine01".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.role, None);
    }

    #[test]
    fn signal_match_role_rule_invalid_regex_fails_at_construction() {
        let user = vec![RoleRule::SignalMatch {
            signal: SignalKind::SnmpSysName,
            pattern: r"(unclosed".to_string(),
            role: "irrelevant".to_string(),
        }];
        assert!(matches!(
            create_classifier(&replace_role_rules(user)),
            Err(RastreoError::Classifier(
                ClassifierError::InvalidRegex { .. }
            ))
        ));
    }

    #[test]
    fn platform_rule_reads_snmp_sys_object_id() {
        let user = vec![PlatformRule {
            signal: SignalKind::SnmpSysObjectId,
            pattern: r"^1\.3\.6\.1\.4\.1\.6527\.".to_string(),
            platform: Some("nokia_srlinux".to_string()),
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        }];
        let c = create_classifier(&replace_rules(user)).expect("create");
        let mut record = empty_record();
        record
            .signals
            .push(Signal::SnmpSysObjectId("1.3.6.1.4.1.6527.1.20.26".into()));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("nokia_srlinux"));
    }

    #[cfg(feature = "config")]
    #[test]
    fn role_rule_signal_match_deserializes_from_yaml() {
        let yaml = r#"
type: signal_match
signal: snmp_sys_object_id
pattern: "^1\\.3\\.6\\.1\\.4\\.1\\.6527\\."
role: switch
"#;
        let rule: RoleRule = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match rule {
            RoleRule::SignalMatch {
                signal,
                pattern,
                role,
            } => {
                assert_eq!(signal, SignalKind::SnmpSysObjectId);
                assert_eq!(pattern, r"^1\.3\.6\.1\.4\.1\.6527\.");
                assert_eq!(role, "switch");
            }
            _ => panic!("expected SignalMatch"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_scenario_written_against_the_previous_vocabulary_classifies_unchanged() {
        let yaml = r#"
type: rules
merge_mode: replace
platform_rules:
  - signal: snmp_sys_descr
    pattern: "^Cisco IOS Software.*Version (?P<version>[\\d\\.]+)"
    platform: cisco_ios
    os_version_capture: version
  - signal: ssh_banner
    pattern: "^SSH-2\\.0-(?P<sshv>OpenSSH_[\\d\\.p]+)"
    platform: linux
    ssh_version_capture: sshv
role_rules:
  - type: sys_object_id_prefix
    prefix: "1.3.6.1.4.1.9.1"
    role: router
  - type: ports_open
    ports: [22, 179]
    role: router
"#;
        let cfg: ClassifierConfig = serde_yaml_ng::from_str(yaml).expect("deserialize");
        let c = create_classifier(&cfg).expect("create");
        let mut record = empty_record();
        record.signals.push(cisco_ios_sys_descr());
        record
            .signals
            .push(Signal::SnmpSysObjectId("1.3.6.1.4.1.9.1.2050".into()));
        record.signals.push(Signal::OpenPort(22));
        c.classify(&mut record).expect("classify ok");
        assert_eq!(record.platform.as_deref(), Some("cisco_ios"));
        assert_eq!(record.os_version.as_deref(), Some("15.7"));
        assert_eq!(record.role.as_deref(), Some("router"));
        assert_eq!(record.ssh_version, None);
    }

    #[test]
    fn every_signal_is_rule_addressable_or_excluded_with_a_reason() {
        const SIGNAL_VARIANT_COUNT: usize = 24;

        // Each arm is const-evaluated, so an index past the count fails to build even though the walk never reaches that arm.
        const fn slot(index: usize) -> usize {
            assert!(index < SIGNAL_VARIANT_COUNT);
            index
        }

        fn variant_index(signal: &Signal) -> usize {
            match signal {
                Signal::OpenPort(_) => const { slot(0) },
                Signal::HttpBanner(_) => const { slot(1) },
                Signal::SnmpSysObjectId(_) => const { slot(2) },
                Signal::SnmpSysDescr(_) => const { slot(3) },
                Signal::Mac(_) => const { slot(4) },
                Signal::DnsHost(_) => const { slot(5) },
                Signal::NtpBanner(_) => const { slot(6) },
                Signal::SipUserAgent(_) => const { slot(7) },
                Signal::MemcachedVersion(_) => const { slot(8) },
                Signal::StunMappedAddress(_) => const { slot(9) },
                Signal::SnmpSysName(_) => const { slot(10) },
                Signal::SshBanner(_) => const { slot(11) },
                Signal::SshHostKey(_) => const { slot(12) },
                Signal::IcmpEchoRttMicros(_) => const { slot(13) },
                Signal::TlsSubject(_) => const { slot(14) },
                Signal::TlsSanName(_) => const { slot(15) },
                Signal::TlsProtocolVersion(_) => const { slot(16) },
                Signal::TlsCipherSuite(_) => const { slot(17) },
                Signal::TlsAlpn(_) => const { slot(18) },
                Signal::ReverseDnsName(_) => const { slot(19) },
                Signal::GnmiVersion(_) => const { slot(20) },
                Signal::GnmiSupportedModel(_) => const { slot(21) },
                Signal::GnmiSupportedEncoding(_) => const { slot(22) },
                Signal::GnmiState { .. } => const { slot(23) },
            }
        }

        enum Reach {
            Addressable(SignalKind),
            NoText,
            Excluded(&'static str),
        }

        fn declared_reach(signal: &Signal) -> Reach {
            match signal {
                Signal::SnmpSysDescr(_) => Reach::Addressable(SignalKind::SnmpSysDescr),
                Signal::SnmpSysName(_) => Reach::Addressable(SignalKind::SnmpSysName),
                Signal::SnmpSysObjectId(_) => Reach::Addressable(SignalKind::SnmpSysObjectId),
                Signal::SshBanner(_) => Reach::Addressable(SignalKind::SshBanner),
                Signal::HttpBanner(_) => Reach::Addressable(SignalKind::HttpBanner),
                Signal::OpenPort(_) => Reach::NoText,
                Signal::IcmpEchoRttMicros(_) => Reach::NoText,
                Signal::Mac(_) => Reach::Excluded("correlated by IdentityFuser and surfaced as DeviceRecord::mac"),
                Signal::DnsHost(_) => Reach::Excluded("resolution artefact of the target spec, not an observation of the device"),
                Signal::ReverseDnsName(_) => Reach::Excluded("correlated by IdentityFuser"),
                Signal::SshHostKey(_) => Reach::Excluded("correlated by IdentityFuser; a key fingerprint carries no platform or role text"),
                Signal::TlsSubject(_) => Reach::Excluded("correlated by IdentityFuser"),
                Signal::TlsSanName(_) => Reach::Excluded("correlated by IdentityFuser"),
                Signal::TlsProtocolVersion(_) => Reach::Excluded("transport negotiation, not a device attribute"),
                Signal::TlsCipherSuite(_) => Reach::Excluded("transport negotiation, not a device attribute"),
                Signal::TlsAlpn(_) => Reach::Excluded("transport negotiation, not a device attribute"),
                Signal::NtpBanner(_) => Reach::Excluded("service banner; no rule kind reads it yet"),
                Signal::SipUserAgent(_) => Reach::Excluded("service banner; no rule kind reads it yet"),
                Signal::MemcachedVersion(_) => Reach::Excluded("service banner; no rule kind reads it yet"),
                Signal::StunMappedAddress(_) => Reach::Excluded("NAT observation, not a device attribute"),
                Signal::GnmiVersion(_) => Reach::Excluded("capability data owned by the collection profile"),
                Signal::GnmiSupportedModel(_) => Reach::Excluded("capability data owned by the collection profile"),
                Signal::GnmiSupportedEncoding(_) => Reach::Excluded("capability data owned by the collection profile"),
                Signal::GnmiState { .. } => Reach::Excluded("state values can be sensitive and are kept out of downstream records"),
            }
        }

        let text = "text".to_string();
        let walked: [Signal; SIGNAL_VARIANT_COUNT] = [
            Signal::OpenPort(22),
            Signal::HttpBanner(text.clone()),
            Signal::SnmpSysObjectId(text.clone()),
            Signal::SnmpSysDescr(text.clone()),
            Signal::Mac(text.clone()),
            Signal::DnsHost(text.clone()),
            Signal::NtpBanner(text.clone()),
            Signal::SipUserAgent(text.clone()),
            Signal::MemcachedVersion(text.clone()),
            Signal::StunMappedAddress(text.clone()),
            Signal::SnmpSysName(text.clone()),
            Signal::SshBanner(text.clone()),
            Signal::SshHostKey(text.clone()),
            Signal::IcmpEchoRttMicros(1),
            Signal::TlsSubject(text.clone()),
            Signal::TlsSanName(text.clone()),
            Signal::TlsProtocolVersion(text.clone()),
            Signal::TlsCipherSuite(text.clone()),
            Signal::TlsAlpn(text.clone()),
            Signal::ReverseDnsName(text.clone()),
            Signal::GnmiVersion(text.clone()),
            Signal::GnmiSupportedModel(text.clone()),
            Signal::GnmiSupportedEncoding(text.clone()),
            Signal::GnmiState {
                path: text.clone(),
                value: text,
            },
        ];
        let mut covered = [false; SIGNAL_VARIANT_COUNT];
        for signal in &walked {
            let index = variant_index(signal);
            assert!(!covered[index], "{signal:?} appears twice in the walk");
            covered[index] = true;
        }
        assert!(
            covered.iter().all(|seen| *seen),
            "a Signal variant is missing from this walk; variant_index names every one"
        );

        for signal in &walked {
            match declared_reach(signal) {
                Reach::Addressable(kind) => assert!(
                    signal_text_for(signal, kind).is_some(),
                    "{signal:?} is declared addressable as {kind:?} but signal_text_for does not read it"
                ),
                Reach::NoText | Reach::Excluded(_) => {
                    for kind in *SignalKind::all() {
                        assert!(
                            signal_text_for(signal, kind).is_none(),
                            "{signal:?} is outside the rule vocabulary but {kind:?} reads it"
                        );
                    }
                }
            }
            if let Reach::Excluded(reason) = declared_reach(signal) {
                assert!(
                    !reason.trim().is_empty(),
                    "{signal:?} is excluded without a stated reason"
                );
            }
        }
    }
}
