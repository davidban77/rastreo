use super::{PlatformRule, PlatformSignal};

/// Curated platform-detection rules shipped with rastreo. Matched in the order returned;
/// SNMP `sysDescr` rules run first (most specific), followed by SSH banner rules, then HTTP banner rules.
pub fn baked_platform_rules() -> Vec<PlatformRule> {
    vec![
        PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"^Cisco IOS Software.*Version (?P<version>[\d\.]+)".to_string(),
            platform: "cisco_ios".to_string(),
            os_version_capture: Some("version".to_string()),
        },
        PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"^Cisco IOS XR.*Version (?P<version>[\d\.]+)".to_string(),
            platform: "cisco_ios_xr".to_string(),
            os_version_capture: Some("version".to_string()),
        },
        PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"^Cisco NX-OS.*Version (?P<version>[\d\.]+)".to_string(),
            platform: "cisco_nxos".to_string(),
            os_version_capture: Some("version".to_string()),
        },
        PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"^Juniper Networks, Inc\..*JUNOS (?P<version>[\d\.]+)".to_string(),
            platform: "junos".to_string(),
            os_version_capture: Some("version".to_string()),
        },
        PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"^Arista Networks EOS version (?P<version>[\d\.]+)".to_string(),
            platform: "arista_eos".to_string(),
            os_version_capture: Some("version".to_string()),
        },
        PlatformRule {
            signal: PlatformSignal::SnmpSysDescr,
            pattern: r"^Linux\s+\S+\s+(?P<version>[\d\.]+)-".to_string(),
            platform: "linux".to_string(),
            os_version_capture: Some("version".to_string()),
        },
        PlatformRule {
            signal: PlatformSignal::SshBanner,
            pattern: r"^SSH-2\.0-OpenSSH_[\d\.p]+\s+Ubuntu".to_string(),
            platform: "linux".to_string(),
            os_version_capture: None,
        },
        PlatformRule {
            signal: PlatformSignal::SshBanner,
            pattern: r"^SSH-2\.0-OpenSSH_[\d\.p]+\s+Debian".to_string(),
            platform: "linux".to_string(),
            os_version_capture: None,
        },
        PlatformRule {
            signal: PlatformSignal::SshBanner,
            pattern: r"^SSH-2\.0-OpenSSH_[\d\.p]+\s+FreeBSD".to_string(),
            platform: "freebsd".to_string(),
            os_version_capture: None,
        },
        PlatformRule {
            signal: PlatformSignal::HttpBanner,
            pattern: r"^nginx/(?P<version>[\d\.]+)".to_string(),
            platform: "nginx".to_string(),
            os_version_capture: Some("version".to_string()),
        },
        PlatformRule {
            signal: PlatformSignal::HttpBanner,
            pattern: r"^Apache/(?P<version>[\d\.]+)".to_string(),
            platform: "apache_httpd".to_string(),
            os_version_capture: Some("version".to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baked_rules_are_non_empty() {
        assert!(!baked_platform_rules().is_empty());
    }

    #[test]
    fn baked_rules_snmp_precedes_ssh_precedes_http() {
        let rules = baked_platform_rules();
        let mut seen_ssh = false;
        let mut seen_http = false;
        for rule in &rules {
            match rule.signal {
                PlatformSignal::SnmpSysDescr | PlatformSignal::SnmpSysName => {
                    assert!(
                        !seen_ssh && !seen_http,
                        "SNMP rule appeared after SSH or HTTP: {}",
                        rule.pattern
                    );
                }
                PlatformSignal::SshBanner => {
                    assert!(!seen_http, "SSH rule appeared after HTTP: {}", rule.pattern);
                    seen_ssh = true;
                }
                PlatformSignal::HttpBanner => {
                    seen_http = true;
                }
            }
        }
    }

    #[test]
    fn baked_rules_all_compile_as_regex() {
        for rule in baked_platform_rules() {
            regex::Regex::new(&rule.pattern).unwrap_or_else(|e| {
                panic!("baked pattern `{}` failed to compile: {e}", rule.pattern)
            });
        }
    }
}
