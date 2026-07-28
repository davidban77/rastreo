use super::{PlatformRule, SignalKind};

#[derive(Clone, Copy, PartialEq, Eq)]
enum BannerHeuristics {
    Off,
    On,
}

/// Platform-detection rules applied by default, in match order: only SNMP `sysDescr` rules claim a platform, because a service banner names the software on a port rather than the device's OS.
pub fn baked_platform_rules() -> Vec<PlatformRule> {
    platform_rules(BannerHeuristics::Off)
}

/// The default rules with the SSH and HTTP banner rules additionally claiming `platform` (and `os_version` for SSH), inferring the device OS from a service banner.
pub fn baked_platform_rules_with_banner_heuristics() -> Vec<PlatformRule> {
    platform_rules(BannerHeuristics::On)
}

fn platform_rules(banner: BannerHeuristics) -> Vec<PlatformRule> {
    let claim = |value: &str| match banner {
        BannerHeuristics::On => Some(value.to_string()),
        BannerHeuristics::Off => None,
    };
    vec![
        PlatformRule {
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^Cisco IOS Software.*Version (?P<version>[\d\.]+)".to_string(),
            platform: Some("cisco_ios".to_string()),
            os_version_capture: Some("version".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^Cisco IOS XR.*Version (?P<version>[\d\.]+)".to_string(),
            platform: Some("cisco_ios_xr".to_string()),
            os_version_capture: Some("version".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^Cisco NX-OS.*Version (?P<version>[\d\.]+)".to_string(),
            platform: Some("cisco_nxos".to_string()),
            os_version_capture: Some("version".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^Juniper Networks, Inc\..*JUNOS (?P<version>[\d\.]+)".to_string(),
            platform: Some("junos".to_string()),
            os_version_capture: Some("version".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^Arista Networks EOS version (?P<version>[\d\.]+)".to_string(),
            platform: Some("arista_eos".to_string()),
            os_version_capture: Some("version".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^SRLinux-v(?P<version>[\d\.]+)".to_string(),
            platform: Some("nokia_srlinux".to_string()),
            os_version_capture: Some("version".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SnmpSysDescr,
            pattern: r"^Linux\s+\S+\s+(?P<version>[\d\.]+)-".to_string(),
            platform: Some("linux".to_string()),
            os_version_capture: Some("version".to_string()),
            ssh_version_capture: None,
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SshBanner,
            pattern: r"^SSH-2\.0-(?P<sshv>OpenSSH_[\d\.p]+)\s+(?P<osv>Ubuntu)".to_string(),
            platform: claim("linux"),
            os_version_capture: claim("osv"),
            ssh_version_capture: Some("sshv".to_string()),
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SshBanner,
            pattern: r"^SSH-2\.0-(?P<sshv>OpenSSH_[\d\.p]+)\s+(?P<osv>Debian)".to_string(),
            platform: claim("linux"),
            os_version_capture: claim("osv"),
            ssh_version_capture: Some("sshv".to_string()),
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::SshBanner,
            pattern: r"^SSH-2\.0-(?P<sshv>OpenSSH_[\d\.p]+)\s+(?P<osv>FreeBSD)".to_string(),
            platform: claim("freebsd"),
            os_version_capture: claim("osv"),
            ssh_version_capture: Some("sshv".to_string()),
            http_server_capture: None,
            http_version_capture: None,
        },
        PlatformRule {
            signal: SignalKind::HttpBanner,
            pattern: r"^(?P<server>nginx)/(?P<version>[\d\.]+)".to_string(),
            platform: claim("linux"),
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: Some("server".to_string()),
            http_version_capture: Some("version".to_string()),
        },
        PlatformRule {
            signal: SignalKind::HttpBanner,
            pattern: r"^(?P<server>Apache)/(?P<version>[\d\.]+)".to_string(),
            platform: claim("linux"),
            os_version_capture: None,
            ssh_version_capture: None,
            http_server_capture: Some("server".to_string()),
            http_version_capture: Some("version".to_string()),
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
                SignalKind::SnmpSysDescr
                | SignalKind::SnmpSysName
                | SignalKind::SnmpSysObjectId => {
                    assert!(
                        !seen_ssh && !seen_http,
                        "SNMP rule appeared after SSH or HTTP: {}",
                        rule.pattern
                    );
                }
                SignalKind::SshBanner => {
                    assert!(!seen_http, "SSH rule appeared after HTTP: {}", rule.pattern);
                    seen_ssh = true;
                }
                SignalKind::HttpBanner => {
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

    #[test]
    fn no_default_rule_claims_a_platform_from_a_service_banner() {
        for rule in baked_platform_rules() {
            if matches!(rule.signal, SignalKind::SshBanner | SignalKind::HttpBanner) {
                assert!(
                    rule.platform.is_none(),
                    "`{}` reads a service banner and claims platform `{:?}`; a banner names the software on a port, not the device OS, so the claim belongs in baked_platform_rules_with_banner_heuristics",
                    rule.pattern,
                    rule.platform
                );
                assert!(
                    rule.os_version_capture.is_none(),
                    "`{}` reads a service banner and captures os_version; os_version is paired with platform",
                    rule.pattern
                );
            }
        }
    }

    #[test]
    fn every_default_rule_that_claims_a_platform_reads_a_device_identity_signal() {
        for rule in baked_platform_rules() {
            if rule.platform.is_some() {
                assert_eq!(
                    rule.signal,
                    SignalKind::SnmpSysDescr,
                    "`{}` claims a platform from {:?}",
                    rule.pattern,
                    rule.signal
                );
            }
        }
    }

    #[test]
    fn banner_heuristics_differ_from_the_defaults_only_in_platform_and_os_version() {
        let default = baked_platform_rules();
        let opt_in = baked_platform_rules_with_banner_heuristics();
        assert_eq!(default.len(), opt_in.len());
        for (base, extended) in default.iter().zip(&opt_in) {
            assert_eq!(base.signal, extended.signal);
            assert_eq!(base.pattern, extended.pattern);
            assert_eq!(base.ssh_version_capture, extended.ssh_version_capture);
            assert_eq!(base.http_server_capture, extended.http_server_capture);
            assert_eq!(base.http_version_capture, extended.http_version_capture);
            if base.signal == SignalKind::SnmpSysDescr {
                assert_eq!(base.platform, extended.platform);
                assert_eq!(base.os_version_capture, extended.os_version_capture);
            } else {
                assert!(base.platform.is_none());
                assert!(extended.platform.is_some());
                assert_eq!(
                    extended.os_version_capture.is_some(),
                    base.signal == SignalKind::SshBanner,
                    "only an ssh_banner rule restores an os_version capture: `{}`",
                    base.pattern
                );
            }
        }
    }

    #[test]
    fn banner_heuristics_restore_the_ssh_os_version_capture() {
        for rule in baked_platform_rules_with_banner_heuristics() {
            if rule.signal == SignalKind::SshBanner {
                assert_eq!(rule.os_version_capture.as_deref(), Some("osv"));
            }
        }
    }
}
