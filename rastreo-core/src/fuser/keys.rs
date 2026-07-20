/// Canonical MAC form for identity correlation: hex digits only, lowercased, `:`/`-` dropped.
pub(crate) fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| *c != ':' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Canonicalizes a vendor-rendered MAC string to the SNMP path's bare lowercase hex form. Unlike
/// [`normalize_mac`], this also strips Cisco dotted `.` and whitespace, so `aabb.ccdd.eeff` and
/// `AA:BB:CC:DD:EE:FF` both converge to `aabbccddeeff` and match a cross-source SNMP endpoint.
#[cfg(feature = "gnmi")]
pub(crate) fn canonical_mac_str(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ':' | '-' | '.') && !c.is_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Canonical system-name form for identity correlation: ASCII-lowercased. Matches the
/// case-insensitive comparison the identity fuser applies to `SnmpSysName` / `ReverseDnsName`.
pub(crate) fn normalize_sys_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_separators_and_lowercases() {
        assert_eq!(normalize_mac("AA:BB:cc-DD:ee:FF"), "aabbccddeeff");
    }

    #[test]
    fn already_normalized_is_unchanged() {
        assert_eq!(normalize_mac("aabbccddeeff"), "aabbccddeeff");
    }

    #[test]
    fn normalize_sys_name_lowercases_ascii() {
        assert_eq!(normalize_sys_name("Core-SW01"), "core-sw01");
        assert_eq!(normalize_sys_name("core-sw01"), "core-sw01");
    }

    #[cfg(feature = "gnmi")]
    #[test]
    fn canonical_mac_str_converges_colon_dash_dotted_uppercase_to_bare_hex() {
        assert_eq!(canonical_mac_str("aa:bb:cc:dd:ee:ff"), "aabbccddeeff");
        assert_eq!(canonical_mac_str("AA-BB-CC-DD-EE-FF"), "aabbccddeeff");
        assert_eq!(canonical_mac_str("aabb.ccdd.eeff"), "aabbccddeeff");
        assert_eq!(canonical_mac_str("AABB.CCDD.EEFF"), "aabbccddeeff");
        assert_eq!(canonical_mac_str("aabbccddeeff"), "aabbccddeeff");
    }

    #[cfg(feature = "gnmi")]
    #[test]
    fn canonical_mac_str_strips_dot_which_normalize_mac_keeps() {
        assert_eq!(
            canonical_mac_str("aabb.ccdd.eeff"),
            normalize_mac("aabbccddeeff")
        );
        assert_ne!(normalize_mac("aabb.ccdd.eeff"), "aabbccddeeff");
    }

    #[cfg(feature = "gnmi")]
    #[test]
    fn canonical_mac_str_strips_surrounding_whitespace() {
        assert_eq!(canonical_mac_str("  aa:bb:cc:dd:ee:ff \n"), "aabbccddeeff");
    }
}
