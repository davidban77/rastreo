/// Canonical MAC form for identity correlation: hex digits only, lowercased, `:`/`-` dropped.
pub(crate) fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| *c != ':' && *c != '-')
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
}
