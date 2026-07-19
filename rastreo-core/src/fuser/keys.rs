/// Canonical MAC form for identity correlation: hex digits only, lowercased, `:`/`-` dropped.
pub(crate) fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| *c != ':' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect()
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
}
