// The SNMP prober emits arcs joined by '.', no leading dot; any other form matches nothing.
pub(crate) fn is_dotted_decimal(s: &str) -> bool {
    let mut arcs = 0usize;
    for part in s.split('.') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        arcs += 1;
    }
    arcs >= 2
}

/// True when `oid` equals `prefix` or sits in its subtree; `1.3.6.1.4.1.9.1` does not match `1.3.6.1.4.1.9.15`. `prefix` must already have passed [`is_dotted_decimal`] — a trailing dot defeats the arc-boundary check.
pub(crate) fn has_arc_prefix(oid: &str, prefix: &str) -> bool {
    debug_assert!(
        is_dotted_decimal(prefix),
        "prefix `{prefix}` was not validated by is_dotted_decimal"
    );
    oid.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_decimal_accepts_a_prober_emitted_oid() {
        assert!(is_dotted_decimal("1.3.6.1.4.1.6527.1.20.26"));
    }

    #[test]
    fn dotted_decimal_accepts_the_shortest_two_arc_form() {
        assert!(is_dotted_decimal("1.3"));
    }

    #[test]
    fn dotted_decimal_rejects_a_leading_dot() {
        assert!(!is_dotted_decimal(".1.3.6.1.4.1.9"));
    }

    #[test]
    fn dotted_decimal_rejects_a_trailing_dot() {
        assert!(!is_dotted_decimal("1.3.6.1.4.1.9."));
    }

    #[test]
    fn dotted_decimal_rejects_embedded_whitespace() {
        assert!(!is_dotted_decimal("1.3.6 .1"));
        assert!(!is_dotted_decimal(" 1.3.6.1"));
    }

    #[test]
    fn dotted_decimal_rejects_non_digit_arcs() {
        assert!(!is_dotted_decimal("iso.3.6.1"));
        assert!(!is_dotted_decimal("1.3.6.1.4.1.9.1a"));
    }

    #[test]
    fn dotted_decimal_rejects_empty_and_single_arc_values() {
        assert!(!is_dotted_decimal(""));
        assert!(!is_dotted_decimal("1"));
        assert!(!is_dotted_decimal("."));
    }

    #[test]
    fn arc_prefix_matches_the_exact_oid() {
        assert!(has_arc_prefix("1.3.6.1.4.1.9.1", "1.3.6.1.4.1.9.1"));
    }

    #[test]
    fn arc_prefix_matches_a_descendant() {
        assert!(has_arc_prefix("1.3.6.1.4.1.9.1.2050", "1.3.6.1.4.1.9.1"));
    }

    #[test]
    fn arc_prefix_rejects_a_sibling_subtree_sharing_a_digit_run() {
        assert!(!has_arc_prefix("1.3.6.1.4.1.9.15.2", "1.3.6.1.4.1.9.1"));
        assert!(!has_arc_prefix("1.3.6.1.4.1.9.12", "1.3.6.1.4.1.9.1"));
    }

    #[test]
    fn arc_prefix_rejects_an_oid_shorter_than_the_prefix() {
        assert!(!has_arc_prefix("1.3.6.1.4.1.9", "1.3.6.1.4.1.9.1"));
    }

    #[test]
    fn arc_prefix_rejects_an_unrelated_tree() {
        assert!(!has_arc_prefix(
            "1.3.6.1.4.1.6527.1.20.26",
            "1.3.6.1.4.1.9.1"
        ));
    }
}
