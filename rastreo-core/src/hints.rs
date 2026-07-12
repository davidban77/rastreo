use crate::error::ProbeErrorKind;

/// Terse operator guidance for a probe fault, keyed on its typed [`ProbeErrorKind`]; `None` when the kind carries no specific action. Both the CLI and the server derive their hint from this function so the same fault surfaces the same guidance.
pub fn hint_for_error_kind(kind: ProbeErrorKind) -> Option<&'static str> {
    match kind {
        ProbeErrorKind::PermissionDenied => Some(
            "the probe was denied a local socket operation — grant CAP_NET_RAW (ARP/NDP/ICMP) or check local egress policy (a firewall REJECT in the OUTPUT chain).",
        ),
        ProbeErrorKind::DnsFailed => Some(
            "DNS resolution failed for the target — check the resolver configuration and that the DNS server is reachable.",
        ),
        ProbeErrorKind::DecodeFailed => Some(
            "the target answered with a reply the prober could not parse — check the protocol version, the credentials, and that the expected service is on the port.",
        ),
        ProbeErrorKind::AuthFailed => Some(
            "the probe's authentication was rejected — verify the credentials (SNMP community, USM user/keys, or SSH credentials).",
        ),
        ProbeErrorKind::Other => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_hint_mentions_cap_net_raw_and_egress() {
        let hint = hint_for_error_kind(ProbeErrorKind::PermissionDenied).expect("hint");
        assert!(hint.contains("CAP_NET_RAW"), "hint: {hint}");
        assert!(hint.contains("egress"), "hint: {hint}");
    }

    #[test]
    fn dns_failed_hint_mentions_resolver() {
        let hint = hint_for_error_kind(ProbeErrorKind::DnsFailed).expect("hint");
        assert!(hint.contains("resolver"), "hint: {hint}");
    }

    #[test]
    fn decode_failed_hint_mentions_parse() {
        let hint = hint_for_error_kind(ProbeErrorKind::DecodeFailed).expect("hint");
        assert!(hint.contains("could not parse"), "hint: {hint}");
    }

    #[test]
    fn auth_failed_hint_mentions_credentials() {
        let hint = hint_for_error_kind(ProbeErrorKind::AuthFailed).expect("hint");
        assert!(hint.contains("credentials"), "hint: {hint}");
    }

    #[test]
    fn other_kind_has_no_hint() {
        assert!(hint_for_error_kind(ProbeErrorKind::Other).is_none());
    }

    #[test]
    fn no_hint_content_carries_a_presentation_prefix() {
        for kind in [
            ProbeErrorKind::PermissionDenied,
            ProbeErrorKind::DnsFailed,
            ProbeErrorKind::DecodeFailed,
            ProbeErrorKind::AuthFailed,
        ] {
            let hint = hint_for_error_kind(kind).expect("hint");
            assert!(
                !hint.starts_with("hint:"),
                "content must be prefix-free so the wire `hint` field is not doubled: {hint}"
            );
        }
    }
}
