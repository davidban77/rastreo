use crate::error::ResolverError;

/// Whether the network answered that the name has no addresses, rather than not answering, answering with a server error, or there being no resolver to ask.
pub(crate) fn answered_with_no_addresses(err: &ResolverError) -> bool {
    match err {
        // `NetError` is #[non_exhaustive]; hickory's own predicate answers false for every other variant, so an unrecognized DNS failure stays fatal.
        ResolverError::DnsLookupFailed { source, .. } => source.net_error().is_no_records_found(),
        ResolverError::DnsNoRecords { .. } => true,
        ResolverError::CidrTooLarge { .. }
        | ResolverError::RangeTooLarge { .. }
        | ResolverError::InvalidRange { .. }
        | ResolverError::MixedFamilyRange { .. }
        | ResolverError::TargetNotAllowed { .. }
        | ResolverError::AggregateHostCapExceeded { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use hickory_resolver::net::{DnsError, NetError, NoRecords};
    use hickory_resolver::proto::op::{Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};

    fn query(name: &str) -> Query {
        Query::query(
            Name::from_ascii(name).expect("test name parses"),
            RecordType::AAAA,
        )
    }

    fn lookup_failed(source: NetError) -> ResolverError {
        ResolverError::DnsLookupFailed {
            name: "missing.lab".into(),
            source: source.into(),
        }
    }

    #[test]
    fn nxdomain_is_an_answer_that_the_name_has_no_addresses() {
        let nxdomain = NetError::from(NoRecords::new(
            query("missing.lab."),
            ResponseCode::NXDomain,
        ));
        assert!(answered_with_no_addresses(&lookup_failed(nxdomain)));
    }

    #[test]
    fn a_nodata_answer_is_an_answer_that_the_name_has_no_addresses() {
        let nodata = NetError::from(NoRecords::new(query("missing.lab."), ResponseCode::NoError));
        assert!(answered_with_no_addresses(&lookup_failed(nodata)));
    }

    // A `NoRecords` is by construction a response that carried none, whatever code it arrived under.
    #[test]
    fn an_unregistered_response_code_carrying_no_records_is_still_an_answer_about_the_name() {
        let unknown = NetError::from(NoRecords::new(
            query("missing.lab."),
            ResponseCode::Unknown(3210),
        ));
        assert!(answered_with_no_addresses(&lookup_failed(unknown)));
    }

    #[test]
    fn a_server_error_response_is_not_an_answer_about_the_name() {
        for code in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::NotAuth,
            ResponseCode::FormErr,
        ] {
            let err = lookup_failed(NetError::Dns(DnsError::ResponseCode(code)));
            assert!(
                !answered_with_no_addresses(&err),
                "{code:?} must stay fatal"
            );
        }
    }

    #[test]
    fn a_nameserver_that_did_not_answer_is_not_an_answer_about_the_name() {
        for err in [
            NetError::Timeout,
            NetError::NoConnections,
            NetError::Busy,
            NetError::Msg("resolver in a bad state".into()),
            NetError::Message("resolver in a bad state"),
            NetError::QueryCaseMismatch,
            NetError::Io(Arc::new(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused,
            ))),
        ] {
            let display = err.to_string();
            assert!(
                !answered_with_no_addresses(&lookup_failed(err)),
                "{display} must stay fatal"
            );
        }
    }

    #[test]
    fn an_empty_successful_lookup_is_an_answer_that_the_name_has_no_addresses() {
        assert!(answered_with_no_addresses(&ResolverError::DnsNoRecords {
            name: "missing.lab".into(),
        }));
    }

    #[test]
    fn a_refusal_that_discards_enumerable_work_stays_fatal() {
        for err in [
            ResolverError::CidrTooLarge {
                cidr: "10.0.0.0/8".into(),
                hosts: 16_777_214,
                limit: 65_536,
            },
            ResolverError::RangeTooLarge {
                start: "10.0.0.1".into(),
                end: "10.255.255.254".into(),
                hosts: 16_777_214,
                limit: 65_536,
            },
            ResolverError::InvalidRange {
                start: "10.0.0.9".into(),
                end: "10.0.0.1".into(),
            },
            ResolverError::MixedFamilyRange {
                start: "10.0.0.1".into(),
                end: "2001:db8::1".into(),
            },
        ] {
            assert!(!answered_with_no_addresses(&err), "{err} must stay fatal");
        }
    }

    #[test]
    fn a_policy_refusal_stays_fatal() {
        for err in [
            ResolverError::TargetNotAllowed {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            },
            ResolverError::AggregateHostCapExceeded {
                hosts: 262_145,
                limit: 262_144,
            },
        ] {
            assert!(!answered_with_no_addresses(&err), "{err} must stay fatal");
        }
    }
}
