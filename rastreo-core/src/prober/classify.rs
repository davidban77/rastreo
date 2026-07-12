use std::io::ErrorKind;

use hickory_resolver::net::NetError;

/// Whether a failed probe attempt is evidence of an absent target or of a broken probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Absence,
    Fault,
}

pub(crate) fn io_error(err: &std::io::Error) -> Disposition {
    match err.kind() {
        ErrorKind::TimedOut
        | ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable => Disposition::Absence,
        // A remote admin-prohibited answer arrives as `HostUnreachable`, so `PermissionDenied`
        // here is always local egress policy (netfilter REJECT in OUTPUT, SELinux, a NetworkPolicy).
        _ => Disposition::Fault,
    }
}

pub(crate) fn net_error(err: &NetError) -> Disposition {
    match err {
        NetError::Timeout => Disposition::Absence,
        NetError::Io(io) => io_error(io),
        // `NetError` is #[non_exhaustive]: classify an unknown variant by the io error in its
        // source chain; a resolver-layer failure with no io evidence is a fault.
        other => io_source(other).map(io_error).unwrap_or(Disposition::Fault),
    }
}

fn io_source(err: &NetError) -> Option<&std::io::Error> {
    let mut source = std::error::Error::source(err);
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            return Some(io);
        }
        source = current.source();
    }
    None
}

#[cfg(feature = "http")]
pub(crate) fn io_error_in_chain<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a std::io::Error> {
    let mut current = Some(err);
    while let Some(entry) = current {
        if let Some(io) = entry.downcast_ref::<std::io::Error>() {
            return Some(io);
        }
        current = entry.source();
    }
    None
}

/// A rustls error in the chain is proof that the TCP connect completed: the peer answered.
#[cfg(feature = "http")]
pub(crate) fn rustls_error_in_chain<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a rustls::Error> {
    let mut current = Some(err);
    while let Some(entry) = current {
        if let Some(tls) = entry.downcast_ref::<rustls::Error>() {
            return Some(tls);
        }
        // `io::Error::source` yields the *inner* error's source, skipping the inner error itself,
        // so a nested io wrapper is invisible to a plain source walk. Step into it explicitly:
        // reqwest reaches rustls through two of them (hyper-rustls over tokio-rustls).
        if let Some(inner) = entry
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
        {
            current = Some(inner);
            continue;
        }
        current = entry.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const ABSENCE_KINDS: [ErrorKind; 6] = [
        ErrorKind::TimedOut,
        ErrorKind::ConnectionRefused,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::HostUnreachable,
        ErrorKind::NetworkUnreachable,
    ];

    #[test]
    fn silent_or_rejecting_peer_io_kinds_are_absence() {
        for kind in ABSENCE_KINDS {
            assert_eq!(
                io_error(&std::io::Error::from(kind)),
                Disposition::Absence,
                "{kind:?} must be absence, not a fault"
            );
        }
    }

    #[test]
    fn local_resource_io_kinds_are_faults() {
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::AddrNotAvailable,
            ErrorKind::InvalidInput,
            ErrorKind::OutOfMemory,
        ] {
            assert_eq!(
                io_error(&std::io::Error::from(kind)),
                Disposition::Fault,
                "{kind:?} must be a fault, not absence"
            );
        }
    }

    #[test]
    fn dns_timeout_is_absence() {
        assert_eq!(net_error(&NetError::Timeout), Disposition::Absence);
    }

    #[test]
    fn dns_io_absence_kinds_are_absence() {
        for kind in ABSENCE_KINDS {
            let err = NetError::Io(Arc::new(std::io::Error::from(kind)));
            assert_eq!(net_error(&err), Disposition::Absence, "{kind:?}");
        }
    }

    #[test]
    fn dns_io_fault_kinds_are_faults() {
        let err = NetError::Io(Arc::new(std::io::Error::from(ErrorKind::PermissionDenied)));
        assert_eq!(net_error(&err), Disposition::Fault);
    }

    #[test]
    fn dns_no_connections_is_a_fault() {
        // hickory raises `NoConnections` when the connection policy selects no usable connection
        // config, or when no configured server survives the pool's filter — never when a server
        // was asked and stayed silent (that is `Timeout`).
        assert_eq!(net_error(&NetError::NoConnections), Disposition::Fault);
    }

    #[test]
    fn dns_resolver_layer_failure_without_io_evidence_is_a_fault() {
        assert_eq!(net_error(&NetError::Busy), Disposition::Fault);
        assert_eq!(
            net_error(&NetError::Msg("bad resolver state".into())),
            Disposition::Fault
        );
        assert_eq!(net_error(&NetError::QueryCaseMismatch), Disposition::Fault);
    }

    #[cfg(feature = "http")]
    #[test]
    fn rustls_error_is_recovered_from_an_io_error_wrapper() {
        let wrapped = std::io::Error::new(
            ErrorKind::InvalidData,
            rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure),
        );
        let found =
            rustls_error_in_chain(&wrapped).expect("rustls error recovered from io wrapper");
        assert_eq!(
            *found,
            rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure)
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn rustls_error_is_recovered_from_nested_io_error_wrappers() {
        // The shape reqwest hands us: hyper-rustls wraps tokio-rustls wraps rustls.
        let inner = std::io::Error::new(
            ErrorKind::InvalidData,
            rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType),
        );
        let outer = std::io::Error::other(inner);
        let found = rustls_error_in_chain(&outer).expect("rustls error recovered through wrappers");
        assert!(
            matches!(found, rustls::Error::InvalidMessage(_)),
            "got: {found:?}"
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn plain_io_error_carries_no_rustls_error() {
        let err = std::io::Error::from(ErrorKind::ConnectionReset);
        assert!(rustls_error_in_chain(&err).is_none());
    }

    #[cfg(feature = "http")]
    #[derive(Debug)]
    struct Layer(Box<dyn std::error::Error + Send + Sync + 'static>);

    #[cfg(feature = "http")]
    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "layer: {}", self.0)
        }
    }

    #[cfg(feature = "http")]
    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[cfg(feature = "http")]
    fn wrap(err: std::io::Error) -> Layer {
        Layer(Box::new(Layer(Box::new(err))))
    }

    #[cfg(feature = "http")]
    #[test]
    fn a_refused_peer_wrapped_by_a_client_stack_is_absence() {
        let wrapped = wrap(std::io::Error::from(ErrorKind::ConnectionRefused));
        let io = io_error_in_chain(&wrapped).expect("io error recovered through the source chain");
        assert_eq!(io_error(io), Disposition::Absence);
    }

    #[cfg(feature = "http")]
    #[test]
    fn a_denied_local_socket_wrapped_by_a_client_stack_is_a_fault() {
        let wrapped = wrap(std::io::Error::from(ErrorKind::PermissionDenied));
        let io = io_error_in_chain(&wrapped).expect("io error recovered through the source chain");
        assert_eq!(io_error(io), Disposition::Fault);
    }

    #[cfg(feature = "http")]
    #[test]
    fn descriptor_exhaustion_wrapped_by_a_client_stack_is_a_fault() {
        // EMFILE has no `ErrorKind` of its own on stable: it arrives as `Uncategorized`.
        let emfile = std::io::Error::from_raw_os_error(24);
        let wrapped = wrap(emfile);
        let io = io_error_in_chain(&wrapped).expect("io error recovered through the source chain");
        assert_eq!(io_error(io), Disposition::Fault);
    }

    #[cfg(feature = "http")]
    #[derive(Debug)]
    struct Opaque;

    #[cfg(feature = "http")]
    impl std::fmt::Display for Opaque {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "opaque")
        }
    }

    #[cfg(feature = "http")]
    impl std::error::Error for Opaque {}

    #[cfg(feature = "http")]
    #[test]
    fn an_error_chain_with_no_io_error_yields_none() {
        let no_io = Layer(Box::new(Layer(Box::new(Opaque))));
        assert!(io_error_in_chain(&no_io).is_none());
    }
}
