/// Best-effort raise of `CAP_NET_RAW` from permitted to effective; a failed raise is swallowed so
/// the default unprivileged deploy execs and degrades gracefully instead of erroring the caller.
pub(crate) fn raise_net_raw_effective() {
    let _ = caps::raise(None, caps::CapSet::Effective, caps::Capability::CAP_NET_RAW);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raise_net_raw_effective_is_infallible_to_the_caller() {
        raise_net_raw_effective();
        raise_net_raw_effective();
    }
}
