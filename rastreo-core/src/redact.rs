use std::borrow::Cow;

/// Drop inline `user:pass@` userinfo from a server URL, leaving the scheme, host, port, and path.
pub(crate) fn strip_userinfo(server: &str) -> Cow<'_, str> {
    let Some(scheme_end) = server.find("://") else {
        return Cow::Borrowed(server);
    };
    let authority_start = scheme_end + 3;
    let authority_end = server[authority_start..]
        .find('/')
        .map_or(server.len(), |i| authority_start + i);
    let Some(at) = server[authority_start..authority_end].rfind('@') else {
        return Cow::Borrowed(server);
    };
    let host_start = authority_start + at + 1;
    Cow::Owned(format!(
        "{}{}",
        &server[..authority_start],
        &server[host_start..]
    ))
}

pub(crate) fn redacted_server_list(servers: &[String]) -> String {
    servers
        .iter()
        .map(|s| strip_userinfo(s))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_userinfo_drops_user_and_password() {
        assert_eq!(
            strip_userinfo("nats://user:pass@host:4222"),
            "nats://host:4222"
        );
    }

    #[test]
    fn strip_userinfo_drops_a_user_without_a_password() {
        assert_eq!(strip_userinfo("nats://user@host:4222"), "nats://host:4222");
    }

    #[test]
    fn strip_userinfo_keeps_a_url_that_carries_no_userinfo() {
        assert_eq!(strip_userinfo("nats://host:4222"), "nats://host:4222");
        assert_eq!(strip_userinfo("host:4222"), "host:4222");
    }

    #[test]
    fn strip_userinfo_keeps_the_path_and_ignores_an_at_sign_inside_it() {
        assert_eq!(
            strip_userinfo("nats://u:p@host:4222/js"),
            "nats://host:4222/js"
        );
        assert_eq!(
            strip_userinfo("nats://host:4222/a@b"),
            "nats://host:4222/a@b"
        );
    }

    #[test]
    fn strip_userinfo_takes_the_last_at_sign_in_the_authority() {
        assert_eq!(strip_userinfo("nats://a@b@host:4222"), "nats://host:4222");
    }

    #[test]
    fn strip_userinfo_borrows_when_there_is_nothing_to_redact() {
        assert!(matches!(
            strip_userinfo("nats://host:4222"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn redacted_server_list_redacts_every_entry() {
        let servers = vec![
            "nats://admin:hunter2@a.example.com:4222".to_string(),
            "nats://b.example.com:4222".to_string(),
            "nats://svc:s3cr3t@c.example.com:4222".to_string(),
        ];
        let rendered = redacted_server_list(&servers);
        assert_eq!(
            rendered,
            "nats://a.example.com:4222,nats://b.example.com:4222,nats://c.example.com:4222"
        );
        assert!(!rendered.contains("hunter2"), "rendered: {rendered}");
        assert!(!rendered.contains("s3cr3t"), "rendered: {rendered}");
    }

    #[test]
    fn redacted_server_list_of_no_servers_is_empty() {
        assert_eq!(redacted_server_list(&[]), "");
    }
}
