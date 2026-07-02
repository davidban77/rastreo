//! SIP OPTIONS request (RFC 3261): text protocol over UDP, CRLF-delimited headers.

use std::net::IpAddr;

use crate::model::Signal;

const HEADER_MAX_BYTES: usize = 256;

/// Build a SIP OPTIONS request targeting `<target_ip>:<port>`. `call_id_seed` picks the
/// per-request Call-ID hex so retries look distinct to the server.
pub fn build_request(target_ip: IpAddr, port: u16, call_id_seed: u64) -> Vec<u8> {
    let host = format_host(target_ip);
    let call_id = format!("{call_id_seed:016x}");
    let mut req = String::with_capacity(320);
    req.push_str(&format!("OPTIONS sip:probe@{host}:{port} SIP/2.0\r\n"));
    req.push_str("Via: SIP/2.0/UDP 0.0.0.0:0;branch=z9hG4bK-rastreo-probe\r\n");
    req.push_str("Max-Forwards: 70\r\n");
    req.push_str("From: <sip:probe@localhost>;tag=rastreo\r\n");
    req.push_str(&format!("To: <sip:probe@{host}:{port}>\r\n"));
    req.push_str(&format!("Call-ID: rastreo-{call_id}\r\n"));
    req.push_str("CSeq: 1 OPTIONS\r\n");
    req.push_str(&format!(
        "User-Agent: rastreo/{}\r\n",
        env!("CARGO_PKG_VERSION")
    ));
    req.push_str("Content-Length: 0\r\n\r\n");
    req.into_bytes()
}

/// Parse a SIP response and pick the `Server:` header (preferred) or `User-Agent:` header,
/// trimmed and byte-capped, as a [`Signal::SipUserAgent`].
pub fn parse_response(bytes: &[u8]) -> Option<Signal> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");
    let status = lines.next()?;
    if !status.starts_with("SIP/2.0") {
        return None;
    }
    let mut server: Option<String> = None;
    let mut user_agent: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(value) = header_value(line, "server") {
            if server.is_none() {
                server = Some(value.to_string());
            }
        } else if let Some(value) = header_value(line, "user-agent") {
            if user_agent.is_none() {
                user_agent = Some(value.to_string());
            }
        }
    }
    let picked = server.or(user_agent)?;
    let trimmed = truncate_header(picked.trim());
    if trimmed.is_empty() {
        return None;
    }
    Some(Signal::SipUserAgent(trimmed))
}

fn format_host(ip: IpAddr) -> String {
    if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    }
}

fn header_value<'a>(line: &'a str, name_lower: &str) -> Option<&'a str> {
    let colon = line.find(':')?;
    let (name, rest) = line.split_at(colon);
    if !name.eq_ignore_ascii_case(name_lower) {
        return None;
    }
    Some(&rest[1..])
}

fn truncate_header(raw: &str) -> String {
    if raw.len() <= HEADER_MAX_BYTES {
        return raw.to_string();
    }
    let mut end = HEADER_MAX_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    raw[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn build_request_embeds_ip_and_port_for_ipv4_target() {
        let bytes = build_request(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060, 0xdeadbeef);
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.starts_with("OPTIONS sip:probe@10.0.0.1:5060 SIP/2.0\r\n"));
        assert!(text.contains("Call-ID: rastreo-00000000deadbeef\r\n"));
        assert!(text.contains("CSeq: 1 OPTIONS\r\n"));
        assert!(text.ends_with("Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn build_request_brackets_ipv6_target_in_request_uri() {
        let bytes = build_request(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060, 0);
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.starts_with("OPTIONS sip:probe@[::1]:5060 SIP/2.0\r\n"));
    }

    #[test]
    fn parse_response_extracts_server_header() {
        let raw = "SIP/2.0 200 OK\r\nServer: Kamailio/5.6.5\r\nContent-Length: 0\r\n\r\n";
        match parse_response(raw.as_bytes()) {
            Some(Signal::SipUserAgent(s)) => assert_eq!(s, "Kamailio/5.6.5"),
            other => panic!("expected SipUserAgent, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_prefers_server_over_user_agent() {
        let raw =
            "SIP/2.0 200 OK\r\nUser-Agent: Asterisk PBX 18.10.0\r\nServer: Kamailio/5.6.5\r\n\r\n";
        match parse_response(raw.as_bytes()) {
            Some(Signal::SipUserAgent(s)) => assert_eq!(s, "Kamailio/5.6.5"),
            other => panic!("expected SipUserAgent, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_falls_back_to_user_agent_when_no_server_header() {
        let raw = "SIP/2.0 200 OK\r\nUser-Agent: Asterisk PBX 18.10.0\r\n\r\n";
        match parse_response(raw.as_bytes()) {
            Some(Signal::SipUserAgent(s)) => assert_eq!(s, "Asterisk PBX 18.10.0"),
            other => panic!("expected SipUserAgent, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_is_case_insensitive_on_header_names() {
        let raw = "SIP/2.0 200 OK\r\nSERVER: Kamailio\r\n\r\n";
        match parse_response(raw.as_bytes()) {
            Some(Signal::SipUserAgent(s)) => assert_eq!(s, "Kamailio"),
            other => panic!("expected SipUserAgent, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_handles_error_responses() {
        let raw = "SIP/2.0 404 Not Found\r\nServer: Kamailio/5.6.5\r\n\r\n";
        match parse_response(raw.as_bytes()) {
            Some(Signal::SipUserAgent(s)) => assert_eq!(s, "Kamailio/5.6.5"),
            other => panic!("expected SipUserAgent, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_returns_none_when_no_sip_prefix() {
        let raw = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        assert!(parse_response(raw.as_bytes()).is_none());
    }

    #[test]
    fn parse_response_returns_none_when_no_server_or_ua_header() {
        let raw = "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_response(raw.as_bytes()).is_none());
    }

    #[test]
    fn parse_response_returns_none_for_non_utf8_bytes() {
        let bytes = [0xFF, 0xFE, 0x00, 0x01];
        assert!(parse_response(&bytes).is_none());
    }

    #[test]
    fn parse_response_truncates_long_header_value() {
        let long = "X".repeat(400);
        let raw = format!("SIP/2.0 200 OK\r\nServer: {long}\r\n\r\n");
        match parse_response(raw.as_bytes()) {
            Some(Signal::SipUserAgent(s)) => assert_eq!(s.len(), HEADER_MAX_BYTES),
            other => panic!("expected SipUserAgent, got {other:?}"),
        }
    }
}
