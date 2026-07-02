//! Memcached ASCII protocol `stats` command over UDP.

use crate::model::Signal;

const VERSION_MAX_BYTES: usize = 64;
pub(super) const FRAME_HEADER_LEN: usize = 8;

/// Build a memcached UDP datagram: 8-byte frame header + `stats\r\n`.
pub fn build_request(request_id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + 7);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // sequence number
    buf.extend_from_slice(&1u16.to_be_bytes()); // total datagrams
    buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
    buf.extend_from_slice(b"stats\r\n");
    buf
}

/// Parse a memcached UDP stats response: strip the 8-byte frame header and pick the
/// `version` value as [`Signal::MemcachedVersion`]. Multi-datagram responses are rejected.
pub fn parse_response(bytes: &[u8]) -> Option<Signal> {
    if bytes.len() < FRAME_HEADER_LEN {
        return None;
    }
    let total_datagrams = u16::from_be_bytes([bytes[4], bytes[5]]);
    if total_datagrams != 1 {
        return None;
    }
    let text = std::str::from_utf8(&bytes[FRAME_HEADER_LEN..]).ok()?;
    if !(text.starts_with("STAT ") || text.starts_with("END") || text.starts_with("SERVER_ERROR")) {
        return None;
    }
    for line in text.split("\r\n") {
        let Some(rest) = line.strip_prefix("STAT ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(' ') else {
            continue;
        };
        if name == "version" {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            let capped = if value.len() <= VERSION_MAX_BYTES {
                value.to_string()
            } else {
                let mut end = VERSION_MAX_BYTES;
                while end > 0 && !value.is_char_boundary(end) {
                    end -= 1;
                }
                value[..end].to_string()
            };
            return Some(Signal::MemcachedVersion(capped));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(request_id: u16, total_datagrams: u16, body: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
        buf.extend_from_slice(&request_id.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&total_datagrams.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(body);
        buf
    }

    #[test]
    fn build_request_writes_frame_header_and_command() {
        let req = build_request(0xBEEF);
        assert_eq!(req.len(), FRAME_HEADER_LEN + 7);
        assert_eq!(&req[0..2], &0xBEEFu16.to_be_bytes());
        assert_eq!(&req[2..4], &0u16.to_be_bytes());
        assert_eq!(&req[4..6], &1u16.to_be_bytes());
        assert_eq!(&req[6..8], &0u16.to_be_bytes());
        assert_eq!(&req[FRAME_HEADER_LEN..], b"stats\r\n");
    }

    #[test]
    fn parse_response_strips_frame_header_and_extracts_version() {
        let body = b"STAT pid 42\r\nSTAT version 1.6.24\r\nSTAT uptime 3600\r\nEND\r\n";
        let raw = framed(0x0001, 1, body);
        match parse_response(&raw) {
            Some(Signal::MemcachedVersion(s)) => assert_eq!(s, "1.6.24"),
            other => panic!("expected MemcachedVersion, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_rejects_missing_frame_header() {
        assert!(parse_response(b"STAT version 1.6.24\r\nEND\r\n").is_none());
    }

    #[test]
    fn parse_response_rejects_multi_datagram_response() {
        let raw = framed(0x0001, 2, b"STAT version 1.6.24\r\nEND\r\n");
        assert!(parse_response(&raw).is_none());
    }

    #[test]
    fn parse_response_returns_none_when_no_version_line() {
        let raw = framed(0x0001, 1, b"STAT pid 42\r\nSTAT uptime 3600\r\nEND\r\n");
        assert!(parse_response(&raw).is_none());
    }

    #[test]
    fn parse_response_returns_none_when_response_is_not_memcached() {
        let raw = framed(0x0001, 1, b"220 SMTP welcome\r\n");
        assert!(parse_response(&raw).is_none());
    }

    #[test]
    fn parse_response_returns_none_for_non_utf8_bytes() {
        let raw = framed(0x0001, 1, &[0xFF, 0xFE]);
        assert!(parse_response(&raw).is_none());
    }

    #[test]
    fn parse_response_truncates_long_version_string() {
        let long = "1.".to_string() + &"9".repeat(200);
        let body = format!("STAT version {long}\r\nEND\r\n");
        let raw = framed(0x0001, 1, body.as_bytes());
        match parse_response(&raw) {
            Some(Signal::MemcachedVersion(s)) => assert_eq!(s.len(), VERSION_MAX_BYTES),
            other => panic!("expected MemcachedVersion, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_accepts_server_error_prefix_as_memcached_shape() {
        let raw = framed(0x0001, 1, b"SERVER_ERROR out of memory\r\n");
        assert!(parse_response(&raw).is_none());
    }

    #[test]
    fn parse_response_ignores_stat_line_missing_value() {
        let raw = framed(0x0001, 1, b"STAT version\r\nEND\r\n");
        assert!(parse_response(&raw).is_none());
    }
}
