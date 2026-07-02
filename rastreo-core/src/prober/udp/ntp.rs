//! NTPv3 client packet (RFC 5905): 48 bytes, LI=0 VN=3 Mode=3 client.

use crate::model::Signal;

const PACKET_LEN: usize = 48;
const MODE_SERVER: u8 = 4;

/// Build a 48-byte NTPv3 client request. First byte encodes `LI=0 VN=3 Mode=3`.
pub fn build_request() -> Vec<u8> {
    let mut buf = vec![0u8; PACKET_LEN];
    buf[0] = 0x1B;
    buf
}

/// Parse a server response into an [`Signal::NtpBanner`] carrying `stratum=<n> ref=<id>`.
pub fn parse_response(bytes: &[u8]) -> Option<Signal> {
    if bytes.len() < PACKET_LEN {
        return None;
    }
    let mode = bytes[0] & 0b0000_0111;
    if mode != MODE_SERVER {
        return None;
    }
    let stratum = bytes[1];
    let ref_id = &bytes[12..16];
    let ref_str = format_ref_id(stratum, ref_id);
    Some(Signal::NtpBanner(format!(
        "stratum={stratum} ref={ref_str}"
    )))
}

fn format_ref_id(stratum: u8, ref_id: &[u8]) -> String {
    // Stratum 0 (kiss-of-death) and stratum 1 carry a 4-char ASCII code.
    if stratum <= 1 {
        let mut s = String::with_capacity(4);
        for &b in ref_id {
            if (0x20..=0x7E).contains(&b) {
                s.push(b as char);
            }
        }
        if !s.is_empty() {
            return s;
        }
    }
    format!("{}.{}.{}.{}", ref_id[0], ref_id[1], ref_id[2], ref_id[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_packet(mode: u8, stratum: u8, ref_id: [u8; 4]) -> Vec<u8> {
        let mut buf = vec![0u8; PACKET_LEN];
        // LI=0, VN=4, Mode=<mode>
        buf[0] = (4 << 3) | (mode & 0b111);
        buf[1] = stratum;
        buf[12..16].copy_from_slice(&ref_id);
        buf
    }

    #[test]
    fn build_request_is_48_bytes_with_correct_first_byte() {
        let req = build_request();
        assert_eq!(req.len(), PACKET_LEN);
        assert_eq!(req[0], 0x1B);
        assert!(req[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn parse_response_extracts_stratum_and_ipv4_ref_id() {
        let bytes = server_packet(MODE_SERVER, 2, [203, 0, 113, 1]);
        match parse_response(&bytes) {
            Some(Signal::NtpBanner(s)) => assert_eq!(s, "stratum=2 ref=203.0.113.1"),
            other => panic!("expected NtpBanner, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_extracts_ascii_ref_id_for_stratum_1() {
        let bytes = server_packet(MODE_SERVER, 1, *b"GPS ");
        match parse_response(&bytes) {
            Some(Signal::NtpBanner(s)) => assert_eq!(s, "stratum=1 ref=GPS "),
            other => panic!("expected NtpBanner, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_extracts_ascii_ref_id_for_stratum_0_kod() {
        let bytes = server_packet(MODE_SERVER, 0, *b"RATE");
        match parse_response(&bytes) {
            Some(Signal::NtpBanner(s)) => assert_eq!(s, "stratum=0 ref=RATE"),
            other => panic!("expected NtpBanner, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_falls_back_to_numeric_when_stratum_1_ref_is_not_ascii() {
        let bytes = server_packet(MODE_SERVER, 1, [0x00, 0xFF, 0x00, 0xFF]);
        match parse_response(&bytes) {
            Some(Signal::NtpBanner(s)) => assert_eq!(s, "stratum=1 ref=0.255.0.255"),
            other => panic!("expected NtpBanner, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_rejects_wrong_mode() {
        let bytes = server_packet(3, 2, [203, 0, 113, 1]);
        assert!(parse_response(&bytes).is_none());
    }

    #[test]
    fn parse_response_rejects_truncated_packet() {
        let bytes = vec![0u8; 32];
        assert!(parse_response(&bytes).is_none());
    }

    #[test]
    fn parse_response_rejects_empty_bytes() {
        assert!(parse_response(&[]).is_none());
    }

    #[test]
    fn parse_response_accepts_unsynchronized_stratum() {
        let bytes = server_packet(MODE_SERVER, 16, [0, 0, 0, 0]);
        match parse_response(&bytes) {
            Some(Signal::NtpBanner(s)) => assert_eq!(s, "stratum=16 ref=0.0.0.0"),
            other => panic!("expected NtpBanner, got {other:?}"),
        }
    }
}
