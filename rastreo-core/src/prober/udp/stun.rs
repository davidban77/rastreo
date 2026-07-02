//! STUN Binding Request / Success Response (RFC 8489). XOR-MAPPED-ADDRESS only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::Signal;

pub(super) const MAGIC_COOKIE: u32 = 0x2112_A442;
pub(super) const TRANSACTION_ID_LEN: usize = 12;
pub(super) const HEADER_LEN: usize = 20;

const MSG_TYPE_BINDING_REQUEST: u16 = 0x0001;
const MSG_TYPE_BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// Build a 20-byte STUN Binding Request with the given transaction ID.
pub fn build_request(transaction_id: [u8; TRANSACTION_ID_LEN]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.extend_from_slice(&MSG_TYPE_BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // Message Length
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&transaction_id);
    buf
}

/// Parse a Binding Success Response, requiring the same `transaction_id`, and extract
/// XOR-MAPPED-ADDRESS as a [`Signal::StunMappedAddress`] shaped `ip:port` (IPv6 bracketed).
pub fn parse_response(bytes: &[u8], transaction_id: &[u8; TRANSACTION_ID_LEN]) -> Option<Signal> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if msg_type != MSG_TYPE_BINDING_SUCCESS {
        return None;
    }
    let msg_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if !msg_len.is_multiple_of(4) {
        return None;
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return None;
    }
    if &bytes[8..20] != transaction_id.as_slice() {
        return None;
    }
    if bytes.len() < HEADER_LEN + msg_len {
        return None;
    }

    let mut cursor = HEADER_LEN;
    let end = HEADER_LEN + msg_len;
    while cursor + 4 <= end {
        let attr_type = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let attr_len = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        let value_start = cursor + 4;
        let value_end = value_start.checked_add(attr_len)?;
        if value_end > end {
            return None;
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            let value = &bytes[value_start..value_end];
            return parse_xor_mapped_address(value, transaction_id);
        }
        // STUN attributes are padded to 4-byte boundaries.
        let padded_len = (attr_len + 3) & !3;
        cursor = value_start + padded_len;
    }
    None
}

fn parse_xor_mapped_address(
    value: &[u8],
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Option<Signal> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let x_port = u16::from_be_bytes([value[2], value[3]]);
    let port = x_port ^ ((MAGIC_COOKIE >> 16) as u16);
    let ip: IpAddr = match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return None;
            }
            let x_addr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = x_addr ^ MAGIC_COOKIE;
            IpAddr::V4(Ipv4Addr::from(addr))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            octets[4..16].copy_from_slice(transaction_id);
            let mut out = [0u8; 16];
            for i in 0..16 {
                out[i] = value[4 + i] ^ octets[i];
            }
            IpAddr::V6(Ipv6Addr::from(out))
        }
        _ => return None,
    };
    let formatted = match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };
    Some(Signal::StunMappedAddress(formatted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success_response(transaction_id: [u8; TRANSACTION_ID_LEN], attrs: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + attrs.len());
        buf.extend_from_slice(&MSG_TYPE_BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&transaction_id);
        buf.extend_from_slice(attrs);
        buf
    }

    fn xor_mapped_ipv4_attr(port: u16, ip: Ipv4Addr) -> Vec<u8> {
        let x_port = port ^ ((MAGIC_COOKIE >> 16) as u16);
        let x_addr = u32::from(ip) ^ MAGIC_COOKIE;
        let mut attr = Vec::with_capacity(4 + 8);
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0x00); // reserved
        attr.push(FAMILY_IPV4);
        attr.extend_from_slice(&x_port.to_be_bytes());
        attr.extend_from_slice(&x_addr.to_be_bytes());
        attr
    }

    fn xor_mapped_ipv6_attr(
        port: u16,
        ip: Ipv6Addr,
        transaction_id: [u8; TRANSACTION_ID_LEN],
    ) -> Vec<u8> {
        let x_port = port ^ ((MAGIC_COOKIE >> 16) as u16);
        let mut xor_key = [0u8; 16];
        xor_key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        xor_key[4..16].copy_from_slice(&transaction_id);
        let mut x_addr = [0u8; 16];
        let ip_octets = ip.octets();
        for i in 0..16 {
            x_addr[i] = ip_octets[i] ^ xor_key[i];
        }
        let mut attr = Vec::with_capacity(4 + 20);
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&20u16.to_be_bytes());
        attr.push(0x00);
        attr.push(FAMILY_IPV6);
        attr.extend_from_slice(&x_port.to_be_bytes());
        attr.extend_from_slice(&x_addr);
        attr
    }

    fn software_attr(text: &[u8]) -> Vec<u8> {
        let mut attr = Vec::with_capacity(4 + text.len() + 3);
        attr.extend_from_slice(&0x8022u16.to_be_bytes()); // SOFTWARE (comprehension-optional)
        attr.extend_from_slice(&(text.len() as u16).to_be_bytes());
        attr.extend_from_slice(text);
        while attr.len() % 4 != 0 {
            attr.push(0);
        }
        attr
    }

    #[test]
    fn build_request_produces_20_byte_binding_request() {
        let tid = [0xAAu8; TRANSACTION_ID_LEN];
        let req = build_request(tid);
        assert_eq!(req.len(), HEADER_LEN);
        assert_eq!(&req[0..2], &MSG_TYPE_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[2..4], &0u16.to_be_bytes());
        assert_eq!(&req[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&req[8..20], &tid);
    }

    #[test]
    fn parse_response_extracts_ipv4_xor_mapped_address() {
        let tid = [0x11u8; TRANSACTION_ID_LEN];
        let attrs = xor_mapped_ipv4_attr(54321, Ipv4Addr::new(203, 0, 113, 42));
        let resp = success_response(tid, &attrs);
        match parse_response(&resp, &tid) {
            Some(Signal::StunMappedAddress(s)) => assert_eq!(s, "203.0.113.42:54321"),
            other => panic!("expected StunMappedAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_extracts_ipv6_xor_mapped_address() {
        let tid = [0x22u8; TRANSACTION_ID_LEN];
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let attrs = xor_mapped_ipv6_attr(3478, ip, tid);
        let resp = success_response(tid, &attrs);
        match parse_response(&resp, &tid) {
            Some(Signal::StunMappedAddress(s)) => assert_eq!(s, "[2001:db8::1]:3478"),
            other => panic!("expected StunMappedAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_skips_leading_software_attribute_to_find_xma() {
        let tid = [0x33u8; TRANSACTION_ID_LEN];
        let mut attrs = software_attr(b"CoTurn 4.5.2");
        attrs.extend(xor_mapped_ipv4_attr(1234, Ipv4Addr::new(198, 51, 100, 5)));
        let resp = success_response(tid, &attrs);
        match parse_response(&resp, &tid) {
            Some(Signal::StunMappedAddress(s)) => assert_eq!(s, "198.51.100.5:1234"),
            other => panic!("expected StunMappedAddress, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_rejects_wrong_magic_cookie() {
        let tid = [0x44u8; TRANSACTION_ID_LEN];
        let attrs = xor_mapped_ipv4_attr(54321, Ipv4Addr::new(203, 0, 113, 42));
        let mut resp = success_response(tid, &attrs);
        resp[4] = 0x00; // clobber magic cookie
        assert!(parse_response(&resp, &tid).is_none());
    }

    #[test]
    fn parse_response_rejects_transaction_id_mismatch() {
        let tid = [0x55u8; TRANSACTION_ID_LEN];
        let wrong = [0x00u8; TRANSACTION_ID_LEN];
        let attrs = xor_mapped_ipv4_attr(54321, Ipv4Addr::new(203, 0, 113, 42));
        let resp = success_response(tid, &attrs);
        assert!(parse_response(&resp, &wrong).is_none());
    }

    #[test]
    fn parse_response_rejects_binding_error_message_type() {
        let tid = [0x66u8; TRANSACTION_ID_LEN];
        let attrs = xor_mapped_ipv4_attr(54321, Ipv4Addr::new(203, 0, 113, 42));
        let mut resp = success_response(tid, &attrs);
        resp[0] = 0x01;
        resp[1] = 0x11; // Binding Error
        assert!(parse_response(&resp, &tid).is_none());
    }

    #[test]
    fn parse_response_rejects_truncated_header() {
        let tid = [0x77u8; TRANSACTION_ID_LEN];
        let short = vec![0u8; 10];
        assert!(parse_response(&short, &tid).is_none());
    }

    #[test]
    fn parse_response_returns_none_when_no_xor_mapped_address_attr() {
        let tid = [0x88u8; TRANSACTION_ID_LEN];
        let attrs = software_attr(b"OnlySoftware");
        let resp = success_response(tid, &attrs);
        assert!(parse_response(&resp, &tid).is_none());
    }

    #[test]
    fn parse_response_rejects_unaligned_message_length() {
        let tid = [0xAAu8; TRANSACTION_ID_LEN];
        let attrs = xor_mapped_ipv4_attr(54321, Ipv4Addr::new(203, 0, 113, 42));
        let mut resp = success_response(tid, &attrs);
        resp[2] = 0;
        resp[3] = 3; // not a multiple of 4
        assert!(parse_response(&resp, &tid).is_none());
    }

    #[test]
    fn parse_response_rejects_unknown_address_family() {
        let tid = [0x99u8; TRANSACTION_ID_LEN];
        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0x00);
        attr.push(0xFF); // unknown family
        attr.extend_from_slice(&0u16.to_be_bytes());
        attr.extend_from_slice(&0u32.to_be_bytes());
        let resp = success_response(tid, &attr);
        assert!(parse_response(&resp, &tid).is_none());
    }
}
