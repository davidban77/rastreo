use crate::error::{EncoderError, RastreoError};
use crate::model::DeviceRecord;

use super::Encoder;

pub struct NdjsonEncoder;

impl NdjsonEncoder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NdjsonEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for NdjsonEncoder {
    fn encode_record(&self, record: &DeviceRecord, buf: &mut Vec<u8>) -> Result<(), RastreoError> {
        serde_json::to_writer(&mut *buf, record).map_err(EncoderError::SerializationFailed)?;
        // NDJSON: one record per line.
        buf.push(b'\n');
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::model::{
        Confidence, IdentityKey, ScanMetadata, Signal, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
    };

    fn sample_record(name: &str) -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new(name).expect("identity key"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            manufacturer: Some("Cisco".into()),
            platform: Some("IOS-XR".into()),
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: Some("router".into()),
            confidence: Confidence::new(0.75).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: vec![Signal::OpenPort(22)],
            probe_kinds: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    #[test]
    fn encode_then_parse_recovers_record() {
        let enc = NdjsonEncoder::new();
        let record = sample_record("router-1");
        let mut buf = Vec::new();
        enc.encode_record(&record, &mut buf).expect("encode");

        let line = &buf[..buf.len() - 1];
        let back: DeviceRecord = serde_json::from_slice(line).expect("parse json");
        assert_eq!(back.identity_key.as_str(), "router-1");
        assert_eq!(back.mgmt_ip, record.mgmt_ip);
        assert_eq!(back.confidence.value(), 0.75);
        assert_eq!(back.signals.len(), 1);
    }

    #[test]
    fn encoded_output_ends_with_newline() {
        let enc = NdjsonEncoder::new();
        let mut buf = Vec::new();
        enc.encode_record(&sample_record("a"), &mut buf)
            .expect("encode");
        assert_eq!(buf.last().copied(), Some(b'\n'));
    }

    #[test]
    fn two_records_produce_two_lines() {
        let enc = NdjsonEncoder::new();
        let mut buf = Vec::new();
        enc.encode_record(&sample_record("a"), &mut buf)
            .expect("encode 1");
        enc.encode_record(&sample_record("b"), &mut buf)
            .expect("encode 2");

        let newline_count = buf.iter().filter(|b| **b == b'\n').count();
        assert_eq!(newline_count, 2);

        let mut lines = buf.split(|b| *b == b'\n').filter(|l| !l.is_empty());
        let first: DeviceRecord =
            serde_json::from_slice(lines.next().expect("line 1")).expect("parse 1");
        let second: DeviceRecord =
            serde_json::from_slice(lines.next().expect("line 2")).expect("parse 2");
        assert_eq!(first.identity_key.as_str(), "a");
        assert_eq!(second.identity_key.as_str(), "b");
        assert!(lines.next().is_none(), "exactly two non-empty lines");
    }

    #[test]
    fn empty_buffer_is_accepted() {
        let enc = NdjsonEncoder::new();
        let mut buf: Vec<u8> = Vec::new();
        assert!(buf.is_empty());
        enc.encode_record(&sample_record("a"), &mut buf)
            .expect("encode");
        assert!(!buf.is_empty());
    }

    #[test]
    fn ndjson_encoder_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NdjsonEncoder>();
    }

    #[test]
    fn encode_link_writes_one_newline_terminated_json_line() {
        use crate::model::{LinkEndpoint, LinkRecord, LINK_SCHEMA_ID};

        let link = LinkRecord {
            schema_version: LinkRecord::SCHEMA_VERSION.to_string(),
            schema_id: LINK_SCHEMA_ID.to_string(),
            a: LinkEndpoint {
                identity_key: Some("mac:aabbccddeeff".into()),
                chassis_id: "aabbccddeeff".into(),
                sys_name: None,
                port: "Gi0/1".into(),
            },
            b: LinkEndpoint {
                identity_key: None,
                chassis_id: "001122334455".into(),
                sys_name: Some("peer".into()),
                port: "Gi0/2".into(),
            },
            discovered_via: "lldp".into(),
            observed_at: SystemTime::UNIX_EPOCH,
            scan_metadata: ScanMetadata::default(),
        };
        let enc = NdjsonEncoder::new();
        let mut buf = Vec::new();
        enc.encode_link(&link, &mut buf).expect("encode link");
        assert_eq!(buf.last().copied(), Some(b'\n'));
        let back: LinkRecord = serde_json::from_slice(&buf[..buf.len() - 1]).expect("parse line");
        assert_eq!(back, link);
    }
}
