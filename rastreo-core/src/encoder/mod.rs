pub mod ndjson;

pub use ndjson::NdjsonEncoder;

use crate::error::{EncoderError, RastreoError};
use crate::model::{CollectionProfileRecord, DeviceRecord, LinkRecord};

pub trait Encoder: Send + Sync {
    fn encode_record(&self, record: &DeviceRecord, buf: &mut Vec<u8>) -> Result<(), RastreoError>;

    /// Encodes a topology link. Defaulted so existing encoders gain the second stream without
    /// change; the default mirrors `encode_record`'s one-object-per-line NDJSON framing.
    fn encode_link(&self, link: &LinkRecord, buf: &mut Vec<u8>) -> Result<(), RastreoError> {
        serde_json::to_writer(&mut *buf, link).map_err(EncoderError::SerializationFailed)?;
        buf.push(b'\n');
        Ok(())
    }

    /// Encodes a collection profile. Defaulted like `encode_link`, so existing encoders gain the
    /// profile stream without change; the default is one-object-per-line NDJSON.
    fn encode_profile(
        &self,
        profile: &CollectionProfileRecord,
        buf: &mut Vec<u8>,
    ) -> Result<(), RastreoError> {
        serde_json::to_writer(&mut *buf, profile).map_err(EncoderError::SerializationFailed)?;
        buf.push(b'\n');
        Ok(())
    }
}

/// The output wire format for records.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EncoderConfig {
    Ndjson,
}

pub fn create_encoder(config: &EncoderConfig) -> Result<Box<dyn Encoder>, RastreoError> {
    match config {
        EncoderConfig::Ndjson => Ok(Box::new(NdjsonEncoder::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::error::EncoderError;
    use crate::model::{
        Confidence, IdentityKey, ScanMetadata, CURRENT_SCHEMA_ID, CURRENT_SCHEMA_VERSION,
    };

    struct MockEncoder;

    impl Encoder for MockEncoder {
        fn encode_record(
            &self,
            record: &DeviceRecord,
            buf: &mut Vec<u8>,
        ) -> Result<(), RastreoError> {
            let json = serde_json::to_vec(record)
                .map_err(|e| RastreoError::Encoder(EncoderError::SerializationFailed(e)))?;
            buf.extend_from_slice(&json);
            Ok(())
        }
    }

    fn sample_record() -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new("router-1").expect("identity"),
            mgmt_ip: None,
            mac: None,
            manufacturer: None,
            model: None,
            product_family: None,
            platform: None,
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: None,
            confidence: Confidence::new(0.5).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: vec![],
            probe_kinds: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    #[test]
    fn mock_encoder_writes_to_caller_buffer() {
        let enc: Box<dyn Encoder> = Box::new(MockEncoder);
        let mut buf = Vec::new();
        enc.encode_record(&sample_record(), &mut buf)
            .expect("encode");
        assert!(!buf.is_empty(), "encoder must write something to buf");
        assert!(buf.starts_with(b"{"), "JSON-shaped output");
    }

    #[test]
    fn encoder_trait_object_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Encoder>();
    }

    #[test]
    fn create_encoder_ndjson_returns_working_trait_object() {
        let enc = create_encoder(&EncoderConfig::Ndjson).expect("create ndjson encoder");
        let mut buf = Vec::new();
        enc.encode_record(&sample_record(), &mut buf)
            .expect("encode");
        assert_eq!(buf.last().copied(), Some(b'\n'));
        let line = &buf[..buf.len() - 1];
        let back: DeviceRecord = serde_json::from_slice(line).expect("parse line");
        assert_eq!(back.identity_key.as_str(), "router-1");
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_ndjson_encoder_config_from_yaml() {
        let yaml = "type: ndjson\n";
        let config: EncoderConfig = serde_yaml_ng::from_str(yaml).expect("deserialize ndjson");
        match config {
            EncoderConfig::Ndjson => {}
        }
    }
}
