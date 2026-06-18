use crate::error::RastreoError;
use crate::model::DeviceRecord;

pub trait Encoder: Send + Sync {
    fn encode_record(&self, record: &DeviceRecord, buf: &mut Vec<u8>) -> Result<(), RastreoError>;
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EncoderConfig {}

pub fn create_encoder(config: &EncoderConfig) -> Result<Box<dyn Encoder>, RastreoError> {
    match *config {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use crate::error::EncoderError;
    use crate::model::{Confidence, IdentityKey};

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

    #[test]
    fn mock_encoder_writes_to_caller_buffer() {
        let enc: Box<dyn Encoder> = Box::new(MockEncoder);
        let record = DeviceRecord {
            identity_key: IdentityKey::new("router-1").expect("identity"),
            mgmt_ip: None,
            mac: None,
            manufacturer: None,
            platform: None,
            role: None,
            confidence: Confidence::new(0.5).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: vec![],
        };
        let mut buf = Vec::new();
        enc.encode_record(&record, &mut buf).expect("encode");
        assert!(!buf.is_empty(), "encoder must write something to buf");
        assert!(buf.starts_with(b"{"), "JSON-shaped output");
    }

    #[test]
    fn encoder_trait_object_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Encoder>();
    }
}
