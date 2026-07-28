pub mod ndjson;
pub mod table;

pub use ndjson::NdjsonEncoder;
pub use table::TableEncoder;

use crate::error::{ConfigError, EncoderError, RastreoError};
use crate::model::{CollectionProfileRecord, DeviceRecord, LinkRecord};

/// Renders records into a caller-provided byte buffer. An encoder with nothing to render for a
/// record kind leaves the buffer untouched; the pipeline then skips the write and does not count it.
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
    /// Aligned fixed-width text for reading a scan directly; links and collection profiles are not rendered.
    Table {
        /// Total line width the columns are laid out within, clamped to `55..=153`.
        #[serde(default = "table::default_width")]
        width: u16,
    },
}

impl EncoderConfig {
    /// Whether every record leaves as one machine-parseable object.
    pub fn emits_structured_records(&self) -> bool {
        match self {
            EncoderConfig::Ndjson => true,
            EncoderConfig::Table { .. } => false,
        }
    }
}

/// Rejects an encoder whose output the destination cannot carry; the flag comes from either
/// [`crate::sink::SinkConfig`] or a live [`crate::sink::Sink`].
pub fn ensure_encoder_output_fits_sink(
    encoder: &EncoderConfig,
    sink_requires_structured_records: bool,
) -> Result<(), RastreoError> {
    if sink_requires_structured_records && !encoder.emits_structured_records() {
        return Err(ConfigError::invalid(
            "the table encoder writes aligned text rows, which this sink cannot carry: its consumers read one structured record per message. Use the ndjson encoder with this sink.",
        )
        .into());
    }
    Ok(())
}

pub fn create_encoder(config: &EncoderConfig) -> Result<Box<dyn Encoder>, RastreoError> {
    match config {
        EncoderConfig::Ndjson => Ok(Box::new(NdjsonEncoder::new())),
        EncoderConfig::Table { width } => Ok(Box::new(TableEncoder::new(*width))),
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

    #[test]
    fn create_encoder_table_returns_working_trait_object() {
        let enc = create_encoder(&EncoderConfig::Table {
            width: table::default_width(),
        })
        .expect("create table encoder");
        let mut buf = Vec::new();
        enc.encode_record(&sample_record(), &mut buf)
            .expect("encode");
        let rendered = String::from_utf8(buf).expect("utf-8");
        assert!(rendered.starts_with("ADDRESS"), "rendered: {rendered}");
        assert!(rendered.contains("router-1"), "rendered: {rendered}");
    }

    fn table_header(width: u16) -> String {
        let enc = create_encoder(&EncoderConfig::Table { width }).expect("create");
        let mut buf = Vec::new();
        enc.encode_record(&sample_record(), &mut buf)
            .expect("encode");
        let rendered = String::from_utf8(buf).expect("utf-8");
        rendered.lines().next().expect("header").to_string()
    }

    #[test]
    fn create_encoder_table_widens_the_columns_with_the_configured_width() {
        // The last column carries no trailing padding, so a header stops short of the full grid.
        assert_eq!(table_header(60).chars().count(), 52);
        assert_eq!(table_header(120).chars().count(), 95);
    }

    #[test]
    fn create_encoder_table_saturates_a_width_beyond_the_widest_grid() {
        assert_eq!(table_header(200), table_header(table::MAX_TOTAL_WIDTH));
    }

    #[test]
    fn ndjson_emits_structured_records_and_table_does_not() {
        assert!(EncoderConfig::Ndjson.emits_structured_records());
        assert!(!EncoderConfig::Table { width: 100 }.emits_structured_records());
    }

    #[test]
    fn a_structured_sink_rejects_the_table_encoder() {
        let err = ensure_encoder_output_fits_sink(&EncoderConfig::Table { width: 100 }, true)
            .expect_err("table into a structured sink must be rejected");
        match err {
            RastreoError::Config(crate::error::ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("table encoder"), "msg was: {msg}");
                assert!(msg.contains("ndjson"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn a_structured_sink_accepts_the_ndjson_encoder() {
        ensure_encoder_output_fits_sink(&EncoderConfig::Ndjson, true).expect("ndjson is accepted");
    }

    #[test]
    fn an_unstructured_sink_accepts_either_encoder() {
        ensure_encoder_output_fits_sink(&EncoderConfig::Ndjson, false).expect("ndjson");
        ensure_encoder_output_fits_sink(&EncoderConfig::Table { width: 100 }, false)
            .expect("table");
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_ndjson_encoder_config_from_yaml() {
        let yaml = "type: ndjson\n";
        let config: EncoderConfig = serde_yaml_ng::from_str(yaml).expect("deserialize ndjson");
        match config {
            EncoderConfig::Ndjson => {}
            other => panic!("expected Ndjson, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_table_encoder_config_without_width_uses_the_typed_default() {
        let yaml = "type: table\n";
        let config: EncoderConfig = serde_yaml_ng::from_str(yaml).expect("deserialize table");
        match config {
            EncoderConfig::Table { width } => assert_eq!(width, table::default_width()),
            other => panic!("expected Table, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_table_encoder_config_with_an_explicit_width() {
        let yaml = "type: table\nwidth: 200\n";
        let config: EncoderConfig = serde_yaml_ng::from_str(yaml).expect("deserialize table");
        match config {
            EncoderConfig::Table { width } => assert_eq!(width, 200),
            other => panic!("expected Table, got {other:?}"),
        }
    }
}
