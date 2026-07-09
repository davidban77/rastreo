use std::collections::BTreeMap;
use std::io;

use async_trait::async_trait;
use chrono::Utc;
use rskafka::{
    client::{
        partition::{Compression, PartitionClient, UnknownTopicHandling},
        ClientBuilder,
    },
    record::Record,
};

use crate::error::{ConfigError, RastreoError};
use crate::sink::Sink;

/// Quarantine topic configuration for records the primary Kafka produce refused.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct DeadLetterConfig {
    pub topic: String,
    #[serde(default = "default_include_error_metadata")]
    pub include_error_metadata: bool,
}

impl DeadLetterConfig {
    /// Reject empty / whitespace-only topics at config-load time rather than at broker-connect time.
    pub fn validate(&self) -> Result<(), RastreoError> {
        if self.topic.trim().is_empty() {
            return Err(ConfigError::invalid("kafka sink: dead-letter topic is empty").into());
        }
        Ok(())
    }
}

fn default_include_error_metadata() -> bool {
    true
}

const HEADER_SOURCE_TOPIC: &str = "x-rastreo-source-topic";
const HEADER_ERROR_CLASS: &str = "x-rastreo-error-class";
const HEADER_DLQ_TIMESTAMP: &str = "x-rastreo-dlq-timestamp";
const ERROR_CLASS_PRODUCE_FAILURE: &str = "produce_failure";

fn clamp_threshold(bytes: usize) -> usize {
    bytes.max(1)
}

fn should_flush_after_append(buffer_len: usize, threshold: usize) -> bool {
    buffer_len >= threshold
}

fn default_batch_threshold() -> usize {
    KafkaSink::DEFAULT_BUFFER_THRESHOLD
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum KafkaFlushMode {
    PerRecord,
    Batched {
        #[serde(default = "default_batch_threshold")]
        threshold_bytes: usize,
    },
}

impl KafkaFlushMode {
    fn to_threshold(&self) -> usize {
        match self {
            Self::PerRecord => 1,
            Self::Batched { threshold_bytes } => clamp_threshold(*threshold_bytes),
        }
    }
}

impl Default for KafkaFlushMode {
    fn default() -> Self {
        Self::Batched {
            threshold_bytes: KafkaSink::DEFAULT_BUFFER_THRESHOLD,
        }
    }
}

pub struct KafkaSink {
    topic: String,
    brokers: Vec<String>,
    client: PartitionClient,
    buffer: Vec<u8>,
    buffer_threshold: usize,
    last_write_delivered: bool,
    dlq_client: Option<PartitionClient>,
    dlq_topic: Option<String>,
    include_error_metadata: bool,
}

impl std::fmt::Debug for KafkaSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaSink")
            .field("topic", &self.topic)
            .field("brokers", &self.brokers)
            .field("buffer_len", &self.buffer.len())
            .field("buffer_threshold", &self.buffer_threshold)
            .field("last_write_delivered", &self.last_write_delivered)
            .field("dlq_topic", &self.dlq_topic)
            .field("include_error_metadata", &self.include_error_metadata)
            .finish_non_exhaustive()
    }
}

fn build_produce_error(
    topic: &str,
    brokers: &[String],
    err: rskafka::client::error::Error,
) -> RastreoError {
    let brokers_for_err = brokers.join(",");
    RastreoError::Sink(io::Error::other(format!(
        "kafka sink: failed to produce record to topic '{topic}' at broker(s) '{brokers_for_err}': {err}"
    )))
}

/// Envelope headers follow the `x-<vendor>-<name>` convention so downstream
/// consumers can filter DLQ records without inspecting the payload.
fn build_dlq_headers(source_topic: &str) -> BTreeMap<String, Vec<u8>> {
    let mut headers = BTreeMap::new();
    headers.insert(
        HEADER_SOURCE_TOPIC.to_string(),
        source_topic.as_bytes().to_vec(),
    );
    headers.insert(
        HEADER_ERROR_CLASS.to_string(),
        ERROR_CLASS_PRODUCE_FAILURE.as_bytes().to_vec(),
    );
    headers.insert(
        HEADER_DLQ_TIMESTAMP.to_string(),
        Utc::now().to_rfc3339().into_bytes(),
    );
    headers
}

impl KafkaSink {
    pub const DEFAULT_BUFFER_THRESHOLD: usize = 64 * 1024;

    pub async fn new(brokers: Vec<String>, topic: String) -> Result<Self, RastreoError> {
        if brokers.is_empty() {
            return Err(ConfigError::invalid("kafka sink: brokers list is empty").into());
        }
        if brokers.iter().any(|b| b.trim().is_empty()) {
            return Err(
                ConfigError::invalid("kafka sink: brokers list contains an empty entry").into(),
            );
        }
        if topic.trim().is_empty() {
            return Err(ConfigError::invalid("kafka sink: topic is empty").into());
        }

        let brokers_for_err = brokers.join(",");
        let kafka_client = ClientBuilder::new(brokers.clone())
            .build()
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("kafka sink: failed to connect to broker(s) '{brokers_for_err}': {e}"),
                )
            })
            .map_err(RastreoError::Sink)?;

        // Single-partition: always produces to partition 0.
        let client = kafka_client
            .partition_client(topic.clone(), 0, UnknownTopicHandling::Retry)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "kafka sink: failed to get partition client for topic '{topic}' at broker(s) '{brokers_for_err}': {e}"
                ))
            })
            .map_err(RastreoError::Sink)?;

        Ok(Self {
            topic,
            brokers,
            client,
            buffer: Vec::with_capacity(Self::DEFAULT_BUFFER_THRESHOLD),
            buffer_threshold: Self::DEFAULT_BUFFER_THRESHOLD,
            last_write_delivered: false,
            dlq_client: None,
            dlq_topic: None,
            include_error_metadata: false,
        })
    }

    pub fn with_flush_mode(mut self, mode: KafkaFlushMode) -> Self {
        self.buffer_threshold = mode.to_threshold();
        self
    }

    pub async fn with_dead_letter(
        mut self,
        config: DeadLetterConfig,
    ) -> Result<Self, RastreoError> {
        config.validate()?;

        let brokers_for_err = self.brokers.join(",");
        let dlq_topic = config.topic.clone();
        let kafka_client = ClientBuilder::new(self.brokers.clone())
            .build()
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("kafka sink: failed to connect to broker(s) '{brokers_for_err}' for dead-letter topic '{dlq_topic}': {e}"),
                )
            })
            .map_err(RastreoError::Sink)?;

        let dlq_client = kafka_client
            .partition_client(dlq_topic.clone(), 0, UnknownTopicHandling::Retry)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "kafka sink: failed to get partition client for dead-letter topic '{dlq_topic}' at broker(s) '{brokers_for_err}': {e}"
                ))
            })
            .map_err(RastreoError::Sink)?;

        self.dlq_client = Some(dlq_client);
        self.dlq_topic = Some(dlq_topic);
        self.include_error_metadata = config.include_error_metadata;
        Ok(self)
    }

    async fn publish_buffer(&mut self) -> Result<(), RastreoError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        // Buffer retained on produce failure so a caller can retry via flush().
        // Single-clone on the success/no-DLQ path; the DLQ fallback re-clones from
        // self.buffer (still intact) only when we actually reach it.
        let primary_record = Record {
            key: None,
            value: Some(self.buffer.clone()),
            headers: BTreeMap::new(),
            timestamp: Utc::now(),
        };

        let primary_err = match self
            .client
            .produce(vec![primary_record], Compression::NoCompression)
            .await
        {
            Ok(_) => {
                self.buffer.clear();
                return Ok(());
            }
            Err(e) => e,
        };

        let (Some(dlq_client), Some(dlq_topic)) =
            (self.dlq_client.as_ref(), self.dlq_topic.as_ref())
        else {
            return Err(build_produce_error(&self.topic, &self.brokers, primary_err));
        };

        tracing::warn!(
            topic = self.topic.as_str(),
            dlq_topic = dlq_topic.as_str(),
            error = %primary_err,
            "kafka sink: primary produce failed; shipping payload to DLQ",
        );

        let dlq_headers = if self.include_error_metadata {
            build_dlq_headers(&self.topic)
        } else {
            BTreeMap::new()
        };
        let dlq_record = Record {
            key: None,
            value: Some(self.buffer.clone()),
            headers: dlq_headers,
            timestamp: Utc::now(),
        };

        match dlq_client
            .produce(vec![dlq_record], Compression::NoCompression)
            .await
        {
            Ok(_) => {
                // DLQ absorbed the payload; primary failure is quarantined, not propagated.
                self.buffer.clear();
                Ok(())
            }
            Err(dlq_err) => {
                tracing::error!(
                    topic = self.topic.as_str(),
                    dlq_topic = dlq_topic.as_str(),
                    dlq_error = %dlq_err,
                    "kafka sink: DLQ produce also failed; retaining buffer",
                );
                Err(build_produce_error(&self.topic, &self.brokers, primary_err))
            }
        }
    }
}

#[async_trait]
impl Sink for KafkaSink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.last_write_delivered = false;
        self.buffer.extend_from_slice(data);
        if should_flush_after_append(self.buffer.len(), self.buffer_threshold) {
            self.publish_buffer().await?;
            self.last_write_delivered = true;
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        if !self.buffer.is_empty() {
            self.publish_buffer().await?;
            self.last_write_delivered = true;
        }
        Ok(())
    }

    fn last_write_delivered(&self) -> bool {
        self.last_write_delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_with_empty_brokers_returns_config_error() {
        let err = KafkaSink::new(vec![], "topic".into())
            .await
            .expect_err("empty brokers must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("brokers"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_with_blank_broker_entry_returns_config_error() {
        let err = KafkaSink::new(vec!["localhost:9092".into(), "   ".into()], "topic".into())
            .await
            .expect_err("blank broker entry must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("empty entry"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_with_empty_topic_returns_config_error() {
        let err = KafkaSink::new(vec!["localhost:9092".into()], "  ".into())
            .await
            .expect_err("blank topic must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("topic"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn default_buffer_threshold_is_64_kib() {
        assert_eq!(KafkaSink::DEFAULT_BUFFER_THRESHOLD, 64 * 1024);
    }

    #[test]
    fn dead_letter_config_validate_rejects_empty_topic() {
        let cfg = DeadLetterConfig {
            topic: "  ".into(),
            include_error_metadata: true,
        };
        let err = cfg.validate().expect_err("blank topic must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("dead-letter"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn dead_letter_config_validate_accepts_non_empty_topic() {
        let cfg = DeadLetterConfig {
            topic: "rastreo.discovery.dlq".into(),
            include_error_metadata: false,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn clamp_threshold_coerces_zero_to_one() {
        assert_eq!(clamp_threshold(0), 1);
    }

    #[test]
    fn clamp_threshold_passes_through_non_zero_values() {
        assert_eq!(clamp_threshold(1), 1);
        assert_eq!(clamp_threshold(1024), 1024);
        assert_eq!(clamp_threshold(usize::MAX), usize::MAX);
    }

    #[test]
    fn should_flush_after_append_is_false_below_threshold() {
        assert!(!should_flush_after_append(0, 1024));
        assert!(!should_flush_after_append(1023, 1024));
    }

    #[test]
    fn should_flush_after_append_is_true_at_or_above_threshold() {
        assert!(should_flush_after_append(1024, 1024));
        assert!(should_flush_after_append(2048, 1024));
    }

    #[test]
    fn kafka_sink_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<KafkaSink>();
        assert_send_sync::<Box<dyn Sink>>();
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_kafka_sink_config_from_yaml() {
        use crate::sink::SinkConfig;

        let yaml = "type: kafka\nbrokers: [\"kafka:9092\"]\ntopic: rastreo.devices\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka {
                brokers,
                topic,
                flush_mode,
                dead_letter,
            } => {
                assert_eq!(brokers, vec!["kafka:9092".to_string()]);
                assert_eq!(topic, "rastreo.devices");
                assert!(dead_letter.is_none());
                match flush_mode {
                    KafkaFlushMode::Batched { threshold_bytes } => {
                        assert_eq!(threshold_bytes, KafkaSink::DEFAULT_BUFFER_THRESHOLD);
                    }
                    other => panic!("expected default Batched flush mode, got {other:?}"),
                }
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
    }

    #[test]
    fn kafka_flush_mode_default_is_batched_64_kib() {
        match KafkaFlushMode::default() {
            KafkaFlushMode::Batched { threshold_bytes } => {
                assert_eq!(threshold_bytes, 64 * 1024);
            }
            other => panic!("expected Batched default, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn kafka_flush_mode_per_record_deserializes_from_yaml() {
        let yaml = "type: per_record\n";
        let mode: KafkaFlushMode = serde_yaml_ng::from_str(yaml).expect("deserialize per_record");
        assert!(matches!(mode, KafkaFlushMode::PerRecord));
    }

    #[cfg(feature = "config")]
    #[test]
    fn kafka_flush_mode_batched_with_threshold_deserializes() {
        let yaml = "type: batched\nthreshold_bytes: 1024\n";
        let mode: KafkaFlushMode = serde_yaml_ng::from_str(yaml).expect("deserialize batched");
        match mode {
            KafkaFlushMode::Batched { threshold_bytes } => assert_eq!(threshold_bytes, 1024),
            other => panic!("expected Batched, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn kafka_flush_mode_batched_default_threshold_deserializes() {
        let yaml = "type: batched\n";
        let mode: KafkaFlushMode =
            serde_yaml_ng::from_str(yaml).expect("deserialize batched no threshold");
        match mode {
            KafkaFlushMode::Batched { threshold_bytes } => {
                assert_eq!(threshold_bytes, 64 * 1024);
            }
            other => panic!("expected Batched, got {other:?}"),
        }
    }

    #[test]
    fn flush_mode_per_record_maps_to_threshold_one() {
        assert_eq!(KafkaFlushMode::PerRecord.to_threshold(), 1);
    }

    #[test]
    fn flush_mode_batched_maps_to_clamped_threshold() {
        assert_eq!(
            KafkaFlushMode::Batched { threshold_bytes: 0 }.to_threshold(),
            1
        );
        assert_eq!(
            KafkaFlushMode::Batched {
                threshold_bytes: 1024
            }
            .to_threshold(),
            1024
        );
    }

    #[test]
    fn flush_mode_batched_with_threshold_one_flushes_after_every_byte() {
        let threshold = KafkaFlushMode::PerRecord.to_threshold();
        assert!(should_flush_after_append(1, threshold));
        assert!(should_flush_after_append(2, threshold));
    }

    #[test]
    fn flush_mode_batched_holds_until_threshold_reached() {
        let threshold = KafkaFlushMode::Batched {
            threshold_bytes: 1024,
        }
        .to_threshold();
        assert!(!should_flush_after_append(0, threshold));
        assert!(!should_flush_after_append(1023, threshold));
        assert!(should_flush_after_append(1024, threshold));
        assert!(should_flush_after_append(2048, threshold));
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_kafka_sink_config_requires_brokers() {
        use crate::sink::SinkConfig;

        let yaml = "type: kafka\ntopic: t\n";
        let result: Result<SinkConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err(), "missing brokers must fail");
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_kafka_sink_config_requires_topic() {
        use crate::sink::SinkConfig;

        let yaml = "type: kafka\nbrokers: [\"a:9092\"]\n";
        let result: Result<SinkConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err(), "missing topic must fail");
    }

    #[cfg(feature = "config")]
    #[test]
    fn dead_letter_config_include_error_metadata_defaults_to_true() {
        let yaml = "topic: rastreo.dlq\n";
        let config: DeadLetterConfig =
            serde_yaml_ng::from_str(yaml).expect("deserialize dead-letter config");
        assert_eq!(config.topic, "rastreo.dlq");
        assert!(config.include_error_metadata);
    }

    #[cfg(feature = "config")]
    #[test]
    fn dead_letter_config_explicit_false_deserializes() {
        let yaml = "topic: rastreo.dlq\ninclude_error_metadata: false\n";
        let config: DeadLetterConfig =
            serde_yaml_ng::from_str(yaml).expect("deserialize dead-letter config");
        assert!(!config.include_error_metadata);
    }

    #[test]
    fn build_dlq_headers_contains_source_topic_and_error_class_and_timestamp() {
        let headers = build_dlq_headers("rastreo.devices");
        assert!(headers.contains_key(HEADER_SOURCE_TOPIC));
        assert!(headers.contains_key(HEADER_ERROR_CLASS));
        assert!(headers.contains_key(HEADER_DLQ_TIMESTAMP));
        for value in headers.values() {
            assert!(!value.is_empty(), "header value must be non-empty");
        }
    }

    #[test]
    fn build_dlq_headers_source_topic_matches_input() {
        let headers = build_dlq_headers("rastreo.devices");
        let value = headers
            .get(HEADER_SOURCE_TOPIC)
            .expect("source-topic header present");
        assert_eq!(
            std::str::from_utf8(value).expect("utf-8"),
            "rastreo.devices"
        );
    }

    #[test]
    fn build_dlq_headers_error_class_is_produce_failure() {
        let headers = build_dlq_headers("rastreo.devices");
        let value = headers
            .get(HEADER_ERROR_CLASS)
            .expect("error-class header present");
        assert_eq!(
            std::str::from_utf8(value).expect("utf-8"),
            ERROR_CLASS_PRODUCE_FAILURE
        );
    }

    #[test]
    fn build_dlq_headers_timestamp_parses_as_rfc3339() {
        let headers = build_dlq_headers("rastreo.devices");
        let value = headers
            .get(HEADER_DLQ_TIMESTAMP)
            .expect("timestamp header present");
        let ts = std::str::from_utf8(value).expect("utf-8");
        chrono::DateTime::parse_from_rfc3339(ts).expect("valid rfc3339 timestamp");
    }
}
