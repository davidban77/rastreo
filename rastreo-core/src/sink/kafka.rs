use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use chrono::Utc;
use rskafka::{
    client::{
        partition::{Compression, OffsetAt, PartitionClient, UnknownTopicHandling},
        ClientBuilder,
    },
    record::Record,
};

use crate::error::{ConfigError, RastreoError};
use crate::sink::{Sink, SinkType};

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

fn buffer_record(buffer: &mut Vec<Vec<u8>>, buffered_bytes: &mut usize, data: &[u8]) {
    buffer.push(data.to_vec());
    *buffered_bytes += data.len();
}

fn build_records(
    entries: &[Vec<u8>],
    headers: &BTreeMap<String, Vec<u8>>,
    timestamp: chrono::DateTime<Utc>,
) -> Vec<Record> {
    entries
        .iter()
        .map(|value| Record {
            key: None,
            value: Some(value.clone()),
            headers: headers.clone(),
            timestamp,
        })
        .collect()
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
    buffer: Vec<Vec<u8>>,
    buffered_bytes: usize,
    buffer_threshold: usize,
    last_write_delivered: bool,
    dlq_client: Option<PartitionClient>,
    dlq_topic: Option<String>,
    include_error_metadata: bool,
    dlq_delivered: AtomicU64,
}

impl std::fmt::Debug for KafkaSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaSink")
            .field("topic", &self.topic)
            .field("brokers", &self.brokers)
            .field("buffered_records", &self.buffer.len())
            .field("buffered_bytes", &self.buffered_bytes)
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
            buffer: Vec::new(),
            buffered_bytes: 0,
            buffer_threshold: Self::DEFAULT_BUFFER_THRESHOLD,
            last_write_delivered: false,
            dlq_client: None,
            dlq_topic: None,
            include_error_metadata: false,
            dlq_delivered: AtomicU64::new(0),
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

    fn clear_buffer(&mut self) {
        self.buffer.clear();
        self.buffered_bytes = 0;
    }

    async fn publish_buffer(&mut self) -> Result<(), RastreoError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let record_count = self.buffer.len() as u64;
        // One Record per entry: N entries produce N individually-consumable messages in one round-trip.
        let primary_records = build_records(&self.buffer, &BTreeMap::new(), Utc::now());

        let primary_err = match self
            .client
            .produce(primary_records, Compression::NoCompression)
            .await
        {
            Ok(_) => {
                self.clear_buffer();
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
            records = record_count,
            "kafka sink: primary produce failed; shipping records to DLQ",
        );

        let dlq_headers = if self.include_error_metadata {
            build_dlq_headers(&self.topic)
        } else {
            BTreeMap::new()
        };
        let dlq_records = build_records(&self.buffer, &dlq_headers, Utc::now());

        match dlq_client
            .produce(dlq_records, Compression::NoCompression)
            .await
        {
            Ok(_) => {
                // DLQ absorbed every buffered record; primary failure is quarantined, not propagated.
                self.clear_buffer();
                self.dlq_delivered
                    .fetch_add(record_count, Ordering::Relaxed);
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
        buffer_record(&mut self.buffer, &mut self.buffered_bytes, data);
        if should_flush_after_append(self.buffered_bytes, self.buffer_threshold) {
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

    fn kind(&self) -> SinkType {
        SinkType::Kafka
    }

    fn dlq_records_delivered(&self) -> u64 {
        self.dlq_delivered.load(Ordering::Relaxed)
    }

    async fn probe(&self) -> Result<(), io::Error> {
        let brokers_for_err = self.brokers.join(",");
        let primary_result = self.client.get_offset(OffsetAt::Latest).await;
        let dlq_result = match (self.dlq_client.as_ref(), self.dlq_topic.as_ref()) {
            (Some(dlq_client), Some(dlq_topic)) => {
                Some((dlq_client.get_offset(OffsetAt::Latest).await, dlq_topic))
            }
            _ => None,
        };

        let mut failures: Vec<String> = Vec::with_capacity(2);
        if let Err(e) = primary_result {
            failures.push(format!(
                "primary partition unreachable for topic '{}' at broker(s) '{brokers_for_err}': {e}",
                self.topic
            ));
        }
        if let Some((Err(e), dlq_topic)) = dlq_result {
            failures.push(format!(
                "dead-letter partition unreachable for topic '{dlq_topic}' at broker(s) '{brokers_for_err}': {e}"
            ));
        }

        if failures.is_empty() {
            return Ok(());
        }

        Err(io::Error::other(format!(
            "kafka sink probe: {}",
            failures.join("; ")
        )))
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
    fn buffer_record_appends_one_entry_per_call_and_sums_bytes() {
        let mut buffer: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0usize;
        buffer_record(&mut buffer, &mut bytes, b"one\n");
        buffer_record(&mut buffer, &mut bytes, b"two\n");
        buffer_record(&mut buffer, &mut bytes, b"three\n");
        assert_eq!(buffer.len(), 3, "each write must stay a distinct entry");
        assert_eq!(buffer[0], b"one\n");
        assert_eq!(buffer[1], b"two\n");
        assert_eq!(buffer[2], b"three\n");
        assert_eq!(bytes, 4 + 4 + 6);
    }

    #[test]
    fn build_records_produces_one_record_per_entry() {
        let entries = vec![b"a\n".to_vec(), b"b\n".to_vec(), b"c\n".to_vec()];
        let records = build_records(&entries, &BTreeMap::new(), Utc::now());
        assert_eq!(
            records.len(),
            3,
            "a batched flush of 3 records must produce 3 messages, not one concatenated value"
        );
        assert_eq!(records[0].value.as_deref(), Some(b"a\n".as_ref()));
        assert_eq!(records[1].value.as_deref(), Some(b"b\n".as_ref()));
        assert_eq!(records[2].value.as_deref(), Some(b"c\n".as_ref()));
    }

    #[test]
    fn build_records_attaches_dlq_headers_to_every_record() {
        let entries = vec![b"a\n".to_vec(), b"b\n".to_vec()];
        let headers = build_dlq_headers("rastreo.devices");
        let records = build_records(&entries, &headers, Utc::now());
        assert_eq!(records.len(), 2, "all buffered records ship to the DLQ");
        for record in &records {
            assert!(record.headers.contains_key(HEADER_SOURCE_TOPIC));
            assert!(record.headers.contains_key(HEADER_ERROR_CLASS));
        }
    }

    #[test]
    fn build_records_on_empty_buffer_produces_no_records() {
        let records = build_records(&[], &BTreeMap::new(), Utc::now());
        assert!(records.is_empty());
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

    #[ignore = "requires a live Kafka broker; exercised in Live Infra UAT"]
    #[tokio::test]
    async fn probe_reports_reachable_against_live_broker() {
        let sink = KafkaSink::new(vec!["localhost:9092".into()], "rastreo.probe".into())
            .await
            .expect("connect to live broker");
        <KafkaSink as Sink>::probe(&sink).await.expect("probe");
    }

    #[ignore = "requires a live Kafka broker with primary + DLQ topics; exercised in Live Infra UAT"]
    #[tokio::test]
    async fn probe_returns_ok_when_primary_and_dlq_both_reachable() {
        let sink = KafkaSink::new(vec!["localhost:9092".into()], "rastreo.probe".into())
            .await
            .expect("connect to live broker")
            .with_dead_letter(DeadLetterConfig {
                topic: "rastreo.probe.dlq".into(),
                include_error_metadata: true,
            })
            .await
            .expect("attach dlq");
        <KafkaSink as Sink>::probe(&sink)
            .await
            .expect("probe both sides");
    }

    #[ignore = "requires a live Kafka broker where the DLQ topic partition is offline / non-existent"]
    #[tokio::test]
    async fn probe_reports_unreachable_when_dlq_partition_offline() {
        let sink = KafkaSink::new(vec!["localhost:9092".into()], "rastreo.probe".into())
            .await
            .expect("connect to live broker")
            .with_dead_letter(DeadLetterConfig {
                topic: "rastreo.probe.dlq.does-not-exist".into(),
                include_error_metadata: true,
            })
            .await
            .expect("attach dlq");
        let err = <KafkaSink as Sink>::probe(&sink)
            .await
            .expect_err("dlq partition offline must fail probe");
        let msg = err.to_string();
        assert!(
            msg.starts_with("kafka sink probe: "),
            "expected canonical prefix, got: {msg}"
        );
        assert!(
            msg.contains("dead-letter partition unreachable"),
            "expected DLQ-attributed failure, got: {msg}"
        );
        assert!(
            msg.contains("rastreo.probe.dlq.does-not-exist"),
            "expected DLQ topic in message, got: {msg}"
        );
    }

    #[ignore = "requires a live Kafka broker where both primary and DLQ partitions are offline / non-existent"]
    #[tokio::test]
    async fn probe_reports_both_sides_unreachable_when_primary_and_dlq_both_offline() {
        let sink = KafkaSink::new(
            vec!["localhost:9092".into()],
            "rastreo.probe.does-not-exist".into(),
        )
        .await
        .expect("connect to live broker")
        .with_dead_letter(DeadLetterConfig {
            topic: "rastreo.probe.dlq.does-not-exist".into(),
            include_error_metadata: true,
        })
        .await
        .expect("attach dlq");
        let err = <KafkaSink as Sink>::probe(&sink)
            .await
            .expect_err("both partitions offline must fail probe");
        let msg = err.to_string();
        assert!(
            msg.starts_with("kafka sink probe: "),
            "expected canonical prefix, got: {msg}"
        );
        assert!(
            msg.contains("primary partition unreachable"),
            "expected primary-attributed failure segment, got: {msg}"
        );
        assert!(
            msg.contains("dead-letter partition unreachable"),
            "expected DLQ-attributed failure segment, got: {msg}"
        );
        let primary_idx = msg
            .find("primary partition unreachable")
            .expect("primary segment present");
        let dlq_idx = msg
            .find("dead-letter partition unreachable")
            .expect("dlq segment present");
        assert!(
            primary_idx < dlq_idx,
            "expected primary segment before DLQ segment, got: {msg}"
        );
        let between = &msg[primary_idx..dlq_idx];
        assert!(
            between.contains("; "),
            "expected '; ' separator between failure segments, got: {msg}"
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
