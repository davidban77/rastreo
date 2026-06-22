use std::collections::BTreeMap;
use std::io;

use async_trait::async_trait;
use chrono::Utc;
use rskafka::{
    client::{
        partition::{Compression, UnknownTopicHandling},
        ClientBuilder,
    },
    record::Record,
};

use crate::error::{ConfigError, RastreoError};
use crate::sink::Sink;

fn clamp_threshold(bytes: usize) -> usize {
    bytes.max(1)
}

fn should_flush_after_append(buffer_len: usize, threshold: usize) -> bool {
    buffer_len >= threshold
}

fn default_batch_threshold() -> usize {
    KafkaSink::DEFAULT_BUFFER_THRESHOLD
}

#[derive(Debug, Clone, serde::Deserialize)]
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
    client: rskafka::client::partition::PartitionClient,
    buffer: Vec<u8>,
    buffer_threshold: usize,
    last_write_delivered: bool,
}

impl std::fmt::Debug for KafkaSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaSink")
            .field("topic", &self.topic)
            .field("brokers", &self.brokers)
            .field("buffer_len", &self.buffer.len())
            .field("buffer_threshold", &self.buffer_threshold)
            .field("last_write_delivered", &self.last_write_delivered)
            .finish_non_exhaustive()
    }
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
        })
    }

    pub fn with_flush_mode(mut self, mode: KafkaFlushMode) -> Self {
        self.buffer_threshold = mode.to_threshold();
        self
    }

    async fn publish_buffer(&mut self) -> Result<(), RastreoError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        // Buffer retained on produce failure so a caller can retry via flush().
        let payload = self.buffer.clone();
        let record = Record {
            key: None,
            value: Some(payload),
            headers: BTreeMap::new(),
            timestamp: Utc::now(),
        };
        let brokers_for_err = self.brokers.join(",");
        let topic = &self.topic;
        self.client
            .produce(vec![record], Compression::NoCompression)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "kafka sink: failed to produce record to topic '{topic}' at broker(s) '{brokers_for_err}': {e}"
                ))
            })
            .map_err(RastreoError::Sink)?;
        self.buffer.clear();
        Ok(())
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
            } => {
                assert_eq!(brokers, vec!["kafka:9092".to_string()]);
                assert_eq!(topic, "rastreo.devices");
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
}
