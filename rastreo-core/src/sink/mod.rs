pub mod file;
#[cfg(feature = "kafka")]
pub mod kafka;
pub mod memory;
#[cfg(feature = "nats")]
pub mod nats;
pub mod stdout;

pub use file::FileSink;
#[cfg(feature = "kafka")]
pub use kafka::{DeadLetterConfig, KafkaFlushMode, KafkaSink};
pub use memory::{MemorySink, MemorySinkHandle};
#[cfg(feature = "nats")]
pub use nats::{NatsCredentials, NatsDelivery, NatsSink};
pub use stdout::StdoutSink;

use std::path::PathBuf;

use schemars::JsonSchema;

use crate::error::RastreoError;

#[async_trait::async_trait]
pub trait Sink: Send + Sync {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError>;

    async fn flush(&mut self) -> Result<(), RastreoError>;

    // Default: every write is delivered. Batching sinks override to reflect buffered state.
    fn last_write_delivered(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SinkConfig {
    Stdout,
    File {
        path: PathBuf,
    },
    Memory,
    #[cfg(feature = "kafka")]
    Kafka {
        brokers: Vec<String>,
        topic: String,
        #[serde(default)]
        flush_mode: KafkaFlushMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dead_letter: Option<DeadLetterConfig>,
    },
    #[cfg(feature = "nats")]
    Nats {
        servers: Vec<String>,
        subject: String,
        stream: String,
        #[serde(default)]
        credentials: NatsCredentials,
        #[serde(default)]
        delivery: NatsDelivery,
    },
}

pub async fn create_sink(config: &SinkConfig) -> Result<Box<dyn Sink>, RastreoError> {
    match config {
        SinkConfig::Stdout => Ok(Box::new(StdoutSink::new())),
        SinkConfig::File { path } => Ok(Box::new(FileSink::new(path).await?)),
        SinkConfig::Memory => Ok(Box::new(MemorySink::new())),
        #[cfg(feature = "kafka")]
        SinkConfig::Kafka {
            brokers,
            topic,
            flush_mode,
            dead_letter,
        } => {
            let mut sink = KafkaSink::new(brokers.clone(), topic.clone()).await?;
            sink = sink.with_flush_mode(flush_mode.clone());
            if let Some(dlq) = dead_letter {
                sink = sink.with_dead_letter(dlq.clone()).await?;
            }
            Ok(Box::new(sink))
        }
        #[cfg(feature = "nats")]
        SinkConfig::Nats {
            servers,
            subject,
            stream,
            credentials,
            delivery,
        } => {
            let sink = NatsSink::new(
                servers.clone(),
                subject.clone(),
                stream.clone(),
                credentials.clone(),
            )
            .await?;
            Ok(Box::new(sink.with_delivery(delivery.clone())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSink {
        buffer: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl Sink for MockSink {
        async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
            self.buffer.extend_from_slice(data);
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
    }

    #[test]
    fn default_last_write_delivered_is_true() {
        let s: Box<dyn Sink> = Box::new(MockSink { buffer: Vec::new() });
        assert!(s.last_write_delivered());
    }

    #[test]
    fn sink_trait_object_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Sink>();
    }

    #[tokio::test]
    async fn create_sink_stdout_returns_trait_object() {
        let _sink: Box<dyn Sink> = create_sink(&SinkConfig::Stdout)
            .await
            .expect("create stdout sink");
    }

    #[tokio::test]
    async fn create_sink_file_returns_trait_object() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("factory.ndjson");
        let _sink: Box<dyn Sink> = create_sink(&SinkConfig::File { path })
            .await
            .expect("create file sink");
    }

    #[tokio::test]
    async fn create_sink_memory_returns_trait_object() {
        let mut sink: Box<dyn Sink> = create_sink(&SinkConfig::Memory)
            .await
            .expect("create memory sink");
        sink.write(b"factory").await.expect("write");
        sink.flush().await.expect("flush");
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_stdout_sink_config_from_yaml() {
        let yaml = "type: stdout\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize stdout");
        match config {
            SinkConfig::Stdout => {}
            other => panic!("expected Stdout, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_file_sink_config_from_yaml() {
        let yaml = "type: file\npath: /tmp/foo.ndjson\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize file");
        match config {
            SinkConfig::File { path } => {
                assert_eq!(path, PathBuf::from("/tmp/foo.ndjson"));
            }
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_memory_sink_config_from_yaml() {
        let yaml = "type: memory\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize memory");
        match config {
            SinkConfig::Memory => {}
            other => panic!("expected Memory, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "kafka"))]
    #[test]
    fn deserialize_kafka_sink_config_with_per_record_flush_mode() {
        let yaml =
            "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\nflush_mode:\n  type: per_record\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka {
                brokers,
                topic,
                flush_mode,
                dead_letter,
            } => {
                assert_eq!(brokers, vec!["k:9092".to_string()]);
                assert_eq!(topic, "t");
                assert!(matches!(flush_mode, KafkaFlushMode::PerRecord));
                assert!(dead_letter.is_none());
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_with_defaults() {
        let yaml = "type: nats\nservers: [\"nats://nats:4222\"]\nsubject: rastreo.discovery.records.v1\nstream: rastreo\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats {
                servers,
                subject,
                stream,
                credentials,
                delivery,
            } => {
                assert_eq!(servers, vec!["nats://nats:4222".to_string()]);
                assert_eq!(subject, "rastreo.discovery.records.v1");
                assert_eq!(stream, "rastreo");
                assert!(matches!(credentials, NatsCredentials::Anonymous));
                assert!(matches!(delivery, NatsDelivery::PerRecord));
            }
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_with_user_pass_credentials() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\ncredentials:\n  auth_type: user_pass\n  username: admin\n  password: sekret\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { credentials, .. } => match credentials {
                NatsCredentials::UserPass { username, password } => {
                    assert_eq!(username, "admin");
                    assert_eq!(&*password, "sekret");
                }
                other => panic!("expected UserPass, got {other:?}"),
            },
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_with_token_credentials() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\ncredentials:\n  auth_type: token\n  token: tok\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { credentials, .. } => match credentials {
                NatsCredentials::Token { token } => assert_eq!(&*token, "tok"),
                other => panic!("expected Token, got {other:?}"),
            },
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_with_creds_file() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\ncredentials:\n  auth_type: creds\n  creds_file: /etc/rastreo/nats.creds\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { credentials, .. } => match credentials {
                NatsCredentials::Creds { creds_file } => {
                    assert_eq!(creds_file, "/etc/rastreo/nats.creds");
                }
                other => panic!("expected Creds, got {other:?}"),
            },
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_with_batched_delivery() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\ndelivery:\n  mode: batched\n  threshold_bytes: 4096\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { delivery, .. } => match delivery {
                NatsDelivery::Batched { threshold_bytes } => assert_eq!(threshold_bytes, 4096),
                other => panic!("expected Batched, got {other:?}"),
            },
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_requires_servers() {
        let yaml = "type: nats\nsubject: s\nstream: st\n";
        let result: Result<SinkConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err(), "missing servers must fail");
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_requires_subject() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nstream: st\n";
        let result: Result<SinkConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err(), "missing subject must fail");
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_requires_stream() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\n";
        let result: Result<SinkConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err(), "missing stream must fail");
    }

    #[cfg(all(feature = "config", feature = "kafka"))]
    #[test]
    fn deserialize_kafka_sink_config_with_batched_flush_mode_and_threshold() {
        let yaml = "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\nflush_mode:\n  type: batched\n  threshold_bytes: 2048\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka { flush_mode, .. } => match flush_mode {
                KafkaFlushMode::Batched { threshold_bytes } => {
                    assert_eq!(threshold_bytes, 2048);
                }
                other => panic!("expected Batched, got {other:?}"),
            },
            other => panic!("expected Kafka, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "kafka"))]
    #[test]
    fn sink_config_kafka_deserializes_dead_letter_field() {
        let yaml =
            "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\ndead_letter:\n  topic: rastreo.dlq\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka { dead_letter, .. } => {
                let dlq = dead_letter.expect("dead_letter present");
                assert_eq!(dlq.topic, "rastreo.dlq");
                assert!(dlq.include_error_metadata);
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "kafka"))]
    #[test]
    fn sink_config_kafka_without_dead_letter_deserializes_as_none() {
        let yaml = "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka { dead_letter, .. } => {
                assert!(dead_letter.is_none());
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
    }
}
