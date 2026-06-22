pub mod file;
#[cfg(feature = "kafka")]
pub mod kafka;
pub mod memory;
pub mod stdout;

pub use file::FileSink;
#[cfg(feature = "kafka")]
pub use kafka::{KafkaFlushMode, KafkaSink};
pub use memory::{MemorySink, MemorySinkHandle};
pub use stdout::StdoutSink;

use std::path::PathBuf;

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

#[derive(Debug, Clone, serde::Deserialize)]
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
        } => {
            let sink = KafkaSink::new(brokers.clone(), topic.clone()).await?;
            Ok(Box::new(sink.with_flush_mode(flush_mode.clone())))
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
            } => {
                assert_eq!(brokers, vec!["k:9092".to_string()]);
                assert_eq!(topic, "t");
                assert!(matches!(flush_mode, KafkaFlushMode::PerRecord));
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
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
}
