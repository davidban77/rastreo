pub mod file;
#[cfg(feature = "kafka")]
pub mod kafka;
pub mod memory;
#[cfg(feature = "nats")]
pub mod nats;
pub mod stdout;
pub mod tee;

pub use file::FileSink;
#[cfg(feature = "kafka")]
pub use kafka::{DeadLetterConfig, KafkaFlushMode, KafkaSink};
pub use memory::{MemorySink, MemorySinkHandle};
#[cfg(feature = "nats")]
pub use nats::{NatsCredentials, NatsDeadLetterConfig, NatsDelivery, NatsSink};
pub use stdout::StdoutSink;
pub use tee::{TeeChild, TeeSink};

use std::path::PathBuf;

use schemars::JsonSchema;

use crate::error::RastreoError;

/// Bounded taxonomy of sink failure classes surfaced on `sink_errors_total` and `dlq_records_total`.
///
/// The classifier maps `io::Error` messages produced by concrete sinks to one of these
/// variants. Variants are `#[non_exhaustive]` so future sinks can add classes without
/// breaking downstream exhaustive matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SinkErrorClass {
    PublishFailure,
    AckRejection,
    ProduceFailure,
    WriteFailure,
    FlushFailure,
    Other,
}

/// Number of `SinkErrorClass` variants — indexes fixed-size counter arrays without heap allocation.
pub const SINK_ERROR_CLASS_COUNT: usize = 6;

impl SinkErrorClass {
    /// Every variant in a stable, deterministic order — used for iterating fixed-size counter arrays.
    pub const fn all() -> &'static [SinkErrorClass; SINK_ERROR_CLASS_COUNT] {
        &[
            SinkErrorClass::PublishFailure,
            SinkErrorClass::AckRejection,
            SinkErrorClass::ProduceFailure,
            SinkErrorClass::WriteFailure,
            SinkErrorClass::FlushFailure,
            SinkErrorClass::Other,
        ]
    }

    /// Stable index for use in fixed-size `[T; SINK_ERROR_CLASS_COUNT]` arrays.
    pub const fn index(self) -> usize {
        match self {
            SinkErrorClass::PublishFailure => 0,
            SinkErrorClass::AckRejection => 1,
            SinkErrorClass::ProduceFailure => 2,
            SinkErrorClass::WriteFailure => 3,
            SinkErrorClass::FlushFailure => 4,
            SinkErrorClass::Other => 5,
        }
    }

    /// snake_case wire label used in `/metrics` and OTLP attribute values.
    pub const fn as_label(self) -> &'static str {
        match self {
            SinkErrorClass::PublishFailure => "publish_failure",
            SinkErrorClass::AckRejection => "ack_rejection",
            SinkErrorClass::ProduceFailure => "produce_failure",
            SinkErrorClass::WriteFailure => "write_failure",
            SinkErrorClass::FlushFailure => "flush_failure",
            SinkErrorClass::Other => "other",
        }
    }
}

/// Concrete sink kind — surfaced on `dlq_records_total{sink_type}` and set on `DiscoverySummary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SinkType {
    Stdout,
    File,
    Memory,
    Kafka,
    Nats,
    Tee,
}

impl SinkType {
    /// snake_case wire label used in `/metrics` and OTLP attribute values.
    pub const fn as_label(self) -> &'static str {
        match self {
            SinkType::Stdout => "stdout",
            SinkType::File => "file",
            SinkType::Memory => "memory",
            SinkType::Kafka => "kafka",
            SinkType::Nats => "nats",
            SinkType::Tee => "tee",
        }
    }
}

/// Map a sink-produced `io::Error` to a bounded `SinkErrorClass` for metric labelling.
///
/// The mapping keys off message prefixes that concrete sinks emit — the classifier is
/// intentionally structural (string-based) because the underlying error types differ
/// across sinks and stringifying is already the shared surface via `io::Error`.
pub fn classify_sink_error(err: &std::io::Error) -> SinkErrorClass {
    let msg = err.to_string();
    if msg.contains("was not acked") {
        SinkErrorClass::AckRejection
    } else if msg.contains("failed to publish") {
        SinkErrorClass::PublishFailure
    } else if msg.contains("failed to produce") {
        SinkErrorClass::ProduceFailure
    } else if msg.contains("failed to flush") {
        SinkErrorClass::FlushFailure
    } else if msg.contains("failed to write") {
        SinkErrorClass::WriteFailure
    } else {
        SinkErrorClass::Other
    }
}

#[async_trait::async_trait]
pub trait Sink: Send + Sync {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError>;

    async fn flush(&mut self) -> Result<(), RastreoError>;

    // Default: every write is delivered. Batching sinks override to reflect buffered state.
    fn last_write_delivered(&self) -> bool {
        true
    }

    /// Concrete sink kind; overridden by every built-in implementation.
    fn kind(&self) -> SinkType {
        SinkType::Memory
    }

    /// Cumulative count of records delivered to a dead-letter destination.
    ///
    /// Default is `0`; sinks with DLQ support increment the counter only when a
    /// record is successfully accepted by the DLQ (publish AND ack when applicable).
    /// Failures to DLQ do not count.
    fn dlq_records_delivered(&self) -> u64 {
        0
    }

    /// DLQ deliveries attributed to the underlying destination sink type.
    ///
    /// Default derives from `kind()` and `dlq_records_delivered()` — a single-protocol
    /// sink returns one entry (or empty when its count is zero). Fan-out sinks that
    /// deliver to children of different protocols override this to preserve per-type
    /// attribution for the DLQ metric.
    fn dlq_records_by_type(&self) -> Vec<(SinkType, u64)> {
        let count = self.dlq_records_delivered();
        if count == 0 {
            Vec::new()
        } else {
            vec![(self.kind(), count)]
        }
    }

    /// Lightweight liveness check the server-side reachability probe consumes.
    ///
    /// Default is `Ok(())` — local sinks are always reachable. Network-backed sinks
    /// override with a cheap round-trip (metadata / flush / ping). The error message
    /// is surfaced verbatim on `/readyz`, so implementations should include the sink
    /// kind and enough operator-facing context to triage without opening logs.
    async fn probe(&self) -> Result<(), std::io::Error> {
        Ok(())
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dead_letter: Option<NatsDeadLetterConfig>,
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
            dead_letter,
        } => {
            let mut sink = NatsSink::new(
                servers.clone(),
                subject.clone(),
                stream.clone(),
                credentials.clone(),
            )
            .await?;
            sink = sink.with_delivery(delivery.clone());
            if let Some(dlq) = dead_letter {
                sink = sink.with_dead_letter(dlq.clone()).await?;
            }
            Ok(Box::new(sink))
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
    fn default_dlq_records_delivered_is_zero() {
        let s: Box<dyn Sink> = Box::new(MockSink { buffer: Vec::new() });
        assert_eq!(s.dlq_records_delivered(), 0);
    }

    #[tokio::test]
    async fn default_probe_reports_reachable() {
        let s: Box<dyn Sink> = Box::new(MockSink { buffer: Vec::new() });
        s.probe().await.expect("default probe must succeed");
    }

    #[tokio::test]
    async fn stdout_sink_probe_reports_reachable() {
        let sink: Box<dyn Sink> = create_sink(&SinkConfig::Stdout).await.expect("create");
        sink.probe().await.expect("stdout probe must succeed");
    }

    #[tokio::test]
    async fn memory_sink_probe_reports_reachable() {
        let sink: Box<dyn Sink> = create_sink(&SinkConfig::Memory).await.expect("create");
        sink.probe().await.expect("memory probe must succeed");
    }

    #[tokio::test]
    async fn file_sink_probe_reports_reachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("probe.ndjson");
        let sink: Box<dyn Sink> = create_sink(&SinkConfig::File { path })
            .await
            .expect("create");
        sink.probe().await.expect("file probe must succeed");
    }

    #[test]
    fn sink_error_class_all_and_indices_are_dense() {
        let all = SinkErrorClass::all();
        assert_eq!(all.len(), SINK_ERROR_CLASS_COUNT);
        for (i, class) in all.iter().enumerate() {
            assert_eq!(class.index(), i);
        }
    }

    #[test]
    fn sink_error_class_labels_are_unique_snake_case() {
        let mut labels: Vec<&str> = SinkErrorClass::all().iter().map(|c| c.as_label()).collect();
        labels.sort();
        for pair in labels.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
        for label in labels {
            assert!(label.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    #[test]
    fn sink_type_labels_match_snake_case_variant_names() {
        assert_eq!(SinkType::Stdout.as_label(), "stdout");
        assert_eq!(SinkType::File.as_label(), "file");
        assert_eq!(SinkType::Memory.as_label(), "memory");
        assert_eq!(SinkType::Kafka.as_label(), "kafka");
        assert_eq!(SinkType::Nats.as_label(), "nats");
        assert_eq!(SinkType::Tee.as_label(), "tee");
    }

    #[test]
    fn classify_produce_failure_matches_kafka_produce_message() {
        let io_err = std::io::Error::other(
            "kafka sink: failed to produce record to topic 't' at broker(s) 'b:9092': boom",
        );
        assert_eq!(classify_sink_error(&io_err), SinkErrorClass::ProduceFailure);
    }

    #[test]
    fn classify_publish_failure_matches_nats_publish_message() {
        let io_err = std::io::Error::other(
            "nats sink: failed to publish to subject 'x' at server(s) 'n:4222': boom",
        );
        assert_eq!(classify_sink_error(&io_err), SinkErrorClass::PublishFailure);
    }

    #[test]
    fn classify_ack_rejection_matches_nats_ack_message() {
        let io_err = std::io::Error::other(
            "nats sink: publish to subject 'x' at server(s) 'n:4222' was not acked: rejected",
        );
        assert_eq!(classify_sink_error(&io_err), SinkErrorClass::AckRejection);
    }

    #[test]
    fn classify_other_falls_through_for_unknown_message() {
        let io_err = std::io::Error::other("some unrelated io failure");
        assert_eq!(classify_sink_error(&io_err), SinkErrorClass::Other);
    }

    #[tokio::test]
    async fn stdout_sink_reports_kind_stdout() {
        let sink: Box<dyn Sink> = create_sink(&SinkConfig::Stdout).await.expect("create");
        assert_eq!(sink.kind(), SinkType::Stdout);
    }

    #[tokio::test]
    async fn memory_sink_reports_kind_memory() {
        let sink: Box<dyn Sink> = create_sink(&SinkConfig::Memory).await.expect("create");
        assert_eq!(sink.kind(), SinkType::Memory);
    }

    #[tokio::test]
    async fn file_sink_reports_kind_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kind.ndjson");
        let sink: Box<dyn Sink> = create_sink(&SinkConfig::File { path })
            .await
            .expect("create");
        assert_eq!(sink.kind(), SinkType::File);
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
                dead_letter,
            } => {
                assert_eq!(servers, vec!["nats://nats:4222".to_string()]);
                assert_eq!(subject, "rastreo.discovery.records.v1");
                assert_eq!(stream, "rastreo");
                assert!(matches!(credentials, NatsCredentials::Anonymous));
                assert!(matches!(delivery, NatsDelivery::PerRecord));
                assert!(dead_letter.is_none());
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

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn sink_config_nats_deserializes_dead_letter_field() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\ndead_letter:\n  stream: dlq-stream\n  subject: rastreo.dlq\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { dead_letter, .. } => {
                let dlq = dead_letter.expect("dead_letter present");
                assert_eq!(dlq.stream, "dlq-stream");
                assert_eq!(dlq.subject, "rastreo.dlq");
                assert!(dlq.include_error_metadata);
            }
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn sink_config_nats_without_dead_letter_deserializes_as_none() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { dead_letter, .. } => {
                assert!(dead_letter.is_none());
            }
            other => panic!("expected Nats, got {other:?}"),
        }
    }
}
