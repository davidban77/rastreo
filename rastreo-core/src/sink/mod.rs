pub mod file;
#[cfg(feature = "kafka")]
pub mod kafka;
pub mod memory;
#[cfg(feature = "nats")]
pub mod nats;
pub mod retry;
pub mod stdout;
pub mod tee;

pub use file::FileSink;
#[cfg(feature = "kafka")]
pub use kafka::{DeadLetterConfig, KafkaFlushMode, KafkaSasl, KafkaSink, KafkaTls, SaslMechanism};
pub use memory::{MemorySink, MemorySinkHandle};
#[cfg(feature = "nats")]
pub use nats::{NatsCredentials, NatsDeadLetterConfig, NatsFlushMode, NatsSink};
pub use retry::{retry_with_backoff, SinkRetry};
pub use stdout::StdoutSink;
pub use tee::{TeeChild, TeeSink};

use std::path::PathBuf;

use schemars::JsonSchema;

#[cfg(any(feature = "kafka", feature = "nats"))]
use crate::error::ConfigError;
use crate::error::RastreoError;

/// The record stream a write belongs to. Sinks that fan a second stream to a distinct destination
/// (Kafka topic, NATS subject) route on this; the rest deliver every kind to one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordKind {
    Device,
    Link,
    CollectionProfile,
}

/// Default links topic (Kafka) / subject (NATS) when the sink config omits an override.
#[cfg(any(feature = "kafka", feature = "nats"))]
pub const DEFAULT_LINKS_DESTINATION: &str = "rastreo.discovery.links.v1";

/// Default collection-profile topic (Kafka) / subject (NATS) when the sink config omits an override.
#[cfg(any(feature = "kafka", feature = "nats"))]
pub const DEFAULT_PROFILES_DESTINATION: &str = "rastreo.discovery.profiles.v1";

/// Bounded taxonomy of sink failure classes surfaced on `sink_errors_total` and `dlq_records_total`.
///
/// Each concrete sink tags its failures with one of these variants at the failure site;
/// the class is carried on [`SinkError`], never re-derived from the message. Variants are
/// `#[non_exhaustive]` so future sinks can add classes without breaking downstream exhaustive
/// matching.
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

    /// Whether this destination's consumers parse each write as one structured record, which makes
    /// aligned-text encoders unusable against it. Read by both the `Sink` and `SinkConfig` twins.
    pub const fn requires_structured_records(self) -> bool {
        match self {
            SinkType::Kafka | SinkType::Nats => true,
            SinkType::Stdout | SinkType::File | SinkType::Memory | SinkType::Tee => false,
        }
    }
}

/// A sink I/O failure tagged with its [`SinkErrorClass`], constructed at the failure site.
///
/// The class travels as data on the error, so DLQ headers and metric attribution read it
/// directly instead of re-deriving it from the message.
#[derive(Debug, thiserror::Error)]
#[error("output sink failed")]
pub struct SinkError {
    pub class: SinkErrorClass,
    #[source]
    pub source: std::io::Error,
}

impl SinkError {
    pub fn new(class: SinkErrorClass, source: std::io::Error) -> Self {
        Self { class, source }
    }

    /// Tag an unclassified I/O failure (connect, partition-client, stream-lookup) as [`SinkErrorClass::Other`].
    pub fn other(source: std::io::Error) -> Self {
        Self::new(SinkErrorClass::Other, source)
    }
}

#[cfg(test)]
pub(crate) fn sink_io_detail(err: &RastreoError) -> String {
    std::error::Error::source(err)
        .expect("a sink error carries its io detail as the source")
        .to_string()
}

#[async_trait::async_trait]
pub trait Sink: Send + Sync {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError>;

    /// Writes a record of the given kind. The default delivers every kind to the single `write`
    /// stream (records self-describe via `schema_id`); sinks with separate second-stream
    /// destinations override to route the non-`Device` kinds there.
    async fn write_kind(&mut self, kind: RecordKind, data: &[u8]) -> Result<(), RastreoError> {
        let _ = kind;
        self.write(data).await
    }

    async fn flush(&mut self) -> Result<(), RastreoError>;

    /// Terminal drain at end-of-stream; default delegates to `flush`. Batching sinks
    /// override only when they need connection-drain beyond a buffer flush.
    async fn close(&mut self) -> Result<(), RastreoError> {
        self.flush().await
    }

    // Default: every write is delivered. Batching sinks override to reflect buffered state.
    fn last_write_delivered(&self) -> bool {
        true
    }

    /// Concrete sink kind — drives DLQ/metric attribution and, through [`Sink::requires_structured_records`], whether an aligned-text encoder may write here.
    fn kind(&self) -> SinkType;

    /// Reads [`SinkType::requires_structured_records`] off `kind()`. Async like [`Sink::probe`],
    /// because a fan-out sink overrides it to consult children held behind an async mutex.
    async fn requires_structured_records(&self) -> bool {
        self.kind().requires_structured_records()
    }

    /// Cumulative count of records delivered to a dead-letter destination.
    ///
    /// Default is `0`; sinks with DLQ support increment the counter only when a
    /// record is successfully accepted by the DLQ (publish AND ack when applicable).
    /// Failures to DLQ do not count.
    fn dlq_records_delivered(&self) -> u64 {
        0
    }

    /// Cumulative DLQ deliveries per [`SinkErrorClass`], indexed by `SinkErrorClass::index()`.
    ///
    /// Default is all-zero — a sink without a DLQ never quarantines a record. Sinks with a
    /// DLQ override to report each delivery under the class of the failure that triggered it.
    fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
        [0; SINK_ERROR_CLASS_COUNT]
    }

    /// DLQ deliveries attributed to `(destination sink type, failure class)`.
    ///
    /// Default derives from `kind()` and `dlq_records_by_class()`. Fan-out sinks that
    /// deliver to children of different protocols override this to preserve per-child
    /// attribution for the DLQ metric.
    fn dlq_records_by_type_and_class(&self) -> Vec<(SinkType, SinkErrorClass, u64)> {
        let kind = self.kind();
        let by_class = self.dlq_records_by_class();
        SinkErrorClass::all()
            .iter()
            .filter_map(|class| {
                let count = by_class[class.index()];
                (count > 0).then_some((kind, *class, count))
            })
            .collect()
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

/// Where discovered records are sent (stdout, file, Kafka, NATS).
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
        /// Topic the `Link` record stream is produced to; defaults to `rastreo.discovery.links.v1`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        links_topic: Option<String>,
        /// Topic the collection-profile stream is produced to; defaults to `rastreo.discovery.profiles.v1`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profiles_topic: Option<String>,
        #[serde(default)]
        flush_mode: KafkaFlushMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dead_letter: Option<DeadLetterConfig>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls: Option<KafkaTls>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sasl: Option<KafkaSasl>,
        #[serde(default)]
        retry: SinkRetry,
    },
    #[cfg(feature = "nats")]
    Nats {
        servers: Vec<String>,
        subject: String,
        stream: String,
        /// Subject the `Link` record stream is published to; defaults to `rastreo.discovery.links.v1`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        links_subject: Option<String>,
        /// Subject the collection-profile stream is published to; defaults to `rastreo.discovery.profiles.v1`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profiles_subject: Option<String>,
        #[serde(default)]
        credentials: NatsCredentials,
        #[serde(default)]
        flush_mode: NatsFlushMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dead_letter: Option<NatsDeadLetterConfig>,
        #[serde(default)]
        retry: SinkRetry,
    },
}

impl SinkConfig {
    /// Whether a scan writing to this sink can be resumed from a checkpoint: `true` for durable
    /// append destinations (`File`/`Kafka`/`Nats`), `false` for `Stdout`/`Memory`.
    pub fn supports_resume(&self) -> bool {
        match self {
            SinkConfig::File { .. } => true,
            #[cfg(feature = "kafka")]
            SinkConfig::Kafka { .. } => true,
            #[cfg(feature = "nats")]
            SinkConfig::Nats { .. } => true,
            SinkConfig::Stdout | SinkConfig::Memory => false,
        }
    }

    /// The [`SinkType`] this config builds.
    pub fn sink_type(&self) -> SinkType {
        match self {
            SinkConfig::Stdout => SinkType::Stdout,
            SinkConfig::File { .. } => SinkType::File,
            SinkConfig::Memory => SinkType::Memory,
            #[cfg(feature = "kafka")]
            SinkConfig::Kafka { .. } => SinkType::Kafka,
            #[cfg(feature = "nats")]
            SinkConfig::Nats { .. } => SinkType::Nats,
        }
    }

    /// Offline twin of [`Sink::requires_structured_records`], so a config can be checked without
    /// constructing the sink (and, for a broker sink, without dialling it).
    pub fn requires_structured_records(&self) -> bool {
        self.sink_type().requires_structured_records()
    }

    /// Validate the sink configuration offline: no network, no connect, no filesystem access.
    pub fn validate(&self) -> Result<(), RastreoError> {
        match self {
            SinkConfig::Stdout | SinkConfig::File { .. } | SinkConfig::Memory => Ok(()),
            #[cfg(feature = "kafka")]
            SinkConfig::Kafka {
                brokers,
                topic,
                links_topic,
                profiles_topic,
                dead_letter,
                tls,
                sasl,
                ..
            } => {
                if brokers.is_empty() {
                    return Err(ConfigError::invalid("kafka sink: brokers list is empty").into());
                }
                if brokers.iter().any(|b| b.trim().is_empty()) {
                    return Err(ConfigError::invalid(
                        "kafka sink: brokers list contains an empty entry",
                    )
                    .into());
                }
                if topic.trim().is_empty() {
                    return Err(ConfigError::invalid("kafka sink: topic is empty").into());
                }
                if links_topic.as_deref().is_some_and(|t| t.trim().is_empty()) {
                    return Err(ConfigError::invalid("kafka sink: links_topic is empty").into());
                }
                if profiles_topic
                    .as_deref()
                    .is_some_and(|t| t.trim().is_empty())
                {
                    return Err(ConfigError::invalid("kafka sink: profiles_topic is empty").into());
                }
                if let Some(tls) = tls {
                    tls.validate()?;
                }
                if let Some(sasl) = sasl {
                    sasl.validate()?;
                }
                if let Some(dead_letter) = dead_letter {
                    dead_letter.validate()?;
                }
                Ok(())
            }
            #[cfg(feature = "nats")]
            SinkConfig::Nats {
                servers,
                subject,
                links_subject,
                profiles_subject,
                stream,
                dead_letter,
                ..
            } => {
                if servers.is_empty() {
                    return Err(ConfigError::invalid("nats sink: servers list is empty").into());
                }
                if servers.iter().any(|s| s.trim().is_empty()) {
                    return Err(ConfigError::invalid(
                        "nats sink: servers list contains an empty entry",
                    )
                    .into());
                }
                if subject.trim().is_empty() {
                    return Err(ConfigError::invalid("nats sink: subject is empty").into());
                }
                if links_subject
                    .as_deref()
                    .is_some_and(|s| s.trim().is_empty())
                {
                    return Err(ConfigError::invalid("nats sink: links_subject is empty").into());
                }
                if profiles_subject
                    .as_deref()
                    .is_some_and(|s| s.trim().is_empty())
                {
                    return Err(ConfigError::invalid("nats sink: profiles_subject is empty").into());
                }
                if stream.trim().is_empty() {
                    return Err(ConfigError::invalid("nats sink: stream is empty").into());
                }
                if let Some(dead_letter) = dead_letter {
                    dead_letter.validate()?;
                }
                Ok(())
            }
        }
    }
}

pub async fn create_sink(config: &SinkConfig) -> Result<Box<dyn Sink>, RastreoError> {
    // Validate offline at the config boundary; the constructors below trust a validated config.
    config.validate()?;
    match config {
        SinkConfig::Stdout => Ok(Box::new(StdoutSink::new())),
        SinkConfig::File { path } => Ok(Box::new(FileSink::new(path).await?)),
        SinkConfig::Memory => Ok(Box::new(MemorySink::new())),
        #[cfg(feature = "kafka")]
        SinkConfig::Kafka {
            brokers,
            topic,
            links_topic,
            profiles_topic,
            flush_mode,
            dead_letter,
            tls,
            sasl,
            retry,
        } => {
            let links = links_topic
                .clone()
                .unwrap_or_else(|| DEFAULT_LINKS_DESTINATION.to_string());
            let profiles = profiles_topic
                .clone()
                .unwrap_or_else(|| DEFAULT_PROFILES_DESTINATION.to_string());
            let mut sink =
                KafkaSink::new(brokers.clone(), topic.clone(), tls.clone(), sasl.clone()).await?;
            sink = sink.with_links_topic(links);
            sink = sink.with_profiles_topic(profiles);
            sink = sink.with_flush_mode(flush_mode.clone());
            sink = sink.with_retry(retry.clone());
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
            links_subject,
            profiles_subject,
            credentials,
            flush_mode,
            dead_letter,
            retry,
        } => {
            let links = links_subject
                .clone()
                .unwrap_or_else(|| DEFAULT_LINKS_DESTINATION.to_string());
            let profiles = profiles_subject
                .clone()
                .unwrap_or_else(|| DEFAULT_PROFILES_DESTINATION.to_string());
            let mut sink = NatsSink::new(
                servers.clone(),
                subject.clone(),
                stream.clone(),
                credentials.clone(),
            )
            .await?;
            sink = sink.with_links_subject(links);
            sink = sink.with_profiles_subject(profiles);
            sink = sink.with_flush_mode(flush_mode.clone());
            sink = sink.with_retry(retry.clone());
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
        flushes: usize,
    }

    impl MockSink {
        fn new() -> Self {
            Self {
                buffer: Vec::new(),
                flushes: 0,
            }
        }
    }

    #[async_trait::async_trait]
    impl Sink for MockSink {
        async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
            self.buffer.extend_from_slice(data);
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.flushes += 1;
            Ok(())
        }

        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    #[test]
    fn default_last_write_delivered_is_true() {
        let s: Box<dyn Sink> = Box::new(MockSink::new());
        assert!(s.last_write_delivered());
    }

    #[tokio::test]
    async fn default_write_kind_delivers_every_kind_to_the_single_write_stream() {
        let mut sink = MockSink::new();
        sink.write_kind(RecordKind::Device, b"device\n")
            .await
            .expect("device");
        sink.write_kind(RecordKind::Link, b"link\n")
            .await
            .expect("link");
        assert_eq!(
            sink.buffer, b"device\nlink\n",
            "the default routes both kinds to one interleaved stream"
        );
    }

    #[tokio::test]
    async fn routing_sink_splits_each_kind_to_its_own_destination() {
        // Models the Kafka / NATS contract: override write_kind to split the three streams.
        #[derive(Default)]
        struct RoutingSink {
            device_stream: Vec<u8>,
            link_stream: Vec<u8>,
            profile_stream: Vec<u8>,
        }
        #[async_trait::async_trait]
        impl Sink for RoutingSink {
            async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
                self.device_stream.extend_from_slice(data);
                Ok(())
            }
            async fn write_kind(
                &mut self,
                kind: RecordKind,
                data: &[u8],
            ) -> Result<(), RastreoError> {
                match kind {
                    RecordKind::Device => self.write(data).await,
                    RecordKind::Link => {
                        self.link_stream.extend_from_slice(data);
                        Ok(())
                    }
                    RecordKind::CollectionProfile => {
                        self.profile_stream.extend_from_slice(data);
                        Ok(())
                    }
                }
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn kind(&self) -> SinkType {
                SinkType::Kafka
            }
        }

        let mut sink = RoutingSink::default();
        sink.write_kind(RecordKind::Device, b"device\n")
            .await
            .expect("device");
        sink.write(b"device2\n").await.expect("device via write");
        sink.write_kind(RecordKind::Link, b"link\n")
            .await
            .expect("link");
        sink.write_kind(RecordKind::CollectionProfile, b"profile\n")
            .await
            .expect("profile");
        assert_eq!(sink.device_stream, b"device\ndevice2\n");
        assert_eq!(sink.link_stream, b"link\n");
        assert_eq!(sink.profile_stream, b"profile\n");
    }

    #[tokio::test]
    async fn default_close_delegates_to_flush() {
        let mut s = MockSink::new();
        s.close().await.expect("close");
        assert_eq!(s.flushes, 1, "default close must call flush exactly once");
    }

    #[test]
    fn default_dlq_records_delivered_is_zero() {
        let s: Box<dyn Sink> = Box::new(MockSink::new());
        assert_eq!(s.dlq_records_delivered(), 0);
    }

    #[tokio::test]
    async fn default_probe_reports_reachable() {
        let s: Box<dyn Sink> = Box::new(MockSink::new());
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
    fn sink_error_carries_the_class_it_was_constructed_with() {
        let err = SinkError::new(
            SinkErrorClass::AckRejection,
            std::io::Error::other("rejected"),
        );
        assert_eq!(err.class, SinkErrorClass::AckRejection);
    }

    #[test]
    fn sink_error_other_tags_unclassified_io_as_other() {
        let err = SinkError::other(std::io::Error::other("connect refused"));
        assert_eq!(err.class, SinkErrorClass::Other);
    }

    #[test]
    fn sink_error_display_names_the_sink_and_sources_the_io_message() {
        let err = SinkError::new(
            SinkErrorClass::WriteFailure,
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broke"),
        );
        assert_eq!(err.to_string(), "output sink failed");
        assert_eq!(sink_io_detail(&err.into()), "pipe broke");
    }

    #[test]
    fn dlq_records_by_type_and_class_default_derives_from_kind_and_class_counts() {
        struct KafkaLike(u64);
        #[async_trait::async_trait]
        impl Sink for KafkaLike {
            async fn write(&mut self, _: &[u8]) -> Result<(), RastreoError> {
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn kind(&self) -> SinkType {
                SinkType::Kafka
            }
            fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
                let mut out = [0; SINK_ERROR_CLASS_COUNT];
                out[SinkErrorClass::ProduceFailure.index()] = self.0;
                out
            }
        }
        let sink = KafkaLike(4);
        assert_eq!(
            sink.dlq_records_by_type_and_class(),
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 4)]
        );
    }

    #[test]
    fn dlq_records_by_type_and_class_default_is_empty_without_dlq() {
        struct Plain;
        #[async_trait::async_trait]
        impl Sink for Plain {
            async fn write(&mut self, _: &[u8]) -> Result<(), RastreoError> {
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn kind(&self) -> SinkType {
                SinkType::Memory
            }
        }
        assert!(Plain.dlq_records_by_type_and_class().is_empty());
    }

    #[tokio::test]
    async fn dlq_by_class_totals_sum_to_the_scalar_delivered_count() {
        struct DlqCountingSink {
            class: SinkErrorClass,
            delivered: u64,
            by_class: [u64; SINK_ERROR_CLASS_COUNT],
        }

        #[async_trait::async_trait]
        impl Sink for DlqCountingSink {
            async fn write(&mut self, _: &[u8]) -> Result<(), RastreoError> {
                self.delivered += 1;
                self.by_class[self.class.index()] += 1;
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn kind(&self) -> SinkType {
                SinkType::Kafka
            }
            fn dlq_records_delivered(&self) -> u64 {
                self.delivered
            }
            fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
                self.by_class
            }
        }

        let mut family: Vec<Box<dyn Sink>> = vec![Box::new(MockSink::new())];
        for class in [
            SinkErrorClass::ProduceFailure,
            SinkErrorClass::AckRejection,
            SinkErrorClass::WriteFailure,
        ] {
            let mut sink = DlqCountingSink {
                class,
                delivered: 0,
                by_class: [0; SINK_ERROR_CLASS_COUNT],
            };
            for _ in 0..3 {
                sink.write(b"quarantined").await.expect("write");
            }
            family.push(Box::new(sink));
        }

        for (i, sink) in family.iter().enumerate() {
            assert_eq!(
                sink.dlq_records_by_class().iter().sum::<u64>(),
                sink.dlq_records_delivered(),
                "sink {i}: by_class sum must equal the scalar delivered total"
            );
        }
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
                links_topic,
                profiles_topic,
                flush_mode,
                dead_letter,
                tls,
                sasl,
                retry,
            } => {
                assert_eq!(brokers, vec!["k:9092".to_string()]);
                assert_eq!(topic, "t");
                assert!(links_topic.is_none());
                assert!(profiles_topic.is_none());
                assert!(matches!(flush_mode, KafkaFlushMode::PerRecord));
                assert!(dead_letter.is_none());
                assert!(tls.is_none());
                assert!(sasl.is_none());
                assert_eq!(retry, SinkRetry::default());
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
                links_subject,
                profiles_subject,
                credentials,
                flush_mode,
                dead_letter,
                retry,
            } => {
                assert_eq!(servers, vec!["nats://nats:4222".to_string()]);
                assert_eq!(subject, "rastreo.discovery.records.v1");
                assert_eq!(stream, "rastreo");
                assert!(links_subject.is_none());
                assert!(profiles_subject.is_none());
                assert!(matches!(credentials, NatsCredentials::Anonymous));
                assert!(matches!(flush_mode, NatsFlushMode::PerRecord));
                assert!(dead_letter.is_none());
                assert_eq!(retry, SinkRetry::default());
            }
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn deserialize_nats_sink_config_with_user_pass_credentials() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\ncredentials:\n  type: user_pass\n  username: admin\n  password: sekret\n";
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
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\ncredentials:\n  type: token\n  token: tok\n";
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
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\ncredentials:\n  type: creds\n  creds_file: /etc/rastreo/nats.creds\n";
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
    fn deserialize_nats_sink_config_with_batched_flush_mode() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\nflush_mode:\n  type: batched\n  threshold_bytes: 4096\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { flush_mode, .. } => match flush_mode {
                NatsFlushMode::Batched { threshold_bytes } => assert_eq!(threshold_bytes, 4096),
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

    #[cfg(all(feature = "config", feature = "kafka"))]
    #[test]
    fn sink_config_kafka_absent_retry_deserializes_as_default() {
        let yaml = "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka { retry, .. } => assert_eq!(retry, SinkRetry::default()),
            other => panic!("expected Kafka, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "kafka"))]
    #[test]
    fn sink_config_kafka_parses_explicit_retry() {
        let yaml = "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\nretry:\n  max_attempts: 5\n  backoff_initial_ms: 50\n  backoff_max_ms: 500\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka { retry, .. } => {
                assert_eq!(retry.max_attempts, 5);
                assert_eq!(retry.backoff_initial_ms, 50);
                assert_eq!(retry.backoff_max_ms, 500);
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "kafka"))]
    #[test]
    fn sink_config_kafka_partial_retry_fills_remaining_fields_with_defaults() {
        let yaml = "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\nretry:\n  max_attempts: 1\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka { retry, .. } => {
                assert_eq!(retry.max_attempts, 1);
                assert_eq!(retry.backoff_initial_ms, 100);
                assert_eq!(retry.backoff_max_ms, 2000);
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn sink_config_nats_absent_retry_deserializes_as_default() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { retry, .. } => assert_eq!(retry, SinkRetry::default()),
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[cfg(all(feature = "config", feature = "nats"))]
    #[test]
    fn sink_config_nats_parses_explicit_retry() {
        let yaml = "type: nats\nservers: [\"nats://n:4222\"]\nsubject: s\nstream: st\nretry:\n  max_attempts: 5\n  backoff_initial_ms: 50\n  backoff_max_ms: 500\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize nats");
        match config {
            SinkConfig::Nats { retry, .. } => {
                assert_eq!(retry.max_attempts, 5);
                assert_eq!(retry.backoff_initial_ms, 50);
                assert_eq!(retry.backoff_max_ms, 500);
            }
            other => panic!("expected Nats, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn default_sink_does_not_require_structured_records() {
        let s: Box<dyn Sink> = Box::new(MockSink::new());
        assert!(!s.requires_structured_records().await);
    }

    struct KindOnlySink(SinkType);

    #[async_trait::async_trait]
    impl Sink for KindOnlySink {
        async fn write(&mut self, _: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn kind(&self) -> SinkType {
            self.0
        }
    }

    #[tokio::test]
    async fn the_trait_default_reads_structuredness_off_the_sink_kind() {
        let s: Box<dyn Sink> = Box::new(KindOnlySink(SinkType::Kafka));
        assert!(s.requires_structured_records().await);
        let s: Box<dyn Sink> = Box::new(KindOnlySink(SinkType::Stdout));
        assert!(!s.requires_structured_records().await);
    }

    #[tokio::test]
    async fn every_constructible_sink_config_agrees_with_the_sink_it_builds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let constructible: Vec<SinkConfig> = vec![
            SinkConfig::Stdout,
            SinkConfig::File {
                path: dir.path().join("parity.ndjson"),
            },
            SinkConfig::Memory,
        ];
        for config in &constructible {
            let sink = create_sink(config).await.expect("create");
            assert_eq!(
                config.sink_type(),
                sink.kind(),
                "config and sink disagree on kind for {config:?}"
            );
            assert_eq!(
                config.requires_structured_records(),
                sink.requires_structured_records().await,
                "config and sink disagree for {config:?}"
            );
        }
    }

    #[test]
    fn broker_sink_types_require_structured_records() {
        assert!(SinkType::Kafka.requires_structured_records());
        assert!(SinkType::Nats.requires_structured_records());
    }

    #[test]
    fn local_sink_types_do_not_require_structured_records() {
        for kind in [
            SinkType::Stdout,
            SinkType::File,
            SinkType::Memory,
            SinkType::Tee,
        ] {
            assert!(!kind.requires_structured_records(), "{kind:?}");
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn kafka_sink_config_requires_structured_records() {
        let config = kafka_config(vec!["kafka:9092"], "t");
        assert_eq!(config.sink_type(), SinkType::Kafka);
        assert!(config.requires_structured_records());
    }

    #[cfg(feature = "nats")]
    #[test]
    fn nats_sink_config_requires_structured_records() {
        let config = nats_config(vec!["nats://n:4222"], "s", "st");
        assert_eq!(config.sink_type(), SinkType::Nats);
        assert!(config.requires_structured_records());
    }

    #[test]
    fn local_sink_configs_do_not_require_structured_records() {
        assert!(!SinkConfig::Stdout.requires_structured_records());
        assert!(!SinkConfig::Memory.requires_structured_records());
        assert!(!SinkConfig::File {
            path: PathBuf::from("/tmp/rastreo.ndjson"),
        }
        .requires_structured_records());
    }

    #[test]
    fn supports_resume_true_for_file_sink() {
        assert!(SinkConfig::File {
            path: PathBuf::from("/tmp/rastreo.ndjson"),
        }
        .supports_resume());
    }

    #[test]
    fn supports_resume_false_for_stdout_and_memory() {
        assert!(!SinkConfig::Stdout.supports_resume());
        assert!(!SinkConfig::Memory.supports_resume());
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn supports_resume_true_for_kafka_sink() {
        assert!(kafka_config(vec!["kafka:9092"], "rastreo.devices").supports_resume());
    }

    #[cfg(feature = "nats")]
    #[test]
    fn supports_resume_true_for_nats_sink() {
        assert!(nats_config(vec!["nats://n:4222"], "rastreo.records", "rastreo").supports_resume());
    }

    #[test]
    fn validate_stdout_is_ok() {
        SinkConfig::Stdout
            .validate()
            .expect("stdout is trivially valid");
    }

    #[test]
    fn validate_memory_is_ok() {
        SinkConfig::Memory
            .validate()
            .expect("memory is trivially valid");
    }

    #[test]
    fn validate_file_does_not_touch_the_filesystem() {
        let config = SinkConfig::File {
            path: PathBuf::from("/nonexistent/rastreo/does-not-exist.ndjson"),
        };
        config
            .validate()
            .expect("file config validates without touching disk");
    }

    #[cfg(feature = "kafka")]
    fn kafka_config(brokers: Vec<&str>, topic: &str) -> SinkConfig {
        SinkConfig::Kafka {
            brokers: brokers.into_iter().map(String::from).collect(),
            topic: topic.into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: None,
            retry: SinkRetry::default(),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_valid_config_passes() {
        kafka_config(vec!["kafka:9092"], "rastreo.devices")
            .validate()
            .expect("valid kafka config passes");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_empty_brokers() {
        match kafka_config(vec![], "t").validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("brokers"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_blank_broker_entry() {
        match kafka_config(vec!["kafka:9092", "   "], "t").validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("empty entry"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_empty_topic() {
        match kafka_config(vec!["kafka:9092"], "  ").validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("topic"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_empty_links_topic() {
        let config = SinkConfig::Kafka {
            brokers: vec!["kafka:9092".into()],
            topic: "t".into(),
            links_topic: Some("  ".into()),
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: None,
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("links_topic"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_accepts_present_links_topic() {
        let config = SinkConfig::Kafka {
            brokers: vec!["kafka:9092".into()],
            topic: "t".into(),
            links_topic: Some("rastreo.discovery.links.v1".into()),
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: None,
            retry: SinkRetry::default(),
        };
        config.validate().expect("present links_topic passes");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_empty_profiles_topic() {
        let config = SinkConfig::Kafka {
            brokers: vec!["kafka:9092".into()],
            topic: "t".into(),
            links_topic: None,
            profiles_topic: Some("  ".into()),
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: None,
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("profiles_topic"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_ca_cert_without_verify() {
        let config = SinkConfig::Kafka {
            brokers: vec!["kafka:9092".into()],
            topic: "t".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: Some(KafkaTls {
                verify: false,
                ca_cert: Some("anything".into()),
            }),
            sasl: None,
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("tls.verify: true"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_malformed_ca_pem() {
        let config = SinkConfig::Kafka {
            brokers: vec!["kafka:9092".into()],
            topic: "t".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: Some(KafkaTls {
                verify: true,
                ca_cert: Some("not a certificate".into()),
            }),
            sasl: None,
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("ca_cert"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_empty_sasl_username() {
        let config = SinkConfig::Kafka {
            brokers: vec!["kafka:9092".into()],
            topic: "t".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: Some(KafkaSasl {
                mechanism: SaslMechanism::Plain,
                username: "  ".into(),
                password: crate::prober::Password("pw".into()),
            }),
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("username"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_rejects_empty_dead_letter_topic() {
        let config = SinkConfig::Kafka {
            brokers: vec!["kafka:9092".into()],
            topic: "t".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: Some(DeadLetterConfig {
                topic: "  ".into(),
                include_error_metadata: true,
            }),
            tls: None,
            sasl: None,
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("dead-letter"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn validate_kafka_secured_tls_and_sasl_passes_offline() {
        let config = SinkConfig::Kafka {
            brokers: vec!["kafka:9092".into()],
            topic: "rastreo.devices".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: Some(KafkaTls {
                verify: true,
                ca_cert: None,
            }),
            sasl: Some(KafkaSasl {
                mechanism: SaslMechanism::ScramSha256,
                username: "svc".into(),
                password: crate::prober::Password("pw".into()),
            }),
            retry: SinkRetry::default(),
        };
        config
            .validate()
            .expect("secured kafka config validates offline");
    }

    #[cfg(feature = "kafka")]
    #[tokio::test]
    async fn create_sink_rejects_invalid_kafka_config_before_connecting() {
        // Empty dead-letter topic: validate() rejects it offline before the unreachable broker connect.
        let config = SinkConfig::Kafka {
            brokers: vec!["127.0.0.1:1".into()],
            topic: "rastreo.devices".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: Some(DeadLetterConfig {
                topic: "  ".into(),
                include_error_metadata: true,
            }),
            tls: None,
            sasl: None,
            retry: SinkRetry::default(),
        };
        match create_sink(&config).await {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("dead-letter"), "msg was: {msg}");
            }
            Err(other) => panic!("expected offline ConfigError from validate, got {other:?}"),
            Ok(_) => panic!("expected offline ConfigError from validate, got a sink"),
        }
    }

    #[cfg(feature = "nats")]
    fn nats_config(servers: Vec<&str>, subject: &str, stream: &str) -> SinkConfig {
        SinkConfig::Nats {
            servers: servers.into_iter().map(String::from).collect(),
            subject: subject.into(),
            stream: stream.into(),
            links_subject: None,
            profiles_subject: None,
            credentials: NatsCredentials::Anonymous,
            flush_mode: NatsFlushMode::default(),
            dead_letter: None,
            retry: SinkRetry::default(),
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_valid_config_passes() {
        nats_config(vec!["nats://n:4222"], "rastreo.records", "rastreo")
            .validate()
            .expect("valid nats config passes");
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_rejects_empty_servers() {
        match nats_config(vec![], "s", "st").validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("servers"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_rejects_blank_server_entry() {
        match nats_config(vec!["nats://n:4222", "  "], "s", "st").validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("empty entry"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_rejects_empty_subject() {
        match nats_config(vec!["nats://n:4222"], "  ", "st").validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("subject"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_rejects_empty_stream() {
        match nats_config(vec!["nats://n:4222"], "s", "  ").validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("stream"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_rejects_empty_links_subject() {
        let config = SinkConfig::Nats {
            servers: vec!["nats://n:4222".into()],
            subject: "s".into(),
            stream: "st".into(),
            links_subject: Some("  ".into()),
            profiles_subject: None,
            credentials: NatsCredentials::Anonymous,
            flush_mode: NatsFlushMode::default(),
            dead_letter: None,
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("links_subject"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_accepts_present_links_subject() {
        let config = SinkConfig::Nats {
            servers: vec!["nats://n:4222".into()],
            subject: "s".into(),
            stream: "st".into(),
            links_subject: Some("rastreo.discovery.links.v1".into()),
            profiles_subject: None,
            credentials: NatsCredentials::Anonymous,
            flush_mode: NatsFlushMode::default(),
            dead_letter: None,
            retry: SinkRetry::default(),
        };
        config.validate().expect("present links_subject passes");
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_rejects_empty_profiles_subject() {
        let config = SinkConfig::Nats {
            servers: vec!["nats://n:4222".into()],
            subject: "s".into(),
            stream: "st".into(),
            links_subject: None,
            profiles_subject: Some("  ".into()),
            credentials: NatsCredentials::Anonymous,
            flush_mode: NatsFlushMode::default(),
            dead_letter: None,
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("profiles_subject"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_rejects_empty_dead_letter_stream() {
        let config = SinkConfig::Nats {
            servers: vec!["nats://n:4222".into()],
            subject: "s".into(),
            stream: "st".into(),
            links_subject: None,
            profiles_subject: None,
            credentials: NatsCredentials::Anonymous,
            flush_mode: NatsFlushMode::default(),
            dead_letter: Some(NatsDeadLetterConfig {
                stream: "  ".into(),
                subject: "rastreo.dlq".into(),
                include_error_metadata: true,
            }),
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("stream"), "msg was: {msg}");
                assert!(msg.contains("dead-letter"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn validate_nats_rejects_empty_dead_letter_subject() {
        let config = SinkConfig::Nats {
            servers: vec!["nats://n:4222".into()],
            subject: "s".into(),
            stream: "st".into(),
            links_subject: None,
            profiles_subject: None,
            credentials: NatsCredentials::Anonymous,
            flush_mode: NatsFlushMode::default(),
            dead_letter: Some(NatsDeadLetterConfig {
                stream: "dlq-stream".into(),
                subject: "  ".into(),
                include_error_metadata: true,
            }),
            retry: SinkRetry::default(),
        };
        match config.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("subject"), "msg was: {msg}");
                assert!(msg.contains("dead-letter"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }
}
