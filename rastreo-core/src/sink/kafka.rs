use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use rskafka::{
    client::{
        partition::{Compression, OffsetAt, PartitionClient, UnknownTopicHandling},
        ClientBuilder, Credentials, SaslConfig,
    },
    record::Record,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};

use crate::error::{ConfigError, RastreoError};
use crate::prober::Password;
use crate::sink::{
    retry_with_backoff, RecordKind, Sink, SinkError, SinkErrorClass, SinkRetry, SinkType,
    DEFAULT_LINKS_DESTINATION, DEFAULT_PROFILES_DESTINATION, SINK_ERROR_CLASS_COUNT,
};

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

/// TLS for the Kafka producer; `verify` defaults to `false` (accept any certificate), mirroring the probers' permissive default.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct KafkaTls {
    #[serde(default)]
    pub verify: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SaslMechanism {
    Plain,
    #[serde(rename = "scram_sha_256")]
    ScramSha256,
    #[serde(rename = "scram_sha_512")]
    ScramSha512,
}

/// SASL credentials for the Kafka producer; composes independently with `KafkaTls`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct KafkaSasl {
    pub mechanism: SaslMechanism,
    pub username: String,
    pub password: Password,
}

impl KafkaSasl {
    pub(crate) fn validate(&self) -> Result<(), RastreoError> {
        if self.username.trim().is_empty() {
            return Err(ConfigError::invalid("kafka sink: sasl username is empty").into());
        }
        Ok(())
    }

    // rskafka's SaslConfig/Credentials hold the plaintext password and are NOT redacted; keep them transient (never store on KafkaSink, never Debug-log) — redaction lives on KafkaSasl.
    fn to_sasl_config(&self) -> SaslConfig {
        let credentials =
            Credentials::new(self.username.clone(), self.password.expose().to_string());
        match self.mechanism {
            SaslMechanism::Plain => SaslConfig::Plain(credentials),
            SaslMechanism::ScramSha256 => SaslConfig::ScramSha256(credentials),
            SaslMechanism::ScramSha512 => SaslConfig::ScramSha512(credentials),
        }
    }
}

#[derive(Debug)]
struct AcceptAnyVerifier;

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

impl KafkaTls {
    pub(crate) fn validate(&self) -> Result<(), RastreoError> {
        // Reject the footgun: a ca_cert with verify:false would silently accept any certificate.
        if !self.verify && self.ca_cert.is_some() {
            return Err(
                ConfigError::invalid("kafka sink: tls.ca_cert requires tls.verify: true").into(),
            );
        }
        if let Some(ca_pem) = &self.ca_cert {
            parse_ca_certs(ca_pem)?;
        }
        Ok(())
    }

    fn build_client_config(&self) -> Result<Arc<ClientConfig>, RastreoError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports rustls default protocol versions");

        let config = if self.verify {
            let mut roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            if let Some(ca_pem) = &self.ca_cert {
                let (added, _ignored) = roots.add_parsable_certificates(parse_ca_certs(ca_pem)?);
                if added == 0 {
                    return Err(ConfigError::invalid(
                        "kafka sink: tls.ca_cert contained no usable certificate",
                    )
                    .into());
                }
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            // Accept any server certificate: reach lab / self-signed brokers the way the probers do.
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
                .with_no_client_auth()
        };
        Ok(Arc::new(config))
    }
}

fn parse_ca_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, RastreoError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            ConfigError::invalid(format!("kafka sink: tls.ca_cert is not valid PEM: {e}"))
        })?;
    if certs.is_empty() {
        return Err(
            ConfigError::invalid("kafka sink: tls.ca_cert contained no certificate").into(),
        );
    }
    Ok(certs)
}

fn configure_client_builder(
    brokers: Vec<String>,
    tls_config: Option<&Arc<ClientConfig>>,
    sasl: Option<&KafkaSasl>,
) -> ClientBuilder {
    let mut builder = ClientBuilder::new(brokers);
    if let Some(tls) = tls_config {
        builder = builder.tls_config(Arc::clone(tls));
    }
    if let Some(sasl) = sasl {
        builder = builder.sasl_config(sasl.to_sasl_config());
    }
    builder
}

async fn connect_partition_client(
    brokers: &[String],
    topic: &str,
    tls_config: Option<&Arc<ClientConfig>>,
    sasl: Option<&KafkaSasl>,
) -> Result<PartitionClient, RastreoError> {
    let brokers_for_err = brokers.join(",");
    let kafka_client = configure_client_builder(brokers.to_vec(), tls_config, sasl)
        .build()
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("kafka sink: failed to connect to broker(s) '{brokers_for_err}': {e}"),
            )
        })
        .map_err(SinkError::other)?;

    // Single-partition: always produces to partition 0.
    let client = kafka_client
        .partition_client(topic.to_string(), 0, UnknownTopicHandling::Retry)
        .await
        .map_err(|e| {
            io::Error::other(format!(
                "kafka sink: failed to get partition client for topic '{topic}' at broker(s) '{brokers_for_err}': {e}"
            ))
        })
        .map_err(SinkError::other)?;
    Ok(client)
}

const HEADER_SOURCE_TOPIC: &str = "x-rastreo-source-topic";
const HEADER_ERROR_CLASS: &str = "x-rastreo-error-class";
const HEADER_DLQ_TIMESTAMP: &str = "x-rastreo-dlq-timestamp";

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
    tls_config: Option<Arc<ClientConfig>>,
    sasl: Option<KafkaSasl>,
    retry: SinkRetry,
    links_topic: String,
    // Lazily connected on the first link write: a scan with no LLDP data never opens it.
    links_client: Option<PartitionClient>,
    links_buffer: Vec<Vec<u8>>,
    links_buffered_bytes: usize,
    profiles_topic: String,
    // Lazily connected on the first profile write: a scan with no gNMI capability data never opens it.
    profiles_client: Option<PartitionClient>,
    profiles_buffer: Vec<Vec<u8>>,
    profiles_buffered_bytes: usize,
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
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

fn build_produce_error(
    topic: &str,
    brokers: &[String],
    err: rskafka::client::error::Error,
) -> RastreoError {
    let brokers_for_err = brokers.join(",");
    RastreoError::Sink(SinkError::new(
        SinkErrorClass::ProduceFailure,
        io::Error::other(format!(
            "kafka sink: failed to produce record to topic '{topic}' at broker(s) '{brokers_for_err}': {err}"
        )),
    ))
}

/// Envelope headers follow the `x-<vendor>-<name>` convention so downstream
/// consumers can filter DLQ records without inspecting the payload. `error_class`
/// is the class of the failure that quarantined the record.
fn build_dlq_headers(source_topic: &str, error_class: SinkErrorClass) -> BTreeMap<String, Vec<u8>> {
    let mut headers = BTreeMap::new();
    headers.insert(
        HEADER_SOURCE_TOPIC.to_string(),
        source_topic.as_bytes().to_vec(),
    );
    headers.insert(
        HEADER_ERROR_CLASS.to_string(),
        error_class.as_label().as_bytes().to_vec(),
    );
    headers.insert(
        HEADER_DLQ_TIMESTAMP.to_string(),
        Utc::now().to_rfc3339().into_bytes(),
    );
    headers
}

impl KafkaSink {
    pub const DEFAULT_BUFFER_THRESHOLD: usize = 64 * 1024;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Assumes a config already validated by `create_sink`; does not re-validate before connecting.
    pub async fn new(
        brokers: Vec<String>,
        topic: String,
        tls: Option<KafkaTls>,
        sasl: Option<KafkaSasl>,
    ) -> Result<Self, RastreoError> {
        Self::new_with_connect_timeout(brokers, topic, tls, sasl, Self::CONNECT_TIMEOUT).await
    }

    async fn new_with_connect_timeout(
        brokers: Vec<String>,
        topic: String,
        tls: Option<KafkaTls>,
        sasl: Option<KafkaSasl>,
        connect_timeout: Duration,
    ) -> Result<Self, RastreoError> {
        let tls_config = match &tls {
            Some(tls) => Some(tls.build_client_config()?),
            None => None,
        };

        let brokers_for_err = brokers.join(",");

        // Bound the whole connect: a black-hole broker never completes the handshake and would hang forever.
        let connect =
            connect_partition_client(&brokers, &topic, tls_config.as_ref(), sasl.as_ref());
        let client = tokio::time::timeout(connect_timeout, connect)
            .await
            .map_err(|_elapsed| {
                SinkError::other(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "kafka sink: connecting to broker(s) '{brokers_for_err}' timed out after {}s",
                        connect_timeout.as_secs()
                    ),
                ))
            })??;

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
            tls_config,
            sasl,
            retry: SinkRetry::default(),
            links_topic: DEFAULT_LINKS_DESTINATION.to_string(),
            links_client: None,
            links_buffer: Vec::new(),
            links_buffered_bytes: 0,
            profiles_topic: DEFAULT_PROFILES_DESTINATION.to_string(),
            profiles_client: None,
            profiles_buffer: Vec::new(),
            profiles_buffered_bytes: 0,
        })
    }

    pub fn with_flush_mode(mut self, mode: KafkaFlushMode) -> Self {
        self.buffer_threshold = mode.to_threshold();
        self
    }

    pub fn with_links_topic(mut self, topic: String) -> Self {
        self.links_topic = topic;
        self
    }

    pub fn with_profiles_topic(mut self, topic: String) -> Self {
        self.profiles_topic = topic;
        self
    }

    pub fn with_retry(mut self, retry: SinkRetry) -> Self {
        self.retry = retry;
        self
    }

    pub async fn with_dead_letter(
        mut self,
        config: DeadLetterConfig,
    ) -> Result<Self, RastreoError> {
        config.validate()?;

        let brokers_for_err = self.brokers.join(",");
        let dlq_topic = config.topic.clone();

        let connect = connect_partition_client(
            &self.brokers,
            &dlq_topic,
            self.tls_config.as_ref(),
            self.sasl.as_ref(),
        );
        let dlq_client = tokio::time::timeout(Self::CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_elapsed| {
                SinkError::other(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "kafka sink: connecting to broker(s) '{brokers_for_err}' for dead-letter topic '{dlq_topic}' timed out after {}s",
                        Self::CONNECT_TIMEOUT.as_secs()
                    ),
                ))
            })??;

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
        let timestamp = Utc::now();

        // Retry the primary produce before the DLQ: a transient blip that clears within
        // the attempt budget is delivered to the primary and never quarantined.
        let primary_result = {
            let client = &self.client;
            let buffer = &self.buffer;
            let topic = &self.topic;
            let brokers = &self.brokers;
            retry_with_backoff(&self.retry, || async move {
                // One Record per entry: N entries produce N individually-consumable messages in one round-trip.
                let records = build_records(buffer, &BTreeMap::new(), timestamp);
                client
                    .produce(records, Compression::NoCompression)
                    .await
                    .map(|_| ())
                    .map_err(|e| build_produce_error(topic, brokers, e))
            })
            .await
        };

        let primary_err = match primary_result {
            Ok(()) => {
                self.clear_buffer();
                return Ok(());
            }
            Err(e) => e,
        };

        let (Some(dlq_client), Some(dlq_topic)) =
            (self.dlq_client.as_ref(), self.dlq_topic.as_ref())
        else {
            return Err(primary_err);
        };

        tracing::warn!(
            topic = self.topic.as_str(),
            dlq_topic = dlq_topic.as_str(),
            error = %primary_err,
            records = record_count,
            "kafka sink: primary produce failed; shipping records to DLQ",
        );

        let dlq_headers = if self.include_error_metadata {
            build_dlq_headers(&self.topic, SinkErrorClass::ProduceFailure)
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
                Err(primary_err)
            }
        }
    }

    async fn write_link(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.last_write_delivered = false;
        if self.links_client.is_none() {
            let client = connect_partition_client(
                &self.brokers,
                &self.links_topic,
                self.tls_config.as_ref(),
                self.sasl.as_ref(),
            )
            .await?;
            self.links_client = Some(client);
        }
        buffer_record(&mut self.links_buffer, &mut self.links_buffered_bytes, data);
        if should_flush_after_append(self.links_buffered_bytes, self.buffer_threshold) {
            self.publish_links_buffer().await?;
            self.last_write_delivered = true;
        }
        Ok(())
    }

    async fn publish_links_buffer(&mut self) -> Result<(), RastreoError> {
        if self.links_buffer.is_empty() {
            return Ok(());
        }
        // A buffered record with no client would leave flush claiming delivery it never made.
        debug_assert!(self.links_client.is_some());
        let Some(client) = self.links_client.as_ref() else {
            return Ok(());
        };
        let timestamp = Utc::now();
        let result = {
            let buffer = &self.links_buffer;
            let topic = &self.links_topic;
            let brokers = &self.brokers;
            retry_with_backoff(&self.retry, || async move {
                let records = build_records(buffer, &BTreeMap::new(), timestamp);
                client
                    .produce(records, Compression::NoCompression)
                    .await
                    .map(|_| ())
                    .map_err(|e| build_produce_error(topic, brokers, e))
            })
            .await
        };
        result?;
        self.links_buffer.clear();
        self.links_buffered_bytes = 0;
        Ok(())
    }

    async fn write_profile(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.last_write_delivered = false;
        if self.profiles_client.is_none() {
            let client = connect_partition_client(
                &self.brokers,
                &self.profiles_topic,
                self.tls_config.as_ref(),
                self.sasl.as_ref(),
            )
            .await?;
            self.profiles_client = Some(client);
        }
        buffer_record(
            &mut self.profiles_buffer,
            &mut self.profiles_buffered_bytes,
            data,
        );
        if should_flush_after_append(self.profiles_buffered_bytes, self.buffer_threshold) {
            self.publish_profiles_buffer().await?;
            self.last_write_delivered = true;
        }
        Ok(())
    }

    async fn publish_profiles_buffer(&mut self) -> Result<(), RastreoError> {
        if self.profiles_buffer.is_empty() {
            return Ok(());
        }
        // A buffered record with no client would leave flush claiming delivery it never made.
        debug_assert!(self.profiles_client.is_some());
        let Some(client) = self.profiles_client.as_ref() else {
            return Ok(());
        };
        let timestamp = Utc::now();
        let result = {
            let buffer = &self.profiles_buffer;
            let topic = &self.profiles_topic;
            let brokers = &self.brokers;
            retry_with_backoff(&self.retry, || async move {
                let records = build_records(buffer, &BTreeMap::new(), timestamp);
                client
                    .produce(records, Compression::NoCompression)
                    .await
                    .map(|_| ())
                    .map_err(|e| build_produce_error(topic, brokers, e))
            })
            .await
        };
        result?;
        self.profiles_buffer.clear();
        self.profiles_buffered_bytes = 0;
        Ok(())
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

    async fn write_kind(&mut self, kind: RecordKind, data: &[u8]) -> Result<(), RastreoError> {
        match kind {
            RecordKind::Device => self.write(data).await,
            RecordKind::Link => self.write_link(data).await,
            RecordKind::CollectionProfile => self.write_profile(data).await,
        }
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        self.publish_buffer().await?;
        self.publish_links_buffer().await?;
        self.publish_profiles_buffer().await?;
        self.last_write_delivered = true;
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

    fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
        // Kafka only quarantines on a primary produce failure.
        let mut out = [0u64; SINK_ERROR_CLASS_COUNT];
        out[SinkErrorClass::ProduceFailure.index()] = self.dlq_delivered.load(Ordering::Relaxed);
        out
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
    use crate::sink::sink_io_detail;

    #[test]
    fn default_buffer_threshold_is_64_kib() {
        assert_eq!(KafkaSink::DEFAULT_BUFFER_THRESHOLD, 64 * 1024);
    }

    #[tokio::test]
    async fn new_with_connect_timeout_bounds_a_black_hole_broker() {
        use std::time::Instant;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();

        // Accept the TCP connection but never speak Kafka: the handshake read hangs forever.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });

        let start = Instant::now();
        let result = KafkaSink::new_with_connect_timeout(
            vec![addr],
            "t".into(),
            None,
            None,
            Duration::from_secs(1),
        )
        .await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "black-hole broker must fail, not hang");
        assert!(
            elapsed < Duration::from_secs(5),
            "connect must be bounded; took {elapsed:?}"
        );
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
        let headers = build_dlq_headers("rastreo.devices", SinkErrorClass::ProduceFailure);
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
                links_topic,
                profiles_topic,
                flush_mode,
                dead_letter,
                tls,
                sasl,
                retry,
            } => {
                assert_eq!(brokers, vec!["kafka:9092".to_string()]);
                assert_eq!(topic, "rastreo.devices");
                assert!(links_topic.is_none());
                assert!(profiles_topic.is_none());
                assert!(dead_letter.is_none());
                assert!(tls.is_none());
                assert!(sasl.is_none());
                assert_eq!(retry, SinkRetry::default());
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
        let headers = build_dlq_headers("rastreo.devices", SinkErrorClass::ProduceFailure);
        assert!(headers.contains_key(HEADER_SOURCE_TOPIC));
        assert!(headers.contains_key(HEADER_ERROR_CLASS));
        assert!(headers.contains_key(HEADER_DLQ_TIMESTAMP));
        for value in headers.values() {
            assert!(!value.is_empty(), "header value must be non-empty");
        }
    }

    #[test]
    fn build_dlq_headers_source_topic_matches_input() {
        let headers = build_dlq_headers("rastreo.devices", SinkErrorClass::ProduceFailure);
        let value = headers
            .get(HEADER_SOURCE_TOPIC)
            .expect("source-topic header present");
        assert_eq!(
            std::str::from_utf8(value).expect("utf-8"),
            "rastreo.devices"
        );
    }

    #[test]
    fn build_dlq_headers_error_class_renders_carried_class_label() {
        let headers = build_dlq_headers("rastreo.devices", SinkErrorClass::ProduceFailure);
        let value = headers
            .get(HEADER_ERROR_CLASS)
            .expect("error-class header present");
        assert_eq!(
            std::str::from_utf8(value).expect("utf-8"),
            "produce_failure"
        );
    }

    #[ignore = "requires a live Kafka broker; exercised in Live Infra UAT"]
    #[tokio::test]
    async fn probe_reports_reachable_against_live_broker() {
        let sink = KafkaSink::new(
            vec!["localhost:9092".into()],
            "rastreo.probe".into(),
            None,
            None,
        )
        .await
        .expect("connect to live broker");
        <KafkaSink as Sink>::probe(&sink).await.expect("probe");
    }

    #[ignore = "requires a live Kafka broker with primary + DLQ topics; exercised in Live Infra UAT"]
    #[tokio::test]
    async fn probe_returns_ok_when_primary_and_dlq_both_reachable() {
        let sink = KafkaSink::new(
            vec!["localhost:9092".into()],
            "rastreo.probe".into(),
            None,
            None,
        )
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
        let sink = KafkaSink::new(
            vec!["localhost:9092".into()],
            "rastreo.probe".into(),
            None,
            None,
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
            None,
            None,
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
        let headers = build_dlq_headers("rastreo.devices", SinkErrorClass::ProduceFailure);
        let value = headers
            .get(HEADER_DLQ_TIMESTAMP)
            .expect("timestamp header present");
        let ts = std::str::from_utf8(value).expect("utf-8");
        chrono::DateTime::parse_from_rfc3339(ts).expect("valid rfc3339 timestamp");
    }

    #[test]
    fn produce_error_carries_produce_failure_class() {
        let err = build_produce_error(
            "rastreo.devices",
            &["b:9092".to_string()],
            rskafka::client::error::Error::InvalidResponse("boom".to_string()),
        );
        assert_eq!(err.sink_error_class(), Some(SinkErrorClass::ProduceFailure));
        assert!(sink_io_detail(&err).contains("failed to produce"));
    }

    fn sample_ca_pem() -> String {
        use rcgen::{CertificateParams, DnType, KeyPair};
        let key_pair = KeyPair::generate().expect("keypair");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "rastreo-test-ca".to_string());
        params.self_signed(&key_pair).expect("self-sign").pem()
    }

    #[test]
    fn tls_config_verify_false_builds_accept_any() {
        let tls = KafkaTls {
            verify: false,
            ca_cert: None,
        };
        tls.build_client_config()
            .expect("accept-any config must build");
    }

    #[test]
    fn tls_config_verify_true_builds_against_webpki_roots() {
        let tls = KafkaTls {
            verify: true,
            ca_cert: None,
        };
        tls.build_client_config()
            .expect("webpki-roots config must build");
    }

    #[test]
    fn tls_config_verify_true_accepts_a_custom_ca() {
        let tls = KafkaTls {
            verify: true,
            ca_cert: Some(sample_ca_pem()),
        };
        tls.build_client_config()
            .expect("custom CA must be added to the root store");
    }

    #[test]
    fn tls_config_verify_true_rejects_non_pem_ca() {
        let tls = KafkaTls {
            verify: true,
            ca_cert: Some("not a certificate".to_string()),
        };
        match tls.build_client_config() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("ca_cert"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn tls_validate_rejects_verify_false_with_ca_cert() {
        let tls = KafkaTls {
            verify: false,
            ca_cert: Some(sample_ca_pem()),
        };
        match tls.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("tls.verify: true"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn tls_validate_rejects_non_pem_ca() {
        let tls = KafkaTls {
            verify: true,
            ca_cert: Some("not a certificate".to_string()),
        };
        match tls.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("ca_cert"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn tls_validate_accepts_verify_true_with_custom_ca() {
        let tls = KafkaTls {
            verify: true,
            ca_cert: Some(sample_ca_pem()),
        };
        tls.validate().expect("valid custom CA must pass");
    }

    #[test]
    fn tls_validate_accepts_verify_true_without_ca() {
        let tls = KafkaTls {
            verify: true,
            ca_cert: None,
        };
        tls.validate().expect("verify without CA must pass");
    }

    #[test]
    fn tls_validate_accepts_verify_false_without_ca() {
        let tls = KafkaTls {
            verify: false,
            ca_cert: None,
        };
        tls.validate().expect("accept-any without CA must pass");
    }

    #[test]
    fn sasl_validate_rejects_empty_username() {
        let sasl = KafkaSasl {
            mechanism: SaslMechanism::Plain,
            username: "  ".into(),
            password: Password("pw".into()),
        };
        match sasl.validate() {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("username"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn sasl_validate_accepts_non_empty_username() {
        let sasl = KafkaSasl {
            mechanism: SaslMechanism::Plain,
            username: "svc".into(),
            password: Password("pw".into()),
        };
        sasl.validate().expect("non-empty username must pass");
    }

    #[test]
    fn parse_ca_certs_accepts_a_pem_certificate() {
        let certs = parse_ca_certs(&sample_ca_pem()).expect("valid PEM");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn parse_ca_certs_rejects_input_without_a_certificate() {
        match parse_ca_certs("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n") {
            Err(RastreoError::Config(ConfigError::InvalidValue(msg))) => {
                assert!(msg.contains("ca_cert"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn sasl_plain_maps_to_plain_config_with_credentials() {
        let sasl = KafkaSasl {
            mechanism: SaslMechanism::Plain,
            username: "svc".into(),
            password: Password("pw".into()),
        };
        match sasl.to_sasl_config() {
            SaslConfig::Plain(creds) => {
                assert_eq!(creds.username, "svc");
                assert_eq!(creds.password, "pw");
            }
            other => panic!("expected Plain, got {other:?}"),
        }
    }

    #[test]
    fn sasl_scram_sha_256_maps_to_scram_sha_256_config() {
        let sasl = KafkaSasl {
            mechanism: SaslMechanism::ScramSha256,
            username: "svc".into(),
            password: Password("pw".into()),
        };
        assert!(matches!(sasl.to_sasl_config(), SaslConfig::ScramSha256(_)));
    }

    #[test]
    fn sasl_scram_sha_512_maps_to_scram_sha_512_config() {
        let sasl = KafkaSasl {
            mechanism: SaslMechanism::ScramSha512,
            username: "svc".into(),
            password: Password("pw".into()),
        };
        assert!(matches!(sasl.to_sasl_config(), SaslConfig::ScramSha512(_)));
    }

    #[test]
    fn kafka_sasl_debug_redacts_password() {
        let sasl = KafkaSasl {
            mechanism: SaslMechanism::Plain,
            username: "svc".into(),
            password: Password("supersecret".into()),
        };
        let s = format!("{sasl:?}");
        assert!(!s.contains("supersecret"), "password leaked in Debug: {s}");
        assert!(s.contains("<redacted:"));
    }

    #[test]
    fn kafka_sasl_serialize_redacts_password() {
        let sasl = KafkaSasl {
            mechanism: SaslMechanism::Plain,
            username: "svc".into(),
            password: Password("supersecret".into()),
        };
        let json = serde_json::to_string(&sasl).expect("serialize");
        assert!(!json.contains("supersecret"), "password leaked: {json}");
        assert!(json.contains("<redacted:"));
    }

    #[test]
    fn sink_config_kafka_with_sasl_does_not_leak_password() {
        use crate::sink::SinkConfig;

        let config = SinkConfig::Kafka {
            brokers: vec!["k:9092".into()],
            topic: "t".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: Some(KafkaSasl {
                mechanism: SaslMechanism::ScramSha512,
                username: "svc".into(),
                password: Password("supersecret".into()),
            }),
            retry: SinkRetry::default(),
        };
        let json = serde_json::to_string(&config).expect("serialize");
        assert!(
            !json.contains("supersecret"),
            "password leaked in JSON: {json}"
        );
        let debug = format!("{config:?}");
        assert!(
            !debug.contains("supersecret"),
            "password leaked in Debug: {debug}"
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn deserialize_kafka_sink_config_with_tls_and_sasl() {
        use crate::sink::SinkConfig;

        let yaml = "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\ntls:\n  verify: true\nsasl:\n  mechanism: scram_sha_256\n  username: svc\n  password: pw\n";
        let config: SinkConfig = serde_yaml_ng::from_str(yaml).expect("deserialize kafka");
        match config {
            SinkConfig::Kafka { tls, sasl, .. } => {
                let tls = tls.expect("tls present");
                assert!(tls.verify);
                assert!(tls.ca_cert.is_none());
                let sasl = sasl.expect("sasl present");
                assert!(matches!(sasl.mechanism, SaslMechanism::ScramSha256));
                assert_eq!(sasl.username, "svc");
                assert_eq!(sasl.password.expose(), "pw");
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn kafka_tls_verify_defaults_to_false_when_omitted() {
        let tls: KafkaTls = serde_yaml_ng::from_str("ca_cert: ~\n").expect("deserialize tls");
        assert!(!tls.verify);
        assert!(tls.ca_cert.is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn kafka_sasl_mechanism_deserializes_snake_case() {
        for (yaml, expected) in [
            ("plain", SaslMechanism::Plain),
            ("scram_sha_256", SaslMechanism::ScramSha256),
            ("scram_sha_512", SaslMechanism::ScramSha512),
        ] {
            let m: SaslMechanism =
                serde_yaml_ng::from_str(yaml).unwrap_or_else(|e| panic!("{yaml}: {e}"));
            assert_eq!(m, expected);
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn kafka_sink_config_expands_file_ca_cert_and_env_password() {
        use crate::config::secrets::{expand, SecretSource};
        use crate::sink::SinkConfig;
        use std::io::Write;

        let ca = sample_ca_pem();
        let mut ca_file = tempfile::NamedTempFile::new().expect("tempfile");
        ca_file.write_all(ca.as_bytes()).expect("write ca");
        let ca_path = ca_file.path().to_str().expect("utf-8 path").to_string();

        // SAFETY: env var mutation is process-global; this test uses a unique name.
        unsafe { std::env::set_var("RASTREO_TEST_KAFKA_SASL_PW", "topsecret-scram") };

        let yaml = format!(
            "type: kafka\nbrokers: [\"k:9092\"]\ntopic: t\ntls:\n  verify: true\n  ca_cert: !file {ca_path}\nsasl:\n  mechanism: scram_sha_256\n  username: svc\n  password: ${{RASTREO_TEST_KAFKA_SASL_PW}}\n"
        );
        let raw: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).expect("parse");
        let expanded = expand(raw, SecretSource::SinkConfig).expect("expand secrets");
        let config: SinkConfig = serde_yaml_ng::from_value(expanded).expect("deserialize");

        // SAFETY: see set_var above.
        unsafe { std::env::remove_var("RASTREO_TEST_KAFKA_SASL_PW") };

        match config {
            SinkConfig::Kafka { tls, sasl, .. } => {
                let tls = tls.expect("tls present");
                assert_eq!(tls.ca_cert.as_deref(), Some(ca.trim_end()));
                let sasl = sasl.expect("sasl present");
                assert_eq!(sasl.password.expose(), "topsecret-scram");
            }
            other => panic!("expected Kafka, got {other:?}"),
        }
    }
}
