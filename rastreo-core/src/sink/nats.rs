use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use async_nats::jetstream::context::{PublishAckFuture, PublishError};
use async_nats::jetstream::{self, Context};
use async_nats::{Client, ConnectOptions, HeaderMap};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;

use crate::error::{ConfigError, RastreoError};
use crate::prober::Password;
use crate::redact::redacted_server_list;
use crate::sink::{
    retry_with_backoff, RecordKind, Sink, SinkError, SinkErrorClass, SinkRetry, SinkType,
    DEFAULT_LINKS_DESTINATION, DEFAULT_PROFILES_DESTINATION, SINK_ERROR_CLASS_COUNT,
};

const HEADER_SOURCE_SUBJECT: &str = "x-rastreo-source-subject";
const HEADER_ERROR_CLASS: &str = "x-rastreo-error-class";
const HEADER_DLQ_TIMESTAMP: &str = "x-rastreo-dlq-timestamp";

/// Cap on acks left un-awaited between publishes; a deferred ack holds a client permit that only its drain releases.
const MAX_PENDING_ACKS: usize = 512;
/// One permit per deferred ack, plus slack: a cancelled drain leaves its permits with the client's acker task until each ack resolves or times out.
const ACK_PERMIT_CAPACITY: usize = MAX_PENDING_ACKS + 64;

fn clamp_threshold(bytes: usize) -> usize {
    bytes.max(1)
}

fn should_drain_pending_acks(pending: usize) -> bool {
    pending >= MAX_PENDING_ACKS
}

fn should_flush_after_append(buffer_len: usize, threshold: usize) -> bool {
    buffer_len >= threshold
}

fn buffer_record(buffer: &mut VecDeque<Bytes>, buffered_bytes: &mut usize, data: &[u8]) {
    buffer.push_back(Bytes::from(data.to_vec()));
    *buffered_bytes += data.len();
}

fn pop_accepted(buffer: &mut VecDeque<Bytes>, buffered_bytes: &mut usize) {
    if let Some(entry) = buffer.pop_front() {
        *buffered_bytes = buffered_bytes.saturating_sub(entry.len());
    }
}

/// Puts payloads whose ack was rejected back at the head of `buffer`, ahead of anything written since.
fn retain_unacked(
    buffer: &mut VecDeque<Bytes>,
    buffered_bytes: &mut usize,
    mut unacked: VecDeque<Bytes>,
) {
    if unacked.is_empty() {
        return;
    }
    *buffered_bytes += unacked.iter().map(Bytes::len).sum::<usize>();
    unacked.append(buffer);
    *buffer = unacked;
}

pub fn default_batch_threshold() -> usize {
    NatsSink::DEFAULT_BUFFER_THRESHOLD
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum NatsCredentials {
    #[default]
    Anonymous,
    UserPass {
        username: String,
        password: Password,
    },
    Token {
        token: Password,
    },
    Creds {
        creds_file: String,
    },
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum NatsFlushMode {
    #[default]
    PerRecord,
    Batched {
        #[serde(default = "default_batch_threshold")]
        threshold_bytes: usize,
    },
}

impl NatsFlushMode {
    fn to_threshold(&self) -> usize {
        match self {
            Self::PerRecord => 1,
            Self::Batched { threshold_bytes } => clamp_threshold(*threshold_bytes),
        }
    }
}

/// Quarantine JetStream target for records the primary NATS publish or ack rejected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct NatsDeadLetterConfig {
    pub stream: String,
    pub subject: String,
    #[serde(default = "default_include_error_metadata")]
    pub include_error_metadata: bool,
}

impl NatsDeadLetterConfig {
    /// Reject empty / whitespace-only stream and subject at config-load time rather than at broker-connect time.
    pub fn validate(&self) -> Result<(), RastreoError> {
        if self.stream.trim().is_empty() {
            return Err(ConfigError::invalid("nats sink: dead-letter stream is empty").into());
        }
        if self.subject.trim().is_empty() {
            return Err(ConfigError::invalid("nats sink: dead-letter subject is empty").into());
        }
        Ok(())
    }
}

fn default_include_error_metadata() -> bool {
    true
}

struct PendingPublish {
    payload: Bytes,
    ack: PublishAckFuture,
}

pub struct NatsSink {
    subject: String,
    stream: String,
    servers: Vec<String>,
    ctx: Context,
    buffer: VecDeque<Bytes>,
    buffered_bytes: usize,
    buffer_threshold: usize,
    pending_acks: Vec<PendingPublish>,
    last_write_delivered: bool,
    dlq_stream: Option<String>,
    dlq_subject: Option<String>,
    include_error_metadata: bool,
    dlq_delivered: [AtomicU64; SINK_ERROR_CLASS_COUNT],
    retry: SinkRetry,
    links_subject: String,
    links_buffer: VecDeque<Bytes>,
    links_buffered_bytes: usize,
    profiles_subject: String,
    profiles_buffer: VecDeque<Bytes>,
    profiles_buffered_bytes: usize,
}

impl std::fmt::Debug for NatsSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsSink")
            .field("subject", &self.subject)
            .field("stream", &self.stream)
            .field("servers", &redacted_server_list(&self.servers))
            .field("buffered_records", &self.buffer.len())
            .field("buffered_bytes", &self.buffered_bytes)
            .field("buffer_threshold", &self.buffer_threshold)
            .field("pending_acks", &self.pending_acks.len())
            .field("last_write_delivered", &self.last_write_delivered)
            .field("dlq_stream", &self.dlq_stream)
            .field("dlq_subject", &self.dlq_subject)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

fn build_publish_error(subject: &str, servers: &[String], err: PublishError) -> RastreoError {
    let servers_for_err = redacted_server_list(servers);
    RastreoError::Sink(SinkError::new(
        SinkErrorClass::PublishFailure,
        io::Error::other(format!(
            "nats sink: failed to publish to subject '{subject}' at server(s) '{servers_for_err}': {err}"
        )),
    ))
}

fn build_ack_error(subject: &str, servers: &[String], err: PublishError) -> RastreoError {
    let servers_for_err = redacted_server_list(servers);
    RastreoError::Sink(SinkError::new(
        SinkErrorClass::AckRejection,
        io::Error::other(format!(
            "nats sink: publish to subject '{subject}' at server(s) '{servers_for_err}' was not acked: {err}"
        )),
    ))
}

fn build_probe_error(subject: &str, servers: &[String], err: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!(
        "nats sink probe failed for subject '{subject}' at server(s) '{}': {err}",
        redacted_server_list(servers)
    ))
}

/// Envelope headers follow the `x-<vendor>-<name>` convention so downstream
/// consumers can filter DLQ records without inspecting the payload. `error_class`
/// is the class of the failure that quarantined the record.
fn build_dlq_headers(source_subject: &str, error_class: SinkErrorClass) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_SOURCE_SUBJECT, source_subject);
    headers.insert(HEADER_ERROR_CLASS, error_class.as_label());
    headers.insert(HEADER_DLQ_TIMESTAMP, Utc::now().to_rfc3339().as_str());
    headers
}

impl NatsSink {
    pub const DEFAULT_BUFFER_THRESHOLD: usize = 64 * 1024;

    /// Assumes a config already validated by `create_sink`; does not re-validate before connecting.
    pub async fn new(
        servers: Vec<String>,
        subject: String,
        stream: String,
        credentials: NatsCredentials,
    ) -> Result<Self, RastreoError> {
        let servers_for_err = redacted_server_list(&servers);
        let client = connect_with_credentials(&servers, credentials)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "nats sink: failed to connect to server(s) '{servers_for_err}': {e}"
                ))
            })
            .map_err(SinkError::other)?;

        let ctx = jetstream::ContextBuilder::new()
            .max_ack_inflight(ACK_PERMIT_CAPACITY)
            .build(client);

        ctx.get_stream(&stream)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "nats sink: JetStream stream '{stream}' not found or unreachable at server(s) '{servers_for_err}': {e}"
                ))
            })
            .map_err(SinkError::other)?;

        Ok(Self {
            subject,
            stream,
            servers,
            ctx,
            buffer: VecDeque::new(),
            buffered_bytes: 0,
            buffer_threshold: 1,
            pending_acks: Vec::new(),
            last_write_delivered: false,
            dlq_stream: None,
            dlq_subject: None,
            include_error_metadata: false,
            dlq_delivered: std::array::from_fn(|_| AtomicU64::new(0)),
            retry: SinkRetry::default(),
            links_subject: DEFAULT_LINKS_DESTINATION.to_string(),
            links_buffer: VecDeque::new(),
            links_buffered_bytes: 0,
            profiles_subject: DEFAULT_PROFILES_DESTINATION.to_string(),
            profiles_buffer: VecDeque::new(),
            profiles_buffered_bytes: 0,
        })
    }

    pub fn with_flush_mode(mut self, mode: NatsFlushMode) -> Self {
        self.buffer_threshold = mode.to_threshold();
        self
    }

    pub fn with_links_subject(mut self, subject: String) -> Self {
        self.links_subject = subject;
        self
    }

    pub fn with_profiles_subject(mut self, subject: String) -> Self {
        self.profiles_subject = subject;
        self
    }

    pub fn with_retry(mut self, retry: SinkRetry) -> Self {
        self.retry = retry;
        self
    }

    pub async fn with_dead_letter(
        mut self,
        config: NatsDeadLetterConfig,
    ) -> Result<Self, RastreoError> {
        config.validate()?;

        let servers_for_err = redacted_server_list(&self.servers);
        let dlq_stream = config.stream.clone();
        self.ctx
            .get_stream(&dlq_stream)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "nats sink: JetStream dead-letter stream '{dlq_stream}' not found or unreachable at server(s) '{servers_for_err}': {e}"
                ))
            })
            .map_err(SinkError::other)?;

        self.dlq_stream = Some(dlq_stream);
        self.dlq_subject = Some(config.subject);
        self.include_error_metadata = config.include_error_metadata;
        Ok(self)
    }

    /// `true` once the DLQ accepted *and* acked the payload; `false` when no DLQ is configured or
    /// it refused, in which case the caller still holds the record and must retain it.
    async fn quarantine(
        &self,
        payload: Bytes,
        error_class: SinkErrorClass,
        cause: &RastreoError,
    ) -> bool {
        let Some(dlq_subject) = self.dlq_subject.clone() else {
            return false;
        };

        tracing::warn!(
            subject = self.subject.as_str(),
            dlq_subject = dlq_subject.as_str(),
            error = %cause,
            "nats sink: primary delivery failed; shipping record to DLQ",
        );

        let published = if self.include_error_metadata {
            let headers = build_dlq_headers(&self.subject, error_class);
            self.ctx
                .publish_with_headers(dlq_subject.clone(), headers, payload)
                .await
        } else {
            self.ctx.publish(dlq_subject.clone(), payload).await
        };

        let ack = match published {
            Ok(ack) => ack,
            Err(dlq_err) => {
                tracing::error!(
                    subject = self.subject.as_str(),
                    dlq_subject = dlq_subject.as_str(),
                    dlq_error = %dlq_err,
                    "nats sink: DLQ publish also failed; retaining record",
                );
                return false;
            }
        };

        if let Err(dlq_ack_err) = ack.await {
            tracing::error!(
                subject = self.subject.as_str(),
                dlq_subject = dlq_subject.as_str(),
                dlq_error = %dlq_ack_err,
                "nats sink: DLQ publish accepted but ack rejected; retaining record",
            );
            return false;
        }

        self.credit_dlq(error_class);
        true
    }

    fn credit_dlq(&self, class: SinkErrorClass) {
        self.dlq_delivered[class.index()].fetch_add(1, Ordering::Relaxed);
    }

    async fn publish_buffer(&mut self) -> Result<(), RastreoError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let subject = self.subject.clone();
        // One publish per entry, pipelined. An entry leaves the buffer only once it is
        // accepted, so any failure retains it along with every entry behind it.
        while let Some(payload) = self.buffer.front().cloned() {
            // Retry only the primary publish: a transient connection blip self-heals within the
            // attempt budget. The returned ack stays deferred for pipelined draining.
            let publish_result = {
                let ctx = &self.ctx;
                let servers = &self.servers;
                let subject = &subject;
                let payload = &payload;
                retry_with_backoff(&self.retry, || async move {
                    ctx.publish(subject.clone(), payload.clone())
                        .await
                        .map_err(|e| build_publish_error(subject, servers, e))
                })
                .await
            };

            let primary_err = match publish_result {
                Ok(ack) => {
                    pop_accepted(&mut self.buffer, &mut self.buffered_bytes);
                    self.pending_acks.push(PendingPublish { payload, ack });
                    if should_drain_pending_acks(self.pending_acks.len()) {
                        // A drain that put records back returns Err, so `?` leaves before this walk re-reads the buffer it mutated.
                        self.drain_pending_acks().await?;
                    }
                    continue;
                }
                Err(e) => e,
            };

            if !self
                .quarantine(payload, SinkErrorClass::PublishFailure, &primary_err)
                .await
            {
                return Err(primary_err);
            }
            pop_accepted(&mut self.buffer, &mut self.buffered_bytes);
        }
        Ok(())
    }

    async fn drain_pending_acks(&mut self) -> Result<(), RastreoError> {
        if self.pending_acks.is_empty() {
            return Ok(());
        }
        let mut pending = std::mem::take(&mut self.pending_acks);
        let subject = self.subject.clone();
        // Collect only the first non-recovered ack error; every ack is still awaited so
        // JetStream drains and the DLQ receives every quarantinable payload. Every retained
        // payload also sets that error, so a non-empty `unacked` and an `Err` return are the same event.
        let mut first_error: Option<RastreoError> = None;
        let mut unacked: VecDeque<Bytes> = VecDeque::new();

        for PendingPublish { payload, ack } in pending.drain(..) {
            let Err(ack_err) = ack.await else {
                continue;
            };
            let ack_error = build_ack_error(&subject, &self.servers, ack_err);

            if self
                .quarantine(payload.clone(), SinkErrorClass::AckRejection, &ack_error)
                .await
            {
                continue;
            }

            unacked.push_back(payload);
            if first_error.is_none() {
                first_error = Some(ack_error);
            }
        }

        // Drained empty but with its capacity intact, so a scan grows this once rather than once per drain.
        self.pending_acks = pending;
        retain_unacked(&mut self.buffer, &mut self.buffered_bytes, unacked);

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Drains unconditionally: a mid-buffer publish failure leaves earlier entries in `pending_acks`, and skipping the drain would strand them in neither buffer nor DLQ.
    async fn publish_and_drain(&mut self) -> Result<(), RastreoError> {
        let publish_err = self.publish_buffer().await.err();
        let drain_err = self.drain_pending_acks().await.err();
        match publish_err.or(drain_err) {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    async fn write_link(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.last_write_delivered = false;
        buffer_record(&mut self.links_buffer, &mut self.links_buffered_bytes, data);
        if should_flush_after_append(self.links_buffered_bytes, self.buffer_threshold) {
            // publish_links_buffer awaits each ack inline, so the publish is the acceptance.
            self.publish_links_buffer().await?;
            self.last_write_delivered = true;
        }
        Ok(())
    }

    async fn publish_links_buffer(&mut self) -> Result<(), RastreoError> {
        publish_stream_buffer(
            &self.ctx,
            &self.retry,
            &self.servers,
            &self.links_subject,
            &mut self.links_buffer,
            &mut self.links_buffered_bytes,
        )
        .await
    }

    async fn write_profile(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.last_write_delivered = false;
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
        publish_stream_buffer(
            &self.ctx,
            &self.retry,
            &self.servers,
            &self.profiles_subject,
            &mut self.profiles_buffer,
            &mut self.profiles_buffered_bytes,
        )
        .await
    }
}

/// Publishes a second-stream buffer entry by entry, awaiting each ack inline. An entry leaves
/// the buffer only once it is acked, so any failure retains it along with every entry behind it.
async fn publish_stream_buffer(
    ctx: &Context,
    retry: &SinkRetry,
    servers: &[String],
    subject: &str,
    buffer: &mut VecDeque<Bytes>,
    buffered_bytes: &mut usize,
) -> Result<(), RastreoError> {
    while let Some(payload) = buffer.front().cloned() {
        let ack = {
            let payload = &payload;
            retry_with_backoff(retry, || async move {
                ctx.publish(subject.to_string(), payload.clone())
                    .await
                    .map_err(|e| build_publish_error(subject, servers, e))
            })
            .await
        }?;
        ack.await
            .map_err(|e| build_ack_error(subject, servers, e))?;
        pop_accepted(buffer, buffered_bytes);
    }
    Ok(())
}

async fn connect_with_credentials(
    servers: &[String],
    credentials: NatsCredentials,
) -> Result<Client, async_nats::ConnectError> {
    match credentials {
        NatsCredentials::Anonymous => ConnectOptions::new().connect(servers.to_vec()).await,
        NatsCredentials::UserPass { username, password } => {
            ConnectOptions::new()
                .user_and_password(username, password.expose().to_string())
                .connect(servers.to_vec())
                .await
        }
        NatsCredentials::Token { token } => {
            ConnectOptions::new()
                .token(token.expose().to_string())
                .connect(servers.to_vec())
                .await
        }
        NatsCredentials::Creds { creds_file } => {
            let path = std::path::PathBuf::from(&creds_file);
            let opts = ConnectOptions::new()
                .credentials_file(&path)
                .await
                .map_err(async_nats::ConnectError::from)?;
            opts.connect(servers.to_vec()).await
        }
    }
}

#[async_trait]
impl Sink for NatsSink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.last_write_delivered = false;
        buffer_record(&mut self.buffer, &mut self.buffered_bytes, data);
        if should_flush_after_append(self.buffered_bytes, self.buffer_threshold) {
            if self.buffer_threshold == 1 {
                self.publish_and_drain().await?;
                self.last_write_delivered = true;
            } else {
                // Batched mode pipelines the acks deliberately; flush drains them.
                self.publish_buffer().await?;
            }
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

    /// Publishes all three stream buffers whatever any one of them does, returning the first error.
    async fn flush(&mut self) -> Result<(), RastreoError> {
        let device_err = self.publish_and_drain().await.err();
        let links_err = self.publish_links_buffer().await.err();
        let profiles_err = self.publish_profiles_buffer().await.err();
        let first_error = device_err.or(links_err).or(profiles_err);
        self.last_write_delivered = first_error.is_none();
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn last_write_delivered(&self) -> bool {
        self.last_write_delivered && self.pending_acks.is_empty()
    }

    fn kind(&self) -> SinkType {
        SinkType::Nats
    }

    fn dlq_records_delivered(&self) -> u64 {
        self.dlq_delivered
            .iter()
            .fold(0u64, |acc, c| acc.saturating_add(c.load(Ordering::Relaxed)))
    }

    fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
        std::array::from_fn(|i| self.dlq_delivered[i].load(Ordering::Relaxed))
    }

    async fn probe(&self) -> Result<(), io::Error> {
        // Client-level flush is a ping: it drains any pending client-side buffer and
        // requires the server round-trip to complete, so failure signals the same
        // connectivity break publish() would surface.
        self.ctx
            .client()
            .flush()
            .await
            .map_err(|e| build_probe_error(&self.subject, &self.servers, e))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
    use testcontainers_modules::nats::{Nats, NatsServerCmd};

    use super::*;
    use crate::sink::sink_io_detail;

    struct JetStream {
        _node: ContainerAsync<Nats>,
        server: String,
        admin: Context,
    }

    impl JetStream {
        async fn start() -> Self {
            let cmd = NatsServerCmd::default().with_jetstream();
            let node = Nats::default()
                .with_cmd(&cmd)
                .start()
                .await
                .expect("start nats container");
            let port = node
                .get_host_port_ipv4(4222)
                .await
                .expect("mapped nats port");
            let server = format!("nats://127.0.0.1:{port}");

            // The container reports ready from its log, which can win the race against the server accepting connections.
            let mut client = None;
            for _ in 0..40 {
                if let Ok(connected) = async_nats::connect(&server).await {
                    client = Some(connected);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            let admin = jetstream::new(client.expect("nats server never accepted a connection"));
            Self {
                _node: node,
                server,
                admin,
            }
        }

        async fn create_stream(&self, name: &str, subjects: &[&str]) {
            self.admin
                .create_stream(jetstream::stream::Config {
                    name: name.to_string(),
                    subjects: subjects.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                })
                .await
                .unwrap_or_else(|e| panic!("create stream {name}: {e}"));
        }

        async fn sink(&self, subject: &str, stream: &str) -> Result<NatsSink, RastreoError> {
            NatsSink::new(
                vec![self.server.clone()],
                subject.to_string(),
                stream.to_string(),
                NatsCredentials::Anonymous,
            )
            .await
        }
    }

    #[test]
    fn default_buffer_threshold_is_64_kib() {
        assert_eq!(NatsSink::DEFAULT_BUFFER_THRESHOLD, 64 * 1024);
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
    fn should_drain_pending_acks_is_false_below_the_cap() {
        assert!(!should_drain_pending_acks(0));
        assert!(!should_drain_pending_acks(1));
        assert!(!should_drain_pending_acks(MAX_PENDING_ACKS - 1));
    }

    #[test]
    fn should_drain_pending_acks_is_true_at_or_above_the_cap() {
        assert!(should_drain_pending_acks(MAX_PENDING_ACKS));
        assert!(should_drain_pending_acks(MAX_PENDING_ACKS + 1));
    }

    fn buffered(records: &[&[u8]]) -> (VecDeque<Bytes>, usize) {
        let mut buffer = VecDeque::new();
        let mut bytes = 0usize;
        for record in records {
            buffer_record(&mut buffer, &mut bytes, record);
        }
        (buffer, bytes)
    }

    #[test]
    fn buffer_record_keeps_each_record_a_distinct_entry() {
        let (buffer, bytes) = buffered(&[b"one\n", b"two\n", b"three\n"]);
        assert_eq!(
            buffer.len(),
            3,
            "a batched flush of 3 records must issue 3 publishes, not one concatenated payload"
        );
        assert_eq!(buffer[0], b"one\n".as_slice());
        assert_eq!(buffer[1], b"two\n".as_slice());
        assert_eq!(buffer[2], b"three\n".as_slice());
        assert_eq!(bytes, 4 + 4 + 6);
    }

    #[test]
    fn pop_accepted_removes_the_head_and_debits_only_its_bytes() {
        let (mut buffer, mut bytes) = buffered(&[b"one\n", b"two\n", b"three\n"]);
        pop_accepted(&mut buffer, &mut bytes);
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer[0], b"two\n".as_slice());
        assert_eq!(bytes, 4 + 6);
    }

    #[test]
    fn popping_every_accepted_entry_leaves_an_empty_buffer_and_no_bytes() {
        let (mut buffer, mut bytes) = buffered(&[b"one\n", b"two\n", b"three\n"]);
        for _ in 0..3 {
            pop_accepted(&mut buffer, &mut bytes);
        }
        assert!(buffer.is_empty());
        assert_eq!(bytes, 0);
    }

    #[test]
    fn pop_accepted_on_an_empty_buffer_is_a_no_op() {
        let mut buffer: VecDeque<Bytes> = VecDeque::new();
        let mut bytes = 0usize;
        pop_accepted(&mut buffer, &mut bytes);
        assert!(buffer.is_empty());
        assert_eq!(bytes, 0);
    }

    #[test]
    fn retain_unacked_puts_the_payloads_back_ahead_of_later_writes_in_order() {
        let (mut buffer, mut bytes) = buffered(&[b"later\n"]);
        let (unacked, unacked_bytes) = buffered(&[b"first\n", b"second\n"]);

        retain_unacked(&mut buffer, &mut bytes, unacked);

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer[0], b"first\n".as_slice());
        assert_eq!(buffer[1], b"second\n".as_slice());
        assert_eq!(buffer[2], b"later\n".as_slice());
        assert_eq!(bytes, unacked_bytes + 6);
    }

    #[test]
    fn retain_unacked_on_an_empty_buffer_restores_the_whole_batch() {
        let mut buffer: VecDeque<Bytes> = VecDeque::new();
        let mut bytes = 0usize;
        let (unacked, unacked_bytes) = buffered(&[b"one\n", b"two\n"]);

        retain_unacked(&mut buffer, &mut bytes, unacked);

        assert_eq!(buffer.len(), 2);
        assert_eq!(bytes, unacked_bytes);
    }

    #[test]
    fn retain_unacked_with_nothing_to_retain_leaves_the_buffer_untouched() {
        let (mut buffer, mut bytes) = buffered(&[b"one\n"]);
        retain_unacked(&mut buffer, &mut bytes, VecDeque::new());
        assert_eq!(buffer.len(), 1);
        assert_eq!(bytes, 4);
    }

    #[test]
    fn a_retained_batch_still_triggers_the_flush_threshold_it_reached() {
        let (mut buffer, mut bytes) = buffered(&[]);
        let (unacked, _) = buffered(&[b"0123456789\n"]);

        retain_unacked(&mut buffer, &mut bytes, unacked);

        assert!(should_flush_after_append(bytes, 11));
    }

    #[test]
    fn nats_credentials_default_is_anonymous() {
        assert!(matches!(
            NatsCredentials::default(),
            NatsCredentials::Anonymous
        ));
    }

    #[test]
    fn nats_flush_mode_default_is_per_record() {
        assert!(matches!(NatsFlushMode::default(), NatsFlushMode::PerRecord));
    }

    #[test]
    fn nats_flush_mode_batched_default_threshold_is_64k() {
        assert_eq!(default_batch_threshold(), 64 * 1024);
    }

    #[test]
    fn nats_flush_mode_per_record_maps_to_threshold_one() {
        assert_eq!(NatsFlushMode::PerRecord.to_threshold(), 1);
    }

    #[test]
    fn nats_flush_mode_batched_maps_to_clamped_threshold() {
        assert_eq!(
            NatsFlushMode::Batched { threshold_bytes: 0 }.to_threshold(),
            1
        );
        assert_eq!(
            NatsFlushMode::Batched {
                threshold_bytes: 4096
            }
            .to_threshold(),
            4096
        );
    }

    #[test]
    fn nats_credentials_user_pass_password_serializes_redacted() {
        let creds = NatsCredentials::UserPass {
            username: "admin".to_string(),
            password: Password("supersecret".to_string()),
        };
        let json = serde_json::to_string(&creds).expect("serialize");
        assert!(
            !json.contains("supersecret"),
            "password leaked in serialization: {json}"
        );
        assert!(json.contains("<redacted:"));
    }

    #[test]
    fn nats_credentials_token_serializes_redacted() {
        let creds = NatsCredentials::Token {
            token: Password("secret-token-xyz".to_string()),
        };
        let json = serde_json::to_string(&creds).expect("serialize");
        assert!(!json.contains("secret-token-xyz"), "token leaked: {json}");
        assert!(json.contains("<redacted:"));
    }

    #[test]
    fn nats_credentials_user_pass_debug_is_redacted() {
        let creds = NatsCredentials::UserPass {
            username: "admin".to_string(),
            password: Password("supersecret".to_string()),
        };
        let s = format!("{creds:?}");
        assert!(!s.contains("supersecret"), "password leaked in Debug: {s}");
        assert!(s.contains("<redacted:"));
    }

    #[test]
    fn nats_credentials_creds_file_is_plain_string() {
        let creds = NatsCredentials::Creds {
            creds_file: "/etc/rastreo/nats.creds".to_string(),
        };
        let json = serde_json::to_string(&creds).expect("serialize");
        assert!(json.contains("/etc/rastreo/nats.creds"));
    }

    #[test]
    fn nats_sink_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<NatsSink>();
        assert_send_sync::<Box<dyn Sink>>();
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_credentials_anonymous_deserializes_from_yaml() {
        let yaml = "type: anonymous\n";
        let creds: NatsCredentials = serde_yaml_ng::from_str(yaml).expect("deserialize");
        assert!(matches!(creds, NatsCredentials::Anonymous));
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_credentials_user_pass_deserializes_from_yaml() {
        let yaml = "type: user_pass\nusername: admin\npassword: pw\n";
        let creds: NatsCredentials = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match creds {
            NatsCredentials::UserPass { username, password } => {
                assert_eq!(username, "admin");
                assert_eq!(&*password, "pw");
            }
            other => panic!("expected UserPass, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_credentials_token_deserializes_from_yaml() {
        let yaml = "type: token\ntoken: secret-token\n";
        let creds: NatsCredentials = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match creds {
            NatsCredentials::Token { token } => {
                assert_eq!(&*token, "secret-token");
            }
            other => panic!("expected Token, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_credentials_creds_file_deserializes_from_yaml() {
        let yaml = "type: creds\ncreds_file: /etc/rastreo/nats.creds\n";
        let creds: NatsCredentials = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match creds {
            NatsCredentials::Creds { creds_file } => {
                assert_eq!(creds_file, "/etc/rastreo/nats.creds");
            }
            other => panic!("expected Creds, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_flush_mode_per_record_deserializes_from_yaml() {
        let yaml = "type: per_record\n";
        let d: NatsFlushMode = serde_yaml_ng::from_str(yaml).expect("deserialize");
        assert!(matches!(d, NatsFlushMode::PerRecord));
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_flush_mode_batched_with_threshold_deserializes() {
        let yaml = "type: batched\nthreshold_bytes: 2048\n";
        let d: NatsFlushMode = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match d {
            NatsFlushMode::Batched { threshold_bytes } => assert_eq!(threshold_bytes, 2048),
            other => panic!("expected Batched, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_flush_mode_batched_default_threshold_deserializes() {
        let yaml = "type: batched\n";
        let d: NatsFlushMode = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match d {
            NatsFlushMode::Batched { threshold_bytes } => {
                assert_eq!(threshold_bytes, 64 * 1024);
            }
            other => panic!("expected Batched, got {other:?}"),
        }
    }

    #[ignore = "requires a docker daemon; run with --ignored"]
    #[tokio::test]
    async fn nats_sink_construction_verifies_stream_exists() {
        let js = JetStream::start().await;
        let err = js
            .sink("rastreo.discovery.records.v1", "does-not-exist")
            .await
            .expect_err("missing stream must error");
        assert!(
            matches!(err, RastreoError::Sink(_)),
            "expected Sink error, got {err:?}"
        );
        let msg = sink_io_detail(&err);
        assert!(msg.contains("does-not-exist"), "msg was: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_dead_letter_config_include_error_metadata_defaults_to_true() {
        let yaml = "stream: dlq-stream\nsubject: rastreo.dlq\n";
        let config: NatsDeadLetterConfig =
            serde_yaml_ng::from_str(yaml).expect("deserialize dead-letter config");
        assert_eq!(config.stream, "dlq-stream");
        assert_eq!(config.subject, "rastreo.dlq");
        assert!(config.include_error_metadata);
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_dead_letter_config_explicit_false_deserializes() {
        let yaml = "stream: dlq-stream\nsubject: rastreo.dlq\ninclude_error_metadata: false\n";
        let config: NatsDeadLetterConfig =
            serde_yaml_ng::from_str(yaml).expect("deserialize dead-letter config");
        assert!(!config.include_error_metadata);
    }

    #[test]
    fn nats_dead_letter_config_validate_rejects_empty_stream() {
        let cfg = NatsDeadLetterConfig {
            stream: "  ".into(),
            subject: "rastreo.dlq".into(),
            include_error_metadata: true,
        };
        let err = cfg.validate().expect_err("blank stream must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("stream"), "msg was: {msg}");
                assert!(msg.contains("dead-letter"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn nats_dead_letter_config_validate_rejects_empty_subject() {
        let cfg = NatsDeadLetterConfig {
            stream: "dlq-stream".into(),
            subject: "  ".into(),
            include_error_metadata: true,
        };
        let err = cfg.validate().expect_err("blank subject must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("subject"), "msg was: {msg}");
                assert!(msg.contains("dead-letter"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn nats_dead_letter_config_validate_accepts_non_empty_fields() {
        let cfg = NatsDeadLetterConfig {
            stream: "dlq-stream".into(),
            subject: "rastreo.dlq".into(),
            include_error_metadata: false,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn build_dlq_headers_contains_source_subject_and_error_class_and_timestamp() {
        let headers = build_dlq_headers(
            "rastreo.discovery.records.v1",
            SinkErrorClass::PublishFailure,
        );
        assert!(headers.get(HEADER_SOURCE_SUBJECT).is_some());
        assert!(headers.get(HEADER_ERROR_CLASS).is_some());
        assert!(headers.get(HEADER_DLQ_TIMESTAMP).is_some());
    }

    #[test]
    fn build_dlq_headers_source_subject_matches_input() {
        let headers = build_dlq_headers(
            "rastreo.discovery.records.v1",
            SinkErrorClass::PublishFailure,
        );
        let value = headers
            .get(HEADER_SOURCE_SUBJECT)
            .expect("source-subject header present");
        assert_eq!(value.as_str(), "rastreo.discovery.records.v1");
    }

    #[test]
    fn build_dlq_headers_error_class_is_publish_failure_when_publish_class_supplied() {
        let headers = build_dlq_headers(
            "rastreo.discovery.records.v1",
            SinkErrorClass::PublishFailure,
        );
        let value = headers
            .get(HEADER_ERROR_CLASS)
            .expect("error-class header present");
        assert_eq!(value.as_str(), "publish_failure");
    }

    #[test]
    fn build_dlq_headers_error_class_is_ack_rejection_when_ack_class_supplied() {
        let headers =
            build_dlq_headers("rastreo.discovery.records.v1", SinkErrorClass::AckRejection);
        let value = headers
            .get(HEADER_ERROR_CLASS)
            .expect("error-class header present");
        assert_eq!(value.as_str(), "ack_rejection");
    }

    #[test]
    fn build_dlq_headers_timestamp_parses_as_rfc3339() {
        let headers = build_dlq_headers(
            "rastreo.discovery.records.v1",
            SinkErrorClass::PublishFailure,
        );
        let value = headers
            .get(HEADER_DLQ_TIMESTAMP)
            .expect("timestamp header present");
        chrono::DateTime::parse_from_rfc3339(value.as_str()).expect("valid rfc3339 timestamp");
    }

    #[ignore = "requires a docker daemon; run with --ignored"]
    #[tokio::test]
    async fn probe_reports_reachable_against_live_server() {
        let js = JetStream::start().await;
        js.create_stream("RASTREO", &["rastreo.discovery.>"]).await;
        let sink = js
            .sink("rastreo.discovery.records.v1", "RASTREO")
            .await
            .expect("connect to live server");
        <NatsSink as Sink>::probe(&sink).await.expect("probe");
    }

    async fn publish_without_awaiting(sink: &NatsSink) -> PublishAckFuture {
        sink.ctx
            .publish(sink.subject.clone(), Bytes::from_static(b"{}\n"))
            .await
            .expect("publish")
    }

    #[ignore = "requires a docker daemon; run with --ignored"]
    #[tokio::test]
    async fn a_publish_waits_once_every_permit_the_sink_asked_the_client_for_is_parked() {
        const PERMIT_WAIT: Duration = Duration::from_millis(750);

        let js = JetStream::start().await;
        js.create_stream("PERMITS", &["rastreo.permits.>"]).await;
        let sink = js
            .sink("rastreo.permits.records", "PERMITS")
            .await
            .expect("create sink");

        // The permit rides on the future: dropping one hands it to the client's acker task, which releases it.
        let mut parked = Vec::with_capacity(ACK_PERMIT_CAPACITY);
        for _ in 0..ACK_PERMIT_CAPACITY - 1 {
            parked.push(publish_without_awaiting(&sink).await);
        }
        parked.push(
            tokio::time::timeout(PERMIT_WAIT, publish_without_awaiting(&sink))
                .await
                .expect("the last free permit must be handed out without waiting"),
        );

        assert!(
            tokio::time::timeout(PERMIT_WAIT, publish_without_awaiting(&sink))
                .await
                .is_err(),
            "with {ACK_PERMIT_CAPACITY} acks parked the next publish must wait for a permit; a \
             client left on its own default capacity lets it straight through"
        );
    }

    #[tokio::test]
    async fn nats_sink_construction_error_names_the_server_without_its_inline_credentials() {
        let err = NatsSink::new(
            vec!["nats://admin:hunter2@127.0.0.1:1".into()],
            "rastreo.discovery.records.v1".into(),
            "rastreo".into(),
            NatsCredentials::Anonymous,
        )
        .await
        .expect_err("a closed port must fail the connect");
        let msg = error_chain(&err);
        assert!(!msg.contains("hunter2"), "password leaked: {msg}");
        assert!(!msg.contains("admin"), "username leaked: {msg}");
        assert!(msg.contains("nats://127.0.0.1:1"), "msg: {msg}");
        assert!(msg.contains("failed to connect"), "msg: {msg}");
    }

    #[test]
    fn every_error_built_from_a_server_list_redacts_inline_credentials() {
        let servers = vec!["nats://admin:hunter2@n.example.com:4222".to_string()];
        let rendered = [
            sink_io_detail(&build_publish_error("s", &servers, publish_error())),
            sink_io_detail(&build_ack_error("s", &servers, publish_error())),
            build_probe_error("s", &servers, "connection refused").to_string(),
        ];
        for msg in rendered {
            assert!(!msg.contains("hunter2"), "password leaked: {msg}");
            assert!(!msg.contains("admin"), "username leaked: {msg}");
            assert!(msg.contains("nats://n.example.com:4222"), "msg: {msg}");
        }
    }

    #[test]
    fn publish_and_ack_errors_carry_their_distinct_classes() {
        let servers = vec!["nats://n:4222".to_string()];
        let publish = build_publish_error("s", &servers, publish_error());
        let ack = build_ack_error("s", &servers, publish_error());
        assert_eq!(
            publish.sink_error_class(),
            Some(SinkErrorClass::PublishFailure)
        );
        assert_eq!(ack.sink_error_class(), Some(SinkErrorClass::AckRejection));
        assert!(sink_io_detail(&publish).contains("failed to publish"));
        assert!(sink_io_detail(&ack).contains("was not acked"));
    }

    #[test]
    fn dlq_wire_labels_stay_byte_identical() {
        assert_eq!(SinkErrorClass::PublishFailure.as_label(), "publish_failure");
        assert_eq!(SinkErrorClass::AckRejection.as_label(), "ack_rejection");
    }

    fn error_chain(err: &RastreoError) -> String {
        std::iter::successors(Some(err as &dyn std::error::Error), |e| e.source())
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(": ")
    }

    fn publish_error() -> PublishError {
        use async_nats::jetstream::context::PublishErrorKind;
        PublishError::new(PublishErrorKind::StreamNotFound)
    }
}
