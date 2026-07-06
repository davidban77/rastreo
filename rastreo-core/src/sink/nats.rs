use std::future::IntoFuture;
use std::io;

use async_nats::jetstream::context::PublishAckFuture;
use async_nats::jetstream::{self, Context};
use async_nats::{Client, ConnectOptions};
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::join_all;

use crate::error::{ConfigError, RastreoError};
use crate::prober::Password;
use crate::sink::Sink;

fn clamp_threshold(bytes: usize) -> usize {
    bytes.max(1)
}

fn should_flush_after_append(buffer_len: usize, threshold: usize) -> bool {
    buffer_len >= threshold
}

pub fn default_batch_threshold() -> usize {
    NatsSink::DEFAULT_BUFFER_THRESHOLD
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(tag = "auth_type", rename_all = "snake_case")]
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

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[non_exhaustive]
pub enum NatsDelivery {
    #[default]
    PerRecord,
    Batched {
        #[serde(default = "default_batch_threshold")]
        threshold_bytes: usize,
    },
}

impl NatsDelivery {
    fn to_threshold(&self) -> usize {
        match self {
            Self::PerRecord => 1,
            Self::Batched { threshold_bytes } => clamp_threshold(*threshold_bytes),
        }
    }
}

pub struct NatsSink {
    subject: String,
    stream: String,
    servers: Vec<String>,
    ctx: Context,
    buffer: Vec<u8>,
    buffer_threshold: usize,
    pending_acks: Vec<PublishAckFuture>,
    last_write_delivered: bool,
}

impl std::fmt::Debug for NatsSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsSink")
            .field("subject", &self.subject)
            .field("stream", &self.stream)
            .field("servers", &self.servers)
            .field("buffer_len", &self.buffer.len())
            .field("buffer_threshold", &self.buffer_threshold)
            .field("pending_acks", &self.pending_acks.len())
            .field("last_write_delivered", &self.last_write_delivered)
            .finish_non_exhaustive()
    }
}

impl NatsSink {
    pub const DEFAULT_BUFFER_THRESHOLD: usize = 64 * 1024;

    pub async fn new(
        servers: Vec<String>,
        subject: String,
        stream: String,
        credentials: NatsCredentials,
    ) -> Result<Self, RastreoError> {
        if servers.is_empty() {
            return Err(ConfigError::invalid("nats sink: servers list is empty").into());
        }
        if servers.iter().any(|s| s.trim().is_empty()) {
            return Err(
                ConfigError::invalid("nats sink: servers list contains an empty entry").into(),
            );
        }
        if subject.trim().is_empty() {
            return Err(ConfigError::invalid("nats sink: subject is empty").into());
        }
        if stream.trim().is_empty() {
            return Err(ConfigError::invalid("nats sink: stream is empty").into());
        }

        let servers_for_err = servers.join(",");
        let client = connect_with_credentials(&servers, credentials)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "nats sink: failed to connect to server(s) '{servers_for_err}': {e}"
                ))
            })
            .map_err(RastreoError::Sink)?;

        let ctx = jetstream::new(client);

        ctx.get_stream(&stream)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "nats sink: JetStream stream '{stream}' not found or unreachable at server(s) '{servers_for_err}': {e}"
                ))
            })
            .map_err(RastreoError::Sink)?;

        Ok(Self {
            subject,
            stream,
            servers,
            ctx,
            buffer: Vec::with_capacity(Self::DEFAULT_BUFFER_THRESHOLD),
            buffer_threshold: 1,
            pending_acks: Vec::new(),
            last_write_delivered: false,
        })
    }

    pub fn with_delivery(mut self, delivery: NatsDelivery) -> Self {
        self.buffer_threshold = delivery.to_threshold();
        self
    }

    async fn publish_buffer(&mut self) -> Result<(), RastreoError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let payload = Bytes::from(self.buffer.clone());
        let servers_for_err = self.servers.join(",");
        let subject = self.subject.clone();
        let ack_future = self
            .ctx
            .publish(subject.clone(), payload)
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "nats sink: failed to publish to subject '{subject}' at server(s) '{servers_for_err}': {e}"
                ))
            })
            .map_err(RastreoError::Sink)?;
        self.buffer.clear();
        self.pending_acks.push(ack_future);
        Ok(())
    }

    async fn drain_pending_acks(&mut self) -> Result<(), RastreoError> {
        if self.pending_acks.is_empty() {
            return Ok(());
        }
        let futures = std::mem::take(&mut self.pending_acks);
        let awaited = futures.into_iter().map(IntoFuture::into_future);
        let results = join_all(awaited).await;
        let servers_for_err = self.servers.join(",");
        let subject = &self.subject;
        for result in results {
            result
                .map_err(|e| {
                    io::Error::other(format!(
                        "nats sink: publish to subject '{subject}' at server(s) '{servers_for_err}' was not acked: {e}"
                    ))
                })
                .map_err(RastreoError::Sink)?;
        }
        Ok(())
    }
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
        self.buffer.extend_from_slice(data);
        if should_flush_after_append(self.buffer.len(), self.buffer_threshold) {
            self.publish_buffer().await?;
            if self.buffer_threshold == 1 {
                self.drain_pending_acks().await?;
                self.last_write_delivered = true;
            }
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        if !self.buffer.is_empty() {
            self.publish_buffer().await?;
        }
        self.drain_pending_acks().await?;
        self.last_write_delivered = true;
        Ok(())
    }

    fn last_write_delivered(&self) -> bool {
        self.last_write_delivered && self.pending_acks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn nats_credentials_default_is_anonymous() {
        assert!(matches!(
            NatsCredentials::default(),
            NatsCredentials::Anonymous
        ));
    }

    #[test]
    fn nats_delivery_default_is_per_record() {
        assert!(matches!(NatsDelivery::default(), NatsDelivery::PerRecord));
    }

    #[test]
    fn nats_delivery_batched_default_threshold_is_64k() {
        assert_eq!(default_batch_threshold(), 64 * 1024);
    }

    #[test]
    fn nats_delivery_per_record_maps_to_threshold_one() {
        assert_eq!(NatsDelivery::PerRecord.to_threshold(), 1);
    }

    #[test]
    fn nats_delivery_batched_maps_to_clamped_threshold() {
        assert_eq!(
            NatsDelivery::Batched { threshold_bytes: 0 }.to_threshold(),
            1
        );
        assert_eq!(
            NatsDelivery::Batched {
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
        let yaml = "auth_type: anonymous\n";
        let creds: NatsCredentials = serde_yaml_ng::from_str(yaml).expect("deserialize");
        assert!(matches!(creds, NatsCredentials::Anonymous));
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_credentials_user_pass_deserializes_from_yaml() {
        let yaml = "auth_type: user_pass\nusername: admin\npassword: pw\n";
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
        let yaml = "auth_type: token\ntoken: secret-token\n";
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
        let yaml = "auth_type: creds\ncreds_file: /etc/rastreo/nats.creds\n";
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
    fn nats_delivery_per_record_deserializes_from_yaml() {
        let yaml = "mode: per_record\n";
        let d: NatsDelivery = serde_yaml_ng::from_str(yaml).expect("deserialize");
        assert!(matches!(d, NatsDelivery::PerRecord));
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_delivery_batched_with_threshold_deserializes() {
        let yaml = "mode: batched\nthreshold_bytes: 2048\n";
        let d: NatsDelivery = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match d {
            NatsDelivery::Batched { threshold_bytes } => assert_eq!(threshold_bytes, 2048),
            other => panic!("expected Batched, got {other:?}"),
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn nats_delivery_batched_default_threshold_deserializes() {
        let yaml = "mode: batched\n";
        let d: NatsDelivery = serde_yaml_ng::from_str(yaml).expect("deserialize");
        match d {
            NatsDelivery::Batched { threshold_bytes } => {
                assert_eq!(threshold_bytes, 64 * 1024);
            }
            other => panic!("expected Batched, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_with_empty_servers_returns_config_error() {
        let err = NatsSink::new(
            vec![],
            "subj".into(),
            "stream".into(),
            NatsCredentials::Anonymous,
        )
        .await
        .expect_err("empty servers must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("servers"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_with_blank_server_entry_returns_config_error() {
        let err = NatsSink::new(
            vec!["nats://n:4222".into(), "  ".into()],
            "subj".into(),
            "stream".into(),
            NatsCredentials::Anonymous,
        )
        .await
        .expect_err("blank server entry must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("empty entry"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_with_empty_subject_returns_config_error() {
        let err = NatsSink::new(
            vec!["nats://n:4222".into()],
            "  ".into(),
            "stream".into(),
            NatsCredentials::Anonymous,
        )
        .await
        .expect_err("blank subject must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("subject"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_with_empty_stream_returns_config_error() {
        let err = NatsSink::new(
            vec!["nats://n:4222".into()],
            "subj".into(),
            "  ".into(),
            NatsCredentials::Anonymous,
        )
        .await
        .expect_err("blank stream must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("stream"), "msg was: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[ignore = "requires a live NATS JetStream server; exercised in Live Infra UAT"]
    #[tokio::test]
    async fn nats_sink_construction_verifies_stream_exists() {
        let err = NatsSink::new(
            vec!["nats://localhost:4222".into()],
            "rastreo.discovery.records.v1".into(),
            "does-not-exist".into(),
            NatsCredentials::Anonymous,
        )
        .await
        .expect_err("missing stream must error");
        match err {
            RastreoError::Sink(io) => {
                let msg = format!("{io}");
                assert!(
                    msg.contains("does-not-exist") || msg.contains("stream"),
                    "msg was: {msg}"
                );
            }
            other => panic!("expected Sink error, got {other:?}"),
        }
    }
}
