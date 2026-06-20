pub mod file;
pub mod stdout;

pub use file::FileSink;
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
    File { path: PathBuf },
}

pub async fn create_sink(config: &SinkConfig) -> Result<Box<dyn Sink>, RastreoError> {
    match config {
        SinkConfig::Stdout => Ok(Box::new(StdoutSink::new())),
        SinkConfig::File { path } => Ok(Box::new(FileSink::new(path).await?)),
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
}
