use tokio::io::{AsyncWriteExt, BufWriter, Stdout};

use crate::error::RastreoError;

use super::{Sink, SinkType};

pub struct StdoutSink {
    writer: BufWriter<Stdout>,
}

impl StdoutSink {
    pub fn new() -> Self {
        Self {
            writer: BufWriter::new(tokio::io::stdout()),
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Sink for StdoutSink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.writer.write_all(data).await.map_err(|e| {
            RastreoError::Sink(std::io::Error::new(
                e.kind(),
                format!("failed to write to stdout sink: {e}"),
            ))
        })?;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        self.writer.flush().await.map_err(|e| {
            RastreoError::Sink(std::io::Error::new(
                e.kind(),
                format!("failed to flush stdout sink: {e}"),
            ))
        })?;
        Ok(())
    }

    fn kind(&self) -> SinkType {
        SinkType::Stdout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_sink_new_returns_value_infallibly() {
        let _sink = StdoutSink::new();
    }

    #[test]
    fn stdout_sink_default_returns_value_infallibly() {
        let _sink = StdoutSink::default();
    }

    #[tokio::test]
    async fn write_empty_slice_succeeds() {
        let mut sink = StdoutSink::new();
        sink.write(b"").await.expect("empty write");
        sink.flush().await.expect("flush");
    }

    #[test]
    fn stdout_sink_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<StdoutSink>();
        assert_send_sync::<Box<dyn Sink>>();
    }

    #[test]
    fn stdout_sink_write_error_prefix_matches_classifier() {
        use crate::sink::{classify_sink_error, SinkErrorClass};
        // Contract: the exact prefix `StdoutSink::write` produces must classify as WriteFailure.
        let simulated = std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "failed to write to stdout sink: Broken pipe",
        );
        assert_eq!(
            classify_sink_error(&simulated),
            SinkErrorClass::WriteFailure
        );
    }

    #[test]
    fn stdout_sink_flush_error_prefix_matches_classifier() {
        use crate::sink::{classify_sink_error, SinkErrorClass};
        let simulated = std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "failed to flush stdout sink: Broken pipe",
        );
        assert_eq!(
            classify_sink_error(&simulated),
            SinkErrorClass::FlushFailure
        );
    }
}
