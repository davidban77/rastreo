use tokio::io::{AsyncWriteExt, BufWriter, Stdout};

use crate::error::RastreoError;

use super::{Sink, SinkError, SinkErrorClass, SinkType};

fn write_error(e: std::io::Error) -> RastreoError {
    RastreoError::Sink(SinkError::new(
        SinkErrorClass::WriteFailure,
        std::io::Error::new(e.kind(), format!("failed to write to stdout sink: {e}")),
    ))
}

fn flush_error(e: std::io::Error) -> RastreoError {
    RastreoError::Sink(SinkError::new(
        SinkErrorClass::FlushFailure,
        std::io::Error::new(e.kind(), format!("failed to flush stdout sink: {e}")),
    ))
}

pub struct StdoutSink {
    writer: BufWriter<Stdout>,
    delivered: bool,
}

impl StdoutSink {
    pub fn new() -> Self {
        Self {
            writer: BufWriter::new(tokio::io::stdout()),
            delivered: false,
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
        // write_all may drain the buffer to the fd when it fills, but not observably: only a successful flush proves the bytes left.
        self.delivered = false;
        self.writer.write_all(data).await.map_err(write_error)?;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        self.writer.flush().await.map_err(flush_error)?;
        self.delivered = true;
        Ok(())
    }

    fn last_write_delivered(&self) -> bool {
        self.delivered
    }

    fn kind(&self) -> SinkType {
        SinkType::Stdout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::sink_io_detail;

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

    #[tokio::test]
    async fn a_buffered_write_is_not_delivered_until_flush() {
        let mut sink = StdoutSink::new();
        assert!(!sink.last_write_delivered());
        sink.write(b"\n").await.expect("write");
        assert!(!sink.last_write_delivered());
        sink.flush().await.expect("flush");
        assert!(sink.last_write_delivered());
    }

    #[tokio::test]
    async fn a_write_after_a_flush_revokes_the_delivery_claim() {
        let mut sink = StdoutSink::new();
        sink.write(b"\n").await.expect("write");
        sink.flush().await.expect("flush");
        assert!(sink.last_write_delivered());
        sink.write(b"\n").await.expect("write");
        assert!(!sink.last_write_delivered());
    }

    #[test]
    fn stdout_sink_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<StdoutSink>();
        assert_send_sync::<Box<dyn Sink>>();
    }

    #[test]
    fn write_error_carries_write_failure_class_and_prefix() {
        let err = write_error(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Broken pipe",
        ));
        assert_eq!(err.sink_error_class(), Some(SinkErrorClass::WriteFailure));
        assert!(sink_io_detail(&err).contains("failed to write to stdout sink"));
    }

    #[test]
    fn flush_error_carries_flush_failure_class_and_prefix() {
        let err = flush_error(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Broken pipe",
        ));
        assert_eq!(err.sink_error_class(), Some(SinkErrorClass::FlushFailure));
        assert!(sink_io_detail(&err).contains("failed to flush stdout sink"));
    }
}
