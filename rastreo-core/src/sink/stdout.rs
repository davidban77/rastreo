use tokio::io::{AsyncWriteExt, BufWriter, Stdout};

use crate::error::RastreoError;

use super::Sink;

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
        self.writer
            .write_all(data)
            .await
            .map_err(RastreoError::Sink)?;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        self.writer.flush().await.map_err(RastreoError::Sink)?;
        Ok(())
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
}
