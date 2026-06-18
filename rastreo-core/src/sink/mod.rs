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
pub enum SinkConfig {}

pub async fn create_sink(config: &SinkConfig) -> Result<Box<dyn Sink>, RastreoError> {
    match *config {}
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
}
