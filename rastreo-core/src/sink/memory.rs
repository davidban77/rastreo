use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::error::RastreoError;

use super::Sink;

#[derive(Debug, Clone, Default)]
pub struct MemorySink {
    inner: Arc<Mutex<Vec<u8>>>,
    last_write_delivered: Arc<Mutex<bool>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cheap clone that observes writes after the sink has been moved into a
    /// `Box<dyn Sink>` and handed off to a runner.
    pub fn handle(&self) -> MemorySinkHandle {
        MemorySinkHandle {
            inner: Arc::clone(&self.inner),
            last_write_delivered: Arc::clone(&self.last_write_delivered),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemorySinkHandle {
    inner: Arc<Mutex<Vec<u8>>>,
    last_write_delivered: Arc<Mutex<bool>>,
}

impl MemorySinkHandle {
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.lock().expect("memory sink mutex").clone()
    }

    pub fn ndjson_lines(&self) -> Vec<String> {
        let bytes = self.bytes();
        String::from_utf8_lossy(&bytes)
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    pub fn last_write_delivered(&self) -> bool {
        *self.last_write_delivered.lock().expect("memory sink mutex")
    }
}

#[async_trait]
impl Sink for MemorySink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.inner
            .lock()
            .expect("memory sink mutex")
            .extend_from_slice(data);
        *self.last_write_delivered.lock().expect("memory sink mutex") = true;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        // No-op: writes are eagerly visible via the handle.
        Ok(())
    }

    fn last_write_delivered(&self) -> bool {
        *self.last_write_delivered.lock().expect("memory sink mutex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_sink_captures_writes() {
        let mut sink = MemorySink::new();
        let handle = sink.handle();
        sink.write(b"foo").await.expect("write foo");
        sink.write(b"bar").await.expect("write bar");
        assert_eq!(handle.bytes(), b"foobar");
    }

    #[tokio::test]
    async fn memory_sink_ndjson_lines_splits_on_newline() {
        let mut sink = MemorySink::new();
        let handle = sink.handle();
        sink.write(b"{\"a\":1}\n{\"b\":2}\n")
            .await
            .expect("write ndjson");
        let lines = handle.ndjson_lines();
        assert_eq!(
            lines,
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()]
        );
    }

    #[tokio::test]
    async fn memory_sink_handle_observes_writes_after_box_dyn_handoff() {
        let sink = MemorySink::new();
        let handle = sink.handle();
        let mut boxed: Box<dyn Sink> = Box::new(sink);
        boxed.write(b"through box").await.expect("write");
        boxed.flush().await.expect("flush");
        assert_eq!(handle.bytes(), b"through box");
    }

    #[tokio::test]
    async fn memory_sink_last_write_delivered_starts_false_then_true() {
        let mut sink = MemorySink::new();
        let handle = sink.handle();
        assert!(!sink.last_write_delivered());
        assert!(!handle.last_write_delivered());
        sink.write(b"x").await.expect("write");
        assert!(sink.last_write_delivered());
        assert!(handle.last_write_delivered());
    }

    #[test]
    fn memory_sink_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<MemorySink>();
        assert_send_sync::<MemorySinkHandle>();
        assert_send_sync::<Box<dyn Sink>>();
    }
}
