use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::error::RastreoError;

use super::{Sink, SinkType};

#[derive(Debug, Default)]
struct Inner {
    buffer: Mutex<Vec<u8>>,
    delivered: AtomicBool,
    truncated: AtomicBool,
    max_bytes: Option<usize>,
}

#[derive(Debug, Default)]
pub struct MemorySink {
    inner: Arc<Inner>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    /// A `MemorySink` that drops any write which would push the buffer past `max_bytes`,
    /// flagging [`MemorySinkHandle::truncated`] instead of growing unbounded.
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                max_bytes: Some(max_bytes),
                ..Default::default()
            }),
        }
    }

    /// Cheap clone that observes writes after the sink has been moved into a
    /// `Box<dyn Sink>` and handed off to a runner.
    pub fn handle(&self) -> MemorySinkHandle {
        MemorySinkHandle {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemorySinkHandle {
    inner: Arc<Inner>,
}

impl MemorySinkHandle {
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.buffer.lock().expect("memory sink mutex").clone()
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
        self.inner.delivered.load(Ordering::SeqCst)
    }

    pub fn truncated(&self) -> bool {
        self.inner.truncated.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Sink for MemorySink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        let mut buffer = self.inner.buffer.lock().expect("memory sink mutex");
        if let Some(max) = self.inner.max_bytes {
            // Drop the whole write rather than erroring so the scan still completes; each write is one NDJSON record, so skipping keeps the buffer whole lines under the cap.
            if buffer.len() + data.len() > max {
                self.inner.truncated.store(true, Ordering::SeqCst);
                return Ok(());
            }
        }
        buffer.extend_from_slice(data);
        self.inner.delivered.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        // No-op: writes are eagerly visible via the handle.
        Ok(())
    }

    fn last_write_delivered(&self) -> bool {
        self.inner.delivered.load(Ordering::SeqCst)
    }

    fn kind(&self) -> SinkType {
        SinkType::Memory
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

    #[tokio::test]
    async fn new_is_unbounded_and_never_truncates() {
        let mut sink = MemorySink::new();
        let handle = sink.handle();
        let record = vec![b'x'; 10_000];
        for _ in 0..100 {
            sink.write(&record).await.expect("write");
        }
        assert_eq!(handle.bytes().len(), 1_000_000);
        assert!(!handle.truncated());
    }

    #[tokio::test]
    async fn with_max_bytes_appends_writes_that_fit() {
        let mut sink = MemorySink::with_max_bytes(100);
        let handle = sink.handle();
        sink.write(b"{\"a\":1}\n").await.expect("write");
        sink.write(b"{\"b\":2}\n").await.expect("write");
        assert_eq!(handle.bytes(), b"{\"a\":1}\n{\"b\":2}\n");
        assert!(!handle.truncated());
    }

    #[tokio::test]
    async fn with_max_bytes_allows_write_that_exactly_reaches_cap() {
        let mut sink = MemorySink::with_max_bytes(8);
        let handle = sink.handle();
        sink.write(b"{\"a\":1}\n").await.expect("write"); // exactly 8 bytes
        assert_eq!(handle.bytes().len(), 8);
        assert!(!handle.truncated());
    }

    #[tokio::test]
    async fn with_max_bytes_skips_a_single_write_larger_than_cap() {
        let mut sink = MemorySink::with_max_bytes(4);
        let handle = sink.handle();
        sink.write(b"{\"a\":1}\n").await.expect("write");
        assert!(
            handle.bytes().is_empty(),
            "an over-cap first write leaves the buffer empty, never a partial line"
        );
        assert!(handle.truncated());
    }

    #[tokio::test]
    async fn with_max_bytes_never_exceeds_cap_and_stays_valid_ndjson() {
        let cap = 40;
        let mut sink = MemorySink::with_max_bytes(cap);
        let handle = sink.handle();
        for i in 0..1000 {
            let line = format!("{{\"n\":{i}}}\n");
            sink.write(line.as_bytes()).await.expect("write");
        }
        let bytes = handle.bytes();
        assert!(
            bytes.len() <= cap,
            "buffer {} exceeded cap {cap}",
            bytes.len()
        );
        assert!(handle.truncated(), "over-cap writes must flag truncation");
        let lines = handle.ndjson_lines();
        assert!(!lines.is_empty(), "records under the cap must still land");
        for line in lines {
            let _: serde_json::Value =
                serde_json::from_str(&line).expect("each retained line is complete valid JSON");
        }
    }
}
