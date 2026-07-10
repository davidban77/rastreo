use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::error::RastreoError;

use super::{Sink, SinkType};

/// A child of [`TeeSink`] — either an owned `Box<dyn Sink>` or a shared handle to one.
pub enum TeeChild {
    Owned(Box<dyn Sink>),
    Shared(Arc<Mutex<Box<dyn Sink>>>),
}

/// Fans every `write` / `flush` / `probe` call out to a fixed set of child sinks.
///
/// The first child to error aborts the fan-out and surfaces the error; remaining children
/// are not called for that record. `last_write_delivered` and `probe` follow the same
/// fail-close model — success requires every child to succeed.
pub struct TeeSink {
    children: Vec<TeeChild>,
    last_delivered: bool,
    // Per-TeeSink DLQ attribution: only writes issued through THIS Tee credit it,
    // so overlapping scans against a shared child never cross-credit each other.
    attribution: StdMutex<Vec<(SinkType, u64)>>,
}

impl TeeSink {
    pub fn new(children: Vec<TeeChild>) -> Self {
        Self {
            children,
            last_delivered: false,
            attribution: StdMutex::new(Vec::new()),
        }
    }
}

fn credit_attribution(bucket: &StdMutex<Vec<(SinkType, u64)>>, kind: SinkType, delta: u64) {
    let mut guard = bucket.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = guard.iter_mut().find(|(k, _)| *k == kind) {
        entry.1 = entry.1.saturating_add(delta);
    } else {
        guard.push((kind, delta));
    }
}

struct WriteAttribution {
    kind: SinkType,
    delta: u64,
    delivered: bool,
}

async fn write_child(child: &mut TeeChild, data: &[u8]) -> Result<WriteAttribution, RastreoError> {
    match child {
        TeeChild::Owned(sink) => {
            let before = sink.dlq_records_delivered();
            sink.write(data).await?;
            let after = sink.dlq_records_delivered();
            Ok(WriteAttribution {
                kind: sink.kind(),
                delta: after.saturating_sub(before),
                delivered: sink.last_write_delivered(),
            })
        }
        TeeChild::Shared(sink) => {
            let mut guard = sink.lock().await;
            let before = guard.dlq_records_delivered();
            guard.write(data).await?;
            let after = guard.dlq_records_delivered();
            Ok(WriteAttribution {
                kind: guard.kind(),
                delta: after.saturating_sub(before),
                delivered: guard.last_write_delivered(),
            })
        }
    }
}

async fn flush_child(child: &mut TeeChild) -> Result<(), RastreoError> {
    match child {
        TeeChild::Owned(sink) => sink.flush().await,
        TeeChild::Shared(sink) => sink.lock().await.flush().await,
    }
}

async fn probe_child(child: &TeeChild) -> Result<(), std::io::Error> {
    match child {
        TeeChild::Owned(sink) => sink.probe().await,
        TeeChild::Shared(sink) => sink.lock().await.probe().await,
    }
}

#[async_trait]
impl Sink for TeeSink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        let mut all_delivered = true;
        for child in &mut self.children {
            let WriteAttribution {
                kind,
                delta,
                delivered,
            } = write_child(child, data).await?;
            if delta > 0 {
                credit_attribution(&self.attribution, kind, delta);
            }
            all_delivered &= delivered;
        }
        self.last_delivered = all_delivered;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        for child in &mut self.children {
            flush_child(child).await?;
        }
        Ok(())
    }

    fn last_write_delivered(&self) -> bool {
        self.last_delivered
    }

    fn kind(&self) -> SinkType {
        SinkType::Tee
    }

    fn dlq_records_delivered(&self) -> u64 {
        let guard = self.attribution.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .fold(0u64, |acc, (_, c)| acc.saturating_add(*c))
    }

    fn dlq_records_by_type(&self) -> Vec<(SinkType, u64)> {
        let guard = self.attribution.lock().unwrap_or_else(|e| e.into_inner());
        guard.iter().filter(|(_, c)| *c > 0).copied().collect()
    }

    async fn probe(&self) -> Result<(), std::io::Error> {
        for child in &self.children {
            probe_child(child).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::MemorySink;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RecordingSink {
        writes: Arc<AtomicUsize>,
        flushes: Arc<AtomicUsize>,
        probes: Arc<AtomicUsize>,
        delivered: bool,
        dlq: u64,
        dlq_per_write: u64,
        kind: SinkType,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                writes: Arc::new(AtomicUsize::new(0)),
                flushes: Arc::new(AtomicUsize::new(0)),
                probes: Arc::new(AtomicUsize::new(0)),
                delivered: true,
                dlq: 0,
                dlq_per_write: 0,
                kind: SinkType::Memory,
            }
        }
    }

    #[async_trait]
    impl Sink for RecordingSink {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.dlq = self.dlq.saturating_add(self.dlq_per_write);
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            self.delivered
        }
        fn kind(&self) -> SinkType {
            self.kind
        }
        fn dlq_records_delivered(&self) -> u64 {
            self.dlq
        }
        async fn probe(&self) -> Result<(), io::Error> {
            self.probes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FailingWrite;

    #[async_trait]
    impl Sink for FailingWrite {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Err(RastreoError::Sink(io::Error::other("boom")))
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
    }

    struct FailingFlush;

    #[async_trait]
    impl Sink for FailingFlush {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Err(RastreoError::Sink(io::Error::other("flush failed")))
        }
    }

    struct FailingProbe(&'static str);

    #[async_trait]
    impl Sink for FailingProbe {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn probe(&self) -> Result<(), io::Error> {
            Err(io::Error::other(self.0))
        }
    }

    #[tokio::test]
    async fn tee_sink_kind_returns_tee() {
        let tee = TeeSink::new(Vec::new());
        assert_eq!(tee.kind(), SinkType::Tee);
    }

    #[tokio::test]
    async fn tee_sink_write_with_no_children_is_ok_and_delivered() {
        let mut tee = TeeSink::new(Vec::new());
        tee.write(b"x").await.expect("write");
        assert!(tee.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_sink_write_fans_out_to_owned_and_shared_children() {
        let owned = MemorySink::new();
        let owned_handle = owned.handle();

        let shared_inner: Box<dyn Sink> = Box::new(MemorySink::new());
        let shared = Arc::new(Mutex::new(shared_inner));

        let children = vec![
            TeeChild::Owned(Box::new(owned)),
            TeeChild::Shared(Arc::clone(&shared)),
        ];
        let mut tee = TeeSink::new(children);

        tee.write(b"payload\n").await.expect("write");
        tee.flush().await.expect("flush");

        assert_eq!(owned_handle.bytes(), b"payload\n");
        let guard = shared.lock().await;
        assert!(guard.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_sink_write_returns_first_error_and_stops() {
        let ok_recording = RecordingSink::new();
        let after_writes = Arc::clone(&ok_recording.writes);
        let children = vec![
            TeeChild::Owned(Box::new(FailingWrite)),
            TeeChild::Owned(Box::new(ok_recording)),
        ];
        let mut tee = TeeSink::new(children);
        let err = tee.write(b"x").await.expect_err("must error");
        assert!(matches!(err, RastreoError::Sink(_)));
        assert_eq!(after_writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tee_sink_flush_calls_flush_on_every_child() {
        let a = RecordingSink::new();
        let b = RecordingSink::new();
        let a_flushes = Arc::clone(&a.flushes);
        let b_flushes = Arc::clone(&b.flushes);
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(a)),
            TeeChild::Owned(Box::new(b)),
        ]);
        tee.flush().await.expect("flush");
        assert_eq!(a_flushes.load(Ordering::SeqCst), 1);
        assert_eq!(b_flushes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tee_sink_flush_returns_first_error_and_stops() {
        let after = RecordingSink::new();
        let after_flushes = Arc::clone(&after.flushes);
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingFlush)),
            TeeChild::Owned(Box::new(after)),
        ]);
        let err = tee.flush().await.expect_err("must error");
        assert!(matches!(err, RastreoError::Sink(_)));
        assert_eq!(after_flushes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tee_sink_probe_returns_ok_only_if_all_probe_ok() {
        let a = RecordingSink::new();
        let b = RecordingSink::new();
        let a_probes = Arc::clone(&a.probes);
        let b_probes = Arc::clone(&b.probes);
        let tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(a)),
            TeeChild::Owned(Box::new(b)),
        ]);
        tee.probe().await.expect("probe ok");
        assert_eq!(a_probes.load(Ordering::SeqCst), 1);
        assert_eq!(b_probes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tee_sink_probe_returns_first_probe_error() {
        let recording = RecordingSink::new();
        let recording_probes = Arc::clone(&recording.probes);
        let tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingProbe("no route"))),
            TeeChild::Owned(Box::new(recording)),
        ]);
        let err = tee.probe().await.expect_err("probe must fail");
        assert!(err.to_string().contains("no route"));
        assert_eq!(recording_probes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tee_sink_last_write_delivered_true_only_when_all_children_delivered() {
        let mut ok = RecordingSink::new();
        ok.delivered = true;
        let mut not_yet = RecordingSink::new();
        not_yet.delivered = false;

        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(ok)),
            TeeChild::Owned(Box::new(not_yet)),
        ]);
        tee.write(b"x").await.expect("write");
        assert!(!tee.last_write_delivered());

        let mut ok_a = RecordingSink::new();
        ok_a.delivered = true;
        let mut ok_b = RecordingSink::new();
        ok_b.delivered = true;
        let mut tee_ok = TeeSink::new(vec![
            TeeChild::Owned(Box::new(ok_a)),
            TeeChild::Owned(Box::new(ok_b)),
        ]);
        tee_ok.write(b"x").await.expect("write");
        assert!(tee_ok.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_sink_dlq_records_delivered_sums_writes_across_children() {
        let mut a = RecordingSink::new();
        a.dlq_per_write = 3;
        let mut b = RecordingSink::new();
        b.dlq_per_write = 4;
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(a)),
            TeeChild::Owned(Box::new(b)),
        ]);
        tee.write(b"x").await.expect("write");
        assert_eq!(tee.dlq_records_delivered(), 7);
    }

    #[tokio::test]
    async fn tee_sink_dlq_records_by_type_aggregates_writes_by_sink_type() {
        let mut a = RecordingSink::new();
        a.dlq_per_write = 3;
        a.kind = SinkType::Kafka;
        let mut b = RecordingSink::new();
        b.dlq_per_write = 5;
        b.kind = SinkType::Kafka;
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(a)),
            TeeChild::Owned(Box::new(b)),
        ]);
        tee.write(b"x").await.expect("write");
        let entries = tee.dlq_records_by_type();
        assert_eq!(entries, vec![(SinkType::Kafka, 8)]);
    }

    #[tokio::test]
    async fn tee_sink_dlq_records_by_type_reports_distinct_sink_types_separately() {
        let mut kafka_child = RecordingSink::new();
        kafka_child.dlq_per_write = 2;
        kafka_child.kind = SinkType::Kafka;
        let mut nats_child = RecordingSink::new();
        nats_child.dlq_per_write = 1;
        nats_child.kind = SinkType::Nats;
        let kafka_shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(kafka_child)));
        let nats_shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(nats_child)));
        let mut tee = TeeSink::new(vec![
            TeeChild::Shared(kafka_shared),
            TeeChild::Shared(nats_shared),
        ]);
        tee.write(b"x").await.expect("write");
        let mut entries = tee.dlq_records_by_type();
        entries.sort_by_key(|(k, _)| k.as_label());
        assert_eq!(entries, vec![(SinkType::Kafka, 2), (SinkType::Nats, 1)]);
    }

    #[tokio::test]
    async fn tee_sink_dlq_records_by_type_is_empty_when_no_writes_credited_dlq() {
        let mut a = RecordingSink::new();
        a.kind = SinkType::Kafka;
        let mut b = RecordingSink::new();
        b.kind = SinkType::Nats;
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(a)),
            TeeChild::Owned(Box::new(b)),
        ]);
        tee.write(b"x").await.expect("write");
        assert!(tee.dlq_records_by_type().is_empty());
    }

    #[tokio::test]
    async fn default_dlq_records_by_type_derives_from_kind_and_count() {
        let mut s = RecordingSink::new();
        s.dlq = 5;
        s.kind = SinkType::Kafka;
        assert_eq!(s.dlq_records_by_type(), vec![(SinkType::Kafka, 5)]);
    }

    #[tokio::test]
    async fn default_dlq_records_by_type_is_empty_when_count_is_zero() {
        let s = RecordingSink::new();
        assert!(s.dlq_records_by_type().is_empty());
    }

    #[tokio::test]
    async fn tee_sink_dlq_records_delivered_includes_writes_to_shared_children() {
        let mut owned = RecordingSink::new();
        owned.dlq_per_write = 2;
        let mut shared_inner = RecordingSink::new();
        shared_inner.dlq_per_write = 5;
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(shared_inner)));
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(owned)),
            TeeChild::Shared(shared),
        ]);
        tee.write(b"x").await.expect("write");
        assert_eq!(tee.dlq_records_delivered(), 7);
    }

    #[tokio::test]
    async fn tee_sink_dlq_attribution_only_credits_this_teesinks_writes() {
        let mut shared_inner = RecordingSink::new();
        shared_inner.dlq_per_write = 1;
        shared_inner.kind = SinkType::Kafka;
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(shared_inner)));

        let mut tee_a = TeeSink::new(vec![TeeChild::Shared(Arc::clone(&shared))]);
        let tee_b = TeeSink::new(vec![TeeChild::Shared(Arc::clone(&shared))]);

        tee_a.write(b"a").await.expect("write via A");

        assert_eq!(
            tee_a.dlq_records_by_type(),
            vec![(SinkType::Kafka, 1)],
            "A must observe the DLQ contribution of its own write",
        );
        assert!(
            tee_b.dlq_records_by_type().is_empty(),
            "B must not see A's write in its per-Tee attribution",
        );
        let guard = shared.lock().await;
        assert_eq!(guard.dlq_records_delivered(), 1);
    }

    #[tokio::test]
    async fn tee_sink_with_three_children_writes_to_all_of_them() {
        let a = MemorySink::new();
        let a_handle = a.handle();
        let b = MemorySink::new();
        let b_handle = b.handle();
        let c = MemorySink::new();
        let c_handle = c.handle();
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(a)),
            TeeChild::Owned(Box::new(b)),
            TeeChild::Owned(Box::new(c)),
        ]);
        tee.write(b"multi\n").await.expect("write");
        assert_eq!(a_handle.bytes(), b"multi\n");
        assert_eq!(b_handle.bytes(), b"multi\n");
        assert_eq!(c_handle.bytes(), b"multi\n");
    }

    #[tokio::test]
    async fn tee_sink_write_to_shared_child_visible_via_arc_after_lock() {
        let inner = MemorySink::new();
        let handle = inner.handle();
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(inner)));
        let mut tee = TeeSink::new(vec![TeeChild::Shared(Arc::clone(&shared))]);
        tee.write(b"via-shared\n").await.expect("write");
        assert_eq!(handle.bytes(), b"via-shared\n");
    }

    #[test]
    fn tee_sink_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<TeeSink>();
        assert_send_sync::<TeeChild>();
    }
}
