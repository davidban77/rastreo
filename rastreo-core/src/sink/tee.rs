use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::error::RastreoError;

use super::{RecordKind, Sink, SinkErrorClass, SinkType, SINK_ERROR_CLASS_COUNT};

/// A child of [`TeeSink`] — either an owned `Box<dyn Sink>` or a shared handle to one.
pub enum TeeChild {
    Owned(Box<dyn Sink>),
    Shared(Arc<Mutex<Box<dyn Sink>>>),
}

type ClassDeltas = [u64; SINK_ERROR_CLASS_COUNT];

/// Fans every `write` / `write_kind` / `flush` / `close` / `probe` call out to a fixed set of child
/// sinks.
///
/// `write` and `write_kind` stop at the first child error. `flush` and `close` attempt every child
/// and return the first error, so a failing destination never strands what a healthy one already
/// holds. Whatever the call, a child is credited for the DLQ records it landed before failing.
/// `last_write_delivered` and `probe` are fail-close — success requires every child to succeed.
pub struct TeeSink {
    children: Vec<TeeChild>,
    last_delivered: bool,
    // Per-TeeSink DLQ attribution: only writes issued through THIS Tee credit it,
    // so overlapping scans against a shared child never cross-credit each other.
    attribution: StdMutex<Vec<(SinkType, SinkErrorClass, u64)>>,
}

impl TeeSink {
    pub fn new(children: Vec<TeeChild>) -> Self {
        Self {
            children,
            last_delivered: false,
            attribution: StdMutex::new(Vec::new()),
        }
    }

    async fn fan_out(&mut self, call: Fanout<'_>) -> Result<(), RastreoError> {
        self.last_delivered = false;
        let mut all_delivered = true;
        let mut first_error: Option<RastreoError> = None;
        for child in &mut self.children {
            let (attribution, error) = fanout_child(child, call).await;
            credit_attribution(&self.attribution, attribution.kind, &attribution.deltas);
            all_delivered &= attribution.delivered;
            let abort = error.is_some() && call.aborts_on_child_error();
            first_error = first_error.or(error);
            if abort {
                break;
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => {
                self.last_delivered = all_delivered;
                Ok(())
            }
        }
    }
}

fn class_deltas(before: ClassDeltas, after: ClassDeltas) -> ClassDeltas {
    std::array::from_fn(|i| after[i].saturating_sub(before[i]))
}

fn credit_attribution(
    bucket: &StdMutex<Vec<(SinkType, SinkErrorClass, u64)>>,
    kind: SinkType,
    deltas: &ClassDeltas,
) {
    let mut guard = bucket.lock().unwrap_or_else(|e| e.into_inner());
    for class in SinkErrorClass::all() {
        let delta = deltas[class.index()];
        if delta == 0 {
            continue;
        }
        if let Some(entry) = guard.iter_mut().find(|(k, c, _)| *k == kind && c == class) {
            entry.2 = entry.2.saturating_add(delta);
        } else {
            guard.push((kind, *class, delta));
        }
    }
}

struct ChildAttribution {
    kind: SinkType,
    deltas: ClassDeltas,
    delivered: bool,
}

#[derive(Clone, Copy)]
enum Fanout<'a> {
    Write(&'a [u8]),
    WriteKind(RecordKind, &'a [u8]),
    Flush,
    Close,
}

impl Fanout<'_> {
    fn aborts_on_child_error(self) -> bool {
        match self {
            Fanout::Write(_) | Fanout::WriteKind(_, _) => true,
            Fanout::Flush | Fanout::Close => false,
        }
    }
}

async fn fanout_sink(
    sink: &mut dyn Sink,
    call: Fanout<'_>,
) -> (ChildAttribution, Option<RastreoError>) {
    let before = sink.dlq_records_by_class();
    let error = match call {
        Fanout::Write(data) => sink.write(data).await.err(),
        Fanout::WriteKind(kind, data) => sink.write_kind(kind, data).await.err(),
        Fanout::Flush => sink.flush().await.err(),
        Fanout::Close => sink.close().await.err(),
    };
    let after = sink.dlq_records_by_class();
    let attribution = ChildAttribution {
        kind: sink.kind(),
        deltas: class_deltas(before, after),
        delivered: sink.last_write_delivered(),
    };
    (attribution, error)
}

async fn fanout_child(
    child: &mut TeeChild,
    call: Fanout<'_>,
) -> (ChildAttribution, Option<RastreoError>) {
    match child {
        TeeChild::Owned(sink) => fanout_sink(sink.as_mut(), call).await,
        TeeChild::Shared(sink) => {
            let mut guard = sink.lock().await;
            fanout_sink(guard.as_mut(), call).await
        }
    }
}

async fn probe_child(child: &TeeChild) -> Result<(), std::io::Error> {
    match child {
        TeeChild::Owned(sink) => sink.probe().await,
        TeeChild::Shared(sink) => sink.lock().await.probe().await,
    }
}

async fn child_requires_structured_records(child: &TeeChild) -> bool {
    match child {
        TeeChild::Owned(sink) => sink.requires_structured_records().await,
        TeeChild::Shared(sink) => sink.lock().await.requires_structured_records().await,
    }
}

#[async_trait]
impl Sink for TeeSink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.fan_out(Fanout::Write(data)).await
    }

    async fn write_kind(&mut self, kind: RecordKind, data: &[u8]) -> Result<(), RastreoError> {
        self.fan_out(Fanout::WriteKind(kind, data)).await
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        self.fan_out(Fanout::Flush).await
    }

    async fn close(&mut self) -> Result<(), RastreoError> {
        self.fan_out(Fanout::Close).await
    }

    fn last_write_delivered(&self) -> bool {
        self.last_delivered
    }

    fn kind(&self) -> SinkType {
        SinkType::Tee
    }

    async fn requires_structured_records(&self) -> bool {
        for child in &self.children {
            if child_requires_structured_records(child).await {
                return true;
            }
        }
        false
    }

    fn dlq_records_delivered(&self) -> u64 {
        let guard = self.attribution.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .fold(0u64, |acc, (_, _, c)| acc.saturating_add(*c))
    }

    fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
        let guard = self.attribution.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = [0u64; SINK_ERROR_CLASS_COUNT];
        for (_, class, count) in guard.iter() {
            let slot = &mut out[class.index()];
            *slot = slot.saturating_add(*count);
        }
        out
    }

    fn dlq_records_by_type_and_class(&self) -> Vec<(SinkType, SinkErrorClass, u64)> {
        let guard = self.attribution.lock().unwrap_or_else(|e| e.into_inner());
        guard.iter().filter(|(_, _, c)| *c > 0).copied().collect()
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
        closes: Arc<AtomicUsize>,
        probes: Arc<AtomicUsize>,
        delivered: bool,
        dlq: u64,
        dlq_per_write: u64,
        dlq_on_flush: u64,
        dlq_on_close: u64,
        dlq_class: SinkErrorClass,
        kind: SinkType,
        fail_write: bool,
        fail_flush: bool,
        fail_close: bool,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                writes: Arc::new(AtomicUsize::new(0)),
                flushes: Arc::new(AtomicUsize::new(0)),
                closes: Arc::new(AtomicUsize::new(0)),
                probes: Arc::new(AtomicUsize::new(0)),
                delivered: true,
                dlq: 0,
                dlq_per_write: 0,
                dlq_on_flush: 0,
                dlq_on_close: 0,
                dlq_class: SinkErrorClass::ProduceFailure,
                kind: SinkType::Memory,
                fail_write: false,
                fail_flush: false,
                fail_close: false,
            }
        }
    }

    #[async_trait]
    impl Sink for RecordingSink {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.dlq = self.dlq.saturating_add(self.dlq_per_write);
            if self.fail_write {
                return Err(sink_err(SinkErrorClass::WriteFailure, "recording write"));
            }
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            self.dlq = self.dlq.saturating_add(self.dlq_on_flush);
            if self.fail_flush {
                return Err(sink_err(SinkErrorClass::FlushFailure, "recording flush"));
            }
            Ok(())
        }
        async fn close(&mut self) -> Result<(), RastreoError> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            self.dlq = self.dlq.saturating_add(self.dlq_on_close);
            if self.fail_close {
                return Err(sink_err(SinkErrorClass::FlushFailure, "recording close"));
            }
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
        fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
            let mut out = [0u64; SINK_ERROR_CLASS_COUNT];
            out[self.dlq_class.index()] = self.dlq;
            out
        }
        async fn probe(&self) -> Result<(), io::Error> {
            self.probes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn sink_err(class: SinkErrorClass, msg: &str) -> RastreoError {
        RastreoError::Sink(crate::sink::SinkError::new(class, io::Error::other(msg)))
    }

    struct FailingWrite;

    #[async_trait]
    impl Sink for FailingWrite {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Err(sink_err(SinkErrorClass::WriteFailure, "boom"))
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            false
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    struct FailingFlush(&'static str);

    #[async_trait]
    impl Sink for FailingFlush {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Err(sink_err(SinkErrorClass::FlushFailure, self.0))
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    struct FailingClose(&'static str);

    #[async_trait]
    impl Sink for FailingClose {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn close(&mut self) -> Result<(), RastreoError> {
            Err(sink_err(SinkErrorClass::FlushFailure, self.0))
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
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
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
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

    struct FailsAfterFirstWrite {
        writes: usize,
    }

    #[async_trait]
    impl Sink for FailsAfterFirstWrite {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            self.writes += 1;
            if self.writes > 1 {
                return Err(sink_err(SinkErrorClass::WriteFailure, "boom"));
            }
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    #[tokio::test]
    async fn tee_write_failure_revokes_the_delivery_claim_an_earlier_write_earned() {
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(RecordingSink::new())),
            TeeChild::Owned(Box::new(FailsAfterFirstWrite { writes: 0 })),
        ]);
        tee.write(b"first").await.expect("write");
        assert!(tee.last_write_delivered());

        tee.write(b"second").await.expect_err("must error");
        assert!(!tee.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_write_kind_failure_revokes_the_delivery_claim_an_earlier_write_earned() {
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(RecordingSink::new())),
            TeeChild::Owned(Box::new(FailsAfterFirstWrite { writes: 0 })),
        ]);
        tee.write_kind(RecordKind::Link, b"first")
            .await
            .expect("write");
        assert!(tee.last_write_delivered());

        tee.write_kind(RecordKind::Link, b"second")
            .await
            .expect_err("must error");
        assert!(!tee.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_write_credits_dlq_a_child_landed_before_its_write_failed() {
        let mut failing = RecordingSink::new();
        failing.fail_write = true;
        failing.dlq_per_write = 3;
        failing.kind = SinkType::Nats;
        failing.dlq_class = SinkErrorClass::PublishFailure;
        let mut tee = TeeSink::new(vec![TeeChild::Owned(Box::new(failing))]);

        tee.write(b"x").await.expect_err("must error");
        assert_eq!(
            tee.dlq_records_by_type_and_class(),
            vec![(SinkType::Nats, SinkErrorClass::PublishFailure, 3)]
        );
    }

    #[tokio::test]
    async fn tee_write_kind_credits_dlq_a_child_landed_before_its_write_failed() {
        let mut failing = RecordingSink::new();
        failing.fail_write = true;
        failing.dlq_per_write = 2;
        failing.kind = SinkType::Kafka;
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(failing)));
        let mut tee = TeeSink::new(vec![TeeChild::Shared(shared)]);

        tee.write_kind(RecordKind::CollectionProfile, b"x")
            .await
            .expect_err("must error");
        assert_eq!(
            tee.dlq_records_by_type_and_class(),
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 2)]
        );
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
    async fn tee_sink_flush_returns_an_error_after_flushing_every_later_child() {
        let after = RecordingSink::new();
        let after_flushes = Arc::clone(&after.flushes);
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingFlush("boom"))),
            TeeChild::Owned(Box::new(after)),
        ]);
        let err = tee.flush().await.expect_err("must error");
        assert!(matches!(err, RastreoError::Sink(_)));
        assert_eq!(after_flushes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tee_sink_flush_returns_the_error_of_the_first_child_that_failed() {
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingFlush("first child"))),
            TeeChild::Owned(Box::new(FailingFlush("second child"))),
        ]);
        let err = tee.flush().await.expect_err("must error");
        assert_eq!(crate::sink::sink_io_detail(&err), "first child");
    }

    #[tokio::test]
    async fn tee_flush_puts_a_healthy_childs_bytes_on_disk_though_an_earlier_child_failed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("healthy-flush.ndjson");
        let file = crate::sink::FileSink::new(&path).await.expect("file child");
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingFlush("boom"))),
            TeeChild::Owned(Box::new(file)),
        ]);

        tee.write(b"kept\n").await.expect("write");
        tee.flush().await.expect_err("the first child fails");

        assert_eq!(std::fs::read(&path).expect("read"), b"kept\n");
    }

    #[tokio::test]
    async fn tee_flush_failure_revokes_the_delivery_claim_even_when_children_claim_delivery() {
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingFlush("boom"))),
            TeeChild::Owned(Box::new(RecordingSink::new())),
        ]);
        tee.write(b"x").await.expect("write");
        assert!(tee.last_write_delivered());

        tee.flush().await.expect_err("must error");
        assert!(!tee.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_flush_credits_dlq_a_child_landed_before_its_flush_failed() {
        let mut failing = RecordingSink::new();
        failing.fail_flush = true;
        failing.dlq_on_flush = 3;
        failing.kind = SinkType::Kafka;
        let mut tee = TeeSink::new(vec![TeeChild::Owned(Box::new(failing))]);

        tee.flush().await.expect_err("must error");
        assert_eq!(tee.dlq_records_delivered(), 3);
    }

    #[tokio::test]
    async fn tee_flush_credits_dlq_a_later_child_landed_after_an_earlier_one_failed() {
        let mut healthy = RecordingSink::new();
        healthy.dlq_on_flush = 2;
        healthy.kind = SinkType::Nats;
        healthy.dlq_class = SinkErrorClass::PublishFailure;
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingFlush("boom"))),
            TeeChild::Owned(Box::new(healthy)),
        ]);

        tee.flush().await.expect_err("must error");
        assert_eq!(
            tee.dlq_records_by_type_and_class(),
            vec![(SinkType::Nats, SinkErrorClass::PublishFailure, 2)]
        );
    }

    #[tokio::test]
    async fn tee_sink_close_fans_out_close_to_every_child() {
        let a = RecordingSink::new();
        let b = RecordingSink::new();
        let a_closes = Arc::clone(&a.closes);
        let a_flushes = Arc::clone(&a.flushes);
        let b_closes = Arc::clone(&b.closes);
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(a)),
            TeeChild::Owned(Box::new(b)),
        ]);
        tee.close().await.expect("close");
        assert_eq!(a_closes.load(Ordering::SeqCst), 1);
        assert_eq!(b_closes.load(Ordering::SeqCst), 1);
        assert_eq!(
            a_flushes.load(Ordering::SeqCst),
            0,
            "close must call the child's close(), not flush()"
        );
    }

    #[tokio::test]
    async fn tee_sink_close_fans_out_to_shared_children() {
        let shared_inner = RecordingSink::new();
        let shared_closes = Arc::clone(&shared_inner.closes);
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(shared_inner)));
        let mut tee = TeeSink::new(vec![TeeChild::Shared(shared)]);
        tee.close().await.expect("close");
        assert_eq!(shared_closes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tee_sink_close_returns_an_error_after_closing_every_later_child() {
        let after = RecordingSink::new();
        let after_closes = Arc::clone(&after.closes);
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingClose("boom"))),
            TeeChild::Owned(Box::new(after)),
        ]);
        let err = tee.close().await.expect_err("must error");
        assert!(matches!(err, RastreoError::Sink(_)));
        assert_eq!(after_closes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tee_sink_close_returns_the_error_of_the_first_child_that_failed() {
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingClose("first child"))),
            TeeChild::Owned(Box::new(FailingClose("second child"))),
        ]);
        let err = tee.close().await.expect_err("must error");
        assert_eq!(crate::sink::sink_io_detail(&err), "first child");
    }

    #[tokio::test]
    async fn tee_close_puts_a_healthy_childs_bytes_on_disk_though_an_earlier_child_failed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("healthy-close.ndjson");
        let file = crate::sink::FileSink::new(&path).await.expect("file child");
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingClose("boom"))),
            TeeChild::Owned(Box::new(file)),
        ]);

        tee.write(b"kept\n").await.expect("write");
        tee.close().await.expect_err("the first child fails");

        assert_eq!(std::fs::read(&path).expect("read"), b"kept\n");
    }

    #[tokio::test]
    async fn tee_close_failure_revokes_the_delivery_claim_even_when_children_claim_delivery() {
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingClose("boom"))),
            TeeChild::Owned(Box::new(RecordingSink::new())),
        ]);
        tee.write(b"x").await.expect("write");
        assert!(tee.last_write_delivered());

        tee.close().await.expect_err("must error");
        assert!(!tee.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_close_credits_dlq_a_child_landed_before_its_close_failed() {
        let mut failing = RecordingSink::new();
        failing.fail_close = true;
        failing.dlq_on_close = 4;
        failing.kind = SinkType::Kafka;
        let mut tee = TeeSink::new(vec![TeeChild::Owned(Box::new(failing))]);

        tee.close().await.expect_err("must error");
        assert_eq!(tee.dlq_records_delivered(), 4);
    }

    #[tokio::test]
    async fn tee_close_credits_dlq_a_later_child_landed_after_an_earlier_one_failed() {
        let mut healthy = RecordingSink::new();
        healthy.dlq_on_close = 5;
        healthy.kind = SinkType::Kafka;
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingClose("boom"))),
            TeeChild::Owned(Box::new(healthy)),
        ]);

        tee.close().await.expect_err("must error");
        assert_eq!(
            tee.dlq_records_by_type_and_class(),
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 5)]
        );
    }

    #[tokio::test]
    async fn tee_flush_reaches_a_shared_child_behind_a_failing_owned_one() {
        let recording = RecordingSink::new();
        let flushes = Arc::clone(&recording.flushes);
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(recording)));
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingFlush("boom"))),
            TeeChild::Shared(shared),
        ]);

        tee.flush().await.expect_err("must error");
        assert_eq!(flushes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tee_close_reaches_a_shared_child_behind_a_failing_owned_one() {
        let recording = RecordingSink::new();
        let closes = Arc::clone(&recording.closes);
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(recording)));
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(FailingClose("boom"))),
            TeeChild::Shared(shared),
        ]);

        tee.close().await.expect_err("must error");
        assert_eq!(closes.load(Ordering::SeqCst), 1);
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
    async fn tee_flush_restores_the_claim_a_buffering_child_revoked_on_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = crate::sink::FileSink::new(dir.path().join("tee-flush.ndjson"))
            .await
            .expect("file child");
        let mut tee = TeeSink::new(vec![TeeChild::Owned(Box::new(file))]);

        tee.write(b"x\n").await.expect("write");
        assert!(!tee.last_write_delivered());

        tee.flush().await.expect("flush");
        assert!(
            tee.last_write_delivered(),
            "the child put the bytes on disk, so the tee's claim is restored"
        );
    }

    #[tokio::test]
    async fn tee_close_restores_the_claim_a_buffering_child_revoked_on_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = crate::sink::FileSink::new(dir.path().join("tee-close.ndjson"))
            .await
            .expect("file child");
        let mut tee = TeeSink::new(vec![TeeChild::Owned(Box::new(file))]);

        tee.write(b"x\n").await.expect("write");
        assert!(!tee.last_write_delivered());

        tee.close().await.expect("close");
        assert!(tee.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_flush_keeps_the_claim_false_while_one_child_still_withholds() {
        let mut withholding = RecordingSink::new();
        withholding.delivered = false;
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(RecordingSink::new())),
            TeeChild::Owned(Box::new(withholding)),
        ]);
        tee.write(b"x").await.expect("write");
        tee.flush().await.expect("flush");
        assert!(!tee.last_write_delivered());
    }

    #[tokio::test]
    async fn tee_flush_recomputes_the_claim_over_shared_children() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = crate::sink::FileSink::new(dir.path().join("tee-shared.ndjson"))
            .await
            .expect("file child");
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(file)));
        let mut tee = TeeSink::new(vec![TeeChild::Shared(shared)]);

        tee.write(b"x\n").await.expect("write");
        assert!(!tee.last_write_delivered());

        tee.flush().await.expect("flush");
        assert!(tee.last_write_delivered());
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
    async fn tee_sink_dlq_records_by_type_and_class_aggregates_writes_by_sink_type() {
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
        let entries = tee.dlq_records_by_type_and_class();
        assert_eq!(
            entries,
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 8)]
        );
    }

    #[tokio::test]
    async fn tee_sink_dlq_records_by_type_and_class_reports_distinct_sink_types_separately() {
        let mut kafka_child = RecordingSink::new();
        kafka_child.dlq_per_write = 2;
        kafka_child.kind = SinkType::Kafka;
        kafka_child.dlq_class = SinkErrorClass::ProduceFailure;
        let mut nats_child = RecordingSink::new();
        nats_child.dlq_per_write = 1;
        nats_child.kind = SinkType::Nats;
        nats_child.dlq_class = SinkErrorClass::PublishFailure;
        let kafka_shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(kafka_child)));
        let nats_shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(nats_child)));
        let mut tee = TeeSink::new(vec![
            TeeChild::Shared(kafka_shared),
            TeeChild::Shared(nats_shared),
        ]);
        tee.write(b"x").await.expect("write");
        let mut entries = tee.dlq_records_by_type_and_class();
        entries.sort_by_key(|(k, _, _)| k.as_label());
        assert_eq!(
            entries,
            vec![
                (SinkType::Kafka, SinkErrorClass::ProduceFailure, 2),
                (SinkType::Nats, SinkErrorClass::PublishFailure, 1),
            ]
        );
    }

    #[tokio::test]
    async fn tee_sink_dlq_by_type_and_class_keeps_publish_and_ack_distinct_for_one_type() {
        let mut publish_child = RecordingSink::new();
        publish_child.dlq_per_write = 2;
        publish_child.kind = SinkType::Nats;
        publish_child.dlq_class = SinkErrorClass::PublishFailure;
        let mut ack_child = RecordingSink::new();
        ack_child.dlq_per_write = 1;
        ack_child.kind = SinkType::Nats;
        ack_child.dlq_class = SinkErrorClass::AckRejection;
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(publish_child)),
            TeeChild::Owned(Box::new(ack_child)),
        ]);
        tee.write(b"x").await.expect("write");
        let mut entries = tee.dlq_records_by_type_and_class();
        entries.sort_by_key(|(_, c, _)| c.index());
        assert_eq!(
            entries,
            vec![
                (SinkType::Nats, SinkErrorClass::PublishFailure, 2),
                (SinkType::Nats, SinkErrorClass::AckRejection, 1),
            ]
        );
    }

    #[tokio::test]
    async fn tee_sink_dlq_records_by_type_and_class_is_empty_when_no_writes_credited_dlq() {
        let mut a = RecordingSink::new();
        a.kind = SinkType::Kafka;
        let mut b = RecordingSink::new();
        b.kind = SinkType::Nats;
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(a)),
            TeeChild::Owned(Box::new(b)),
        ]);
        tee.write(b"x").await.expect("write");
        assert!(tee.dlq_records_by_type_and_class().is_empty());
    }

    #[tokio::test]
    async fn default_dlq_records_by_type_and_class_derives_from_kind_and_count() {
        let mut s = RecordingSink::new();
        s.dlq = 5;
        s.kind = SinkType::Kafka;
        assert_eq!(
            s.dlq_records_by_type_and_class(),
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 5)]
        );
    }

    #[tokio::test]
    async fn default_dlq_records_by_type_and_class_is_empty_when_count_is_zero() {
        let s = RecordingSink::new();
        assert!(s.dlq_records_by_type_and_class().is_empty());
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
            tee_a.dlq_records_by_type_and_class(),
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 1)],
            "A must observe the DLQ contribution of its own write",
        );
        assert!(
            tee_b.dlq_records_by_type_and_class().is_empty(),
            "B must not see A's write in its per-Tee attribution",
        );
        let guard = shared.lock().await;
        assert_eq!(guard.dlq_records_delivered(), 1);
    }

    #[tokio::test]
    async fn tee_sink_credits_child_dlq_landing_during_close() {
        let mut batched = RecordingSink::new();
        batched.dlq_on_close = 4;
        batched.kind = SinkType::Kafka;
        let mut tee = TeeSink::new(vec![TeeChild::Owned(Box::new(batched))]);

        tee.write(b"buffered\n").await.expect("write");
        assert_eq!(tee.dlq_records_delivered(), 0, "batch not yet published");

        tee.close().await.expect("close");
        assert_eq!(tee.dlq_records_delivered(), 4);
        assert_eq!(
            tee.dlq_records_by_type_and_class(),
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 4)]
        );
    }

    #[tokio::test]
    async fn tee_sink_credits_child_dlq_landing_during_flush() {
        let mut batched = RecordingSink::new();
        batched.dlq_on_flush = 3;
        batched.kind = SinkType::Kafka;
        let mut tee = TeeSink::new(vec![TeeChild::Owned(Box::new(batched))]);

        tee.write(b"buffered\n").await.expect("write");
        assert_eq!(tee.dlq_records_delivered(), 0, "batch not yet published");

        tee.flush().await.expect("flush");
        assert_eq!(tee.dlq_records_delivered(), 3);
        assert_eq!(
            tee.dlq_records_by_type_and_class(),
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 3)]
        );
    }

    #[tokio::test]
    async fn tee_sink_credits_shared_child_dlq_landing_during_close() {
        let mut batched = RecordingSink::new();
        batched.dlq_on_close = 2;
        batched.kind = SinkType::Nats;
        batched.dlq_class = SinkErrorClass::PublishFailure;
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(batched)));
        let mut tee = TeeSink::new(vec![TeeChild::Shared(shared)]);

        tee.close().await.expect("close");
        assert_eq!(tee.dlq_records_delivered(), 2);
        assert_eq!(
            tee.dlq_records_by_type_and_class(),
            vec![(SinkType::Nats, SinkErrorClass::PublishFailure, 2)]
        );
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

    struct StructuredOnlySink;

    #[async_trait]
    impl Sink for StructuredOnlySink {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        // A local kind under a structured answer, so the tee must OR children's answers, not their kinds.
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
        async fn requires_structured_records(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn tee_sink_with_no_children_does_not_require_structured_records() {
        let tee = TeeSink::new(Vec::new());
        assert!(!tee.requires_structured_records().await);
    }

    #[tokio::test]
    async fn tee_sink_of_plain_children_does_not_require_structured_records() {
        let tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(MemorySink::new())),
            TeeChild::Shared(Arc::new(Mutex::new(
                Box::new(MemorySink::new()) as Box<dyn Sink>
            ))),
        ]);
        assert!(!tee.requires_structured_records().await);
    }

    #[tokio::test]
    async fn one_structured_owned_child_makes_the_whole_tee_structured() {
        let tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(MemorySink::new())),
            TeeChild::Owned(Box::new(StructuredOnlySink)),
        ]);
        assert!(tee.requires_structured_records().await);
    }

    #[tokio::test]
    async fn one_structured_shared_child_makes_the_whole_tee_structured() {
        let shared: Arc<Mutex<Box<dyn Sink>>> = Arc::new(Mutex::new(Box::new(StructuredOnlySink)));
        let tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(MemorySink::new())),
            TeeChild::Shared(shared),
        ]);
        assert!(tee.requires_structured_records().await);
    }

    #[test]
    fn tee_sink_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<TeeSink>();
        assert_send_sync::<TeeChild>();
    }

    struct KindRecordingSink {
        kinds: Arc<std::sync::Mutex<Vec<RecordKind>>>,
    }

    #[async_trait]
    impl Sink for KindRecordingSink {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            self.kinds
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(RecordKind::Device);
            Ok(())
        }
        async fn write_kind(&mut self, kind: RecordKind, _data: &[u8]) -> Result<(), RastreoError> {
            self.kinds
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(kind);
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Memory
        }
    }

    #[tokio::test]
    async fn tee_sink_write_kind_forwards_the_kind_to_every_child() {
        let a_kinds = Arc::new(std::sync::Mutex::new(Vec::new()));
        let b_kinds = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(KindRecordingSink {
                kinds: Arc::clone(&a_kinds),
            })),
            TeeChild::Owned(Box::new(KindRecordingSink {
                kinds: Arc::clone(&b_kinds),
            })),
        ]);
        tee.write_kind(RecordKind::Device, b"d")
            .await
            .expect("device");
        tee.write_kind(RecordKind::Link, b"l").await.expect("link");
        tee.write_kind(RecordKind::CollectionProfile, b"p")
            .await
            .expect("profile");
        let expected = vec![
            RecordKind::Device,
            RecordKind::Link,
            RecordKind::CollectionProfile,
        ];
        assert_eq!(*a_kinds.lock().unwrap_or_else(|e| e.into_inner()), expected);
        assert_eq!(*b_kinds.lock().unwrap_or_else(|e| e.into_inner()), expected);
    }
}
