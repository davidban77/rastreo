//! Machine-independent guards for what `benches/emit_path.rs` measures: per-record allocations on the emit path, and the shape of the record fixture feeding it.
//!
//! These are exact pins, not ceilings. Removing an allocation reddens one — that is how an
//! optimisation lands, and the fix lowers the number here in the same commit.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use rastreo_core::pipeline::write_encoded;
use rastreo_core::{
    DeviceRecord, Encoder, NdjsonEncoder, RastreoError, RecordKind, Sink, TeeChild, TeeSink,
};
use tokio::runtime::Runtime;

// `Cell<u64>` has no destructor, so the thread-local registers none and the counters never allocate.
thread_local! {
    static ALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
    static ALLOC_BYTES: Cell<u64> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOC_COUNT.try_with(|c| c.set(c.get() + 1));
        let _ = ALLOC_BYTES.try_with(|c| c.set(c.get() + layout.size() as u64));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Allocations {
    count: u64,
    bytes: u64,
}

fn measure(body: impl FnOnce()) -> Allocations {
    ALLOC_COUNT.with(|c| c.set(0));
    ALLOC_BYTES.with(|c| c.set(0));
    body();
    Allocations {
        count: ALLOC_COUNT.with(Cell::get),
        bytes: ALLOC_BYTES.with(Cell::get),
    }
}

const SAMPLE: u64 = 64;

/// Difference between a `2n`-record run and an `n`-record run, so per-run setup cancels out.
fn per_record(mut op: impl FnMut(usize)) -> Allocations {
    let n = SAMPLE as usize;
    op(n);
    let base = measure(|| op(n));
    let doubled = measure(|| op(2 * n));
    let count = doubled.count - base.count;
    let bytes = doubled.bytes - base.bytes;
    assert_eq!(
        count % SAMPLE,
        0,
        "allocation count is not linear in records"
    );
    assert_eq!(
        bytes % SAMPLE,
        0,
        "allocated bytes are not linear in records"
    );
    Allocations {
        count: count / SAMPLE,
        bytes: bytes / SAMPLE,
    }
}

#[derive(Default)]
struct CountingSink {
    bytes: u64,
    writes: u64,
}

#[async_trait::async_trait]
impl Sink for CountingSink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.bytes += data.len() as u64;
        self.writes += 1;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        Ok(())
    }
}

#[derive(Default)]
struct InlineKindSink {
    bytes: u64,
    writes: u64,
}

#[async_trait::async_trait]
impl Sink for InlineKindSink {
    async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
        self.bytes += data.len() as u64;
        self.writes += 1;
        Ok(())
    }

    async fn write_kind(&mut self, _kind: RecordKind, data: &[u8]) -> Result<(), RastreoError> {
        self.bytes += data.len() as u64;
        self.writes += 1;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        Ok(())
    }
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
}

fn counting_sink() -> Box<dyn Sink> {
    Box::new(CountingSink::default())
}

fn tee_sink(children: usize) -> Box<dyn Sink> {
    let children = (0..children)
        .map(|_| TeeChild::Owned(counting_sink()))
        .collect();
    Box::new(TeeSink::new(children))
}

const RECORD_TEMPLATE: &str = include_str!("../benches/fixtures/device_record.json");

fn fixture_json(index: usize) -> String {
    let address = format!("10.42.{}.{}", (index / 256) % 256, index % 256);
    let mac = format!(
        "aa:bb:cc:{:02x}:{:02x}:{:02x}",
        (index / 65536) % 256,
        (index / 256) % 256,
        index % 256
    );
    let name = format!("edge-{index:04}.lab.example.net");
    RECORD_TEMPLATE
        .replace("__ADDRESS__", &address)
        .replace("__MAC__", &mac)
        .replace("__NAME__", &name)
}

fn fixture_record() -> DeviceRecord {
    serde_json::from_str(&fixture_json(0)).expect("fixture parses as a device record")
}

fn ndjson_line() -> Vec<u8> {
    let mut buf = Vec::new();
    NdjsonEncoder::new()
        .encode_record(&fixture_record(), &mut buf)
        .expect("encode");
    buf
}

#[test]
fn plain_write_costs_one_boxed_future_per_record() {
    let rt = runtime();
    let line = ndjson_line();

    let cost = per_record(|n| {
        rt.block_on(async {
            let mut sink = counting_sink();
            for _ in 0..n {
                sink.write(&line).await.expect("counting sink accepts");
            }
        });
    });

    assert_eq!(cost.count, 1);
}

#[test]
fn write_kind_on_a_non_overriding_sink_costs_two_boxed_futures_per_record() {
    let rt = runtime();
    let line = ndjson_line();

    let cost = per_record(|n| {
        rt.block_on(async {
            let mut sink = counting_sink();
            for _ in 0..n {
                sink.write_kind(RecordKind::Device, &line)
                    .await
                    .expect("counting sink accepts");
            }
        });
    });

    assert_eq!(cost.count, 2);
}

#[test]
fn overriding_write_kind_gives_back_the_second_boxed_future() {
    let rt = runtime();
    let line = ndjson_line();

    let cost = per_record(|n| {
        rt.block_on(async {
            let mut sink: Box<dyn Sink> = Box::new(InlineKindSink::default());
            for _ in 0..n {
                sink.write_kind(RecordKind::Device, &line)
                    .await
                    .expect("inline sink accepts");
            }
        });
    });

    assert_eq!(cost.count, 1);
}

#[test]
fn emit_guard_costs_exactly_one_allocation_more_than_plain_write() {
    let rt = runtime();
    let line = ndjson_line();

    let plain = per_record(|n| {
        rt.block_on(async {
            let mut sink = counting_sink();
            for _ in 0..n {
                sink.write(&line).await.expect("counting sink accepts");
            }
        });
    });

    let guarded = per_record(|n| {
        rt.block_on(async {
            let mut sink = counting_sink();
            let mut emitted = 0usize;
            for _ in 0..n {
                let written = write_encoded(sink.as_mut(), RecordKind::Device, &line)
                    .await
                    .expect("counting sink accepts");
                emitted += usize::from(written);
            }
            assert_eq!(emitted, n);
        });
    });

    assert_eq!(guarded.count, plain.count + 1);
    assert!(guarded.bytes > plain.bytes);
}

#[test]
fn emit_guard_allocates_nothing_when_the_encoder_rendered_nothing() {
    let rt = runtime();

    let cost = per_record(|n| {
        rt.block_on(async {
            let mut sink = counting_sink();
            let mut emitted = 0usize;
            for _ in 0..n {
                let written = write_encoded(sink.as_mut(), RecordKind::Device, &[])
                    .await
                    .expect("counting sink accepts");
                emitted += usize::from(written);
            }
            assert_eq!(emitted, 0);
        });
    });

    assert_eq!(cost, Allocations { count: 0, bytes: 0 });
}

#[test]
fn tee_multiplies_the_second_boxed_future_by_its_child_count() {
    let rt = runtime();
    let line = ndjson_line();

    for children in [1usize, 2, 4] {
        let plain = per_record(|n| {
            rt.block_on(async {
                let mut sink = tee_sink(children);
                for _ in 0..n {
                    sink.write(&line).await.expect("tee accepts");
                }
            });
        });
        let by_kind = per_record(|n| {
            rt.block_on(async {
                let mut sink = tee_sink(children);
                for _ in 0..n {
                    sink.write_kind(RecordKind::Device, &line)
                        .await
                        .expect("tee accepts");
                }
            });
        });

        assert_eq!(
            plain.count,
            1 + children as u64,
            "tee write, {children} children"
        );
        assert_eq!(
            by_kind.count,
            1 + 2 * children as u64,
            "tee write_kind, {children} children"
        );
    }
}

#[test]
fn ndjson_encoding_allocates_one_string_per_rfc3339_timestamp() {
    let record = fixture_record();
    let encoder = NdjsonEncoder::new();
    let mut buf = Vec::with_capacity(4096);

    let cost = per_record(|n| {
        for _ in 0..n {
            buf.clear();
            encoder.encode_record(&record, &mut buf).expect("encode");
        }
    });

    // One `String` per RFC-3339 timestamp: `last_seen` and `scan_metadata.initiated_at`.
    assert_eq!(
        cost,
        Allocations {
            count: 2,
            bytes: cost.bytes
        },
        "two RFC-3339 strings; sizes are chrono's buffer strategy, not an invariant"
    );

    let metadata_only = per_record(|n| {
        for _ in 0..n {
            buf.clear();
            serde_json::to_writer(&mut buf, &record.scan_metadata).expect("encode");
        }
    });
    assert_eq!(
        metadata_only,
        Allocations {
            count: 1,
            bytes: metadata_only.bytes
        }
    );
}

#[test]
fn bench_fixture_round_trips_every_field_it_sets() {
    let json = fixture_json(0);
    let fixture: serde_json::Value = serde_json::from_str(&json).expect("fixture is valid json");
    let record: DeviceRecord = serde_json::from_str(&json).expect("fixture parses as a record");
    let round_tripped = serde_json::to_value(&record).expect("record serializes");

    for (key, expected) in fixture.as_object().expect("fixture is a json object") {
        let actual = round_tripped.get(key).unwrap_or(&serde_json::Value::Null);
        assert_eq!(actual, expected, "fixture field `{key}` did not round trip");
    }
}

#[test]
fn bench_fixture_carries_a_full_size_record() {
    let fixture: serde_json::Value =
        serde_json::from_str(&fixture_json(0)).expect("fixture is valid json");
    assert_eq!(fixture.as_object().map(|o| o.len()), Some(15));

    let record = fixture_record();
    assert_eq!(record.signals.len(), 14);
    assert_eq!(record.probe_kinds.len(), 6);
    // Not a rename guard: `bench_fixture_round_trips_every_field_it_sets` is. A renamed
    // field can keep the length identical, so this only catches wholesale shrinkage.
    assert!(ndjson_line().len() > 1000);
}

#[test]
fn encoding_and_emitting_one_record_costs_the_sum_of_both() {
    let record = fixture_record();
    let encoder = NdjsonEncoder::new();
    let sink: Box<dyn Sink> = Box::new(CountingSink::default());
    let runtime = Runtime::new().expect("runtime");
    let mut sink = sink;
    let mut buf = Vec::with_capacity(4096);

    let cost = per_record(|n| {
        for _ in 0..n {
            buf.clear();
            encoder.encode_record(&record, &mut buf).expect("encode");
            runtime
                .block_on(write_encoded(sink.as_mut(), RecordKind::Device, &buf))
                .expect("write");
        }
    });

    // The derived in-situ figures in CLAUDE.md sum the two groups; this pins that they are additive.
    assert_eq!(cost.count, 4, "2 encoding the record + 2 emitting it");
}
