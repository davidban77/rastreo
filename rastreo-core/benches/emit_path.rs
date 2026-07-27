use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rastreo_core::pipeline::write_encoded;
use rastreo_core::{
    DeviceRecord, Encoder, NdjsonEncoder, RastreoError, RecordKind, Sink, TableEncoder,
};

// A /16 swept at a 1% answer rate lands on the middle size; the smallest carries visible fixed harness cost, so quote 6500.
const RECORD_COUNTS: [usize; 3] = [65, 650, 6500];

const RECORD_TEMPLATE: &str = include_str!("fixtures/device_record.json");

#[derive(Default)]
struct CountingSink {
    bytes: u64,
    writes: u64,
}

// No `write_kind` override, so the trait default routes through `write`: the second boxed future under test.
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

// The shape where every concrete sink overrides `write_kind` instead of falling through to `write`.
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

    async fn write_kind(&mut self, kind: RecordKind, data: &[u8]) -> Result<(), RastreoError> {
        match kind {
            RecordKind::Device => {
                self.bytes += data.len() as u64;
                self.writes += 1;
            }
            _ => self.bytes += data.len() as u64,
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), RastreoError> {
        Ok(())
    }
}

fn opaque_sink() -> Box<dyn Sink> {
    let sink: Box<dyn Sink> = Box::new(CountingSink::default());
    black_box(sink)
}

fn opaque_inline_kind_sink() -> Box<dyn Sink> {
    let sink: Box<dyn Sink> = Box::new(InlineKindSink::default());
    black_box(sink)
}

fn opaque_encoder(encoder: impl Encoder + 'static) -> Box<dyn Encoder> {
    let encoder: Box<dyn Encoder> = Box::new(encoder);
    black_box(encoder)
}

fn device_record(index: usize) -> DeviceRecord {
    let address = format!("10.42.{}.{}", (index / 256) % 256, index % 256);
    let mac = format!(
        "aa:bb:cc:{:02x}:{:02x}:{:02x}",
        (index / 65536) % 256,
        (index / 256) % 256,
        index % 256
    );
    let name = format!("edge-{index:04}.lab.example.net");
    let json = RECORD_TEMPLATE
        .replace("__ADDRESS__", &address)
        .replace("__MAC__", &mac)
        .replace("__NAME__", &name);
    serde_json::from_str(&json).expect("bench fixture parses as a device record")
}

fn device_records(count: usize) -> Vec<DeviceRecord> {
    (0..count).map(device_record).collect()
}

fn ndjson_lines(records: &[DeviceRecord]) -> Vec<Vec<u8>> {
    let encoder = NdjsonEncoder::new();
    records
        .iter()
        .map(|record| {
            let mut buf = Vec::new();
            encoder.encode_record(record, &mut buf).expect("encode");
            buf
        })
        .collect()
}

fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime")
}

fn emit_dispatch(c: &mut Criterion) {
    let rt = bench_runtime();
    let mut group = c.benchmark_group("emit_dispatch");
    for count in RECORD_COUNTS {
        let lines = ndjson_lines(&device_records(count));
        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(BenchmarkId::new("write", count), &lines, |b, lines| {
            b.to_async(&rt).iter(|| async {
                let mut sink = opaque_sink();
                let mut emitted = 0usize;
                for line in lines {
                    sink.write(line).await.expect("counting sink accepts");
                    emitted += 1;
                }
                black_box((sink, emitted));
            });
        });

        group.bench_with_input(BenchmarkId::new("write_kind", count), &lines, |b, lines| {
            b.to_async(&rt).iter(|| async {
                let mut sink = opaque_sink();
                let mut emitted = 0usize;
                for line in lines {
                    sink.write_kind(RecordKind::Device, line)
                        .await
                        .expect("counting sink accepts");
                    emitted += 1;
                }
                black_box((sink, emitted));
            });
        });

        group.bench_with_input(
            BenchmarkId::new("write_kind_inline", count),
            &lines,
            |b, lines| {
                b.to_async(&rt).iter(|| async {
                    let mut sink = opaque_inline_kind_sink();
                    let mut emitted = 0usize;
                    for line in lines {
                        sink.write_kind(RecordKind::Device, line)
                            .await
                            .expect("counting sink accepts");
                        emitted += 1;
                    }
                    black_box((sink, emitted));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("write_encoded", count),
            &lines,
            |b, lines| {
                b.to_async(&rt).iter(|| async {
                    let mut sink = opaque_sink();
                    let mut emitted = 0usize;
                    for line in lines {
                        let written = write_encoded(sink.as_mut(), RecordKind::Device, line)
                            .await
                            .expect("counting sink accepts");
                        emitted += usize::from(written);
                    }
                    black_box((sink, emitted));
                });
            },
        );
    }
    group.finish();
}

fn encode_record(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_record");
    for count in RECORD_COUNTS {
        let records = device_records(count);
        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(BenchmarkId::new("ndjson", count), &records, |b, records| {
            let encoder = opaque_encoder(NdjsonEncoder::new());
            let mut buf = Vec::with_capacity(2048);
            b.iter(|| {
                for record in records {
                    buf.clear();
                    encoder.encode_record(record, &mut buf).expect("encode");
                    black_box(&buf);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("table", count), &records, |b, records| {
            let encoder = opaque_encoder(TableEncoder::default());
            let mut buf = Vec::with_capacity(2048);
            b.iter(|| {
                for record in records {
                    buf.clear();
                    encoder.encode_record(record, &mut buf).expect("encode");
                    black_box(&buf);
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, emit_dispatch, encode_record);
criterion_main!(benches);
