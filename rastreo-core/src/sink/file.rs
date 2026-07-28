use std::path::Path;

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::error::RastreoError;

use super::{Sink, SinkError, SinkErrorClass, SinkType};

fn open_error(path: &Path, e: std::io::Error) -> RastreoError {
    RastreoError::Sink(SinkError::other(std::io::Error::new(
        e.kind(),
        format!("failed to open file sink at {}: {e}", path.display()),
    )))
}

fn write_error(e: std::io::Error) -> RastreoError {
    RastreoError::Sink(SinkError::new(
        SinkErrorClass::WriteFailure,
        std::io::Error::new(e.kind(), format!("failed to write to file sink: {e}")),
    ))
}

fn flush_error(e: std::io::Error) -> RastreoError {
    RastreoError::Sink(SinkError::new(
        SinkErrorClass::FlushFailure,
        std::io::Error::new(e.kind(), format!("failed to flush file sink: {e}")),
    ))
}

pub struct FileSink {
    writer: BufWriter<File>,
    delivered: bool,
}

impl FileSink {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, RastreoError> {
        let path = path.as_ref();
        // create-if-missing, append-if-exists: never truncate.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|e| open_error(path, e))?;
        Ok(Self {
            writer: BufWriter::new(file),
            delivered: false,
        })
    }
}

#[async_trait::async_trait]
impl Sink for FileSink {
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
        SinkType::File
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::encoder::{Encoder, NdjsonEncoder};
    use crate::model::{
        Confidence, DeviceRecord, IdentityKey, ScanMetadata, Signal, CURRENT_SCHEMA_ID,
        CURRENT_SCHEMA_VERSION,
    };
    use crate::sink::{create_sink, sink_io_detail, SinkConfig};

    fn sample_record(name: &str) -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new(name).expect("identity key"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            manufacturer: Some("Cisco".into()),
            model: None,
            product_family: None,
            platform: Some("IOS-XR".into()),
            os_version: None,
            ssh_version: None,
            http_server: None,
            http_version: None,
            role: Some("router".into()),
            confidence: Confidence::new(0.5).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: vec![Signal::OpenPort(22)],
            probe_kinds: Vec::new(),
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            schema_id: CURRENT_SCHEMA_ID.to_string(),
            alt_ips: Vec::new(),
            possible_alias_of: None,
            scan_metadata: Arc::new(ScanMetadata::default()),
        }
    }

    async fn write_record(sink: &mut FileSink, enc: &NdjsonEncoder, name: &str) {
        let mut buf = Vec::new();
        enc.encode_record(&sample_record(name), &mut buf)
            .expect("encode");
        sink.write(&buf).await.expect("write");
    }

    #[tokio::test]
    async fn round_trip_three_records_via_ndjson_encoder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("discoveries.ndjson");

        let mut sink = FileSink::new(&path).await.expect("open file");
        let enc = NdjsonEncoder::new();
        write_record(&mut sink, &enc, "a").await;
        write_record(&mut sink, &enc, "b").await;
        write_record(&mut sink, &enc, "c").await;
        sink.flush().await.expect("flush");
        drop(sink);

        let bytes = std::fs::read(&path).expect("read");
        let lines: Vec<&[u8]> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 3);
        let names: Vec<String> = lines
            .iter()
            .map(|l| {
                let r: DeviceRecord = serde_json::from_slice(l).expect("parse json line");
                r.identity_key.as_str().to_string()
            })
            .collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn append_mode_preserves_existing_content_across_two_sinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("append.ndjson");

        let enc = NdjsonEncoder::new();

        {
            let mut sink = FileSink::new(&path).await.expect("open first sink");
            write_record(&mut sink, &enc, "first").await;
            sink.flush().await.expect("flush 1");
        }

        {
            let mut sink = FileSink::new(&path).await.expect("open second sink");
            write_record(&mut sink, &enc, "second").await;
            sink.flush().await.expect("flush 2");
        }

        let bytes = std::fs::read(&path).expect("read");
        let lines: Vec<&[u8]> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        let first: DeviceRecord = serde_json::from_slice(lines[0]).expect("parse first");
        let second: DeviceRecord = serde_json::from_slice(lines[1]).expect("parse second");
        assert_eq!(first.identity_key.as_str(), "first");
        assert_eq!(second.identity_key.as_str(), "second");
    }

    #[tokio::test]
    async fn new_creates_file_when_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-yet-here.ndjson");
        assert!(!path.exists(), "precondition: path does not exist");

        let _sink = FileSink::new(&path).await.expect("open should create file");
        assert!(path.exists(), "file must exist after construction");
    }

    #[tokio::test]
    async fn new_errors_on_unopenable_path_with_other_class() {
        let bad = Path::new("/this/path/should/not/exist/anywhere/foo.ndjson");
        match FileSink::new(bad).await {
            Err(RastreoError::Sink(e)) => assert_eq!(e.class, SinkErrorClass::Other),
            Err(other) => panic!("expected RastreoError::Sink, got {other:?}"),
            Ok(_) => panic!("bad path must error"),
        }
    }

    #[tokio::test]
    async fn new_names_the_path_it_could_not_open() {
        let bad = Path::new("/this/path/should/not/exist/anywhere/foo.ndjson");
        let Err(err) = FileSink::new(bad).await else {
            panic!("bad path must error");
        };
        let detail = sink_io_detail(&err);
        assert!(
            detail.contains(&bad.display().to_string()),
            "detail: {detail}"
        );
        assert!(
            detail.contains("failed to open file sink"),
            "detail: {detail}"
        );
    }

    #[tokio::test]
    async fn factory_returns_file_sink_for_file_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("factory.ndjson");

        let mut sink = create_sink(&SinkConfig::File { path: path.clone() })
            .await
            .expect("factory should return file sink");
        sink.write(b"hello\n").await.expect("write");
        sink.flush().await.expect("flush");
        drop(sink);

        let content = std::fs::read(&path).expect("read");
        assert_eq!(content, b"hello\n");
    }

    #[tokio::test]
    async fn a_buffered_write_is_not_delivered_until_flush_puts_it_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("delivery.ndjson");
        let mut sink = FileSink::new(&path).await.expect("open file");
        assert!(!sink.last_write_delivered());

        sink.write(b"{\"a\":1}\n").await.expect("write");
        assert!(!sink.last_write_delivered());
        assert!(
            std::fs::read(&path).expect("read").is_empty(),
            "the bytes are still in the BufWriter, so the claim would be a lie"
        );

        sink.flush().await.expect("flush");
        assert!(sink.last_write_delivered());
        assert_eq!(std::fs::read(&path).expect("read"), b"{\"a\":1}\n");
    }

    #[tokio::test]
    async fn a_write_after_a_flush_revokes_the_delivery_claim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("revoke.ndjson");
        let mut sink = FileSink::new(&path).await.expect("open file");
        sink.write(b"first\n").await.expect("write");
        sink.flush().await.expect("flush");
        assert!(sink.last_write_delivered());

        sink.write(b"second\n").await.expect("write");
        assert!(!sink.last_write_delivered());
    }

    #[tokio::test]
    async fn a_failed_flush_does_not_claim_delivery() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seed = dir.path().join("failed-flush.ndjson");
        std::fs::File::create(&seed).expect("create seed");
        let mut sink = FileSink::new(&seed).await.expect("open sink");
        let read_only = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&seed)
            .expect("reopen read-only");
        sink.writer = BufWriter::new(File::from_std(read_only));
        sink.write(b"buffered\n").await.expect("buffer write");

        sink.flush().await.expect_err("flush must fail");
        assert!(!sink.last_write_delivered());
    }

    #[test]
    fn file_sink_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<FileSink>();
        assert_send_sync::<Box<dyn Sink>>();
    }

    #[tokio::test]
    async fn flush_failure_on_readonly_fd_carries_flush_failure_class() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seed = dir.path().join("flush-seed.ndjson");
        std::fs::File::create(&seed).expect("create seed");
        let mut sink = FileSink::new(&seed).await.expect("open sink");
        // Swap in a read-only fd; buffered bytes fail to drain on flush with EBADF.
        let read_only = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&seed)
            .expect("reopen read-only");
        sink.writer = BufWriter::new(File::from_std(read_only));
        sink.write(b"buffered\n").await.expect("buffer write");

        let err = sink.flush().await.expect_err("flush must fail");
        assert_eq!(err.sink_error_class(), Some(SinkErrorClass::FlushFailure));
        assert!(sink_io_detail(&err).contains("failed to flush"));
    }

    #[test]
    fn write_error_carries_write_failure_class_and_prefix() {
        let err = write_error(std::io::Error::other("No space left on device"));
        assert_eq!(err.sink_error_class(), Some(SinkErrorClass::WriteFailure));
        assert!(sink_io_detail(&err).contains("failed to write to file sink"));
    }

    #[test]
    fn flush_error_carries_flush_failure_class_and_prefix() {
        let err = flush_error(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Broken pipe",
        ));
        assert_eq!(err.sink_error_class(), Some(SinkErrorClass::FlushFailure));
        assert!(sink_io_detail(&err).contains("failed to flush file sink"));
    }
}
