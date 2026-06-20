use std::path::Path;

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::error::RastreoError;

use super::Sink;

pub struct FileSink {
    writer: BufWriter<File>,
}

impl FileSink {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, RastreoError> {
        // create-if-missing, append-if-exists: never truncate.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .await
            .map_err(RastreoError::Sink)?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }
}

#[async_trait::async_trait]
impl Sink for FileSink {
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use crate::encoder::{Encoder, NdjsonEncoder};
    use crate::model::{Confidence, DeviceRecord, IdentityKey, Signal};
    use crate::sink::{create_sink, SinkConfig};

    fn sample_record(name: &str) -> DeviceRecord {
        DeviceRecord {
            identity_key: IdentityKey::new(name).expect("identity key"),
            mgmt_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            manufacturer: Some("Cisco".into()),
            platform: Some("IOS-XR".into()),
            role: Some("router".into()),
            confidence: Confidence::new(0.5).expect("confidence"),
            last_seen: SystemTime::UNIX_EPOCH,
            signals: vec![Signal::OpenPort(22)],
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
    async fn new_errors_on_unopenable_path() {
        let bad = Path::new("/this/path/should/not/exist/anywhere/foo.ndjson");
        match FileSink::new(bad).await {
            Err(RastreoError::Sink(_)) => {}
            Err(other) => panic!("expected RastreoError::Sink, got {other:?}"),
            Ok(_) => panic!("bad path must error"),
        }
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

    #[test]
    fn file_sink_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<FileSink>();
        assert_send_sync::<Box<dyn Sink>>();
    }
}
