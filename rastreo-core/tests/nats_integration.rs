#![cfg(feature = "nats")]

use std::time::Duration;

use async_nats::jetstream;
use rastreo_core::sink::{
    create_sink, NatsCredentials, NatsFlushMode, RecordKind, SinkConfig, SinkErrorClass, SinkRetry,
};
use testcontainers::{runners::AsyncRunner, ImageExt};
use testcontainers_modules::nats::{Nats, NatsServerCmd};

// testcontainers reports readiness from the container log, which can win the race against
// the server actually accepting connections; poll a real connect until it lands.
async fn connect_when_ready(server: &str) -> async_nats::Client {
    for _ in 0..40 {
        if let Ok(client) = async_nats::connect(server).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("nats server never accepted a connection at {server}");
}

async fn start_jetstream() -> (
    testcontainers::ContainerAsync<Nats>,
    String,
    jetstream::Context,
) {
    let cmd = NatsServerCmd::default().with_jetstream();
    let node = Nats::default()
        .with_cmd(&cmd)
        .start()
        .await
        .expect("start nats container");
    let port = node
        .get_host_port_ipv4(4222)
        .await
        .expect("mapped nats port");
    let server = format!("nats://127.0.0.1:{port}");
    let js = jetstream::new(connect_when_ready(&server).await);
    (node, server, js)
}

async fn create_stream(js: &jetstream::Context, name: &str, subjects: &[&str]) {
    js.create_stream(jetstream::stream::Config {
        name: name.to_string(),
        subjects: subjects.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    })
    .await
    .unwrap_or_else(|e| panic!("create stream {name}: {e}"));
}

async fn stored_messages(js: &jetstream::Context, name: &str) -> Vec<(String, Vec<u8>)> {
    let stream = js.get_stream(name).await.expect("get stream");
    let count = stream.get_info().await.expect("stream info").state.messages;
    let mut messages = Vec::new();
    for sequence in 1..=count {
        let raw = stream
            .get_raw_message(sequence)
            .await
            .unwrap_or_else(|e| panic!("{name} message at sequence {sequence}: {e}"));
        messages.push((raw.subject.to_string(), raw.payload.to_vec()));
    }
    messages
}

fn retention_sink_config(server: &str, subject: &str, flush_mode: NatsFlushMode) -> SinkConfig {
    SinkConfig::Nats {
        servers: vec![server.to_string()],
        subject: subject.to_string(),
        stream: "RASTREO".to_string(),
        links_subject: Some("rastreo.retention.links".to_string()),
        profiles_subject: Some("rastreo.retention.profiles".to_string()),
        credentials: NatsCredentials::Anonymous,
        flush_mode,
        dead_letter: None,
        retry: SinkRetry::default(),
    }
}

fn batched_sink_config(server: &str, subject: &str) -> SinkConfig {
    retention_sink_config(
        server,
        subject,
        NatsFlushMode::Batched {
            threshold_bytes: 64 * 1024,
        },
    )
}

// Over the server's 1 MiB default max_payload, which async-nats enforces client-side: every publish attempt fails, at every point in the buffer's life.
fn unpublishable_record() -> Vec<u8> {
    vec![b'x'; 2 * 1024 * 1024]
}

fn device_messages(records: &[String]) -> Vec<(String, Vec<u8>)> {
    records
        .iter()
        .map(|line| {
            (
                "rastreo.retention.records".to_string(),
                line.as_bytes().to_vec(),
            )
        })
        .collect()
}

// A publish to a subject no stream is bound to is accepted by the core connection and rejected
// when its ack is awaited, so the failure both sinks must survive is inducible by configuration.
#[tokio::test]
#[ignore]
async fn nats_second_stream_records_survive_a_rejected_flush_and_arrive_on_the_next_one() {
    let (_node, server, js) = start_jetstream().await;
    create_stream(&js, "RASTREO", &["rastreo.retention.records"]).await;

    let config = batched_sink_config(&server, "rastreo.retention.records");
    let mut sink = create_sink(&config).await.expect("create nats sink");

    let links: Vec<String> = (0..3)
        .map(|i| format!("{{\"link\":\"itest-{i}\"}}\n"))
        .collect();
    let profiles: Vec<String> = (0..3)
        .map(|i| format!("{{\"profile\":\"itest-{i}\"}}\n"))
        .collect();
    for line in &links {
        sink.write_kind(RecordKind::Link, line.as_bytes())
            .await
            .expect("a link record buffers under the batched threshold");
    }
    for line in &profiles {
        sink.write_kind(RecordKind::CollectionProfile, line.as_bytes())
            .await
            .expect("a profile record buffers under the batched threshold");
    }

    sink.flush()
        .await
        .expect_err("no stream is bound to the links subject");
    assert!(
        !sink.last_write_delivered(),
        "a rejected flush must not claim delivery"
    );

    create_stream(
        &js,
        "RASTREO_SECOND",
        &["rastreo.retention.links", "rastreo.retention.profiles"],
    )
    .await;

    sink.flush()
        .await
        .expect("the retained second-stream buffers publish once a stream covers their subjects");
    assert!(sink.last_write_delivered());

    let stored = stored_messages(&js, "RASTREO_SECOND").await;
    let expected: Vec<(String, Vec<u8>)> = links
        .iter()
        .map(|line| {
            (
                "rastreo.retention.links".to_string(),
                line.as_bytes().to_vec(),
            )
        })
        .chain(profiles.iter().map(|line| {
            (
                "rastreo.retention.profiles".to_string(),
                line.as_bytes().to_vec(),
            )
        }))
        .collect();
    assert_eq!(
        stored, expected,
        "every buffered link and profile record must survive the rejected flush, head and tail alike"
    );
}

#[tokio::test]
#[ignore]
async fn nats_device_records_whose_ack_was_rejected_are_retained_for_the_next_flush() {
    let (_node, server, js) = start_jetstream().await;
    // The sink verifies the stream by name, so a subject outside its filter still constructs.
    create_stream(&js, "RASTREO", &["rastreo.retention.other"]).await;

    let config = batched_sink_config(&server, "rastreo.retention.records");
    let mut sink = create_sink(&config).await.expect("create nats sink");

    let records: Vec<String> = (0..3)
        .map(|i| format!("{{\"id\":\"itest-{i}\",\"ts\":0}}\n"))
        .collect();
    for line in &records {
        sink.write(line.as_bytes())
            .await
            .expect("a device record buffers under the batched threshold");
    }

    sink.flush()
        .await
        .expect_err("no stream is bound to the device subject");
    assert!(
        !sink.last_write_delivered(),
        "a rejected flush must not claim delivery"
    );

    create_stream(&js, "RASTREO_DEVICES", &["rastreo.retention.records"]).await;

    sink.flush()
        .await
        .expect("the retained device buffer publishes once a stream covers its subject");
    assert!(sink.last_write_delivered());

    let stored = stored_messages(&js, "RASTREO_DEVICES").await;
    assert_eq!(
        stored,
        device_messages(&records),
        "a record published but never acked must be held for the next flush, not dropped"
    );
}

#[tokio::test]
#[ignore]
async fn nats_records_published_before_a_mid_buffer_publish_failure_survive_the_failed_flush() {
    let (_node, server, js) = start_jetstream().await;
    create_stream(&js, "RASTREO", &["rastreo.retention.other"]).await;

    let config = batched_sink_config(&server, "rastreo.retention.records");
    let mut sink = create_sink(&config).await.expect("create nats sink");

    let records: Vec<String> = (0..3)
        .map(|i| format!("{{\"id\":\"strand-{i}\",\"ts\":0}}\n"))
        .collect();
    for line in &records {
        sink.write(line.as_bytes())
            .await
            .expect("a device record buffers under the batched threshold");
    }
    sink.write(&unpublishable_record())
        .await
        .expect_err("the oversized entry crosses the threshold and fails its own publish");

    let err = sink
        .flush()
        .await
        .expect_err("the oversized entry cannot publish");
    assert_eq!(
        err.sink_error_class(),
        Some(SinkErrorClass::PublishFailure),
        "the publish failure is the original error, not the ack rejection drained behind it"
    );

    create_stream(&js, "RASTREO_DEVICES", &["rastreo.retention.records"]).await;

    sink.flush()
        .await
        .expect_err("the oversized entry keeps blocking its buffer head");

    let stored = stored_messages(&js, "RASTREO_DEVICES").await;
    assert_eq!(
        stored,
        device_messages(&records),
        "records published ahead of the failing entry must be back in the buffer, not left in acks no flush ever awaits"
    );
}

#[tokio::test]
#[ignore]
async fn nats_a_per_record_write_that_fails_retains_what_it_already_published() {
    let (_node, server, js) = start_jetstream().await;
    create_stream(&js, "RASTREO", &["rastreo.retention.other"]).await;

    let config = retention_sink_config(
        &server,
        "rastreo.retention.records",
        NatsFlushMode::PerRecord,
    );
    let mut sink = create_sink(&config).await.expect("create nats sink");

    let records = vec!["{\"id\":\"strand-per-record\",\"ts\":0}\n".to_string()];
    sink.write(records[0].as_bytes())
        .await
        .expect_err("no stream is bound to the device subject");
    sink.write(&unpublishable_record())
        .await
        .expect_err("the oversized entry fails its publish behind the retained record");

    create_stream(&js, "RASTREO_DEVICES", &["rastreo.retention.records"]).await;

    sink.flush()
        .await
        .expect_err("the oversized entry keeps blocking its buffer head");

    let stored = stored_messages(&js, "RASTREO_DEVICES").await;
    assert_eq!(
        stored,
        device_messages(&records),
        "the record the failing write had already published must be retained by that write, so the first flush after the subject is bound delivers it"
    );
}

#[tokio::test]
#[ignore]
async fn nats_create_sink_delivers_each_record_to_the_stream() {
    let cmd = NatsServerCmd::default().with_jetstream();
    let node = Nats::default()
        .with_cmd(&cmd)
        .start()
        .await
        .expect("start nats container");
    let port = node
        .get_host_port_ipv4(4222)
        .await
        .expect("mapped nats port");
    let server = format!("nats://127.0.0.1:{port}");

    let stream_name = "RASTREO";
    let subject = "rastreo.records.v1";

    // Create the JetStream stream first: NatsSink::new verifies the stream exists on connect.
    let admin = connect_when_ready(&server).await;
    let js = jetstream::new(admin);
    js.create_stream(jetstream::stream::Config {
        name: stream_name.to_string(),
        subjects: vec!["rastreo.>".to_string()],
        ..Default::default()
    })
    .await
    .expect("create stream");

    let config = SinkConfig::Nats {
        servers: vec![server.clone()],
        subject: subject.to_string(),
        stream: stream_name.to_string(),
        links_subject: None,
        profiles_subject: None,
        credentials: NatsCredentials::Anonymous,
        flush_mode: NatsFlushMode::default(),
        dead_letter: None,
        retry: SinkRetry::default(),
    };
    let mut sink = create_sink(&config).await.expect("create nats sink");
    assert_eq!(
        config.sink_type(),
        sink.kind(),
        "structuredness is read off the sink kind, so the kind must match the config"
    );
    assert_eq!(
        config.requires_structured_records(),
        sink.requires_structured_records().await,
        "the offline config twin must match the live sink"
    );
    assert!(sink.requires_structured_records().await);

    let written: Vec<String> = (0..4)
        .map(|i| format!("{{\"id\":\"itest-{i}\",\"ts\":0}}\n"))
        .collect();
    for line in &written {
        sink.write(line.as_bytes()).await.expect("write");
    }
    sink.close().await.expect("close");
    assert!(
        sink.last_write_delivered(),
        "close must publish and ack every record"
    );

    let stream = js.get_stream(stream_name).await.expect("get stream");
    let info = stream.get_info().await.expect("stream info");
    assert_eq!(
        info.state.messages,
        written.len() as u64,
        "stream must hold exactly one message per written record"
    );

    for (i, want) in written.iter().enumerate() {
        let sequence = (i + 1) as u64;
        let message = stream
            .get_raw_message(sequence)
            .await
            .expect("message by sequence");
        assert_eq!(
            message.payload.as_ref(),
            want.as_bytes(),
            "payload round-trip at sequence {sequence}"
        );
    }

    // Every stream shares the batched threshold, so a small second-stream record stays local.
    let batched = SinkConfig::Nats {
        servers: vec![server.clone()],
        subject: subject.to_string(),
        stream: stream_name.to_string(),
        links_subject: None,
        profiles_subject: None,
        credentials: NatsCredentials::Anonymous,
        flush_mode: NatsFlushMode::Batched {
            threshold_bytes: 64 * 1024,
        },
        dead_letter: None,
        retry: SinkRetry::default(),
    };
    let mut sink = create_sink(&batched)
        .await
        .expect("create batched nats sink");
    sink.write(b"{\"id\":\"batched\",\"ts\":0}\n")
        .await
        .expect("write");
    sink.flush().await.expect("flush");

    for (kind, payload) in [
        (RecordKind::Link, b"{\"link\":\"itest\"}\n".as_slice()),
        (
            RecordKind::CollectionProfile,
            b"{\"profile\":\"itest\"}\n".as_slice(),
        ),
    ] {
        assert!(
            sink.last_write_delivered(),
            "{kind:?}: the preceding flush left nothing buffered"
        );
        sink.write_kind(kind, payload).await.expect("write");
        assert!(
            !sink.last_write_delivered(),
            "{kind:?}: a record buffered under the batched threshold has not reached the stream"
        );
        sink.flush().await.expect("flush");
        assert!(
            sink.last_write_delivered(),
            "{kind:?}: flush publishes the second-stream buffer too"
        );
    }
}
