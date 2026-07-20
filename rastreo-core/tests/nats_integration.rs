#![cfg(feature = "nats")]

use std::time::Duration;

use async_nats::jetstream;
use rastreo_core::sink::{create_sink, NatsCredentials, NatsFlushMode, SinkConfig, SinkRetry};
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
}
