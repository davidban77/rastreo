#![cfg(feature = "kafka")]

use rastreo_core::sink::{
    create_sink, KafkaFlushMode, RecordKind, SinkConfig, SinkRetry, DEFAULT_LINKS_DESTINATION,
    DEFAULT_PROFILES_DESTINATION,
};
use rskafka::client::{
    partition::{OffsetAt, UnknownTopicHandling},
    ClientBuilder,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::kafka;

#[tokio::test]
#[ignore]
async fn kafka_create_sink_batched_close_delivers_one_message_per_record() {
    let node = kafka::Kafka::default()
        .start()
        .await
        .expect("start kafka container");
    let port = node
        .get_host_port_ipv4(kafka::KAFKA_PORT)
        .await
        .expect("mapped kafka port");
    let broker = format!("127.0.0.1:{port}");
    let topic = "rastreo.itest";

    // Pre-create the topics so the sink's partition-clients resolve without waiting on auto-create.
    let controller = ClientBuilder::new(vec![broker.clone()])
        .build()
        .await
        .expect("admin client")
        .controller_client()
        .expect("controller client");
    for name in [
        topic,
        DEFAULT_LINKS_DESTINATION,
        DEFAULT_PROFILES_DESTINATION,
    ] {
        controller
            .create_topic(name, 1, 1, 5_000)
            .await
            .unwrap_or_else(|e| panic!("create topic {name}: {e}"));
    }

    let config = SinkConfig::Kafka {
        brokers: vec![broker.clone()],
        topic: topic.to_string(),
        links_topic: None,
        profiles_topic: None,
        flush_mode: KafkaFlushMode::default(),
        dead_letter: None,
        tls: None,
        sasl: None,
        retry: SinkRetry::default(),
    };
    let mut sink = create_sink(&config).await.expect("create kafka sink");
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

    let written: Vec<String> = (0..3)
        .map(|i| format!("{{\"id\":\"itest-{i}\",\"ts\":0}}\n"))
        .collect();
    for line in &written {
        sink.write(line.as_bytes()).await.expect("write");
    }
    sink.close().await.expect("close");
    assert!(
        sink.last_write_delivered(),
        "batched close must flush every buffered record"
    );

    let consumer = ClientBuilder::new(vec![broker])
        .build()
        .await
        .expect("consumer client")
        .partition_client(topic, 0, UnknownTopicHandling::Retry)
        .await
        .expect("partition client");
    let earliest = consumer
        .get_offset(OffsetAt::Earliest)
        .await
        .expect("earliest offset");

    let mut values: Vec<Vec<u8>> = Vec::new();
    let mut offset = earliest;
    while values.len() < written.len() {
        let (batch, high_watermark) = consumer
            .fetch_records(offset, 1..1_000_000, 5_000)
            .await
            .expect("fetch records");
        if batch.is_empty() {
            assert!(
                offset < high_watermark,
                "stream exhausted at offset {offset} with only {} of {} records",
                values.len(),
                written.len()
            );
            continue;
        }
        for record_and_offset in batch {
            offset = record_and_offset.offset + 1;
            values.push(record_and_offset.record.value.expect("record value"));
        }
    }

    assert_eq!(
        values.len(),
        written.len(),
        "three writes must produce three individually-consumable messages"
    );
    for (got, want) in values.iter().zip(written.iter()) {
        assert_eq!(got.as_slice(), want.as_bytes(), "payload round-trip");
    }

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
            "{kind:?}: a record buffered under the batched threshold has not reached the broker"
        );
        sink.flush().await.expect("flush");
        assert!(
            sink.last_write_delivered(),
            "{kind:?}: flush publishes the second-stream buffer too"
        );
    }
}
