#![cfg(feature = "kafka")]

use std::time::Duration;

use rastreo_core::sink::{
    create_sink, KafkaFlushMode, RecordKind, SinkConfig, SinkRetry, DEFAULT_LINKS_DESTINATION,
    DEFAULT_PROFILES_DESTINATION,
};
use rskafka::client::{
    partition::{OffsetAt, UnknownTopicHandling},
    ClientBuilder,
};
use testcontainers::{runners::AsyncRunner, ImageExt};
use testcontainers_modules::kafka;

async fn create_topics(broker: &str, names: &[&str]) {
    let controller = ClientBuilder::new(vec![broker.to_string()])
        .build()
        .await
        .expect("admin client")
        .controller_client()
        .expect("controller client");
    for name in names {
        controller
            .create_topic(*name, 1, 1, 5_000)
            .await
            .unwrap_or_else(|e| panic!("create topic {name}: {e}"));
    }
}

async fn consume(broker: &str, topic: &str, expected: usize) -> Vec<Vec<u8>> {
    let consumer = ClientBuilder::new(vec![broker.to_string()])
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
    while values.len() < expected {
        let (batch, high_watermark) = consumer
            .fetch_records(offset, 1..1_000_000, 5_000)
            .await
            .expect("fetch records");
        if batch.is_empty() {
            assert!(
                offset < high_watermark,
                "{topic} exhausted at offset {offset} with only {} of {expected} records",
                values.len()
            );
            continue;
        }
        for record_and_offset in batch {
            offset = record_and_offset.offset + 1;
            values.push(record_and_offset.record.value.expect("record value"));
        }
    }
    values
}

// A topic that does not exist yet is a produce destination the sink cannot reach and the test can
// repair, so retention across a failed flush is observable as delivery rather than as internal state.
#[tokio::test]
#[ignore]
async fn kafka_second_stream_records_survive_a_failed_flush_and_arrive_on_the_next_one() {
    let node = kafka::Kafka::default()
        .with_env_var("KAFKA_AUTO_CREATE_TOPICS_ENABLE", "false")
        .start()
        .await
        .expect("start kafka container");
    let port = node
        .get_host_port_ipv4(kafka::KAFKA_PORT)
        .await
        .expect("mapped kafka port");
    let broker = format!("127.0.0.1:{port}");
    let topic = "rastreo.itest.retention";
    let links_topic = "rastreo.itest.retention.links";
    let profiles_topic = "rastreo.itest.retention.profiles";

    create_topics(&broker, &[topic]).await;

    let config = SinkConfig::Kafka {
        brokers: vec![broker.clone()],
        topic: topic.to_string(),
        links_topic: Some(links_topic.to_string()),
        profiles_topic: Some(profiles_topic.to_string()),
        flush_mode: KafkaFlushMode::Batched {
            threshold_bytes: 64 * 1024,
        },
        dead_letter: None,
        tls: None,
        sasl: None,
        retry: SinkRetry::default(),
    };
    let mut sink = create_sink(&config).await.expect("create kafka sink");

    let links: Vec<String> = (0..3)
        .map(|i| format!("{{\"link\":\"itest-{i}\"}}\n"))
        .collect();
    let profiles: Vec<String> = (0..3)
        .map(|i| format!("{{\"profile\":\"itest-{i}\"}}\n"))
        .collect();
    for (kind, lines) in [
        (RecordKind::Link, &links),
        (RecordKind::CollectionProfile, &profiles),
    ] {
        for line in lines {
            tokio::time::timeout(
                Duration::from_secs(5),
                sink.write_kind(kind, line.as_bytes()),
            )
            .await
            .unwrap_or_else(|_| panic!("{kind:?}: a buffered write must not reach for a broker"))
            .unwrap_or_else(|e| panic!("{kind:?}: buffering a record cannot fail: {e}"));
        }
    }

    sink.flush()
        .await
        .expect_err("neither second-stream topic exists yet");
    assert!(
        !sink.last_write_delivered(),
        "a failed flush must not claim delivery"
    );

    create_topics(&broker, &[links_topic, profiles_topic]).await;

    sink.flush()
        .await
        .expect("the retained second-stream buffers produce once their topics exist");
    assert!(sink.last_write_delivered());

    let delivered_links = consume(&broker, links_topic, links.len()).await;
    let delivered_profiles = consume(&broker, profiles_topic, profiles.len()).await;
    for (got, want) in delivered_links.iter().zip(links.iter()) {
        assert_eq!(got.as_slice(), want.as_bytes(), "link payload round-trip");
    }
    for (got, want) in delivered_profiles.iter().zip(profiles.iter()) {
        assert_eq!(
            got.as_slice(),
            want.as_bytes(),
            "profile payload round-trip"
        );
    }
    assert_eq!(delivered_links.len(), links.len());
    assert_eq!(delivered_profiles.len(), profiles.len());
}

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
    create_topics(
        &broker,
        &[
            topic,
            DEFAULT_LINKS_DESTINATION,
            DEFAULT_PROFILES_DESTINATION,
        ],
    )
    .await;

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

    let values = consume(&broker, topic, written.len()).await;

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
