#![cfg(feature = "kafka")]

use rastreo_core::sink::{create_sink, KafkaFlushMode, SinkConfig, SinkRetry};
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

    // Pre-create the topic so the sink's partition-client resolves without waiting on auto-create.
    ClientBuilder::new(vec![broker.clone()])
        .build()
        .await
        .expect("admin client")
        .controller_client()
        .expect("controller client")
        .create_topic(topic, 1, 1, 5_000)
        .await
        .expect("create topic");

    let config = SinkConfig::Kafka {
        brokers: vec![broker.clone()],
        topic: topic.to_string(),
        flush_mode: KafkaFlushMode::default(),
        dead_letter: None,
        tls: None,
        sasl: None,
        retry: SinkRetry::default(),
    };
    let mut sink = create_sink(&config).await.expect("create kafka sink");

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
}
