#![cfg(feature = "kafka")]

use rastreo_core::sink::{KafkaSink, Sink};

#[tokio::test]
#[ignore]
async fn kafka_batched_close_delivers_one_message_per_record() {
    let mut sink = KafkaSink::new(
        vec!["localhost:9092".into()],
        "rastreo.uat".into(),
        None,
        None,
    )
    .await
    .expect("connect to compose kafka");

    // Each write carries one full NDJSON record; default Batched mode buffers all three,
    // then close() drains them as three individually-consumable messages in one produce.
    for i in 0..3 {
        let line = format!("{{\"id\":\"test-{i}\",\"ts\":0}}\n");
        sink.write(line.as_bytes()).await.expect("write");
    }
    sink.close().await.expect("close");
    assert!(sink.last_write_delivered());
}
