#![cfg(feature = "kafka")]

use rastreo_core::sink::{KafkaSink, Sink};

#[tokio::test]
#[ignore]
async fn kafka_sink_produces_to_compose_broker() {
    let mut sink = KafkaSink::new(vec!["localhost:9092".into()], "rastreo.uat".into())
        .await
        .expect("connect to compose kafka");

    for i in 0..3 {
        let line = format!(r#"{{"id":"test-{i}","ts":0}}"#);
        sink.write(line.as_bytes()).await.expect("write");
        sink.write(b"\n").await.expect("newline");
    }
    sink.flush().await.expect("flush");
    assert!(sink.last_write_delivered());
}
