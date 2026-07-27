// Own test binary: a concurrent test thread reaching this callsite with no subscriber caches
// `Interest::never()` in tracing's process-global interest cache, and this capture sees nothing.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rastreo_core::fuser::identity::default_max_correlation_bucket;
use rastreo_core::{DirectFuser, Fuser, IdentityFuser, IdentityHints, ProbeOutcome};
use serde_json::json;

struct CapturingSubscriber(Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Visitor(String);
        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        let mut visitor = Visitor(String::new());
        event.record(&mut visitor);
        self.0
            .lock()
            .expect("lock")
            .push((*event.metadata().level(), visitor.0));
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

fn ssh_key_outcome(ip: IpAddr, host_key: &str) -> ProbeOutcome {
    serde_json::from_value(json!({
        "kind": "Ssh",
        "target_ip": ip,
        "timestamp": SystemTime::UNIX_EPOCH,
        "reachable": true,
        "signals": [{ "SshHostKey": host_key }],
    }))
    .expect("probe outcome")
}

fn distinct_ips_sharing_a_host_key(count: u32, host_key: &str) -> Vec<ProbeOutcome> {
    (0..count)
        .map(|i| ssh_key_outcome(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i)), host_key))
        .collect()
}

#[test]
fn oversized_bucket_emits_one_info_line_naming_the_knob() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = CapturingSubscriber(Arc::clone(&captured));

    let over_cap = default_max_correlation_bucket() + 5;
    let outcomes =
        distinct_ips_sharing_a_host_key(over_cap as u32, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI");
    let mut fuser = IdentityFuser::new(Box::new(DirectFuser::new()), IdentityHints::default())
        .expect("identity fuser");

    let merged = tracing::subscriber::with_default(subscriber, || {
        for outcome in outcomes {
            fuser.ingest(vec![outcome]).expect("ingest");
        }
        fuser.finish().expect("finish")
    });
    assert_eq!(
        merged.len(),
        over_cap,
        "the fixture must trip the cap: an over-cap bucket is skipped, so nothing merges",
    );

    let events = captured.lock().expect("lock");
    let info: Vec<&(tracing::Level, String)> = events
        .iter()
        .filter(|(level, _)| *level == tracing::Level::INFO)
        .collect();
    assert_eq!(info.len(), 1, "one aggregate info line per correlate pass");
    assert!(
        info[0].1.contains("identity_hints.max_correlation_bucket"),
        "the line must name the knob to raise: {}",
        info[0].1,
    );
}
