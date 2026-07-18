#![cfg(feature = "icmp")]

//! Multiplexing proof for the shared per-family ICMP engine: many concurrent probes through ONE
//! socket, each correlated to its own reply by nonce. Needs `CAP_NET_RAW` (or the Linux
//! `ping_group_range` sysctl), so it is `#[ignore]`d like the broker container tests. Run with:
//! `cargo test -p rastreo-core --features icmp --test icmp_integration -- --ignored --nocapture`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rastreo_core::{
    BoundedScheduler, IcmpProber, ProbeCtx, ProbeOutcome, Prober, ResolvedTarget, Scheduler,
    Signal, Target, TargetScan,
};
use tokio::sync::{mpsc, watch};

fn target_at(ip: IpAddr) -> ResolvedTarget {
    ResolvedTarget {
        ip,
        original: Target::Ip(ip),
        resolved_at: SystemTime::UNIX_EPOCH,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn many_concurrent_probes_share_one_socket_without_cross_talk() {
    // 127.0.0.0/8 all resolves to loopback on Linux and answers ICMP echo, so these are distinct
    // targets that each reply through the single shared socket.
    let answering: Vec<IpAddr> = (2..=201u8)
        .map(|last| IpAddr::V4(Ipv4Addr::new(127, 0, 0, last)))
        .collect();
    // TEST-NET-1: routes nowhere, so it never answers — the absence case mixed into the load.
    let dark = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    let mut all: Vec<IpAddr> = answering.clone();
    all.push(dark);

    let prober = IcmpProber::new(1, 0).expect("valid prober");
    let ctx = ProbeCtx::new(Duration::from_secs(2), 0);
    let targets: Vec<ResolvedTarget> = all.iter().map(|ip| target_at(*ip)).collect();

    let outcomes = futures_util::future::join_all(
        targets
            .iter()
            .map(|t| async { (t.ip, prober.probe(t, &ctx).await.expect("probe ok")) }),
    )
    .await;

    let results: HashMap<IpAddr, ProbeOutcome> = outcomes.into_iter().collect();

    for ip in &answering {
        let outcome = results
            .get(ip)
            .unwrap_or_else(|| panic!("every target has a result, missing {ip}"));
        assert_eq!(
            outcome.target_ip, *ip,
            "an outcome must carry its own target"
        );
        assert!(
            outcome.reachable,
            "answering loopback {ip} must be reachable through the shared socket: {outcome:?}"
        );
        assert!(
            outcome.fault.is_none(),
            "an answered probe carries no fault: {outcome:?}"
        );
        assert_eq!(
            outcome.signals.len(),
            1,
            "answering {ip} yields exactly one signal, got {:?}",
            outcome.signals
        );
        assert!(
            matches!(outcome.signals.first(), Some(Signal::IcmpEchoRttMicros(_))),
            "answering {ip} must carry its own rtt signal, got {:?}",
            outcome.signals
        );
    }

    let dark_outcome = results.get(&dark).expect("dark target result");
    assert!(
        !dark_outcome.reachable,
        "the never-answering target is absent: {dark_outcome:?}"
    );
    assert!(
        dark_outcome.signals.is_empty(),
        "an absent target yields no signals"
    );
    assert!(
        dark_outcome.fault.is_none(),
        "a silent target is absence, not a fault: {dark_outcome:?}"
    );

    let reachable = answering.iter().filter(|ip| results[ip].reachable).count();
    assert_eq!(
        reachable,
        answering.len(),
        "every distinct target got ITS OWN reply through the one shared socket — no cross-talk"
    );

    eprintln!(
        "icmp shared-socket multiplex: {reachable}/{} distinct answering targets reachable, \
         1 dark target absent, all through one socket + one reader",
        answering.len()
    );
}

async fn run_scan_collect(
    scheduler: &BoundedScheduler,
    prober: Arc<dyn Prober>,
    targets: Vec<ResolvedTarget>,
    ctx: ProbeCtx,
) -> Vec<TargetScan> {
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let (tx, mut rx) = mpsc::channel(scheduler.max_concurrent().max(1));
    let scan = scheduler.run_scan(vec![prober], targets, ctx, cancel_rx, tx);
    tokio::pin!(scan);
    let mut out = Vec::new();
    let mut done = false;
    loop {
        tokio::select! {
            biased;
            _ = &mut scan, if !done => done = true,
            maybe = rx.recv() => match maybe {
                Some(sc) => out.push(sc),
                None => break,
            },
        }
    }
    out
}

fn reachable_count(scans: &[TargetScan]) -> usize {
    scans
        .iter()
        .filter(|scan| {
            scan.outcomes
                .iter()
                .any(|(_, result)| result.as_ref().map(|o| o.reachable).unwrap_or(false))
        })
        .count()
}

// Mirrors the CLI's huge-scan profile — default num-cpus worker threads (NOT worker_threads = 4)
// and concurrency 256 — where a reply burst overran the shared socket. The loss is intermittent, so
// it drives several rounds; constraining either knob stops it reproducing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a multi-core Linux host with CAP_NET_RAW (or ping_group_range sysctl)"]
async fn high_concurrency_scan_loses_no_replies() {
    const ROUNDS: usize = 10;
    let total = 254usize;

    for round in 0..ROUNDS {
        let targets: Vec<ResolvedTarget> = (1..=254u8)
            .map(|last| target_at(IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))))
            .collect();
        assert_eq!(targets.len(), total);

        let prober: Arc<dyn Prober> = Arc::new(IcmpProber::new(1, 0).expect("valid prober"));
        let ctx = ProbeCtx::new(Duration::from_secs(3), 0);
        let scheduler = BoundedScheduler::new(256);

        let scans = run_scan_collect(&scheduler, prober, targets, ctx).await;
        assert_eq!(
            scans.len(),
            total,
            "round {round}: every target must be fully scanned"
        );

        let reachable = reachable_count(&scans);
        assert_eq!(
            reachable, total,
            "round {round}: every answering loopback target must be reachable — the shared socket \
             must not drop replies under concurrency 256 ({reachable}/{total} reachable)"
        );
        eprintln!("round {round}: {reachable}/{total} reachable");
    }
}
