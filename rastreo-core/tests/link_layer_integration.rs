//! Real-fabric scale guard for the shared ARP engine. It builds a Linux network-namespace fabric
//! (a veth pair with ~253 kernel-answered ARP responders behind it) and drives a concurrency-256
//! scan through ONE shared engine, asserting every responder is reached with its MAC — no loss, no
//! cross-talk. It is the only mutation-check for the `SO_RCVBUF` drain: shrink the socket buffer and
//! the reply burst overflows the kernel receive queue, dropping replies until the scan goes red.
//!
//! Requires `CAP_NET_RAW` + `CAP_NET_ADMIN` (run as root in a `--cap-add=NET_ADMIN,NET_RAW` or
//! `--privileged` container). `#[ignore]`d; it skips cleanly when the capabilities are absent.

#![cfg(feature = "arp")]

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rastreo_core::prober::ArpProber;
use rastreo_core::{ProbeCtx, ProbeKind, Prober, ResolvedTarget, Signal, Target};

const NETNS: &str = "rastreo-ns";
const MAIN_IF: &str = "rtmain";
const RESP_IF: &str = "rtresp";
const SUBNET: &str = "10.99.77";
const MAIN_HOST: u8 = 1;
const FIRST_RESPONDER: u8 = 2;
const LAST_RESPONDER: u8 = 254;
const CONCURRENCY: usize = 256;

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

fn run(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The netns / veth / bridge fabric, torn down on drop so a panicking assertion still cleans up.
struct Fabric;

impl Fabric {
    fn setup() -> Option<Fabric> {
        Self::teardown();

        let script = format!(
            "set -e\n\
             ip netns add {ns}\n\
             ip link add {main} type veth peer name {resp}\n\
             ip link set {resp} netns {ns}\n\
             ip addr add {net}.{main_host}/24 dev {main}\n\
             ip link set {main} up\n\
             ip -n {ns} link set lo up\n\
             ip -n {ns} link set {resp} up\n\
             for i in $(seq {first} {last}); do ip -n {ns} addr add {net}.$i/24 dev {resp}; done\n",
            ns = NETNS,
            main = MAIN_IF,
            resp = RESP_IF,
            net = SUBNET,
            main_host = MAIN_HOST,
            first = FIRST_RESPONDER,
            last = LAST_RESPONDER,
        );

        let ok = Command::new("sh")
            .arg("-c")
            .arg(&script)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !ok {
            Self::teardown();
            return None;
        }
        // Let the veth carrier settle before the one-shot ARP requests go out (no retry yet).
        std::thread::sleep(Duration::from_millis(500));
        Some(Fabric)
    }

    fn responder_mac(&self) -> Option<String> {
        let out = Command::new("ip")
            .args(["-n", NETNS, "link", "show", RESP_IF])
            .output()
            .ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        text.split_whitespace()
            .skip_while(|w| *w != "link/ether")
            .nth(1)
            .map(|s| s.to_string())
    }

    fn teardown() {
        let _ = run(&["netns", "del", NETNS]);
        let _ = run(&["link", "del", MAIN_IF]);
    }
}

impl Drop for Fabric {
    fn drop(&mut self) {
        Self::teardown();
    }
}

fn responder_targets() -> Vec<ResolvedTarget> {
    (FIRST_RESPONDER..=LAST_RESPONDER)
        .map(|host| {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 77, host));
            ResolvedTarget {
                ip,
                original: Target::Ip(ip),
                resolved_at: SystemTime::UNIX_EPOCH,
            }
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CAP_NET_RAW + CAP_NET_ADMIN (root / privileged container); builds a netns fabric"]
async fn concurrency_256_over_254_responders_reaches_all_with_no_loss() {
    if !is_root() {
        eprintln!("skipping: needs root / CAP_NET_ADMIN + CAP_NET_RAW to build the netns fabric");
        return;
    }
    let Some(fabric) = Fabric::setup() else {
        eprintln!("skipping: netns fabric setup failed (no NET_ADMIN?)");
        return;
    };
    let responder_mac = fabric
        .responder_mac()
        .expect("read the responder veth MAC")
        .to_lowercase();

    let prober = Arc::new(ArpProber::new(MAIN_IF.to_string()).expect("bind arp prober to rtmain"));
    let ctx = Arc::new(ProbeCtx::new(Duration::from_secs(5), 0));
    let targets = responder_targets();
    let expected = targets.len();

    let semaphore = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for target in targets {
        let prober = Arc::clone(&prober);
        let ctx = Arc::clone(&ctx);
        let semaphore = Arc::clone(&semaphore);
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("permit");
            let outcome = prober.probe(&target, &ctx).await.expect("probe ok");
            (target.ip, outcome)
        });
    }

    let mut reached = 0usize;
    let mut lost: Vec<IpAddr> = Vec::new();
    let mut wrong_mac: Vec<(IpAddr, String)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        let (ip, outcome) = joined.expect("probe task joined");
        assert_eq!(outcome.kind, ProbeKind::Arp);
        assert_eq!(outcome.target_ip, ip);
        assert!(
            outcome.fault.is_none(),
            "{ip}: unexpected fault {:?}",
            outcome.fault
        );
        if outcome.reachable {
            reached += 1;
            match outcome.signals.first() {
                Some(Signal::Mac(mac)) if *mac == responder_mac => {}
                Some(Signal::Mac(mac)) => wrong_mac.push((ip, mac.clone())),
                other => panic!("{ip}: expected a Mac signal, got {other:?}"),
            }
        } else {
            lost.push(ip);
        }
    }

    drop(fabric);

    assert!(
        wrong_mac.is_empty(),
        "cross-talk: {} responders returned a MAC that is not the responder's {responder_mac}: {wrong_mac:?}",
        wrong_mac.len()
    );
    assert_eq!(
        reached,
        expected,
        "reply loss: {reached}/{expected} responders reached; the SO_RCVBUF drain dropped {} \
         replies (missing {lost:?})",
        lost.len()
    );
}
