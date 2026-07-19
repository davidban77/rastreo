use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::sync::{mpsc, Mutex};
use tokio::task::{Id, JoinSet};
use tokio::time::Instant;

use crate::error::{RastreoError, RuntimeError};
use crate::model::{ProbeCtx, ProbeOutcome, ResolvedTarget};
use crate::prober::Prober;

/// One target's complete probe results: every prober's outcome paired with its pass index
/// (the prober's position in `scenario.probers`), collected once the target is fully scanned.
#[derive(Debug)]
pub struct TargetScan {
    pub target_index: usize,
    pub outcomes: Vec<(usize, Result<ProbeOutcome, RastreoError>)>,
}

#[async_trait::async_trait]
pub trait Scheduler: Send + Sync {
    /// Runs every prober against every target — in-flight probes bounded by the concurrency cap,
    /// starts paced by the probe rate — sending each fully-scanned target on `results` the moment
    /// its last prober completes (completion order). The bounded channel backpressures the scan to
    /// the consumer's pace, so in-flight state stays bounded by the concurrency window when the sink
    /// paces the scan.
    async fn run_scan(
        &self,
        probers: Vec<Arc<dyn Prober>>,
        targets: Vec<ResolvedTarget>,
        ctx: ProbeCtx,
        cancel: watch::Receiver<bool>,
        results: mpsc::Sender<TargetScan>,
    );
}

/// Steady min-interval pacer: hands each probe start a monotonically increasing slot spaced `1/rate` apart, so starts never burst.
struct Pacer {
    interval: Duration,
    next_start: Mutex<Option<Instant>>,
}

impl Pacer {
    fn from_rate(rate: u32) -> Option<Arc<Self>> {
        // rate 0 would mean an infinite interval; treat it as "no pacing".
        if rate == 0 {
            return None;
        }
        Some(Arc::new(Self {
            interval: Duration::from_secs_f64(1.0 / f64::from(rate)),
            next_start: Mutex::new(None),
        }))
    }

    async fn wait_for_slot(&self) {
        let scheduled = {
            let mut next = self.next_start.lock().await;
            let now = Instant::now();
            let scheduled = match *next {
                Some(t) if t > now => t,
                _ => now,
            };
            *next = Some(scheduled + self.interval);
            scheduled
        };
        tokio::time::sleep_until(scheduled).await;
    }
}

pub struct BoundedScheduler {
    max_concurrent: usize,
    pacer: Option<Arc<Pacer>>,
}

impl BoundedScheduler {
    pub const DEFAULT_MAX_CONCURRENT: usize = 64;

    // A cap of 0 would prime no probes and leave every slot unfilled; coerce to 1 (serial).
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent: max_concurrent.max(1),
            pacer: None,
        }
    }

    pub fn with_default_concurrency() -> Self {
        Self::new(Self::DEFAULT_MAX_CONCURRENT)
    }

    /// Cap probe starts at `probe_rate` per second; `None` (or `0`) leaves the scan unpaced.
    pub fn with_probe_rate(mut self, probe_rate: Option<u32>) -> Self {
        self.pacer = probe_rate.and_then(Pacer::from_rate);
        self
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_probe(
    set: &mut JoinSet<Result<ProbeOutcome, RastreoError>>,
    coord_by_id: &mut HashMap<Id, (usize, usize)>,
    pass_index: usize,
    target_index: usize,
    prober: &Arc<dyn Prober>,
    targets: &Arc<Vec<ResolvedTarget>>,
    ctx: &ProbeCtx,
    pacer: &Option<Arc<Pacer>>,
) {
    let prober = Arc::clone(prober);
    let targets = Arc::clone(targets);
    let ctx = ctx.clone();
    let pacer = pacer.clone();

    let handle = set.spawn(async move {
        if let Some(pacer) = pacer {
            pacer.wait_for_slot().await;
        }
        prober.probe(&targets[target_index], &ctx).await
    });
    coord_by_id.insert(handle.id(), (pass_index, target_index));
}

#[async_trait::async_trait]
impl Scheduler for BoundedScheduler {
    async fn run_scan(
        &self,
        probers: Vec<Arc<dyn Prober>>,
        targets: Vec<ResolvedTarget>,
        ctx: ProbeCtx,
        cancel: watch::Receiver<bool>,
        results: mpsc::Sender<TargetScan>,
    ) {
        let num_targets = targets.len();
        let num_probers = probers.len();
        if num_targets == 0 || num_probers == 0 {
            return;
        }
        let targets = Arc::new(targets);

        // JoinSet aborts every spawned probe on drop, bounding an abandoned scan to the request-timeout instead of leaking detached tasks.
        let mut set: JoinSet<Result<ProbeOutcome, RastreoError>> = JoinSet::new();
        let mut coord_by_id: HashMap<Id, (usize, usize)> =
            HashMap::with_capacity(self.max_concurrent);
        let mut slots: Vec<Vec<Option<Result<ProbeOutcome, RastreoError>>>> = (0..num_targets)
            .map(|_| (0..num_probers).map(|_| None).collect())
            .collect();
        let mut completed = vec![0usize; num_targets];

        // Target-outer feed order: a target's whole probe set is scheduled before the next target's,
        // so a cancelled scan leaves the earliest targets fully scanned rather than all targets torn.
        let mut work = (0..num_targets).flat_map(move |t| (0..num_probers).map(move |p| (p, t)));

        for _ in 0..self.max_concurrent {
            if *cancel.borrow() {
                break;
            }
            match work.next() {
                Some((pass_index, target_index)) => spawn_probe(
                    &mut set,
                    &mut coord_by_id,
                    pass_index,
                    target_index,
                    &probers[pass_index],
                    &targets,
                    &ctx,
                    &self.pacer,
                ),
                None => break,
            }
        }

        while let Some(joined) = set.join_next_with_id().await {
            let (id, outcome) = match joined {
                Ok((id, probe_result)) => (id, probe_result),
                Err(join_err) => {
                    let reason = if join_err.is_panic() {
                        "prober task panicked"
                    } else {
                        "prober task cancelled"
                    };
                    (
                        join_err.id(),
                        Err(RastreoError::Runtime(RuntimeError::TaskPanicked(
                            reason.to_string(),
                        ))),
                    )
                }
            };
            let mut ready_target: Option<usize> = None;
            if let Some((pass_index, target_index)) = coord_by_id.remove(&id) {
                slots[target_index][pass_index] = Some(outcome);
                completed[target_index] += 1;
                if completed[target_index] == num_probers {
                    ready_target = Some(target_index);
                }
            }
            // A live cancel stops new probe starts but lets in-flight probes drain, so a target that
            // already started still reports every prober's outcome instead of a partial record.
            if !*cancel.borrow() {
                if let Some((pass_index, target_index)) = work.next() {
                    spawn_probe(
                        &mut set,
                        &mut coord_by_id,
                        pass_index,
                        target_index,
                        &probers[pass_index],
                        &targets,
                        &ctx,
                        &self.pacer,
                    );
                }
            }
            // Refill happens before the send so an in-flight backpressure block never drops the
            // window below the cap. `send` awaits when the channel is full, pacing the scan to the
            // consumer; a receiver-dropped error means the consumer gave up, so stop scanning.
            if let Some(target_index) = ready_target {
                let outcomes = std::mem::take(&mut slots[target_index])
                    .into_iter()
                    .enumerate()
                    .map(|(pass_index, slot)| {
                        (
                            pass_index,
                            slot.expect("a fully-scanned target has every prober's outcome"),
                        )
                    })
                    .collect();
                if results
                    .send(TargetScan {
                        target_index,
                        outcomes,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    use crate::model::{ProbeKind, Signal, Target};
    use crate::resolver::{HickoryResolver, Resolver};

    struct CountingProber {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Prober for CountingProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProbeOutcome {
                lldp: None,
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::OpenPort(22)],
                fault: None,
            })
        }
    }

    struct SlowCountingProber {
        delay: Duration,
        completed: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Prober for SlowCountingProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            tokio::time::sleep(self.delay).await;
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(ProbeOutcome {
                lldp: None,
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: Vec::new(),
                fault: None,
            })
        }
    }

    struct StartCountingProber {
        delay: Duration,
        started: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Prober for StartCountingProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(ProbeOutcome {
                lldp: None,
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: Vec::new(),
                fault: None,
            })
        }
    }

    struct DelayProber {
        delays_us: Vec<u64>,
    }

    #[async_trait::async_trait]
    impl Prober for DelayProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            let index = match target.ip {
                IpAddr::V4(v4) => (v4.octets()[3] as usize) % self.delays_us.len(),
                IpAddr::V6(_) => 0,
            };
            tokio::time::sleep(Duration::from_micros(self.delays_us[index])).await;
            Ok(ProbeOutcome {
                lldp: None,
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: Vec::new(),
                fault: None,
            })
        }
    }

    struct PeakProber {
        in_flight: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Prober for PeakProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(current, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(ProbeOutcome {
                lldp: None,
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: Vec::new(),
                fault: None,
            })
        }
    }

    struct SaturationProber {
        kind: ProbeKind,
        in_flight: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        probed: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Prober for SaturationProber {
        fn kind(&self) -> ProbeKind {
            self.kind
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            self.probed.fetch_add(1, Ordering::SeqCst);
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(current, Ordering::SeqCst);
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(ProbeOutcome {
                lldp: None,
                kind: self.kind,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: Vec::new(),
                fault: None,
            })
        }
    }

    struct FailAtIndexProber {
        fail_octet: u8,
    }

    #[async_trait::async_trait]
    impl Prober for FailAtIndexProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            let last_octet = match target.ip {
                IpAddr::V4(v4) => v4.octets()[3],
                IpAddr::V6(_) => 0,
            };
            if last_octet == self.fail_octet {
                return Err(RastreoError::Probe(crate::error::ProbeError::Other(
                    format!(
                        "tcp connect failed on port 22: too many open files ({})",
                        target.ip
                    ),
                )));
            }
            Ok(ProbeOutcome {
                lldp: None,
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: Vec::new(),
                fault: None,
            })
        }
    }

    struct PanicAtIndexProber {
        panic_octet: u8,
    }

    #[async_trait::async_trait]
    impl Prober for PanicAtIndexProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
        }

        async fn probe(
            &self,
            target: &ResolvedTarget,
            _ctx: &ProbeCtx,
        ) -> Result<ProbeOutcome, RastreoError> {
            let last_octet = match target.ip {
                IpAddr::V4(v4) => v4.octets()[3],
                IpAddr::V6(_) => 0,
            };
            if last_octet == self.panic_octet {
                panic!("intentional panic at octet {last_octet}");
            }
            Ok(ProbeOutcome {
                lldp: None,
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: Vec::new(),
                fault: None,
            })
        }
    }

    fn ctx() -> ProbeCtx {
        ProbeCtx::new(Duration::from_millis(500), 0)
    }

    fn target(last_octet: u8) -> ResolvedTarget {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet));
        ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn open_cancel() -> watch::Receiver<bool> {
        watch::channel(false).1
    }

    fn one(prober: Arc<dyn Prober>) -> Vec<Arc<dyn Prober>> {
        vec![prober]
    }

    // Drives the streaming scan to completion, draining every sent target, and returns them sorted
    // by input-target index so the order/count assertions read against the input ordering.
    async fn collect(
        s: &BoundedScheduler,
        probers: Vec<Arc<dyn Prober>>,
        targets: Vec<ResolvedTarget>,
        ctx: ProbeCtx,
        cancel: watch::Receiver<bool>,
    ) -> Vec<TargetScan> {
        let cap = s.max_concurrent().max(1);
        let (tx, mut rx) = mpsc::channel(cap);
        let scan = s.run_scan(probers, targets, ctx, cancel, tx);
        tokio::pin!(scan);
        let mut out = Vec::new();
        let mut done = false;
        loop {
            tokio::select! {
                biased;
                _ = &mut scan, if !done => { done = true; }
                maybe = rx.recv() => {
                    match maybe {
                        Some(sc) => out.push(sc),
                        None => break,
                    }
                }
            }
        }
        out.sort_by_key(|s| s.target_index);
        out
    }

    // Flattens a single-prober scan back to target-ordered results for the order/error assertions.
    fn single_prober_results(scans: Vec<TargetScan>) -> Vec<Result<ProbeOutcome, RastreoError>> {
        scans
            .into_iter()
            .map(|s| {
                s.outcomes
                    .into_iter()
                    .next()
                    .expect("single-prober scan has one outcome")
                    .1
            })
            .collect()
    }

    #[tokio::test]
    async fn new_normalizes_zero_to_one() {
        let s = BoundedScheduler::new(0);
        assert_eq!(s.max_concurrent(), 1);
    }

    #[tokio::test]
    async fn with_default_concurrency_is_sixty_four() {
        let s = BoundedScheduler::with_default_concurrency();
        assert_eq!(s.max_concurrent(), BoundedScheduler::DEFAULT_MAX_CONCURRENT);
        assert_eq!(s.max_concurrent(), 64);
    }

    #[tokio::test(start_paused = true)]
    async fn probe_rate_paces_starts_to_min_interval() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::clone(&calls),
        });
        // 10 probes/sec => 100ms between starts. 5 starts land at 0,100,200,300,400ms.
        let s = BoundedScheduler::new(64).with_probe_rate(Some(10));
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();
        let start = Instant::now();
        let out = collect(&s, one(prober), targets, ctx(), open_cancel()).await;
        let elapsed = start.elapsed();
        assert_eq!(out.len(), 5);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert!(
            elapsed >= Duration::from_millis(400),
            "5 probes at 10/sec must span >= 400ms, got {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_rate_none_adds_no_latency() {
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let s = BoundedScheduler::new(64);
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();
        let start = Instant::now();
        let out = collect(&s, one(prober), targets, ctx(), open_cancel()).await;
        let elapsed = start.elapsed();
        assert_eq!(out.len(), 5);
        assert!(
            elapsed < Duration::from_millis(1),
            "unpaced scan must not add latency, got {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_rate_zero_disables_pacing() {
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let s = BoundedScheduler::new(64).with_probe_rate(Some(0));
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();
        let start = Instant::now();
        let out = collect(&s, one(prober), targets, ctx(), open_cancel()).await;
        let elapsed = start.elapsed();
        assert_eq!(out.len(), 5);
        assert!(
            elapsed < Duration::from_millis(1),
            "probe_rate 0 must disable pacing, got {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_rate_preserves_input_order() {
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let s = BoundedScheduler::new(64).with_probe_rate(Some(50));
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();
        let out =
            single_prober_results(collect(&s, one(prober), targets, ctx(), open_cancel()).await);
        assert_eq!(out.len(), 5);
        for (i, result) in out.iter().enumerate() {
            let octet = (i as u8) + 1;
            let expected = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
            assert_eq!(result.as_ref().expect("ok").target_ip, expected);
        }
    }

    #[tokio::test]
    async fn run_scan_with_zero_targets_returns_empty_and_skips_prober() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::clone(&calls),
        });
        let s = BoundedScheduler::with_default_concurrency();
        let out = collect(&s, one(prober), Vec::new(), ctx(), open_cancel()).await;
        assert!(out.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn run_scan_with_zero_probers_returns_empty() {
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=3).map(target).collect();
        let out = collect(&s, Vec::new(), targets, ctx(), open_cancel()).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn run_scan_with_single_target_invokes_prober_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::clone(&calls),
        });
        let s = BoundedScheduler::with_default_concurrency();
        let t = target(1);
        let out =
            single_prober_results(collect(&s, one(prober), vec![t], ctx(), open_cancel()).await);
        assert_eq!(out.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let outcome = out[0].as_ref().expect("ok");
        assert_eq!(outcome.target_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[tokio::test]
    async fn run_scan_preserves_input_order_for_many_targets() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::clone(&calls),
        });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();
        let out =
            single_prober_results(collect(&s, one(prober), targets, ctx(), open_cancel()).await);
        assert_eq!(out.len(), 5);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        for (i, result) in out.iter().enumerate() {
            let octet = (i as u8) + 1;
            let expected = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
            assert_eq!(result.as_ref().expect("ok").target_ip, expected);
        }
    }

    #[tokio::test]
    async fn run_scan_surfaces_every_target_under_variable_latency() {
        // Higher-octet targets finish first; the drain sorts by target_index, so every target is
        // surfaced with its own outcome regardless of completion order.
        let prober: Arc<dyn Prober> = Arc::new(DelayProber {
            delays_us: vec![50_000, 40_000, 30_000, 20_000, 10_000],
        });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (0u8..5).map(target).collect();
        let out =
            single_prober_results(collect(&s, one(prober), targets, ctx(), open_cancel()).await);
        assert_eq!(out.len(), 5);
        for (i, result) in out.iter().enumerate() {
            let expected = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8));
            assert_eq!(result.as_ref().expect("ok").target_ip, expected);
        }
    }

    #[tokio::test]
    async fn run_scan_runs_every_prober_against_every_target_once() {
        let probed = Arc::new(AtomicUsize::new(0));
        let mk = |kind: ProbeKind| -> Arc<dyn Prober> {
            Arc::new(SaturationProber {
                kind,
                in_flight: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
                probed: Arc::clone(&probed),
            })
        };
        let probers = vec![
            mk(ProbeKind::TcpConnect),
            mk(ProbeKind::Http),
            mk(ProbeKind::Snmp),
        ];
        let targets: Vec<ResolvedTarget> = (0u8..4).map(target).collect();
        let s = BoundedScheduler::with_default_concurrency();

        let scans = collect(&s, probers, targets, ctx(), open_cancel()).await;

        assert_eq!(scans.len(), 4, "every target fully scanned");
        assert_eq!(probed.load(Ordering::SeqCst), 12, "3 probers x 4 targets");
        for (t, scan) in scans.iter().enumerate() {
            assert_eq!(scan.target_index, t, "targets returned in input order");
            assert_eq!(scan.outcomes.len(), 3, "one outcome per prober");
            let expected = IpAddr::V4(Ipv4Addr::new(10, 0, 0, t as u8));
            for (pass_index, (tagged, result)) in scan.outcomes.iter().enumerate() {
                assert_eq!(*tagged, pass_index, "outcome tagged with its pass index");
                let outcome = result.as_ref().expect("ok");
                assert_eq!(outcome.target_ip, expected);
            }
        }
    }

    #[tokio::test]
    async fn run_scan_tags_outcomes_with_prober_kind_by_pass() {
        let mk = |kind: ProbeKind| -> Arc<dyn Prober> {
            Arc::new(SaturationProber {
                kind,
                in_flight: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
                probed: Arc::new(AtomicUsize::new(0)),
            })
        };
        let kinds = [ProbeKind::Snmp, ProbeKind::TcpConnect, ProbeKind::Dns];
        let probers = vec![mk(kinds[0]), mk(kinds[1]), mk(kinds[2])];
        let targets = vec![target(7)];
        let s = BoundedScheduler::with_default_concurrency();

        let scans = collect(&s, probers, targets, ctx(), open_cancel()).await;
        assert_eq!(scans.len(), 1);
        for (pass_index, (tagged, result)) in scans[0].outcomes.iter().enumerate() {
            assert_eq!(*tagged, pass_index);
            assert_eq!(result.as_ref().expect("ok").kind, kinds[pass_index]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_run_scan_future_aborts_in_flight_probes() {
        let completed = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(SlowCountingProber {
            delay: Duration::from_millis(200),
            completed: Arc::clone(&completed),
        });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=8).map(target).collect();

        let (tx, _rx) = mpsc::channel(64);
        let dropped = tokio::time::timeout(
            Duration::from_millis(50),
            s.run_scan(one(prober), targets, ctx(), open_cancel(), tx),
        )
        .await;
        assert!(
            dropped.is_err(),
            "the timeout must drop the run_scan future mid-scan"
        );

        // Advance past every probe's 200ms completion; aborted tasks never increment, detached ones would.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "dropping the run_scan future must abort in-flight probes, not detach them"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn run_scan_cancel_before_start_primes_nothing() {
        let started = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(StartCountingProber {
            delay: Duration::from_millis(10),
            started: Arc::clone(&started),
        });
        let s = BoundedScheduler::new(4);
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();

        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("send cancel");

        let out = collect(&s, one(prober), targets, ctx(), rx).await;
        assert!(out.is_empty(), "a pre-cancelled scan primes no probes");
        assert_eq!(started.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn run_scan_cancel_stops_priming_and_returns_completed_targets() {
        // cap=2 primes only target 0's + target 1's probe (single prober). Cancel lands before the
        // in-flight probes finish, so targets 2..5 are never scheduled and the finished ones return.
        let started = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(StartCountingProber {
            delay: Duration::from_millis(100),
            started: Arc::clone(&started),
        });
        let s = BoundedScheduler::new(2);
        let targets: Vec<ResolvedTarget> = (0u8..5).map(target).collect();

        let (tx, rx) = watch::channel(false);
        let (out, _) = tokio::join!(collect(&s, one(prober), targets, ctx(), rx), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tx.send(true).expect("send cancel");
        });

        assert_eq!(
            started.load(Ordering::SeqCst),
            2,
            "only the primed probes started"
        );
        let indices: Vec<usize> = out.iter().map(|s| s.target_index).collect();
        assert_eq!(
            indices,
            vec![0, 1],
            "the two primed targets returned in order"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_scan_respects_concurrency_cap() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(PeakProber {
            in_flight: Arc::clone(&in_flight),
            peak: Arc::clone(&peak),
        });
        let s = BoundedScheduler::new(2);
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();
        let out = collect(&s, one(prober), targets, ctx(), open_cancel()).await;
        assert_eq!(out.len(), 5);
        let observed_peak = peak.load(Ordering::SeqCst);
        assert!(
            observed_peak <= 2,
            "peak in-flight {observed_peak} exceeded cap of 2"
        );
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn feed_loop_saturates_caps_refills_and_orders() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let probed = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(SaturationProber {
            kind: ProbeKind::TcpConnect,
            in_flight: Arc::clone(&in_flight),
            peak: Arc::clone(&peak),
            probed: Arc::clone(&probed),
        });
        let cap = 16;
        let s = BoundedScheduler::new(cap);
        let targets: Vec<ResolvedTarget> = (0..500u32)
            .map(|i| {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xff) as u8));
                ResolvedTarget {
                    ip,
                    original: Target::Ip(ip),
                    resolved_at: SystemTime::UNIX_EPOCH,
                }
            })
            .collect();

        let out =
            single_prober_results(collect(&s, one(prober), targets, ctx(), open_cancel()).await);

        assert_eq!(out.len(), 500);
        assert_eq!(probed.load(Ordering::SeqCst), 500);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(
            peak.load(Ordering::SeqCst),
            cap,
            "feed-loop must saturate to and never exceed the cap"
        );
        for (i, result) in out.iter().enumerate() {
            let i = i as u32;
            let expected = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xff) as u8));
            assert_eq!(result.as_ref().expect("ok").target_ip, expected);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn feed_loop_saturates_to_cap_across_the_whole_prober_set() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let probed = Arc::new(AtomicUsize::new(0));
        let mk = |kind: ProbeKind| -> Arc<dyn Prober> {
            Arc::new(SaturationProber {
                kind,
                in_flight: Arc::clone(&in_flight),
                peak: Arc::clone(&peak),
                probed: Arc::clone(&probed),
            })
        };
        let probers = vec![
            mk(ProbeKind::TcpConnect),
            mk(ProbeKind::Http),
            mk(ProbeKind::Snmp),
            mk(ProbeKind::Dns),
        ];
        let cap = 16;
        let s = BoundedScheduler::new(cap);
        let targets: Vec<ResolvedTarget> = (0..100u32)
            .map(|i| {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xff) as u8));
                ResolvedTarget {
                    ip,
                    original: Target::Ip(ip),
                    resolved_at: SystemTime::UNIX_EPOCH,
                }
            })
            .collect();

        let scans = collect(&s, probers, targets, ctx(), open_cancel()).await;

        assert_eq!(scans.len(), 100);
        assert_eq!(
            probed.load(Ordering::SeqCst),
            400,
            "4 probers x 100 targets"
        );
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(
            peak.load(Ordering::SeqCst),
            cap,
            "in-flight probes across every prober must saturate to and never exceed the cap"
        );
    }

    #[tokio::test]
    async fn run_scan_propagates_prober_error_at_failing_index() {
        let prober: Arc<dyn Prober> = Arc::new(FailAtIndexProber { fail_octet: 3 });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=4).map(target).collect();
        let out =
            single_prober_results(collect(&s, one(prober), targets, ctx(), open_cancel()).await);
        assert_eq!(out.len(), 4);
        assert!(out[0].is_ok());
        assert!(out[1].is_ok());
        assert!(matches!(
            out[2],
            Err(RastreoError::Probe(crate::error::ProbeError::Other(_)))
        ));
        assert!(out[3].is_ok());
    }

    #[tokio::test]
    async fn run_scan_maps_prober_panic_to_runtime_task_panicked() {
        let prober: Arc<dyn Prober> = Arc::new(PanicAtIndexProber { panic_octet: 2 });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=3).map(target).collect();
        let out =
            single_prober_results(collect(&s, one(prober), targets, ctx(), open_cancel()).await);
        assert_eq!(out.len(), 3);
        assert!(out[0].is_ok());
        assert!(matches!(
            out[1],
            Err(RastreoError::Runtime(RuntimeError::TaskPanicked(_)))
        ));
        assert!(out[2].is_ok());
    }

    #[tokio::test]
    async fn resolver_to_scheduler_pipeline_probes_each_host() {
        let resolver = HickoryResolver::from_system().expect("system resolver init");
        let net: ipnet::IpNet = "10.0.0.0/30".parse().expect("cidr");
        let resolved = resolver.resolve(&Target::Cidr(net)).await.expect("resolve");
        assert_eq!(resolved.len(), 2);
        let calls = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::clone(&calls),
        });
        let scheduler = BoundedScheduler::with_default_concurrency();
        let out = single_prober_results(
            collect(&scheduler, one(prober), resolved, ctx(), open_cancel()).await,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        for result in &out {
            assert!(result.as_ref().expect("ok").reachable);
        }
    }

    #[test]
    fn bounded_scheduler_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<BoundedScheduler>();
        assert_send_sync::<dyn Scheduler>();
        assert_send_sync::<Box<dyn Scheduler>>();
    }
}
