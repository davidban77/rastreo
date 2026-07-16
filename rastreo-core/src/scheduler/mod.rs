use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::{Id, JoinSet};
use tokio::time::Instant;

use crate::error::{RastreoError, RuntimeError};
use crate::model::{ProbeCtx, ProbeOutcome, ResolvedTarget};
use crate::prober::Prober;

#[async_trait::async_trait]
pub trait Scheduler: Send + Sync {
    async fn run(
        &self,
        prober: Arc<dyn Prober>,
        targets: Vec<ResolvedTarget>,
        ctx: ProbeCtx,
    ) -> Vec<Result<ProbeOutcome, RastreoError>>;
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

fn spawn_probe(
    set: &mut JoinSet<Result<ProbeOutcome, RastreoError>>,
    index_by_id: &mut HashMap<Id, usize>,
    index: usize,
    target: ResolvedTarget,
    prober: &Arc<dyn Prober>,
    ctx: &ProbeCtx,
    pacer: &Option<Arc<Pacer>>,
) {
    let prober_for_task = Arc::clone(prober);
    let ctx_for_task = ctx.clone();
    let pacer_for_task = pacer.clone();

    let handle = set.spawn(async move {
        if let Some(pacer) = pacer_for_task {
            pacer.wait_for_slot().await;
        }
        prober_for_task.probe(&target, &ctx_for_task).await
    });
    index_by_id.insert(handle.id(), index);
}

#[async_trait::async_trait]
impl Scheduler for BoundedScheduler {
    async fn run(
        &self,
        prober: Arc<dyn Prober>,
        targets: Vec<ResolvedTarget>,
        ctx: ProbeCtx,
    ) -> Vec<Result<ProbeOutcome, RastreoError>> {
        if targets.is_empty() {
            return Vec::new();
        }

        let len = targets.len();

        // JoinSet aborts every spawned probe on drop, bounding an abandoned scan to the request-timeout instead of leaking detached tasks.
        let mut set: JoinSet<Result<ProbeOutcome, RastreoError>> = JoinSet::new();
        let mut index_by_id: HashMap<Id, usize> = HashMap::with_capacity(len);
        let mut slots: Vec<Option<Result<ProbeOutcome, RastreoError>>> =
            (0..len).map(|_| None).collect();

        let mut pending = targets.into_iter().enumerate();
        for _ in 0..self.max_concurrent {
            match pending.next() {
                Some((index, target)) => {
                    spawn_probe(
                        &mut set,
                        &mut index_by_id,
                        index,
                        target,
                        &prober,
                        &ctx,
                        &self.pacer,
                    );
                }
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
            if let Some(&index) = index_by_id.get(&id) {
                slots[index] = Some(outcome);
            }
            if let Some((index, target)) = pending.next() {
                spawn_probe(
                    &mut set,
                    &mut index_by_id,
                    index,
                    target,
                    &prober,
                    &ctx,
                    &self.pacer,
                );
            }
        }

        slots
            .into_iter()
            .map(|slot| slot.expect("every spawned probe reports its index exactly once"))
            .collect()
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
        in_flight: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        probed: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Prober for SaturationProber {
        fn kind(&self) -> ProbeKind {
            ProbeKind::TcpConnect
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
                kind: ProbeKind::TcpConnect,
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
        ProbeCtx {
            timeout: Duration::from_millis(500),
            retries: 0,
        }
    }

    fn target(last_octet: u8) -> ResolvedTarget {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet));
        ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        }
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
        let out = s.run(prober, targets, ctx()).await;
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
        let out = s.run(prober, targets, ctx()).await;
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
        let out = s.run(prober, targets, ctx()).await;
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
        let out = s.run(prober, targets, ctx()).await;
        assert_eq!(out.len(), 5);
        for (i, result) in out.iter().enumerate() {
            let octet = (i as u8) + 1;
            let expected = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
            assert_eq!(result.as_ref().expect("ok").target_ip, expected);
        }
    }

    #[tokio::test]
    async fn run_with_zero_targets_returns_empty_and_skips_prober() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::clone(&calls),
        });
        let s = BoundedScheduler::with_default_concurrency();
        let out = s.run(prober, Vec::new(), ctx()).await;
        assert!(out.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn run_with_single_target_invokes_prober_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::clone(&calls),
        });
        let s = BoundedScheduler::with_default_concurrency();
        let t = target(1);
        let out = s.run(prober, vec![t], ctx()).await;
        assert_eq!(out.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let outcome = out[0].as_ref().expect("ok");
        assert_eq!(outcome.target_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[tokio::test]
    async fn run_preserves_input_order_for_many_targets() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(CountingProber {
            calls: Arc::clone(&calls),
        });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();
        let out = s.run(prober, targets, ctx()).await;
        assert_eq!(out.len(), 5);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        for (i, result) in out.iter().enumerate() {
            let octet = (i as u8) + 1;
            let expected = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
            assert_eq!(result.as_ref().expect("ok").target_ip, expected);
        }
    }

    #[tokio::test]
    async fn run_preserves_input_order_under_variable_latency() {
        // Higher-octet targets finish first; result order must still follow input order.
        let prober: Arc<dyn Prober> = Arc::new(DelayProber {
            delays_us: vec![50_000, 40_000, 30_000, 20_000, 10_000],
        });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (0u8..5).map(target).collect();
        let out = s.run(prober, targets, ctx()).await;
        assert_eq!(out.len(), 5);
        for (i, result) in out.iter().enumerate() {
            let expected = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8));
            assert_eq!(result.as_ref().expect("ok").target_ip, expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_run_future_aborts_in_flight_probes() {
        let completed = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(SlowCountingProber {
            delay: Duration::from_millis(200),
            completed: Arc::clone(&completed),
        });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=8).map(target).collect();

        let dropped =
            tokio::time::timeout(Duration::from_millis(50), s.run(prober, targets, ctx())).await;
        assert!(
            dropped.is_err(),
            "the timeout must drop the run future mid-scan"
        );

        // Advance past every probe's 200ms completion; aborted tasks never increment, detached ones would.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "dropping the run future must abort in-flight probes, not detach them"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_respects_concurrency_cap() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let prober: Arc<dyn Prober> = Arc::new(PeakProber {
            in_flight: Arc::clone(&in_flight),
            peak: Arc::clone(&peak),
        });
        let s = BoundedScheduler::new(2);
        let targets: Vec<ResolvedTarget> = (1u8..=5).map(target).collect();
        let out = s.run(prober, targets, ctx()).await;
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

        let out = s.run(prober, targets, ctx()).await;

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

    #[tokio::test]
    async fn run_propagates_prober_error_at_failing_index() {
        let prober: Arc<dyn Prober> = Arc::new(FailAtIndexProber { fail_octet: 3 });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=4).map(target).collect();
        let out = s.run(prober, targets, ctx()).await;
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
    async fn run_maps_prober_panic_to_runtime_task_panicked() {
        let prober: Arc<dyn Prober> = Arc::new(PanicAtIndexProber { panic_octet: 2 });
        let s = BoundedScheduler::with_default_concurrency();
        let targets: Vec<ResolvedTarget> = (1u8..=3).map(target).collect();
        let out = s.run(prober, targets, ctx()).await;
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
        let out = scheduler.run(prober, resolved, ctx()).await;
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
