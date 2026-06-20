use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

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

pub struct BoundedScheduler {
    max_concurrent: usize,
}

impl BoundedScheduler {
    pub const DEFAULT_MAX_CONCURRENT: usize = 64;

    // A cap of 0 would deadlock the semaphore; coerce to 1 (serial) instead of panicking.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent: max_concurrent.max(1),
        }
    }

    pub fn with_default_concurrency() -> Self {
        Self::new(Self::DEFAULT_MAX_CONCURRENT)
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }
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

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut handles: Vec<JoinHandle<Result<ProbeOutcome, RastreoError>>> =
            Vec::with_capacity(targets.len());

        // Order-preserving spawn: collect JoinHandles in input order and await sequentially.
        // Tasks still execute in parallel on the multi-thread runtime; await order alone
        // determines result order.
        for target in targets {
            let permit_source = Arc::clone(&semaphore);
            let prober_for_task = Arc::clone(&prober);
            let ctx_for_task = ctx.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit_source
                    .acquire_owned()
                    .await
                    .expect("scheduler semaphore is never closed");
                prober_for_task.probe(&target, &ctx_for_task).await
            });
            handles.push(handle);
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(probe_result) => results.push(probe_result),
                Err(join_err) => {
                    let reason = if join_err.is_panic() {
                        "prober task panicked"
                    } else {
                        "prober task cancelled"
                    };
                    results.push(Err(RastreoError::Runtime(RuntimeError::TaskPanicked(
                        reason.to_string(),
                    ))));
                }
            }
        }
        results
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
                return Err(RastreoError::Probe(crate::error::ProbeError::Unreachable {
                    target: target.ip.to_string(),
                }));
            }
            Ok(ProbeOutcome {
                kind: ProbeKind::TcpConnect,
                target_ip: target.ip,
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: Vec::new(),
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
            Err(RastreoError::Probe(
                crate::error::ProbeError::Unreachable { .. }
            ))
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
