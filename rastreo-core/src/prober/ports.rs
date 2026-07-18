use std::future::Future;
use std::sync::Arc;

use futures_util::future::join_all;
use tokio::sync::Semaphore;

/// Per-target ceiling on how many of a single target's ports probe at once, bounding one target's
/// pending-future memory. File-descriptor exhaustion is bounded separately and globally by the
/// `ProbeCtx::port_budget` semaphore threaded into `probe_ports`.
pub(crate) const MAX_PORTS_IN_FLIGHT: usize = 32;

/// Runs `per_port` for every port concurrently and returns results in port order (not completion
/// order) so each prober folds them exactly as it would a serial sweep. Two bounds compose:
/// `max_in_flight` walks the ports in waves to cap one target's pending futures (memory), and
/// `budget`, when `Some`, caps total in-flight socket ops across every target (file descriptors).
pub(crate) async fn probe_ports<T, F, Fut>(
    ports: &[u16],
    max_in_flight: usize,
    budget: Option<&Arc<Semaphore>>,
    per_port: F,
) -> Vec<T>
where
    F: Fn(u16) -> Fut,
    Fut: Future<Output = T>,
{
    let cap = max_in_flight.max(1);
    let mut results = Vec::with_capacity(ports.len());
    for wave in ports.chunks(cap) {
        results.extend(
            join_all(wave.iter().map(|&port| {
                let budget = budget.cloned();
                let fut = per_port(port);
                async move {
                    // Hold a permit only for this one op so permits always free — a target never
                    // waits for more permits while holding one, so the shared pool cannot deadlock.
                    let _permit = match budget {
                        Some(sem) => Some(
                            sem.acquire_owned()
                                .await
                                .expect("port budget semaphore is never closed"),
                        ),
                        None => None,
                    };
                    fut.await
                }
            }))
            .await,
        );
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn returns_empty_for_no_ports() {
        let out = probe_ports(&[], 4, None, |port: u16| async move { port }).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn maps_each_port_once_in_input_order() {
        let out = probe_ports(&[22, 80, 443], 8, None, |port| async move { port * 2 }).await;
        assert_eq!(out, vec![44, 160, 886]);
    }

    #[tokio::test]
    async fn preserves_port_order_regardless_of_completion_order() {
        // Smaller index sleeps longest, so completion order is the reverse of input order.
        let out = probe_ports(&[10u16, 20, 30, 40], 8, None, |port| async move {
            tokio::time::sleep(Duration::from_millis(80u64.saturating_sub(port as u64))).await;
            port
        })
        .await;
        assert_eq!(out, vec![10, 20, 30, 40]);
    }

    #[tokio::test]
    async fn preserves_port_order_across_waves() {
        let out = probe_ports(&[1u16, 2, 3, 4, 5], 2, None, |port| async move {
            tokio::time::sleep(Duration::from_millis((10 - port as u64) * 5)).await;
            port
        })
        .await;
        assert_eq!(out, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn runs_ports_within_cap_concurrently() {
        let ports: Vec<u16> = (0..8).collect();
        let start = Instant::now();
        probe_ports(&ports, 8, None, |_port| async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
        })
        .await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(300),
            "eight 100ms ports run concurrently should finish near 1x, got {elapsed:?}"
        );
    }

    async fn observe_peak(port_count: u16, cap: usize) -> usize {
        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let ports: Vec<u16> = (0..port_count).collect();
        let cur = Arc::clone(&current);
        let pk = Arc::clone(&peak);
        probe_ports(&ports, cap, None, move |_port| {
            let cur = Arc::clone(&cur);
            let pk = Arc::clone(&pk);
            async move {
                let in_flight = cur.fetch_add(1, Ordering::SeqCst) + 1;
                pk.fetch_max(in_flight, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                cur.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;
        peak.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn bounds_in_flight_to_cap() {
        let peak = observe_peak(12, 4).await;
        assert!(peak <= 4, "peak {peak} exceeded cap 4");
        assert_eq!(peak, 4, "waves should fill up to the cap");
    }

    #[tokio::test]
    async fn respects_max_ports_in_flight_const() {
        let peak = observe_peak(MAX_PORTS_IN_FLIGHT as u16 + 8, MAX_PORTS_IN_FLIGHT).await;
        assert!(
            peak <= MAX_PORTS_IN_FLIGHT,
            "peak {peak} exceeded MAX_PORTS_IN_FLIGHT {MAX_PORTS_IN_FLIGHT}"
        );
        assert_eq!(peak, MAX_PORTS_IN_FLIGHT);
    }
}
