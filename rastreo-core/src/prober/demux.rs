use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;

use tokio::sync::oneshot;

use crate::model::ProbeFault;

/// What a demux waiter receives: `Reached` from the reader on a matched reply, `Failed` from
/// `poison` when the engine dies. A waiter that times out with NO delivery reads absence.
pub(crate) enum EngineReply<R> {
    Reached(R),
    Failed(ProbeFault),
}

struct Waiter<C, R> {
    context: C,
    tx: oneshot::Sender<EngineReply<R>>,
}

struct State<K, C, R> {
    waiters: HashMap<K, Waiter<C, R>>,
    poison: Option<ProbeFault>,
}

/// Correlates one shared reader against many in-flight waiters by key. Generic over the key `K`,
/// the per-waiter context `C` the reader reads to validate a reply, and the reached payload `R`.
pub(crate) struct Demux<K, C, R> {
    state: Mutex<State<K, C, R>>,
}

impl<K, C, R> Default for Demux<K, C, R> {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                waiters: HashMap::new(),
                poison: None,
            }),
        }
    }
}

impl<K, C, R> Demux<K, C, R>
where
    K: Eq + Hash,
    C: Clone,
{
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Registers a waiter and hands back its receiver. On an already-poisoned engine the receiver
    /// is completed with the poison fault immediately, so a probe racing the reader's death faults
    /// rather than falling through to a bogus absence.
    pub(crate) fn register(&self, key: K, context: C) -> oneshot::Receiver<EngineReply<R>> {
        let (tx, rx) = oneshot::channel();
        let mut state = self.lock();
        match &state.poison {
            Some(fault) => {
                let _ = tx.send(EngineReply::Failed(fault.clone()));
            }
            None => {
                state.waiters.insert(key, Waiter { context, tx });
            }
        }
        rx
    }

    pub(crate) fn context(&self, key: &K) -> Option<C> {
        self.lock().waiters.get(key).map(|w| w.context.clone())
    }

    pub(crate) fn dispatch(&self, key: &K, reply: EngineReply<R>) {
        if let Some(waiter) = self.lock().waiters.remove(key) {
            // Send-after-drop (the waiter already timed out and dropped its receiver) is a no-op.
            let _ = waiter.tx.send(reply);
        }
    }

    pub(crate) fn deregister(&self, key: &K) {
        self.lock().waiters.remove(key);
    }

    /// Marks the engine dead and wakes every in-flight waiter with `fault`; future `register`
    /// calls return the same fault. First poison wins.
    pub(crate) fn poison(&self, fault: ProbeFault) {
        let mut state = self.lock();
        if state.poison.is_some() {
            return;
        }
        state.poison = Some(fault.clone());
        for (_, waiter) in state.waiters.drain() {
            let _ = waiter.tx.send(EngineReply::Failed(fault.clone()));
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State<K, C, R>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn waiter_count(&self) -> usize {
        self.lock().waiters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProbeErrorKind;

    fn fault(detail: &str) -> ProbeFault {
        ProbeFault::new(ProbeErrorKind::Other, detail.to_string())
    }

    #[tokio::test]
    async fn register_then_dispatch_delivers_to_the_matching_waiter() {
        let demux: Demux<u64, (), u32> = Demux::new();
        let rx_a = demux.register(1, ());
        let rx_b = demux.register(2, ());

        demux.dispatch(&1, EngineReply::Reached(111));
        demux.dispatch(&2, EngineReply::Reached(222));

        assert!(matches!(rx_a.await, Ok(EngineReply::Reached(111))));
        assert!(matches!(rx_b.await, Ok(EngineReply::Reached(222))));
    }

    #[tokio::test]
    async fn dispatch_carries_the_registered_context_to_the_reader() {
        let demux: Demux<u64, &'static str, u32> = Demux::new();
        let _rx = demux.register(7, "ctx-7");
        assert_eq!(demux.context(&7), Some("ctx-7"));
        assert_eq!(demux.context(&8), None);
    }

    #[tokio::test]
    async fn deregister_drops_the_waiter_so_a_late_reply_is_ignored() {
        let demux: Demux<u64, (), u32> = Demux::new();
        let rx = demux.register(1, ());
        demux.deregister(&1);
        assert_eq!(demux.waiter_count(), 0);

        demux.dispatch(&1, EngineReply::Reached(9));
        assert!(
            rx.await.is_err(),
            "a deregistered waiter never resolves to a reply"
        );
    }

    #[tokio::test]
    async fn a_second_reply_for_a_resolved_waiter_is_dropped() {
        let demux: Demux<u64, (), u32> = Demux::new();
        let rx = demux.register(1, ());

        demux.dispatch(&1, EngineReply::Reached(1));
        demux.dispatch(&1, EngineReply::Reached(2));

        assert!(matches!(rx.await, Ok(EngineReply::Reached(1))));
        assert_eq!(demux.waiter_count(), 0);
    }

    #[tokio::test]
    async fn a_late_reply_after_the_receiver_is_dropped_is_a_silent_no_op() {
        let demux: Demux<u64, (), u32> = Demux::new();
        let rx = demux.register(1, ());
        drop(rx);
        demux.dispatch(&1, EngineReply::Reached(1));
    }

    #[tokio::test]
    async fn a_reply_for_an_unregistered_key_is_dropped() {
        let demux: Demux<u64, (), u32> = Demux::new();
        demux.dispatch(&42, EngineReply::Reached(1));
        assert_eq!(demux.waiter_count(), 0);
    }

    #[tokio::test]
    async fn poison_wakes_every_waiter_with_a_fault_not_an_absence() {
        let demux: Demux<u64, (), u32> = Demux::new();
        let rx_a = demux.register(1, ());
        let rx_b = demux.register(2, ());
        let rx_c = demux.register(3, ());

        demux.poison(fault("reader died"));

        for rx in [rx_a, rx_b, rx_c] {
            match rx.await {
                Ok(EngineReply::Failed(f)) => assert_eq!(f.detail, "reader died"),
                _ => panic!("a poisoned engine wakes waiters with a fault, not an absence"),
            }
        }
        assert_eq!(demux.waiter_count(), 0);
    }

    #[tokio::test]
    async fn register_after_poison_returns_the_fault() {
        let demux: Demux<u64, (), u32> = Demux::new();
        demux.poison(fault("reader died"));

        let rx = demux.register(1, ());
        match rx.await {
            Ok(EngineReply::Failed(f)) => assert_eq!(f.detail, "reader died"),
            _ => panic!(
                "registering on a poisoned engine must return the fault, not hang or absence"
            ),
        }
    }

    #[tokio::test]
    async fn poison_is_first_write_wins() {
        let demux: Demux<u64, (), u32> = Demux::new();
        let rx = demux.register(1, ());
        demux.poison(fault("first"));
        demux.poison(fault("second"));
        match rx.await {
            Ok(EngineReply::Failed(f)) => assert_eq!(f.detail, "first"),
            _ => panic!("first poison wins"),
        }
    }
}
