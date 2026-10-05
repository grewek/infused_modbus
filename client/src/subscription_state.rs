//! Tracks, per machine, whether it is currently "active" under the `mqtt`
//! representation layer's dynamic per-machine subscription model — see
//! CLAUDE.md's "Planned: dynamic per-machine subscription via Sparkplug B".
//! Every machine starts dormant (no entry here) right after its placeholder
//! `DBIRTH` (see `client::sparkplug_translator::
//! build_machine_metrics_null_placeholders`); a Subscribe `NCMD` activates
//! it by spawning its Modbus polling task and DDATA ticker and registering
//! both here (not yet wired — Thread C5); an Unsubscribe `NCMD` aborts and
//! removes them again (Thread C6). This module only holds the bookkeeping —
//! it doesn't itself spawn or decode anything.

use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// The two background tasks a subscribed machine runs: its Modbus polling
/// loop (`client::polling::run_polling_loop`) and its periodic DDATA
/// publisher. Always started/stopped together — neither is meaningful
/// without the other, so `SubscriptionState` only ever tracks them as a
/// pair, never individually.
pub struct MachineTasks {
    pub polling: JoinHandle<()>,
    pub ddata_ticker: JoinHandle<()>,
}

impl MachineTasks {
    /// Aborts both tasks. `JoinHandle::abort` is fire-and-forget — doesn't
    /// block on the task actually stopping, matching every other shutdown
    /// path in this project (e.g. `wait_for_shutdown_signal` doesn't join
    /// spawned tasks either).
    pub fn abort(&self) {
        self.polling.abort();
        self.ddata_ticker.abort();
    }
}

/// Which machines currently have their tasks running. Shared via `Arc`
/// across the NCMD handler task (which mutates it) and anything else that
/// needs to query activation state.
#[derive(Default)]
pub struct SubscriptionState {
    active: Mutex<HashMap<String, MachineTasks>>,
}

impl SubscriptionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `machine_name` currently has tasks tracked as running.
    pub async fn is_active(&self, machine_name: &str) -> bool {
        self.active.lock().await.contains_key(machine_name)
    }

    /// Registers `tasks` as the running tasks for `machine_name`. If the
    /// machine was already active, the previous tasks are aborted first — a
    /// duplicate Subscribe for an already-active machine replaces its tasks
    /// idempotently rather than leaking a second pair.
    pub async fn activate(&self, machine_name: String, tasks: MachineTasks) {
        let mut active = self.active.lock().await;
        if let Some(previous) = active.insert(machine_name, tasks) {
            previous.abort();
        }
    }

    /// Aborts and removes `machine_name`'s tracked tasks, if any. Returns
    /// whether it was actually active — an Unsubscribe for a machine that
    /// was never (or no longer) active is a no-op, not an error.
    pub async fn deactivate(&self, machine_name: &str) -> bool {
        let mut active = self.active.lock().await;
        match active.remove(machine_name) {
            Some(tasks) => {
                tasks.abort();
                true
            }
            None => false,
        }
    }

    /// Whether no machine is currently active — the dormant bootstrap state
    /// (see CLAUDE.md: unsubscribing the last machine returns the whole
    /// client here, zero Modbus traffic, waiting for a new Subscribe).
    pub async fn is_dormant(&self) -> bool {
        self.active.lock().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_task() -> JoinHandle<()> {
        tokio::spawn(std::future::pending())
    }

    /// A task that never completes on its own, but flips a shared flag to
    /// `true` when its future is dropped — the only way to observe that
    /// `abort()` actually cancelled it (an aborted `JoinHandle` is moved out
    /// and dropped by `SubscriptionState` itself, so the handle's own
    /// `is_finished()` isn't observable from the test).
    fn pending_task_with_drop_flag() -> (
        JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = SetOnDrop(Arc::clone(&dropped));
        let handle = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        (handle, dropped)
    }

    #[tokio::test]
    async fn starts_dormant() {
        let state = SubscriptionState::new();
        assert!(state.is_dormant().await);
        assert!(!state.is_active("PumpA").await);
    }

    #[tokio::test]
    async fn activate_makes_a_machine_active_and_not_dormant() {
        let state = SubscriptionState::new();
        state
            .activate(
                "PumpA".to_string(),
                MachineTasks {
                    polling: pending_task(),
                    ddata_ticker: pending_task(),
                },
            )
            .await;

        assert!(state.is_active("PumpA").await);
        assert!(!state.is_dormant().await);
    }

    #[tokio::test]
    async fn deactivate_removes_a_machine_and_returns_true() {
        let state = SubscriptionState::new();
        state
            .activate(
                "PumpA".to_string(),
                MachineTasks {
                    polling: pending_task(),
                    ddata_ticker: pending_task(),
                },
            )
            .await;

        assert!(state.deactivate("PumpA").await);
        assert!(!state.is_active("PumpA").await);
        assert!(state.is_dormant().await);
    }

    #[tokio::test]
    async fn deactivate_an_inactive_machine_returns_false() {
        let state = SubscriptionState::new();
        assert!(!state.deactivate("PumpA").await);
    }

    #[tokio::test]
    async fn deactivate_aborts_the_tracked_tasks() {
        let state = SubscriptionState::new();
        let (polling, polling_dropped) = pending_task_with_drop_flag();
        let (ddata_ticker, ticker_dropped) = pending_task_with_drop_flag();
        state
            .activate(
                "PumpA".to_string(),
                MachineTasks {
                    polling,
                    ddata_ticker,
                },
            )
            .await;

        assert!(state.deactivate("PumpA").await);

        // abort() only requests cancellation — give the runtime a moment to
        // actually drop the aborted task's future.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(polling_dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(ticker_dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn activating_an_already_active_machine_aborts_the_previous_tasks() {
        let state = SubscriptionState::new();
        let (polling, polling_dropped) = pending_task_with_drop_flag();
        let (ddata_ticker, ticker_dropped) = pending_task_with_drop_flag();
        state
            .activate(
                "PumpA".to_string(),
                MachineTasks {
                    polling,
                    ddata_ticker,
                },
            )
            .await;
        state
            .activate(
                "PumpA".to_string(),
                MachineTasks {
                    polling: pending_task(),
                    ddata_ticker: pending_task(),
                },
            )
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(polling_dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(ticker_dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(state.is_active("PumpA").await);
    }

    #[tokio::test]
    async fn multiple_machines_track_independently() {
        let state = SubscriptionState::new();
        state
            .activate(
                "PumpA".to_string(),
                MachineTasks {
                    polling: pending_task(),
                    ddata_ticker: pending_task(),
                },
            )
            .await;
        state
            .activate(
                "PumpB".to_string(),
                MachineTasks {
                    polling: pending_task(),
                    ddata_ticker: pending_task(),
                },
            )
            .await;

        assert!(state.deactivate("PumpA").await);
        assert!(state.is_active("PumpB").await);
        assert!(!state.is_dormant().await);

        assert!(state.deactivate("PumpB").await);
        assert!(state.is_dormant().await);
    }
}
