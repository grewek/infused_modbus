// Self-healing for the one `Connection` every configured machine's polling
// task and the transaction consumer share (see CLAUDE.md's multi-machine
// design) — before this module existed, `main` connected exactly once at
// startup and never again (its own doc comment used to say so explicitly):
// a connection that died (server restart, network blip, unplugged serial
// adapter, ...) stayed dead until the whole client process was restarted
// by hand, no matter how long `client` kept running afterward.
//
// Detection happens where the connection is already exercised continuously
// regardless of write activity: `client::polling`'s poll loop runs every
// `poll_interval` no matter what, so it's the natural, already-existing
// place to notice a broken connection quickly — see its own call sites of
// `ReconnectSignal::mark_broken`. The transaction/write path doesn't need
// its own detection wired in: a write attempted against a still-broken
// connection already reports `WriteStatus::Failed` correctly today (see
// write_confirmation.rs), and once polling's own detection heals the
// shared `Connection`, the next write just works again.
//
// Reconnection itself runs on one dedicated task reading from a shared
// `ReconnectSignal`, not inline in the failing request — a failed
// poll/write shouldn't block waiting for a fresh connection, and several
// simultaneous failures (e.g. every data type's poll batch failing in the
// same tick) must collapse into one reconnect attempt, not each
// independently start redialing.

use crate::connection::Connection;
use protocol::connection_string::ConnectionTarget;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, Notify};

// Confirmed with the project owner: retries forever, no giving-up-after-N-
// attempts cutoff — a client that outlives a server restart or a transient
// network problem should keep trying indefinitely rather than requiring a
// manual restart once some attempt count is exhausted.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Shared between every task that issues requests over the one `Connection`
/// and the dedicated reconnect task (`run_reconnect_loop`) below.
/// `mark_broken` is cheap and idempotent to call from anywhere a request
/// just failed with an I/O error — multiple simultaneous callers collapse
/// into a single reconnect attempt (`Notify::notify_one` only ever stores
/// one pending wakeup, regardless of how many times it's called before
/// something consumes it).
pub struct ReconnectSignal {
    notify: Notify,
    broken: AtomicBool,
}

impl ReconnectSignal {
    pub fn new() -> Self {
        Self {
            notify: Notify::new(),
            broken: AtomicBool::new(false),
        }
    }

    pub fn mark_broken(&self) {
        self.broken.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// For tests: whether `mark_broken` has been called since the last time
    /// the reconnect loop consumed it. Not used by any production code path
    /// (the reconnect loop itself uses `broken.swap` directly, since it
    /// needs to atomically read-and-clear in one step).
    pub fn is_broken(&self) -> bool {
        self.broken.load(Ordering::SeqCst)
    }
}

impl Default for ReconnectSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Redials `target` fresh — the same per-scheme dispatch `main::open_connection`
/// uses once at startup, reused here so a reconnect attempt doesn't
/// duplicate it. Unlike startup connecting (where failing to connect at
/// all is treated as fatal), a failed redial here is routine and
/// expected — returns an `io::Result` instead of panicking, so the
/// caller's backoff loop can just try again.
pub async fn redial(
    handle: &tokio::runtime::Handle,
    target: &ConnectionTarget,
    expected_server_fingerprint: Option<protocol::tls::Fingerprint>,
    client_tls_identity_directory: &Path,
) -> std::io::Result<Connection> {
    match target {
        ConnectionTarget::Tcp { address } => Connection::connect_tcp(address).await,
        ConnectionTarget::TlsTcp { address } => {
            // Not yet policed by the server (client approval is milestone
            // N) — see CLAUDE.md's TLS design. Loaded fresh (not reprinted)
            // on every reconnect attempt; `main::open_connection` prints it
            // once at startup, so repeating the same unchanged value on
            // every retry would just be log noise.
            let client_identity =
                protocol::tls::load_or_generate_identity(client_tls_identity_directory)?;
            Connection::connect_tls(address, expected_server_fingerprint, Some(client_identity))
                .await
        }
        ConnectionTarget::Rtu { path, baud_rate } => {
            // See client::connection::Connection::open_rtu: tokio-serial
            // registers the file descriptor with the reactor immediately
            // at open time, so opening it needs an active runtime context
            // even though this isn't an async call.
            let _guard = handle.enter();
            Connection::open_rtu(handle, path, *baud_rate)
        }
    }
}

/// Runs forever, healing `connection` whenever `signal` reports it broken —
/// spawn this once per client process (one `Connection`, shared by every
/// machine's polling task and the transaction consumer). Retries with
/// exponential backoff (`INITIAL_BACKOFF`, doubling, capped at
/// `MAX_BACKOFF`) and never gives up on its own — see `ReconnectSignal`'s
/// own doc comment for why.
pub async fn run_reconnect_loop(
    connection: Arc<AsyncMutex<Connection>>,
    signal: Arc<ReconnectSignal>,
    handle: tokio::runtime::Handle,
    target: ConnectionTarget,
    expected_server_fingerprint: Option<protocol::tls::Fingerprint>,
    client_tls_identity_directory: std::path::PathBuf,
) {
    loop {
        signal.notify.notified().await;
        // Only `mark_broken` actually starts a reconnect pass — a stray
        // extra wakeup (e.g. from a failure reported against the
        // now-already-dead-and-about-to-be-replaced connection while a
        // previous pass was still redialing) finds `broken` already
        // cleared and just goes back to waiting.
        if !signal.broken.swap(false, Ordering::SeqCst) {
            continue;
        }
        eprintln!("Connection lost — attempting to reconnect...");
        let mut backoff = INITIAL_BACKOFF;
        loop {
            match redial(
                &handle,
                &target,
                expected_server_fingerprint,
                &client_tls_identity_directory,
            )
            .await
            {
                Ok(new_connection) => {
                    *connection.lock().await = new_connection;
                    println!("Reconnected.");
                    break;
                }
                Err(error) => {
                    eprintln!(
                        "Reconnect failed ({error}), retrying in {}s...",
                        backoff.as_secs()
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_broken_sets_the_flag() {
        let signal = ReconnectSignal::new();
        assert!(!signal.broken.load(Ordering::SeqCst));
        signal.mark_broken();
        assert!(signal.broken.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn mark_broken_wakes_a_waiting_notified_call() {
        let signal = Arc::new(ReconnectSignal::new());
        let waiter = {
            let signal = Arc::clone(&signal);
            tokio::spawn(async move {
                signal.notify.notified().await;
            })
        };
        // Give the spawned task a chance to actually start waiting before
        // marking broken — otherwise this could race and notify before
        // anyone's listening (Notify still stores the permit for the next
        // `notified()` call in that case, so this isn't strictly required
        // for correctness, just for making the test deterministic about
        // what it's exercising).
        tokio::task::yield_now().await;
        signal.mark_broken();

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("mark_broken should have woken the waiting notified() call")
            .unwrap();
    }

    #[tokio::test]
    async fn redial_over_tcp_reconnects_to_the_same_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let target = ConnectionTarget::Tcp {
            address: address.clone(),
        };

        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });

        let handle = tokio::runtime::Handle::current();
        let connection = redial(&handle, &target, None, Path::new("unused-for-tcp"))
            .await
            .unwrap();

        accept_task.await.unwrap();
        assert!(matches!(connection, Connection::Tcp { .. }));
    }

    #[tokio::test]
    async fn redial_over_tcp_fails_when_nothing_is_listening() {
        // Port 0 always fails to connect to directly (it only means
        // "pick any free port" when *binding*) — a reliable way to
        // exercise the failure path without racing a real listener.
        let target = ConnectionTarget::Tcp {
            address: "127.0.0.1:0".to_string(),
        };
        let handle = tokio::runtime::Handle::current();
        let result = redial(&handle, &target, None, Path::new("unused-for-tcp")).await;
        assert!(result.is_err());
    }
}
