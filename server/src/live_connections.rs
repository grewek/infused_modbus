// Tracks currently-open TLS connections per approved client fingerprint,
// so Milestone R's `REVOKE` can actually terminate an already-open
// connection, not just block future handshakes (see CLAUDE.md:
// "Revoking a fingerprint must actively terminate any already-open
// connection using it, not just block future handshakes"). R1 scope
// only: the tracking/cancellation data structure itself, fully unit
// tested — not yet wired into the real TLS accept loop or the admin
// `REVOKE` command (that's R2). Plain data structure, no interior
// mutability, same externally-applied `Arc<Mutex<LiveConnections>>`
// sharing convention as `ApprovedClients`/`ClientTrustState`.

use protocol::tls::Fingerprint;
use std::collections::HashMap;
use tokio::sync::oneshot;

/// Identifies one registered connection so `deregister` can remove exactly
/// that entry (and no other connection sharing the same fingerprint).
/// Opaque on purpose — the id has no meaning outside this module.
pub struct ConnectionHandle {
    fingerprint: Fingerprint,
    id: u64,
}

#[derive(Debug, Default)]
pub struct LiveConnections {
    by_fingerprint: HashMap<Fingerprint, HashMap<u64, oneshot::Sender<()>>>,
    next_id: u64,
    // Milestone U3: bounds how many connections a single approved
    // fingerprint may hold open at once, separate from U2's global cap —
    // so an already-approved but compromised or buggy client can't exhaust
    // the whole connection pool by itself. `None` (the `Default`/`new()`
    // case) means unlimited, matching every pre-U3 server's behavior.
    max_connections_per_fingerprint: Option<usize>,
}

impl LiveConnections {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_connections_per_fingerprint(max_connections_per_fingerprint: usize) -> Self {
        Self {
            max_connections_per_fingerprint: Some(max_connections_per_fingerprint),
            ..Self::default()
        }
    }

    /// Registers a newly-accepted, already-verified connection for
    /// `fingerprint`, or `None` if `fingerprint` already holds
    /// `max_connections_per_fingerprint` connections open (Milestone U3).
    /// On success, returns a handle to pass back to `deregister` once the
    /// connection ends on its own, and a receiver that resolves (`Err`,
    /// since nothing is ever actually sent — dropping the sender is the
    /// signal) once `revoke` is called for this fingerprint.
    pub fn register(
        &mut self,
        fingerprint: Fingerprint,
    ) -> Option<(ConnectionHandle, oneshot::Receiver<()>)> {
        let current_count = self
            .by_fingerprint
            .get(&fingerprint)
            .map_or(0, HashMap::len);
        if self
            .max_connections_per_fingerprint
            .is_some_and(|max| current_count >= max)
        {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        let (sender, receiver) = oneshot::channel();
        self.by_fingerprint
            .entry(fingerprint)
            .or_default()
            .insert(id, sender);
        Some((ConnectionHandle { fingerprint, id }, receiver))
    }

    /// Removes a single connection's registration once it ends on its
    /// own, not via revocation — otherwise entries for long-closed
    /// connections would accumulate forever. A no-op if `handle`'s
    /// fingerprint was already fully revoked (its whole entry, this one
    /// included, is already gone).
    pub fn deregister(&mut self, handle: ConnectionHandle) {
        if let Some(connections) = self.by_fingerprint.get_mut(&handle.fingerprint) {
            connections.remove(&handle.id);
            if connections.is_empty() {
                self.by_fingerprint.remove(&handle.fingerprint);
            }
        }
    }

    /// Terminates every currently-open connection for `fingerprint` by
    /// dropping their cancellation senders — each paired receiver then
    /// resolves, which the connection task (R2) treats as "stop serving
    /// now". Returns how many connections were terminated (`0` if none
    /// were open, the common case — most revocations target a fingerprint
    /// that either was never connected or already disconnected on its
    /// own).
    pub fn revoke(&mut self, fingerprint: &Fingerprint) -> usize {
        match self.by_fingerprint.remove(fingerprint) {
            Some(connections) => connections.len(),
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(seed: &[u8]) -> Fingerprint {
        Fingerprint::of(seed)
    }

    #[test]
    fn register_returns_a_receiver_that_has_not_resolved_yet() {
        let mut live = LiveConnections::new();
        let (_handle, mut receiver) = live.register(fingerprint(b"client-a")).unwrap();
        assert_eq!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
    }

    #[test]
    fn revoke_of_a_fingerprint_with_no_live_connections_returns_zero() {
        let mut live = LiveConnections::new();
        assert_eq!(live.revoke(&fingerprint(b"never-connected")), 0);
    }

    #[test]
    fn revoke_resolves_every_registered_receiver_for_that_fingerprint() {
        let mut live = LiveConnections::new();
        let fp = fingerprint(b"client-a");
        let (_handle_one, mut receiver_one) = live.register(fp).unwrap();
        let (_handle_two, mut receiver_two) = live.register(fp).unwrap();

        assert_eq!(live.revoke(&fp), 2);

        assert_eq!(
            receiver_one.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
        assert_eq!(
            receiver_two.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
    }

    #[test]
    fn revoke_does_not_affect_a_different_fingerprint() {
        let mut live = LiveConnections::new();
        let fp_a = fingerprint(b"client-a");
        let fp_b = fingerprint(b"client-b");
        let (_handle_a, _receiver_a) = live.register(fp_a).unwrap();
        let (_handle_b, mut receiver_b) = live.register(fp_b).unwrap();

        live.revoke(&fp_a);

        assert_eq!(
            receiver_b.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
    }

    #[test]
    fn deregister_removes_only_its_own_connection() {
        let mut live = LiveConnections::new();
        let fp = fingerprint(b"client-a");
        let (handle_one, _receiver_one) = live.register(fp).unwrap();
        let (_handle_two, mut receiver_two) = live.register(fp).unwrap();

        live.deregister(handle_one);

        // The other connection for the same fingerprint is still tracked
        // and still revocable.
        assert_eq!(live.revoke(&fp), 1);
        assert_eq!(
            receiver_two.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
    }

    #[test]
    fn deregister_of_the_only_connection_leaves_the_fingerprint_untracked() {
        let mut live = LiveConnections::new();
        let fp = fingerprint(b"client-a");
        let (handle, _receiver) = live.register(fp).unwrap();

        live.deregister(handle);

        assert_eq!(live.revoke(&fp), 0);
    }

    #[test]
    fn unlimited_live_connections_accepts_many_registrations_for_one_fingerprint() {
        let mut live = LiveConnections::new();
        let fp = fingerprint(b"client-a");
        for _ in 0..10 {
            assert!(live.register(fp).is_some());
        }
    }

    #[test]
    fn with_max_connections_per_fingerprint_rejects_registration_once_at_the_limit() {
        let mut live = LiveConnections::with_max_connections_per_fingerprint(2);
        let fp = fingerprint(b"client-a");
        assert!(live.register(fp).is_some());
        assert!(live.register(fp).is_some());

        assert!(live.register(fp).is_none());
    }

    #[test]
    fn with_max_connections_per_fingerprint_does_not_affect_a_different_fingerprint() {
        let mut live = LiveConnections::with_max_connections_per_fingerprint(1);
        let fp_a = fingerprint(b"client-a");
        let fp_b = fingerprint(b"client-b");
        assert!(live.register(fp_a).is_some());

        // fp_a is now at its limit, but fp_b has its own independent count.
        assert!(live.register(fp_b).is_some());
    }

    #[test]
    fn deregister_frees_a_slot_for_a_new_registration_under_the_limit() {
        let mut live = LiveConnections::with_max_connections_per_fingerprint(1);
        let fp = fingerprint(b"client-a");
        let (handle, _receiver) = live.register(fp).unwrap();
        assert!(live.register(fp).is_none());

        live.deregister(handle);

        assert!(live.register(fp).is_some());
    }

    #[test]
    fn revoke_frees_every_slot_for_a_new_registration_under_the_limit() {
        let mut live = LiveConnections::with_max_connections_per_fingerprint(1);
        let fp = fingerprint(b"client-a");
        live.register(fp).unwrap();
        assert!(live.register(fp).is_none());

        live.revoke(&fp);

        assert!(live.register(fp).is_some());
    }

    #[test]
    fn with_max_connections_per_fingerprint_of_zero_rejects_every_registration() {
        let mut live = LiveConnections::with_max_connections_per_fingerprint(0);
        assert!(live.register(fingerprint(b"client-a")).is_none());
    }
}
