// The server's client-approval policy state — which TLS client
// fingerprints are allowed to connect (see CLAUDE.md's "client-trust"
// design). Plain data structure, no interior mutability: callers share it
// the same way as fuse_fs::RegisterStore/CoilStore, via an externally
// applied Arc<Mutex<ApprovedClients>>, not a lock owned by this type.

use protocol::tls::Fingerprint;
use std::collections::HashSet;

/// Starts empty — nothing is approved until the admin channel (Milestone
/// P) inserts something, so a freshly started server is fail-closed by
/// default (see the `ClientCertVerifier` that will consult this, N2a).
#[derive(Debug, Default)]
pub struct ApprovedClients {
    fingerprints: HashSet<Fingerprint>,
    // `--max-clients` (Milestone Q): bounds the number of *currently
    // valid* approved fingerprints at once, not total approvals ever
    // granted — revoking one frees the slot for a new approval (Q3).
    // `None` (the `Default`/`new()` case) means unlimited, matching every
    // pre-Q server's behavior exactly. Q1 scope only: stored and queryable
    // via `is_at_capacity`, not yet consulted by `insert` — that's Q2.
    max_clients: Option<usize>,
}

impl ApprovedClients {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_clients(max_clients: usize) -> Self {
        Self {
            max_clients: Some(max_clients),
            ..Self::default()
        }
    }

    /// Whether the approved set currently holds `max_clients` (if any)
    /// entries already — always `false` when unlimited (`new()`).
    pub fn is_at_capacity(&self) -> bool {
        self.max_clients
            .is_some_and(|max_clients| self.fingerprints.len() >= max_clients)
    }

    /// Returns whether `fingerprint` was newly inserted (`false` if it was
    /// already approved).
    pub fn insert(&mut self, fingerprint: Fingerprint) -> bool {
        self.fingerprints.insert(fingerprint)
    }

    pub fn contains(&self, fingerprint: &Fingerprint) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// Returns whether `fingerprint` was present (and is now removed).
    pub fn remove(&mut self, fingerprint: &Fingerprint) -> bool {
        self.fingerprints.remove(fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(seed: &[u8]) -> Fingerprint {
        Fingerprint::of(seed)
    }

    #[test]
    fn starts_empty() {
        let approved = ApprovedClients::new();
        assert!(!approved.contains(&fingerprint(b"anything")));
    }

    #[test]
    fn insert_makes_a_fingerprint_contained() {
        let mut approved = ApprovedClients::new();
        let fp = fingerprint(b"client-a");

        assert!(approved.insert(fp));
        assert!(approved.contains(&fp));
    }

    #[test]
    fn insert_of_an_already_approved_fingerprint_returns_false() {
        let mut approved = ApprovedClients::new();
        let fp = fingerprint(b"client-a");

        assert!(approved.insert(fp));
        assert!(!approved.insert(fp));
    }

    #[test]
    fn remove_makes_a_fingerprint_no_longer_contained() {
        let mut approved = ApprovedClients::new();
        let fp = fingerprint(b"client-a");
        approved.insert(fp);

        assert!(approved.remove(&fp));
        assert!(!approved.contains(&fp));
    }

    #[test]
    fn remove_of_an_absent_fingerprint_returns_false() {
        let mut approved = ApprovedClients::new();
        assert!(!approved.remove(&fingerprint(b"never-approved")));
    }

    #[test]
    fn approving_one_fingerprint_does_not_approve_another() {
        let mut approved = ApprovedClients::new();
        approved.insert(fingerprint(b"client-a"));

        assert!(!approved.contains(&fingerprint(b"client-b")));
    }

    #[test]
    fn unlimited_approved_clients_is_never_at_capacity() {
        let mut approved = ApprovedClients::new();
        for seed in 0u8..10 {
            approved.insert(fingerprint(&[seed]));
        }
        assert!(!approved.is_at_capacity());
    }

    #[test]
    fn with_max_clients_is_not_at_capacity_below_the_limit() {
        let mut approved = ApprovedClients::with_max_clients(2);
        approved.insert(fingerprint(b"client-a"));
        assert!(!approved.is_at_capacity());
    }

    #[test]
    fn with_max_clients_is_at_capacity_once_the_limit_is_reached() {
        let mut approved = ApprovedClients::with_max_clients(2);
        approved.insert(fingerprint(b"client-a"));
        approved.insert(fingerprint(b"client-b"));
        assert!(approved.is_at_capacity());
    }

    #[test]
    fn with_max_clients_of_zero_starts_at_capacity() {
        let approved = ApprovedClients::with_max_clients(0);
        assert!(approved.is_at_capacity());
    }
}
