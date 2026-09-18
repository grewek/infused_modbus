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
    // pre-Q server's behavior exactly. Consulted by `insert` (Q2).
    max_clients: Option<usize>,
}

/// What `insert` actually did — richer than a plain `bool` since Q2 adds a
/// third real outcome (`AtCapacity`) that the admin channel (`server::admin
/// ::apply_command`) needs to report distinctly from ordinary success, not
/// silently swallow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Newly inserted.
    Approved,
    /// Already approved — a no-op, but still a success from the caller's
    /// perspective (re-approving an already-approved client isn't an
    /// error), and deliberately exempt from the capacity check below: an
    /// idempotent re-approval can never itself grow the approved count.
    AlreadyApproved,
    /// Not inserted: the approved set is already at its configured
    /// `--max-clients` limit.
    AtCapacity,
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

    /// Checking capacity and inserting both happen here, inside the one
    /// `&mut self` call — since every caller already holds this struct's
    /// lock for the call's duration (see the module doc comment), that's
    /// the single critical section CLAUDE.md requires: "checking the
    /// current approved count against `--max-clients` and inserting a
    /// newly-approved fingerprint must happen inside one held lock ...
    /// never as two separate lock acquisitions".
    pub fn insert(&mut self, fingerprint: Fingerprint) -> ApprovalOutcome {
        if self.fingerprints.contains(&fingerprint) {
            return ApprovalOutcome::AlreadyApproved;
        }
        if self.is_at_capacity() {
            return ApprovalOutcome::AtCapacity;
        }
        self.fingerprints.insert(fingerprint);
        ApprovalOutcome::Approved
    }

    /// Inserts `fingerprint` unconditionally, bypassing the `--max-clients`
    /// capacity check `insert` enforces. Used only to seed the set from
    /// `approved-clients.toml` at startup (Milestone S1): a fingerprint
    /// that was already validly approved before a restart must not be
    /// silently dropped just because `--max-clients` happens to have been
    /// lowered in the meantime — an operator who actually wants to shrink
    /// the roster can revoke specific entries by hand instead.
    pub fn seed(&mut self, fingerprint: Fingerprint) {
        self.fingerprints.insert(fingerprint);
    }

    pub fn contains(&self, fingerprint: &Fingerprint) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// Returns whether `fingerprint` was present (and is now removed).
    pub fn remove(&mut self, fingerprint: &Fingerprint) -> bool {
        self.fingerprints.remove(fingerprint)
    }

    /// A snapshot of every currently approved fingerprint — used by the
    /// admin channel (Milestone S2) to persist the set to disk after every
    /// successful `insert`/`remove`, called while still holding this
    /// struct's own lock so the snapshot and the on-disk file can never
    /// observe a different, later-superseded state.
    pub fn fingerprints(&self) -> Vec<Fingerprint> {
        self.fingerprints.iter().copied().collect()
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

        assert_eq!(approved.insert(fp), ApprovalOutcome::Approved);
        assert!(approved.contains(&fp));
    }

    #[test]
    fn insert_of_an_already_approved_fingerprint_reports_already_approved() {
        let mut approved = ApprovedClients::new();
        let fp = fingerprint(b"client-a");

        assert_eq!(approved.insert(fp), ApprovalOutcome::Approved);
        assert_eq!(approved.insert(fp), ApprovalOutcome::AlreadyApproved);
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

    #[test]
    fn fingerprints_returns_every_currently_approved_fingerprint() {
        let mut approved = ApprovedClients::new();
        let fp_a = fingerprint(b"client-a");
        let fp_b = fingerprint(b"client-b");
        approved.insert(fp_a);
        approved.insert(fp_b);

        let mut fingerprints = approved.fingerprints();
        fingerprints.sort_by_key(Fingerprint::to_string);
        let mut expected = vec![fp_a, fp_b];
        expected.sort_by_key(Fingerprint::to_string);
        assert_eq!(fingerprints, expected);
    }

    #[test]
    fn fingerprints_excludes_a_removed_fingerprint() {
        let mut approved = ApprovedClients::new();
        let fp = fingerprint(b"client-a");
        approved.insert(fp);
        approved.remove(&fp);

        assert_eq!(approved.fingerprints(), Vec::new());
    }

    #[test]
    fn insert_rejects_a_new_fingerprint_once_at_capacity() {
        let mut approved = ApprovedClients::with_max_clients(1);
        assert_eq!(
            approved.insert(fingerprint(b"client-a")),
            ApprovalOutcome::Approved
        );

        assert_eq!(
            approved.insert(fingerprint(b"client-b")),
            ApprovalOutcome::AtCapacity
        );
        assert!(!approved.contains(&fingerprint(b"client-b")));
    }

    #[test]
    fn insert_of_an_already_approved_fingerprint_succeeds_even_at_capacity() {
        let mut approved = ApprovedClients::with_max_clients(1);
        let fp = fingerprint(b"client-a");
        assert_eq!(approved.insert(fp), ApprovalOutcome::Approved);

        // The set is now full, but re-approving the one fingerprint
        // already in it doesn't grow the count, so it must still succeed.
        assert_eq!(approved.insert(fp), ApprovalOutcome::AlreadyApproved);
    }

    #[test]
    fn revoke_frees_a_slot_for_a_new_approval() {
        let mut approved = ApprovedClients::with_max_clients(1);
        let fp_a = fingerprint(b"client-a");
        let fp_b = fingerprint(b"client-b");
        assert_eq!(approved.insert(fp_a), ApprovalOutcome::Approved);
        assert_eq!(approved.insert(fp_b), ApprovalOutcome::AtCapacity);

        assert!(approved.remove(&fp_a));

        assert_eq!(approved.insert(fp_b), ApprovalOutcome::Approved);
    }

    #[test]
    fn seed_makes_a_fingerprint_contained() {
        let mut approved = ApprovedClients::new();
        let fp = fingerprint(b"client-a");

        approved.seed(fp);

        assert!(approved.contains(&fp));
    }

    #[test]
    fn seed_bypasses_the_max_clients_capacity_check() {
        let mut approved = ApprovedClients::with_max_clients(1);
        approved.seed(fingerprint(b"client-a"));

        approved.seed(fingerprint(b"client-b"));

        assert!(approved.contains(&fingerprint(b"client-a")));
        assert!(approved.contains(&fingerprint(b"client-b")));
    }

    #[test]
    fn concurrent_approvals_never_exceed_max_clients() {
        use std::sync::{Arc, Mutex};

        const MAX_CLIENTS: usize = 5;
        const CONCURRENT_ATTEMPTS: u8 = 50;

        let approved = Arc::new(Mutex::new(ApprovedClients::with_max_clients(MAX_CLIENTS)));
        let handles: Vec<_> = (0..CONCURRENT_ATTEMPTS)
            .map(|seed| {
                let approved = Arc::clone(&approved);
                std::thread::spawn(move || {
                    approved.lock().unwrap().insert(fingerprint(&[seed]));
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let approved = approved.lock().unwrap();
        let approved_count = (0..CONCURRENT_ATTEMPTS)
            .filter(|seed| approved.contains(&fingerprint(&[*seed])))
            .count();
        assert!(approved_count <= MAX_CLIENTS);
    }
}
