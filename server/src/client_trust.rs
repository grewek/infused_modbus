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
}

impl ApprovedClients {
    pub fn new() -> Self {
        Self::default()
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
}
