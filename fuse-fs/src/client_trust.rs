// Server-only FUSE state for the `client-trust/` subtree (see CLAUDE.md's
// TLS design) — the first FUSE feature in this project that isn't
// symmetric between client and server. Threaded into `InfusedFilesystem`
// as `Option<Arc<Mutex<ClientTrustState>>>`: `None` on the client (the
// directory then simply doesn't exist at all), `Some(...)` on the server.
//
// Deliberately no `protocol` dependency here, matching every other store in
// this crate (RegisterStore, CoilStore, WriteReport) — fingerprints are
// carried as their `Display` string form, not `protocol::tls::Fingerprint`,
// so this crate stays decoupled from wire/TLS types.

use fuser::INodeNo;
use std::collections::HashMap;

/// `client-trust/approved/`'s dynamic entries (one file per approved
/// fingerprint) need runtime-assigned inodes — the approved set changes
/// over time (Milestone P's admin channel adds/removes), unlike
/// `holding-registers/`'s fixed-at-construction register files. Mirrors
/// `filesystem::TransactionFsState`'s `name_to_ino`/`ino_to_name`/`next_ino`
/// shape for the same reason.
#[derive(Debug, Default)]
pub struct ClientTrustState {
    approved_name_to_ino: HashMap<String, INodeNo>,
    approved_ino_to_name: HashMap<INodeNo, String>,
    next_ino: u64,
}

impl ClientTrustState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calibrates where dynamically-assigned inodes start counting from.
    /// Called once by `InfusedFilesystem::new`, which is the only place
    /// that knows the full fixed-inode layout (depends on how many
    /// registers/coils the device description has) — `ClientTrustState`
    /// itself has no visibility into that.
    pub fn set_next_ino(&mut self, next_ino: u64) {
        self.next_ino = next_ino;
    }

    /// Returns the fingerprint's inode, assigning a fresh one only if it
    /// isn't already approved (idempotent — approving an already-approved
    /// fingerprint again is a no-op, not a second file).
    pub fn insert_approved(&mut self, fingerprint: impl Into<String>) -> INodeNo {
        let fingerprint = fingerprint.into();
        if let Some(&ino) = self.approved_name_to_ino.get(&fingerprint) {
            return ino;
        }
        let ino = INodeNo(self.next_ino);
        self.next_ino += 1;
        self.approved_name_to_ino.insert(fingerprint.clone(), ino);
        self.approved_ino_to_name.insert(ino, fingerprint);
        ino
    }

    /// Returns whether `fingerprint` was approved (and is now removed).
    pub fn remove_approved(&mut self, fingerprint: &str) -> bool {
        match self.approved_name_to_ino.remove(fingerprint) {
            Some(ino) => {
                self.approved_ino_to_name.remove(&ino);
                true
            }
            None => false,
        }
    }

    pub fn ino_by_fingerprint(&self, fingerprint: &str) -> Option<INodeNo> {
        self.approved_name_to_ino.get(fingerprint).copied()
    }

    pub fn fingerprint_by_ino(&self, ino: INodeNo) -> Option<&str> {
        self.approved_ino_to_name.get(&ino).map(String::as_str)
    }

    pub fn approved_entries(&self) -> impl Iterator<Item = (&str, INodeNo)> {
        self.approved_name_to_ino
            .iter()
            .map(|(name, &ino)| (name.as_str(), ino))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_assigns_increasing_inodes_starting_from_next_ino() {
        let mut state = ClientTrustState::new();
        state.set_next_ino(100);

        let first = state.insert_approved("aa:bb");
        let second = state.insert_approved("cc:dd");

        assert_eq!(first, INodeNo(100));
        assert_eq!(second, INodeNo(101));
    }

    #[test]
    fn inserting_the_same_fingerprint_twice_returns_the_same_inode() {
        let mut state = ClientTrustState::new();
        state.set_next_ino(100);

        let first = state.insert_approved("aa:bb");
        let second = state.insert_approved("aa:bb");

        assert_eq!(first, second);
    }

    #[test]
    fn remove_makes_a_fingerprint_no_longer_resolvable() {
        let mut state = ClientTrustState::new();
        state.set_next_ino(100);
        let ino = state.insert_approved("aa:bb");

        assert!(state.remove_approved("aa:bb"));
        assert_eq!(state.ino_by_fingerprint("aa:bb"), None);
        assert_eq!(state.fingerprint_by_ino(ino), None);
    }

    #[test]
    fn remove_of_an_absent_fingerprint_returns_false() {
        let mut state = ClientTrustState::new();
        assert!(!state.remove_approved("never-approved"));
    }

    #[test]
    fn approved_entries_lists_everything_inserted() {
        let mut state = ClientTrustState::new();
        state.set_next_ino(100);
        state.insert_approved("aa:bb");
        state.insert_approved("cc:dd");

        let mut names: Vec<&str> = state.approved_entries().map(|(name, _ino)| name).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["aa:bb", "cc:dd"]);
    }
}
