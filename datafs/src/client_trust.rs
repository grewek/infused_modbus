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
use std::collections::{HashMap, VecDeque};

// Each connection_attempts/*.log file is a fixed-size ring buffer — an
// attacker who floods handshake attempts must not be able to grow these
// files without bound (same "validate/bound untrusted input" instinct as
// PDU-length checks elsewhere in this project). Oldest entry drops when a
// new one arrives past capacity. Arbitrary but generous for a first cut;
// not yet configurable.
const CONNECTION_ATTEMPTS_LOG_CAPACITY: usize = 50;

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
    // connection_attempts/*.log content — see `log_approved`/`log_pending`/
    // `log_rejected`. Three separate buffers, not one shared log with an
    // outcome column, so `cat`ing one file never needs the reader to filter
    // anything out themselves (matches CLAUDE.md's fixed-three-files
    // design).
    approved_log: VecDeque<String>,
    pending_log: VecDeque<String>,
    rejected_log: VecDeque<String>,
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

    /// A fingerprint that was checked against the approved set and matched
    /// — the connection was allowed to proceed.
    pub fn log_approved(&mut self, entry: impl Into<String>) {
        push_bounded(&mut self.approved_log, entry.into());
    }

    /// A fingerprint that presented a well-formed certificate but isn't
    /// (yet) in the approved set — worth a technician's review, not a hard
    /// failure like a malformed certificate. See `log_rejected` for the
    /// distinction this project draws between the two.
    pub fn log_pending(&mut self, entry: impl Into<String>) {
        push_bounded(&mut self.pending_log, entry.into());
    }

    /// A connection attempt that failed for a reason that isn't "not yet
    /// approved" — e.g. a certificate that couldn't even be parsed. Kept
    /// separate from `log_pending` so a technician reviewing pending
    /// requests never has to filter out attempts there's nothing to
    /// approve about.
    pub fn log_rejected(&mut self, entry: impl Into<String>) {
        push_bounded(&mut self.rejected_log, entry.into());
    }

    pub fn approved_log_content(&self) -> String {
        join_log(&self.approved_log)
    }

    pub fn pending_log_content(&self) -> String {
        join_log(&self.pending_log)
    }

    pub fn rejected_log_content(&self) -> String {
        join_log(&self.rejected_log)
    }
}

fn push_bounded(log: &mut VecDeque<String>, entry: String) {
    if log.len() >= CONNECTION_ATTEMPTS_LOG_CAPACITY {
        log.pop_front();
    }
    log.push_back(entry);
}

fn join_log(log: &VecDeque<String>) -> String {
    log.iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>()
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

    #[test]
    fn logs_start_empty() {
        let state = ClientTrustState::new();
        assert_eq!(state.approved_log_content(), "");
        assert_eq!(state.pending_log_content(), "");
        assert_eq!(state.rejected_log_content(), "");
    }

    #[test]
    fn each_log_is_independent_of_the_others() {
        let mut state = ClientTrustState::new();
        state.log_approved("aa:bb");
        state.log_pending("cc:dd");
        state.log_rejected("ee:ff");

        assert_eq!(state.approved_log_content(), "aa:bb\n");
        assert_eq!(state.pending_log_content(), "cc:dd\n");
        assert_eq!(state.rejected_log_content(), "ee:ff\n");
    }

    #[test]
    fn log_entries_appear_in_the_order_they_were_logged() {
        let mut state = ClientTrustState::new();
        state.log_approved("first");
        state.log_approved("second");

        assert_eq!(state.approved_log_content(), "first\nsecond\n");
    }

    #[test]
    fn log_drops_the_oldest_entry_once_over_capacity() {
        let mut state = ClientTrustState::new();
        for index in 0..(CONNECTION_ATTEMPTS_LOG_CAPACITY + 1) {
            state.log_approved(format!("entry-{index}"));
        }

        let content = state.approved_log_content();
        assert!(!content.contains("entry-0\n"));
        assert!(content.contains(&format!("entry-{CONNECTION_ATTEMPTS_LOG_CAPACITY}\n")));
        assert_eq!(content.lines().count(), CONNECTION_ATTEMPTS_LOG_CAPACITY);
    }
}
