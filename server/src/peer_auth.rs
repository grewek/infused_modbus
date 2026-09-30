//! Shared `SO_PEERCRED` authorization check for this server's local Unix
//! domain sockets (`admin.rs`'s approval channel, `data_daemon.rs`'s
//! `ServerHandle` socket) — extracted once a second call site needed the
//! exact same check, rather than risking the two drifting apart if one were
//! ever updated and the other forgotten (this is security-relevant logic,
//! not a place to tolerate copy-paste drift).

/// The real UID this process is running as — the only UID ever allowed to
/// talk to a local admin/data socket (see `is_authorized_uid`). Read once
/// via `libc::getuid()` (already a transitive dependency through `fuser`,
/// so this reuses it rather than adding a second crate like `nix`/`rustix`
/// just for one syscall) rather than cached, since a UID can't change
/// during a process's lifetime.
pub fn server_uid() -> libc::uid_t {
    // SAFETY: getuid() takes no arguments, performs no memory access, and
    // cannot fail — it's one of the few POSIX calls with no error return.
    unsafe { libc::getuid() }
}

/// Whether a peer presenting `peer_uid` (as reported by the kernel via
/// `SO_PEERCRED`, see `UnixStream::peer_cred`) is allowed to use a local
/// socket — only this server's own real UID, never anyone else's, matching
/// the socket file's own `0600` permissions with a second, kernel-verified
/// check that doesn't depend on the filesystem permission bits being
/// correct (see CLAUDE.md's "Approval/revocation channel": "defense in
/// depth if the file permissions were ever misconfigured").
pub fn is_authorized_uid(peer_uid: libc::uid_t) -> bool {
    peer_uid == server_uid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_authorized_uid_accepts_the_servers_own_uid() {
        assert!(is_authorized_uid(server_uid()));
    }

    #[test]
    fn is_authorized_uid_rejects_a_different_uid() {
        assert!(!is_authorized_uid(server_uid().wrapping_add(1)));
    }
}
