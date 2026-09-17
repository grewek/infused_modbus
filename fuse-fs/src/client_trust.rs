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

/// Still empty at Milestone O1 — this step is pure plumbing, proving the
/// asymmetric `Option`-based wiring into `InfusedFilesystem` works before
/// any real content (the approved list in O2, the connection-attempt logs
/// in O3) is added.
#[derive(Debug, Default)]
pub struct ClientTrustState {}

impl ClientTrustState {
    pub fn new() -> Self {
        Self::default()
    }
}
