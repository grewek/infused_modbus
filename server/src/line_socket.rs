//! Shared Unix-domain-socket line-protocol server, used by both `admin.rs`'s
//! approval channel and `data_daemon.rs`'s `ServerHandle` socket — the two
//! already explicitly documented themselves as mirroring each other line
//! for line before this was pulled out, same "extract once a second call
//! site needs the exact same thing" reasoning as `peer_auth.rs`'s own
//! extraction.

use crate::peer_auth::is_authorized_uid;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Same "owned by the server's own service account" discipline as the TLS
/// private key file (see `protocol::tls::PRIVATE_KEY_FILE_MODE`) — nobody
/// but this process's own user can even open a socket served this way.
/// `SO_PEERCRED` (checked per connection below) is defense in depth on top
/// of this, not a substitute for it.
pub const SOCKET_FILE_MODE: u32 = 0o600;

/// Binds a Unix socket at `socket_path` (removing any stale leftover file
/// first, e.g. left behind by an unclean shutdown) and serves a line-based
/// protocol on every connection, forever. Every accepted connection is
/// checked against `SO_PEERCRED` before a single byte of the protocol is
/// read — an unauthorized UID (or a peer-credential lookup that failed
/// outright) never gets to speak the protocol at all, fail-closed just like
/// TLS client-cert verification (see CLAUDE.md). `handle_line` turns one
/// received line into the response line to write back (without a trailing
/// newline); it's cloned once per accepted connection so each spawned task
/// gets its own copy of whatever state it closed over.
pub async fn run_line_socket<F>(socket_path: &Path, handle_line: F) -> std::io::Result<()>
where
    F: Fn(&str) -> String + Clone + Send + 'static,
{
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(
        socket_path,
        std::fs::Permissions::from_mode(SOCKET_FILE_MODE),
    )?;

    loop {
        let (stream, _address) = match listener.accept().await {
            Ok(accepted) => accepted,
            // A single failed accept shouldn't take the whole channel down,
            // same reasoning as the Modbus TCP/TLS accept loops in main.rs.
            Err(_) => continue,
        };
        match stream.peer_cred() {
            Ok(credentials) if is_authorized_uid(credentials.uid()) => {}
            // Rejected before a single byte of the protocol is read, per
            // CLAUDE.md: an unauthorized UID (or a peer credential lookup
            // that failed outright) never gets to speak the line protocol
            // at all, fail-closed just like TLS client-cert verification.
            _ => continue,
        }
        let handle_line = handle_line.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let response = handle_line(&line);
                if writer
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }
}
