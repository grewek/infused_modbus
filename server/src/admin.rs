// The admin approval channel (Milestone P): a Unix domain socket that a
// technician-facing `server admin approve|revoke|list <fingerprint>` CLI
// subcommand talks to, so approving/revoking a TLS client never requires
// speaking the raw protocol by hand (see CLAUDE.md's "Approval/revocation
// channel"). APPROVE/REVOKE mutate both `ApprovedClients` (N1, which the
// real TLS `ClientCertVerifier` consults) and `fuse_fs::client_trust::
// ClientTrustState` (the read-only `client-trust/approved/` FUSE mirror) —
// keeping these in sync here is what closes O2's "known gap" note about
// the two never being wired to the same writer. REVOKE also terminates any
// already-open connection using the revoked fingerprint (Milestone R), not
// just future handshakes — see `live_connections::LiveConnections`.

use crate::client_trust::{ApprovalOutcome, ApprovedClients};
use crate::live_connections::LiveConnections;
use fuse_fs::client_trust::ClientTrustState;
use protocol::tls::Fingerprint;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// The real UID this process is running as — the only UID ever allowed to
/// talk to the admin socket (see `is_authorized_uid`). Read once via
/// `libc::getuid()` (already a transitive dependency through `fuser`, so
/// this reuses it rather than adding a second crate like `nix`/`rustix`
/// just for one syscall) rather than cached, since a UID can't change
/// during a process's lifetime.
fn server_uid() -> libc::uid_t {
    // SAFETY: getuid() takes no arguments, performs no memory access, and
    // cannot fail — it's one of the few POSIX calls with no error return.
    unsafe { libc::getuid() }
}

/// Whether a peer presenting `peer_uid` (as reported by the kernel via
/// `SO_PEERCRED`, see `UnixStream::peer_cred`) is allowed to use the admin
/// socket — only this server's own real UID, never anyone else's, matching
/// the socket file's own `0600` permissions with a second, kernel-verified
/// check that doesn't depend on the filesystem permission bits being
/// correct (see CLAUDE.md's "Approval/revocation channel": "defense in
/// depth if the file permissions were ever misconfigured").
fn is_authorized_uid(peer_uid: libc::uid_t) -> bool {
    peer_uid == server_uid()
}

/// Same "owned by the server's own service account" discipline as the TLS
/// private key file (see `protocol::tls::PRIVATE_KEY_FILE_MODE`) — nobody
/// but this process's own user can even open the socket. `SO_PEERCRED`
/// (P3) is defense in depth on top of this, not a substitute for it.
const SOCKET_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCommand {
    Approve(Fingerprint),
    Revoke(Fingerprint),
    List,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AdminCommandParseError(String);

impl fmt::Display for AdminCommandParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl AdminCommand {
    /// Parses one line of the admin protocol. Verbs match the `server
    /// admin` CLI subcommand's own verbs one-to-one (P4) so that subcommand
    /// can forward its argument almost verbatim.
    pub fn parse(line: &str) -> Result<Self, AdminCommandParseError> {
        let mut words = line.split_whitespace();
        let Some(verb) = words.next() else {
            return Err(AdminCommandParseError("empty command".to_string()));
        };
        match verb {
            "APPROVE" | "REVOKE" => {
                let Some(fingerprint_text) = words.next() else {
                    return Err(AdminCommandParseError(format!(
                        "{verb} requires a fingerprint argument"
                    )));
                };
                if words.next().is_some() {
                    return Err(AdminCommandParseError(format!(
                        "{verb} takes exactly one argument"
                    )));
                }
                let fingerprint = fingerprint_text.parse::<Fingerprint>().map_err(|error| {
                    AdminCommandParseError(format!("invalid fingerprint: {error}"))
                })?;
                Ok(if verb == "APPROVE" {
                    AdminCommand::Approve(fingerprint)
                } else {
                    AdminCommand::Revoke(fingerprint)
                })
            }
            "LIST" => {
                if words.next().is_some() {
                    return Err(AdminCommandParseError(
                        "LIST takes no arguments".to_string(),
                    ));
                }
                Ok(AdminCommand::List)
            }
            other => Err(AdminCommandParseError(format!("unknown command {other:?}"))),
        }
    }
}

/// Applies a parsed command's effect and returns the response line (without
/// a trailing newline). Revoking is idempotent — revoking a fingerprint
/// that was never approved is still a success, not an error, matching
/// `ApprovedClients::remove`'s own `bool` "was this present" return rather
/// than treating it as a hard precondition. Approving is idempotent too,
/// *except* when the approved set is already at its configured
/// `--max-clients` capacity (Milestone Q) — see `ApprovedClients::insert`'s
/// `ApprovalOutcome`.
fn apply_command(
    command: &AdminCommand,
    approved: &Mutex<ApprovedClients>,
    client_trust: &Mutex<ClientTrustState>,
    live_connections: &Mutex<LiveConnections>,
) -> String {
    match command {
        AdminCommand::Approve(fingerprint) => match approved.lock().unwrap().insert(*fingerprint) {
            ApprovalOutcome::Approved | ApprovalOutcome::AlreadyApproved => {
                client_trust
                    .lock()
                    .unwrap()
                    .insert_approved(fingerprint.to_string());
                format!("OK APPROVE {fingerprint}")
            }
            ApprovalOutcome::AtCapacity => {
                format!("ERROR APPROVE {fingerprint}: at max-clients capacity")
            }
        },
        AdminCommand::Revoke(fingerprint) => {
            approved.lock().unwrap().remove(fingerprint);
            client_trust
                .lock()
                .unwrap()
                .remove_approved(&fingerprint.to_string());
            let terminated = live_connections.lock().unwrap().revoke(fingerprint);
            format!("OK REVOKE {fingerprint} ({terminated} connection(s) terminated)")
        }
        AdminCommand::List => {
            let fingerprints: Vec<String> = client_trust
                .lock()
                .unwrap()
                .approved_entries()
                .map(|(fingerprint, _ino)| fingerprint.to_string())
                .collect();
            format!("OK LIST {}", fingerprints.join(","))
        }
    }
}

/// Handles one line of admin-protocol input and returns the response line
/// (without a trailing newline).
fn handle_line(
    line: &str,
    approved: &Mutex<ApprovedClients>,
    client_trust: &Mutex<ClientTrustState>,
    live_connections: &Mutex<LiveConnections>,
) -> String {
    match AdminCommand::parse(line.trim_end()) {
        Ok(command) => apply_command(&command, approved, client_trust, live_connections),
        Err(error) => format!("ERROR {error}"),
    }
}

/// Binds the admin socket at `socket_path` (removing any stale leftover
/// file first, e.g. left behind by an unclean shutdown) and serves the line
/// protocol above on every connection, forever.
pub async fn run_admin_socket(
    socket_path: &Path,
    approved: Arc<Mutex<ApprovedClients>>,
    client_trust: Arc<Mutex<ClientTrustState>>,
    live_connections: Arc<Mutex<LiveConnections>>,
) -> std::io::Result<()> {
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
        let approved = Arc::clone(&approved);
        let client_trust = Arc::clone(&client_trust);
        let live_connections = Arc::clone(&live_connections);
        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let response = handle_line(&line, &approved, &client_trust, &live_connections);
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

/// Sends one command to the admin socket at `socket_path` and returns its
/// response line (without the trailing newline). Wraps the raw line
/// protocol so the `server admin` CLI subcommand (P4) never has to speak it
/// directly.
pub async fn send_admin_command(socket_path: &Path, command: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path).await?;
    stream.write_all(format!("{command}\n").as_bytes()).await?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).await?;
    Ok(response.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint() -> Fingerprint {
        Fingerprint::of(b"admin-socket-test")
    }

    fn other_fingerprint() -> Fingerprint {
        Fingerprint::of(b"admin-socket-test-other")
    }

    #[test]
    fn is_authorized_uid_accepts_the_servers_own_uid() {
        assert!(is_authorized_uid(server_uid()));
    }

    #[test]
    fn is_authorized_uid_rejects_a_different_uid() {
        assert!(!is_authorized_uid(server_uid().wrapping_add(1)));
    }

    #[test]
    fn parses_approve_with_a_valid_fingerprint() {
        let line = format!("APPROVE {}", fingerprint());
        assert_eq!(
            AdminCommand::parse(&line),
            Ok(AdminCommand::Approve(fingerprint()))
        );
    }

    #[test]
    fn parses_revoke_with_a_valid_fingerprint() {
        let line = format!("REVOKE {}", fingerprint());
        assert_eq!(
            AdminCommand::parse(&line),
            Ok(AdminCommand::Revoke(fingerprint()))
        );
    }

    #[test]
    fn parses_list() {
        assert_eq!(AdminCommand::parse("LIST"), Ok(AdminCommand::List));
    }

    #[test]
    fn rejects_an_empty_line() {
        assert!(AdminCommand::parse("").is_err());
    }

    #[test]
    fn rejects_an_unknown_verb() {
        assert!(AdminCommand::parse("DELETE something").is_err());
    }

    #[test]
    fn rejects_approve_without_a_fingerprint() {
        assert!(AdminCommand::parse("APPROVE").is_err());
    }

    #[test]
    fn rejects_approve_with_an_invalid_fingerprint() {
        assert!(AdminCommand::parse("APPROVE not-a-fingerprint").is_err());
    }

    #[test]
    fn rejects_approve_with_trailing_extra_arguments() {
        let line = format!("APPROVE {} extra", fingerprint());
        assert!(AdminCommand::parse(&line).is_err());
    }

    #[test]
    fn rejects_list_with_arguments() {
        assert!(AdminCommand::parse("LIST extra").is_err());
    }

    type TestState = (
        Arc<Mutex<ApprovedClients>>,
        Arc<Mutex<ClientTrustState>>,
        Arc<Mutex<LiveConnections>>,
    );

    fn state() -> TestState {
        (
            Arc::new(Mutex::new(ApprovedClients::new())),
            Arc::new(Mutex::new(ClientTrustState::new())),
            Arc::new(Mutex::new(LiveConnections::new())),
        )
    }

    #[test]
    fn handle_line_approve_marks_the_fingerprint_approved_in_both_stores() {
        let (approved, client_trust, live_connections) = state();
        let line = format!("APPROVE {}", fingerprint());

        let response = handle_line(&line, &approved, &client_trust, &live_connections);

        assert_eq!(response, format!("OK APPROVE {}", fingerprint()));
        assert!(approved.lock().unwrap().contains(&fingerprint()));
        assert!(
            client_trust
                .lock()
                .unwrap()
                .ino_by_fingerprint(&fingerprint().to_string())
                .is_some()
        );
    }

    #[test]
    fn handle_line_approve_is_idempotent() {
        let (approved, client_trust, live_connections) = state();
        let line = format!("APPROVE {}", fingerprint());

        handle_line(&line, &approved, &client_trust, &live_connections);
        let second_response = handle_line(&line, &approved, &client_trust, &live_connections);

        assert_eq!(second_response, format!("OK APPROVE {}", fingerprint()));
        assert_eq!(client_trust.lock().unwrap().approved_entries().count(), 1);
    }

    #[test]
    fn handle_line_approve_is_rejected_once_at_max_clients_capacity() {
        let approved = Arc::new(Mutex::new(ApprovedClients::with_max_clients(1)));
        let client_trust = Arc::new(Mutex::new(ClientTrustState::new()));
        let live_connections = Arc::new(Mutex::new(LiveConnections::new()));
        handle_line(
            &format!("APPROVE {}", fingerprint()),
            &approved,
            &client_trust,
            &live_connections,
        );

        let response = handle_line(
            &format!("APPROVE {}", other_fingerprint()),
            &approved,
            &client_trust,
            &live_connections,
        );

        assert!(response.starts_with("ERROR"));
        assert!(!approved.lock().unwrap().contains(&other_fingerprint()));
        assert!(
            client_trust
                .lock()
                .unwrap()
                .ino_by_fingerprint(&other_fingerprint().to_string())
                .is_none()
        );
        // The already-approved fingerprint is unaffected and re-approving
        // it still succeeds even though the set is full.
        assert_eq!(
            handle_line(
                &format!("APPROVE {}", fingerprint()),
                &approved,
                &client_trust,
                &live_connections
            ),
            format!("OK APPROVE {}", fingerprint())
        );
    }

    #[test]
    fn handle_line_revoke_removes_the_fingerprint_from_both_stores() {
        let (approved, client_trust, live_connections) = state();
        handle_line(
            &format!("APPROVE {}", fingerprint()),
            &approved,
            &client_trust,
            &live_connections,
        );

        let response = handle_line(
            &format!("REVOKE {}", fingerprint()),
            &approved,
            &client_trust,
            &live_connections,
        );

        assert_eq!(
            response,
            format!("OK REVOKE {} (0 connection(s) terminated)", fingerprint())
        );
        assert!(!approved.lock().unwrap().contains(&fingerprint()));
        assert!(
            client_trust
                .lock()
                .unwrap()
                .ino_by_fingerprint(&fingerprint().to_string())
                .is_none()
        );
    }

    #[test]
    fn handle_line_revoke_of_an_unapproved_fingerprint_still_succeeds() {
        let (approved, client_trust, live_connections) = state();
        let response = handle_line(
            &format!("REVOKE {}", fingerprint()),
            &approved,
            &client_trust,
            &live_connections,
        );
        assert_eq!(
            response,
            format!("OK REVOKE {} (0 connection(s) terminated)", fingerprint())
        );
    }

    #[test]
    fn handle_line_revoke_terminates_live_connections_for_that_fingerprint() {
        let (approved, client_trust, live_connections) = state();
        handle_line(
            &format!("APPROVE {}", fingerprint()),
            &approved,
            &client_trust,
            &live_connections,
        );
        let (_handle, mut cancelled) = live_connections.lock().unwrap().register(fingerprint());

        let response = handle_line(
            &format!("REVOKE {}", fingerprint()),
            &approved,
            &client_trust,
            &live_connections,
        );

        assert_eq!(
            response,
            format!("OK REVOKE {} (1 connection(s) terminated)", fingerprint())
        );
        assert_eq!(
            cancelled.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        );
    }

    #[test]
    fn handle_line_list_reflects_approved_fingerprints() {
        let (approved, client_trust, live_connections) = state();
        assert_eq!(
            handle_line("LIST", &approved, &client_trust, &live_connections),
            "OK LIST "
        );

        handle_line(
            &format!("APPROVE {}", fingerprint()),
            &approved,
            &client_trust,
            &live_connections,
        );

        assert_eq!(
            handle_line("LIST", &approved, &client_trust, &live_connections),
            format!("OK LIST {}", fingerprint())
        );
    }

    #[test]
    fn handle_line_reports_a_parse_error() {
        let (approved, client_trust, live_connections) = state();
        assert!(
            handle_line("nonsense", &approved, &client_trust, &live_connections)
                .starts_with("ERROR ")
        );
    }

    #[tokio::test]
    async fn serves_a_list_command_over_a_real_socket() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("admin.sock");
        let (approved, client_trust, live_connections) = state();

        let bound_path = socket_path.clone();
        tokio::spawn(async move {
            run_admin_socket(&bound_path, approved, client_trust, live_connections)
                .await
                .unwrap();
        });
        // The listener above binds asynchronously; poll for the socket file
        // to exist rather than a fixed sleep, since the exact bind timing
        // isn't guaranteed.
        while !socket_path.exists() {
            tokio::task::yield_now().await;
        }

        let permissions = std::fs::metadata(&socket_path).unwrap().permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        stream.write_all(b"LIST\n").await.unwrap();
        let mut response = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut response)
            .await
            .unwrap();
        assert_eq!(response, "OK LIST \n");
    }

    #[tokio::test]
    async fn approving_over_the_real_socket_is_visible_to_a_later_list() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("admin.sock");
        let (approved, client_trust, live_connections) = state();

        let bound_path = socket_path.clone();
        tokio::spawn(async move {
            run_admin_socket(&bound_path, approved, client_trust, live_connections)
                .await
                .unwrap();
        });
        while !socket_path.exists() {
            tokio::task::yield_now().await;
        }

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut reader = BufReader::new(&mut stream);

        reader
            .get_mut()
            .write_all(format!("APPROVE {}\n", fingerprint()).as_bytes())
            .await
            .unwrap();
        let mut approve_response = String::new();
        reader.read_line(&mut approve_response).await.unwrap();
        assert_eq!(approve_response, format!("OK APPROVE {}\n", fingerprint()));

        reader.get_mut().write_all(b"LIST\n").await.unwrap();
        let mut list_response = String::new();
        reader.read_line(&mut list_response).await.unwrap();
        assert_eq!(list_response, format!("OK LIST {}\n", fingerprint()));
    }

    #[tokio::test]
    async fn a_same_uid_connection_is_still_served_normally() {
        // The only peer UID a test process can realistically present is its
        // own — actually connecting as a *different* UID would require
        // spawning a second process under another real user account, which
        // needs privileges a test run doesn't have. This test instead
        // guards the regression the SO_PEERCRED check could introduce by
        // mistake: rejecting the server's own legitimate caller. The
        // rejection logic itself is covered directly by
        // `is_authorized_uid_rejects_a_different_uid` above.
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("admin.sock");
        let (approved, client_trust, live_connections) = state();

        let bound_path = socket_path.clone();
        tokio::spawn(async move {
            run_admin_socket(&bound_path, approved, client_trust, live_connections)
                .await
                .unwrap();
        });
        while !socket_path.exists() {
            tokio::task::yield_now().await;
        }

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        stream.write_all(b"LIST\n").await.unwrap();
        let mut response = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut response)
            .await
            .unwrap();
        assert_eq!(response, "OK LIST \n");
    }

    #[tokio::test]
    async fn removes_a_stale_socket_file_before_binding() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("admin.sock");
        std::fs::write(&socket_path, b"leftover, not a real socket").unwrap();
        let (approved, client_trust, live_connections) = state();

        let bound_path = socket_path.clone();
        tokio::spawn(async move {
            run_admin_socket(&bound_path, approved, client_trust, live_connections)
                .await
                .unwrap();
        });
        while UnixStream::connect(&socket_path).await.is_err() {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn send_admin_command_round_trips_approve_and_list() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("admin.sock");
        let (approved, client_trust, live_connections) = state();

        let bound_path = socket_path.clone();
        tokio::spawn(async move {
            run_admin_socket(&bound_path, approved, client_trust, live_connections)
                .await
                .unwrap();
        });
        while !socket_path.exists() {
            tokio::task::yield_now().await;
        }

        let approve_response =
            send_admin_command(&socket_path, &format!("APPROVE {}", fingerprint()))
                .await
                .unwrap();
        assert_eq!(approve_response, format!("OK APPROVE {}", fingerprint()));

        let list_response = send_admin_command(&socket_path, "LIST").await.unwrap();
        assert_eq!(list_response, format!("OK LIST {}", fingerprint()));
    }
}
