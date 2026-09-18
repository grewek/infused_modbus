// The admin approval channel (Milestone P): a Unix domain socket that a
// technician-facing `server admin approve|revoke|list <fingerprint>` CLI
// subcommand talks to, so approving/revoking a TLS client never requires
// speaking the raw protocol by hand (see CLAUDE.md's "Approval/revocation
// channel"). P1 scope only: the socket listener plus a trivial line
// protocol (`APPROVE <fingerprint>` / `REVOKE <fingerprint>` / `LIST`)
// that parses and acknowledges each command. It does not yet mutate
// `ApprovedClients` (P2) or verify the caller's identity via `SO_PEERCRED`
// (P3).

use protocol::tls::Fingerprint;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

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

/// Handles one line of admin-protocol input and returns the response line
/// (without a trailing newline). P1 scope: acknowledges a syntactically
/// valid command without acting on it yet — mutating `ApprovedClients` is
/// P2.
pub fn handle_line(line: &str) -> String {
    match AdminCommand::parse(line.trim_end()) {
        Ok(AdminCommand::Approve(fingerprint)) => format!("OK APPROVE {fingerprint}"),
        Ok(AdminCommand::Revoke(fingerprint)) => format!("OK REVOKE {fingerprint}"),
        Ok(AdminCommand::List) => "OK LIST".to_string(),
        Err(error) => format!("ERROR {error}"),
    }
}

/// Binds the admin socket at `socket_path` (removing any stale leftover
/// file first, e.g. left behind by an unclean shutdown) and serves the line
/// protocol above on every connection, forever.
pub async fn run_admin_socket(socket_path: &Path) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    fn fingerprint() -> Fingerprint {
        Fingerprint::of(b"admin-socket-test")
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

    #[test]
    fn handle_line_acknowledges_approve() {
        let line = format!("APPROVE {}", fingerprint());
        assert_eq!(handle_line(&line), format!("OK APPROVE {}", fingerprint()));
    }

    #[test]
    fn handle_line_acknowledges_revoke() {
        let line = format!("REVOKE {}", fingerprint());
        assert_eq!(handle_line(&line), format!("OK REVOKE {}", fingerprint()));
    }

    #[test]
    fn handle_line_acknowledges_list() {
        assert_eq!(handle_line("LIST"), "OK LIST");
    }

    #[test]
    fn handle_line_reports_a_parse_error() {
        assert!(handle_line("nonsense").starts_with("ERROR "));
    }

    #[tokio::test]
    async fn serves_a_list_command_over_a_real_socket() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("admin.sock");

        let bound_path = socket_path.clone();
        tokio::spawn(async move {
            run_admin_socket(&bound_path).await.unwrap();
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
        assert_eq!(response, "OK LIST\n");
    }

    #[tokio::test]
    async fn removes_a_stale_socket_file_before_binding() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("admin.sock");
        std::fs::write(&socket_path, b"leftover, not a real socket").unwrap();

        let bound_path = socket_path.clone();
        tokio::spawn(async move {
            run_admin_socket(&bound_path).await.unwrap();
        });
        while UnixStream::connect(&socket_path).await.is_err() {
            tokio::task::yield_now().await;
        }
    }
}
