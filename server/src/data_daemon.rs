//! The local socket half of CLAUDE.md's "Option C" MQTT/Sparkplug B design:
//! a Unix domain socket a host process (or, per the design's own explicitly-
//! deferred FFI plan, eventually a `cdylib` shim) talks to in order to read
//! or update this server's own `ServerHandle`-backed dataset — the
//! replacement for `files`' file-watching approach on the server side, using
//! the "REST/socket API" pattern real Modbus-slave prior art (`ModbusSim`,
//! `gplug-ems`) actually converged on, not `files`' own file-watching
//! pattern. Shares its socket shape (line protocol, `SO_PEERCRED`-gated,
//! `0600`-mode socket file) with `admin.rs` via `line_socket::run_line_socket`
//! — this is the second local-socket daemon this server runs, not a new
//! pattern.

use crate::line_socket::run_line_socket;
use crate::server_handle::ServerHandle;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataCommand {
    Set {
        machine: String,
        point: String,
        value: String,
    },
    Get {
        machine: String,
        point: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct DataCommandParseError(String);

impl fmt::Display for DataCommandParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl DataCommand {
    /// Parses one line of this socket's protocol. `SET <machine> <point>
    /// <value...>` takes the rest of the line as `value` verbatim (not
    /// re-split further) since a file record's hex content is itself
    /// whitespace-separated (`"0D FE 00 20"`) — splitting on every space
    /// would otherwise mangle it. `GET <machine> <point>` takes no value.
    pub fn parse(line: &str) -> Result<Self, DataCommandParseError> {
        let mut words = line.split_whitespace();
        let Some(verb) = words.next() else {
            return Err(DataCommandParseError("empty command".to_string()));
        };
        match verb {
            "SET" => {
                let machine = words
                    .next()
                    .ok_or_else(|| {
                        DataCommandParseError("SET requires a machine argument".to_string())
                    })?
                    .to_string();
                let point = words
                    .next()
                    .ok_or_else(|| {
                        DataCommandParseError("SET requires a point argument".to_string())
                    })?
                    .to_string();
                let remaining: Vec<&str> = words.collect();
                if remaining.is_empty() {
                    return Err(DataCommandParseError(
                        "SET requires a value argument".to_string(),
                    ));
                }
                Ok(DataCommand::Set {
                    machine,
                    point,
                    value: remaining.join(" "),
                })
            }
            "GET" => {
                let machine = words
                    .next()
                    .ok_or_else(|| {
                        DataCommandParseError("GET requires a machine argument".to_string())
                    })?
                    .to_string();
                let point = words
                    .next()
                    .ok_or_else(|| {
                        DataCommandParseError("GET requires a point argument".to_string())
                    })?
                    .to_string();
                if words.next().is_some() {
                    return Err(DataCommandParseError(
                        "GET takes exactly two arguments".to_string(),
                    ));
                }
                Ok(DataCommand::Get { machine, point })
            }
            other => Err(DataCommandParseError(format!("unknown command {other:?}"))),
        }
    }
}

/// Applies a parsed command against `handle` and returns the response line
/// (without a trailing newline) — same `"OK <verb> ..."`/`"ERROR <verb>
/// ...: <reason>"` shape `admin.rs::apply_command` already established.
fn apply_command(command: &DataCommand, handle: &ServerHandle) -> String {
    match command {
        DataCommand::Set {
            machine,
            point,
            value,
        } => match handle.set(machine, point, value) {
            Ok(()) => format!("OK SET {machine} {point}"),
            Err(error) => format!("ERROR SET {machine} {point}: {error}"),
        },
        DataCommand::Get { machine, point } => match handle.get(machine, point) {
            Ok(value) => format!("OK GET {machine} {point} {value}"),
            Err(error) => format!("ERROR GET {machine} {point}: {error}"),
        },
    }
}

/// Handles one line of this socket's protocol and returns the response line
/// (without a trailing newline).
fn handle_line(line: &str, handle: &ServerHandle) -> String {
    match DataCommand::parse(line.trim_end()) {
        Ok(command) => apply_command(&command, handle),
        Err(error) => format!("ERROR {error}"),
    }
}

/// Binds the data socket at `socket_path` and serves the line protocol
/// above on every connection, forever — see `line_socket::run_line_socket`
/// for the shared bind/chmod/accept-loop/SO_PEERCRED-gate machinery (this
/// used to duplicate `admin::run_admin_socket` line for line before that
/// was pulled out).
pub async fn run_data_socket(socket_path: &Path, handle: Arc<ServerHandle>) -> std::io::Result<()> {
    run_line_socket(socket_path, move |line| handle_line(line, &handle)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafs::MachineStores;
    use protocol::device_description::{
        AccessRight, CoilDescription, DataType, MachineDescription, MemLayout, RegisterDescription,
    };
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    fn test_machine() -> MachineDescription {
        MachineDescription {
            name: "PumpA".to_string(),
            unit_id: 1,
            registers: vec![RegisterDescription {
                name: "Tank_Temperature".to_string(),
                address: 0,
                data_type: DataType::U16,
                access: AccessRight::ReadWrite,
                unit: None,
            }],
            coils: vec![CoilDescription {
                name: "Motor_Running".to_string(),
                address: 0,
            }],
            discrete_inputs: Vec::new(),
            input_registers: Vec::new(),
            file_records: Vec::new(),
            mem_layout: MemLayout::Abcd,
            input_register_mem_layout: MemLayout::Abcd,
            server_id: None,
        }
    }

    fn test_handle() -> ServerHandle {
        let machine = test_machine();
        let mut stores = HashMap::new();
        stores.insert("PumpA".to_string(), MachineStores::new());
        ServerHandle::new(std::slice::from_ref(&machine), &stores)
    }

    #[test]
    fn parses_set_with_a_single_word_value() {
        assert_eq!(
            DataCommand::parse("SET PumpA Tank_Temperature 30"),
            Ok(DataCommand::Set {
                machine: "PumpA".to_string(),
                point: "Tank_Temperature".to_string(),
                value: "30".to_string(),
            })
        );
    }

    #[test]
    fn parses_set_with_a_multi_word_hex_value() {
        assert_eq!(
            DataCommand::parse("SET PumpA 4:1 0D FE 00 20"),
            Ok(DataCommand::Set {
                machine: "PumpA".to_string(),
                point: "4:1".to_string(),
                value: "0D FE 00 20".to_string(),
            })
        );
    }

    #[test]
    fn parses_get() {
        assert_eq!(
            DataCommand::parse("GET PumpA Tank_Temperature"),
            Ok(DataCommand::Get {
                machine: "PumpA".to_string(),
                point: "Tank_Temperature".to_string(),
            })
        );
    }

    #[test]
    fn rejects_set_missing_a_value() {
        assert!(DataCommand::parse("SET PumpA Tank_Temperature").is_err());
    }

    #[test]
    fn rejects_get_with_a_trailing_argument() {
        assert!(DataCommand::parse("GET PumpA Tank_Temperature extra").is_err());
    }

    #[test]
    fn rejects_an_unknown_verb() {
        assert!(DataCommand::parse("DELETE PumpA Tank_Temperature").is_err());
    }

    #[test]
    fn rejects_an_empty_line() {
        assert!(DataCommand::parse("").is_err());
    }

    #[test]
    fn handle_line_applies_a_valid_set_and_reports_ok() {
        let handle = test_handle();
        assert_eq!(
            handle_line("SET PumpA Tank_Temperature 42", &handle),
            "OK SET PumpA Tank_Temperature"
        );
        assert_eq!(handle.get("PumpA", "Tank_Temperature").unwrap(), "42");
    }

    #[test]
    fn handle_line_applies_a_valid_get() {
        let handle = test_handle();
        handle.set("PumpA", "Motor_Running", "1").unwrap();
        assert_eq!(
            handle_line("GET PumpA Motor_Running", &handle),
            "OK GET PumpA Motor_Running 1"
        );
    }

    #[test]
    fn handle_line_reports_a_validation_error() {
        let handle = test_handle();
        assert_eq!(
            handle_line("SET PumpA Nonexistent 1", &handle),
            "ERROR SET PumpA Nonexistent: unknown point Nonexistent"
        );
    }

    #[test]
    fn handle_line_reports_a_parse_error() {
        let handle = test_handle();
        assert_eq!(
            handle_line("NOT_A_VERB", &handle),
            "ERROR unknown command \"NOT_A_VERB\""
        );
    }

    #[tokio::test]
    async fn run_data_socket_serves_a_real_connection_end_to_end() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("data.sock");
        let handle = Arc::new(test_handle());

        let server_socket_path = socket_path.clone();
        tokio::spawn(async move {
            let _ = run_data_socket(&server_socket_path, handle).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        stream
            .write_all(b"SET PumpA Tank_Temperature 55\n")
            .await
            .unwrap();
        let mut response = vec![0u8; 128];
        let read = stream.read(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&response[..read]),
            "OK SET PumpA Tank_Temperature\n"
        );

        stream
            .write_all(b"GET PumpA Tank_Temperature\n")
            .await
            .unwrap();
        let read = stream.read(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&response[..read]),
            "OK GET PumpA Tank_Temperature 55\n"
        );
    }

    #[tokio::test]
    async fn run_data_socket_sets_the_socket_file_to_owner_only_permissions() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let socket_path = temporary_directory.path().join("data.sock");
        let handle = Arc::new(test_handle());

        let server_socket_path = socket_path.clone();
        tokio::spawn(async move {
            let _ = run_data_socket(&server_socket_path, handle).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let metadata = std::fs::metadata(&socket_path).unwrap();
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            crate::line_socket::SOCKET_FILE_MODE
        );
    }
}
