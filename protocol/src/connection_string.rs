// Parsing only — actually opening a connection (real I/O, and for
// `tls+tcp://` eventually a loaded `tls::Identity`) is the caller's job.
// Extracted out of what was, before `tls+tcp://` existed, an
// `if let Some(...) = connection_string.strip_prefix(...)` chain duplicated
// almost identically in both `client::main` and `server::main` — a second
// scheme was tolerable duplicated, a third is the concrete second
// occurrence that makes extraction worth it.

/// What kind of connection a `tcp://`/`rtu://`/`tls+tcp://`-prefixed
/// connection string names, and the transport-specific parameters needed to
/// actually open it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionTarget {
    Tcp { address: String },
    Rtu { path: String, baud_rate: u32 },
    TlsTcp { address: String },
}

pub fn parse_connection_string(connection_string: &str) -> Result<ConnectionTarget, String> {
    if let Some(address) = connection_string.strip_prefix("tls+tcp://") {
        Ok(ConnectionTarget::TlsTcp {
            address: address.to_string(),
        })
    } else if let Some(address) = connection_string.strip_prefix("tcp://") {
        Ok(ConnectionTarget::Tcp {
            address: address.to_string(),
        })
    } else if let Some(rest) = connection_string.strip_prefix("rtu://") {
        let (path, baud_rate) = rest.rsplit_once(':').ok_or_else(|| {
            format!("rtu:// connection must be rtu://<path>:<baud-rate>, got {connection_string:?}")
        })?;
        let baud_rate: u32 = baud_rate
            .parse()
            .map_err(|error| format!("invalid baud rate {baud_rate:?}: {error}"))?;
        Ok(ConnectionTarget::Rtu {
            path: path.to_string(),
            baud_rate,
        })
    } else {
        Err(format!(
            "connection must start with tcp://, tls+tcp://, or rtu://, got {connection_string:?}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp() {
        assert_eq!(
            parse_connection_string("tcp://127.0.0.1:502").unwrap(),
            ConnectionTarget::Tcp {
                address: "127.0.0.1:502".to_string()
            }
        );
    }

    #[test]
    fn parses_tls_tcp() {
        assert_eq!(
            parse_connection_string("tls+tcp://127.0.0.1:502").unwrap(),
            ConnectionTarget::TlsTcp {
                address: "127.0.0.1:502".to_string()
            }
        );
    }

    #[test]
    fn parses_rtu() {
        assert_eq!(
            parse_connection_string("rtu:///dev/ttyUSB0:9600").unwrap(),
            ConnectionTarget::Rtu {
                path: "/dev/ttyUSB0".to_string(),
                baud_rate: 9600
            }
        );
    }

    #[test]
    fn rejects_rtu_without_baud_rate() {
        assert!(parse_connection_string("rtu:///dev/ttyUSB0").is_err());
    }

    #[test]
    fn rejects_rtu_with_non_numeric_baud_rate() {
        assert!(parse_connection_string("rtu:///dev/ttyUSB0:fast").is_err());
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_connection_string("udp://127.0.0.1:502").is_err());
    }
}
