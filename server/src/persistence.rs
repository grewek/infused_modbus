// Persists the approved-clients fingerprint set to disk (Milestone S) —
// the first durable state this project's server itself writes, and the
// first exception to every other piece of runtime state (RegisterStore,
// PendingTransaction, WriteReport, ApprovedClients itself until now) being
// deliberately in-memory only. Losing every approval on every restart is a
// real availability problem, not just an inconvenience (see CLAUDE.md's
// "Persistence" section). S1 scope only: loading at startup — the file is
// read once, here, never hot-reloaded or watched; every live change must
// go through the admin channel, which will own writing it back (S2).

use protocol::tls::Fingerprint;
use serde::Deserialize;
use std::fmt;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
struct RawApprovedClients {
    #[serde(default)]
    fingerprints: Vec<String>,
}

#[derive(Debug)]
pub enum LoadError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    InvalidFingerprint(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io(error) => write!(formatter, "{error}"),
            LoadError::Toml(error) => write!(formatter, "{error}"),
            LoadError::InvalidFingerprint(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Reads `path`'s previously-approved fingerprints — an **empty** list if
/// `path` doesn't exist at all (a fresh server, or one that has never had
/// anything approved, has nothing to restore; this is not an error).
pub fn load(path: &Path) -> Result<Vec<Fingerprint>, LoadError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let source = std::fs::read_to_string(path).map_err(LoadError::Io)?;
    let raw: RawApprovedClients = toml::from_str(&source).map_err(LoadError::Toml)?;
    raw.fingerprints
        .into_iter()
        .map(|text| text.parse().map_err(LoadError::InvalidFingerprint))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(seed: &[u8]) -> Fingerprint {
        Fingerprint::of(seed)
    }

    #[test]
    fn load_of_a_missing_file_returns_an_empty_list() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");
        assert_eq!(load(&path).unwrap(), Vec::new());
    }

    #[test]
    fn load_reads_previously_saved_fingerprints() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");
        let fp_a = fingerprint(b"client-a");
        let fp_b = fingerprint(b"client-b");
        std::fs::write(&path, format!("fingerprints = [\"{fp_a}\", \"{fp_b}\"]\n")).unwrap();

        assert_eq!(load(&path).unwrap(), vec![fp_a, fp_b]);
    }

    #[test]
    fn load_of_an_empty_fingerprints_list_returns_an_empty_list() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");
        std::fs::write(&path, "fingerprints = []\n").unwrap();

        assert_eq!(load(&path).unwrap(), Vec::new());
    }

    #[test]
    fn load_rejects_an_invalid_fingerprint_string() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");
        std::fs::write(&path, "fingerprints = [\"not-a-fingerprint\"]\n").unwrap();

        assert!(load(&path).is_err());
    }

    #[test]
    fn load_rejects_invalid_toml_syntax() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");
        std::fs::write(&path, "this is not valid toml [[[").unwrap();

        assert!(load(&path).is_err());
    }
}
