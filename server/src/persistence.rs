// Persists the approved-clients fingerprint set to disk (Milestone S) —
// the first durable state this project's server itself writes, and the
// first exception to every other piece of runtime state (RegisterStore,
// PendingTransaction, WriteReport, ApprovedClients itself until now) being
// deliberately in-memory only. Losing every approval on every restart is a
// real availability problem, not just an inconvenience (see CLAUDE.md's
// "Persistence" section). The file is read once, at startup only (S1) —
// never hot-reloaded or watched; every live change goes through the admin
// channel (`server::admin`), which is the only thing that ever calls
// `save_atomically` (S2), always while still holding `ApprovedClients`'s
// own lock so the snapshot written and the in-memory state it represents
// can never diverge.

use protocol::tls::Fingerprint;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Same "owned by the server's own service account" discipline as the TLS
/// private key file and the admin socket — this file records exactly who
/// is allowed to connect, so it gets the same restriction (Milestone S3).
const FILE_MODE: u32 = 0o600;

#[derive(Debug, Default, Deserialize, Serialize)]
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

/// Atomically rewrites `path` with `fingerprints`: writes to a temp file
/// in the same directory (so the final rename stays on one filesystem,
/// where POSIX guarantees `rename` is atomic) with `0600` permissions set
/// before the rename — never chmod'd after the fact, so the real file is
/// never briefly world/group-readable, same discipline as the TLS private
/// key file — then renames it over `path`. A crash mid-write therefore
/// never leaves a half-written or corrupt file at `path` itself: the temp
/// file is either fully written and renamed, or the rename never happens
/// and `path` is untouched.
pub fn save_atomically(path: &Path, fingerprints: &[Fingerprint]) -> std::io::Result<()> {
    let raw = RawApprovedClients {
        fingerprints: fingerprints.iter().map(Fingerprint::to_string).collect(),
    };
    let serialized =
        toml::to_string(&raw).expect("a plain list of fingerprint strings always serializes");

    let temp_path = path.with_extension("toml.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(&temp_path)?;
    file.write_all(serialized.as_bytes())?;
    // `OpenOptions::mode` only applies when `open` actually creates the
    // file — if a stale temp file from a previous crashed write already
    // existed with some other mode, explicitly re-assert `0600` rather
    // than trusting that path (Milestone S3: "explicit check, not left at
    // OS default").
    std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(FILE_MODE))?;
    drop(file);
    std::fs::rename(&temp_path, path)
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

    #[test]
    fn save_atomically_then_load_round_trips_the_fingerprint_list() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");
        let fp_a = fingerprint(b"client-a");
        let fp_b = fingerprint(b"client-b");

        save_atomically(&path, &[fp_a, fp_b]).unwrap();

        assert_eq!(load(&path).unwrap(), vec![fp_a, fp_b]);
    }

    #[test]
    fn save_atomically_of_an_empty_slice_round_trips_to_an_empty_list() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");

        save_atomically(&path, &[]).unwrap();

        assert_eq!(load(&path).unwrap(), Vec::new());
    }

    #[test]
    fn save_atomically_overwrites_a_previous_snapshot() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");
        let fp_a = fingerprint(b"client-a");
        let fp_b = fingerprint(b"client-b");
        save_atomically(&path, &[fp_a]).unwrap();

        save_atomically(&path, &[fp_b]).unwrap();

        assert_eq!(load(&path).unwrap(), vec![fp_b]);
    }

    #[test]
    fn save_atomically_sets_0600_permissions_on_the_real_file() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");

        save_atomically(&path, &[fingerprint(b"client-a")]).unwrap();

        let permissions = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn save_atomically_leaves_no_leftover_temp_file() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");

        save_atomically(&path, &[fingerprint(b"client-a")]).unwrap();

        assert!(!path.with_extension("toml.tmp").exists());
    }

    #[test]
    fn save_atomically_forces_0600_even_over_a_stale_temp_file_with_different_permissions() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("approved-clients.toml");
        let temp_path = path.with_extension("toml.tmp");
        std::fs::write(&temp_path, b"leftover from a crashed write").unwrap();
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        save_atomically(&path, &[fingerprint(b"client-a")]).unwrap();

        let permissions = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }
}
