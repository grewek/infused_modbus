//! Persists the Sparkplug B `bdSeq` value across `client` process restarts.
//!
//! Real conformance gap found via the Eclipse Sparkplug TCK's "Session
//! Establishment" test, not anticipated at design time: `bdSeq` was
//! generated fresh via `sparkplug::seq_counter::BdSeqCounter::new()` every
//! time `client::edge_node::connect_edge_node` ran, so every process
//! restart produced the exact same `bdSeq` (0) as the last one. Per spec,
//! `bdSeq` exists specifically so a Host Application can tell a *new*
//! session's `NBIRTH` apart from a *stale* `NDEATH` belonging to a
//! previous, already-superseded session that might still arrive late (the
//! MQTT Will is only delivered once the broker notices the old TCP
//! connection is gone, which can race a fast reconnect) — reusing the same
//! value across sessions defeats that entirely, which is exactly what the
//! TCK's `topics-nbirth-bdseq-increment`/
//! `message-flow-edge-node-birth-publish-will-message-payload-bdSeq`
//! assertions caught. `sparkplug::seq_counter::BdSeqCounter` itself already
//! only ever "generates" one value per session, since this project's own
//! design has exactly one Edge Node identity per `client` process (see
//! `client::edge_node`'s own module doc comment) — the real missing piece
//! was persisting that one value *between* processes, which is
//! `client`-side I/O, not something the protocol-only `sparkplug` crate
//! should own.

use std::path::Path;

/// Reads the `bdSeq` value to use for this session from `path` (`0` if the
/// file doesn't exist yet — the first run), then persists `current + 1` back
/// to the same path (atomic temp-file-plus-rename, same discipline this
/// project already uses for its other small persisted-state files) so the
/// *next* run gets a genuinely higher value. A read/parse/write failure
/// falls back to `0` and is logged, not treated as fatal — a technician
/// losing TCK-level bdSeq strictness because of a transient disk issue is
/// preferable to `client` refusing to start at all over it.
pub fn next_bd_seq(path: &Path) -> u64 {
    let current = std::fs::read_to_string(path)
        .ok()
        .and_then(|content| content.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let temp_path = path.with_extension("tmp");
    let persisted = std::fs::write(&temp_path, (current + 1).to_string())
        .and_then(|()| std::fs::rename(&temp_path, path));
    if let Err(error) = persisted {
        eprintln!(
            "warning: failed to persist next bdSeq to {path:?}: {error} \
             (every future session will reuse bdSeq {current} until this is fixed)"
        );
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_against_a_nonexistent_file_returns_zero() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("bdseq");

        assert_eq!(next_bd_seq(&path), 0);
    }

    #[test]
    fn each_call_increments_from_the_last_persisted_value() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("bdseq");

        assert_eq!(next_bd_seq(&path), 0);
        assert_eq!(next_bd_seq(&path), 1);
        assert_eq!(next_bd_seq(&path), 2);
    }

    #[test]
    fn value_survives_being_read_by_a_fresh_call_simulating_a_new_process() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("bdseq");

        next_bd_seq(&path);
        next_bd_seq(&path);
        // A third "process" starting fresh sees the same persisted state.
        assert_eq!(next_bd_seq(&path), 2);
    }

    #[test]
    fn no_stray_temp_file_is_left_behind() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("bdseq");

        next_bd_seq(&path);

        assert!(!path.with_extension("tmp").exists());
        assert!(path.exists());
    }
}
