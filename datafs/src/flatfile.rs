//! The `files` representation layer (M2 of the datafs plan — see CLAUDE.md's
//! "Planned: pluggable data-representation layer" section): renders Modbus
//! data as real regular files on a real filesystem instead of a synthetic
//! FUSE tree, using write-to-temp + atomic `rename()` so a concurrent reader
//! never sees a torn value regardless of content size.
//!
//! Scope of this first slice (M2): a single machine's `holding-registers/`
//! directory, read-only. Every other data type (M3), the write path via
//! `inotify` (M4/M5), multi-machine layout (M6), and CLI wiring (M9) are
//! deliberately not here yet — this module exists to prove the core
//! rename-based mechanism works before it's repeated across every data type.
//!
//! Deliberate scope reduction vs. the CLAUDE.md design text: that section
//! describes change detection as push-based (`Notify`, fired by every
//! `.set()` on a `MachineStores`). Wiring that would mean touching every
//! `store.set()` call site in `client`/`server`, well outside this module's
//! "prove the mechanism inside `datafs` alone" scope. For now,
//! `FlatfileRegisterRenderer` only exposes `render_once` — a caller decides
//! how/when to call it (a plain loop, a timer, or a real `Notify` later).
//! Revisit once a real caller (M9) shows whether a tight poll loop is
//! actually good enough or the `Notify` wiring is worth its wider blast
//! radius.

use crate::{RegisterStore, register_file_content};
use protocol::device_description::RegisterDescription;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Renders one machine's `holding-registers/` directory as real files under
/// `directory`, kept in sync with a `RegisterStore` by whoever calls
/// `render_once`.
pub struct FlatfileRegisterRenderer {
    directory: PathBuf,
    registers: Vec<RegisterDescription>,
    store: Arc<Mutex<RegisterStore>>,
    // Last content actually written per register file, so `render_once`
    // skips the write+rename syscalls entirely for a register whose value
    // hasn't changed since the previous call — atomic rename makes repeated
    // writes safe, not free, and a tight poll loop calls this often.
    last_rendered: Mutex<HashMap<String, String>>,
}

impl FlatfileRegisterRenderer {
    pub fn new(
        directory: PathBuf,
        registers: Vec<RegisterDescription>,
        store: Arc<Mutex<RegisterStore>>,
    ) -> Self {
        Self {
            directory,
            registers,
            store,
            last_rendered: Mutex::new(HashMap::new()),
        }
    }

    /// Creates the directory (if missing) and writes every configured
    /// register's current content, so `ls` shows every entry immediately —
    /// mirrors the FUSE layer's static `lookup`/`readdir` listing every
    /// entry declared in the TOML, even before a value has ever been
    /// polled/written.
    pub fn initialize(&self) -> io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        self.render_once()
    }

    /// Re-renders every configured register's file to match the store's
    /// current value. Each file is updated via write-to-`<name>.tmp` +
    /// `rename()` over the real path — `rename()` within one directory is
    /// POSIX-atomic, so a concurrent reader always sees either the fully-old
    /// or the fully-new content, never a torn read, regardless of how many
    /// times this races against an in-progress `cat`.
    pub fn render_once(&self) -> io::Result<()> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut last_rendered = self
            .last_rendered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for register in &self.registers {
            let content = register_file_content(&store, &register.name);
            if last_rendered.get(&register.name) == Some(&content) {
                continue;
            }
            atomic_write(&self.directory.join(&register.name), &content)?;
            last_rendered.insert(register.name.clone(), content);
        }
        Ok(())
    }
}

// Writes `content` to `<path>.tmp` in the same directory as `path`, then
// `rename()`s it over `path` — atomic on POSIX as long as both paths are on
// the same filesystem, which they always are here since the temp file is a
// sibling of the file it replaces.
fn atomic_write(path: &Path, content: &str) -> io::Result<()> {
    let mut temporary_file_name = path.file_name().unwrap_or_default().to_os_string();
    temporary_file_name.push(".tmp");
    let temporary_path = path.with_file_name(temporary_file_name);
    fs::write(&temporary_path, content)?;
    fs::rename(&temporary_path, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RegisterValue;
    use protocol::device_description::{AccessRight, DataType};

    fn a_register(name: &str) -> RegisterDescription {
        RegisterDescription {
            name: name.to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadOnly,
        }
    }

    #[test]
    fn initialize_creates_the_directory_and_an_empty_file_per_register() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("holding-registers");
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let renderer = FlatfileRegisterRenderer::new(
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            store,
        );

        renderer.initialize().unwrap();

        assert_eq!(
            fs::read_to_string(directory.join("Tank_Temperature")).unwrap(),
            ""
        );
    }

    #[test]
    fn render_once_reflects_a_value_set_after_initialize() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("holding-registers");
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let renderer = FlatfileRegisterRenderer::new(
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            store.clone(),
        );
        renderer.initialize().unwrap();

        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(42));
        renderer.render_once().unwrap();

        assert_eq!(
            fs::read_to_string(directory.join("Tank_Temperature")).unwrap(),
            "42\n"
        );
    }

    #[test]
    fn render_once_overwrites_a_previously_rendered_value() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("holding-registers");
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let renderer = FlatfileRegisterRenderer::new(
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            store.clone(),
        );
        renderer.initialize().unwrap();
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(42));
        renderer.render_once().unwrap();

        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(43));
        renderer.render_once().unwrap();

        assert_eq!(
            fs::read_to_string(directory.join("Tank_Temperature")).unwrap(),
            "43\n"
        );
    }

    #[test]
    fn render_once_does_not_touch_the_file_when_the_value_is_unchanged() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("holding-registers");
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let renderer = FlatfileRegisterRenderer::new(
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            store.clone(),
        );
        renderer.initialize().unwrap();
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(42));
        renderer.render_once().unwrap();
        let modified_at_first = fs::metadata(directory.join("Tank_Temperature"))
            .unwrap()
            .modified()
            .unwrap();

        renderer.render_once().unwrap();

        let modified_at_second = fs::metadata(directory.join("Tank_Temperature"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(modified_at_first, modified_at_second);
    }

    #[test]
    fn render_once_leaves_no_leftover_tmp_file() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("holding-registers");
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let renderer = FlatfileRegisterRenderer::new(
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            store.clone(),
        );
        renderer.initialize().unwrap();
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(42));
        renderer.render_once().unwrap();

        assert!(!directory.join("Tank_Temperature.tmp").exists());
    }

    #[test]
    fn initialize_creates_one_file_per_configured_register_even_with_none_set() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("holding-registers");
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let renderer = FlatfileRegisterRenderer::new(
            directory.clone(),
            vec![a_register("Tank_Temperature"), a_register("Flow_Rate")],
            store,
        );

        renderer.initialize().unwrap();

        let mut entries: Vec<String> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        entries.sort();
        assert_eq!(entries, vec!["Flow_Rate", "Tank_Temperature"]);
    }
}
