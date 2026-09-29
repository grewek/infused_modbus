//! The `files` representation layer (M2/M3 of the datafs plan — see
//! CLAUDE.md's "Planned: pluggable data-representation layer" section):
//! renders Modbus data as real regular files on a real filesystem instead of
//! a synthetic FUSE tree, using write-to-temp + atomic `rename()` so a
//! concurrent reader never sees a torn value regardless of content size.
//!
//! Scope so far: M2 proved the mechanism with `holding-registers/` alone
//! (single machine, read-only); M3 extends it to every other read-only data
//! type — `coils/`, `discrete-inputs/`, `input-registers/`,
//! `file-records/<file_number>/<record_number>` (nested), and `server-id`
//! (a single static file, client-only). The write path via `inotify`
//! (M4/M5), multi-machine layout (M6), and CLI wiring (M9) are still not
//! here yet.
//!
//! Deliberate scope reduction vs. the CLAUDE.md design text: that section
//! describes change detection as push-based (`Notify`, fired by every
//! `.set()` on a `MachineStores`). Wiring that would mean touching every
//! `store.set()` call site in `client`/`server`, well outside this module's
//! "prove the mechanism inside `datafs` alone" scope. For now, every
//! renderer only exposes `render_once` — a caller decides how/when to call
//! it (a plain loop, a timer, or a real `Notify` later). Revisit once a real
//! caller (M9) shows whether a tight poll loop is actually good enough or
//! the `Notify` wiring is worth its wider blast radius.

use crate::{
    CoilStore, DiscreteInputStore, FileRecordStore, InputRegisterStore, RegisterStore,
    coil_file_content, discrete_input_file_content, file_record_file_content,
    input_register_file_content, register_file_content,
};
use protocol::device_description::{
    CoilDescription, DiscreteInputDescription, FileRecordDescription, InputRegisterDescription,
    RegisterDescription,
};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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

// Shared by every "one file per named entry" renderer below (registers,
// coils, discrete inputs, input registers): re-renders each name's file via
// `atomic_write`, skipping any entry whose content hasn't changed since the
// last call — atomic rename makes repeated writes safe, not free, and a
// tight poll loop calls this often.
fn render_named_files(
    directory: &Path,
    names: impl Iterator<Item = String>,
    content_for: impl Fn(&str) -> String,
    last_rendered: &mut HashMap<String, String>,
) -> io::Result<()> {
    for name in names {
        let content = content_for(&name);
        if last_rendered.get(&name) == Some(&content) {
            continue;
        }
        atomic_write(&directory.join(&name), &content)?;
        last_rendered.insert(name, content);
    }
    Ok(())
}

/// Renders one machine's `holding-registers/` directory as real files under
/// `directory`, kept in sync with a `RegisterStore` by whoever calls
/// `render_once`.
pub struct FlatfileRegisterRenderer {
    directory: PathBuf,
    registers: Vec<RegisterDescription>,
    store: Arc<Mutex<RegisterStore>>,
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
    /// current value — see `render_named_files` for the atomicity guarantee.
    pub fn render_once(&self) -> io::Result<()> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut last_rendered = self
            .last_rendered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        render_named_files(
            &self.directory,
            self.registers.iter().map(|register| register.name.clone()),
            |name| register_file_content(&store, name),
            &mut last_rendered,
        )
    }
}

/// Mirrors `FlatfileRegisterRenderer` exactly, for `coils/`.
pub struct FlatfileCoilRenderer {
    directory: PathBuf,
    coils: Vec<CoilDescription>,
    store: Arc<Mutex<CoilStore>>,
    last_rendered: Mutex<HashMap<String, String>>,
}

impl FlatfileCoilRenderer {
    pub fn new(
        directory: PathBuf,
        coils: Vec<CoilDescription>,
        store: Arc<Mutex<CoilStore>>,
    ) -> Self {
        Self {
            directory,
            coils,
            store,
            last_rendered: Mutex::new(HashMap::new()),
        }
    }

    pub fn initialize(&self) -> io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        self.render_once()
    }

    pub fn render_once(&self) -> io::Result<()> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut last_rendered = self
            .last_rendered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        render_named_files(
            &self.directory,
            self.coils.iter().map(|coil| coil.name.clone()),
            |name| coil_file_content(&store, name),
            &mut last_rendered,
        )
    }
}

/// Mirrors `FlatfileRegisterRenderer` exactly, for `discrete-inputs/`.
pub struct FlatfileDiscreteInputRenderer {
    directory: PathBuf,
    discrete_inputs: Vec<DiscreteInputDescription>,
    store: Arc<Mutex<DiscreteInputStore>>,
    last_rendered: Mutex<HashMap<String, String>>,
}

impl FlatfileDiscreteInputRenderer {
    pub fn new(
        directory: PathBuf,
        discrete_inputs: Vec<DiscreteInputDescription>,
        store: Arc<Mutex<DiscreteInputStore>>,
    ) -> Self {
        Self {
            directory,
            discrete_inputs,
            store,
            last_rendered: Mutex::new(HashMap::new()),
        }
    }

    pub fn initialize(&self) -> io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        self.render_once()
    }

    pub fn render_once(&self) -> io::Result<()> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut last_rendered = self
            .last_rendered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        render_named_files(
            &self.directory,
            self.discrete_inputs
                .iter()
                .map(|discrete_input| discrete_input.name.clone()),
            |name| discrete_input_file_content(&store, name),
            &mut last_rendered,
        )
    }
}

/// Mirrors `FlatfileRegisterRenderer` exactly, for `input-registers/`.
pub struct FlatfileInputRegisterRenderer {
    directory: PathBuf,
    input_registers: Vec<InputRegisterDescription>,
    store: Arc<Mutex<InputRegisterStore>>,
    last_rendered: Mutex<HashMap<String, String>>,
}

impl FlatfileInputRegisterRenderer {
    pub fn new(
        directory: PathBuf,
        input_registers: Vec<InputRegisterDescription>,
        store: Arc<Mutex<InputRegisterStore>>,
    ) -> Self {
        Self {
            directory,
            input_registers,
            store,
            last_rendered: Mutex::new(HashMap::new()),
        }
    }

    pub fn initialize(&self) -> io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        self.render_once()
    }

    pub fn render_once(&self) -> io::Result<()> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut last_rendered = self
            .last_rendered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        render_named_files(
            &self.directory,
            self.input_registers
                .iter()
                .map(|input_register| input_register.name.clone()),
            |name| input_register_file_content(&store, name),
            &mut last_rendered,
        )
    }
}

/// Renders `file-records/<file_number>/<record_number>` as a two-level real
/// directory tree — unlike every other data type here, entries are keyed by
/// a `(file_number, record_number)` pair, not a name, and grouped one
/// directory per unique `file_number` (mirrors the FUSE layer's own nested
/// `file_records_ino`/`file_number_to_ino` structure, but as literal nested
/// paths instead of an inode-range trick).
pub struct FlatfileFileRecordRenderer {
    directory: PathBuf,
    file_records: Vec<FileRecordDescription>,
    store: Arc<Mutex<FileRecordStore>>,
    last_rendered: Mutex<HashMap<(u16, u16), String>>,
}

impl FlatfileFileRecordRenderer {
    pub fn new(
        directory: PathBuf,
        file_records: Vec<FileRecordDescription>,
        store: Arc<Mutex<FileRecordStore>>,
    ) -> Self {
        Self {
            directory,
            file_records,
            store,
            last_rendered: Mutex::new(HashMap::new()),
        }
    }

    /// Creates `directory` plus one subdirectory per unique `file_number`
    /// and writes every configured entry's current content.
    pub fn initialize(&self) -> io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        for file_number in self.unique_file_numbers() {
            fs::create_dir_all(self.directory.join(file_number.to_string()))?;
        }
        self.render_once()
    }

    pub fn render_once(&self) -> io::Result<()> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut last_rendered = self
            .last_rendered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for description in &self.file_records {
            let content = file_record_file_content(
                &store,
                description.file_number,
                description.record_number,
                description.record_length,
            );
            let key = (description.file_number, description.record_number);
            if last_rendered.get(&key) == Some(&content) {
                continue;
            }
            let path = self
                .directory
                .join(description.file_number.to_string())
                .join(description.record_number.to_string());
            atomic_write(&path, &content)?;
            last_rendered.insert(key, content);
        }
        Ok(())
    }

    // First-seen order, deduplicated — matches the FUSE layer's own
    // `unique_file_numbers` precedent.
    fn unique_file_numbers(&self) -> Vec<u16> {
        let mut seen = Vec::new();
        for description in &self.file_records {
            if !seen.contains(&description.file_number) {
                seen.push(description.file_number);
            }
        }
        seen
    }
}

/// `server-id` is a single static file (client-only, mirrors whichever
/// `MachineDescription.server_id` the client already parsed) — no store to
/// poll, no change to ever re-render, so a plain one-shot write is enough;
/// no dedicated renderer type needed for something written exactly once.
pub fn write_server_id_file(path: &Path, server_id: Option<&str>) -> io::Result<()> {
    let content = match server_id {
        Some(server_id) => format!("{server_id}\n"),
        None => return Ok(()),
    };
    atomic_write(path, &content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoilValue, RegisterValue};
    use protocol::device_description::{AccessRight, DataType};

    fn a_register(name: &str) -> RegisterDescription {
        RegisterDescription {
            name: name.to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadOnly,
        }
    }

    fn a_coil(name: &str) -> CoilDescription {
        CoilDescription {
            name: name.to_string(),
            address: 1,
        }
    }

    fn a_discrete_input(name: &str) -> DiscreteInputDescription {
        DiscreteInputDescription {
            name: name.to_string(),
            address: 1,
        }
    }

    fn an_input_register(name: &str) -> InputRegisterDescription {
        InputRegisterDescription {
            name: name.to_string(),
            address: 30001,
            data_type: DataType::U16,
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

    #[test]
    fn coil_renderer_reflects_a_value_as_zero_or_one() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("coils");
        let store = Arc::new(Mutex::new(CoilStore::new()));
        let renderer = FlatfileCoilRenderer::new(
            directory.clone(),
            vec![a_coil("Motor_Running")],
            store.clone(),
        );
        renderer.initialize().unwrap();

        store.lock().unwrap().set("Motor_Running", CoilValue(true));
        renderer.render_once().unwrap();

        assert_eq!(
            fs::read_to_string(directory.join("Motor_Running")).unwrap(),
            "1\n"
        );
    }

    #[test]
    fn discrete_input_renderer_reflects_a_value() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("discrete-inputs");
        let store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let renderer = FlatfileDiscreteInputRenderer::new(
            directory.clone(),
            vec![a_discrete_input("Door_Open_Sensor")],
            store.clone(),
        );
        renderer.initialize().unwrap();

        store
            .lock()
            .unwrap()
            .set("Door_Open_Sensor", CoilValue(true));
        renderer.render_once().unwrap();

        assert_eq!(
            fs::read_to_string(directory.join("Door_Open_Sensor")).unwrap(),
            "1\n"
        );
    }

    #[test]
    fn input_register_renderer_reflects_a_value() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("input-registers");
        let store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let renderer = FlatfileInputRegisterRenderer::new(
            directory.clone(),
            vec![an_input_register("Flow_Rate")],
            store.clone(),
        );
        renderer.initialize().unwrap();

        store
            .lock()
            .unwrap()
            .set("Flow_Rate", RegisterValue::U16(7));
        renderer.render_once().unwrap();

        assert_eq!(
            fs::read_to_string(directory.join("Flow_Rate")).unwrap(),
            "7\n"
        );
    }

    fn a_file_record(
        file_number: u16,
        record_number: u16,
        record_length: u16,
    ) -> FileRecordDescription {
        FileRecordDescription {
            file_number,
            record_number,
            record_length,
        }
    }

    #[test]
    fn file_record_renderer_initialize_creates_a_subdirectory_per_unique_file_number() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("file-records");
        let store = Arc::new(Mutex::new(FileRecordStore::new()));
        let renderer = FlatfileFileRecordRenderer::new(
            directory.clone(),
            vec![
                a_file_record(4, 1, 2),
                a_file_record(4, 2, 2),
                a_file_record(3, 9, 1),
            ],
            store,
        );

        renderer.initialize().unwrap();

        let mut subdirectories: Vec<String> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        subdirectories.sort();
        assert_eq!(subdirectories, vec!["3", "4"]);
        assert_eq!(
            fs::read_to_string(directory.join("4").join("1")).unwrap(),
            "00 00 00 00\n"
        );
    }

    #[test]
    fn file_record_renderer_reflects_a_written_value() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("file-records");
        let store = Arc::new(Mutex::new(FileRecordStore::new()));
        let renderer = FlatfileFileRecordRenderer::new(
            directory.clone(),
            vec![a_file_record(4, 1, 2)],
            store.clone(),
        );
        renderer.initialize().unwrap();

        store
            .lock()
            .unwrap()
            .set(4, 1, vec![0x0D, 0xFE, 0x00, 0x20]);
        renderer.render_once().unwrap();

        assert_eq!(
            fs::read_to_string(directory.join("4").join("1")).unwrap(),
            "0D FE 00 20\n"
        );
    }

    #[test]
    fn write_server_id_file_writes_the_configured_value() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("server-id");

        write_server_id_file(&path, Some("pump-a-plc")).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "pump-a-plc\n");
    }

    #[test]
    fn write_server_id_file_does_nothing_when_not_configured() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let path = temporary_directory.path().join("server-id");

        write_server_id_file(&path, None).unwrap();

        assert!(!path.exists());
    }
}
