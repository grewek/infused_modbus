//! The `files` representation layer (M2/M3 of the datafs plan — see
//! CLAUDE.md's "Planned: pluggable data-representation layer" section):
//! renders Modbus data as real regular files on a real filesystem instead of
//! a synthetic FUSE tree, using write-to-temp + atomic `rename()` so a
//! concurrent reader never sees a torn value regardless of content size.
//!
//! Scope so far: M2 proved the mechanism with `holding-registers/` alone
//! (single machine, read-only); M3 extended it to every other read-only data
//! type — `coils/`, `discrete-inputs/`, `input-registers/`,
//! `file-records/<file_number>/<record_number>` (nested), and `server-id`
//! (a single static file, client-only). M4 adds the client write path:
//! `transactions/`+`TRANSACTION_END` via `inotify`, mirroring the FUSE
//! layer's `write()`/`release()`-then-`create()` staging ritual —
//! `FlatfileTransactionWatcher`. The server direct-write path (M5),
//! multi-machine layout (M6), and CLI wiring (M9) are still not here yet.
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
    CoilStore, CoilValue, DiscreteInputStore, FileRecordStore, InputRegisterStore,
    PendingTransaction, RegisterStore, StagedValue, coil_file_content, discrete_input_file_content,
    file_record_file_content, input_register_file_content, parse_coil_value,
    parse_file_record_name, parse_file_record_value, parse_masked_register_value,
    parse_register_value, register_file_content,
};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use protocol::device_description::{
    AccessRight, CoilDescription, DiscreteInputDescription, FileRecordDescription,
    InputRegisterDescription, RegisterDescription,
};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

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

// The sentinel name that triggers a transaction commit — same name and
// meaning as `filesystem::TRANSACTION_END_NAME`, kept as its own constant
// here rather than shared, since the two live in genuinely separate,
// independent presentation layers (no code path imports across them).
const TRANSACTION_END_NAME: &str = "TRANSACTION_END";

/// Watches `transactions/` for the client's staging ritual — `inotify`
/// stands in for the FUSE layer's own `write()`/`release()`-then-`create()`
/// interception, which a real filesystem gives no way to hook directly.
///
/// Two events matter: `IN_CLOSE_WRITE` on a file under `transactions/`
/// (a real `open()+write()+close()` sequence — exactly what `echo value >
/// path` produces) stages that file's current content, and `IN_CREATE` of
/// `TRANSACTION_END` drains everything staged so far and sends it down the
/// same `(machine_name, HashMap<String, StagedValue>)`-tagged channel
/// `client::transaction_consumer` already reads from — no changes needed
/// downstream of the channel.
///
/// The daemon's own read-path updates (`FlatfileRegisterRenderer` and
/// friends) go through `rename()`, which the kernel reports as
/// `IN_MOVED_TO`, never `IN_CLOSE_WRITE` — so watching only `IN_CLOSE_WRITE`
/// here can't ever mistake the daemon's own writes for user input, no
/// origin-tagging needed (see CLAUDE.md's design section for this in full).
///
/// One real, structural difference from the FUSE layer, not fixable here:
/// FUSE can reject an unknown target at `create()` time (`ENOENT`, so
/// `echo` itself fails instantly). A real filesystem gives no such hook —
/// `echo` always succeeds. The closest available parity is to notice the
/// unknown target at `IN_CLOSE_WRITE` time and remove the stray file, which
/// `stage_one` does — closer to "the write never really happened" than
/// leaving it sitting there unprocessed, even though the user's `echo`
/// itself didn't get an error the way it would under FUSE. A target that
/// *is* known but whose content fails to parse is left exactly where FUSE
/// leaves it too: not staged, file untouched, no feedback (an open gap
/// noted in CLAUDE.md's Milestone H3, not solved by either layer).
pub struct FlatfileTransactionWatcher {
    machine_name: String,
    directory: PathBuf,
    registers: Vec<RegisterDescription>,
    coils: Vec<CoilDescription>,
    file_records: Vec<FileRecordDescription>,
    transaction_sender: mpsc::Sender<(String, HashMap<String, StagedValue>)>,
}

impl FlatfileTransactionWatcher {
    pub fn new(
        machine_name: String,
        directory: PathBuf,
        registers: Vec<RegisterDescription>,
        coils: Vec<CoilDescription>,
        file_records: Vec<FileRecordDescription>,
        transaction_sender: mpsc::Sender<(String, HashMap<String, StagedValue>)>,
    ) -> Self {
        Self {
            machine_name,
            directory,
            registers,
            coils,
            file_records,
            transaction_sender,
        }
    }

    /// Creates `transactions/` if missing — mirrors every other renderer's
    /// `initialize`, so `ls` shows an (empty) staging area immediately.
    pub fn initialize(&self) -> io::Result<()> {
        fs::create_dir_all(&self.directory)
    }

    /// Blocks the calling thread forever, watching `transactions/`. Returns
    /// only if setting up or reading the inotify watch itself fails — a
    /// caller is expected to run this on its own dedicated thread.
    pub fn run_forever(&self) -> io::Result<()> {
        let mut inotify = Inotify::init()?;
        inotify
            .watches()
            .add(&self.directory, WatchMask::CLOSE_WRITE | WatchMask::CREATE)?;
        let mut pending = PendingTransaction::new();
        let mut buffer = [0u8; 4096];
        loop {
            let events = inotify.read_events_blocking(&mut buffer)?;
            for event in events {
                let Some(name) = event.name.and_then(|name| name.to_str()) else {
                    continue;
                };
                if event.mask.contains(EventMask::CREATE) && name == TRANSACTION_END_NAME {
                    self.commit(&mut pending);
                } else if event.mask.contains(EventMask::CLOSE_WRITE) {
                    self.stage_one(&mut pending, name);
                }
            }
        }
    }

    fn register_by_name(&self, name: &str) -> Option<&RegisterDescription> {
        self.registers.iter().find(|register| register.name == name)
    }

    fn coil_by_name(&self, name: &str) -> Option<&CoilDescription> {
        self.coils.iter().find(|coil| coil.name == name)
    }

    fn file_record_by_numbers(&self, file_number: u16, record_number: u16) -> bool {
        self.file_records.iter().any(|description| {
            description.file_number == file_number && description.record_number == record_number
        })
    }

    // Mirrors `filesystem::MachineFs::release`'s staging dispatch exactly
    // (same precedence: masked register, then plain register, then coil,
    // then file record), just reading the file's already-closed content
    // from disk instead of an in-memory write buffer.
    fn stage_one(&self, pending: &mut PendingTransaction, name: &str) {
        let path = self.directory.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            return;
        };

        let staged = if let Some(register) = self.register_by_name(name) {
            if let Some((and_mask, or_mask)) = parse_masked_register_value(&text) {
                Some(StagedValue::MaskedRegister { and_mask, or_mask })
            } else {
                parse_register_value(register.data_type, &text).map(StagedValue::Register)
            }
        } else if self.coil_by_name(name).is_some() {
            parse_coil_value(&text).map(StagedValue::Coil)
        } else if let Some((file_number, record_number)) =
            parse_file_record_name(name).filter(|&(file_number, record_number)| {
                self.file_record_by_numbers(file_number, record_number)
            })
        {
            parse_file_record_value(&text).map(|value| StagedValue::FileRecord {
                file_number,
                record_number,
                value,
            })
        } else {
            // Unknown target — FUSE would have refused to create this file
            // at all (ENOENT); the closest available parity here is to
            // remove the stray file rather than leave it sitting inert.
            let _ = fs::remove_file(&path);
            None
        };

        if let Some(staged) = staged {
            pending.stage(name, staged);
        }
    }

    // Drains whatever's staged, sends it (if non-empty) down
    // `transaction_sender` exactly like `filesystem::MachineFs::
    // commit_transaction`, then clears the real `transactions/` directory
    // of every staged file plus the `TRANSACTION_END` sentinel itself —
    // real files don't vanish on their own the way FUSE's synthetic ones
    // do once their bookkeeping is forgotten, so this has to remove them.
    fn commit(&self, pending: &mut PendingTransaction) {
        let drained = pending.drain();
        for name in drained.keys() {
            let _ = fs::remove_file(self.directory.join(name));
        }
        let _ = fs::remove_file(self.directory.join(TRANSACTION_END_NAME));
        if !drained.is_empty() {
            let _ = self
                .transaction_sender
                .send((self.machine_name.clone(), drained));
        }
    }
}

// Which of the five directly-writable directories a given inotify watch
// belongs to — `FlatfileDirectWriteWatcher::run_forever` looks this up by
// `WatchDescriptor` to know how to interpret an event's `name`.
enum DirectWriteKind {
    Register,
    Coil,
    DiscreteInput,
    InputRegister,
    FileRecord { file_number: u16 },
}

/// Watches every directly-writable directory — `holding-registers/`,
/// `coils/`, `discrete-inputs/`, `input-registers/`, and one subdirectory
/// per unique `file_number` under `file-records/` — for `IN_CLOSE_WRITE`,
/// server-only (mirrors `filesystem::MachineFs::release`'s `WriteMode::
/// Direct` dispatch). Unlike `FlatfileTransactionWatcher`, there is no
/// staging/commit ritual: each write is sent as its own implicit one-item
/// transaction the instant its file is closed, exactly like FUSE's own
/// direct-write `release()` handling.
///
/// `holding-registers/<name>` additionally respects the register's own
/// declared `AccessRight` — a `read_only` register's write is discarded
/// rather than staged, same as every other directly-writable data type
/// respects the server-only/no-wire-write-path constraints that already
/// apply to it. Kept application-level (skip staging, remove the stray
/// file) rather than real kernel-enforced file permissions, matching
/// `FlatfileTransactionWatcher`'s own "flatfile can't intercept before a
/// write completes" gap — real per-file `chmod` parity is a candidate for
/// M8 (`fuse-permissions.toml` → real `chmod`/`chown`), not solved here.
pub struct FlatfileDirectWriteWatcher {
    machine_name: String,
    holding_registers_directory: PathBuf,
    coils_directory: PathBuf,
    discrete_inputs_directory: PathBuf,
    input_registers_directory: PathBuf,
    file_records_directory: PathBuf,
    registers: Vec<RegisterDescription>,
    coils: Vec<CoilDescription>,
    discrete_inputs: Vec<DiscreteInputDescription>,
    input_registers: Vec<InputRegisterDescription>,
    file_records: Vec<FileRecordDescription>,
    transaction_sender: mpsc::Sender<(String, HashMap<String, StagedValue>)>,
}

impl FlatfileDirectWriteWatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        machine_name: String,
        holding_registers_directory: PathBuf,
        coils_directory: PathBuf,
        discrete_inputs_directory: PathBuf,
        input_registers_directory: PathBuf,
        file_records_directory: PathBuf,
        registers: Vec<RegisterDescription>,
        coils: Vec<CoilDescription>,
        discrete_inputs: Vec<DiscreteInputDescription>,
        input_registers: Vec<InputRegisterDescription>,
        file_records: Vec<FileRecordDescription>,
        transaction_sender: mpsc::Sender<(String, HashMap<String, StagedValue>)>,
    ) -> Self {
        Self {
            machine_name,
            holding_registers_directory,
            coils_directory,
            discrete_inputs_directory,
            input_registers_directory,
            file_records_directory,
            registers,
            coils,
            discrete_inputs,
            input_registers,
            file_records,
            transaction_sender,
        }
    }

    // First-seen order, deduplicated — same precedent as
    // `FlatfileFileRecordRenderer::unique_file_numbers`.
    fn unique_file_numbers(&self) -> Vec<u16> {
        let mut seen = Vec::new();
        for description in &self.file_records {
            if !seen.contains(&description.file_number) {
                seen.push(description.file_number);
            }
        }
        seen
    }

    /// Blocks the calling thread forever, watching every directly-writable
    /// directory. Returns only if setting up or reading the inotify watch
    /// itself fails — a caller is expected to run this on its own dedicated
    /// thread.
    pub fn run_forever(&self) -> io::Result<()> {
        let mut inotify = Inotify::init()?;
        let mut watch_kinds: HashMap<WatchDescriptor, DirectWriteKind> = HashMap::new();
        let mut watches = inotify.watches();
        watch_kinds.insert(
            watches.add(&self.holding_registers_directory, WatchMask::CLOSE_WRITE)?,
            DirectWriteKind::Register,
        );
        watch_kinds.insert(
            watches.add(&self.coils_directory, WatchMask::CLOSE_WRITE)?,
            DirectWriteKind::Coil,
        );
        watch_kinds.insert(
            watches.add(&self.discrete_inputs_directory, WatchMask::CLOSE_WRITE)?,
            DirectWriteKind::DiscreteInput,
        );
        watch_kinds.insert(
            watches.add(&self.input_registers_directory, WatchMask::CLOSE_WRITE)?,
            DirectWriteKind::InputRegister,
        );
        for file_number in self.unique_file_numbers() {
            let path = self.file_records_directory.join(file_number.to_string());
            watch_kinds.insert(
                watches.add(&path, WatchMask::CLOSE_WRITE)?,
                DirectWriteKind::FileRecord { file_number },
            );
        }

        let mut buffer = [0u8; 4096];
        loop {
            let events = inotify.read_events_blocking(&mut buffer)?;
            for event in events {
                if !event.mask.contains(EventMask::CLOSE_WRITE) {
                    continue;
                }
                let Some(kind) = watch_kinds.get(&event.wd) else {
                    continue;
                };
                let Some(name) = event.name.and_then(|name| name.to_str()) else {
                    continue;
                };
                self.handle_write(kind, name);
            }
        }
    }

    fn handle_write(&self, kind: &DirectWriteKind, name: &str) {
        match kind {
            DirectWriteKind::Register => {
                self.handle_register_write(name);
            }
            DirectWriteKind::Coil => {
                self.handle_simple_write(
                    &self.coils_directory,
                    name,
                    self.coils.iter().any(|coil| coil.name == name),
                    StagedValue::Coil,
                );
            }
            DirectWriteKind::DiscreteInput => {
                self.handle_simple_write(
                    &self.discrete_inputs_directory,
                    name,
                    self.discrete_inputs
                        .iter()
                        .any(|discrete_input| discrete_input.name == name),
                    StagedValue::DiscreteInput,
                );
            }
            DirectWriteKind::InputRegister => {
                self.handle_input_register_write(name);
            }
            DirectWriteKind::FileRecord { file_number } => {
                self.handle_file_record_write(*file_number, name);
            }
        }
    }

    fn handle_register_write(&self, name: &str) {
        let path = self.holding_registers_directory.join(name);
        let Some(register) = self.registers.iter().find(|register| register.name == name) else {
            let _ = fs::remove_file(&path);
            return;
        };
        if register.access != AccessRight::ReadWrite {
            let _ = fs::remove_file(&path);
            return;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            return;
        };
        if let Some(value) = parse_register_value(register.data_type, &text) {
            self.send(name.to_string(), StagedValue::Register(value));
        }
    }

    fn handle_input_register_write(&self, name: &str) {
        let path = self.input_registers_directory.join(name);
        let Some(input_register) = self
            .input_registers
            .iter()
            .find(|input_register| input_register.name == name)
        else {
            let _ = fs::remove_file(&path);
            return;
        };
        let Ok(text) = fs::read_to_string(&path) else {
            return;
        };
        if let Some(value) = parse_register_value(input_register.data_type, &text) {
            self.send(name.to_string(), StagedValue::InputRegister(value));
        }
    }

    // Shared by `coils/` and `discrete-inputs/`: both are plain 0/1 values
    // with no per-entry access concept, only the target `StagedValue`
    // variant differs.
    fn handle_simple_write(
        &self,
        directory: &Path,
        name: &str,
        is_known_target: bool,
        wrap: impl Fn(CoilValue) -> StagedValue,
    ) {
        let path = directory.join(name);
        if !is_known_target {
            let _ = fs::remove_file(&path);
            return;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            return;
        };
        if let Some(value) = parse_coil_value(&text) {
            self.send(name.to_string(), wrap(value));
        }
    }

    fn handle_file_record_write(&self, file_number: u16, name: &str) {
        let path = self
            .file_records_directory
            .join(file_number.to_string())
            .join(name);
        let Ok(record_number) = name.parse::<u16>() else {
            let _ = fs::remove_file(&path);
            return;
        };
        let is_known_target = self.file_records.iter().any(|description| {
            description.file_number == file_number && description.record_number == record_number
        });
        if !is_known_target {
            let _ = fs::remove_file(&path);
            return;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            return;
        };
        if let Some(value) = parse_file_record_value(&text) {
            self.send(
                format!("{file_number}:{record_number}"),
                StagedValue::FileRecord {
                    file_number,
                    record_number,
                    value,
                },
            );
        }
    }

    fn send(&self, name: String, value: StagedValue) {
        let _ = self
            .transaction_sender
            .send((self.machine_name.clone(), HashMap::from([(name, value)])));
    }
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

    // Spawns `watcher.run_forever()` on its own thread and gives the
    // inotify watch a moment to actually be registered before the caller
    // starts writing files — inotify only reports events that happen after
    // `watches().add(...)` returns, so a test that writes immediately could
    // race the watch's own setup.
    fn spawn_watcher(watcher: Arc<FlatfileTransactionWatcher>) {
        watcher.initialize().unwrap();
        std::thread::spawn(move || {
            let _ = watcher.run_forever();
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    #[test]
    fn staging_a_register_then_committing_sends_the_transaction() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("transactions");
        let (sender, receiver) = mpsc::channel();
        let watcher = Arc::new(FlatfileTransactionWatcher::new(
            "PumpA".to_string(),
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            vec![],
            vec![],
            sender,
        ));
        spawn_watcher(watcher);

        fs::write(directory.join("Tank_Temperature"), "42").unwrap();
        fs::write(directory.join("TRANSACTION_END"), "").unwrap();

        let (machine_name, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(machine_name, "PumpA");
        assert_eq!(
            transaction.get("Tank_Temperature"),
            Some(&StagedValue::Register(RegisterValue::U16(42)))
        );
    }

    #[test]
    fn commit_clears_every_staged_file_and_the_sentinel() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("transactions");
        let (sender, receiver) = mpsc::channel();
        let watcher = Arc::new(FlatfileTransactionWatcher::new(
            "PumpA".to_string(),
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            vec![],
            vec![],
            sender,
        ));
        spawn_watcher(watcher);

        fs::write(directory.join("Tank_Temperature"), "42").unwrap();
        fs::write(directory.join("TRANSACTION_END"), "").unwrap();
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let entries: Vec<String> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            entries.is_empty(),
            "expected an empty directory, got {entries:?}"
        );
    }

    #[test]
    fn staging_a_coil_uses_zero_one_parsing() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("transactions");
        let (sender, receiver) = mpsc::channel();
        let watcher = Arc::new(FlatfileTransactionWatcher::new(
            "PumpA".to_string(),
            directory.clone(),
            vec![],
            vec![a_coil("Motor_Running")],
            vec![],
            sender,
        ));
        spawn_watcher(watcher);

        fs::write(directory.join("Motor_Running"), "1").unwrap();
        fs::write(directory.join("TRANSACTION_END"), "").unwrap();

        let (_, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            transaction.get("Motor_Running"),
            Some(&StagedValue::Coil(CoilValue(true)))
        );
    }

    #[test]
    fn staging_a_mask_write_on_a_register_name_produces_a_masked_register() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("transactions");
        let (sender, receiver) = mpsc::channel();
        let watcher = Arc::new(FlatfileTransactionWatcher::new(
            "PumpA".to_string(),
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            vec![],
            vec![],
            sender,
        ));
        spawn_watcher(watcher);

        fs::write(directory.join("Tank_Temperature"), "MASK 0x00F2 0x0025").unwrap();
        fs::write(directory.join("TRANSACTION_END"), "").unwrap();

        let (_, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            transaction.get("Tank_Temperature"),
            Some(&StagedValue::MaskedRegister {
                and_mask: 0x00F2,
                or_mask: 0x0025
            })
        );
    }

    #[test]
    fn staging_a_known_file_record_by_colon_name() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("transactions");
        let (sender, receiver) = mpsc::channel();
        let watcher = Arc::new(FlatfileTransactionWatcher::new(
            "PumpA".to_string(),
            directory.clone(),
            vec![],
            vec![],
            vec![FileRecordDescription {
                file_number: 4,
                record_number: 1,
                record_length: 2,
            }],
            sender,
        ));
        spawn_watcher(watcher);

        fs::write(directory.join("4:1"), "0D FE 00 20").unwrap();
        fs::write(directory.join("TRANSACTION_END"), "").unwrap();

        let (_, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            transaction.get("4:1"),
            Some(&StagedValue::FileRecord {
                file_number: 4,
                record_number: 1,
                value: vec![0x0D, 0xFE, 0x00, 0x20],
            })
        );
    }

    #[test]
    fn staging_an_unknown_target_removes_the_stray_file() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("transactions");
        let (sender, _receiver) = mpsc::channel();
        let watcher = Arc::new(FlatfileTransactionWatcher::new(
            "PumpA".to_string(),
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            vec![],
            vec![],
            sender,
        ));
        spawn_watcher(watcher);

        fs::write(directory.join("Nonexistent_Register"), "1").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));

        assert!(!directory.join("Nonexistent_Register").exists());
    }

    #[test]
    fn committing_with_nothing_staged_sends_nothing() {
        let temporary_directory = tempfile::tempdir().unwrap();
        let directory = temporary_directory.path().join("transactions");
        let (sender, receiver) = mpsc::channel();
        let watcher = Arc::new(FlatfileTransactionWatcher::new(
            "PumpA".to_string(),
            directory.clone(),
            vec![a_register("Tank_Temperature")],
            vec![],
            vec![],
            sender,
        ));
        spawn_watcher(watcher);

        fs::write(directory.join("TRANSACTION_END"), "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));

        assert!(receiver.try_recv().is_err());
    }

    struct DirectWriteDirs {
        holding_registers: PathBuf,
        coils: PathBuf,
        discrete_inputs: PathBuf,
        input_registers: PathBuf,
        file_records: PathBuf,
    }

    #[allow(clippy::type_complexity)]
    fn spawn_direct_write_watcher(
        registers: Vec<RegisterDescription>,
        coils: Vec<CoilDescription>,
        discrete_inputs: Vec<DiscreteInputDescription>,
        input_registers: Vec<InputRegisterDescription>,
        file_records: Vec<FileRecordDescription>,
    ) -> (
        tempfile::TempDir,
        DirectWriteDirs,
        mpsc::Receiver<(String, HashMap<String, StagedValue>)>,
    ) {
        let temporary_directory = tempfile::tempdir().unwrap();
        let dirs = DirectWriteDirs {
            holding_registers: temporary_directory.path().join("holding-registers"),
            coils: temporary_directory.path().join("coils"),
            discrete_inputs: temporary_directory.path().join("discrete-inputs"),
            input_registers: temporary_directory.path().join("input-registers"),
            file_records: temporary_directory.path().join("file-records"),
        };
        fs::create_dir_all(&dirs.holding_registers).unwrap();
        fs::create_dir_all(&dirs.coils).unwrap();
        fs::create_dir_all(&dirs.discrete_inputs).unwrap();
        fs::create_dir_all(&dirs.input_registers).unwrap();
        fs::create_dir_all(&dirs.file_records).unwrap();
        for file_record in &file_records {
            fs::create_dir_all(dirs.file_records.join(file_record.file_number.to_string()))
                .unwrap();
        }

        let (sender, receiver) = mpsc::channel();
        let watcher = Arc::new(FlatfileDirectWriteWatcher::new(
            "PumpA".to_string(),
            dirs.holding_registers.clone(),
            dirs.coils.clone(),
            dirs.discrete_inputs.clone(),
            dirs.input_registers.clone(),
            dirs.file_records.clone(),
            registers,
            coils,
            discrete_inputs,
            input_registers,
            file_records,
            sender,
        ));
        {
            let watcher = watcher.clone();
            std::thread::spawn(move || {
                let _ = watcher.run_forever();
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(100));

        (temporary_directory, dirs, receiver)
    }

    #[test]
    fn direct_write_to_a_register_sends_immediately_without_transaction_end() {
        let mut register = a_register("Tank_Temperature");
        register.access = AccessRight::ReadWrite;
        let (_temporary_directory, dirs, receiver) =
            spawn_direct_write_watcher(vec![register], vec![], vec![], vec![], vec![]);

        fs::write(dirs.holding_registers.join("Tank_Temperature"), "42").unwrap();

        let (machine_name, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(machine_name, "PumpA");
        assert_eq!(
            transaction.get("Tank_Temperature"),
            Some(&StagedValue::Register(RegisterValue::U16(42)))
        );
    }

    #[test]
    fn direct_write_to_a_read_only_register_is_discarded_and_the_file_removed() {
        let mut register = a_register("Tank_Temperature");
        register.access = AccessRight::ReadOnly;
        let (_temporary_directory, dirs, receiver) =
            spawn_direct_write_watcher(vec![register], vec![], vec![], vec![], vec![]);

        fs::write(dirs.holding_registers.join("Tank_Temperature"), "42").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));

        assert!(receiver.try_recv().is_err());
        assert!(!dirs.holding_registers.join("Tank_Temperature").exists());
    }

    #[test]
    fn direct_write_to_a_coil_sends_immediately() {
        let (_temporary_directory, dirs, receiver) = spawn_direct_write_watcher(
            vec![],
            vec![a_coil("Motor_Running")],
            vec![],
            vec![],
            vec![],
        );

        fs::write(dirs.coils.join("Motor_Running"), "1").unwrap();

        let (_, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            transaction.get("Motor_Running"),
            Some(&StagedValue::Coil(CoilValue(true)))
        );
    }

    #[test]
    fn direct_write_to_a_discrete_input_sends_immediately() {
        let (_temporary_directory, dirs, receiver) = spawn_direct_write_watcher(
            vec![],
            vec![],
            vec![a_discrete_input("Door_Open_Sensor")],
            vec![],
            vec![],
        );

        fs::write(dirs.discrete_inputs.join("Door_Open_Sensor"), "1").unwrap();

        let (_, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            transaction.get("Door_Open_Sensor"),
            Some(&StagedValue::DiscreteInput(CoilValue(true)))
        );
    }

    #[test]
    fn direct_write_to_an_input_register_sends_immediately() {
        let (_temporary_directory, dirs, receiver) = spawn_direct_write_watcher(
            vec![],
            vec![],
            vec![],
            vec![an_input_register("Flow_Rate")],
            vec![],
        );

        fs::write(dirs.input_registers.join("Flow_Rate"), "7").unwrap();

        let (_, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            transaction.get("Flow_Rate"),
            Some(&StagedValue::InputRegister(RegisterValue::U16(7)))
        );
    }

    #[test]
    fn direct_write_to_a_known_file_record_sends_immediately() {
        let (_temporary_directory, dirs, receiver) = spawn_direct_write_watcher(
            vec![],
            vec![],
            vec![],
            vec![],
            vec![FileRecordDescription {
                file_number: 4,
                record_number: 1,
                record_length: 2,
            }],
        );

        fs::write(dirs.file_records.join("4").join("1"), "0D FE 00 20").unwrap();

        let (_, transaction) = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            transaction.get("4:1"),
            Some(&StagedValue::FileRecord {
                file_number: 4,
                record_number: 1,
                value: vec![0x0D, 0xFE, 0x00, 0x20],
            })
        );
    }

    #[test]
    fn direct_write_to_an_unknown_register_name_removes_the_stray_file() {
        let (_temporary_directory, dirs, receiver) = spawn_direct_write_watcher(
            vec![a_register("Tank_Temperature")],
            vec![],
            vec![],
            vec![],
            vec![],
        );

        fs::write(dirs.holding_registers.join("Nonexistent"), "1").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));

        assert!(receiver.try_recv().is_err());
        assert!(!dirs.holding_registers.join("Nonexistent").exists());
    }
}
