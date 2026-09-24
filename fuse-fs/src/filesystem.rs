use crate::client_trust::ClientTrustState;
use crate::permissions::{DirectoryPermissions, FusePermissions};
use crate::{
    CoilStore, CoilValue, DiscreteInputStore, FileRecordStore, InputRegisterStore,
    PendingTransaction, RegisterStore, RegisterValue, StagedValue, WriteReport,
};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyWrite, Request,
    TimeOrNow,
};
use protocol::device_description::{
    CoilDescription, DataType, DiscreteInputDescription, FileRecordDescription,
    InputRegisterDescription, RegisterDescription,
};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

/// Distinguishes the two roles `InfusedFilesystem` is shared between — see
/// CLAUDE.md's "server direct-write model" section. The client has no
/// authoritative state of its own: a write must round-trip to a real
/// device, which can fail, so it stages writes via `transactions/`+
/// `TRANSACTION_END` and confirms them asynchronously. The server's own
/// state *is* authoritative, so it (once wired up — this variant alone
/// changes no behavior yet) writes directly into `holding-registers/`/
/// `coils/` instead, with no staging step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    Staged,
    Direct,
}

const ROOT_INO: INodeNo = INodeNo(1);
const HOLDING_REGISTERS_INO: INodeNo = INodeNo(2);
const FIRST_REGISTER_INO: u64 = 3;

// The sentinel name that triggers a transaction commit (see CLAUDE.md's
// "TRANSACTION_END confirmation semantics"). Not a register name, so it's
// checked before the "must be a real register" guard in `create`.
const TRANSACTION_END_NAME: &str = "TRANSACTION_END";

// How long the kernel may cache an entry/attr reply before asking again.
// Register values can change between our own reads (a real device is polled
// independently), so this is kept short rather than the usual much longer
// default.
const ATTR_TTL: Duration = Duration::from_secs(1);

// U24/I24 are stored in the next-larger native integer (u32/i32 — see
// RegisterValue's own doc comment) but must still be kept within the real
// 24-bit range, since nothing else validates that later. I24's range is the
// standard two's-complement 24-bit one: -2^23..=2^23-1.
const U24_MAX: u32 = 0x00FF_FFFF;
const I24_MIN: i32 = -0x0080_0000;
const I24_MAX: i32 = 0x007F_FFFF;

// Parses `text` as either a `0x`/`0X`-prefixed hex literal or a plain
// decimal one. Shared by every unsigned-integer DataType's text parsing in
// `parse_register_value` below — the identical hex-or-decimal shape showed
// up for U8/U16/U32/U64 (and U24's underlying u32) all at once while adding
// the new DataType variants, so it was extracted immediately rather than
// left duplicated across all of them (per this project's
// extraction-based-programming convention: recognized pattern, refactor
// right away).
fn parse_hex_or_decimal<T>(
    text: &str,
    from_hex: impl FnOnce(&str) -> Result<T, std::num::ParseIntError>,
    from_decimal: impl FnOnce(&str) -> Result<T, std::num::ParseIntError>,
) -> Option<T> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => from_hex(hex).ok(),
        None => from_decimal(text).ok(),
    }
}

// Bookkeeping for `transactions/`'s dynamic children — unlike
// `holding-registers/`'s register files (fixed set, known at construction
// time), these are created and removed by the user at runtime, so inode
// numbers have to be handed out on the fly. `buffers` accumulates each open
// file's written bytes until `release` parses them into a RegisterValue and
// stages it (see the `release` doc comment for why parsing happens there,
// not in `write`).
#[derive(Debug, Default)]
struct TransactionFsState {
    pending: PendingTransaction,
    name_to_ino: HashMap<String, INodeNo>,
    ino_to_name: HashMap<INodeNo, String>,
    buffers: HashMap<INodeNo, Vec<u8>>,
    next_ino: u64,
    // Inodes handed back by TRANSACTION_END `create()` calls that haven't
    // had their matching setattr() follow-up yet. Deliberately untracked
    // everywhere else (see `create`), but tools like `touch` immediately
    // follow their create() with a setattr(times) call on the same inode as
    // one logical operation — see `setattr`'s doc comment for why that one
    // follow-up call still needs to succeed. A set rather than a single
    // `Option` because two concurrent `touch transactions/TRANSACTION_END`
    // calls interleave their create()/setattr() pairs across FUSE's worker
    // threads — a single most-recent-inode field would let the second
    // create() overwrite the first's entry before its setattr() arrives,
    // wrongly reporting ENOENT for a commit that actually succeeded.
    last_transaction_end_inos: HashSet<INodeNo>,
}

/// A minimal FUSE projection: root -> `holding-registers` -> one read-only
/// file per register (current value from `store`), root -> `transactions`
/// -> user-created files that stage a pending write per the scheme in
/// CLAUDE.md (filename = register name, content = value to write), and
/// root -> `report` -> one read-only file per register showing the outcome
/// of its most recent write attempt (Milestone H3; content = `WriteReport`,
/// overwritten on every new attempt, no history). Creating `TRANSACTION_END`
/// drains the staged values and hands them off over `transaction_sender` —
/// this layer has no Modbus knowledge, so it cannot itself confirm a write
/// reached the device; `store` (and so `holding-registers/`) is
/// deliberately **not** touched here, and neither is `report` — both are
/// only ever updated by whoever owns the receiving end of
/// `transaction_sender`, once the real write is confirmed or fails (see
/// CLAUDE.md's "TRANSACTION_END confirmation semantics").
pub struct InfusedFilesystem {
    registers: Vec<RegisterDescription>,
    name_to_ino: HashMap<String, INodeNo>,
    store: Arc<Mutex<RegisterStore>>,
    coils: Vec<CoilDescription>,
    coil_name_to_ino: HashMap<String, INodeNo>,
    coil_store: Arc<Mutex<CoilStore>>,
    coils_ino: INodeNo,
    // Discrete inputs (FC 2) / input registers (FC 4): read-only on both
    // client and server today (no `create`/`write` wiring — see CLAUDE.md's
    // "read-only Modbus data types" section), so unlike `transactions_ino`
    // these fixed directories have no dynamic/writable counterpart yet.
    discrete_inputs: Vec<DiscreteInputDescription>,
    discrete_input_name_to_ino: HashMap<String, INodeNo>,
    discrete_input_store: Arc<Mutex<DiscreteInputStore>>,
    discrete_inputs_ino: INodeNo,
    input_registers: Vec<InputRegisterDescription>,
    input_register_name_to_ino: HashMap<String, INodeNo>,
    input_register_store: Arc<Mutex<InputRegisterStore>>,
    input_registers_ino: INodeNo,
    transactions_ino: INodeNo,
    transactions: Mutex<TransactionFsState>,
    transaction_sender: mpsc::Sender<HashMap<String, StagedValue>>,
    report_ino: INodeNo,
    report: Arc<Mutex<WriteReport>>,
    // Only `Some` on the server — see `ClientTrustState`'s own doc comment
    // for why this is the one asymmetric piece of state in this struct.
    client_trust: Option<Arc<Mutex<ClientTrustState>>>,
    client_trust_ino: INodeNo,
    client_trust_approved_ino: INodeNo,
    connection_attempts_ino: INodeNo,
    approved_log_ino: INodeNo,
    pending_log_ino: INodeNo,
    rejected_log_ino: INodeNo,
    // Client-only (see CLAUDE.md's "FC 0x11 (Report Server ID)" section) —
    // the server answers real FC11 requests with its own device
    // description's `server_id` directly in `server::handler`, but never
    // exposes it through this FUSE tree at all, so `server` always passes
    // `None` here regardless of what its own TOML has configured. Mirrors
    // whatever ended up in the client's own effective device description
    // (local file or FC43-fetched), read-only, static for the process's
    // whole lifetime — unlike every other content-bearing field in this
    // struct, never touched again after construction.
    server_id: Option<String>,
    server_id_ino: INodeNo,
    // `file-records/<file_number>/<record_number>` — see CLAUDE.md's "FC
    // 0x14 (Read File Record)" section. Unlike every other data type in
    // this filesystem, this one needs a second nesting level: a
    // `file_number` can hold several `record_number`s, so
    // `file-records/`'s own children are dynamically-named-but-statically-
    // known subdirectories (one per unique `file_number` in `file_records`,
    // in first-seen order — `unique_file_numbers`/`file_number_to_ino`
    // resolve a directory name to its inode), each containing the record
    // files for that file number. Read-only on the client, directly
    // writable on the server (WriteMode::Direct) exactly like
    // holding-registers/coils/discrete-inputs/input-registers — but with
    // no `report/` coverage, same precedent as discrete-inputs/
    // input-registers (H3 stayed scoped to registers/coils; a direct
    // write's own write()/release() return code is the only failure
    // signal needed here too).
    file_records: Vec<FileRecordDescription>,
    file_record_store: Arc<Mutex<FileRecordStore>>,
    file_records_ino: INodeNo,
    unique_file_numbers: Vec<u16>,
    file_number_to_ino: HashMap<u16, INodeNo>,
    // Per-top-level-directory mode/uid/gid from `fuse-permissions.toml`
    // (see `permissions_for`) — deliberately does not cover `client-trust/`
    // at all (T3 hardcodes that subtree's attrs regardless of this field).
    permissions: FusePermissions,
    // See `WriteMode`'s own doc comment — governs whether
    // `holding-registers/`/`coils/` files are directly writable.
    write_mode: WriteMode,
}

impl InfusedFilesystem {
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registers: Vec<RegisterDescription>,
        coils: Vec<CoilDescription>,
        discrete_inputs: Vec<DiscreteInputDescription>,
        input_registers: Vec<InputRegisterDescription>,
        file_records: Vec<FileRecordDescription>,
        store: Arc<Mutex<RegisterStore>>,
        coil_store: Arc<Mutex<CoilStore>>,
        discrete_input_store: Arc<Mutex<DiscreteInputStore>>,
        input_register_store: Arc<Mutex<InputRegisterStore>>,
        file_record_store: Arc<Mutex<FileRecordStore>>,
        transaction_sender: mpsc::Sender<HashMap<String, StagedValue>>,
        report: Arc<Mutex<WriteReport>>,
        client_trust: Option<Arc<Mutex<ClientTrustState>>>,
        permissions: FusePermissions,
        write_mode: WriteMode,
        server_id: Option<String>,
    ) -> Self {
        let name_to_ino = registers
            .iter()
            .enumerate()
            .map(|(index, register)| {
                (
                    register.name.clone(),
                    INodeNo(FIRST_REGISTER_INO + index as u64),
                )
            })
            .collect();
        let coils_ino = INodeNo(FIRST_REGISTER_INO + registers.len() as u64);
        let first_coil_ino = coils_ino.0 + 1;
        let coil_name_to_ino = coils
            .iter()
            .enumerate()
            .map(|(index, coil)| (coil.name.clone(), INodeNo(first_coil_ino + index as u64)))
            .collect();
        let discrete_inputs_ino = INodeNo(first_coil_ino + coils.len() as u64);
        let first_discrete_input_ino = discrete_inputs_ino.0 + 1;
        let discrete_input_name_to_ino = discrete_inputs
            .iter()
            .enumerate()
            .map(|(index, discrete_input)| {
                (
                    discrete_input.name.clone(),
                    INodeNo(first_discrete_input_ino + index as u64),
                )
            })
            .collect();
        let input_registers_ino = INodeNo(first_discrete_input_ino + discrete_inputs.len() as u64);
        let first_input_register_ino = input_registers_ino.0 + 1;
        let input_register_name_to_ino = input_registers
            .iter()
            .enumerate()
            .map(|(index, input_register)| {
                (
                    input_register.name.clone(),
                    INodeNo(first_input_register_ino + index as u64),
                )
            })
            .collect();
        let transactions_ino = INodeNo(first_input_register_ino + input_registers.len() as u64);
        let report_ino = INodeNo(transactions_ino.0 + 1);
        let first_report_ino = report_ino.0 + 1;
        // report/'s coil files sit right after its register files — see
        // `first_coil_report_ino`.
        let transactions = Mutex::new(TransactionFsState {
            next_ino: first_report_ino + registers.len() as u64 + coils.len() as u64,
            ..Default::default()
        });
        // client-trust/'s two fixed directory inodes sit right after every
        // other fixed inode this filesystem hands out — computed the same
        // way regardless of whether `client_trust` is `Some` (client-side
        // `None` just never exposes them), so the numbering stays
        // deterministic and independent of which fields happen to be used.
        let client_trust_ino =
            INodeNo(first_report_ino + registers.len() as u64 + coils.len() as u64);
        let client_trust_approved_ino = INodeNo(client_trust_ino.0 + 1);
        // connection_attempts/'s directory + its three fixed log files sit
        // right after approved/ — fixed like report_ino/coils_ino (always
        // exactly three files), unlike approved/'s dynamic per-fingerprint
        // entries, so no next_ino calibration needed for these.
        let connection_attempts_ino = INodeNo(client_trust_approved_ino.0 + 1);
        let approved_log_ino = INodeNo(connection_attempts_ino.0 + 1);
        let pending_log_ino = INodeNo(approved_log_ino.0 + 1);
        let rejected_log_ino = INodeNo(pending_log_ino.0 + 1);
        // Always computed, same "always allocate the inode, only
        // conditionally expose the name" precedent as client_trust_ino —
        // keeps every fixed inode's number independent of which optional
        // features happen to be in use.
        let server_id_ino = INodeNo(rejected_log_ino.0 + 1);
        // file-records/ needs two nesting levels: one inode for the
        // file-records/ root, then one per *unique* file_number (in
        // first-seen order — `unique_file_numbers`), then one per
        // FileRecordDescription entry itself (in `file_records` order,
        // mirroring how every other data type's file inodes sit
        // contiguously after their own directory inode).
        let file_records_ino = INodeNo(server_id_ino.0 + 1);
        let mut unique_file_numbers: Vec<u16> = Vec::new();
        for entry in &file_records {
            if !unique_file_numbers.contains(&entry.file_number) {
                unique_file_numbers.push(entry.file_number);
            }
        }
        let first_file_number_ino = file_records_ino.0 + 1;
        let file_number_to_ino: HashMap<u16, INodeNo> = unique_file_numbers
            .iter()
            .enumerate()
            .map(|(index, &file_number)| {
                (file_number, INodeNo(first_file_number_ino + index as u64))
            })
            .collect();
        let first_file_record_ino = first_file_number_ino + unique_file_numbers.len() as u64;
        // Unlike server_id_ino (mutually exclusive with client_trust in
        // practice — server_id is client-only, client_trust is
        // server-only), file-records/ genuinely coexists with client_trust
        // on the server, so client_trust's own dynamic `approved/`
        // allocator must start strictly after every fixed inode this
        // filesystem hands out, file-records included — not just after
        // rejected_log_ino/server_id_ino like before file-records existed.
        if let Some(client_trust) = &client_trust {
            client_trust
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .set_next_ino(first_file_record_ino + file_records.len() as u64);
        }
        Self {
            registers,
            name_to_ino,
            store,
            coils,
            coil_name_to_ino,
            coil_store,
            coils_ino,
            discrete_inputs,
            discrete_input_name_to_ino,
            discrete_input_store,
            discrete_inputs_ino,
            input_registers,
            input_register_name_to_ino,
            input_register_store,
            input_registers_ino,
            transactions_ino,
            transactions,
            transaction_sender,
            report_ino,
            report,
            client_trust,
            client_trust_ino,
            client_trust_approved_ino,
            connection_attempts_ino,
            approved_log_ino,
            pending_log_ino,
            rejected_log_ino,
            permissions,
            write_mode,
            server_id,
            server_id_ino,
            file_records,
            file_record_store,
            file_records_ino,
            unique_file_numbers,
            file_number_to_ino,
        }
    }

    // A poisoned lock (a prior panic while holding it) shouldn't take down
    // every future filesystem call with it — recovering the guard is safe
    // here since a panic mid-mutation would at worst leave stale/partial
    // bookkeeping, not memory unsafety.
    fn transactions_lock(&self) -> MutexGuard<'_, TransactionFsState> {
        self.transactions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn store_lock(&self) -> MutexGuard<'_, RegisterStore> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn coil_store_lock(&self) -> MutexGuard<'_, CoilStore> {
        self.coil_store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn discrete_input_store_lock(&self) -> MutexGuard<'_, DiscreteInputStore> {
        self.discrete_input_store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn input_register_store_lock(&self) -> MutexGuard<'_, InputRegisterStore> {
        self.input_register_store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn file_record_store_lock(&self) -> MutexGuard<'_, FileRecordStore> {
        self.file_record_store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn report_lock(&self) -> MutexGuard<'_, WriteReport> {
        self.report.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // `None` on the client (see `ClientTrustState`'s doc comment) — callers
    // must handle that case themselves; there is no sensible "empty lock"
    // to hand back.
    fn client_trust_lock(&self) -> Option<MutexGuard<'_, ClientTrustState>> {
        self.client_trust
            .as_ref()
            .map(|client_trust| client_trust.lock().unwrap_or_else(PoisonError::into_inner))
    }

    // Dispatches one of the three fixed connection_attempts/*.log inodes to
    // its ring buffer's current content. Any other ino (including when
    // client_trust is None) returns empty — callers are expected to have
    // already confirmed `ino` is one of the three via their own match, same
    // convention as every other *_content helper in this file.
    fn connection_attempts_log_content(&self, ino: INodeNo) -> String {
        let Some(state) = self.client_trust_lock() else {
            return String::new();
        };
        if ino == self.approved_log_ino {
            state.approved_log_content()
        } else if ino == self.pending_log_ino {
            state.pending_log_content()
        } else if ino == self.rejected_log_ino {
            state.rejected_log_content()
        } else {
            String::new()
        }
    }

    // Callers are expected to have already confirmed `server_id.is_some()`,
    // same convention as `connection_attempts_log_content` — this just
    // formats what's there.
    fn server_id_content(&self) -> String {
        match &self.server_id {
            Some(server_id) => format!("{server_id}\n"),
            None => String::new(),
        }
    }

    // report/'s file inodes sit right after the fixed report/ directory
    // inode itself — see `new`, where `report_ino` is computed the same way
    // relative to `transactions_ino`.
    fn first_report_ino(&self) -> u64 {
        self.report_ino.0 + 1
    }

    fn register_by_ino(&self, ino: INodeNo) -> Option<&RegisterDescription> {
        let index = ino.0.checked_sub(FIRST_REGISTER_INO)?;
        self.registers.get(index as usize)
    }

    // coils/'s file inodes sit right after the fixed coils/ directory inode
    // itself — see `new`, where `coils_ino` is computed the same way
    // `transactions_ino`/`report_ino` already were.
    fn first_coil_ino(&self) -> u64 {
        self.coils_ino.0 + 1
    }

    fn coil_by_ino(&self, ino: INodeNo) -> Option<&CoilDescription> {
        let index = ino.0.checked_sub(self.first_coil_ino())?;
        self.coils.get(index as usize)
    }

    // discrete-inputs/'s file inodes sit right after the fixed
    // discrete-inputs/ directory inode itself — same pattern as
    // `first_coil_ino`.
    fn first_discrete_input_ino(&self) -> u64 {
        self.discrete_inputs_ino.0 + 1
    }

    fn discrete_input_by_ino(&self, ino: INodeNo) -> Option<&DiscreteInputDescription> {
        let index = ino.0.checked_sub(self.first_discrete_input_ino())?;
        self.discrete_inputs.get(index as usize)
    }

    // input-registers/'s file inodes sit right after the fixed
    // input-registers/ directory inode itself — same pattern as
    // `first_coil_ino`.
    fn first_input_register_ino(&self) -> u64 {
        self.input_registers_ino.0 + 1
    }

    fn input_register_by_ino(&self, ino: INodeNo) -> Option<&InputRegisterDescription> {
        let index = ino.0.checked_sub(self.first_input_register_ino())?;
        self.input_registers.get(index as usize)
    }

    // file-records/<file_number>/'s own directory inodes sit right after
    // the fixed file-records/ directory inode itself — same pattern as
    // `first_coil_ino`, just one more level up the tree.
    fn first_file_number_ino(&self) -> u64 {
        self.file_records_ino.0 + 1
    }

    // Resolves a `file-records/<file_number>` directory inode back to the
    // file_number it represents — the reverse of `file_number_to_ino`,
    // same arithmetic-index pattern as every other `*_by_ino` helper here.
    fn file_number_by_ino(&self, ino: INodeNo) -> Option<u16> {
        let index = ino.0.checked_sub(self.first_file_number_ino())?;
        self.unique_file_numbers.get(index as usize).copied()
    }

    // file-records/<file_number>/<record_number>'s own file inodes sit
    // right after every file_number subdirectory inode.
    fn first_file_record_ino(&self) -> u64 {
        self.first_file_number_ino() + self.unique_file_numbers.len() as u64
    }

    fn file_record_by_ino(&self, ino: INodeNo) -> Option<&FileRecordDescription> {
        let index = ino.0.checked_sub(self.first_file_record_ino())?;
        self.file_records.get(index as usize)
    }

    // Forward lookup for `file-records/<file_number>/<record_number>`'s
    // `lookup()`: given the file_number already resolved from the parent
    // directory's own inode, find the matching entry (linear scan — no
    // dedicated HashMap, since the compound (file_number, record_number)
    // key needs the file_number as context anyway, and entry counts here
    // are small).
    fn file_record_by_numbers(
        &self,
        file_number: u16,
        record_number: u16,
    ) -> Option<(INodeNo, &FileRecordDescription)> {
        let index = self.file_records.iter().position(|description| {
            description.file_number == file_number && description.record_number == record_number
        })?;
        Some((
            INodeNo(self.first_file_record_ino() + index as u64),
            &self.file_records[index],
        ))
    }

    fn report_register_by_ino(&self, ino: INodeNo) -> Option<&RegisterDescription> {
        let index = ino.0.checked_sub(self.first_report_ino())?;
        self.registers.get(index as usize)
    }

    // report/'s coil files sit right after its register files — see `new`.
    fn first_coil_report_ino(&self) -> u64 {
        self.first_report_ino() + self.registers.len() as u64
    }

    fn report_coil_by_ino(&self, ino: INodeNo) -> Option<&CoilDescription> {
        let index = ino.0.checked_sub(self.first_coil_report_ino())?;
        self.coils.get(index as usize)
    }

    // The `fuse-permissions.toml` permissions that apply to `ino`, if it
    // belongs to one of the 4 configurable subtrees (their own directory
    // inode, or any file inside it) — `None` for `root`/`client-trust/*`,
    // which `directory_attr`/`file_attr` fall back to their pre-T2 default
    // for (client-trust/'s own root directory gets its T3 hardcoded
    // override instead — see `client_trust_root_attr_override` — since
    // that subtree can never appear in this schema at all).
    fn permissions_for(&self, ino: INodeNo) -> Option<DirectoryPermissions> {
        if ino == HOLDING_REGISTERS_INO || self.register_by_ino(ino).is_some() {
            Some(self.permissions.holding_registers)
        } else if ino == self.coils_ino || self.coil_by_ino(ino).is_some() {
            Some(self.permissions.coils)
        } else if self.transactions_enabled()
            && (ino == self.transactions_ino || self.transaction_name_by_ino(ino).is_some())
        {
            Some(self.permissions.transactions)
        } else if ino == self.report_ino
            || self.report_register_by_ino(ino).is_some()
            || self.report_coil_by_ino(ino).is_some()
        {
            Some(self.permissions.report)
        } else {
            None
        }
    }

    // `client-trust/`'s own root directory attrs, hardcoded to maximum
    // restriction regardless of `fuse-permissions.toml` (CLAUDE.md: that
    // subtree "cannot appear in this file's schema at all"). Gating just
    // this one top directory at `0o700`/the server's own real UID+GID is
    // sufficient to lock the whole subtree down — nothing nested beneath
    // it (`approved/`, `connection_attempts/`, ...) is reachable by any
    // other uid regardless of its own reported mode/owner, since traversal
    // is blocked here first; those nested entries keep their pre-T3
    // attrs unchanged. `None` for every other ino, including client-trust's
    // own nested directories/files.
    fn client_trust_root_attr_override(&self, ino: INodeNo) -> Option<(u16, u32, u32)> {
        if self.client_trust.is_some() && ino == self.client_trust_ino {
            let (uid, gid) = crate::permissions::real_uid_and_gid();
            Some((0o700, uid, gid))
        } else {
            None
        }
    }

    // `holding-registers/`/`coils/` files are read-only on the client
    // (WriteMode::Staged — writes go through transactions/) but directly
    // writable on the server (WriteMode::Direct — see CLAUDE.md's "server
    // direct-write model"). Reported via `getattr`/`lookup` so the kernel's
    // own `default_permissions` check (which runs before `write` is ever
    // called) doesn't reject a write the FUSE layer would otherwise accept.
    // Used for coils/discrete-inputs/input-registers, none of which have a
    // TOML-declared `AccessRight` (coils are always read/write; the other
    // two have no wire write path at all, so "direct write" is the only way
    // to ever set them) — see `register_file_mode` for the register case,
    // which additionally depends on the register's own `access`.
    fn writable_data_file_mode(&self) -> u16 {
        match self.write_mode {
            WriteMode::Direct => 0o644,
            WriteMode::Staged => 0o444,
        }
    }

    // Like `writable_data_file_mode`, but for `holding-registers/<name>`
    // specifically: a register additionally carries its own TOML-declared
    // `AccessRight`, and `WriteMode::Direct` must not make a
    // `read_only`-declared register writable just because the server
    // otherwise writes directly — the wire handlers (`handle_write_single`/
    // `handle_write_multiple_registers`/FC17's write half) already enforce
    // this `access` check, so the server's own local FUSE write path has to
    // match rather than being a backdoor around it.
    fn register_file_mode(&self, register: &RegisterDescription) -> u16 {
        match (self.write_mode, register.access) {
            (WriteMode::Direct, protocol::device_description::AccessRight::ReadWrite) => 0o644,
            _ => 0o444,
        }
    }

    // Whether `ino` is a holding-register/coil/discrete-input/input-register
    // file that's directly writable in the current WriteMode — used by
    // `write`/`release`/`setattr` to accept a write to `holding-registers/
    // <name>`/`coils/<name>`/`discrete-inputs/<name>`/`input-registers/
    // <name>` alongside the existing `transactions/` staging path. `false`
    // on the client (WriteMode::Staged) regardless of whether `ino` names a
    // real register/coil/discrete-input/input-register. For a register,
    // additionally requires `access == ReadWrite` — a `read_only`-declared
    // register must stay non-writable locally too, matching the wire
    // handlers' own enforcement of the same TOML field.
    fn direct_writable_by_ino(&self, ino: INodeNo) -> bool {
        if self.write_mode != WriteMode::Direct {
            return false;
        }
        if let Some(register) = self.register_by_ino(ino) {
            return register.access == protocol::device_description::AccessRight::ReadWrite;
        }
        self.coil_by_ino(ino).is_some()
            || self.discrete_input_by_ino(ino).is_some()
            || self.input_register_by_ino(ino).is_some()
            || self.file_record_by_ino(ino).is_some()
    }

    // `transactions/`+`TRANSACTION_END` only exist in WriteMode::Staged
    // (the client) — the server writes directly into `holding-registers/`/
    // `coils/` instead (see `direct_writable_by_ino`), so it has no use for
    // a staging directory at all. `transactions_ino` itself is still always
    // computed the same way regardless of mode (same precedent as
    // `client_trust_ino`, which is always computed but only exposed when
    // `client_trust.is_some()`), so this is the single place that decides
    // whether it's ever actually reachable.
    fn transactions_enabled(&self) -> bool {
        self.write_mode == WriteMode::Staged
    }

    fn register_by_name(&self, name: &str) -> Option<&RegisterDescription> {
        self.registers.iter().find(|register| register.name == name)
    }

    fn coil_by_name(&self, name: &str) -> Option<&CoilDescription> {
        self.coils.iter().find(|coil| coil.name == name)
    }

    fn register_content(&self, register: &RegisterDescription) -> String {
        match self.store_lock().get(&register.name) {
            Some(value) => format!("{value}\n"),
            None => String::new(),
        }
    }

    fn coil_content(&self, coil: &CoilDescription) -> String {
        match self.coil_store_lock().get(&coil.name) {
            Some(value) => format!("{value}\n"),
            None => String::new(),
        }
    }

    fn discrete_input_content(&self, discrete_input: &DiscreteInputDescription) -> String {
        match self.discrete_input_store_lock().get(&discrete_input.name) {
            Some(value) => format!("{value}\n"),
            None => String::new(),
        }
    }

    fn input_register_content(&self, input_register: &InputRegisterDescription) -> String {
        match self.input_register_store_lock().get(&input_register.name) {
            Some(value) => format!("{value}\n"),
            None => String::new(),
        }
    }

    // Content of an already-staged transaction file: whatever value is
    // currently pending for that register, or empty if none (e.g. it was
    // just created and nothing has been written to it yet).
    fn transaction_content(&self, name: &str) -> String {
        match self.transactions_lock().pending.get(name) {
            Some(value) => format!("{value}\n"),
            None => String::new(),
        }
    }

    // Content of a report/ file: the outcome of the most recent write
    // attempt for that register, or empty if none has been attempted yet.
    fn report_content(&self, name: &str) -> String {
        match self.report_lock().get(name) {
            Some(status) => format!("{status}\n"),
            None => String::new(),
        }
    }

    // Resolves a transaction file's inode back to its register name. Used
    // by every trait method that has to tell "this ino is a staged
    // transaction file" apart from "this ino doesn't exist" — `getattr`,
    // `setattr`, and `read` all needed this exact lookup.
    fn transaction_name_by_ino(&self, ino: INodeNo) -> Option<String> {
        self.transactions_lock().ino_to_name.get(&ino).cloned()
    }

    // Drains every staged value and clears the whole transactions/ staging
    // area — TRANSACTION_END consumes it regardless of whether the write
    // that's about to be attempted actually succeeds. Does NOT touch
    // `store`; the drained values are only handed off over
    // `transaction_sender` for someone else to confirm and apply (see the
    // struct doc comment).
    fn commit_transaction(&self) {
        let mut state = self.transactions_lock();
        let drained = state.pending.drain();
        state.name_to_ino.clear();
        state.ino_to_name.clear();
        state.buffers.clear();
        drop(state);

        if !drained.is_empty() {
            let _ = self.transaction_sender.send(drained);
        }
    }

    fn parse_register_value(data_type: DataType, text: &str) -> Option<RegisterValue> {
        let text = text.trim();
        match data_type {
            DataType::U8 => Some(RegisterValue::U8(parse_hex_or_decimal(
                text,
                |hex| u8::from_str_radix(hex, 16),
                |decimal| decimal.parse(),
            )?)),
            DataType::I8 => Some(RegisterValue::I8(text.parse().ok()?)),
            DataType::U16 => Some(RegisterValue::U16(parse_hex_or_decimal(
                text,
                |hex| u16::from_str_radix(hex, 16),
                |decimal| decimal.parse(),
            )?)),
            DataType::I16 => Some(RegisterValue::I16(text.parse().ok()?)),
            DataType::U24 => {
                let value = parse_hex_or_decimal(
                    text,
                    |hex| u32::from_str_radix(hex, 16),
                    |decimal| decimal.parse(),
                )?;
                (value <= U24_MAX).then_some(RegisterValue::U24(value))
            }
            DataType::I24 => {
                let value: i32 = text.parse().ok()?;
                (I24_MIN..=I24_MAX)
                    .contains(&value)
                    .then_some(RegisterValue::I24(value))
            }
            DataType::U32 => Some(RegisterValue::U32(parse_hex_or_decimal(
                text,
                |hex| u32::from_str_radix(hex, 16),
                |decimal| decimal.parse(),
            )?)),
            DataType::I32 => Some(RegisterValue::I32(text.parse().ok()?)),
            DataType::U64 => Some(RegisterValue::U64(parse_hex_or_decimal(
                text,
                |hex| u64::from_str_radix(hex, 16),
                |decimal| decimal.parse(),
            )?)),
            DataType::I64 => Some(RegisterValue::I64(text.parse().ok()?)),
            DataType::F32 => Some(RegisterValue::F32(text.parse().ok()?)),
            DataType::F64 => Some(RegisterValue::F64(text.parse().ok()?)),
        }
    }

    // `MASK <and_mask> <or_mask>` (case-insensitive keyword, whitespace
    // separated, each mask a plain `0x`-hex or decimal u16 exactly like a
    // U16 register value) — the one-file syntax for staging a Mask Write
    // Register (FC 0x16) instead of a plain overwrite. Deliberately doesn't
    // check the target register's DataType here (this function only sees
    // text, not which register it's for): a MASK staged against a register
    // wider than one wire word parses fine but is rejected later, with a
    // real reason, by client::transaction_consumer when it tries to send
    // it — matching how encode_write_request already rejects an
    // over-wide plain write at send time rather than at parse time.
    fn parse_masked_register_value(text: &str) -> Option<(u16, u16)> {
        let mut tokens = text.split_whitespace();
        if !tokens.next()?.eq_ignore_ascii_case("MASK") {
            return None;
        }
        let and_mask = parse_hex_or_decimal(
            tokens.next()?,
            |hex| u16::from_str_radix(hex, 16),
            |decimal| decimal.parse(),
        )?;
        let or_mask = parse_hex_or_decimal(
            tokens.next()?,
            |hex| u16::from_str_radix(hex, 16),
            |decimal| decimal.parse(),
        )?;
        if tokens.next().is_some() {
            return None;
        }
        Some((and_mask, or_mask))
    }

    fn parse_coil_value(text: &str) -> Option<CoilValue> {
        match text.trim() {
            "0" => Some(CoilValue(false)),
            "1" => Some(CoilValue(true)),
            _ => None,
        }
    }

    // A file record's content is a plain hex dump — see CLAUDE.md's "FC
    // 0x14 (Read File Record)" section: what the bytes mean is entirely
    // vendor-specific, so this project only ever carries them, never
    // decodes them. Accepts whitespace-separated byte pairs
    // ("0D FE 00 20") or one contiguous run ("0DFE0020") equally — all
    // whitespace is stripped before parsing, so both forms (and anything
    // in between) parse identically. No length check against the
    // register's own declared `record_length` here — that's enforced at
    // the wire-response boundary (`server::handler::handle_read_file_record`),
    // not the FUSE write boundary, so what a technician wrote is always
    // visible exactly as typed via a subsequent read, even if it doesn't
    // match.
    fn parse_file_record_value(text: &str) -> Option<Vec<u8>> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
            return None;
        }
        (0..cleaned.len())
            .step_by(2)
            .map(|start| u8::from_str_radix(&cleaned[start..start + 2], 16).ok())
            .collect()
    }

    fn format_file_record_hex(bytes: &[u8]) -> String {
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{hex}\n")
    }

    // Defaults to `2 * record_length` zero bytes until directly written —
    // same "declared but unset = zero" precedent as
    // `default_register_value` in server::handler, just rendered here
    // rather than there since a file record's default depends on its own
    // declared width, not a fixed per-DataType shape.
    fn file_record_content(&self, description: &FileRecordDescription) -> String {
        let bytes = self
            .file_record_store_lock()
            .get(description.file_number, description.record_number)
            .cloned()
            .unwrap_or_else(|| vec![0u8; description.record_length as usize * 2]);
        Self::format_file_record_hex(&bytes)
    }

    // `ino`'s owner/group: the configured `fuse-permissions.toml` value if
    // `ino` belongs to one of the 4 configurable subtrees, otherwise the
    // pre-T2 fallback (whichever uid/gid is making this particular
    // request) — covers `root` and every `client-trust/*` ino except its
    // own root directory (handled separately in `directory_attr`, see
    // `client_trust_root_attr_override`).
    fn owner_for(&self, ino: INodeNo, req: &Request) -> (u32, u32) {
        match self.permissions_for(ino) {
            Some(permissions) => (permissions.uid, permissions.gid),
            None => (req.uid(), req.gid()),
        }
    }

    fn directory_attr(&self, ino: INodeNo, req: &Request) -> FileAttr {
        let now = SystemTime::now();
        let (mode, uid, gid) = match self.client_trust_root_attr_override(ino) {
            Some((mode, uid, gid)) => (mode, uid, gid),
            None => {
                let mode = self
                    .permissions_for(ino)
                    .map(|permissions| permissions.mode)
                    .unwrap_or(0o755);
                let (uid, gid) = self.owner_for(ino, req);
                (mode, uid, gid)
            }
        };
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: mode,
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn file_attr(&self, ino: INodeNo, size: u64, perm: u16, req: &Request) -> FileAttr {
        let now = SystemTime::now();
        let (uid, gid) = self.owner_for(ino, req);
        FileAttr {
            ino,
            size,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::RegularFile,
            perm,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

impl Filesystem for InfusedFilesystem {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INO {
            match name.to_str() {
                Some("holding-registers") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(HOLDING_REGISTERS_INO, req),
                        Generation(0),
                    );
                }
                Some("coils") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.coils_ino, req),
                        Generation(0),
                    );
                }
                Some("discrete-inputs") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.discrete_inputs_ino, req),
                        Generation(0),
                    );
                }
                Some("input-registers") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.input_registers_ino, req),
                        Generation(0),
                    );
                }
                Some("file-records") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.file_records_ino, req),
                        Generation(0),
                    );
                }
                Some("transactions") if self.transactions_enabled() => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.transactions_ino, req),
                        Generation(0),
                    );
                }
                Some("report") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.report_ino, req),
                        Generation(0),
                    );
                }
                // Only exists on the server (`client_trust.is_some()`) —
                // on the client this falls through to the same ENOENT as
                // any other unknown name, so the directory genuinely
                // doesn't exist there, not just "exists but empty".
                Some("client-trust") if self.client_trust.is_some() => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.client_trust_ino, req),
                        Generation(0),
                    );
                }
                // Only exists when the effective device description (local
                // or FC43-fetched) configured a `server-id` — absent means
                // this file genuinely doesn't exist, same "exists vs.
                // exists-but-empty" distinction as `client-trust` above.
                Some("server-id") if self.server_id.is_some() => {
                    let content = self.server_id_content();
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(self.server_id_ino, content.len() as u64, 0o444, req),
                        Generation(0),
                    );
                }
                _ => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.client_trust_ino && self.client_trust.is_some() {
            match name.to_str() {
                Some("approved") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.client_trust_approved_ino, req),
                        Generation(0),
                    );
                }
                Some("connection_attempts") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.connection_attempts_ino, req),
                        Generation(0),
                    );
                }
                _ => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.connection_attempts_ino && self.client_trust.is_some() {
            let log_ino = match name.to_str() {
                Some("approved.log") => Some(self.approved_log_ino),
                Some("pending.log") => Some(self.pending_log_ino),
                Some("rejected.log") => Some(self.rejected_log_ino),
                _ => None,
            };
            match log_ino {
                Some(ino) => {
                    let content = self.connection_attempts_log_content(ino);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(ino, content.len() as u64, 0o444, req),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.client_trust_approved_ino {
            let Some(name) = name.to_str() else {
                reply.error(Errno::ENOENT);
                return;
            };
            let ino = self
                .client_trust_lock()
                .and_then(|state| state.ino_by_fingerprint(name));
            match ino {
                Some(ino) => {
                    // The file's content is just its own name again (the
                    // fingerprint) — matches CLAUDE.md's "read-only mirror
                    // of the currently approved fingerprint set": presence
                    // in the directory listing already *is* the meaningful
                    // information, the content is there so `cat` alone
                    // (without `ls`) also shows something recognizable.
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(ino, name.len() as u64 + 1, 0o444, req),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == HOLDING_REGISTERS_INO {
            let register = name
                .to_str()
                .and_then(|name| self.name_to_ino.get(name))
                .and_then(|&ino| self.register_by_ino(ino).map(|register| (ino, register)));
            match register {
                Some((ino, register)) => {
                    let content = self.register_content(register);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(
                            ino,
                            content.len() as u64,
                            self.register_file_mode(register),
                            req,
                        ),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.coils_ino {
            let coil = name
                .to_str()
                .and_then(|name| self.coil_name_to_ino.get(name))
                .and_then(|&ino| self.coil_by_ino(ino).map(|coil| (ino, coil)));
            match coil {
                Some((ino, coil)) => {
                    let content = self.coil_content(coil);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(
                            ino,
                            content.len() as u64,
                            self.writable_data_file_mode(),
                            req,
                        ),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.discrete_inputs_ino {
            let discrete_input = name
                .to_str()
                .and_then(|name| self.discrete_input_name_to_ino.get(name))
                .and_then(|&ino| {
                    self.discrete_input_by_ino(ino)
                        .map(|discrete_input| (ino, discrete_input))
                });
            match discrete_input {
                Some((ino, discrete_input)) => {
                    let content = self.discrete_input_content(discrete_input);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(
                            ino,
                            content.len() as u64,
                            self.writable_data_file_mode(),
                            req,
                        ),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.input_registers_ino {
            let input_register = name
                .to_str()
                .and_then(|name| self.input_register_name_to_ino.get(name))
                .and_then(|&ino| {
                    self.input_register_by_ino(ino)
                        .map(|input_register| (ino, input_register))
                });
            match input_register {
                Some((ino, input_register)) => {
                    let content = self.input_register_content(input_register);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(
                            ino,
                            content.len() as u64,
                            self.writable_data_file_mode(),
                            req,
                        ),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.file_records_ino {
            let file_number_dir = name
                .to_str()
                .and_then(|name| name.parse::<u16>().ok())
                .and_then(|file_number| {
                    self.file_number_to_ino
                        .get(&file_number)
                        .map(|&ino| (ino, file_number))
                });
            match file_number_dir {
                Some((ino, _file_number)) => {
                    reply.entry(&ATTR_TTL, &self.directory_attr(ino, req), Generation(0));
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if let Some(file_number) = self.file_number_by_ino(parent) {
            let record = name
                .to_str()
                .and_then(|name| name.parse::<u16>().ok())
                .and_then(|record_number| self.file_record_by_numbers(file_number, record_number));
            match record {
                Some((ino, description)) => {
                    let content = self.file_record_content(description);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(
                            ino,
                            content.len() as u64,
                            self.writable_data_file_mode(),
                            req,
                        ),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.transactions_ino && self.transactions_enabled() {
            let Some(name) = name.to_str() else {
                reply.error(Errno::ENOENT);
                return;
            };
            let ino = self.transactions_lock().name_to_ino.get(name).copied();
            match ino {
                Some(ino) => {
                    let content = self.transaction_content(name);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(ino, content.len() as u64, 0o644, req),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.report_ino {
            let Some(name) = name.to_str() else {
                reply.error(Errno::ENOENT);
                return;
            };
            let ino = if let Some(index) = self
                .registers
                .iter()
                .position(|register| register.name == name)
            {
                Some(INodeNo(self.first_report_ino() + index as u64))
            } else {
                self.coils
                    .iter()
                    .position(|coil| coil.name == name)
                    .map(|index| INodeNo(self.first_coil_report_ino() + index as u64))
            };
            match ino {
                Some(ino) => {
                    let content = self.report_content(name);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(ino, content.len() as u64, 0o444, req),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        reply.error(Errno::ENOENT);
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino == ROOT_INO
            || ino == HOLDING_REGISTERS_INO
            || ino == self.coils_ino
            || ino == self.discrete_inputs_ino
            || ino == self.input_registers_ino
            || ino == self.file_records_ino
            || self.file_number_by_ino(ino).is_some()
            || (ino == self.transactions_ino && self.transactions_enabled())
            || ino == self.report_ino
            || (ino == self.client_trust_ino && self.client_trust.is_some())
            || (ino == self.client_trust_approved_ino && self.client_trust.is_some())
            || (ino == self.connection_attempts_ino && self.client_trust.is_some())
        {
            reply.attr(&ATTR_TTL, &self.directory_attr(ino, req));
            return;
        }

        if self.client_trust.is_some()
            && (ino == self.approved_log_ino
                || ino == self.pending_log_ino
                || ino == self.rejected_log_ino)
        {
            let content = self.connection_attempts_log_content(ino);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(ino, content.len() as u64, 0o444, req),
            );
            return;
        }

        if self.server_id.is_some() && ino == self.server_id_ino {
            let content = self.server_id_content();
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(ino, content.len() as u64, 0o444, req),
            );
            return;
        }

        if let Some(fingerprint) = self
            .client_trust_lock()
            .and_then(|state| state.fingerprint_by_ino(ino).map(str::to_string))
        {
            let content = format!("{fingerprint}\n");
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(ino, content.len() as u64, 0o444, req),
            );
            return;
        }

        if let Some(register) = self.register_by_ino(ino) {
            let content = self.register_content(register);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(
                    ino,
                    content.len() as u64,
                    self.register_file_mode(register),
                    req,
                ),
            );
            return;
        }

        if let Some(coil) = self.coil_by_ino(ino) {
            let content = self.coil_content(coil);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(
                    ino,
                    content.len() as u64,
                    self.writable_data_file_mode(),
                    req,
                ),
            );
            return;
        }

        if let Some(discrete_input) = self.discrete_input_by_ino(ino) {
            let content = self.discrete_input_content(discrete_input);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(
                    ino,
                    content.len() as u64,
                    self.writable_data_file_mode(),
                    req,
                ),
            );
            return;
        }

        if let Some(input_register) = self.input_register_by_ino(ino) {
            let content = self.input_register_content(input_register);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(
                    ino,
                    content.len() as u64,
                    self.writable_data_file_mode(),
                    req,
                ),
            );
            return;
        }

        if let Some(description) = self.file_record_by_ino(ino) {
            let content = self.file_record_content(description);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(
                    ino,
                    content.len() as u64,
                    self.writable_data_file_mode(),
                    req,
                ),
            );
            return;
        }

        if let Some(register) = self.report_register_by_ino(ino) {
            let content = self.report_content(&register.name);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(ino, content.len() as u64, 0o444, req),
            );
            return;
        }

        if let Some(coil) = self.report_coil_by_ino(ino) {
            let content = self.report_content(&coil.name);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(ino, content.len() as u64, 0o444, req),
            );
            return;
        }

        match self.transaction_name_by_ino(ino) {
            Some(name) => {
                let content = self.transaction_content(&name);
                reply.attr(
                    &ATTR_TTL,
                    &self.file_attr(ino, content.len() as u64, 0o644, req),
                );
            }
            None => reply.error(Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // Only meaningful case here: `> transactions/Foo` (or, in
        // WriteMode::Direct, `> holding-registers/Foo`/`> coils/Foo`)
        // truncating an existing file before writing its new value
        // (O_CREAT on an existing name goes through open+setattr, not
        // create). There's no real backing buffer to shrink — the next
        // `write` replaces the value outright — so this just has to
        // succeed and report an attr back.
        let name = self.transaction_name_by_ino(ino);
        if (ino == self.transactions_ino && self.transactions_enabled()) || name.is_some() {
            let content_len = name
                .map(|name| self.transaction_content(&name).len() as u64)
                .unwrap_or(0);
            let reported_size = size.unwrap_or(content_len);
            reply.attr(&ATTR_TTL, &self.file_attr(ino, reported_size, 0o644, req));
            return;
        }

        if self.direct_writable_by_ino(ino) {
            let content_len = if let Some(register) = self.register_by_ino(ino) {
                self.register_content(register).len() as u64
            } else if let Some(coil) = self.coil_by_ino(ino) {
                self.coil_content(coil).len() as u64
            } else if let Some(discrete_input) = self.discrete_input_by_ino(ino) {
                self.discrete_input_content(discrete_input).len() as u64
            } else if let Some(input_register) = self.input_register_by_ino(ino) {
                self.input_register_content(input_register).len() as u64
            } else if let Some(description) = self.file_record_by_ino(ino) {
                self.file_record_content(description).len() as u64
            } else {
                0
            };
            let reported_size = size.unwrap_or(content_len);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(ino, reported_size, self.writable_data_file_mode(), req),
            );
            return;
        }

        // `touch` on a brand-new file does create() then immediately
        // futimens() on the same fd as one logical operation. The
        // TRANSACTION_END inode create() just handed out isn't tracked
        // anywhere else (it's meant to vanish instantly), so without this
        // it would wrongly fail that follow-up call even though the
        // create() itself (and the commit it triggered) succeeded. Consumed
        // on use — a *later*, unrelated setattr on the same stale inode
        // number correctly falls through to ENOENT below.
        let mut state = self.transactions_lock();
        if state.last_transaction_end_inos.remove(&ino) {
            drop(state);
            reply.attr(&ATTR_TTL, &self.file_attr(ino, 0, 0o644, req));
            return;
        }
        drop(state);

        reply.error(Errno::ENOENT);
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let content = if let Some(register) = self.register_by_ino(ino) {
            self.register_content(register)
        } else if let Some(coil) = self.coil_by_ino(ino) {
            self.coil_content(coil)
        } else if let Some(discrete_input) = self.discrete_input_by_ino(ino) {
            self.discrete_input_content(discrete_input)
        } else if let Some(input_register) = self.input_register_by_ino(ino) {
            self.input_register_content(input_register)
        } else if let Some(description) = self.file_record_by_ino(ino) {
            self.file_record_content(description)
        } else if let Some(register) = self.report_register_by_ino(ino) {
            self.report_content(&register.name)
        } else if let Some(coil) = self.report_coil_by_ino(ino) {
            self.report_content(&coil.name)
        } else if let Some(name) = self.transaction_name_by_ino(ino) {
            // The lock must be released before `transaction_content` tries
            // to take it again — std::sync::Mutex isn't reentrant, so
            // holding this guard through that call (as a direct `if let`
            // condition would, since its temporary lives for the whole
            // `if let` body) deadlocks. `transaction_name_by_ino` already
            // resolves to an owned `String` for exactly this reason.
            self.transaction_content(&name)
        } else if let Some(fingerprint) = self
            .client_trust_lock()
            .and_then(|state| state.fingerprint_by_ino(ino).map(str::to_string))
        {
            format!("{fingerprint}\n")
        } else if self.client_trust.is_some()
            && (ino == self.approved_log_ino
                || ino == self.pending_log_ino
                || ino == self.rejected_log_ino)
        {
            self.connection_attempts_log_content(ino)
        } else if self.server_id.is_some() && ino == self.server_id_ino {
            self.server_id_content()
        } else {
            reply.error(Errno::ENOENT);
            return;
        };

        let bytes = content.as_bytes();
        let offset = offset as usize;
        if offset >= bytes.len() {
            reply.data(&[]);
            return;
        }
        let end = (offset + size as usize).min(bytes.len());
        reply.data(&bytes[offset..end]);
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let entries: Vec<(INodeNo, FileType, String)> = if ino == ROOT_INO {
            vec![
                (ROOT_INO, FileType::Directory, ".".to_string()),
                (ROOT_INO, FileType::Directory, "..".to_string()),
                (
                    HOLDING_REGISTERS_INO,
                    FileType::Directory,
                    "holding-registers".to_string(),
                ),
                (self.coils_ino, FileType::Directory, "coils".to_string()),
                (
                    self.discrete_inputs_ino,
                    FileType::Directory,
                    "discrete-inputs".to_string(),
                ),
                (
                    self.input_registers_ino,
                    FileType::Directory,
                    "input-registers".to_string(),
                ),
                (
                    self.file_records_ino,
                    FileType::Directory,
                    "file-records".to_string(),
                ),
                (self.report_ino, FileType::Directory, "report".to_string()),
            ]
            .into_iter()
            .chain(self.transactions_enabled().then_some((
                self.transactions_ino,
                FileType::Directory,
                "transactions".to_string(),
            )))
            .chain(self.client_trust.is_some().then_some((
                self.client_trust_ino,
                FileType::Directory,
                "client-trust".to_string(),
            )))
            .chain(self.server_id.is_some().then_some((
                self.server_id_ino,
                FileType::RegularFile,
                "server-id".to_string(),
            )))
            .collect()
        } else if ino == self.client_trust_ino && self.client_trust.is_some() {
            vec![
                (self.client_trust_ino, FileType::Directory, ".".to_string()),
                (ROOT_INO, FileType::Directory, "..".to_string()),
                (
                    self.client_trust_approved_ino,
                    FileType::Directory,
                    "approved".to_string(),
                ),
                (
                    self.connection_attempts_ino,
                    FileType::Directory,
                    "connection_attempts".to_string(),
                ),
            ]
        } else if ino == self.connection_attempts_ino && self.client_trust.is_some() {
            vec![
                (
                    self.connection_attempts_ino,
                    FileType::Directory,
                    ".".to_string(),
                ),
                (self.client_trust_ino, FileType::Directory, "..".to_string()),
                (
                    self.approved_log_ino,
                    FileType::RegularFile,
                    "approved.log".to_string(),
                ),
                (
                    self.pending_log_ino,
                    FileType::RegularFile,
                    "pending.log".to_string(),
                ),
                (
                    self.rejected_log_ino,
                    FileType::RegularFile,
                    "rejected.log".to_string(),
                ),
            ]
        } else if ino == self.client_trust_approved_ino {
            let mut entries = vec![
                (
                    self.client_trust_approved_ino,
                    FileType::Directory,
                    ".".to_string(),
                ),
                (self.client_trust_ino, FileType::Directory, "..".to_string()),
            ];
            if let Some(state) = self.client_trust_lock() {
                for (fingerprint, ino) in state.approved_entries() {
                    entries.push((ino, FileType::RegularFile, fingerprint.to_string()));
                }
            }
            entries
        } else if ino == HOLDING_REGISTERS_INO {
            let mut entries = vec![
                (HOLDING_REGISTERS_INO, FileType::Directory, ".".to_string()),
                (ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            for register in &self.registers {
                let register_ino = self.name_to_ino[&register.name];
                entries.push((register_ino, FileType::RegularFile, register.name.clone()));
            }
            entries
        } else if ino == self.coils_ino {
            let mut entries = vec![
                (self.coils_ino, FileType::Directory, ".".to_string()),
                (ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            for coil in &self.coils {
                let coil_ino = self.coil_name_to_ino[&coil.name];
                entries.push((coil_ino, FileType::RegularFile, coil.name.clone()));
            }
            entries
        } else if ino == self.discrete_inputs_ino {
            let mut entries = vec![
                (
                    self.discrete_inputs_ino,
                    FileType::Directory,
                    ".".to_string(),
                ),
                (ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            for discrete_input in &self.discrete_inputs {
                let discrete_input_ino = self.discrete_input_name_to_ino[&discrete_input.name];
                entries.push((
                    discrete_input_ino,
                    FileType::RegularFile,
                    discrete_input.name.clone(),
                ));
            }
            entries
        } else if ino == self.input_registers_ino {
            let mut entries = vec![
                (
                    self.input_registers_ino,
                    FileType::Directory,
                    ".".to_string(),
                ),
                (ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            for input_register in &self.input_registers {
                let input_register_ino = self.input_register_name_to_ino[&input_register.name];
                entries.push((
                    input_register_ino,
                    FileType::RegularFile,
                    input_register.name.clone(),
                ));
            }
            entries
        } else if ino == self.file_records_ino {
            let mut entries = vec![
                (self.file_records_ino, FileType::Directory, ".".to_string()),
                (ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            for (index, &file_number) in self.unique_file_numbers.iter().enumerate() {
                let file_number_ino = INodeNo(self.first_file_number_ino() + index as u64);
                entries.push((
                    file_number_ino,
                    FileType::Directory,
                    file_number.to_string(),
                ));
            }
            entries
        } else if let Some(file_number) = self.file_number_by_ino(ino) {
            let mut entries = vec![
                (ino, FileType::Directory, ".".to_string()),
                (self.file_records_ino, FileType::Directory, "..".to_string()),
            ];
            for (index, description) in self.file_records.iter().enumerate() {
                if description.file_number != file_number {
                    continue;
                }
                let record_ino = INodeNo(self.first_file_record_ino() + index as u64);
                entries.push((
                    record_ino,
                    FileType::RegularFile,
                    description.record_number.to_string(),
                ));
            }
            entries
        } else if ino == self.transactions_ino && self.transactions_enabled() {
            let mut entries = vec![
                (self.transactions_ino, FileType::Directory, ".".to_string()),
                (ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            let state = self.transactions_lock();
            for (name, &ino) in &state.name_to_ino {
                entries.push((ino, FileType::RegularFile, name.clone()));
            }
            entries
        } else if ino == self.report_ino {
            let mut entries = vec![
                (self.report_ino, FileType::Directory, ".".to_string()),
                (ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            for (index, register) in self.registers.iter().enumerate() {
                let register_ino = INodeNo(self.first_report_ino() + index as u64);
                entries.push((register_ino, FileType::RegularFile, register.name.clone()));
            }
            for (index, coil) in self.coils.iter().enumerate() {
                let coil_ino = INodeNo(self.first_coil_report_ino() + index as u64);
                entries.push((coil_ino, FileType::RegularFile, coil.name.clone()));
            }
            entries
        } else {
            reply.error(Errno::ENOTDIR);
            return;
        };

        for (index, (entry_ino, kind, name)) in
            entries.into_iter().enumerate().skip(offset as usize)
        {
            let next_offset = (index + 1) as u64;
            if reply.add(entry_ino, next_offset, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if parent != self.transactions_ino || !self.transactions_enabled() {
            reply.error(Errno::EPERM);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };

        if name == TRANSACTION_END_NAME {
            self.commit_transaction();
            // Not tracked in name_to_ino/ino_to_name: the staging area it
            // would belong to was just cleared, so the file doesn't
            // persist — a later lookup() for TRANSACTION_END correctly
            // reports ENOENT, as if it vanished the instant it was created.
            let mut state = self.transactions_lock();
            let ino = INodeNo(state.next_ino);
            state.next_ino += 1;
            state.last_transaction_end_inos.insert(ino);
            drop(state);
            reply.created(
                &ATTR_TTL,
                &self.file_attr(ino, 0, 0o644, req),
                Generation(0),
                FileHandle(0),
                fuser::FopenFlags::empty(),
            );
            return;
        }

        if self.register_by_name(name).is_none() && self.coil_by_name(name).is_none() {
            // Staging a value only makes sense for a real register or coil.
            reply.error(Errno::ENOENT);
            return;
        }

        let mut state = self.transactions_lock();
        let ino = match state.name_to_ino.get(name).copied() {
            Some(ino) => ino,
            None => {
                let ino = INodeNo(state.next_ino);
                state.next_ino += 1;
                state.name_to_ino.insert(name.to_string(), ino);
                state.ino_to_name.insert(ino, name.to_string());
                ino
            }
        };
        state.buffers.insert(ino, Vec::new());
        drop(state);

        reply.created(
            &ATTR_TTL,
            &self.file_attr(ino, 0, 0o644, req),
            Generation(0),
            FileHandle(0),
            fuser::FopenFlags::empty(),
        );
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut state = self.transactions_lock();
        if !state.ino_to_name.contains_key(&ino) && !self.direct_writable_by_ino(ino) {
            reply.error(Errno::ENOENT);
            return;
        }
        let buffer = state.buffers.entry(ino).or_default();
        let offset = offset as usize;
        if buffer.len() < offset {
            buffer.resize(offset, 0);
        }
        let end = offset + data.len();
        if buffer.len() < end {
            buffer.resize(end, 0);
        }
        buffer[offset..end].copy_from_slice(data);
        reply.written(data.len() as u32);
    }

    // Parsing (rather than in `write`) matters because `write` can be
    // called multiple times with fragments of one logical value; `release`
    // is the point where the write is actually finished (the caller closed
    // the file), so it's the first point a full value is guaranteed to be
    // present. A value that fails to parse is silently dropped rather than
    // staged — surfacing that failure back through the filesystem is the
    // open question in CLAUDE.md's Milestone H3, not solved here.
    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let mut state = self.transactions_lock();
        if let Some(name) = state.ino_to_name.get(&ino).cloned()
            && let Some(buffer) = state.buffers.remove(&ino)
            && let Ok(text) = String::from_utf8(buffer)
        {
            let staged = if let Some(register) = self.register_by_name(&name) {
                if let Some((and_mask, or_mask)) = Self::parse_masked_register_value(&text) {
                    Some(StagedValue::MaskedRegister { and_mask, or_mask })
                } else {
                    Self::parse_register_value(register.data_type, &text).map(StagedValue::Register)
                }
            } else if self.coil_by_name(&name).is_some() {
                Self::parse_coil_value(&text).map(StagedValue::Coil)
            } else {
                None
            };
            if let Some(staged) = staged {
                state.pending.stage(name, staged);
            }
            drop(state);
            reply.ok();
            return;
        }

        // WriteMode::Direct: `holding-registers/<name>`/`coils/<name>`
        // written directly, not staged. Sent as an implicit one-item
        // transaction over the same `transaction_sender` channel
        // `commit_transaction` already uses — the receiving consumer can't
        // tell the difference from a drained multi-item transaction, so it
        // needs no changes, and every write to `store`/`coil_store` keeps
        // going through that one consumer thread regardless of how it was
        // triggered (see CLAUDE.md's "server direct-write model" for why
        // that's what keeps this race-free).
        if self.direct_writable_by_ino(ino)
            && let Some(buffer) = state.buffers.remove(&ino)
            && let Ok(text) = String::from_utf8(buffer)
        {
            let direct = if let Some(register) = self.register_by_ino(ino) {
                Self::parse_register_value(register.data_type, &text)
                    .map(|value| (register.name.clone(), StagedValue::Register(value)))
            } else if let Some(coil) = self.coil_by_ino(ino) {
                Self::parse_coil_value(&text)
                    .map(|value| (coil.name.clone(), StagedValue::Coil(value)))
            } else if let Some(discrete_input) = self.discrete_input_by_ino(ino) {
                Self::parse_coil_value(&text).map(|value| {
                    (
                        discrete_input.name.clone(),
                        StagedValue::DiscreteInput(value),
                    )
                })
            } else if let Some(input_register) = self.input_register_by_ino(ino) {
                Self::parse_register_value(input_register.data_type, &text).map(|value| {
                    (
                        input_register.name.clone(),
                        StagedValue::InputRegister(value),
                    )
                })
            } else if let Some(description) = self.file_record_by_ino(ino) {
                let file_number = description.file_number;
                let record_number = description.record_number;
                Self::parse_file_record_value(&text).map(|value| {
                    (
                        format!("{file_number}:{record_number}"),
                        StagedValue::FileRecord {
                            file_number,
                            record_number,
                            value,
                        },
                    )
                })
            } else {
                None
            };
            drop(state);
            if let Some((name, value)) = direct {
                let _ = self.transaction_sender.send(HashMap::from([(name, value)]));
            }
            reply.ok();
            return;
        }
        drop(state);
        reply.ok();
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if parent != self.transactions_ino || !self.transactions_enabled() {
            reply.error(Errno::ENOENT);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };

        let mut state = self.transactions_lock();
        match state.name_to_ino.remove(name) {
            Some(ino) => {
                state.ino_to_name.remove(&ino);
                state.buffers.remove(&ino);
                state.pending.unstage(name);
                reply.ok();
            }
            None => reply.error(Errno::ENOENT),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WriteStatus;
    use protocol::device_description::AccessRight;

    fn test_filesystem() -> (
        InfusedFilesystem,
        mpsc::Receiver<HashMap<String, StagedValue>>,
    ) {
        test_filesystem_with_permissions(FusePermissions::default())
    }

    fn test_filesystem_with_permissions(
        permissions: FusePermissions,
    ) -> (
        InfusedFilesystem,
        mpsc::Receiver<HashMap<String, StagedValue>>,
    ) {
        test_filesystem_with_permissions_and_write_mode(permissions, WriteMode::Staged)
    }

    fn test_filesystem_with_server_id(
        server_id: Option<String>,
    ) -> (
        InfusedFilesystem,
        mpsc::Receiver<HashMap<String, StagedValue>>,
    ) {
        test_filesystem_with_permissions_write_mode_and_server_id(
            FusePermissions::default(),
            WriteMode::Staged,
            server_id,
        )
    }

    fn test_filesystem_with_permissions_and_write_mode(
        permissions: FusePermissions,
        write_mode: WriteMode,
    ) -> (
        InfusedFilesystem,
        mpsc::Receiver<HashMap<String, StagedValue>>,
    ) {
        test_filesystem_with_permissions_write_mode_and_server_id(permissions, write_mode, None)
    }

    fn test_filesystem_with_permissions_write_mode_and_server_id(
        permissions: FusePermissions,
        write_mode: WriteMode,
        server_id: Option<String>,
    ) -> (
        InfusedFilesystem,
        mpsc::Receiver<HashMap<String, StagedValue>>,
    ) {
        let registers = vec![RegisterDescription {
            name: "Stop_Process".to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadWrite,
        }];
        let coils = vec![CoilDescription {
            name: "Motor_Running".to_string(),
            address: 1,
        }];
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();
        (
            InfusedFilesystem::new(
                registers,
                coils,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                store,
                coil_store,
                discrete_input_store,
                input_register_store,
                Arc::new(Mutex::new(FileRecordStore::new())),
                sender,
                report,
                None,
                permissions,
                write_mode,
                server_id,
            ),
            receiver,
        )
    }

    // Mirrors `test_filesystem_with_permissions_write_mode_and_server_id`,
    // but with `Stop_Process` declared `read_only` — dedicated fixture
    // rather than adding a second register to the shared one, since other
    // tests may assume exactly one register exists.
    fn test_filesystem_with_read_only_register(
        write_mode: WriteMode,
    ) -> (
        InfusedFilesystem,
        mpsc::Receiver<HashMap<String, StagedValue>>,
    ) {
        let registers = vec![RegisterDescription {
            name: "Stop_Process".to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadOnly,
        }];
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();
        (
            InfusedFilesystem::new(
                registers,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                store,
                coil_store,
                discrete_input_store,
                input_register_store,
                Arc::new(Mutex::new(FileRecordStore::new())),
                sender,
                report,
                None,
                FusePermissions::default(),
                write_mode,
                None,
            ),
            receiver,
        )
    }

    // Two file numbers (20 has two records, 30 has one) so tests can check
    // both the file_number-grouping level and the record level of
    // file-records/'s two-level nesting.
    fn test_filesystem_with_file_records(
        write_mode: WriteMode,
    ) -> (
        InfusedFilesystem,
        mpsc::Receiver<HashMap<String, StagedValue>>,
    ) {
        let file_records = vec![
            FileRecordDescription {
                file_number: 20,
                record_number: 5,
                record_length: 2,
            },
            FileRecordDescription {
                file_number: 20,
                record_number: 6,
                record_length: 2,
            },
            FileRecordDescription {
                file_number: 30,
                record_number: 1,
                record_length: 1,
            },
        ];
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();
        (
            InfusedFilesystem::new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                file_records,
                store,
                coil_store,
                discrete_input_store,
                input_register_store,
                file_record_store,
                sender,
                report,
                None,
                FusePermissions::default(),
                write_mode,
                None,
            ),
            receiver,
        )
    }

    fn test_filesystem_with_client_trust() -> InfusedFilesystem {
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, _receiver) = mpsc::channel();
        let client_trust = Arc::new(Mutex::new(ClientTrustState::new()));
        InfusedFilesystem::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            store,
            coil_store,
            discrete_input_store,
            input_register_store,
            Arc::new(Mutex::new(FileRecordStore::new())),
            sender,
            report,
            Some(client_trust),
            FusePermissions::default(),
            WriteMode::Direct,
            None,
        )
    }

    // Distinct mode/uid/gid per directory so a test asserting on one
    // directory's permissions can't accidentally pass due to two
    // directories coincidentally sharing a value.
    fn distinct_permissions() -> FusePermissions {
        FusePermissions {
            holding_registers: DirectoryPermissions {
                mode: 0o700,
                uid: 101,
                gid: 201,
            },
            transactions: DirectoryPermissions {
                mode: 0o710,
                uid: 102,
                gid: 202,
            },
            report: DirectoryPermissions {
                mode: 0o720,
                uid: 103,
                gid: 203,
            },
            coils: DirectoryPermissions {
                mode: 0o730,
                uid: 104,
                gid: 204,
            },
        }
    }

    #[test]
    fn permissions_for_applies_to_the_holding_registers_directory_and_its_files() {
        let permissions = distinct_permissions();
        let (filesystem, _receiver) = test_filesystem_with_permissions(permissions);
        let register_ino = *filesystem.name_to_ino.get("Stop_Process").unwrap();

        assert_eq!(
            filesystem.permissions_for(HOLDING_REGISTERS_INO),
            Some(permissions.holding_registers)
        );
        assert_eq!(
            filesystem.permissions_for(register_ino),
            Some(permissions.holding_registers)
        );
    }

    #[test]
    fn permissions_for_applies_to_the_coils_directory_and_its_files() {
        let permissions = distinct_permissions();
        let (filesystem, _receiver) = test_filesystem_with_permissions(permissions);
        let coil_ino = *filesystem.coil_name_to_ino.get("Motor_Running").unwrap();

        assert_eq!(
            filesystem.permissions_for(filesystem.coils_ino),
            Some(permissions.coils)
        );
        assert_eq!(
            filesystem.permissions_for(coil_ino),
            Some(permissions.coils)
        );
    }

    #[test]
    fn permissions_for_applies_to_the_transactions_directory_and_a_staged_file() {
        let permissions = distinct_permissions();
        let (filesystem, _receiver) = test_filesystem_with_permissions(permissions);
        let staged_ino = INodeNo(500);
        filesystem
            .transactions_lock()
            .ino_to_name
            .insert(staged_ino, "Stop_Process".to_string());

        assert_eq!(
            filesystem.permissions_for(filesystem.transactions_ino),
            Some(permissions.transactions)
        );
        assert_eq!(
            filesystem.permissions_for(staged_ino),
            Some(permissions.transactions)
        );
    }

    #[test]
    fn permissions_for_applies_to_the_report_directory_and_its_register_and_coil_files() {
        let permissions = distinct_permissions();
        let (filesystem, _receiver) = test_filesystem_with_permissions(permissions);
        let report_register_ino = INodeNo(filesystem.first_report_ino());
        let report_coil_ino = INodeNo(filesystem.first_coil_report_ino());

        assert_eq!(
            filesystem.permissions_for(filesystem.report_ino),
            Some(permissions.report)
        );
        assert_eq!(
            filesystem.permissions_for(report_register_ino),
            Some(permissions.report)
        );
        assert_eq!(
            filesystem.permissions_for(report_coil_ino),
            Some(permissions.report)
        );
    }

    #[test]
    fn writable_data_file_mode_is_read_only_when_staged() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Staged,
        );
        assert_eq!(filesystem.writable_data_file_mode(), 0o444);
    }

    #[test]
    fn writable_data_file_mode_is_writable_when_direct() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Direct,
        );
        assert_eq!(filesystem.writable_data_file_mode(), 0o644);
    }

    #[test]
    fn direct_writable_by_ino_is_true_for_a_register_in_direct_mode() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Direct,
        );
        let register_ino = *filesystem.name_to_ino.get("Stop_Process").unwrap();
        assert!(filesystem.direct_writable_by_ino(register_ino));
    }

    #[test]
    fn direct_writable_by_ino_is_true_for_a_coil_in_direct_mode() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Direct,
        );
        let coil_ino = *filesystem.coil_name_to_ino.get("Motor_Running").unwrap();
        assert!(filesystem.direct_writable_by_ino(coil_ino));
    }

    #[test]
    fn direct_writable_by_ino_is_false_in_staged_mode() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Staged,
        );
        let register_ino = *filesystem.name_to_ino.get("Stop_Process").unwrap();
        assert!(!filesystem.direct_writable_by_ino(register_ino));
    }

    #[test]
    fn direct_writable_by_ino_is_false_for_an_unrelated_ino() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Direct,
        );
        assert!(!filesystem.direct_writable_by_ino(ROOT_INO));
        assert!(!filesystem.direct_writable_by_ino(filesystem.transactions_ino));
    }

    // Regression test for a bug found during FC17 manual verification (see
    // CLAUDE.md/memory): `direct_writable_by_ino` used to ignore a
    // register's own TOML-declared `AccessRight` entirely, so a
    // `read_only`-declared register was still locally writable on the
    // server via `holding-registers/<name>` — unlike every wire-facing
    // write handler, which does enforce `access`.
    #[test]
    fn direct_writable_by_ino_is_false_for_a_read_only_register_in_direct_mode() {
        let (filesystem, _receiver) = test_filesystem_with_read_only_register(WriteMode::Direct);
        let register_ino = *filesystem.name_to_ino.get("Stop_Process").unwrap();
        assert!(!filesystem.direct_writable_by_ino(register_ino));
    }

    #[test]
    fn direct_writable_by_ino_is_true_for_a_read_write_register_in_direct_mode() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Direct,
        );
        let register_ino = *filesystem.name_to_ino.get("Stop_Process").unwrap();
        assert!(filesystem.direct_writable_by_ino(register_ino));
    }

    #[test]
    fn register_file_mode_is_read_only_for_a_read_only_register_even_in_direct_mode() {
        let (filesystem, _receiver) = test_filesystem_with_read_only_register(WriteMode::Direct);
        let register = filesystem.register_by_name("Stop_Process").unwrap();
        assert_eq!(filesystem.register_file_mode(register), 0o444);
    }

    #[test]
    fn register_file_mode_is_writable_for_a_read_write_register_in_direct_mode() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Direct,
        );
        let register = filesystem.register_by_name("Stop_Process").unwrap();
        assert_eq!(filesystem.register_file_mode(register), 0o644);
    }

    #[test]
    fn register_file_mode_is_read_only_for_a_read_write_register_when_staged() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Staged,
        );
        let register = filesystem.register_by_name("Stop_Process").unwrap();
        assert_eq!(filesystem.register_file_mode(register), 0o444);
    }

    #[test]
    fn transactions_enabled_is_true_when_staged() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Staged,
        );
        assert!(filesystem.transactions_enabled());
    }

    #[test]
    fn transactions_enabled_is_false_when_direct() {
        let (filesystem, _receiver) = test_filesystem_with_permissions_and_write_mode(
            FusePermissions::default(),
            WriteMode::Direct,
        );
        assert!(!filesystem.transactions_enabled());
    }

    #[test]
    fn permissions_for_returns_none_for_root_and_unrelated_inodes() {
        let (filesystem, _receiver) = test_filesystem_with_permissions(distinct_permissions());

        assert_eq!(filesystem.permissions_for(ROOT_INO), None);
        assert_eq!(filesystem.permissions_for(INodeNo(999_999)), None);
    }

    #[test]
    fn permissions_for_returns_none_for_client_trust_inodes() {
        let filesystem = test_filesystem_with_client_trust();

        assert_eq!(
            filesystem.permissions_for(filesystem.client_trust_ino),
            None
        );
        assert_eq!(
            filesystem.permissions_for(filesystem.client_trust_approved_ino),
            None
        );
    }

    #[test]
    fn client_trust_root_attr_override_hardcodes_the_client_trust_root_directory() {
        let filesystem = test_filesystem_with_client_trust();
        let (real_uid, real_gid) = crate::permissions::real_uid_and_gid();

        assert_eq!(
            filesystem.client_trust_root_attr_override(filesystem.client_trust_ino),
            Some((0o700, real_uid, real_gid))
        );
    }

    #[test]
    fn client_trust_root_attr_override_does_not_apply_to_nested_client_trust_inodes() {
        let filesystem = test_filesystem_with_client_trust();

        assert_eq!(
            filesystem.client_trust_root_attr_override(filesystem.client_trust_approved_ino),
            None
        );
        assert_eq!(
            filesystem.client_trust_root_attr_override(filesystem.connection_attempts_ino),
            None
        );
        assert_eq!(
            filesystem.client_trust_root_attr_override(filesystem.approved_log_ino),
            None
        );
    }

    #[test]
    fn client_trust_root_attr_override_does_not_apply_to_unrelated_inodes() {
        let filesystem = test_filesystem_with_client_trust();
        assert_eq!(filesystem.client_trust_root_attr_override(ROOT_INO), None);
    }

    #[test]
    fn client_trust_root_attr_override_is_none_when_client_trust_is_absent() {
        let (filesystem, _receiver) = test_filesystem();
        // On the client (client_trust: None), there is no client-trust/ at
        // all — even passing this instance's own client_trust_ino value
        // must never trigger the override, since the directory it would
        // refer to doesn't actually exist here.
        assert_eq!(
            filesystem.client_trust_root_attr_override(filesystem.client_trust_ino),
            None
        );
    }

    #[test]
    fn commit_transaction_sends_staged_values_and_clears_staging_area() {
        let (filesystem, receiver) = test_filesystem();
        {
            let mut state = filesystem.transactions_lock();
            state
                .pending
                .stage("Stop_Process", StagedValue::Register(RegisterValue::U16(1)));
            state
                .name_to_ino
                .insert("Stop_Process".to_string(), INodeNo(100));
            state
                .ino_to_name
                .insert(INodeNo(100), "Stop_Process".to_string());
            state.buffers.insert(INodeNo(100), b"1".to_vec());
        }

        filesystem.commit_transaction();

        let received = receiver.try_recv().unwrap();
        assert_eq!(
            received.get("Stop_Process"),
            Some(&StagedValue::Register(RegisterValue::U16(1)))
        );

        let state = filesystem.transactions_lock();
        assert!(state.pending.is_empty());
        assert!(state.name_to_ino.is_empty());
        assert!(state.ino_to_name.is_empty());
        assert!(state.buffers.is_empty());
    }

    #[test]
    fn commit_transaction_does_not_touch_store() {
        let (filesystem, receiver) = test_filesystem();
        filesystem
            .store_lock()
            .set("Stop_Process", RegisterValue::U16(0));
        filesystem
            .transactions_lock()
            .pending
            .stage("Stop_Process", StagedValue::Register(RegisterValue::U16(1)));

        filesystem.commit_transaction();

        assert_eq!(
            filesystem.store_lock().get("Stop_Process"),
            Some(RegisterValue::U16(0))
        );
        receiver.try_recv().unwrap();
    }

    #[test]
    fn commit_transaction_with_nothing_staged_sends_nothing() {
        let (filesystem, receiver) = test_filesystem();
        filesystem.commit_transaction();
        assert!(receiver.try_recv().is_err());
    }

    // Simulates two concurrent `touch transactions/TRANSACTION_END` calls:
    // each gets its own create()d inode inserted here before its setattr()
    // follow-up arrives. A `HashSet` (rather than the single most-recent
    // `Option` this replaced) means the second insert can't clobber the
    // first — each inode is only removed by its own matching setattr().
    #[test]
    fn last_transaction_end_inos_tracks_concurrent_touches_independently() {
        let (filesystem, _receiver) = test_filesystem();
        {
            let mut state = filesystem.transactions_lock();
            state.last_transaction_end_inos.insert(INodeNo(100));
            state.last_transaction_end_inos.insert(INodeNo(101));
        }

        {
            let mut state = filesystem.transactions_lock();
            assert!(state.last_transaction_end_inos.remove(&INodeNo(100)));
        }

        let state = filesystem.transactions_lock();
        assert!(state.last_transaction_end_inos.contains(&INodeNo(101)));
        assert!(!state.last_transaction_end_inos.contains(&INodeNo(100)));
    }

    #[test]
    fn report_content_is_empty_when_nothing_was_attempted() {
        let (filesystem, _receiver) = test_filesystem();
        assert_eq!(filesystem.report_content("Stop_Process"), "");
    }

    #[test]
    fn report_content_reflects_the_most_recent_status() {
        let (filesystem, _receiver) = test_filesystem();
        filesystem
            .report_lock()
            .set("Stop_Process", WriteStatus::Ok);
        assert_eq!(filesystem.report_content("Stop_Process"), "OK\n");

        filesystem
            .report_lock()
            .set("Stop_Process", WriteStatus::Failed("timeout".to_string()));
        assert_eq!(
            filesystem.report_content("Stop_Process"),
            "FAILED: timeout\n"
        );
    }

    #[test]
    fn report_register_by_ino_resolves_a_report_file_inode() {
        let (filesystem, _receiver) = test_filesystem();
        let report_ino = INodeNo(filesystem.first_report_ino());
        assert_eq!(
            filesystem
                .report_register_by_ino(report_ino)
                .map(|r| &r.name),
            Some(&"Stop_Process".to_string())
        );
    }

    #[test]
    fn report_register_by_ino_returns_none_for_unrelated_inode() {
        let (filesystem, _receiver) = test_filesystem();
        assert_eq!(filesystem.report_register_by_ino(ROOT_INO), None);
    }

    #[test]
    fn coil_by_ino_resolves_a_coil_file_inode() {
        let (filesystem, _receiver) = test_filesystem();
        let coil_ino = INodeNo(filesystem.first_coil_ino());
        assert_eq!(
            filesystem.coil_by_ino(coil_ino).map(|c| &c.name),
            Some(&"Motor_Running".to_string())
        );
    }

    #[test]
    fn coil_by_ino_returns_none_for_unrelated_inode() {
        let (filesystem, _receiver) = test_filesystem();
        assert_eq!(filesystem.coil_by_ino(ROOT_INO), None);
    }

    #[test]
    fn report_coil_by_ino_resolves_a_report_file_inode() {
        let (filesystem, _receiver) = test_filesystem();
        let report_ino = INodeNo(filesystem.first_coil_report_ino());
        assert_eq!(
            filesystem.report_coil_by_ino(report_ino).map(|c| &c.name),
            Some(&"Motor_Running".to_string())
        );
    }

    #[test]
    fn report_coil_by_ino_returns_none_for_unrelated_inode() {
        let (filesystem, _receiver) = test_filesystem();
        assert_eq!(filesystem.report_coil_by_ino(ROOT_INO), None);
    }

    #[test]
    fn report_coil_by_ino_does_not_collide_with_register_report_range() {
        let (filesystem, _receiver) = test_filesystem();
        // The one register's report file sits at first_report_ino(); the
        // coil report range starts right after it. Neither lookup should
        // claim the other's inode.
        let register_report_ino = INodeNo(filesystem.first_report_ino());
        assert_eq!(filesystem.report_coil_by_ino(register_report_ino), None);
    }

    #[test]
    fn coil_content_is_empty_when_the_coil_store_has_no_value_yet() {
        let (filesystem, _receiver) = test_filesystem();
        let coil = &filesystem.coils[0];
        assert_eq!(filesystem.coil_content(coil), "");
    }

    #[test]
    fn coil_content_reflects_the_coil_store_value() {
        let (filesystem, _receiver) = test_filesystem();
        filesystem
            .coil_store_lock()
            .set("Motor_Running", crate::CoilValue(true));
        let coil = &filesystem.coils[0];
        assert_eq!(filesystem.coil_content(coil), "1\n");
    }

    #[test]
    fn parse_register_value_accepts_decimal_for_every_unsigned_type() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U8, "255"),
            Some(RegisterValue::U8(255))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U16, "65535"),
            Some(RegisterValue::U16(65535))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U32, "4000000000"),
            Some(RegisterValue::U32(4_000_000_000))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U64, "18000000000000000000"),
            Some(RegisterValue::U64(18_000_000_000_000_000_000))
        );
    }

    #[test]
    fn parse_register_value_accepts_hex_for_every_unsigned_type() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U8, "0xFF"),
            Some(RegisterValue::U8(255))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U16, "0xBEEF"),
            Some(RegisterValue::U16(0xBEEF))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U32, "0xDEADBEEF"),
            Some(RegisterValue::U32(0xDEADBEEF))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U64, "0xFFFFFFFFFFFFFFFF"),
            Some(RegisterValue::U64(u64::MAX))
        );
    }

    #[test]
    fn parse_register_value_accepts_decimal_for_every_signed_type() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I8, "-128"),
            Some(RegisterValue::I8(-128))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I16, "-32768"),
            Some(RegisterValue::I16(-32768))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I32, "-2000000000"),
            Some(RegisterValue::I32(-2_000_000_000))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I64, "-9000000000000000000"),
            Some(RegisterValue::I64(-9_000_000_000_000_000_000))
        );
    }

    #[test]
    fn parse_register_value_accepts_decimal_for_both_float_types() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::F32, "3.5"),
            Some(RegisterValue::F32(3.5))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::F64, "3.5"),
            Some(RegisterValue::F64(3.5))
        );
    }

    #[test]
    fn parse_register_value_accepts_u24_within_range_decimal_and_hex() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U24, "16777215"),
            Some(RegisterValue::U24(0x00FF_FFFF))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U24, "0xFFFFFF"),
            Some(RegisterValue::U24(0x00FF_FFFF))
        );
    }

    #[test]
    fn parse_register_value_rejects_u24_above_the_24_bit_range() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U24, "16777216"),
            None
        );
    }

    #[test]
    fn parse_register_value_accepts_i24_within_range() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I24, "-8388608"),
            Some(RegisterValue::I24(-8_388_608))
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I24, "8388607"),
            Some(RegisterValue::I24(8_388_607))
        );
    }

    #[test]
    fn parse_register_value_rejects_i24_outside_the_24_bit_range() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I24, "8388608"),
            None
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I24, "-8388609"),
            None
        );
    }

    #[test]
    fn parse_register_value_trims_whitespace() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U16, " 42\n"),
            Some(RegisterValue::U16(42))
        );
    }

    #[test]
    fn parse_register_value_rejects_garbage() {
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::U16, "not a number"),
            None
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::I32, "not a number"),
            None
        );
        assert_eq!(
            InfusedFilesystem::parse_register_value(DataType::F64, "not a number"),
            None
        );
    }

    #[test]
    fn parse_masked_register_value_accepts_hex_masks() {
        assert_eq!(
            InfusedFilesystem::parse_masked_register_value("MASK 0x00F2 0x0025"),
            Some((0x00F2, 0x0025))
        );
    }

    #[test]
    fn parse_masked_register_value_accepts_decimal_masks() {
        assert_eq!(
            InfusedFilesystem::parse_masked_register_value("MASK 242 37"),
            Some((242, 37))
        );
    }

    #[test]
    fn parse_masked_register_value_is_case_insensitive_and_trims_whitespace() {
        assert_eq!(
            InfusedFilesystem::parse_masked_register_value("  mask 0x00F2 0x0025  \n"),
            Some((0x00F2, 0x0025))
        );
    }

    #[test]
    fn parse_masked_register_value_rejects_missing_keyword() {
        assert_eq!(
            InfusedFilesystem::parse_masked_register_value("0x00F2 0x0025"),
            None
        );
    }

    #[test]
    fn parse_masked_register_value_rejects_wrong_token_count() {
        assert_eq!(
            InfusedFilesystem::parse_masked_register_value("MASK 0x00F2"),
            None
        );
        assert_eq!(
            InfusedFilesystem::parse_masked_register_value("MASK 0x00F2 0x0025 0x0000"),
            None
        );
    }

    #[test]
    fn parse_masked_register_value_rejects_garbage_masks() {
        assert_eq!(
            InfusedFilesystem::parse_masked_register_value("MASK not-a-mask 0x0025"),
            None
        );
    }

    #[test]
    fn parse_coil_value_accepts_zero_and_one() {
        assert_eq!(
            InfusedFilesystem::parse_coil_value("0"),
            Some(CoilValue(false))
        );
        assert_eq!(
            InfusedFilesystem::parse_coil_value("1"),
            Some(CoilValue(true))
        );
    }

    #[test]
    fn parse_coil_value_trims_whitespace() {
        assert_eq!(
            InfusedFilesystem::parse_coil_value(" 1\n"),
            Some(CoilValue(true))
        );
    }

    #[test]
    fn parse_coil_value_rejects_anything_else() {
        assert_eq!(InfusedFilesystem::parse_coil_value("true"), None);
        assert_eq!(InfusedFilesystem::parse_coil_value("2"), None);
        assert_eq!(InfusedFilesystem::parse_coil_value(""), None);
    }

    #[test]
    fn parse_file_record_value_accepts_space_separated_hex() {
        assert_eq!(
            InfusedFilesystem::parse_file_record_value("0D FE 00 20"),
            Some(vec![0x0D, 0xFE, 0x00, 0x20])
        );
    }

    #[test]
    fn parse_file_record_value_accepts_contiguous_hex() {
        assert_eq!(
            InfusedFilesystem::parse_file_record_value("0dfe0020"),
            Some(vec![0x0D, 0xFE, 0x00, 0x20])
        );
    }

    #[test]
    fn parse_file_record_value_trims_surrounding_whitespace() {
        assert_eq!(
            InfusedFilesystem::parse_file_record_value("\n  AB CD  \n"),
            Some(vec![0xAB, 0xCD])
        );
    }

    #[test]
    fn parse_file_record_value_rejects_odd_length() {
        assert_eq!(InfusedFilesystem::parse_file_record_value("ABC"), None);
    }

    #[test]
    fn parse_file_record_value_rejects_non_hex_characters() {
        assert_eq!(InfusedFilesystem::parse_file_record_value("ZZ"), None);
    }

    #[test]
    fn parse_file_record_value_rejects_empty_input() {
        assert_eq!(InfusedFilesystem::parse_file_record_value(""), None);
        assert_eq!(InfusedFilesystem::parse_file_record_value("   "), None);
    }

    #[test]
    fn file_record_content_defaults_to_zero_filled_bytes_when_unset() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        let description = filesystem
            .file_record_by_numbers(20, 5)
            .map(|(_, description)| description)
            .unwrap();
        assert_eq!(filesystem.file_record_content(description), "00 00 00 00\n");
    }

    #[test]
    fn file_record_content_reflects_a_stored_value() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        filesystem
            .file_record_store_lock()
            .set(20, 5, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let description = filesystem
            .file_record_by_numbers(20, 5)
            .map(|(_, description)| description)
            .unwrap();
        assert_eq!(filesystem.file_record_content(description), "DE AD BE EF\n");
    }

    #[test]
    fn first_file_number_ino_sits_right_after_file_records_ino() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        assert_eq!(
            filesystem.first_file_number_ino(),
            filesystem.file_records_ino.0 + 1
        );
    }

    #[test]
    fn file_number_by_ino_resolves_each_unique_file_number_directory() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        let first = INodeNo(filesystem.first_file_number_ino());
        let second = INodeNo(filesystem.first_file_number_ino() + 1);
        assert_eq!(filesystem.file_number_by_ino(first), Some(20));
        assert_eq!(filesystem.file_number_by_ino(second), Some(30));
    }

    #[test]
    fn file_number_by_ino_returns_none_for_an_unrelated_inode() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        assert_eq!(filesystem.file_number_by_ino(ROOT_INO), None);
    }

    #[test]
    fn file_record_by_ino_resolves_each_record_file_in_declaration_order() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        let first = INodeNo(filesystem.first_file_record_ino());
        let second = INodeNo(filesystem.first_file_record_ino() + 1);
        let third = INodeNo(filesystem.first_file_record_ino() + 2);
        assert_eq!(
            filesystem
                .file_record_by_ino(first)
                .map(|d| d.record_number),
            Some(5)
        );
        assert_eq!(
            filesystem
                .file_record_by_ino(second)
                .map(|d| d.record_number),
            Some(6)
        );
        assert_eq!(
            filesystem
                .file_record_by_ino(third)
                .map(|d| d.record_number),
            Some(1)
        );
    }

    #[test]
    fn file_record_by_ino_returns_none_for_an_unrelated_inode() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        assert_eq!(filesystem.file_record_by_ino(ROOT_INO), None);
    }

    #[test]
    fn file_record_by_numbers_resolves_the_matching_entry_and_its_inode() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        let (ino, description) = filesystem.file_record_by_numbers(20, 6).unwrap();
        assert_eq!(ino, INodeNo(filesystem.first_file_record_ino() + 1));
        assert_eq!(description.record_length, 2);
    }

    #[test]
    fn file_record_by_numbers_returns_none_for_an_unknown_combination() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        assert_eq!(filesystem.file_record_by_numbers(20, 999), None);
        assert_eq!(filesystem.file_record_by_numbers(999, 5), None);
    }

    #[test]
    fn direct_writable_by_ino_is_true_for_a_file_record_in_direct_mode() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Direct);
        let (ino, _) = filesystem.file_record_by_numbers(20, 5).unwrap();
        assert!(filesystem.direct_writable_by_ino(ino));
    }

    #[test]
    fn direct_writable_by_ino_is_false_for_a_file_record_in_staged_mode() {
        let (filesystem, _receiver) = test_filesystem_with_file_records(WriteMode::Staged);
        let (ino, _) = filesystem.file_record_by_numbers(20, 5).unwrap();
        assert!(!filesystem.direct_writable_by_ino(ino));
    }

    #[test]
    fn client_trust_is_none_when_not_constructed_with_it() {
        let (filesystem, _receiver) = test_filesystem();
        assert!(filesystem.client_trust_lock().is_none());
    }

    #[test]
    fn client_trust_lock_is_some_when_constructed_with_it() {
        let filesystem = test_filesystem_with_client_trust();
        assert!(filesystem.client_trust_lock().is_some());
    }

    #[test]
    fn client_trust_inodes_are_calibrated_past_every_fixed_inode() {
        let filesystem = test_filesystem_with_client_trust();
        assert_ne!(filesystem.client_trust_ino, filesystem.report_ino);
        assert_ne!(filesystem.client_trust_approved_ino, filesystem.report_ino);
        assert_ne!(
            filesystem.client_trust_ino,
            filesystem.client_trust_approved_ino
        );

        // The dynamic per-fingerprint inode range must start strictly
        // after both fixed client-trust/ directory inodes, same reasoning
        // as TransactionFsState.next_ino sitting past every fixed inode.
        let ino = filesystem
            .client_trust_lock()
            .unwrap()
            .insert_approved("aa:bb");
        assert!(ino.0 > filesystem.client_trust_approved_ino.0);
    }

    #[test]
    fn server_id_ino_is_calibrated_past_every_fixed_inode() {
        let filesystem = test_filesystem_with_client_trust();
        assert_ne!(filesystem.server_id_ino, filesystem.client_trust_ino);
        assert_ne!(
            filesystem.server_id_ino,
            filesystem.client_trust_approved_ino
        );
        assert_ne!(filesystem.server_id_ino, filesystem.connection_attempts_ino);
        assert_ne!(filesystem.server_id_ino, filesystem.approved_log_ino);
        assert_ne!(filesystem.server_id_ino, filesystem.pending_log_ino);
        assert_ne!(filesystem.server_id_ino, filesystem.rejected_log_ino);
    }

    #[test]
    fn server_id_content_is_empty_when_not_configured() {
        let (filesystem, _receiver) = test_filesystem_with_server_id(None);
        assert_eq!(filesystem.server_id_content(), "");
    }

    #[test]
    fn server_id_content_is_the_configured_value_with_a_trailing_newline() {
        let (filesystem, _receiver) =
            test_filesystem_with_server_id(Some("infused_modbus-demo-plc".to_string()));
        assert_eq!(filesystem.server_id_content(), "infused_modbus-demo-plc\n");
    }

    #[test]
    fn approved_fingerprint_is_resolvable_by_name_and_by_ino() {
        let filesystem = test_filesystem_with_client_trust();
        let ino = filesystem
            .client_trust_lock()
            .unwrap()
            .insert_approved("aa:bb:cc");

        let state = filesystem.client_trust_lock().unwrap();
        assert_eq!(state.ino_by_fingerprint("aa:bb:cc"), Some(ino));
        assert_eq!(state.fingerprint_by_ino(ino), Some("aa:bb:cc"));
    }

    #[test]
    fn connection_attempts_log_inodes_are_all_distinct() {
        let filesystem = test_filesystem_with_client_trust();
        let inos = [
            filesystem.client_trust_ino,
            filesystem.client_trust_approved_ino,
            filesystem.connection_attempts_ino,
            filesystem.approved_log_ino,
            filesystem.pending_log_ino,
            filesystem.rejected_log_ino,
        ];
        let unique: HashSet<INodeNo> = inos.iter().copied().collect();
        assert_eq!(unique.len(), inos.len());
    }

    #[test]
    fn connection_attempts_log_content_routes_to_the_right_ring_buffer() {
        let filesystem = test_filesystem_with_client_trust();
        {
            let mut state = filesystem.client_trust_lock().unwrap();
            state.log_approved("aa:bb");
            state.log_pending("cc:dd");
            state.log_rejected("ee:ff");
        }

        assert_eq!(
            filesystem.connection_attempts_log_content(filesystem.approved_log_ino),
            "aa:bb\n"
        );
        assert_eq!(
            filesystem.connection_attempts_log_content(filesystem.pending_log_ino),
            "cc:dd\n"
        );
        assert_eq!(
            filesystem.connection_attempts_log_content(filesystem.rejected_log_ino),
            "ee:ff\n"
        );
    }

    #[test]
    fn connection_attempts_log_content_is_empty_without_client_trust() {
        let (filesystem, _receiver) = test_filesystem();
        // Any ino at all — there's no client_trust, so every one of these
        // should behave the same (empty), not panic on an absent lock.
        assert_eq!(
            filesystem.connection_attempts_log_content(INodeNo(9999)),
            ""
        );
    }
}
