use crate::client_trust::ClientTrustState;
use crate::{
    CoilStore, CoilValue, PendingTransaction, RegisterStore, RegisterValue, StagedValue,
    WriteReport,
};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyWrite, Request,
    TimeOrNow,
};
use protocol::device_description::{CoilDescription, DataType, RegisterDescription};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

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
}

impl InfusedFilesystem {
    pub fn new(
        registers: Vec<RegisterDescription>,
        coils: Vec<CoilDescription>,
        store: Arc<Mutex<RegisterStore>>,
        coil_store: Arc<Mutex<CoilStore>>,
        transaction_sender: mpsc::Sender<HashMap<String, StagedValue>>,
        report: Arc<Mutex<WriteReport>>,
        client_trust: Option<Arc<Mutex<ClientTrustState>>>,
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
        let transactions_ino = INodeNo(first_coil_ino + coils.len() as u64);
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
        if let Some(client_trust) = &client_trust {
            client_trust
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .set_next_ino(client_trust_approved_ino.0 + 1);
        }
        Self {
            registers,
            name_to_ino,
            store,
            coils,
            coil_name_to_ino,
            coil_store,
            coils_ino,
            transactions_ino,
            transactions,
            transaction_sender,
            report_ino,
            report,
            client_trust,
            client_trust_ino,
            client_trust_approved_ino,
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

    fn parse_coil_value(text: &str) -> Option<CoilValue> {
        match text.trim() {
            "0" => Some(CoilValue(false)),
            "1" => Some(CoilValue(true)),
            _ => None,
        }
    }

    fn directory_attr(&self, ino: INodeNo, req: &Request) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn file_attr(&self, ino: INodeNo, size: u64, perm: u16, req: &Request) -> FileAttr {
        let now = SystemTime::now();
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
            uid: req.uid(),
            gid: req.gid(),
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
                Some("transactions") => {
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
                _ => reply.error(Errno::ENOENT),
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
                        &self.file_attr(ino, content.len() as u64, 0o444, req),
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
                        &self.file_attr(ino, content.len() as u64, 0o444, req),
                        Generation(0),
                    );
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        if parent == self.transactions_ino {
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
            || ino == self.transactions_ino
            || ino == self.report_ino
            || (ino == self.client_trust_ino && self.client_trust.is_some())
            || (ino == self.client_trust_approved_ino && self.client_trust.is_some())
        {
            reply.attr(&ATTR_TTL, &self.directory_attr(ino, req));
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
                &self.file_attr(ino, content.len() as u64, 0o444, req),
            );
            return;
        }

        if let Some(coil) = self.coil_by_ino(ino) {
            let content = self.coil_content(coil);
            reply.attr(
                &ATTR_TTL,
                &self.file_attr(ino, content.len() as u64, 0o444, req),
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
        // Only meaningful case here: `> transactions/Foo` truncating an
        // already-staged file before writing its new value (O_CREAT on an
        // existing name goes through open+setattr, not create). There's no
        // real backing buffer to shrink — the next `write` replaces the
        // staged value outright — so this just has to succeed and report
        // an attr back.
        let name = self.transaction_name_by_ino(ino);
        if ino == self.transactions_ino || name.is_some() {
            let content_len = name
                .map(|name| self.transaction_content(&name).len() as u64)
                .unwrap_or(0);
            let reported_size = size.unwrap_or(content_len);
            reply.attr(&ATTR_TTL, &self.file_attr(ino, reported_size, 0o644, req));
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
                    self.transactions_ino,
                    FileType::Directory,
                    "transactions".to_string(),
                ),
                (self.report_ino, FileType::Directory, "report".to_string()),
            ]
            .into_iter()
            .chain(self.client_trust.is_some().then_some((
                self.client_trust_ino,
                FileType::Directory,
                "client-trust".to_string(),
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
        } else if ino == self.transactions_ino {
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
        if parent != self.transactions_ino {
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
        if !state.ino_to_name.contains_key(&ino) {
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
                Self::parse_register_value(register.data_type, &text).map(StagedValue::Register)
            } else if self.coil_by_name(&name).is_some() {
                Self::parse_coil_value(&text).map(StagedValue::Coil)
            } else {
                None
            };
            if let Some(staged) = staged {
                state.pending.stage(name, staged);
            }
        }
        reply.ok();
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if parent != self.transactions_ino {
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
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();
        (
            InfusedFilesystem::new(registers, coils, store, coil_store, sender, report, None),
            receiver,
        )
    }

    fn test_filesystem_with_client_trust() -> InfusedFilesystem {
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, _receiver) = mpsc::channel();
        let client_trust = Arc::new(Mutex::new(ClientTrustState::new()));
        InfusedFilesystem::new(
            Vec::new(),
            Vec::new(),
            store,
            coil_store,
            sender,
            report,
            Some(client_trust),
        )
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
}
