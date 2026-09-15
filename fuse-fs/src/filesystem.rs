use crate::{PendingTransaction, RegisterStore, RegisterValue};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyWrite, Request,
    TimeOrNow,
};
use protocol::device_description::{DataType, RegisterDescription};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

const ROOT_INO: INodeNo = INodeNo(1);
const HOLDING_REGISTERS_INO: INodeNo = INodeNo(2);
const FIRST_REGISTER_INO: u64 = 3;

// How long the kernel may cache an entry/attr reply before asking again.
// Register values can change between our own reads (a real device is polled
// independently), so this is kept short rather than the usual much longer
// default.
const ATTR_TTL: Duration = Duration::from_secs(1);

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
}

/// A minimal FUSE projection: root -> `holding-registers` -> one read-only
/// file per register (current value from `store`), and root ->
/// `transactions` -> user-created files that stage a pending write per the scheme in
/// CLAUDE.md (filename = register name, content = value to write).
/// Draining a transaction on `TRANSACTION_END` (Milestone H2) isn't wired up
/// yet, so staged writes currently just sit in `PendingTransaction` and are
/// only visible by reading them back.
pub struct InfusedFilesystem {
    registers: Vec<RegisterDescription>,
    name_to_ino: HashMap<String, INodeNo>,
    store: Arc<Mutex<RegisterStore>>,
    transactions_ino: INodeNo,
    transactions: Mutex<TransactionFsState>,
}

impl InfusedFilesystem {
    pub fn new(registers: Vec<RegisterDescription>, store: Arc<Mutex<RegisterStore>>) -> Self {
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
        let transactions_ino = INodeNo(FIRST_REGISTER_INO + registers.len() as u64);
        let transactions = Mutex::new(TransactionFsState {
            next_ino: transactions_ino.0 + 1,
            ..Default::default()
        });
        Self {
            registers,
            name_to_ino,
            store,
            transactions_ino,
            transactions,
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

    fn register_by_ino(&self, ino: INodeNo) -> Option<&RegisterDescription> {
        let index = ino.0.checked_sub(FIRST_REGISTER_INO)?;
        self.registers.get(index as usize)
    }

    fn register_by_name(&self, name: &str) -> Option<&RegisterDescription> {
        self.registers.iter().find(|register| register.name == name)
    }

    fn register_content(&self, register: &RegisterDescription) -> String {
        match self.store_lock().get(&register.name) {
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

    // Resolves a transaction file's inode back to its register name. Used
    // by every trait method that has to tell "this ino is a staged
    // transaction file" apart from "this ino doesn't exist" — `getattr`,
    // `setattr`, and `read` all needed this exact lookup.
    fn transaction_name_by_ino(&self, ino: INodeNo) -> Option<String> {
        self.transactions_lock().ino_to_name.get(&ino).cloned()
    }

    fn parse_register_value(data_type: DataType, text: &str) -> Option<RegisterValue> {
        let text = text.trim();
        match data_type {
            DataType::U16 => {
                let value = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    Some(hex) => u16::from_str_radix(hex, 16).ok()?,
                    None => text.parse().ok()?,
                };
                Some(RegisterValue::U16(value))
            }
            DataType::F32 => Some(RegisterValue::F32(text.parse().ok()?)),
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
                Some("transactions") => {
                    reply.entry(
                        &ATTR_TTL,
                        &self.directory_attr(self.transactions_ino, req),
                        Generation(0),
                    );
                }
                _ => reply.error(Errno::ENOENT),
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

        reply.error(Errno::ENOENT);
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino == ROOT_INO || ino == HOLDING_REGISTERS_INO || ino == self.transactions_ino {
            reply.attr(&ATTR_TTL, &self.directory_attr(ino, req));
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
        } else {
            // The lock must be released before `transaction_content` tries
            // to take it again — std::sync::Mutex isn't reentrant, so
            // holding this guard through that call (as a direct `if let`
            // condition would, since its temporary lives for the whole
            // `if let` body) deadlocks.
            match self.transaction_name_by_ino(ino) {
                Some(name) => self.transaction_content(&name),
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
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
                (
                    self.transactions_ino,
                    FileType::Directory,
                    "transactions".to_string(),
                ),
            ]
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
        if self.register_by_name(name).is_none() {
            // Staging a value only makes sense for a real register.
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
            && let Some(register) = self.register_by_name(&name)
            && let Ok(text) = String::from_utf8(buffer)
            && let Some(value) = Self::parse_register_value(register.data_type, &text)
        {
            state.pending.stage(name, value);
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
