use crate::RegisterStore;
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};
use protocol::device_description::RegisterDescription;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const ROOT_INO: INodeNo = INodeNo(1);
const DATA_INO: INodeNo = INodeNo(2);
const FIRST_REGISTER_INO: u64 = 3;

// How long the kernel may cache an entry/attr reply before asking again.
// Register values can change between our own reads (a real device is polled
// independently), so this is kept short rather than the usual much longer
// default.
const ATTR_TTL: Duration = Duration::from_secs(1);

/// A minimal, read-only FUSE projection: root -> `data` -> one file per
/// register, whose content is that register's current value in `store`.
/// No writes yet — that's the `transactions` mechanism, a later milestone.
pub struct InfusedFilesystem {
    registers: Vec<RegisterDescription>,
    name_to_ino: HashMap<String, INodeNo>,
    store: Arc<Mutex<RegisterStore>>,
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
        Self {
            registers,
            name_to_ino,
            store,
        }
    }

    fn register_by_ino(&self, ino: INodeNo) -> Option<&RegisterDescription> {
        let index = ino.0.checked_sub(FIRST_REGISTER_INO)?;
        self.registers.get(index as usize)
    }

    fn register_content(&self, register: &RegisterDescription) -> String {
        match self.store.lock().unwrap().get(&register.name) {
            Some(value) => format!("{value}\n"),
            None => String::new(),
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

    fn file_attr(&self, ino: INodeNo, size: u64, req: &Request) -> FileAttr {
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
            // Read-only for every register regardless of its own declared
            // AccessRight: nothing can write through this filesystem yet at
            // all (that's the `transactions` mechanism, a later milestone),
            // so there's no meaningful distinction to make here yet.
            perm: 0o444,
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
            if name == "data" {
                reply.entry(
                    &ATTR_TTL,
                    &self.directory_attr(DATA_INO, req),
                    Generation(0),
                );
            } else {
                reply.error(Errno::ENOENT);
            }
            return;
        }

        if parent == DATA_INO {
            let register = name
                .to_str()
                .and_then(|name| self.name_to_ino.get(name))
                .and_then(|&ino| self.register_by_ino(ino).map(|register| (ino, register)));
            match register {
                Some((ino, register)) => {
                    let content = self.register_content(register);
                    reply.entry(
                        &ATTR_TTL,
                        &self.file_attr(ino, content.len() as u64, req),
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
        if ino == ROOT_INO || ino == DATA_INO {
            reply.attr(&ATTR_TTL, &self.directory_attr(ino, req));
            return;
        }

        match self.register_by_ino(ino) {
            Some(register) => {
                let content = self.register_content(register);
                reply.attr(&ATTR_TTL, &self.file_attr(ino, content.len() as u64, req));
            }
            None => reply.error(Errno::ENOENT),
        }
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
        let Some(register) = self.register_by_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let content = self.register_content(register);
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
                (DATA_INO, FileType::Directory, "data".to_string()),
            ]
        } else if ino == DATA_INO {
            let mut entries = vec![
                (DATA_INO, FileType::Directory, ".".to_string()),
                (ROOT_INO, FileType::Directory, "..".to_string()),
            ];
            for register in &self.registers {
                let register_ino = self.name_to_ino[&register.name];
                entries.push((register_ino, FileType::RegularFile, register.name.clone()));
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
}
