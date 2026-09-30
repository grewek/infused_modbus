pub mod client_trust;
pub mod filesystem;
pub mod flatfile;
pub mod permissions;
pub mod register_encoding;

use protocol::device_description::{DataType, MachineDescription};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

// Mirrors protocol::device_description::DataType — a register's value is
// whichever of these its TOML description declares it to be. U24/I24 have
// no native Rust type, so they're stored in the next-larger native integer
// (u32/i32) with the value always kept within the 24-bit range — see
// datafs::filesystem::InfusedFilesystem::parse_register_value, the one
// place that constructs a RegisterValue from user/text input and enforces
// that range.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegisterValue {
    U8(u8),
    I8(i8),
    U16(u16),
    I16(i16),
    U24(u32),
    I24(i32),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl RegisterValue {
    /// The DataType this value was decoded/parsed as — the inverse of
    /// looking a value up by a register's own declared `data_type`, useful
    /// wherever a value needs to be checked against what its register
    /// actually declares rather than trusted blindly (e.g. a stored value
    /// that should always match its register's type, but is worth
    /// verifying rather than assuming).
    pub fn data_type(&self) -> DataType {
        match self {
            RegisterValue::U8(_) => DataType::U8,
            RegisterValue::I8(_) => DataType::I8,
            RegisterValue::U16(_) => DataType::U16,
            RegisterValue::I16(_) => DataType::I16,
            RegisterValue::U24(_) => DataType::U24,
            RegisterValue::I24(_) => DataType::I24,
            RegisterValue::U32(_) => DataType::U32,
            RegisterValue::I32(_) => DataType::I32,
            RegisterValue::U64(_) => DataType::U64,
            RegisterValue::I64(_) => DataType::I64,
            RegisterValue::F32(_) => DataType::F32,
            RegisterValue::F64(_) => DataType::F64,
        }
    }
}

// How a register's value is rendered as the content of its FUSE file.
impl fmt::Display for RegisterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterValue::U8(value) => write!(formatter, "{value}"),
            RegisterValue::I8(value) => write!(formatter, "{value}"),
            RegisterValue::U16(value) => write!(formatter, "{value}"),
            RegisterValue::I16(value) => write!(formatter, "{value}"),
            RegisterValue::U24(value) => write!(formatter, "{value}"),
            RegisterValue::I24(value) => write!(formatter, "{value}"),
            RegisterValue::U32(value) => write!(formatter, "{value}"),
            RegisterValue::I32(value) => write!(formatter, "{value}"),
            RegisterValue::U64(value) => write!(formatter, "{value}"),
            RegisterValue::I64(value) => write!(formatter, "{value}"),
            RegisterValue::F32(value) => write!(formatter, "{value}"),
            RegisterValue::F64(value) => write!(formatter, "{value}"),
        }
    }
}

// Zero (or 0.0) for every DataType — what an unset register reads back as,
// same meaning "no value staged/confirmed yet" as U16's old bare `0` did.
// Moved here from server::handler (M5 of the MQTT/Sparkplug design) once
// client::sparkplug_translator needed the exact same "unset register renders
// as a typed zero" behavior for building DBIRTH payloads — a second concrete
// consumer, per this project's Extraction-Based Programming convention.
pub fn default_register_value(data_type: DataType) -> RegisterValue {
    match data_type {
        DataType::U8 => RegisterValue::U8(0),
        DataType::I8 => RegisterValue::I8(0),
        DataType::U16 => RegisterValue::U16(0),
        DataType::I16 => RegisterValue::I16(0),
        DataType::U24 => RegisterValue::U24(0),
        DataType::I24 => RegisterValue::I24(0),
        DataType::U32 => RegisterValue::U32(0),
        DataType::I32 => RegisterValue::I32(0),
        DataType::U64 => RegisterValue::U64(0),
        DataType::I64 => RegisterValue::I64(0),
        DataType::F32 => RegisterValue::F32(0.0),
        DataType::F64 => RegisterValue::F64(0.0),
    }
}

// The shared state between protocol I/O (which updates values from what a
// real device reports) and the FUSE layer (which reads/writes them by name).
// Not thread-safe on its own — how it gets wrapped for concurrent access
// depends on how the FUSE integration (Milestone G) ends up calling into it,
// which isn't decided yet.
#[derive(Debug, Default)]
pub struct RegisterStore {
    values: HashMap<String, RegisterValue>,
}

impl RegisterStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<RegisterValue> {
        self.values.get(name).copied()
    }

    pub fn set(&mut self, name: impl Into<String>, value: RegisterValue) {
        self.values.insert(name.into(), value);
    }
}

// How a value is rendered as file content, shared by every store-backed data
// type and every presentation layer that needs to show one: empty until the
// store has a value (nothing polled/written yet), `"<value>\n"` once it
// does. Extracted once a second, non-FUSE consumer (`flatfile`) needed the
// exact same rendering `filesystem::MachineFs`'s own per-type `*_content`
// methods already had.
fn file_content<T: fmt::Display>(value: Option<T>) -> String {
    match value {
        Some(value) => format!("{value}\n"),
        None => String::new(),
    }
}

pub fn register_file_content(store: &RegisterStore, name: &str) -> String {
    file_content(store.get(name))
}

// Mirrors RegisterStore exactly, keyed by input-register name instead of
// holding-register name. Reuses RegisterValue rather than a new type, since
// input registers (FC 4) can be any of the same DataType range as holding
// registers — the only real difference is that no Modbus function code ever
// lets a master write one, which is a property of who's allowed to call
// `set` (client: only its own polling loop; server: only its own local
// write path), not of the value's shape.
#[derive(Debug, Default)]
pub struct InputRegisterStore {
    values: HashMap<String, RegisterValue>,
}

impl InputRegisterStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<RegisterValue> {
        self.values.get(name).copied()
    }

    pub fn set(&mut self, name: impl Into<String>, value: RegisterValue) {
        self.values.insert(name.into(), value);
    }
}

pub fn input_register_file_content(store: &InputRegisterStore, name: &str) -> String {
    file_content(store.get(name))
}

// A coil's value. Always exactly one bit — unlike RegisterValue there's only
// ever one shape, since protocol::device_description::CoilDescription has no
// data_type — but still a newtype rather than a bare `bool`, so its FUSE file
// rendering ("0"/"1", not Rust's "true"/"false" — see CLAUDE.md's FUSE
// layout section) has one canonical place to live, same as RegisterValue's
// Display below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoilValue(pub bool);

impl fmt::Display for CoilValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", if self.0 { "1" } else { "0" })
    }
}

// Mirrors RegisterStore exactly, keyed by coil name instead of register
// name. Kept as its own store rather than folded into RegisterStore, since
// the two are keyed from separate DeviceDescription fields (registers vs.
// coils) and there's no concrete need yet for a single lookup spanning both.
#[derive(Debug, Default)]
pub struct CoilStore {
    values: HashMap<String, CoilValue>,
}

impl CoilStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<CoilValue> {
        self.values.get(name).copied()
    }

    pub fn set(&mut self, name: impl Into<String>, value: CoilValue) {
        self.values.insert(name.into(), value);
    }
}

pub fn coil_file_content(store: &CoilStore, name: &str) -> String {
    file_content(store.get(name))
}

// Mirrors CoilStore exactly, keyed by discrete-input name instead of coil
// name. Reuses CoilValue rather than a new single-bit type, for the same
// reason InputRegisterStore reuses RegisterValue above — discrete inputs
// (FC 2) are bit-shaped identically to coils, only the write-permission
// story around `set` differs.
#[derive(Debug, Default)]
pub struct DiscreteInputStore {
    values: HashMap<String, CoilValue>,
}

impl DiscreteInputStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<CoilValue> {
        self.values.get(name).copied()
    }

    pub fn set(&mut self, name: impl Into<String>, value: CoilValue) {
        self.values.insert(name.into(), value);
    }
}

pub fn discrete_input_file_content(store: &DiscreteInputStore, name: &str) -> String {
    file_content(store.get(name))
}

// Keyed by (file_number, record_number) rather than a name — file records
// (FC 0x14/0x15) have no `name` field at all, see
// protocol::device_description::FileRecordDescription's own doc comment.
// Values are raw, uninterpreted bytes (see CLAUDE.md's "FC 0x14 (Read File
// Record)" section) — unlike RegisterValue/CoilValue there's no typed
// shape to store, just whatever bytes were last written.
#[derive(Debug, Default)]
pub struct FileRecordStore {
    values: HashMap<(u16, u16), Vec<u8>>,
}

impl FileRecordStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, file_number: u16, record_number: u16) -> Option<&Vec<u8>> {
        self.values.get(&(file_number, record_number))
    }

    pub fn set(&mut self, file_number: u16, record_number: u16, value: Vec<u8>) {
        self.values.insert((file_number, record_number), value);
    }
}

// How a file record's file content is rendered: a space-separated uppercase
// hex dump, defaulting to `2 * record_length` zero bytes until directly
// written — same "declared but unset = zero" precedent as every other
// store-backed data type, just with a record's own declared width standing
// in for a fixed per-DataType default. Extracted for the same reason
// `register_file_content` was: a second, non-FUSE consumer needs the exact
// same rendering `filesystem::MachineFs::file_record_content` already had.
pub fn file_record_file_content(
    store: &FileRecordStore,
    file_number: u16,
    record_number: u16,
    record_length: u16,
) -> String {
    let bytes = store
        .get(file_number, record_number)
        .cloned()
        .unwrap_or_else(|| vec![0u8; record_length as usize * 2]);
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{hex}\n")
}

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

// Parses a `transactions/<name>` file's content into the RegisterValue its
// register's own declared DataType calls for — shared by every presentation
// layer that stages a plain register write, not just FUSE's `create`/
// `write`/`release` (which is where this used to live before the `flatfile`
// backend needed the exact same parsing).
pub fn parse_register_value(data_type: DataType, text: &str) -> Option<RegisterValue> {
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
pub fn parse_masked_register_value(text: &str) -> Option<(u16, u16)> {
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

pub fn parse_coil_value(text: &str) -> Option<CoilValue> {
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
// The `transactions/<file_number>:<record_number>` naming a client
// stages a Write File Record (FC 0x15) through — same colon-separated
// synthetic identifier as `file_record_report_name`, but parsed back
// here rather than just constructed, since this is the one place a
// human actually types it in. Not itself a membership check — callers
// still verify the parsed numbers name a real configured file record.
pub fn parse_file_record_name(name: &str) -> Option<(u16, u16)> {
    let (file_number, record_number) = name.split_once(':')?;
    Some((file_number.parse().ok()?, record_number.parse().ok()?))
}

pub fn parse_file_record_value(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|start| u8::from_str_radix(&cleaned[start..start + 2], 16).ok())
        .collect()
}

// A value staged in `transactions/`, before TRANSACTION_END hands it off to
// be confirmed against the real device. Wraps whichever of RegisterValue or
// CoilValue matches the name being staged — CLAUDE.md's transactions design
// describes one directory shared across Modbus data types, not one per
// type, so PendingTransaction (and the TRANSACTION_END hand-off channel)
// need one value type that can hold either.
#[derive(Debug, Clone, PartialEq)]
pub enum StagedValue {
    Register(RegisterValue),
    Coil(CoilValue),
    // Only ever produced by the server's direct-write path (WriteMode::
    // Direct) — see datafs::filesystem's "server direct-write model" doc
    // comment. The client never constructs these: it has no write path at
    // all for discrete inputs/input registers, staged or direct.
    DiscreteInput(CoilValue),
    InputRegister(RegisterValue),
    // Staged via `transactions/<name>`'s `MASK <and_mask> <or_mask>`
    // content form (see InfusedFilesystem::parse_masked_register_value) —
    // client-only, mirroring Modbus's own Mask Write Register (FC 0x16),
    // which only a master ever sends. The server never constructs this:
    // its direct-write path (WriteMode::Direct) has no `transactions/` to
    // stage one from, and doesn't try MASK-parsing on a plain
    // `holding-registers/<name>` write either.
    MaskedRegister {
        and_mask: u16,
        or_mask: u16,
    },
    // Only ever produced by the server's direct-write path
    // (`file-records/<file_number>/<record_number>`), same "server-only,
    // client has no write path at all" story as `DiscreteInput`/
    // `InputRegister` above — no Modbus function code lets a master write
    // one either (FC 0x15/Write File Record isn't implemented). Carries
    // `file_number`/`record_number` directly rather than relying on the
    // channel's own String key to identify which record this is, since
    // `FileRecordStore::set` needs both numbers, not a name.
    FileRecord {
        file_number: u16,
        record_number: u16,
        value: Vec<u8>,
    },
}

impl fmt::Display for StagedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StagedValue::Register(value) => write!(formatter, "{value}"),
            StagedValue::Coil(value) => write!(formatter, "{value}"),
            StagedValue::DiscreteInput(value) => write!(formatter, "{value}"),
            StagedValue::InputRegister(value) => write!(formatter, "{value}"),
            StagedValue::MaskedRegister { and_mask, or_mask } => {
                write!(formatter, "MASK 0x{and_mask:04X} 0x{or_mask:04X}")
            }
            StagedValue::FileRecord { value, .. } => {
                for byte in value {
                    write!(formatter, "{byte:02X} ")?;
                }
                Ok(())
            }
        }
    }
}

// Staged writes for one in-progress transaction: creating a file in
// `transactions/` and writing a value to it stages a name=value entry here;
// creating `TRANSACTION_END` (Milestone H2, not implemented yet) drains this
// and applies it to a RegisterStore/CoilStore. Plain data structure, no FUSE
// awareness — mirrors how RegisterStore (F1) preceded its own FUSE wiring
// (G1).
#[derive(Debug, Default)]
pub struct PendingTransaction {
    staged: HashMap<String, StagedValue>,
}

impl PendingTransaction {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stage(&mut self, name: impl Into<String>, value: StagedValue) {
        self.staged.insert(name.into(), value);
    }

    pub fn get(&self, name: &str) -> Option<StagedValue> {
        self.staged.get(name).cloned()
    }

    pub fn unstage(&mut self, name: &str) -> Option<StagedValue> {
        self.staged.remove(name)
    }

    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    // Takes every staged value out at once, leaving the transaction empty —
    // what `TRANSACTION_END` needs to atomically hand off everything staged
    // so far to be applied to a RegisterStore/CoilStore.
    pub fn drain(&mut self) -> HashMap<String, StagedValue> {
        std::mem::take(&mut self.staged)
    }
}

// Outcome of the most recent write attempt for one register. Deliberately
// just a status word, not a structured error with timestamp/Modbus
// exception code — see CLAUDE.md's Milestone H3 notes for why the richer
// version was deferred until a real confirmed-write consumer exists to show
// what it would actually need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteStatus {
    Ok,
    Failed(String),
}

// How a write status is rendered as the content of its `Report/` file.
impl fmt::Display for WriteStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteStatus::Ok => write!(formatter, "OK"),
            WriteStatus::Failed(reason) => write!(formatter, "FAILED: {reason}"),
        }
    }
}

// Per-register write outcomes, keyed by register name — mirrors
// RegisterStore's shape exactly, but holds the result of the last write
// attempt rather than the current value. Whoever confirms or fails a write
// (client/server, once wired to `protocol`) reports it here; a new attempt
// simply overwrites the previous outcome, so `Report/<name>` always
// reflects only the most recent attempt. Plain data structure, no FUSE
// awareness — mirrors how RegisterStore (F1) and PendingTransaction (H1)
// preceded their own FUSE wiring.
#[derive(Debug, Default)]
pub struct WriteReport {
    statuses: HashMap<String, WriteStatus>,
}

impl WriteReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&WriteStatus> {
        self.statuses.get(name)
    }

    pub fn set(&mut self, name: impl Into<String>, status: WriteStatus) {
        self.statuses.insert(name.into(), status);
    }
}

// How a `report/<name>` file's content is rendered: empty until a write has
// been attempted for that name, `"<status>\n"` once one has — same "empty
// until set" shape every other store-backed data type's file content
// already has. Extracted for the same reason `register_file_content` etc.
// were: a second, non-FUSE consumer needed the exact same rendering
// `filesystem::MachineFs::report_content` already had.
pub fn report_file_content(report: &WriteReport, name: &str) -> String {
    file_content(report.get(name))
}

// Bundles one instance of every per-machine store type + its write report —
// see CLAUDE.md's "Planned: multi-machine device description & FUSE layout"
// section. A multi-machine deployment holds one of these per configured
// machine name rather than each of `InfusedFilesystem`'s constructor/
// polling/transaction-consumer call sites separately threading five (now
// six) individual stores through per machine. Every field is already
// `Arc<Mutex<_>>` exactly as it was before this bundling, so cloning a
// `MachineStores` handle is cheap and every clone still refers to the same
// underlying data — needed since `InfusedFilesystem`, polling, and the
// transaction consumer all need to see the same machine's stores.
#[derive(Debug, Clone)]
pub struct MachineStores {
    pub registers: Arc<Mutex<RegisterStore>>,
    pub coils: Arc<Mutex<CoilStore>>,
    pub discrete_inputs: Arc<Mutex<DiscreteInputStore>>,
    pub input_registers: Arc<Mutex<InputRegisterStore>>,
    pub file_records: Arc<Mutex<FileRecordStore>>,
    pub report: Arc<Mutex<WriteReport>>,
}

impl MachineStores {
    pub fn new() -> Self {
        Self {
            registers: Arc::new(Mutex::new(RegisterStore::new())),
            coils: Arc::new(Mutex::new(CoilStore::new())),
            discrete_inputs: Arc::new(Mutex::new(DiscreteInputStore::new())),
            input_registers: Arc::new(Mutex::new(InputRegisterStore::new())),
            file_records: Arc::new(Mutex::new(FileRecordStore::new())),
            report: Arc::new(Mutex::new(WriteReport::new())),
        }
    }
}

impl Default for MachineStores {
    fn default() -> Self {
        Self::new()
    }
}

// One fresh `MachineStores` per configured machine, keyed by machine name —
// the construction step both `client` and `server` need identically once
// they build their `InfusedFilesystem`/polling/transaction-consumer setup
// per machine, so it's extracted here rather than duplicated in both
// binaries' `main.rs`.
pub fn build_machine_stores(machines: &[MachineDescription]) -> HashMap<String, MachineStores> {
    machines
        .iter()
        .map(|machine| (machine.name.clone(), MachineStores::new()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_for_unknown_register() {
        let store = RegisterStore::new();
        assert_eq!(store.get("Tank_Temperature"), None);
    }

    #[test]
    fn set_then_get_returns_the_value() {
        let mut store = RegisterStore::new();
        store.set("Tank_Temperature", RegisterValue::U16(42));
        assert_eq!(store.get("Tank_Temperature"), Some(RegisterValue::U16(42)));
    }

    #[test]
    fn set_then_get_returns_an_f32_value() {
        let mut store = RegisterStore::new();
        store.set("Flow_Rate", RegisterValue::F32(3.5));
        assert_eq!(store.get("Flow_Rate"), Some(RegisterValue::F32(3.5)));
    }

    #[test]
    fn set_overwrites_previous_value() {
        let mut store = RegisterStore::new();
        store.set("Tank_Temperature", RegisterValue::U16(42));
        store.set("Tank_Temperature", RegisterValue::U16(43));
        assert_eq!(store.get("Tank_Temperature"), Some(RegisterValue::U16(43)));
    }

    #[test]
    fn u16_value_displays_as_plain_decimal() {
        assert_eq!(RegisterValue::U16(42).to_string(), "42");
    }

    #[test]
    fn f32_value_displays_as_plain_decimal() {
        assert_eq!(RegisterValue::F32(3.5).to_string(), "3.5");
    }

    #[test]
    fn data_type_returns_the_matching_variant_for_every_type() {
        assert_eq!(RegisterValue::U8(0).data_type(), DataType::U8);
        assert_eq!(RegisterValue::I8(0).data_type(), DataType::I8);
        assert_eq!(RegisterValue::U16(0).data_type(), DataType::U16);
        assert_eq!(RegisterValue::I16(0).data_type(), DataType::I16);
        assert_eq!(RegisterValue::U24(0).data_type(), DataType::U24);
        assert_eq!(RegisterValue::I24(0).data_type(), DataType::I24);
        assert_eq!(RegisterValue::U32(0).data_type(), DataType::U32);
        assert_eq!(RegisterValue::I32(0).data_type(), DataType::I32);
        assert_eq!(RegisterValue::U64(0).data_type(), DataType::U64);
        assert_eq!(RegisterValue::I64(0).data_type(), DataType::I64);
        assert_eq!(RegisterValue::F32(0.0).data_type(), DataType::F32);
        assert_eq!(RegisterValue::F64(0.0).data_type(), DataType::F64);
    }

    #[test]
    fn every_new_register_value_variant_displays_as_plain_decimal() {
        assert_eq!(RegisterValue::U8(255).to_string(), "255");
        assert_eq!(RegisterValue::I8(-128).to_string(), "-128");
        assert_eq!(RegisterValue::I16(-1234).to_string(), "-1234");
        assert_eq!(RegisterValue::U24(0x00FF_FFFF).to_string(), "16777215");
        assert_eq!(RegisterValue::I24(-8_388_608).to_string(), "-8388608");
        assert_eq!(RegisterValue::U32(4_000_000_000).to_string(), "4000000000");
        assert_eq!(
            RegisterValue::I32(-2_000_000_000).to_string(),
            "-2000000000"
        );
        assert_eq!(
            RegisterValue::U64(18_000_000_000_000_000_000).to_string(),
            "18000000000000000000"
        );
        assert_eq!(
            RegisterValue::I64(-9_000_000_000_000_000_000).to_string(),
            "-9000000000000000000"
        );
        assert_eq!(RegisterValue::F64(3.5).to_string(), "3.5");
    }

    #[test]
    fn coil_store_get_returns_none_for_unknown_coil() {
        let store = CoilStore::new();
        assert_eq!(store.get("Motor_Running"), None);
    }

    #[test]
    fn coil_store_set_then_get_returns_the_value() {
        let mut store = CoilStore::new();
        store.set("Motor_Running", CoilValue(true));
        assert_eq!(store.get("Motor_Running"), Some(CoilValue(true)));
    }

    #[test]
    fn coil_store_set_overwrites_previous_value() {
        let mut store = CoilStore::new();
        store.set("Motor_Running", CoilValue(true));
        store.set("Motor_Running", CoilValue(false));
        assert_eq!(store.get("Motor_Running"), Some(CoilValue(false)));
    }

    #[test]
    fn coil_value_true_displays_as_one() {
        assert_eq!(CoilValue(true).to_string(), "1");
    }

    #[test]
    fn coil_value_false_displays_as_zero() {
        assert_eq!(CoilValue(false).to_string(), "0");
    }

    #[test]
    fn input_register_store_get_returns_none_for_unknown_register() {
        let store = InputRegisterStore::new();
        assert_eq!(store.get("Flow_Rate"), None);
    }

    #[test]
    fn input_register_store_set_then_get_returns_the_value() {
        let mut store = InputRegisterStore::new();
        store.set("Flow_Rate", RegisterValue::F32(3.5));
        assert_eq!(store.get("Flow_Rate"), Some(RegisterValue::F32(3.5)));
    }

    #[test]
    fn input_register_store_set_overwrites_previous_value() {
        let mut store = InputRegisterStore::new();
        store.set("Flow_Rate", RegisterValue::F32(3.5));
        store.set("Flow_Rate", RegisterValue::F32(4.0));
        assert_eq!(store.get("Flow_Rate"), Some(RegisterValue::F32(4.0)));
    }

    #[test]
    fn discrete_input_store_get_returns_none_for_unknown_input() {
        let store = DiscreteInputStore::new();
        assert_eq!(store.get("Door_Open_Sensor"), None);
    }

    #[test]
    fn discrete_input_store_set_then_get_returns_the_value() {
        let mut store = DiscreteInputStore::new();
        store.set("Door_Open_Sensor", CoilValue(true));
        assert_eq!(store.get("Door_Open_Sensor"), Some(CoilValue(true)));
    }

    #[test]
    fn discrete_input_store_set_overwrites_previous_value() {
        let mut store = DiscreteInputStore::new();
        store.set("Door_Open_Sensor", CoilValue(true));
        store.set("Door_Open_Sensor", CoilValue(false));
        assert_eq!(store.get("Door_Open_Sensor"), Some(CoilValue(false)));
    }

    #[test]
    fn pending_transaction_get_returns_none_for_unstaged_register() {
        let transaction = PendingTransaction::new();
        assert_eq!(transaction.get("Stop_Process"), None);
    }

    #[test]
    fn pending_transaction_stage_then_get_returns_the_value() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Stop_Process", StagedValue::Register(RegisterValue::U16(1)));
        assert_eq!(
            transaction.get("Stop_Process"),
            Some(StagedValue::Register(RegisterValue::U16(1)))
        );
    }

    #[test]
    fn pending_transaction_stage_overwrites_previous_value() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Stop_Process", StagedValue::Register(RegisterValue::U16(1)));
        transaction.stage("Stop_Process", StagedValue::Register(RegisterValue::U16(0)));
        assert_eq!(
            transaction.get("Stop_Process"),
            Some(StagedValue::Register(RegisterValue::U16(0)))
        );
    }

    #[test]
    fn pending_transaction_unstage_removes_a_staged_value() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Stop_Process", StagedValue::Register(RegisterValue::U16(1)));
        assert_eq!(
            transaction.unstage("Stop_Process"),
            Some(StagedValue::Register(RegisterValue::U16(1)))
        );
        assert_eq!(transaction.get("Stop_Process"), None);
    }

    #[test]
    fn pending_transaction_is_empty_reflects_staged_state() {
        let mut transaction = PendingTransaction::new();
        assert!(transaction.is_empty());
        transaction.stage("Stop_Process", StagedValue::Register(RegisterValue::U16(1)));
        assert!(!transaction.is_empty());
        transaction.unstage("Stop_Process");
        assert!(transaction.is_empty());
    }

    #[test]
    fn pending_transaction_stage_accepts_a_coil_value_too() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Motor_Running", StagedValue::Coil(CoilValue(true)));
        assert_eq!(
            transaction.get("Motor_Running"),
            Some(StagedValue::Coil(CoilValue(true)))
        );
    }

    #[test]
    fn pending_transaction_drain_returns_staged_values_and_empties_transaction() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Stop_Process", StagedValue::Register(RegisterValue::U16(1)));
        transaction.stage("Flow_Rate", StagedValue::Register(RegisterValue::F32(3.5)));

        let drained = transaction.drain();

        assert_eq!(
            drained.get("Stop_Process"),
            Some(&StagedValue::Register(RegisterValue::U16(1)))
        );
        assert_eq!(
            drained.get("Flow_Rate"),
            Some(&StagedValue::Register(RegisterValue::F32(3.5)))
        );
        assert_eq!(drained.len(), 2);
        assert!(transaction.is_empty());
    }

    #[test]
    fn staged_value_register_displays_like_the_wrapped_register_value() {
        assert_eq!(
            StagedValue::Register(RegisterValue::U16(42)).to_string(),
            "42"
        );
    }

    #[test]
    fn staged_value_coil_displays_like_the_wrapped_coil_value() {
        assert_eq!(StagedValue::Coil(CoilValue(true)).to_string(), "1");
    }

    #[test]
    fn staged_value_discrete_input_displays_like_the_wrapped_coil_value() {
        assert_eq!(
            StagedValue::DiscreteInput(CoilValue(false)).to_string(),
            "0"
        );
    }

    #[test]
    fn staged_value_input_register_displays_like_the_wrapped_register_value() {
        assert_eq!(
            StagedValue::InputRegister(RegisterValue::F32(3.5)).to_string(),
            "3.5"
        );
    }

    #[test]
    fn staged_value_masked_register_displays_as_mask_with_hex_masks() {
        assert_eq!(
            StagedValue::MaskedRegister {
                and_mask: 0x00F2,
                or_mask: 0x0025,
            }
            .to_string(),
            "MASK 0x00F2 0x0025"
        );
    }

    #[test]
    fn write_report_get_returns_none_for_unknown_register() {
        let report = WriteReport::new();
        assert_eq!(report.get("Stop_Process"), None);
    }

    #[test]
    fn write_report_set_then_get_returns_the_status() {
        let mut report = WriteReport::new();
        report.set("Stop_Process", WriteStatus::Ok);
        assert_eq!(report.get("Stop_Process"), Some(&WriteStatus::Ok));
    }

    #[test]
    fn write_report_set_overwrites_previous_status() {
        let mut report = WriteReport::new();
        report.set("Stop_Process", WriteStatus::Ok);
        report.set(
            "Stop_Process",
            WriteStatus::Failed("device timed out".to_string()),
        );
        assert_eq!(
            report.get("Stop_Process"),
            Some(&WriteStatus::Failed("device timed out".to_string()))
        );
    }

    #[test]
    fn write_status_ok_displays_as_ok() {
        assert_eq!(WriteStatus::Ok.to_string(), "OK");
    }

    #[test]
    fn write_status_failed_displays_reason() {
        assert_eq!(
            WriteStatus::Failed("device timed out".to_string()).to_string(),
            "FAILED: device timed out"
        );
    }

    #[test]
    fn file_record_store_get_returns_none_for_an_unset_combination() {
        let store = FileRecordStore::new();
        assert_eq!(store.get(20, 5), None);
    }

    #[test]
    fn file_record_store_set_then_get_returns_the_value() {
        let mut store = FileRecordStore::new();
        store.set(20, 5, vec![0xDE, 0xAD]);
        assert_eq!(store.get(20, 5), Some(&vec![0xDE, 0xAD]));
    }

    #[test]
    fn file_record_store_keys_are_independent_per_file_and_record_number() {
        let mut store = FileRecordStore::new();
        store.set(20, 5, vec![0x01]);
        store.set(20, 6, vec![0x02]);
        store.set(30, 5, vec![0x03]);
        assert_eq!(store.get(20, 5), Some(&vec![0x01]));
        assert_eq!(store.get(20, 6), Some(&vec![0x02]));
        assert_eq!(store.get(30, 5), Some(&vec![0x03]));
    }

    #[test]
    fn file_record_store_set_overwrites_previous_value() {
        let mut store = FileRecordStore::new();
        store.set(20, 5, vec![0x01]);
        store.set(20, 5, vec![0x02]);
        assert_eq!(store.get(20, 5), Some(&vec![0x02]));
    }

    fn minimal_machine(name: &str) -> MachineDescription {
        MachineDescription {
            name: name.to_string(),
            unit_id: 1,
            registers: vec![],
            coils: vec![],
            discrete_inputs: vec![],
            input_registers: vec![],
            file_records: vec![],
            mem_layout: Default::default(),
            input_register_mem_layout: Default::default(),
            server_id: None,
        }
    }

    #[test]
    fn machine_stores_new_starts_with_every_store_empty() {
        let stores = MachineStores::new();
        assert_eq!(
            stores.registers.lock().unwrap().get("Tank_Temperature"),
            None
        );
        assert_eq!(stores.coils.lock().unwrap().get("Motor_Running"), None);
        assert_eq!(
            stores
                .discrete_inputs
                .lock()
                .unwrap()
                .get("Door_Open_Sensor"),
            None
        );
        assert_eq!(
            stores.input_registers.lock().unwrap().get("Flow_Rate"),
            None
        );
        assert_eq!(stores.file_records.lock().unwrap().get(20, 5), None);
        assert_eq!(stores.report.lock().unwrap().get("Stop_Process"), None);
    }

    #[test]
    fn machine_stores_clone_shares_the_same_underlying_data() {
        let stores = MachineStores::new();
        let cloned = stores.clone();

        stores
            .registers
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(42));

        assert_eq!(
            cloned.registers.lock().unwrap().get("Tank_Temperature"),
            Some(RegisterValue::U16(42))
        );
    }

    #[test]
    fn build_machine_stores_creates_one_entry_per_machine_name() {
        let machines = vec![minimal_machine("PumpA"), minimal_machine("PumpB")];

        let stores = build_machine_stores(&machines);

        assert_eq!(stores.len(), 2);
        assert!(stores.contains_key("PumpA"));
        assert!(stores.contains_key("PumpB"));
    }

    #[test]
    fn build_machine_stores_gives_each_machine_independent_stores() {
        let machines = vec![minimal_machine("PumpA"), minimal_machine("PumpB")];

        let stores = build_machine_stores(&machines);

        stores["PumpA"]
            .registers
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(42));

        assert_eq!(
            stores["PumpA"]
                .registers
                .lock()
                .unwrap()
                .get("Tank_Temperature"),
            Some(RegisterValue::U16(42))
        );
        assert_eq!(
            stores["PumpB"]
                .registers
                .lock()
                .unwrap()
                .get("Tank_Temperature"),
            None
        );
    }
}
