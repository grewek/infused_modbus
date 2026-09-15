pub mod filesystem;

use std::collections::HashMap;
use std::fmt;

// Mirrors protocol::device_description::DataType — a register's value is
// whichever of these its TOML description declares it to be.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegisterValue {
    U16(u16),
    F32(f32),
}

// How a register's value is rendered as the content of its FUSE file.
impl fmt::Display for RegisterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterValue::U16(value) => write!(formatter, "{value}"),
            RegisterValue::F32(value) => write!(formatter, "{value}"),
        }
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

// Staged writes for one in-progress transaction: creating a file in
// `transactions/` and writing a value to it stages a name=value entry here;
// creating `TRANSACTION_END` (Milestone H2, not implemented yet) drains this
// and applies it to a RegisterStore. Plain data structure, no FUSE
// awareness — mirrors how RegisterStore (F1) preceded its own FUSE wiring
// (G1).
#[derive(Debug, Default)]
pub struct PendingTransaction {
    staged: HashMap<String, RegisterValue>,
}

impl PendingTransaction {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stage(&mut self, name: impl Into<String>, value: RegisterValue) {
        self.staged.insert(name.into(), value);
    }

    pub fn get(&self, name: &str) -> Option<RegisterValue> {
        self.staged.get(name).copied()
    }

    pub fn unstage(&mut self, name: &str) -> Option<RegisterValue> {
        self.staged.remove(name)
    }

    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    // Takes every staged value out at once, leaving the transaction empty —
    // what `TRANSACTION_END` needs to atomically hand off everything staged
    // so far to be applied to a RegisterStore.
    pub fn drain(&mut self) -> HashMap<String, RegisterValue> {
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
    fn pending_transaction_get_returns_none_for_unstaged_register() {
        let transaction = PendingTransaction::new();
        assert_eq!(transaction.get("Stop_Process"), None);
    }

    #[test]
    fn pending_transaction_stage_then_get_returns_the_value() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Stop_Process", RegisterValue::U16(1));
        assert_eq!(transaction.get("Stop_Process"), Some(RegisterValue::U16(1)));
    }

    #[test]
    fn pending_transaction_stage_overwrites_previous_value() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Stop_Process", RegisterValue::U16(1));
        transaction.stage("Stop_Process", RegisterValue::U16(0));
        assert_eq!(transaction.get("Stop_Process"), Some(RegisterValue::U16(0)));
    }

    #[test]
    fn pending_transaction_unstage_removes_a_staged_value() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Stop_Process", RegisterValue::U16(1));
        assert_eq!(
            transaction.unstage("Stop_Process"),
            Some(RegisterValue::U16(1))
        );
        assert_eq!(transaction.get("Stop_Process"), None);
    }

    #[test]
    fn pending_transaction_is_empty_reflects_staged_state() {
        let mut transaction = PendingTransaction::new();
        assert!(transaction.is_empty());
        transaction.stage("Stop_Process", RegisterValue::U16(1));
        assert!(!transaction.is_empty());
        transaction.unstage("Stop_Process");
        assert!(transaction.is_empty());
    }

    #[test]
    fn pending_transaction_drain_returns_staged_values_and_empties_transaction() {
        let mut transaction = PendingTransaction::new();
        transaction.stage("Stop_Process", RegisterValue::U16(1));
        transaction.stage("Flow_Rate", RegisterValue::F32(3.5));

        let drained = transaction.drain();

        assert_eq!(drained.get("Stop_Process"), Some(&RegisterValue::U16(1)));
        assert_eq!(drained.get("Flow_Rate"), Some(&RegisterValue::F32(3.5)));
        assert_eq!(drained.len(), 2);
        assert!(transaction.is_empty());
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
}
