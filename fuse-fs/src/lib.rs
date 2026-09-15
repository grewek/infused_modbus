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
}
