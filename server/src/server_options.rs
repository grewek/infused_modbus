// `server-options.toml`: explicit per-function-code opt-in (see CLAUDE.md's
// "Planned: `server-options.toml`" section for the full design rationale).
// Every function code this server can serve is attack surface exposed to
// *any* reachable Modbus master, not just a trusted one — a `server`-only
// concern, since `client` only ever issues function codes it itself chose
// to send, never accepts arbitrary incoming ones.
//
// Default policy: strict default-deny, no legacy exemption. Every function
// code — including ones already fully implemented (Read/Write Coils,
// Read/Write Holding Registers, FC 43, ...) — defaults to disabled unless
// its key is present and `true`. An absent file behaves exactly like a
// present-but-empty one: everything disabled, not a startup error (see
// `Default`).
//
// Unknown keys under `[function-codes]`, or any other top-level key, are a
// hard parse error via `deny_unknown_fields` — same discipline
// `fuse-permissions.toml` uses to reject a `client-trust` key, so a typo
// doesn't leave a technician wrongly believing a function code is
// enabled/disabled.
//
// This is what makes FC 21 (Write File Record) implementable at all once
// it's built: a semantically-unscoped write primitive, mitigated by
// requiring an explicit technician opt-in rather than the on-by-default
// posture every other FC has had. `read_file_record`/`write_file_record`/
// `read_fifo_queue` are included in the schema now even though FC 20/21/18
// aren't implemented yet — `handle_request` has no match arm for them
// regardless of what's configured here, so the key is inert until those
// function codes actually exist, but the config surface is ready for them.

use serde::Deserialize;
use std::fmt;

use protocol::pdu::{
    FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT, FUNCTION_CODE_MASK_WRITE_REGISTER,
    FUNCTION_CODE_READ_COILS, FUNCTION_CODE_READ_DISCRETE_INPUTS, FUNCTION_CODE_READ_FILE_RECORD,
    FUNCTION_CODE_READ_HOLDING_REGISTERS, FUNCTION_CODE_READ_INPUT_REGISTERS,
    FUNCTION_CODE_READ_WRITE_MULTIPLE_REGISTERS, FUNCTION_CODE_REPORT_SERVER_ID,
    FUNCTION_CODE_WRITE_MULTIPLE_COILS, FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
    FUNCTION_CODE_WRITE_SINGLE_COIL, FUNCTION_CODE_WRITE_SINGLE_REGISTER,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFunctionCodes {
    #[serde(default)]
    read_coils: bool,
    #[serde(default)]
    read_discrete_inputs: bool,
    #[serde(default)]
    read_holding_registers: bool,
    #[serde(default)]
    read_input_registers: bool,
    #[serde(default)]
    write_single_coil: bool,
    #[serde(default)]
    write_single_register: bool,
    #[serde(default)]
    write_multiple_coils: bool,
    #[serde(default)]
    write_multiple_registers: bool,
    #[serde(default)]
    report_server_id: bool,
    #[serde(default)]
    read_file_record: bool,
    #[serde(default)]
    write_file_record: bool,
    #[serde(default)]
    mask_write_register: bool,
    #[serde(default)]
    read_write_multiple_registers: bool,
    #[serde(default)]
    read_fifo_queue: bool,
    #[serde(default)]
    read_device_identification: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerOptions {
    #[serde(rename = "function-codes", default)]
    function_codes: RawFunctionCodes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerOptions {
    pub read_coils: bool,
    pub read_discrete_inputs: bool,
    pub read_holding_registers: bool,
    pub read_input_registers: bool,
    pub write_single_coil: bool,
    pub write_single_register: bool,
    pub write_multiple_coils: bool,
    pub write_multiple_registers: bool,
    pub report_server_id: bool,
    pub read_file_record: bool,
    pub write_file_record: bool,
    pub mask_write_register: bool,
    pub read_write_multiple_registers: bool,
    pub read_fifo_queue: bool,
    pub read_device_identification: bool,
}

#[derive(Debug)]
pub struct ServerOptionsError(toml::de::Error);

impl fmt::Display for ServerOptionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for ServerOptionsError {}

impl From<toml::de::Error> for ServerOptionsError {
    fn from(error: toml::de::Error) -> Self {
        ServerOptionsError(error)
    }
}

impl From<RawFunctionCodes> for ServerOptions {
    fn from(raw: RawFunctionCodes) -> Self {
        ServerOptions {
            read_coils: raw.read_coils,
            read_discrete_inputs: raw.read_discrete_inputs,
            read_holding_registers: raw.read_holding_registers,
            read_input_registers: raw.read_input_registers,
            write_single_coil: raw.write_single_coil,
            write_single_register: raw.write_single_register,
            write_multiple_coils: raw.write_multiple_coils,
            write_multiple_registers: raw.write_multiple_registers,
            report_server_id: raw.report_server_id,
            read_file_record: raw.read_file_record,
            write_file_record: raw.write_file_record,
            mask_write_register: raw.mask_write_register,
            read_write_multiple_registers: raw.read_write_multiple_registers,
            read_fifo_queue: raw.read_fifo_queue,
            read_device_identification: raw.read_device_identification,
        }
    }
}

impl ServerOptions {
    pub fn parse(toml_source: &str) -> Result<Self, ServerOptionsError> {
        let raw: RawServerOptions = toml::from_str(toml_source)?;
        Ok(raw.function_codes.into())
    }

    /// Whether `function_code` is enabled per this configuration — the
    /// single gate `handler::handle_request` consults before dispatching to
    /// any real handler. `false` for a function code with no entry in this
    /// struct at all (every out-of-scope FC like 0x07, and any code not
    /// recognized as Modbus at all) — there's nothing to enable for a
    /// function code this server can never serve regardless of
    /// configuration.
    pub fn is_enabled(&self, function_code: u8) -> bool {
        match function_code {
            FUNCTION_CODE_READ_COILS => self.read_coils,
            FUNCTION_CODE_READ_DISCRETE_INPUTS => self.read_discrete_inputs,
            FUNCTION_CODE_READ_HOLDING_REGISTERS => self.read_holding_registers,
            FUNCTION_CODE_READ_INPUT_REGISTERS => self.read_input_registers,
            FUNCTION_CODE_WRITE_SINGLE_COIL => self.write_single_coil,
            FUNCTION_CODE_WRITE_SINGLE_REGISTER => self.write_single_register,
            FUNCTION_CODE_WRITE_MULTIPLE_COILS => self.write_multiple_coils,
            FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS => self.write_multiple_registers,
            FUNCTION_CODE_REPORT_SERVER_ID => self.report_server_id,
            FUNCTION_CODE_MASK_WRITE_REGISTER => self.mask_write_register,
            FUNCTION_CODE_READ_WRITE_MULTIPLE_REGISTERS => self.read_write_multiple_registers,
            FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT => self.read_device_identification,
            FUNCTION_CODE_READ_FILE_RECORD => self.read_file_record,
            _ => false,
        }
    }

    /// Whether at least one function code is enabled — `server`'s `main`
    /// prints a loud startup warning when this is false, since "the server
    /// starts fine but answers nothing" is a real footgun for a forgotten
    /// `--server-options` flag or an empty file.
    pub fn any_enabled(&self) -> bool {
        self.read_coils
            || self.read_discrete_inputs
            || self.read_holding_registers
            || self.read_input_registers
            || self.write_single_coil
            || self.write_single_register
            || self.write_multiple_coils
            || self.write_multiple_registers
            || self.report_server_id
            || self.read_file_record
            || self.write_file_record
            || self.mask_write_register
            || self.read_write_multiple_registers
            || self.read_fifo_queue
            || self.read_device_identification
    }

    /// Every function code enabled — used by tests elsewhere in this crate
    /// that exercise `handle_request` for behavior unrelated to
    /// `ServerOptions` itself, so they don't all need to construct a fully
    /// permissive TOML source by hand.
    #[cfg(test)]
    pub fn allow_all() -> Self {
        ServerOptions {
            read_coils: true,
            read_discrete_inputs: true,
            read_holding_registers: true,
            read_input_registers: true,
            write_single_coil: true,
            write_single_register: true,
            write_multiple_coils: true,
            write_multiple_registers: true,
            report_server_id: true,
            read_file_record: true,
            write_file_record: true,
            mask_write_register: true,
            read_write_multiple_registers: true,
            read_fifo_queue: true,
            read_device_identification: true,
        }
    }
}

impl Default for ServerOptions {
    /// Same result as parsing an empty file — every function code disabled.
    /// Used when no `--server-options` flag was given at all.
    fn default() -> Self {
        ServerOptions::parse("").expect("an empty TOML source always parses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_of_empty_source_disables_every_function_code() {
        let options = ServerOptions::parse("").unwrap();
        assert_eq!(
            options,
            ServerOptions {
                read_coils: false,
                read_discrete_inputs: false,
                read_holding_registers: false,
                read_input_registers: false,
                write_single_coil: false,
                write_single_register: false,
                write_multiple_coils: false,
                write_multiple_registers: false,
                report_server_id: false,
                read_file_record: false,
                write_file_record: false,
                mask_write_register: false,
                read_write_multiple_registers: false,
                read_fifo_queue: false,
                read_device_identification: false,
            }
        );
    }

    #[test]
    fn default_matches_parsing_an_empty_source() {
        assert_eq!(ServerOptions::default(), ServerOptions::parse("").unwrap());
    }

    #[test]
    fn parse_reads_enabled_function_codes() {
        let toml_source = "\
            [function-codes]\n\
            read_holding_registers = true\n\
            write_single_register = true\n\
        ";
        let options = ServerOptions::parse(toml_source).unwrap();
        assert!(options.read_holding_registers);
        assert!(options.write_single_register);
        assert!(!options.read_coils);
        assert!(!options.write_multiple_registers);
    }

    #[test]
    fn parse_rejects_an_unknown_function_code_key() {
        let toml_source = "[function-codes]\nread_exception_status = true\n";
        assert!(ServerOptions::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_an_unknown_top_level_key() {
        assert!(ServerOptions::parse("[nonsense]\nread_coils = true\n").is_err());
    }

    #[test]
    fn parse_rejects_invalid_toml_syntax() {
        assert!(ServerOptions::parse("this is not valid toml [[[").is_err());
    }

    #[test]
    fn is_enabled_reflects_the_matching_field() {
        let options = ServerOptions {
            read_coils: true,
            ..ServerOptions::default()
        };
        assert!(options.is_enabled(FUNCTION_CODE_READ_COILS));
        assert!(!options.is_enabled(FUNCTION_CODE_READ_HOLDING_REGISTERS));
    }

    #[test]
    fn is_enabled_is_false_for_a_function_code_with_no_matching_entry() {
        let options = ServerOptions::allow_all();
        // 0x07 (Read Exception Status) is deliberately out of scope — no
        // field in ServerOptions can ever enable it.
        assert!(!options.is_enabled(0x07));
    }

    #[test]
    fn any_enabled_is_false_by_default() {
        assert!(!ServerOptions::default().any_enabled());
    }

    #[test]
    fn any_enabled_is_true_once_a_single_function_code_is_enabled() {
        let options = ServerOptions {
            read_coils: true,
            ..ServerOptions::default()
        };
        assert!(options.any_enabled());
    }

    #[test]
    fn allow_all_enables_every_function_code() {
        assert!(ServerOptions::allow_all().any_enabled());
        assert!(ServerOptions::allow_all().is_enabled(FUNCTION_CODE_READ_COILS));
        assert!(
            ServerOptions::allow_all().is_enabled(FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT)
        );
        assert!(ServerOptions::allow_all().is_enabled(FUNCTION_CODE_READ_FILE_RECORD));
    }
}
