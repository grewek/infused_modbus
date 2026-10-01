# Supported Modbus function codes

This lists every public function code defined by the Modbus Application Protocol specification, not just the ones this project implements — so the gaps are visible rather than silently omitted. "Not implemented yet" will be added later. "Out of scope" means this project has decided not to implement it at all — see the notes below the table. "Supported" here means `server` is *capable* of answering it — whether it actually does on a given deployment additionally depends on [`server-options.toml`](server-options.md): every function code defaults to disabled until a technician explicitly enables it, so a "Supported" code still gets `ILLEGAL_FUNCTION` if its key isn't set to `true`.

| Code | Name | `server-options.toml` key | Status |
| ---- | ---- | -------------------------- | ------ |
| 0x01 | Read Coils | `read_coils` | Supported |
| 0x02 | Read Discrete Inputs | `read_discrete_inputs` | Supported |
| 0x03 | Read Holding Registers | `read_holding_registers` | Supported |
| 0x04 | Read Input Registers | `read_input_registers` | Supported |
| 0x05 | Write Single Coil | `write_single_coil` | Supported |
| 0x06 | Write Single Register | `write_single_register` | Supported |
| 0x07 | Read Exception Status | — | Out of scope |
| 0x08 | Diagnostics | — | Out of scope |
| 0x0B | Get Comm Event Counter | — | Out of scope |
| 0x0C | Get Comm Event Log | — | Out of scope |
| 0x0F | Write Multiple Coils | `write_multiple_coils` | Supported |
| 0x10 | Write Multiple Registers | `write_multiple_registers` | Supported |
| 0x11 | Report Server ID | `report_server_id` | Supported |
| 0x14 | Read File Record | `read_file_record` | Supported — see note below the table |
| 0x15 | Write File Record | `write_file_record` | Supported — see note below the table |
| 0x16 | Mask Write Register | `mask_write_register` | Supported |
| 0x17 | Read/Write Multiple Registers | `read_write_multiple_registers` | Supported (server only — see note below the table) |
| 0x18 | Read FIFO Queue | `read_fifo_queue` | Not implemented yet |
| 0x2B / MEI 0x0E | Encapsulated Interface Transport — Read Device Identification | `read_device_identification` | Supported (Extended access only — see [Device description discovery](filesystem.md#device-description-discovery-fc-43)) |

**0x07, 0x08, 0x0B, 0x0C are deliberately out of scope.** All four are marked "(Serial Line only)" in the spec itself and exist to diagnose the physical RS-485/RTU link (CRC error counts, character overrun counts, a Listen Only Mode to silence a malfunctioning node on a multidrop bus, a rolling event log of send/receive activity). None of them read or write register/coil data, they have no equivalent over TCP, and implementing them would mean tracking link-level counters/state that serve no purpose for this project while adding attack surface to `server`. Not planned to be revisited.

**0x17 (Read/Write Multiple Registers) is server-only, deliberately.** It combines a write and a read into one request/response round trip (write applied first, then read) — real external Modbus masters can use it against `server` like any other read/write, and the write half applies exactly like Write Multiple Registers (atomically, no partial apply if either half is invalid). `client` never sends it: everything it could express — write via `transactions/`+`TRANSACTION_END`, read via `holding-registers/` — is already covered by the two separate mechanisms this project already has, so a wire-level round-trip optimization here wouldn't unlock anything new through the filesystem.

**0x14/0x15 (Read/Write File Record) are deliberately minimal: raw bytes only, no field-level interpretation.** What a "file"/"record" means is entirely vendor-specific — real devices use it for things like event logs or historical trend data, and this project has no way to know a given device's own field layout without being told. `[[file-records]]` entries in the device description TOML (see [Device description TOML format](device-description.md)) declare which `(file_number, record_number)` combinations exist and how many words each holds; `server` answers real requests for them straight from `file-records/<file_number>/<record_number>`, directly writable there like every other server-side data type (a technician can stage test data by hand). `client` shows the same path as a plain hex dump, refreshed by polling, and — unlike FC17 — can also *write* one back to the real device: stage `transactions/<file_number>:<record_number>` with hex content and commit it via `TRANSACTION_END`, same as any other write, confirmed via `report/<file_number>:<record_number>`. Nothing decodes the bytes into named fields on either side (yet; that's planned as part of a future custom-function-codes feature, not built alongside this one).
