# server-options.toml

`server` only answers the function codes a technician explicitly enables — **strict default-deny, no exceptions for already-implemented ones.** Without `--server-options <path>` (see [Getting started](getting-started.md)), or with a present-but-empty file, every function code is disabled and every incoming request gets an `ILLEGAL_FUNCTION` exception, regardless of what this project actually implements. `server` prints a loud startup warning if it ends up with zero function codes enabled, since "the server starts fine but answers nothing" is an easy flag to forget.

This is a `server`-only concern: `client` only ever sends function codes it itself chooses to issue, so there's nothing to gate on that side. Every function code this server *can* serve is attack surface exposed to any reachable Modbus master, not just a trusted one — enabling one is a deliberate technician choice, not an on-by-default assumption.

The file has one `[function-codes]` table, one boolean per function code, named after the operation rather than a raw code number:

```toml
[function-codes]
read_coils = true                      # 0x01
read_discrete_inputs = true            # 0x02
read_holding_registers = true          # 0x03
read_input_registers = true            # 0x04
write_single_coil = true               # 0x05
write_single_register = true           # 0x06
write_multiple_coils = true            # 0x0F
write_multiple_registers = true        # 0x10
report_server_id = true                # 0x11
read_file_record = true                # 0x14
write_file_record = false              # 0x15
mask_write_register = true             # 0x16
read_write_multiple_registers = true   # 0x17
read_fifo_queue = false                # 0x18 (not implemented yet — the key exists, but there's no handler to enable)
read_device_identification = true      # 0x2B / MEI 0x0E
```

Every key is optional and defaults to `false` — only list what actually needs enabling. An unknown key anywhere under `[function-codes]` (or any other top-level key in the file) is a hard parse error at startup, not a silently-ignored setting — a typo shouldn't leave a technician wrongly believing a function code is enabled.

A disabled function code and one that was never implemented at all respond with the exact same `ILLEGAL_FUNCTION` exception — deliberately indistinguishable on the wire, so a remote peer can't tell "implemented but turned off" apart from "doesn't exist here" just from the response. This composes cleanly with [device description discovery](getting-started.md#device-description-discovery-fc-43): disabling `read_device_identification` needs no special handling on the client side, since its FC 43 fetch already falls back to the local TOML on any failure, `ILLEGAL_FUNCTION` included.

See [the function code table](function-codes.md) for every available key name.
