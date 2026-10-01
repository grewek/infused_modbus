# Interacting with the filesystem

Every configured machine gets its own top-level directory, named after that machine's `name` in the device description (see [Device description TOML format](device-description.md)) — the examples below use `PumpA`. Everything past that first path segment works exactly the same regardless of how many machines are mounted, and regardless of which `--data-representation-layer` was chosen — `files` and `fuse` present the identical directory shape.

Once mounted:

```sh
ls PumpA/holding-registers/                       # see all known registers
cat PumpA/holding-registers/Tank_Temperature      # read the current value

echo 55 > PumpA/transactions/Stop_Process         # stage a write
ls PumpA/transactions/                            # see what's staged
rm PumpA/transactions/Stop_Process                # ...or un-stage it
touch PumpA/transactions/TRANSACTION_END          # commit everything staged

cat PumpA/report/Stop_Process                     # OK, or FAILED: <reason>
```

**This is the client's write path — `transactions/`, `TRANSACTION_END`, and `report/` don't exist on the server at all.** The server writes directly into `holding-registers/<name>` (or `coils/`/`discrete-inputs/`/`input-registers/`) instead — `echo 55 > PumpA/holding-registers/Stop_Process` applies immediately, since the server's own state doesn't need staging or a round trip to confirm:

```sh
echo 55 > PumpA/holding-registers/Stop_Process    # server only — applies immediately, no transactions/
```

`discrete-inputs/` and `input-registers/` (FC 2/FC 4 data) sit alongside `holding-registers/`, same `ls`/`cat` shape — read-only on the client (populated by polling), directly writable on the server exactly like `holding-registers/` above.

Coils work the same way as holding registers, under `coils/` instead — `transactions/` and `report/` are shared across both on the client (one register and one coil can even be staged in the same commit). A coil's value is `0` or `1`:

```sh
cat PumpA/coils/Motor_Running                     # 0 or 1
echo 1 > PumpA/transactions/Motor_Running         # stage turning it on
touch PumpA/transactions/TRANSACTION_END
```

A `transactions/<name>` file can also stage a Mask Write Register (FC 0x16) instead of a plain value, by writing `MASK <and_mask> <or_mask>` as its content — sets/clears specific bits in a single-register-wide value atomically on the real device, without needing to know its current contents:

```sh
echo "MASK 0x00F2 0x0025" > PumpA/transactions/Stop_Process
touch PumpA/transactions/TRANSACTION_END
```

This is client-only (the server has no local use for it — see the [function-code table](function-codes.md) and `CLAUDE.md` for why) and, like every write, can only ever target a single-register-wide value (`u8`/`i8`/`u16`/`i16`).

Declared `[[machines.file-records]]` (FC 0x14/0x15) show up under `file-records/<file_number>/<record_number>` — nested one level deeper than everything else, since file/record numbers are two-axis and there's no human-readable name for them. Content is a plain hex dump; nothing decodes it into fields:

```sh
ls PumpA/file-records/20/                         # e.g. "5"
cat PumpA/file-records/20/5                       # e.g. "0D FE 00 20"

echo "0D FE 00 20" > PumpA/file-records/20/5      # server only — applies immediately, like holding-registers/
```

Read-only on the client's own `file-records/` mount, populated by polling one `Read File Record` request per configured entry at a time. To *write* one to the real device instead, stage it through `transactions/` with the colon-separated `<file_number>:<record_number>` naming, same commit/confirm flow as everything else there:

```sh
echo "0D FE 00 20" > PumpA/transactions/20:5
touch PumpA/transactions/TRANSACTION_END
cat PumpA/report/20:5                             # OK, or FAILED: <reason>
```

If a machine's optional `server-id` field is set (see [Device description TOML format](device-description.md)), that machine's directory on the client's mount also has a read-only `server-id` file at its root, mirroring whatever the connected device (or its own local fallback) declared:

```sh
cat PumpA/server-id                               # e.g. infused_modbus-demo-plc
```

`server` never mirrors its own `server-id` into its FUSE tree this way — it only answers a real Modbus master's FC 0x11 (Report Server ID) request with it (the technician already set it in the TOML they own, so there's nothing new to show them locally). `client-trust/` (server-only, see [Connecting over TLS](tls.md)) is the one exception to the "everything lives under a machine directory" rule — it stays at the real filesystem root, since it's about which clients may connect at all, not about any one machine.

Unmount with Ctrl+C or `SIGTERM` — both `client` and `server` unmount cleanly on shutdown.

## Device description discovery (FC 43)

The client always requires a local `device-description.toml` path on the command line, but at startup it first asks the server for its own description over Modbus function code 43 (Encapsulated Interface Transport, MEI type 0x0E, Read Device Identification). If the server has one, the client uses it instead of the local file — printing progress as it fetches, since this can take a few round trips. If the server has none, doesn't support FC 43, or the fetch fails for any reason, the client transparently falls back to the local file.
