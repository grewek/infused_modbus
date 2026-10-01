# Directory permissions

By default every top-level directory (`holding-registers/`, `transactions/`, `report/`, `coils/`) is mode `0755`, owned by whoever made a given filesystem request (`fuse` layer) or by the process's own real user (`files` layer) — the same behavior as before this option existed. An optional `fuse-permissions.toml`, passed to either binary via `--fuse-permissions <path>` (see [Getting started](getting-started.md)) and applying identically under `fuse`/`files`, overrides `mode`/`uid`/`gid` per directory. Every field, and every directory section, is optional — only what actually needs restricting has to be spelled out. `--data-representation-layer mqtt` has no directories at all, so `--fuse-permissions` is accepted but ignored under it — its socket file (`server-data.sock`) is always mode `0600`, not configurable:

```toml
[transactions]
mode = 0o700
uid = 1000
gid = 1000

[report]
mode = 0o444
```

Under `fuse`, both binaries mount with the kernel's `default_permissions` option, so these values are enforced by the kernel itself, not just displayed by `ls -l`. Under `files`, the same values are applied as real `chmod`/`chown` calls on the underlying directories — note that setting `uid`/`gid` to anything other than the server/client process's own real user requires the process to actually have `CAP_CHOWN` (root); an unprivileged process configuring a different owner will fail at startup with a permission error. Either way, the usual Unix rules apply, including that a directory needs its own execute bit to be enterable at all — a directory meant to stay "read-only but still browsable" needs e.g. `0o555`, not `0o444`, since `0o444` alone makes everything inside it completely unreachable, even to its own owner.

One `fuse-permissions.toml` applies identically to *every* machine's own subtree — there's no per-machine override, `[transactions]` above means "every machine's `transactions/` directory", not one specific machine's.

`client-trust/` (server-only, see [Connecting over TLS](tls.md)) cannot be configured here at all — a `[client-trust]` section anywhere in this file is a hard parse error at startup, not a silently-ignored setting. It is always mode `0700` (its files `0400`), owned by the server process's own real user, regardless of `fuse-permissions.toml` — enforced for real under both representation layers.
