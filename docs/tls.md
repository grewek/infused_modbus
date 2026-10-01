# Connecting over TLS

`tls+tcp://` encrypts the Modbus TCP connection and authenticates both sides — but without a certificate authority: there's no CA to set up, no certificates to buy or issue. Instead, both `client` and `server` generate their own self-signed identity automatically the first time they run (persisted next to wherever the process was started: `server-tls-identity/` and `client-tls-identity/` respectively), and trust is based purely on comparing the raw public-key **fingerprint** a peer presents — the same idea as an SSH host key, not a PKI certificate chain. Read `CLAUDE.md`'s "TLS transport security & client trust" section for the full design this is built from.

**1. Start the server.** It generates its identity on first run and prints its fingerprint:

```sh
cargo run -p server -- /tmp/modbus-server device.toml tls+tcp://0.0.0.0:502
```

```
Server TLS fingerprint: 86:3f:7f:d5:06:06:0f:5e:26:8d:bd:a8:1e:15:14:38:39:f3:f4:ba:0a:a4:a9:6a:da:c6:9a:60:dd:7f:a4:74
```

Note this value down — in a real deployment, a technician commissioning the server would read it directly off the console/log and hand it to whoever sets up a client, out of band (there is no other channel this travels over).

**2. Start the client, pinning that fingerprint:**

```sh
cargo run -p client -- /tmp/modbus-client device.toml tls+tcp://127.0.0.1:502 --expect-server-fingerprint 86:3f:7f:d5:06:06:0f:5e:26:8d:bd:a8:1e:15:14:38:39:f3:f4:ba:0a:a4:a9:6a:da:c6:9a:60:dd:7f:a4:74
```

Without `--expect-server-fingerprint`, the client accepts **any** server certificate unconditionally and prints a warning saying so — useful only for local testing, never for a real deployment. With it, the connection is rejected outright if the server presents a different certificate than expected.

**3. The client also generates (and prints) its own identity** the first time it runs, and presents it to the server as part of a mutual TLS (mTLS) handshake — both sides authenticate to each other, not just the client authenticating the server. Until the client's fingerprint has been approved (next step), the server rejects the handshake — this first connection attempt is expected to fail.

**4. Approve the client.** The server logs every connection attempt (approved, still-pending, or outright rejected) by fingerprint under its own root, in `client-trust/connection_attempts/{approved,pending,rejected}.log`. An unapproved-but-otherwise-valid certificate lands in `pending.log` — read the fingerprint from there (or from the client's own startup output, which prints the same value), then approve it from another terminal:

```sh
cargo run -p server -- admin approve <client-fingerprint>
```

This talks to a Unix domain socket the server always serves in the background, regardless of connection type (`server-admin.sock`, relative to wherever the server was started; mode `0600`, additionally checked against the server process's own UID via `SO_PEERCRED` — only the local user account actually running the server can approve/revoke/list). The currently approved set is also visible read-only under `client-trust/approved/` at the server's root (one file per fingerprint).

**5. Reconnect the client** with the same command as step 2 — the identical certificate now completes the mTLS handshake, and the client mounts and polls normally.

**6. Revoke a client** when it should no longer connect:

```sh
cargo run -p server -- admin revoke <client-fingerprint>
```

This disconnects any already-open connection using that fingerprint immediately, not just future handshake attempts.

**Approvals persist automatically.** Every successful `approve`/`revoke` atomically rewrites `approved-clients.toml` (mode `0600`, in the directory the server was started from) — restarting the server re-reads it at startup, so a previously-approved client doesn't need to be re-approved by hand. `--max-clients <n>` (see [Getting started](getting-started.md)) bounds how many fingerprints can be approved at once; approving past that limit fails until an existing one is revoked.

**DoS hardening.** The TLS handshake itself has a 10-second timeout, independent of the per-request Modbus timeout. The server also caps concurrent connections: at most 100 in total at once, and at most 5 per individual approved fingerprint, so one already-approved but compromised or buggy client can't exhaust the whole connection pool by itself. Either cap being exceeded drops the new connection outright rather than queuing it. Protection against a flood from many different source addresses is out of scope for `infused_modbus` itself — that's upstream infrastructure's job (firewall/rate-limiter), not something the application layer handles.

**Still fixed, not yet configurable via a CLI flag:** the admin socket's path, the TLS identity directories, `approved-clients.toml`'s own path, and the DoS-hardening limits above. RTU's serial link also remains a separate, unauthenticated threat model that TLS does nothing to address.
