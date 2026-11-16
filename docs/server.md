# Sync server

`keyward-server` is an axum + SQLite service. It stores each account's
encrypted vault and lets several `kw` clients keep their copies in step.

It is **zero-knowledge**: it never receives the master password, the master
key, the vault key or any plaintext. See [What the server stores](#what-the-server-stores).

## Running it

### Docker Compose + Caddy (recommended)

```sh
KW_DOMAIN=vault.example.com docker compose up -d --build
```

- Caddy terminates TLS and obtains certificates automatically.
- `keyward-server` is reachable only from Caddy; port 8080 is not published.
- The database lives in the `keyward-data` volume (`/data/keyward.db`).
- After creating your account, close registration:
  `KW_REGISTRATION=closed docker compose up -d`.

The proxy configuration is [`deploy/Caddyfile`](../deploy/Caddyfile).

### Bare binary

```sh
cargo build --release -p keyward-server
KW_BIND=127.0.0.1:8080 KW_DATABASE_URL=sqlite:///var/lib/keyward/keyward.db \
  ./target/release/keyward-server
```

Always put a TLS reverse proxy in front of it. The server only speaks plain
HTTP, and `kw` refuses `http://` for anything other than localhost.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KW_BIND` | `0.0.0.0:8080` | Listen address |
| `KW_DATABASE_URL` | `sqlite://data/keyward.db` | SQLite file (created if missing; WAL mode) |
| `KW_SESSION_TTL_SECS` | `43200` (12 h) | Bearer token lifetime |
| `KW_REGISTRATION` | `open` | `closed` disables `POST /accounts` |
| `KW_TRUST_PROXY` | `false` | Use the last `X-Forwarded-For` entry as the client IP. Set it **only** behind a proxy that rewrites that header. |
| `KW_AUTH_RATE_PER_MIN` | `20` | Auth requests per IP per minute (token bucket) |
| `KW_LOCKOUT_THRESHOLD` | `5` | Failed logins per username before lockout |
| `KW_LOCKOUT_SECS` | `900` | Lockout duration |
| `RUST_LOG` | `keyward_server=info,tower_http=info` | Log filter. Logs never contain credentials or item data. |

### Backups

Back up the SQLite file with `sqlite3 keyward.db ".backup out.db"`, or stop the
container and copy the volume. A server backup is as sensitive as a vault file:
it holds ciphertext and the wrapped key, so it is protected only by the
master password.

## Client usage

```console
$ kw sync register --server https://vault.example.com --username alice   # upload this vault
$ kw --vault laptop.kwv sync clone --server https://vault.example.com --username alice
$ kw sync            # pull + push (also works inside `kw shell`)
$ kw sync status
$ kw sync disconnect
```

## Protocol

### Credentials

```text
MasterKey ─HKDF("keyward/v1/auth")─▶ AuthKey
LoginHash = SHA-256("keyward/v1/login-hash" ‖ AuthKey)      (sent to the server)
server stores Argon2id(LoginHash, random salt)               (PHC string)
```

`AuthKey` and the key-wrapping key come from different HKDF labels, so
knowing `LoginHash` reveals nothing about the key that wraps the vault key.
A leaked database holds only Argon2id hashes of `LoginHash`, which cannot be
used to log in.

A new device first calls `prelogin` to get the salt and KDF settings.

- **Unknown usernames.** `prelogin` returns a salt derived as
  `HMAC(server secret, username)` together with the default settings. The
  answer is stable and looks like a real one.
- **Timing.** Logging in as an unknown user verifies against a dummy hash, so
  it takes as long as a real login.

### Endpoints (`/api/v1`, JSON)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /accounts/prelogin` | none | `{username}` → `{kdf}` |
| `POST /accounts` | none | `{username, login_hash, vault}`: register; 409 if taken, 403 if closed |
| `POST /sessions` | none | `{username, login_hash}` → `{token, expires_at}` |
| `DELETE /sessions/current` | bearer | logout |
| `GET /vault` | bearer | header + wrapped vault key |
| `PUT /account/password` | bearer | `{current_login_hash, new_login_hash, vault}`: revokes **all** sessions |
| `GET /items?since=N&limit=M` | bearer | changes with `seq > N` → `{changes, cursor, has_more}` |
| `PUT /items/{id}` | bearer | `{base_version, version, blob}` |
| `DELETE /items/{id}` | bearer | `{base_version}` → tombstone with `version + 1` |
| `GET /healthz` | none | liveness |

The server answers with these errors:

- **401** generic `invalid credentials`
- **429** with `Retry-After`, from the IP limit or the username lockout
- **409** with `current`, the server's copy of the item

### Versions and conflicts

- **Version check on the server.** Every item has a version. A push says which
  server version it is based on. The server applies it only if that is still
  the current version: `UPDATE … WHERE version = base`, or
  `INSERT … ON CONFLICT DO NOTHING` for `base = 0`. Otherwise it answers 409
  with its copy.
- **Change counter.** Each account has a counter `seq`. Every accepted write
  takes the next value, and `GET /items?since=` returns the latest state of
  every item changed after the client's cursor, deletions (tombstones)
  included.
- **Merging on the client** (`UnlockedVault::apply_remote`):
  - only the server changed: take the server copy
  - both changed: the newer `updated` time wins (last-write-wins). The time
    sits inside the encrypted item, so the server cannot influence the
    decision.
  - local edit vs. remote delete: the edit wins, and the item is restored on
    the server
  - local delete vs. remote edit: the edit wins, and the item comes back
  - the server offers a version *lower* than one already seen: refused
    (`RemoteRollback`)
  - the blob fails AES-GCM authentication with the expected
    `(vault, item, version)` AAD: refused (`RemoteIntegrity`)
- **Where sync state lives.** Server URL, username, cursor, the last-seen
  version per item and pending deletions are stored inside the vault's
  encrypted index. None of it is visible in the file.

### What the server stores

| Data | Visible to the server operator |
|---|---|
| username | yes |
| Argon2id(LoginHash) | yes (useless for login or decryption) |
| vault id, KDF parameters, salt | yes |
| wrapped vault key | ciphertext |
| item id, version, deleted flag, change time, ciphertext size | yes |
| item contents (titles, usernames, URLs, passwords, notes, TOTP, history) | **no** (AES-256-GCM) |
| session tokens | SHA-256 only |
