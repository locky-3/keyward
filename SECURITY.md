# Security

Keyward is a **learning / portfolio project**. It has not been audited. Do not
use it as your only copy of important credentials.

## Reporting

Please open a private security advisory on the repository instead of a public
issue.

## Threat model (summary)

The full model is in [docs/threat-model.md](docs/threat-model.md).

### Protected against

| Threat | Mitigation |
|---|---|
| Someone gets a copy of the vault file (stolen laptop, cloud backup, future sync server) | Every item, title, username and URL is encrypted with AES-256-GCM. Only the KDF parameters, salt, vault id, item ids and versions, and the item count are visible. |
| Offline guessing of the master password | Argon2id (default 64 MiB, 3 passes) with a per-vault 16-byte salt. Vaults below 19 MiB / 2 passes are refused. |
| Modifying the file: flipped bits, swapped or moved item blobs, items copied from another vault, KDF downgrade, deleted or duplicated items, rolling back a single item | AEAD with context-bound AAD, plus an encrypted index of `(id, version, sha256(blob))`. Any of these makes unlocking fail. |
| Learning *why* unlocking failed | Wrong password and every kind of tampering return the same error. |
| Half-written vault after a crash or power loss | Write to a temp file, fsync, atomic rename. Three rotating backups. |
| Two `kw` processes overwriting each other's changes | Lock file, plus a revision check before every write. |
| Secrets left behind in logs or debug output | No secret type implements a revealing `Debug`. Errors never contain secret values. |
| Clipboard leftovers | Cleared after 20 s, but only if it still holds our value. On Windows, excluded from clipboard history and cloud sync. |
| Unattended unlocked `kw shell` / `kw-tui` | Idle auto-lock drops (and zeroizes) all keys and decrypted data. In the TUI, revealed passwords hide again after 15 s, and the locked screen shows no item data. |
| A curious or compromised **sync server**, or a leak of its database | The server only ever sees ciphertext, the wrapped key, the KDF parameters, and an Argon2id hash of a login hash derived from a separate HKDF label. It cannot decrypt anything, and the database is useless for logging in. |
| A **malicious server** altering items | Blobs are authenticated against `(vault, item, version)`. Moved, relabelled or forged blobs are rejected, and so is any version older than one already seen. |
| Online password guessing against the server | Per-IP rate limit, plus a per-username lockout (5 failures → 15 min). Unknown usernames behave identically, and `prelogin` returns stable fake salts for them. |
| Stolen session token | Tokens are random 256-bit values, stored server-side as SHA-256, and expire after 12 h. A password change revokes all sessions. |

### NOT protected against

- **Malware or a hostile admin on your machine.** A keylogger captures the
  master password. Any process running as you can read `kw`'s memory while it
  is unlocked, read the clipboard during the 20-second window, or swap the `kw`
  binary itself.
- **Memory dumps, swap and hibernation while unlocked.** Keyward zeroizes keys
  and decrypted items when they are dropped, but:
  - The OS may already have written those pages to swap or a hibernation file.
    Keyward does not `mlock` its memory.
  - `serde_json`, `clap`, `rpassword` and the clipboard library can leave
    short-lived copies that are not zeroized.
  - A `String` field that is replaced during an edit is freed without being
    zeroized.
  - Zeroization is best effort. It is not a guarantee.
- **Rolling back the whole file.** Replacing the vault with an older,
  self-consistent copy, such as one of the `.bak.N` files, cannot be detected
  offline.
- **A malicious server's availability.** The server can withhold new items or
  updates, refuse service, or delete everything. It cannot forge or decrypt
  them. Keep local backups.
- **A server that never shows you an item.** Rollback protection covers items
  the client has already seen. A server can still hide an item that this
  device has never received.
- **Server-side metadata.** Usernames, item counts and sizes, and edit times
  and frequency are visible to the server operator.
- **Account enumeration via registration.** `register` must say "username
  taken". Close registration (`KW_REGISTRATION=closed`) once your accounts
  exist. Accounts whose KDF settings differ from the defaults can also be
  told apart through `prelogin`.
- **Last-write-wins conflicts.** When two devices edit the same item offline,
  the older edit is discarded, apart from what password history already
  holds.
- **Weak master passwords.** Argon2id slows guessing down. It cannot rescue
  `password1`.
- **Old backups after a password change.** `change-master-password` re-wraps
  the vault key but does not rotate it. Backups and old copies made before the
  change still open with the **old** password. Delete them if the old password
  may be compromised. Rotating the vault key is a known gap.
- **Metadata.** File size, number of items, item ids and edit counts
  (versions), and the timing of saves are all visible.
- **Clipboard managers** that ignore the Windows exclusion formats, or any X11
  or Wayland clipboard manager. These may keep a copy of the secret.
- **Secrets passed as command-line flags.** For example, `kw add --notes …`
  or `kw edit --notes …` end up in shell history and the process list. Use the
  prompting variants (`--notes-prompt`, `--totp`, password prompts) for
  anything sensitive.
- **`--password-stdin`** exists for scripts and tests. Whatever feeds stdin
  (files, CI logs) is outside Keyward's control.
- **Side channels.** AES-GCM uses hardware AES and CLMUL where available.
  Constant-time behaviour of the rest relies on the RustCrypto crates and is
  not independently verified.

## Cryptography used

Only audited or widely reviewed RustCrypto crates are used; there are no
hand-rolled primitives:

- `argon2` 0.5: Argon2id v1.3
- `hkdf` 0.12 and `sha2` 0.10: HKDF-SHA256
- `aes-gcm` 0.10: AES-256-GCM (this version line was audited by NCC Group)
- `rand` 0.8 `OsRng`: all keys, salts and nonces
- `hmac` 0.12 and `sha1` 0.10: TOTP only (HMAC-SHA1 is still secure as a MAC and
  is required by RFC 6238)
- `subtle`: constant-time comparisons of secret strings
- `zeroize` and `secrecy`: wiping memory and redacting secrets

`#![forbid(unsafe_code)]` applies to all Keyward crates. Dependencies, for
example the clipboard backend, do contain `unsafe`.
