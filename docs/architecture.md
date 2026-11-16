# Architecture

## Crates

| Crate | Role | I/O |
|---|---|---|
| `keyward-core` | KDF, key hierarchy, AEAD, item model, vault format, generator, TOTP | none: bytes in, bytes out |
| `keyward-cli` (`kw`) | Commands, prompts, clipboard, atomic storage, interactive shell | filesystem, terminal, clipboard |
| `keyward-server` | Phase 2: axum + SQLite sync server that stores only ciphertext | network, DB |
| `keyward-tui` | Phase 3: ratatui client | terminal |

`keyward-core` doing no I/O keeps it easy to test exhaustively (property tests
and known-answer tests) and lets the CLI, TUI and server share it unchanged.

## Data flow: `kw get github`

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as kw (cli)
    participant S as storage
    participant C as keyward-core
    participant D as clipboard daemon
    U->>CLI: kw get github
    CLI->>S: read_vault(path)
    S-->>CLI: VaultFile (ciphertext)
    CLI->>U: Master password? (no echo)
    CLI->>C: VaultFile::unlock(pw)
    C->>C: Argon2id → MK → HKDF → WK
    C->>C: open(WK, wrapped VK) → open(VK, index) → verify items → open items
    C-->>CLI: UnlockedVault
    CLI->>CLI: resolve("github") → ItemId
    CLI->>D: spawn detached, secret via stdin pipe
    D-->>CLI: "ok"
    CLI-->>U: Copied; clears in 20 s
    Note over D: sleep 20 s; clear if unchanged
```

## Key hierarchy

```mermaid
flowchart LR
    P[master password] -->|Argon2id<br/>salt, m, t, p| MK[MasterKey]
    MK -->|HKDF info=keyward/v1/wrap| WK[WrapKey]
    MK -->|HKDF info=keyward/v1/auth| AK[AuthKey<br/>phase 2]
    RNG[OsRng] --> VK[VaultKey]
    WK -->|AES-GCM, AAD=header| WVK[(wrapped VK)]
    VK -->|AES-GCM, AAD=vault,rev| IDX[(index)]
    VK -->|AES-GCM, AAD=vault,item,ver| ITEMS[(items)]
```

## Saving

`Session::save` runs in this order:

1. Take the exclusive `vault.kwv.lock`.
2. Re-read the file and refuse to save if its revision is no longer the one we
   unlocked.
3. `UnlockedVault::seal`: re-encrypt dirty items, rebuild the index, and
   increase the revision.
4. `storage::write_atomic`: write a temp file and fsync it, rotate
   `.bak.1..3`, rename over the vault, then fsync the directory (Unix).

## Memory hygiene

- Keys are `SecretBox<[u8; 32]>` inside newtypes. They zeroize on drop and
  print `[REDACTED]` in `Debug`.
- `Login` derives `ZeroizeOnDrop`. Its secret fields are `SecretString`.
- Plaintext JSON is produced in exact-size `Zeroizing<Vec<u8>>` buffers. A
  counting pass runs first so the buffer never reallocates.
- AES and GCM key schedules zeroize on drop (the `aes-gcm` `zeroize` feature).
- `kw shell` keeps the session in `Arc<Mutex<Option<Session>>>`. The idle
  watchdog sets it to `None`, which drops and zeroizes everything.

The known limits are listed in [SECURITY.md](../SECURITY.md).

## Testing strategy

| Layer | Technique |
|---|---|
| KDF | RFC 9106 Argon2id vector, parameter floor and ceiling tests |
| HKDF | Known-answer value computed independently (Python `hmac`) |
| AEAD | proptest round-trip; proptest single-bit flips in nonce, ct and AAD |
| Vault | Tamper tests: swap, rollback, delete, duplicate, cross-vault, header and KDF downgrade, revision. proptest: a bit flip anywhere never yields *different* contents. A test documents that whole-file rollback is undetectable. |
| Format | Golden `v1.kwv` fixture must open forever |
| Generator | Class coverage, exact entropy, χ² uniformity, EFF list integrity |
| TOTP | RFC 6238 Appendix B (SHA1/256/512), RFC 4226 Appendix D |
| CLI | Unit tests (storage, lock, conflict detection, idle timer) and end-to-end `assert_cmd` runs of every command, including the shell |
