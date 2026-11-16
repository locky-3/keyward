# Vault file format (v1)

A Keyward vault is a single file, conventionally `vault.kwv`.

## Container

| Offset | Size | Field            | Notes                                   |
|-------:|-----:|------------------|-----------------------------------------|
| 0      | 4    | magic            | ASCII `KWVT`                            |
| 4      | 2    | format_version   | `u16`, big-endian, currently `1`        |
| 6      | 4    | body_len         | `u32`, big-endian; must equal the rest  |
| 10     | n    | body             | UTF-8 JSON, see below                   |

Trailing bytes, a short body, unknown JSON fields or a different version are
all rejected before any cryptography runs (`Malformed`, `UnsupportedVersion`).

## Body

Binary values are standard base64 (padded). IDs are UUID strings.

```jsonc
{
  "header": {
    "vault_id": "33079530-550f-4775-b934-17e9270ad040",
    "kdf": {
      "algorithm": "argon2id",
      "params": { "m_cost_kib": 65536, "t_cost": 3, "p_cost": 1 },
      "salt": "<16 bytes>"
    }
  },
  "wrapped_vault_key": { "nonce": "<12 bytes>", "ct": "<32 + 16 bytes>" },
  "revision": 7,
  "index":             { "nonce": "<12 bytes>", "ct": "..." },
  "items": [
    { "id": "<uuid>", "version": 3, "blob": { "nonce": "<12 bytes>", "ct": "..." } }
  ]
}
```

## Keys

```text
MK  = Argon2id(password_utf8, salt, m, t, p, version 0x13, out = 32 bytes)
WK  = HKDF-SHA256(ikm = MK, salt = none, info = "keyward/v1/wrap", L = 32)
AK  = HKDF-SHA256(ikm = MK, salt = none, info = "keyward/v1/auth", L = 32)   → LoginHash for the sync server
VK  = 32 random bytes from the OS CSPRNG, generated once per vault
```

The password is used exactly as typed (no Unicode normalisation).

## Encryption

All encryption is AES-256-GCM with a fresh random 96-bit nonce and a 128-bit tag.
`ct` is ciphertext‖tag.

| Object              | Key | Plaintext                    | AAD (all integers big-endian) |
|---------------------|-----|------------------------------|-------------------------------|
| `wrapped_vault_key` | WK  | VK (32 bytes)                | `"kw-wrap-v1" ‖ format_version u16 ‖ vault_id[16] ‖ salt[16] ‖ m u32 ‖ t u32 ‖ p u32` |
| `index`             | VK  | index JSON                   | `"kw-index-v1" ‖ vault_id[16] ‖ revision u64` |
| item `blob`         | VK  | item JSON                    | `"kw-item-v1" ‖ vault_id[16] ‖ item_id[16] ‖ version u64` |

Each AAD starts with a distinct label and every other field has a fixed length,
so AADs from different contexts cannot collide.

Binding the header into the key-wrap AAD means that changing the vault id, the
salt or **any KDF parameter** (for example, a downgrade attempt) makes unlocking
fail.

### Index

```jsonc
{ "vault_id": "<uuid>", "revision": 7,
  "entries": [ { "id": "<uuid>", "version": 3, "digest": "<sha256(nonce ‖ ct) of the blob>" } ] }
```

On unlock, the set of items in the file must match the index exactly: the same
ids, versions and digests, with no extra, missing or duplicate items. This
detects blob swapping, deletion, duplication and rolling back a single item.
Per-item AAD alone cannot catch that last case, because an old blob comes with
its old, matching version number.

### Item plaintext

```jsonc
{ "id": "<uuid>", "version": 3,
  "created": "2026-11-16T21:43:00Z", "updated": "2026-11-16T21:50:12Z",
  "kind": { "login": {
      "title": "GitHub", "username": "octocat", "password": "…",
      "url": "https://github.com", "notes": "…", "tags": ["dev"],
      "totp": "otpauth://totp/…",                   // or null
      "history": [ { "password": "…", "replaced_at": "…" } ]
  } } }
```

`id` and `version` are checked against the outer (authenticated) values.

### Optional sync state (in the index)

A vault connected to a sync server has one extra, optional field in the
**encrypted** index plaintext:

```jsonc
"sync": { "server": "https://vault.example.com", "username": "alice", "cursor": 42,
          "synced": { "<item uuid>": 3 },            // last server version seen
          "pending_deletes": { "<item uuid>": 2 } }   // tombstones still to send
```

The field is omitted when absent, so vaults that never synced are byte-for-byte
in the original v1 layout, and the golden fixture keeps opening. A build that
predates sync cannot open a synced vault: it rejects the unknown field and
reports `UnlockFailed`.

## Unlock algorithm

1. Parse the container. Check that the KDF parameters are within the accepted
   range (m ≥ 19 MiB, t ≥ 2, 1 ≤ p ≤ 16, m ≤ 4 GiB, t ≤ 64).
2. Derive MK, then WK, and open `wrapped_vault_key`.
3. Open `index` with AAD(vault_id, revision) and check its `vault_id` and `revision`.
4. Check that the item list matches the index exactly.
5. Open each item and check its embedded id and version.

Any failure in steps 2–5 returns the same `UnlockFailed` error, so the error
gives no oracle that distinguishes a wrong password from tampering.

## Saving

Only items whose `version` changed since the last unlock or save are
re-encrypted. Unchanged items keep their exact ciphertext. `revision` increases
by one on every save, and the index is re-encrypted each time.

Changing the master password re-wraps VK with a new salt and possibly new KDF
parameters. Items are not touched.

## Compatibility

`crates/keyward-core/tests/fixtures/v1.kwv` is a committed v1 vault (password
`correct horse battery staple`). The `golden_vault` test must keep opening it.
A future format change must bump `format_version` and add a migration. It must
never edit the fixture.
