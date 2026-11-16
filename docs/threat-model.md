# Threat model

## Assets

1. **The master password.** It unlocks everything, and users may reuse it
   elsewhere despite advice.
2. **Item secrets.** Passwords, notes, TOTP seeds and password history.
3. **Item metadata.** Titles, usernames, URLs and tags. These are treated as
   secret and encrypted.
4. **Integrity.** A user must never be shown, or copy, a password an attacker
   chose.
5. **Availability.** The vault must survive crashes and concurrent use.

## Trust boundaries

```text
 trusted while unlocked             untrusted at rest
┌──────────────────────────┐      ┌───────────────────────────┐
│ kw process (memory)      │ ───> │ vault.kwv, .bak.N files   │
│  - master key, VK        │      │ disk, cloud backup, USB,  │
│  - decrypted items       │ <─── │ sync server (phase 2)     │
└──────────────────────────┘      └───────────────────────────┘
          ▲  OS, terminal, clipboard: trusted, see "out of scope"
```

## Adversaries and outcomes

| # | Adversary | Capability | Expected outcome |
|---|---|---|---|
| A1 | Thief or cloud provider | Reads the vault file and its backups | Learns only public metadata (see SECURITY.md). Must brute-force Argon2id per guess. |
| A2 | Active file tamperer | Modifies, replaces, reorders or truncates the file, or mixes in blobs from other vaults or older versions | Unlocking fails with a generic error. **Exception:** restoring a complete older file (whole-file rollback) succeeds. |
| A3 | Downgrader | Lowers the KDF cost in the header to speed up guessing | The header is authenticated, so the vault refuses to open. Values below the floor are refused even before derivation. |
| A4 | Another `kw` process | Edits the vault at the same time | The lock file plus a revision check reject the second write. No silent lost update. |
| A5 | Shoulder surfer | Watches the screen | Passwords are not echoed. `list` and `details` never print secrets. Clipboard is the default. |
| A6 | Local malware or root | Reads memory, keystrokes and clipboard | **Out of scope.** No software-only password manager defends against this. |

## Design decisions

- **Two-level keys (MK → WK → VK).** Changing the password re-wraps 48 bytes
  instead of re-encrypting every item, and the same design will carry over to
  sync and shared vaults.
- **HKDF domain separation.** The Argon2 output never encrypts anything
  directly. A future server sees only material derived from
  `"keyward/v1/auth"`, which reveals nothing about the wrapping key.
- **Random nonces.** 96-bit random nonces are safe for about 2³² encryptions
  under one key. A vault re-encrypts only changed items, so it stays many
  orders of magnitude below that.
- **Generic errors.** No "bad MAC on item 3" style oracle.
- **JSON container.** Easy to inspect and debug while learning. It is not
  security-relevant, because every byte that matters is either authenticated or
  parsed strictly with `deny_unknown_fields`.

## Known gaps (tracked)

- No vault-key rotation, so old backups still open with old passwords.
- No `mlock` or `VirtualLock` of secret pages.
- Whole-file rollback cannot be detected offline.
- Login items only. Notes, cards and identities come later.
- A future upgrade to the newer RustCrypto release line (`aes-gcm` 0.11,
  `argon2` 0.6, …) is pending.
