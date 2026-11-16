-- Keyward sync server schema. The server stores only:
--   * an Argon2id hash of each account's login hash,
--   * the vault header (KDF params, salt, vault id) and the wrapped vault key,
--   * item blobs (nonce + AES-GCM ciphertext) with their versions.
-- Nothing here can decrypt anything.

CREATE TABLE server_meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE accounts (
    id         INTEGER PRIMARY KEY,
    username   TEXT    NOT NULL UNIQUE,          -- normalised to lower case
    login_phc  TEXT    NOT NULL,                 -- Argon2id PHC string
    vault_json TEXT    NOT NULL,                 -- RemoteVault (header + wrapped key)
    seq        INTEGER NOT NULL DEFAULT 0,       -- per-account change counter
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash BLOB    PRIMARY KEY,              -- SHA-256 of the bearer token
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_by_account ON sessions(account_id);

CREATE TABLE items (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    item_id    TEXT    NOT NULL,
    version    INTEGER NOT NULL CHECK (version > 0),
    deleted    INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    nonce      BLOB,
    ciphertext BLOB,
    seq        INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, item_id),
    CHECK ((deleted = 1 AND nonce IS NULL AND ciphertext IS NULL)
        OR (deleted = 0 AND nonce IS NOT NULL AND ciphertext IS NOT NULL))
);
CREATE INDEX items_by_seq ON items(account_id, seq);
