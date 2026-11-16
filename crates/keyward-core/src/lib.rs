//! Keyward core: key derivation, vault format, item model, password
//! generation and TOTP. This crate performs no I/O; callers hand it bytes.
#![forbid(unsafe_code)]

mod aead;
mod encoding;
pub mod error;
pub mod generator;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod vault;

pub use error::{Error, Result};
pub use item::{Item, ItemId, ItemKind, Login, PasswordHistoryEntry};
pub use kdf::{KdfParams, Salt, derive_master_key};
pub use keys::{AuthKey, MasterKey, VaultKey, WrapKey};
pub use secrecy::{ExposeSecret, SecretString};
pub use vault::{FORMAT_VERSION, Header, UnlockedVault, VaultFile, VaultId};
