//! Error type for keyward-core.
//!
//! Variants never carry secret material. Everything that could act as an
//! oracle during unlocking (wrong password, tampered header, tampered key
//! wrap, tampered index or item) collapses into [`Error::UnlockFailed`].

/// Result alias used throughout keyward-core.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors returned by keyward-core.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Wrong master password, or any part of the vault failed authentication.
    /// Deliberately does not say which.
    #[error("could not unlock vault: wrong password or the vault is corrupted")]
    UnlockFailed,

    /// The bytes do not start with the Keyward magic.
    #[error("not a Keyward vault file")]
    NotAVault,

    /// The file uses a format version this build does not understand.
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),

    /// The container could not be parsed (before any decryption).
    #[error("malformed vault file")]
    Malformed,

    /// KDF parameters are outside the accepted range.
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(&'static str),

    /// Password/passphrase generator options are unusable.
    #[error("invalid generator options: {0}")]
    InvalidGeneratorOptions(&'static str),

    /// A TOTP secret or `otpauth://` URI could not be parsed.
    #[error("invalid TOTP secret: {0}")]
    InvalidTotp(&'static str),

    /// No item with the given id exists in the vault.
    #[error("item not found")]
    ItemNotFound,

    /// An item received from the sync server failed authentication.
    #[error("an item from the sync server failed authentication")]
    RemoteIntegrity,

    /// The sync server offered an older version than one already seen.
    #[error("the sync server sent an older item version than previously seen (possible rollback)")]
    RemoteRollback,

    /// The operation needs a vault that is connected to a sync server.
    #[error("this vault is not connected to a sync server")]
    SyncNotConfigured,

    /// An encryption or serialization step failed. Carries no detail on purpose.
    #[error("cryptographic operation failed")]
    Crypto,
}
