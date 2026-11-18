//! Library half of `kw`: everything except argument dispatch, so that other
//! front-ends (the TUI) can reuse storage, sessions, clipboard and sync.
#![forbid(unsafe_code)]

pub mod cli;
pub mod clipboard;
pub mod commands;
pub mod prompt;
pub mod session;
pub mod shell;
pub mod storage;
pub mod sync_client;
pub mod sync_cmd;

use std::path::PathBuf;

use anyhow::{Context, Result};

/// The vault path: `explicit` (from `--vault`/`KW_VAULT`) or
/// `<local data dir>/keyward/vault.kwv`.
pub fn vault_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let dir = dirs::data_local_dir().context("no data directory; pass --vault or set KW_VAULT")?;
    Ok(dir.join("keyward").join("vault.kwv"))
}
