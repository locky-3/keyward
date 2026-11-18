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
use std::time::Duration;

use anyhow::{Context, Result};
use cli::{Cli, Command, SyncAction, SyncArgs, VaultCommand};
use keyward_core::KdfParams;
use prompt::Prompter;
use session::Session;

/// The vault path: `explicit` (from `--vault`/`KW_VAULT`) or
/// `<local data dir>/keyward/vault.kwv`.
pub fn vault_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let dir = dirs::data_local_dir().context("no data directory; pass --vault or set KW_VAULT")?;
    Ok(dir.join("keyward").join("vault.kwv"))
}

/// Execute a parsed `kw` command line.
pub fn run(cli: Cli) -> Result<()> {
    let prompter = if cli.password_stdin {
        Prompter::Stdin
    } else {
        Prompter::Tty
    };
    match cli.command {
        Command::ClipboardDaemon { seconds } => clipboard::run_daemon(seconds),
        Command::Vault(VaultCommand::Gen(a)) => commands::gen_password(&a),
        Command::Vault(VaultCommand::Sync(SyncArgs {
            action: Some(SyncAction::Clone(args)),
        })) => sync_cmd::clone(&args, &vault_path(cli.vault)?, prompter),
        Command::Init(kdf) => {
            let path = vault_path(cli.vault)?;
            let params = kdf.resolve(KdfParams::DEFAULT);
            params.validate()?;
            if path.exists() {
                anyhow::bail!("a vault already exists at {}", path.display());
            }
            let pw = prompter.new_master_password()?;
            Session::create(&path, &pw, params)?;
            println!(
                "Created vault at {} (Argon2id: {} MiB, {} passes, {} lane(s))",
                path.display(),
                params.m_cost_kib / 1024,
                params.t_cost,
                params.p_cost
            );
            Ok(())
        }
        Command::Vault(cmd) => {
            let path = vault_path(cli.vault)?;
            let mut session = Session::open(&path, prompter)?;
            commands::run(cmd, &mut session, prompter)
        }
        Command::Shell { idle_timeout } => {
            let path = vault_path(cli.vault)?;
            shell::run(&path, prompter, Duration::from_secs(idle_timeout.max(1)))
        }
    }
}
