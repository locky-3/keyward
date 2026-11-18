//! `kw` — command-line client for Keyward.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use keyward_cli::cli::{Cli, Command, SyncAction, SyncArgs, VaultCommand};
use keyward_cli::prompt::Prompter;
use keyward_cli::session::Session;
use keyward_cli::{clipboard, commands, shell, sync_cmd, vault_path};
use keyward_core::KdfParams;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
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
