//! `keyward` — opens the terminal UI, or runs a `kw` command when given one:
//!
//! ```text
//! keyward                 # TUI
//! keyward add GitHub -u me
//! keyward list            # …every `kw` command works the same way
//! ```
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use clap::Parser;
use keyward_cli::cli::{Cli, Command};
use keyward_cli::{clipboard, vault_path};
use keyward_tui::app::{Action, App, CLIPBOARD_SECS};
use keyward_tui::ui;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};

/// Keyward password manager. Without a command, opens the terminal UI.
#[derive(Debug, Parser)]
#[command(name = "keyward", version, about, propagate_version = true)]
struct Args {
    /// Vault file [default: <data dir>/keyward/vault.kwv]
    #[arg(long, global = true, env = "KW_VAULT", value_name = "PATH")]
    vault: Option<PathBuf>,

    /// Read passwords from stdin, one per line (commands only; for scripts)
    #[arg(long, global = true)]
    password_stdin: bool,

    /// TUI: lock after this many seconds without a key press
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    idle_timeout: u64,

    #[command(subcommand)]
    command: Option<Command>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let result = match args.command {
        // Same commands as `kw` (including the hidden clipboard helper,
        // which the clipboard code starts by re-running this binary).
        Some(command) => keyward_cli::run(Cli {
            vault: args.vault,
            password_stdin: args.password_stdin,
            command,
        }),
        None => run_tui(args.vault, args.idle_timeout),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_tui(vault: Option<PathBuf>, idle_timeout: u64) -> Result<()> {
    let path = vault_path(vault)?;
    if !path.exists() {
        bail!(
            "no vault at {} (create one with `keyward init`, or `keyward sync clone`)",
            path.display()
        );
    }
    let app = App::new(
        path,
        Duration::from_secs(idle_timeout.max(10)),
        Instant::now(),
    );
    // Raw mode + alternate screen; restored on exit and on panic.
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, app);
    ratatui::restore();
    result
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn event_loop(terminal: &mut DefaultTerminal, mut app: App) -> Result<()> {
    loop {
        app.tick(Instant::now());
        terminal.draw(|f| ui::draw(f, &app, Instant::now(), unix_now()))?;
        if app.should_quit {
            return Ok(());
        }
        // Wake up regularly for the TOTP countdown and auto-lock.
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        // Windows reports both press and release; act on presses only.
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match app.handle_key(key, Instant::now()) {
            Action::None => {}
            Action::Copy { secret, what } => {
                let r = clipboard::copy_with_timeout(&secret, CLIPBOARD_SECS);
                app.copied(what, r, Instant::now());
            }
            Action::Unlock(pw) => {
                app.busy = Some("Unlocking…");
                terminal.draw(|f| ui::draw(f, &app, Instant::now(), unix_now()))?;
                app.unlock(&pw, Instant::now());
                app.busy = None;
            }
            Action::Sync => {
                app.busy = Some("Syncing…");
                terminal.draw(|f| ui::draw(f, &app, Instant::now(), unix_now()))?;
                app.sync(Instant::now());
                app.busy = None;
            }
        }
    }
}
