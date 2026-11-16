//! Command-line definitions (clap derive).
//!
//! Doc comments here double as `--help` text, so they are written for the
//! terminal rather than for rustdoc.
#![allow(rustdoc::invalid_html_tags, rustdoc::bare_urls)]

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use keyward_core::KdfParams;

/// Keyward: a zero-knowledge password manager.
#[derive(Debug, Parser)]
#[command(name = "kw", version, about, propagate_version = true)]
pub struct Cli {
    /// Vault file [default: <data dir>/keyward/vault.kwv]
    #[arg(long, global = true, env = "KW_VAULT", value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Read passwords from stdin, one per line, instead of the terminal.
    /// Intended for scripts and tests; anything on stdin may be logged.
    #[arg(long, global = true)]
    pub password_stdin: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new, empty vault
    Init(KdfArgs),

    #[command(flatten)]
    Vault(VaultCommand),

    /// Interactive mode: unlock once, run several commands, auto-lock when idle
    Shell {
        /// Lock after this many seconds without input
        #[arg(long, default_value_t = 300, value_name = "SECONDS")]
        idle_timeout: u64,
    },

    /// Internal: holds a secret on the clipboard and clears it later
    #[command(name = "__clipboard-daemon", hide = true)]
    ClipboardDaemon {
        #[arg(long)]
        seconds: u64,
    },
}

/// Commands that are available both on the command line and inside `kw shell`.
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Add a login
    Add(AddArgs),
    /// Copy a field to the clipboard (default) or print it
    Get(GetArgs),
    /// List all items
    #[command(visible_alias = "ls")]
    List {
        /// Only items with this tag
        #[arg(long, short)]
        tag: Option<String>,
    },
    /// Search title, username, URL and tags
    Search {
        /// Case-insensitive search text
        query: String,
    },
    /// Change fields of an item
    Edit(EditArgs),
    /// Delete an item
    Rm {
        /// Item title, id prefix or search text
        query: String,
        /// Do not ask for confirmation
        #[arg(long, short)]
        yes: bool,
    },
    /// Generate a password or passphrase (no vault needed)
    Gen(GenArgs),
    /// Change the master password (re-wraps the vault key; items are not re-encrypted)
    ChangeMasterPassword(KdfArgs),
    /// Synchronise with a Keyward server (default action: push and pull)
    Sync(SyncArgs),
}

/// `kw sync`
#[derive(Debug, Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub action: Option<SyncAction>,
}

/// Sync sub-commands.
#[derive(Debug, Subcommand)]
pub enum SyncAction {
    /// Pull remote changes and push local ones (the default)
    Run,
    /// Create an account on a server and upload this vault to it
    Register(ServerArgs),
    /// Download a vault from a server into a new local file (`--vault`)
    Clone(ServerArgs),
    /// Show the server connection and pending changes
    Status,
    /// Forget the server connection (local items are kept)
    Disconnect,
}

/// Server address and account.
#[derive(Debug, Args, Clone)]
pub struct ServerArgs {
    /// Server base URL, e.g. https://vault.example.com (http only for localhost)
    #[arg(long)]
    pub server: String,
    /// Account name on the server
    #[arg(long, short)]
    pub username: String,
}

/// Argon2id cost overrides.
#[derive(Debug, Args, Clone, Copy)]
pub struct KdfArgs {
    /// Argon2id memory in MiB [default: 64, or the vault's current value]
    #[arg(long, value_name = "MIB")]
    pub kdf_memory_mib: Option<u32>,
    /// Argon2id passes [default: 3, or the vault's current value]
    #[arg(long, value_name = "N")]
    pub kdf_iterations: Option<u32>,
    /// Argon2id lanes [default: 1, or the vault's current value]
    #[arg(long, value_name = "N")]
    pub kdf_parallelism: Option<u32>,
}

impl KdfArgs {
    /// Apply the overrides on top of `base`.
    pub fn resolve(&self, base: KdfParams) -> KdfParams {
        KdfParams {
            m_cost_kib: self
                .kdf_memory_mib
                .map_or(base.m_cost_kib, |m| m.saturating_mul(1024)),
            t_cost: self.kdf_iterations.unwrap_or(base.t_cost),
            p_cost: self.kdf_parallelism.unwrap_or(base.p_cost),
        }
    }
}

/// `kw add`
#[derive(Debug, Args)]
pub struct AddArgs {
    /// Title of the new item
    pub title: String,
    #[arg(long, short)]
    pub username: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    /// Tag (repeatable)
    #[arg(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,
    /// Notes (visible in shell history; omit for sensitive notes and use `edit --notes-prompt`)
    #[arg(long)]
    pub notes: Option<String>,
    /// Generate the password instead of prompting for it
    #[arg(long, short)]
    pub generate: bool,
    /// Length of the generated password
    #[arg(long, default_value_t = 20, requires = "generate")]
    pub length: usize,
    /// Prompt for a TOTP secret (base32 or otpauth:// URI)
    #[arg(long)]
    pub totp: bool,
}

/// Which field `kw get` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Field {
    Password,
    Username,
    Url,
    Notes,
    /// Current TOTP code
    Totp,
    /// Everything except secrets
    Details,
}

/// `kw get`
#[derive(Debug, Args)]
pub struct GetArgs {
    /// Item title, id prefix or search text
    pub query: String,
    /// Field to return
    #[arg(long, short, value_enum, default_value_t = Field::Password)]
    pub field: Field,
    /// Print to stdout instead of copying to the clipboard
    #[arg(long, short)]
    pub show: bool,
    /// Seconds before the clipboard is cleared
    #[arg(long, default_value_t = 20, value_name = "SECONDS")]
    pub clear_after: u64,
}

/// `kw edit`
#[derive(Debug, Args)]
pub struct EditArgs {
    /// Item title, id prefix or search text
    pub query: String,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long, short)]
    pub username: Option<String>,
    /// New URL (empty string removes it)
    #[arg(long)]
    pub url: Option<String>,
    /// New notes (visible in shell history)
    #[arg(long, conflicts_with = "notes_prompt")]
    pub notes: Option<String>,
    /// Prompt for new notes without echo
    #[arg(long)]
    pub notes_prompt: bool,
    /// Add a tag (repeatable)
    #[arg(long, value_name = "TAG")]
    pub add_tag: Vec<String>,
    /// Remove a tag (repeatable)
    #[arg(long, value_name = "TAG")]
    pub remove_tag: Vec<String>,
    /// Prompt for a new password
    #[arg(long, short, conflicts_with = "generate")]
    pub password: bool,
    /// Generate a new password
    #[arg(long, short)]
    pub generate: bool,
    /// Length of the generated password
    #[arg(long, default_value_t = 20, requires = "generate")]
    pub length: usize,
    /// Prompt for a new TOTP secret
    #[arg(long, conflicts_with = "remove_totp")]
    pub totp: bool,
    /// Remove the TOTP secret
    #[arg(long)]
    pub remove_totp: bool,
}

/// `kw gen`
#[derive(Debug, Args)]
pub struct GenArgs {
    /// Generate a passphrase from the EFF wordlist instead of random characters
    #[arg(long, short)]
    pub passphrase: bool,
    /// Password length
    #[arg(long, short, default_value_t = 20, conflicts_with = "passphrase")]
    pub length: usize,
    #[arg(long, conflicts_with = "passphrase")]
    pub no_lower: bool,
    #[arg(long, conflicts_with = "passphrase")]
    pub no_upper: bool,
    #[arg(long, conflicts_with = "passphrase")]
    pub no_digits: bool,
    #[arg(long, conflicts_with = "passphrase")]
    pub no_symbols: bool,
    /// Avoid look-alike characters (I l 1 O 0 o)
    #[arg(long, short = 'a', conflicts_with = "passphrase")]
    pub exclude_ambiguous: bool,
    /// Number of words
    #[arg(long, short, default_value_t = 6, requires = "passphrase")]
    pub words: usize,
    /// Word separator
    #[arg(long, default_value = "-", requires = "passphrase")]
    pub separator: String,
    /// Capitalise each word
    #[arg(long, requires = "passphrase")]
    pub capitalize: bool,
    /// Append a random digit to one word
    #[arg(long, requires = "passphrase")]
    pub digit: bool,
    /// Copy to the clipboard (cleared after 20 s) instead of printing
    #[arg(long, short)]
    pub copy: bool,
}

/// One line typed into `kw shell`.
#[derive(Debug, Parser)]
#[command(no_binary_name = true, disable_version_flag = true)]
pub struct ShellLine {
    #[command(subcommand)]
    pub command: ShellCommand,
}

/// Commands accepted inside `kw shell`.
#[derive(Debug, Subcommand)]
pub enum ShellCommand {
    #[command(flatten)]
    Vault(VaultCommand),
    /// Lock the vault now (forget all keys)
    Lock,
    /// Leave the shell
    #[command(visible_alias = "quit")]
    Exit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
        ShellLine::command().debug_assert();
    }

    #[test]
    fn kdf_overrides() {
        let a = KdfArgs {
            kdf_memory_mib: Some(128),
            kdf_iterations: None,
            kdf_parallelism: Some(2),
        };
        let p = a.resolve(KdfParams::DEFAULT);
        assert_eq!(
            (p.m_cost_kib, p.t_cost, p.p_cost),
            (128 * 1024, KdfParams::DEFAULT.t_cost, 2)
        );
    }

    #[test]
    fn shell_line_parses_vault_commands() {
        let l = ShellLine::try_parse_from(["get", "github", "-f", "username", "--show"]).unwrap();
        assert!(matches!(
            l.command,
            ShellCommand::Vault(VaultCommand::Get(GetArgs { show: true, .. }))
        ));
        assert!(ShellLine::try_parse_from(["init"]).is_err());
        assert!(ShellLine::try_parse_from(["shell"]).is_err());
    }
}
