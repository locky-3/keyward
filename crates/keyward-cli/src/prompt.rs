//! Reading secrets and confirmations from the terminal (no echo) or stdin.

use std::io::{self, BufRead, Write};

use anyhow::{Context, Result, bail};
use keyward_core::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Minimum master-password length accepted by `init` / `change-master-password`.
pub const MIN_MASTER_LEN: usize = 8;

/// Where secrets come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompter {
    /// Interactive terminal; input is not echoed.
    Tty,
    /// One line per secret from stdin (`--password-stdin`).
    Stdin,
}

impl Prompter {
    /// Read one secret.
    pub fn secret(self, prompt: &str) -> Result<SecretString> {
        match self {
            Self::Tty => {
                let s = rpassword::prompt_password(prompt).context("reading from the terminal")?;
                Ok(SecretString::from(s))
            }
            Self::Stdin => {
                let line = read_stdin_line()?.context("stdin closed while reading a password")?;
                Ok(SecretString::from(line.as_str().to_owned()))
            }
        }
    }

    /// Read a new secret twice and require both entries to match.
    pub fn new_secret(self, what: &str) -> Result<SecretString> {
        let a = self.secret(&format!("{what}: "))?;
        let b = self.secret(&format!("Repeat {}: ", what.to_lowercase()))?;
        let same: bool = a
            .expose_secret()
            .as_bytes()
            .ct_eq(b.expose_secret().as_bytes())
            .into();
        if !same {
            bail!("the two entries did not match");
        }
        Ok(a)
    }

    /// A password to store in an item: confirmed and not empty.
    pub fn new_item_password(self, what: &str) -> Result<SecretString> {
        let pw = self.new_secret(what)?;
        if pw.expose_secret().is_empty() {
            bail!("the password is empty; type one, or use --generate to create a strong one");
        }
        Ok(pw)
    }

    /// A new master password: confirmed and at least [`MIN_MASTER_LEN`] chars.
    pub fn new_master_password(self) -> Result<SecretString> {
        let pw = self.new_secret("New master password")?;
        if pw.expose_secret().chars().count() < MIN_MASTER_LEN {
            bail!("the master password must be at least {MIN_MASTER_LEN} characters");
        }
        Ok(pw)
    }

    /// Ask a yes/no question; defaults to "no".
    pub fn confirm(self, question: &str) -> Result<bool> {
        eprint!("{question} [y/N] ");
        io::stderr().flush()?;
        let answer = read_stdin_line()?.unwrap_or_default();
        Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
    }
}

/// Read one line from stdin without the trailing newline. `None` on EOF.
pub fn read_stdin_line() -> Result<Option<Zeroizing<String>>> {
    let mut line = Zeroizing::new(String::new());
    let n = io::stdin().lock().read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(Some(line))
}
