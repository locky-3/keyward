//! Clipboard with automatic clearing.
//!
//! `kw` hands the secret to a detached copy of itself (`kw __clipboard-daemon`)
//! over a pipe — never via argv or the environment. The daemon puts it on the
//! clipboard, keeps serving it (needed on X11/Wayland where clipboard data
//! lives in the owning process), and after the timeout clears the clipboard
//! **only if it still contains our secret**, so it never wipes something the
//! user copied in the meantime.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use keyward_core::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Copy `secret` to the clipboard and clear it after `seconds`.
pub fn copy_with_timeout(secret: &SecretString, seconds: u64) -> Result<()> {
    let exe = std::env::current_exe().context("locating the kw executable")?;
    let mut cmd = Command::new(exe);
    cmd.args(["__clipboard-daemon", "--seconds", &seconds.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    detach(&mut cmd);
    let mut child = cmd.spawn().context("starting the clipboard helper")?;

    {
        let mut stdin = child.stdin.take().context("clipboard helper stdin")?;
        stdin.write_all(secret.expose_secret().as_bytes())?;
    } // closing stdin signals end of secret

    let mut status = String::new();
    BufReader::new(child.stdout.take().context("clipboard helper stdout")?)
        .read_line(&mut status)?;
    // Reap the helper when it finishes (matters in long-running `kw shell`).
    thread::spawn(move || child.wait());

    match status.trim() {
        "ok" => Ok(()),
        "" => bail!("clipboard helper exited unexpectedly"),
        other => bail!(
            "could not use the clipboard: {}",
            other.trim_start_matches("err: ")
        ),
    }
}

#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Own process group: Ctrl+C in the terminal does not kill the helper.
    cmd.process_group(0);
}

#[cfg(not(any(unix, windows)))]
fn detach(_cmd: &mut Command) {}

/// Body of `kw __clipboard-daemon`. Reports `ok` / `err: …` on stdout.
pub fn run_daemon(seconds: u64) -> Result<()> {
    let mut secret = Zeroizing::new(String::new());
    io::stdin().read_to_string(&mut secret)?;

    let mut out = io::stdout();
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            writeln!(out, "err: {e}")?;
            return Ok(());
        }
    };
    if let Err(e) = set_text(&mut clipboard, &secret) {
        writeln!(out, "err: {e}")?;
        return Ok(());
    }
    writeln!(out, "ok")?;
    out.flush()?;

    thread::sleep(Duration::from_secs(seconds));

    if let Ok(current) = clipboard.get_text() {
        let current = Zeroizing::new(current);
        let unchanged: bool = current.as_bytes().ct_eq(secret.as_bytes()).into();
        if unchanged {
            let _ = clipboard.clear();
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_text(cb: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    use arboard::SetExtWindows;
    // Keep the secret out of Win+V history, cloud clipboard sync and
    // clipboard monitors that honour the exclusion formats.
    cb.set()
        .exclude_from_history()
        .exclude_from_cloud()
        .exclude_from_monitoring()
        .text(text)
}

#[cfg(not(windows))]
fn set_text(cb: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    cb.set_text(text)
}
