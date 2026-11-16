//! `kw shell`: unlock once, run several commands, auto-lock when idle.
//!
//! The unlocked [`Session`] lives in an `Arc<Mutex<Option<_>>>`. A watchdog
//! thread sets it to `None` once no input has arrived for the idle timeout;
//! dropping the session zeroizes the vault key and all decrypted items.
//! The next command asks for the master password again.

use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use zeroize::Zeroizing;

use crate::cli::{ShellCommand, ShellLine, SyncAction, SyncArgs, VaultCommand};
use crate::commands;
use crate::prompt::{Prompter, read_stdin_line};
use crate::session::Session;

/// Tracks the time of the last user activity.
#[derive(Debug, Clone, Copy)]
pub struct IdleTimer {
    timeout: Duration,
    last: Instant,
}

impl IdleTimer {
    pub fn new(timeout: Duration, now: Instant) -> Self {
        Self { timeout, last: now }
    }

    pub fn touch(&mut self, now: Instant) {
        self.last = now;
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last) >= self.timeout
    }
}

struct Shared {
    session: Mutex<Option<Session>>,
    timer: Mutex<IdleTimer>,
    stop: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock cannot leave our data inconsistent in
    // a way that matters here; keep going rather than propagating poison.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn run(path: &Path, prompter: Prompter, idle_timeout: Duration) -> Result<()> {
    let shared = Arc::new(Shared {
        session: Mutex::new(Some(Session::open(path, prompter)?)),
        timer: Mutex::new(IdleTimer::new(idle_timeout, Instant::now())),
        stop: AtomicBool::new(false),
    });
    eprintln!(
        "Vault unlocked. Type `help` for commands, `exit` to quit. \
         Auto-lock after {} s idle.",
        idle_timeout.as_secs()
    );

    let watchdog = {
        let shared = Arc::clone(&shared);
        thread::spawn(move || {
            while !shared.stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(250));
                if lock(&shared.timer).expired(Instant::now()) {
                    let mut s = lock(&shared.session);
                    if s.take().is_some() {
                        eprint!("\n[vault locked after inactivity]\nkw (locked)> ");
                        let _ = io::stderr().flush();
                    }
                }
            }
        })
    };

    let result = repl(path, prompter, &shared);

    shared.stop.store(true, Ordering::Relaxed);
    lock(&shared.session).take(); // zeroize now, not at process exit
    let _ = watchdog.join();
    result
}

fn repl(path: &Path, prompter: Prompter, shared: &Shared) -> Result<()> {
    loop {
        let locked = lock(&shared.session).is_none();
        eprint!("{}", if locked { "kw (locked)> " } else { "kw> " });
        io::stderr().flush()?;

        let Some(line) = read_stdin_line()? else {
            eprintln!();
            return Ok(());
        };
        lock(&shared.timer).touch(Instant::now());

        let words = match shell_words::split(&line) {
            Ok(w) => Zeroizing::new(w),
            Err(e) => {
                eprintln!("error: {e}");
                continue;
            }
        };
        drop(line);
        if words.is_empty() {
            continue;
        }
        let parsed = match ShellLine::try_parse_from(words.iter()) {
            Ok(p) => p,
            Err(e) => {
                let _ = e.print();
                continue;
            }
        };

        let outcome = match parsed.command {
            ShellCommand::Exit => return Ok(()),
            ShellCommand::Lock => {
                lock(&shared.session).take();
                eprintln!("Locked.");
                Ok(())
            }
            ShellCommand::Vault(VaultCommand::Gen(a)) => commands::gen_password(&a),
            ShellCommand::Vault(VaultCommand::Sync(SyncArgs {
                action: Some(SyncAction::Clone(_)),
            })) => Err(anyhow::anyhow!(
                "`kw sync clone` creates a new vault; run it outside the shell"
            )),
            ShellCommand::Vault(cmd) => {
                let mut guard = lock(&shared.session);
                if guard.is_none() {
                    match Session::open(path, prompter) {
                        Ok(s) => *guard = Some(s),
                        Err(e) => {
                            eprintln!("error: {e:#}");
                            continue;
                        }
                    }
                }
                let session = guard.as_mut().expect("session was just ensured");
                commands::run(cmd, session, prompter)
            }
        };
        if let Err(e) = outcome {
            eprintln!("error: {e:#}");
        }
        // Prompts inside a command count as activity too.
        lock(&shared.timer).touch(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_timer_expires_only_after_timeout() {
        let t0 = Instant::now();
        let mut t = IdleTimer::new(Duration::from_secs(10), t0);
        assert!(!t.expired(t0));
        assert!(!t.expired(t0 + Duration::from_secs(9)));
        assert!(t.expired(t0 + Duration::from_secs(10)));
        t.touch(t0 + Duration::from_secs(9));
        assert!(!t.expired(t0 + Duration::from_secs(18)));
        assert!(t.expired(t0 + Duration::from_secs(19)));
    }

    #[test]
    fn idle_timer_tolerates_clock_reordering() {
        let t0 = Instant::now();
        let t = IdleTimer::new(Duration::from_secs(1), t0 + Duration::from_secs(5));
        assert!(!t.expired(t0)); // "now" before last activity
    }
}
