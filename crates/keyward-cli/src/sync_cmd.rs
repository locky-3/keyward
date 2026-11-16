//! `kw sync …` commands.

use std::path::Path;

use anyhow::{Context, Result, bail};
use keyward_core::sync::api::{ChangePasswordRequest, RegisterRequest};
use keyward_core::sync::login_hash_for;
use keyward_core::{MergeOutcome, PasswordChange, SyncState, UnlockedVault};

use crate::cli::{ServerArgs, SyncAction};
use crate::prompt::Prompter;
use crate::session::Session;
use crate::sync_client::{Client, WriteOutcome, normalise_server_url};

/// Counts for the summary line.
#[derive(Debug, Default)]
pub struct Report {
    pub received: usize,
    pub removed: usize,
    pub conflicts: usize,
    pub pushed: usize,
    pub deleted: usize,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "received {} change(s), removed {}, sent {}, deleted {} on server, {} conflict(s) resolved",
            self.received, self.removed, self.pushed, self.deleted, self.conflicts
        )
    }
}

/// Run a sync action that needs an unlocked local vault.
pub fn run(action: SyncAction, s: &mut Session) -> Result<()> {
    match action {
        SyncAction::Run => {
            let report = sync_session(s)?;
            println!("Synced: {report}.");
            Ok(())
        }
        SyncAction::Register(args) => register(&args, s),
        SyncAction::Status => {
            match s.vault.sync_state() {
                None => println!("Not connected to a sync server."),
                Some(st) => {
                    println!("Server:   {}", st.server);
                    println!("Username: {}", st.username);
                    println!("Cursor:   {}", st.cursor);
                    println!("Synced:   {} item(s)", st.synced.len());
                    println!(
                        "Pending:  {} to send, {} deletion(s)",
                        s.vault.pending_pushes().len(),
                        s.vault.pending_deletes().len()
                    );
                }
            }
            Ok(())
        }
        SyncAction::Disconnect => {
            if s.vault.sync_state().is_none() {
                bail!("this vault is not connected to a sync server");
            }
            s.vault.set_sync_state(None);
            s.save()?;
            println!("Disconnected. Items stay in the local vault; the server copy is unchanged.");
            Ok(())
        }
        SyncAction::Clone(_) => {
            bail!("`kw sync clone` creates a new vault; run it outside `kw shell`")
        }
    }
}

fn register(args: &ServerArgs, s: &mut Session) -> Result<()> {
    if let Some(st) = s.vault.sync_state() {
        bail!(
            "this vault is already connected to {} as {}; run `kw sync disconnect` first",
            st.server,
            st.username
        );
    }
    let server = normalise_server_url(&args.server)?;
    let client = Client::new(&server)?;
    client.register(&RegisterRequest {
        username: args.username.clone(),
        login_hash: s.login_hash().clone(),
        vault: s.vault.remote_vault(),
    })?;
    s.vault
        .set_sync_state(Some(SyncState::new(&server, &args.username)));
    s.save()?;
    println!("Registered \"{}\" on {server}.", args.username);
    let report = sync_session(s)?;
    println!("Synced: {report}.");
    Ok(())
}

/// `kw sync clone`: create a new local vault from the server.
pub fn clone(args: &ServerArgs, path: &Path, p: Prompter) -> Result<()> {
    if path.exists() {
        bail!(
            "{} already exists; choose a new path with --vault",
            path.display()
        );
    }
    let server = normalise_server_url(&args.server)?;
    let mut client = Client::new(&server)?;
    let pre = client.prelogin(&args.username)?;
    let pw = p.secret("Master password: ")?;
    let login = login_hash_for(&pw, &pre.kdf)?;
    client.login(&args.username, &login)?;
    let remote = client.vault()?;
    let (mut vault, login2) =
        UnlockedVault::from_remote(remote.header, remote.wrapped_vault_key, &pw)
            .context("could not open the server's vault with this master password")?;
    if login2 != login {
        bail!("the server's KDF settings do not match its vault header");
    }
    vault.set_sync_state(Some(SyncState::new(&server, &args.username)));
    let mut session = Session::create_from(path, vault, login)?;
    let report = pull_push(&client, &mut session.vault);
    session.save()?;
    client.logout();
    let report = report?;
    println!(
        "Cloned vault into {} ({} item(s)).",
        path.display(),
        session.vault.len()
    );
    println!("Synced: {report}.");
    Ok(())
}

/// Log in with the session's credentials and sync both ways.
pub fn sync_session(s: &mut Session) -> Result<Report> {
    let st = s
        .vault
        .sync_state()
        .cloned()
        .context("this vault is not connected to a sync server (see `kw sync register`)")?;
    let mut client = Client::new(&st.server)?;
    client.login(&st.username, s.login_hash())?;
    let remote = client.vault()?;
    if remote.header.vault_id != s.vault.header().vault_id {
        client.logout();
        bail!("the server holds a different vault for this account");
    }
    // Keep whatever was merged even if a later step fails.
    let result = pull_push(&client, &mut s.vault);
    let saved = s.save();
    client.logout();
    let report = result?;
    saved?;
    Ok(report)
}

fn note(report: &mut Report, o: MergeOutcome) {
    match o {
        MergeOutcome::Unchanged => {}
        MergeOutcome::Inserted | MergeOutcome::Updated => report.received += 1,
        MergeOutcome::Deleted => report.removed += 1,
        MergeOutcome::KeptLocal | MergeOutcome::ReplacedLocal => report.conflicts += 1,
    }
}

fn pull_push(client: &Client, v: &mut UnlockedVault) -> Result<Report> {
    let mut report = Report::default();

    // 1. pull everything newer than our cursor
    loop {
        let cursor = v.sync_state().map_or(0, |s| s.cursor);
        let page = client.pull(cursor)?;
        for change in &page.changes {
            note(&mut report, v.apply_remote(change)?);
        }
        v.set_sync_cursor(page.cursor)?;
        if !page.has_more {
            break;
        }
    }

    // 2. push new/changed items; on a race, merge the server copy and retry
    for id in v.pending_pushes() {
        for attempt in 0..3 {
            if !v.pending_pushes().contains(&id) {
                break; // resolved in favour of the server copy
            }
            let req = v.prepare_push(id)?;
            match client.push(id, &req)? {
                WriteOutcome::Ok(w) => {
                    v.mark_pushed(id, w.version)?;
                    report.pushed += 1;
                    break;
                }
                WriteOutcome::Conflict(Some(current)) if attempt < 2 => {
                    note(&mut report, v.apply_remote(&current)?);
                }
                WriteOutcome::Conflict(_) | WriteOutcome::NotFound => {
                    bail!(
                        "could not push item {} (server state changed); run `kw sync` again",
                        id.short()
                    )
                }
            }
        }
    }

    // 3. send tombstones
    for (id, base) in v.pending_deletes() {
        match client.delete(id, base)? {
            WriteOutcome::Ok(_) => {
                v.mark_delete_done(id)?;
                report.deleted += 1;
            }
            WriteOutcome::NotFound => v.mark_delete_done(id)?,
            WriteOutcome::Conflict(Some(current)) => {
                // Edited elsewhere after we deleted: the edit wins.
                note(&mut report, v.apply_remote(&current)?);
                v.mark_delete_done(id)?;
            }
            WriteOutcome::Conflict(None) => v.mark_delete_done(id)?,
        }
    }
    Ok(report)
}

/// Master-password change that keeps the server in step: the server must
/// accept the new credential before the local vault is changed.
pub fn change_password_synced(s: &mut Session, change: PasswordChange) -> Result<()> {
    let st = s
        .vault
        .sync_state()
        .cloned()
        .context("not connected to a sync server")?;
    let mut client = Client::new(&st.server)?;
    client.login(&st.username, s.login_hash())?;
    client
        .change_password(&ChangePasswordRequest {
            current_login_hash: s.login_hash().clone(),
            new_login_hash: change.login.clone(),
            vault: change.remote.clone(),
        })
        .context("the server did not accept the new master password; nothing was changed")?;
    // The server revoked all sessions, including ours; no logout needed.
    s.commit_password_change(change);
    s.save().context(
        "the SERVER now uses the new master password but saving the local vault failed; \
         run `kw sync clone` into a new file with the new password",
    )
}
