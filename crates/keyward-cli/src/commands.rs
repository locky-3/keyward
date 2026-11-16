//! Command handlers.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use keyward_core::generator::{generate_passphrase, generate_password};
use keyward_core::{
    CharsetOptions, ExposeSecret, Item, ItemId, ItemKind, Login, PassphraseOptions, SecretString,
    Totp, UnlockedVault,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cli::{AddArgs, EditArgs, Field, GenArgs, GetArgs, VaultCommand};
use crate::clipboard;
use crate::prompt::Prompter;
use crate::session::Session;

/// Run a command against an unlocked vault.
pub fn run(cmd: VaultCommand, s: &mut Session, p: Prompter) -> Result<()> {
    match cmd {
        VaultCommand::Add(a) => add(a, s, p),
        VaultCommand::Get(a) => get(a, &s.vault),
        VaultCommand::List { tag } => {
            let items = s.vault.list();
            let items: Vec<&Item> = match &tag {
                Some(t) => items.into_iter().filter(|i| has_tag(i, t)).collect(),
                None => items,
            };
            print_table(&items);
            Ok(())
        }
        VaultCommand::Search { query } => {
            print_table(&s.vault.search(&query));
            Ok(())
        }
        VaultCommand::Edit(a) => edit(a, s, p),
        VaultCommand::Rm { query, yes } => rm(&query, yes, s, p),
        VaultCommand::Gen(a) => gen_password(&a),
        VaultCommand::ChangeMasterPassword(a) => {
            let current = s.vault.header().kdf.params;
            let kdf = a.resolve(current);
            kdf.validate()?;
            let new = p.new_master_password()?;
            s.vault.change_master_password(&new, kdf)?;
            s.save()?;
            println!("Master password changed.");
            eprintln!(
                "note: older backups ({}.bak.*) still open with the OLD password; \
                 delete them if that password may be compromised.",
                s.path().display()
            );
            Ok(())
        }
    }
}

fn add(a: AddArgs, s: &mut Session, p: Prompter) -> Result<()> {
    let password = if a.generate {
        let opts = CharsetOptions {
            length: a.length,
            ..Default::default()
        };
        generate_password(&opts)?.0
    } else {
        p.new_secret(&format!("Password for {}", a.title))?
    };
    let mut login = Login::new(a.title, a.username.unwrap_or_default(), password);
    login.url = a.url.filter(|u| !u.is_empty());
    login.tags = dedup_tags(a.tags);
    if let Some(n) = a.notes {
        login.notes = SecretString::from(n);
    }
    if a.totp {
        login.totp = Some(prompt_totp(p)?);
    }
    let title = login.title.clone();
    let id = s.vault.add(ItemKind::Login(login));
    s.save()?;
    println!("Added \"{title}\" ({})", id.short());
    if a.generate {
        println!(
            "A password was generated; copy it with `kw get {}`.",
            id.short()
        );
    }
    Ok(())
}

fn get(a: GetArgs, v: &UnlockedVault) -> Result<()> {
    let item = v.get(resolve(v, &a.query)?).context("item vanished")?;
    let login = item.kind.as_login().context("not a login")?;
    let value: SecretString = match a.field {
        Field::Details => {
            print_details(item, login);
            return Ok(());
        }
        Field::Password => login.password.clone(),
        Field::Username => SecretString::from(login.username.clone()),
        Field::Url => SecretString::from(login.url.clone().unwrap_or_default()),
        Field::Notes => login.notes.clone(),
        Field::Totp => {
            let secret = login
                .totp
                .as_ref()
                .context("this item has no TOTP secret")?;
            let totp = Totp::parse(secret.expose_secret())?;
            let now = unix_now();
            eprintln!("(valid for {} more seconds)", totp.seconds_remaining(now));
            totp.code_at(now)
        }
    };
    if a.show {
        println!("{}", value.expose_secret());
    } else {
        clipboard::copy_with_timeout(&value, a.clear_after)?;
        println!(
            "Copied {} of \"{}\" to the clipboard; it will be cleared in {} s.",
            field_name(a.field),
            login.title,
            a.clear_after
        );
    }
    Ok(())
}

fn edit(a: EditArgs, s: &mut Session, p: Prompter) -> Result<()> {
    let id = resolve(&s.vault, &a.query)?;
    // Collect every prompted/generated value first: the update closure
    // cannot fail or prompt.
    let new_password = if a.password {
        Some(p.new_secret("New password")?)
    } else if a.generate {
        let opts = CharsetOptions {
            length: a.length,
            ..Default::default()
        };
        Some(generate_password(&opts)?.0)
    } else {
        None
    };
    let new_notes = if a.notes_prompt {
        Some(p.secret("Notes: ")?)
    } else {
        a.notes.map(SecretString::from)
    };
    let new_totp = if a.totp { Some(prompt_totp(p)?) } else { None };

    let nothing = new_password.is_none()
        && new_notes.is_none()
        && new_totp.is_none()
        && !a.remove_totp
        && a.title.is_none()
        && a.username.is_none()
        && a.url.is_none()
        && a.add_tag.is_empty()
        && a.remove_tag.is_empty();
    if nothing {
        bail!("nothing to change; see `kw edit --help`");
    }

    let generated = a.generate;
    s.vault.update(id, move |kind| {
        let Some(l) = kind.as_login_mut() else { return };
        if let Some(t) = a.title {
            l.title = t;
        }
        if let Some(u) = a.username {
            l.username = u;
        }
        if let Some(u) = a.url {
            l.url = Some(u).filter(|u| !u.is_empty());
        }
        if let Some(n) = new_notes {
            l.notes = n;
        }
        if let Some(pw) = new_password {
            l.password = pw;
        }
        if let Some(t) = new_totp {
            l.totp = Some(t);
        }
        if a.remove_totp {
            l.totp = None;
        }
        l.tags
            .retain(|t| !a.remove_tag.iter().any(|r| r.eq_ignore_ascii_case(t)));
        let mut tags = std::mem::take(&mut l.tags);
        tags.extend(a.add_tag);
        l.tags = dedup_tags(tags);
    })?;
    s.save()?;
    let title = s.vault.get(id).map(|i| i.kind.title().to_owned());
    println!("Updated \"{}\"", title.unwrap_or_default());
    if generated {
        println!("A new password was generated; the old one is kept in the item's history.");
    }
    Ok(())
}

fn rm(query: &str, yes: bool, s: &mut Session, p: Prompter) -> Result<()> {
    let id = resolve(&s.vault, query)?;
    let title = s
        .vault
        .get(id)
        .map(|i| i.kind.title().to_owned())
        .unwrap_or_default();
    if !yes && !p.confirm(&format!("Delete \"{title}\" ({})?", id.short()))? {
        println!("Cancelled.");
        return Ok(());
    }
    s.vault.remove(id)?;
    s.save()?;
    println!("Deleted \"{title}\"");
    Ok(())
}

/// `kw gen` — needs no vault.
pub fn gen_password(a: &GenArgs) -> Result<()> {
    let (pw, entropy) = if a.passphrase {
        generate_passphrase(&PassphraseOptions {
            words: a.words,
            separator: a.separator.clone(),
            capitalize: a.capitalize,
            add_digit: a.digit,
        })?
    } else {
        generate_password(&CharsetOptions {
            length: a.length,
            lower: !a.no_lower,
            upper: !a.no_upper,
            digits: !a.no_digits,
            symbols: !a.no_symbols,
            exclude_ambiguous: a.exclude_ambiguous,
        })?
    };
    if a.copy {
        clipboard::copy_with_timeout(&pw, 20)?;
        println!("Copied to the clipboard; it will be cleared in 20 s.");
    } else {
        println!("{}", pw.expose_secret());
    }
    eprintln!("entropy: {entropy} ({})", entropy.strength());
    Ok(())
}

/// Find exactly one item by id prefix, exact title, or unique search hit.
pub fn resolve(v: &UnlockedVault, query: &str) -> Result<ItemId> {
    let q = query.trim();
    if q.is_empty() {
        bail!("empty item query");
    }
    let hex: String = q
        .chars()
        .filter(|c| *c != '-')
        .collect::<String>()
        .to_lowercase();
    if hex.len() >= 4 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let by_id: Vec<ItemId> = v
            .ids()
            .into_iter()
            .filter(|id| id.to_hex().starts_with(&hex))
            .collect();
        if by_id.len() == 1 {
            return Ok(by_id[0]);
        }
    }
    let exact: Vec<&Item> = v
        .list()
        .into_iter()
        .filter(|i| i.kind.title().eq_ignore_ascii_case(q))
        .collect();
    let candidates = if exact.is_empty() { v.search(q) } else { exact };
    match candidates.as_slice() {
        [one] => Ok(one.id),
        [] => bail!("no item matches \"{q}\""),
        many => {
            let list: Vec<String> = many
                .iter()
                .take(10)
                .map(|i| format!("  {}  {}", i.id.short(), i.kind.title()))
                .collect();
            bail!(
                "\"{q}\" matches {} items; use a more specific title or an id:\n{}",
                many.len(),
                list.join("\n")
            )
        }
    }
}

fn prompt_totp(p: Prompter) -> Result<SecretString> {
    let s = p.secret("TOTP secret (base32 or otpauth:// URI): ")?;
    Totp::parse(s.expose_secret()).context("checking the TOTP secret")?;
    Ok(s)
}

fn has_tag(i: &Item, tag: &str) -> bool {
    i.kind
        .as_login()
        .is_some_and(|l| l.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
}

fn dedup_tags(tags: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim().to_owned();
        if !t.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(&t)) {
            out.push(t);
        }
    }
    out
}

fn field_name(f: Field) -> &'static str {
    match f {
        Field::Password => "the password",
        Field::Username => "the username",
        Field::Url => "the URL",
        Field::Notes => "the notes",
        Field::Totp => "the TOTP code",
        Field::Details => "the details",
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fmt_time(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "?".into())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn print_table(items: &[&Item]) {
    if items.is_empty() {
        println!("(no items)");
        return;
    }
    let rows: Vec<[String; 4]> = items
        .iter()
        .map(|i| {
            let l = i.kind.as_login();
            [
                i.id.short(),
                truncate(i.kind.title(), 32),
                truncate(l.map_or("", |l| &l.username), 28),
                truncate(l.and_then(|l| l.url.as_deref()).unwrap_or(""), 40),
            ]
        })
        .collect();
    let headers = ["ID", "TITLE", "USERNAME", "URL"];
    let mut w = headers.map(|h| h.chars().count());
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cols: [&str; 4]| {
        let s = format!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {}",
            cols[0],
            cols[1],
            cols[2],
            cols[3],
            w0 = w[0],
            w1 = w[1],
            w2 = w[2],
        );
        println!("{}", s.trim_end());
    };
    line(headers);
    for r in &rows {
        line([&r[0], &r[1], &r[2], &r[3]]);
    }
}

fn print_details(item: &Item, l: &Login) {
    let notes = l.notes.expose_secret();
    println!("Title:     {}", l.title);
    println!("Username:  {}", l.username);
    println!("Password:  ******** (kw get {} --show)", item.id.short());
    println!("URL:       {}", l.url.as_deref().unwrap_or("-"));
    println!(
        "Tags:      {}",
        if l.tags.is_empty() {
            "-".to_owned()
        } else {
            l.tags.join(", ")
        }
    );
    println!(
        "TOTP:      {}",
        if l.totp.is_some() { "configured" } else { "-" }
    );
    println!(
        "Notes:     {}",
        if notes.is_empty() {
            "-".to_owned()
        } else {
            format!("{} line(s), hidden (--field notes)", notes.lines().count())
        }
    );
    println!("History:   {} previous password(s)", l.history.len());
    println!("Created:   {}", fmt_time(item.created));
    println!("Updated:   {}", fmt_time(item.updated));
    println!("Version:   {}", item.version);
    println!("ID:        {}", item.id);
}
