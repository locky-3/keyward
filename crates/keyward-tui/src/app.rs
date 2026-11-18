//! Application state and key handling, independent of the terminal.
//!
//! [`App::handle_key`] turns key presses into state changes and returns an
//! [`Action`] for the few effects that need the outside world (clipboard,
//! a slow unlock, network sync). This keeps everything here unit-testable.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keyward_cli::session::Session;
use keyward_cli::sync_cmd;
use keyward_core::generator::{generate_passphrase, generate_password};
use keyward_core::{
    CharsetOptions, EntropyBits, ExposeSecret, Item, ItemId, ItemKind, Login, PassphraseOptions,
    SecretString, Totp,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use crate::fuzzy;

/// A revealed password hides itself again after this long.
pub const REVEAL_FOR: Duration = Duration::from_secs(15);
/// Status messages disappear after this long.
pub const STATUS_FOR: Duration = Duration::from_secs(6);
/// Seconds the clipboard keeps a copied secret.
pub const CLIPBOARD_SECS: u64 = 20;
/// Longest accepted text input (bytes); buffers are pre-allocated to this
/// size so typing never reallocates (and never leaves secret copies).
pub const MAX_INPUT: usize = 1024;

fn input_buffer() -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(MAX_INPUT))
}

fn push_char(buf: &mut Zeroizing<String>, c: char) {
    if buf.len() + c.len_utf8() <= MAX_INPUT {
        buf.push(c);
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Which pane has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Categories,
    List,
    Details,
}

/// Left-pane filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    All,
    Totp,
    Tag(String),
    Untagged,
}

impl Category {
    pub fn label(&self) -> String {
        match self {
            Self::All => "All items".into(),
            Self::Totp => "With TOTP".into(),
            Self::Tag(t) => format!("#{t}"),
            Self::Untagged => "Untagged".into(),
        }
    }

    fn matches(&self, l: &Login) -> bool {
        match self {
            Self::All => true,
            Self::Totp => l.totp.is_some(),
            Self::Tag(t) => l.tags.iter().any(|x| x.eq_ignore_ascii_case(t)),
            Self::Untagged => l.tags.is_empty(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Error,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub text: String,
    pub kind: StatusKind,
    at: Instant,
}

/// Everything the user can do; reachable by key or via the palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    CopyPassword,
    CopyUsername,
    CopyTotp,
    ToggleReveal,
    NewItem,
    EditItem,
    DeleteItem,
    Generator,
    Sync,
    Lock,
    Help,
    Quit,
}

impl Command {
    pub const ALL: [Self; 12] = [
        Self::CopyPassword,
        Self::CopyUsername,
        Self::CopyTotp,
        Self::ToggleReveal,
        Self::NewItem,
        Self::EditItem,
        Self::DeleteItem,
        Self::Generator,
        Self::Sync,
        Self::Lock,
        Self::Help,
        Self::Quit,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::CopyPassword => "Copy password",
            Self::CopyUsername => "Copy username",
            Self::CopyTotp => "Copy TOTP code",
            Self::ToggleReveal => "Reveal / hide password",
            Self::NewItem => "New item",
            Self::EditItem => "Edit item",
            Self::DeleteItem => "Delete item",
            Self::Generator => "Password generator",
            Self::Sync => "Sync with server",
            Self::Lock => "Lock vault",
            Self::Help => "Help / key bindings",
            Self::Quit => "Quit",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::CopyPassword => "c / Enter",
            Self::CopyUsername => "u",
            Self::CopyTotp => "t",
            Self::ToggleReveal => "r",
            Self::NewItem => "n",
            Self::EditItem => "e",
            Self::DeleteItem => "d",
            Self::Generator => "g",
            Self::Sync => "s",
            Self::Lock => "Ctrl+L",
            Self::Help => "?",
            Self::Quit => "q",
        }
    }
}

/// Ctrl+K command palette.
#[derive(Debug, Default)]
pub struct Palette {
    pub query: String,
    pub selected: usize,
}

impl Palette {
    /// Commands matching the query, best first.
    pub fn matches(&self) -> Vec<Command> {
        let mut scored: Vec<(i64, usize, Command)> = Command::ALL
            .iter()
            .enumerate()
            .filter_map(|(i, c)| fuzzy::score(&self.query, c.label()).map(|s| (s, i, *c)))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, _, c)| c).collect()
    }
}

/// Generator popup.
#[derive(Debug)]
pub struct Generator {
    pub passphrase: bool,
    pub chars: CharsetOptions,
    pub phrase: PassphraseOptions,
    pub current: SecretString,
    pub entropy: EntropyBits,
    pub error: Option<String>,
    /// Form to return to (with the password filled in) on Enter.
    pub return_to: Option<Box<Form>>,
}

impl Generator {
    fn new(return_to: Option<Box<Form>>) -> Self {
        let mut g = Self {
            passphrase: false,
            chars: CharsetOptions::default(),
            phrase: PassphraseOptions::default(),
            current: SecretString::from(String::new()),
            entropy: EntropyBits(0.0),
            error: None,
            return_to,
        };
        g.regenerate();
        g
    }

    pub fn regenerate(&mut self) {
        let r = if self.passphrase {
            generate_passphrase(&self.phrase)
        } else {
            generate_password(&self.chars)
        };
        match r {
            Ok((pw, e)) => {
                self.current = pw;
                self.entropy = e;
                self.error = None;
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    fn adjust(&mut self, delta: isize) {
        if self.passphrase {
            self.phrase.words = self.phrase.words.saturating_add_signed(delta).clamp(3, 20);
        } else {
            self.chars.length = self.chars.length.saturating_add_signed(delta).clamp(8, 128);
        }
        self.regenerate();
    }
}

pub const F_TITLE: usize = 0;
pub const F_USERNAME: usize = 1;
pub const F_URL: usize = 2;
pub const F_TAGS: usize = 3;
pub const F_PASSWORD: usize = 4;
pub const F_TOTP: usize = 5;
pub const F_NOTES: usize = 6;

/// One input of the add/edit form.
#[derive(Debug)]
pub struct FormField {
    pub label: &'static str,
    pub value: Zeroizing<String>,
    /// Rendered masked.
    pub secret: bool,
    pub hint: &'static str,
}

/// Add/edit item form.
#[derive(Debug)]
pub struct Form {
    pub editing: Option<ItemId>,
    pub fields: Vec<FormField>,
    pub focus: usize,
    pub error: Option<String>,
}

impl Form {
    fn new(editing: Option<(ItemId, &Login)>) -> Self {
        let field = |label, secret, hint, value: &str| {
            let mut v = input_buffer();
            for c in value.chars() {
                push_char(&mut v, c);
            }
            FormField {
                label,
                value: v,
                secret,
                hint,
            }
        };
        let (pw_hint, totp_hint) = if editing.is_some() {
            (
                "blank = keep current, Ctrl+G = generate",
                "blank = keep, '-' = remove",
            )
        } else {
            (
                "required, Ctrl+G = generate",
                "optional: base32 or otpauth:// URI",
            )
        };
        let l = editing.map(|(_, l)| l);
        let tags = l.map(|l| l.tags.join(", ")).unwrap_or_default();
        Self {
            editing: editing.map(|(id, _)| id),
            fields: vec![
                field("Title", false, "required", l.map_or("", |l| &l.title)),
                field("Username", false, "", l.map_or("", |l| &l.username)),
                field(
                    "URL",
                    false,
                    "",
                    l.and_then(|l| l.url.as_deref()).unwrap_or(""),
                ),
                field("Tags", false, "comma separated", &tags),
                field("Password", true, pw_hint, ""),
                field("TOTP secret", true, totp_hint, ""),
                field(
                    "Notes",
                    false,
                    "",
                    l.map_or("", |l| l.notes.expose_secret()),
                ),
            ],
            focus: 0,
            error: None,
        }
    }

    fn text(&self, i: usize) -> &str {
        self.fields[i].value.as_str()
    }
}

/// Current screen.
#[derive(Debug)]
pub enum Mode {
    Locked,
    Browse,
    Palette(Palette),
    Generator(Generator),
    Form(Box<Form>),
    ConfirmDelete(ItemId),
    Help,
}

/// Side effects for the event loop.
#[derive(Debug)]
pub enum Action {
    None,
    Copy {
        secret: SecretString,
        what: &'static str,
    },
    Unlock(SecretString),
    Sync,
}

/// The whole application state.
pub struct App {
    pub path: PathBuf,
    session: Option<Session>,
    pub mode: Mode,
    pub focus: Focus,
    pub category: usize,
    pub query: String,
    pub searching: bool,
    pub selected: usize,
    pub revealed: bool,
    revealed_at: Option<Instant>,
    pub status: Option<Status>,
    pub idle_timeout: Duration,
    last_activity: Instant,
    pub should_quit: bool,
    pub lock_input: Zeroizing<String>,
    /// Shown while a slow operation runs ("Unlocking…", "Syncing…").
    pub busy: Option<&'static str>,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("path", &self.path)
            .field("locked", &self.session.is_none())
            .finish_non_exhaustive()
    }
}

impl App {
    pub fn new(path: PathBuf, idle_timeout: Duration, now: Instant) -> Self {
        Self {
            path,
            session: None,
            mode: Mode::Locked,
            focus: Focus::List,
            category: 0,
            query: String::new(),
            searching: false,
            selected: 0,
            revealed: false,
            revealed_at: None,
            status: None,
            idle_timeout,
            last_activity: now,
            should_quit: false,
            lock_input: input_buffer(),
            busy: None,
        }
    }

    // ---------- queries used by the UI ----------

    pub fn is_locked(&self) -> bool {
        self.session.is_none()
    }

    pub fn item_count(&self) -> usize {
        self.session.as_ref().map_or(0, |s| s.vault.len())
    }

    pub fn sync_server(&self) -> Option<&str> {
        self.session
            .as_ref()
            .and_then(|s| s.vault.sync_state())
            .map(|s| s.server.as_str())
    }

    /// Filters with their item counts. Always starts with All / TOTP.
    pub fn categories(&self) -> Vec<(Category, usize)> {
        let Some(s) = &self.session else {
            return Vec::new();
        };
        let logins: Vec<&Login> = s
            .vault
            .list()
            .into_iter()
            .filter_map(|i| i.kind.as_login())
            .collect();
        let count = |c: &Category| logins.iter().filter(|l| c.matches(l)).count();
        let mut tags: Vec<String> = Vec::new();
        for l in &logins {
            for t in &l.tags {
                if !tags.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                    tags.push(t.clone());
                }
            }
        }
        tags.sort_by_key(|t| t.to_lowercase());
        let mut cats = vec![Category::All, Category::Totp];
        cats.extend(tags.into_iter().map(Category::Tag));
        cats.push(Category::Untagged);
        cats.into_iter()
            .map(|c| {
                let n = count(&c);
                (c, n)
            })
            .collect()
    }

    fn current_category(&self) -> Category {
        self.categories()
            .get(self.category)
            .map_or(Category::All, |(c, _)| c.clone())
    }

    /// Items in the current category matching the search, best first.
    pub fn visible(&self) -> Vec<&Item> {
        let Some(s) = &self.session else {
            return Vec::new();
        };
        let cat = self.current_category();
        let mut scored: Vec<(i64, &Item)> = s
            .vault
            .list()
            .into_iter()
            .filter(|i| i.kind.as_login().is_some_and(|l| cat.matches(l)))
            .filter_map(|i| item_score(&self.query, i).map(|sc| (sc, i)))
            .collect();
        if !self.query.trim().is_empty() {
            // stable sort keeps alphabetical order among equal scores
            scored.sort_by_key(|s| std::cmp::Reverse(s.0));
        }
        scored.into_iter().map(|(_, i)| i).collect()
    }

    pub fn selected_item(&self) -> Option<&Item> {
        self.visible().get(self.selected).copied()
    }

    /// Seconds until auto-lock.
    pub fn idle_remaining(&self, now: Instant) -> Duration {
        self.idle_timeout
            .saturating_sub(now.saturating_duration_since(self.last_activity))
    }

    // ---------- lifecycle ----------

    pub fn set_status(&mut self, text: impl Into<String>, kind: StatusKind, now: Instant) {
        self.status = Some(Status {
            text: text.into(),
            kind,
            at: now,
        });
    }

    /// Periodic housekeeping: auto-lock, hide revealed secrets, expire status.
    pub fn tick(&mut self, now: Instant) {
        if !self.is_locked()
            && now.saturating_duration_since(self.last_activity) >= self.idle_timeout
        {
            self.lock();
            self.set_status("Locked after inactivity", StatusKind::Info, now);
        }
        if self.revealed
            && self
                .revealed_at
                .is_some_and(|t| now.saturating_duration_since(t) >= REVEAL_FOR)
        {
            self.revealed = false;
        }
        if self
            .status
            .as_ref()
            .is_some_and(|s| now.saturating_duration_since(s.at) >= STATUS_FOR)
        {
            self.status = None;
        }
    }

    /// Try the master password. Clears the input either way.
    pub fn unlock(&mut self, password: &SecretString, now: Instant) {
        match Session::open_with(&self.path, password) {
            Ok(s) => {
                self.session = Some(s);
                self.mode = Mode::Browse;
                self.last_activity = now;
                self.status = None;
            }
            Err(e) => self.set_status(format!("{e:#}"), StatusKind::Error, now),
        }
    }

    /// Forget all keys and decrypted data (dropping the session zeroizes them).
    pub fn lock(&mut self) {
        self.session = None;
        self.mode = Mode::Locked;
        self.revealed = false;
        self.query.clear();
        self.searching = false;
        self.selected = 0;
        self.category = 0;
        self.lock_input = input_buffer();
    }

    /// Run a sync (blocking; the caller shows a busy indicator first).
    pub fn sync(&mut self, now: Instant) {
        let selected = self.selected_item().map(|i| i.id);
        let Some(s) = &mut self.session else { return };
        match sync_cmd::sync_session(s) {
            Ok(report) => self.set_status(format!("Synced: {report}"), StatusKind::Info, now),
            Err(e) => self.set_status(format!("Sync failed: {e:#}"), StatusKind::Error, now),
        }
        if let Some(id) = selected {
            self.select_id(id);
        }
        self.clamp_selection();
    }

    /// Report the outcome of a clipboard copy.
    pub fn copied(&mut self, what: &str, result: anyhow::Result<()>, now: Instant) {
        match result {
            Ok(()) => self.set_status(
                format!("Copied {what}; clipboard clears in {CLIPBOARD_SECS} s"),
                StatusKind::Info,
                now,
            ),
            Err(e) => self.set_status(format!("Copy failed: {e:#}"), StatusKind::Error, now),
        }
    }

    fn select_id(&mut self, id: ItemId) {
        if let Some(pos) = self.visible().iter().position(|i| i.id == id) {
            self.selected = pos;
        }
    }

    fn clamp_selection(&mut self) {
        let n = self.visible().len();
        self.selected = self.selected.min(n.saturating_sub(1));
        let cats = self.categories().len();
        self.category = self.category.min(cats.saturating_sub(1));
    }

    fn move_selection(&mut self, delta: isize) {
        let n = self.visible().len();
        if n == 0 {
            return;
        }
        let new = self.selected.saturating_add_signed(delta).min(n - 1);
        if new != self.selected {
            self.selected = new;
            self.revealed = false;
        }
    }

    fn save(&mut self, now: Instant) -> bool {
        let Some(s) = &mut self.session else {
            return false;
        };
        match s.save() {
            Ok(()) => true,
            Err(e) => {
                self.set_status(format!("Save failed: {e:#}"), StatusKind::Error, now);
                false
            }
        }
    }

    // ---------- keys ----------

    pub fn handle_key(&mut self, key: KeyEvent, now: Instant) -> Action {
        self.last_activity = now;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return Action::None;
        }
        match std::mem::replace(&mut self.mode, Mode::Browse) {
            Mode::Locked => {
                self.mode = Mode::Locked;
                self.key_locked(key)
            }
            Mode::Browse => self.key_browse(key, now),
            Mode::Palette(p) => self.key_palette(p, key, now),
            Mode::Generator(g) => self.key_generator(g, key),
            Mode::Form(f) => self.key_form(f, key, now),
            Mode::ConfirmDelete(id) => {
                if matches!(key.code, KeyCode::Char('y' | 'Y')) {
                    self.delete(id, now);
                }
                Action::None
            }
            Mode::Help => Action::None,
        }
    }

    fn key_locked(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Enter if !self.lock_input.is_empty() => {
                let pw = SecretString::from(self.lock_input.as_str().to_owned());
                self.lock_input = input_buffer();
                Action::Unlock(pw)
            }
            KeyCode::Backspace => {
                self.lock_input.pop();
                Action::None
            }
            KeyCode::Esc => {
                self.should_quit = true;
                Action::None
            }
            KeyCode::Char(c) => {
                push_char(&mut self.lock_input, c);
                Action::None
            }
            _ => Action::None,
        }
    }

    fn key_browse(&mut self, key: KeyEvent, now: Instant) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl {
            return match key.code {
                KeyCode::Char('k') => {
                    self.mode = Mode::Palette(Palette::default());
                    Action::None
                }
                KeyCode::Char('l') => self.exec(Command::Lock, now),
                _ => Action::None,
            };
        }
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.query.clear();
                    self.searching = false;
                }
                KeyCode::Enter => self.searching = false,
                KeyCode::Backspace => {
                    self.query.pop();
                }
                KeyCode::Up => self.move_selection(-1),
                KeyCode::Down => self.move_selection(1),
                KeyCode::Char(c) if self.query.len() < 128 => self.query.push(c),
                _ => {}
            }
            if matches!(
                key.code,
                KeyCode::Char(_) | KeyCode::Backspace | KeyCode::Esc
            ) {
                self.selected = 0;
                self.revealed = false;
            }
            self.clamp_selection();
            return Action::None;
        }
        match key.code {
            KeyCode::Char('/') => {
                self.searching = true;
                self.focus = Focus::List;
                Action::None
            }
            KeyCode::Esc if !self.query.is_empty() => {
                self.query.clear();
                self.selected = 0;
                Action::None
            }
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Categories => Focus::List,
                    Focus::List => Focus::Details,
                    Focus::Details => Focus::Categories,
                };
                Action::None
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Categories => Focus::Details,
                    Focus::List => Focus::Categories,
                    Focus::Details => Focus::List,
                };
                Action::None
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.focus = Focus::Categories;
                Action::None
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.focus = Focus::List;
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_in_focus(-1);
                Action::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_in_focus(1);
                Action::None
            }
            KeyCode::Enter | KeyCode::Char('c') => self.exec(Command::CopyPassword, now),
            KeyCode::Char('u') => self.exec(Command::CopyUsername, now),
            KeyCode::Char('t') => self.exec(Command::CopyTotp, now),
            KeyCode::Char('r') => self.exec(Command::ToggleReveal, now),
            KeyCode::Char('n') => self.exec(Command::NewItem, now),
            KeyCode::Char('e') => self.exec(Command::EditItem, now),
            KeyCode::Char('d') | KeyCode::Delete => self.exec(Command::DeleteItem, now),
            KeyCode::Char('g') => self.exec(Command::Generator, now),
            KeyCode::Char('s') => self.exec(Command::Sync, now),
            KeyCode::Char('?') => self.exec(Command::Help, now),
            KeyCode::Char('q') => self.exec(Command::Quit, now),
            _ => Action::None,
        }
    }

    fn move_in_focus(&mut self, delta: isize) {
        if self.focus == Focus::Categories {
            let n = self.categories().len();
            if n > 0 {
                self.category = self.category.saturating_add_signed(delta).min(n - 1);
                self.selected = 0;
                self.revealed = false;
            }
        } else {
            self.move_selection(delta);
        }
    }

    /// Execute a command (from a key binding or the palette).
    pub fn exec(&mut self, cmd: Command, now: Instant) -> Action {
        self.mode = Mode::Browse;
        let item = self.selected_item();
        let login = item.and_then(|i| i.kind.as_login());
        let need_item = |app: &mut Self| {
            app.set_status("No item selected", StatusKind::Error, now);
            Action::None
        };
        match cmd {
            Command::CopyPassword => match login {
                Some(l) => Action::Copy {
                    secret: l.password.clone(),
                    what: "password",
                },
                None => need_item(self),
            },
            Command::CopyUsername => match login {
                Some(l) => Action::Copy {
                    secret: SecretString::from(l.username.clone()),
                    what: "username",
                },
                None => need_item(self),
            },
            Command::CopyTotp => match login.map(|l| l.totp.as_ref()) {
                Some(Some(secret)) => match Totp::parse(secret.expose_secret()) {
                    Ok(t) => Action::Copy {
                        secret: t.code_at(unix_now()),
                        what: "TOTP code",
                    },
                    Err(e) => {
                        self.set_status(e.to_string(), StatusKind::Error, now);
                        Action::None
                    }
                },
                Some(None) => {
                    self.set_status("This item has no TOTP secret", StatusKind::Error, now);
                    Action::None
                }
                None => need_item(self),
            },
            Command::ToggleReveal => {
                if item.is_some() {
                    self.revealed = !self.revealed;
                    self.revealed_at = Some(now);
                    Action::None
                } else {
                    need_item(self)
                }
            }
            Command::NewItem => {
                self.mode = Mode::Form(Box::new(Form::new(None)));
                Action::None
            }
            Command::EditItem => match (item, login) {
                (Some(i), Some(l)) => {
                    self.mode = Mode::Form(Box::new(Form::new(Some((i.id, l)))));
                    Action::None
                }
                _ => need_item(self),
            },
            Command::DeleteItem => match item {
                Some(i) => {
                    self.mode = Mode::ConfirmDelete(i.id);
                    Action::None
                }
                None => need_item(self),
            },
            Command::Generator => {
                self.mode = Mode::Generator(Generator::new(None));
                Action::None
            }
            Command::Sync => {
                if self.sync_server().is_some() {
                    Action::Sync
                } else {
                    self.set_status(
                        "Not connected to a sync server (use `kw sync register` first)",
                        StatusKind::Error,
                        now,
                    );
                    Action::None
                }
            }
            Command::Lock => {
                self.lock();
                self.set_status("Locked", StatusKind::Info, now);
                Action::None
            }
            Command::Help => {
                self.mode = Mode::Help;
                Action::None
            }
            Command::Quit => {
                self.should_quit = true;
                Action::None
            }
        }
    }

    fn key_palette(&mut self, mut p: Palette, key: KeyEvent, now: Instant) -> Action {
        let n = p.matches().len();
        match key.code {
            KeyCode::Esc => return Action::None,
            KeyCode::Enter => {
                return match p.matches().get(p.selected) {
                    Some(&cmd) => self.exec(cmd, now),
                    None => Action::None,
                };
            }
            KeyCode::Up => p.selected = p.selected.saturating_sub(1),
            KeyCode::Down => p.selected = (p.selected + 1).min(n.saturating_sub(1)),
            KeyCode::Backspace => {
                p.query.pop();
                p.selected = 0;
            }
            KeyCode::Char(c) if p.query.len() < 64 => {
                p.query.push(c);
                p.selected = 0;
            }
            _ => {}
        }
        self.mode = Mode::Palette(p);
        Action::None
    }

    fn key_generator(&mut self, mut g: Generator, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc => {
                if let Some(form) = g.return_to.take() {
                    self.mode = Mode::Form(form);
                }
                return Action::None;
            }
            KeyCode::Enter => {
                if let Some(mut form) = g.return_to.take() {
                    let mut v = input_buffer();
                    for c in g.current.expose_secret().chars() {
                        push_char(&mut v, c);
                    }
                    form.fields[F_PASSWORD].value = v;
                    self.mode = Mode::Form(form);
                    return Action::None;
                }
                return Action::Copy {
                    secret: g.current.clone(),
                    what: "generated password",
                };
            }
            KeyCode::Char('c') => {
                let action = Action::Copy {
                    secret: g.current.clone(),
                    what: "generated password",
                };
                self.mode = Mode::Generator(g);
                return action;
            }
            KeyCode::Char('r' | ' ') => g.regenerate(),
            KeyCode::Char('p') => {
                g.passphrase = !g.passphrase;
                g.regenerate();
            }
            KeyCode::Left | KeyCode::Char('-') => g.adjust(-1),
            KeyCode::Right | KeyCode::Char('+' | '=') => g.adjust(1),
            KeyCode::Char(c @ ('l' | 'u' | 'd' | 's' | 'a')) if !g.passphrase => {
                let o = &mut g.chars;
                match c {
                    'l' => o.lower = !o.lower,
                    'u' => o.upper = !o.upper,
                    'd' => o.digits = !o.digits,
                    's' => o.symbols = !o.symbols,
                    _ => o.exclude_ambiguous = !o.exclude_ambiguous,
                }
                g.regenerate();
            }
            KeyCode::Char('C') if g.passphrase => {
                g.phrase.capitalize = !g.phrase.capitalize;
                g.regenerate();
            }
            KeyCode::Char('n') if g.passphrase => {
                g.phrase.add_digit = !g.phrase.add_digit;
                g.regenerate();
            }
            _ => {}
        }
        self.mode = Mode::Generator(g);
        Action::None
    }

    fn key_form(&mut self, mut f: Box<Form>, key: KeyEvent, now: Instant) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let n = f.fields.len();
        match key.code {
            KeyCode::Esc => return Action::None,
            KeyCode::Char('g') if ctrl => {
                f.focus = F_PASSWORD;
                self.mode = Mode::Generator(Generator::new(Some(f)));
                return Action::None;
            }
            KeyCode::Enter => match self.submit(&f, now) {
                Ok(()) => return Action::None,
                Err(msg) => f.error = Some(msg),
            },
            KeyCode::Tab | KeyCode::Down => f.focus = (f.focus + 1) % n,
            KeyCode::BackTab | KeyCode::Up => f.focus = (f.focus + n - 1) % n,
            KeyCode::Backspace => {
                f.fields[f.focus].value.pop();
            }
            KeyCode::Char(c) if !ctrl => {
                let i = f.focus;
                push_char(&mut f.fields[i].value, c);
            }
            _ => {}
        }
        self.mode = Mode::Form(f);
        Action::None
    }

    /// Validate and apply the form. On success the mode is Browse.
    fn submit(&mut self, f: &Form, now: Instant) -> Result<(), String> {
        let title = f.text(F_TITLE).trim();
        if title.is_empty() {
            return Err("Title is required".into());
        }
        let password = f.text(F_PASSWORD);
        if f.editing.is_none() && password.is_empty() {
            return Err("Password is required (Ctrl+G generates one)".into());
        }
        let totp_in = f.text(F_TOTP).trim();
        let totp: Option<Option<SecretString>> = match totp_in {
            "" => None,
            "-" => Some(None),
            s => {
                Totp::parse(s).map_err(|e| e.to_string())?;
                Some(Some(SecretString::from(s.to_owned())))
            }
        };
        let tags: Vec<String> = f
            .text(F_TAGS)
            .split(',')
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();
        let url = Some(f.text(F_URL).trim().to_owned()).filter(|u| !u.is_empty());
        let username = f.text(F_USERNAME).trim().to_owned();
        let notes = SecretString::from(f.text(F_NOTES).to_owned());
        let new_password = Some(password)
            .filter(|p| !p.is_empty())
            .map(|p| SecretString::from(p.to_owned()));

        let session = self.session.as_mut().ok_or("Vault is locked")?;
        let id = match f.editing {
            None => {
                let mut l =
                    Login::new(title, username, new_password.ok_or("Password is required")?);
                l.url = url;
                l.tags = tags;
                l.notes = notes;
                l.totp = totp.flatten();
                session.vault.add(ItemKind::Login(l))
            }
            Some(id) => {
                let title = title.to_owned();
                session
                    .vault
                    .update(id, move |k| {
                        if let Some(l) = k.as_login_mut() {
                            l.title = title;
                            l.username = username;
                            l.url = url;
                            l.tags = tags;
                            l.notes = notes;
                            if let Some(p) = new_password {
                                l.password = p;
                            }
                            if let Some(t) = totp {
                                l.totp = t;
                            }
                        }
                    })
                    .map_err(|e| e.to_string())?;
                id
            }
        };
        if self.save(now) {
            let verb = if f.editing.is_some() {
                "Updated"
            } else {
                "Added"
            };
            self.set_status(format!("{verb} \"{title}\""), StatusKind::Info, now);
        }
        self.mode = Mode::Browse;
        // make sure the item is visible and selected
        self.query.clear();
        self.category = 0;
        self.select_id(id);
        Ok(())
    }

    fn delete(&mut self, id: ItemId, now: Instant) {
        let Some(s) = &mut self.session else { return };
        let title = s
            .vault
            .get(id)
            .map(|i| i.kind.title().to_owned())
            .unwrap_or_default();
        if let Err(e) = s.vault.remove(id) {
            self.set_status(e.to_string(), StatusKind::Error, now);
            return;
        }
        if self.save(now) {
            self.set_status(format!("Deleted \"{title}\""), StatusKind::Info, now);
        }
        self.revealed = false;
        self.clamp_selection();
    }
}

/// Best fuzzy score of an item over its searchable (non-secret) fields.
fn item_score(query: &str, item: &Item) -> Option<i64> {
    if query.trim().is_empty() {
        return Some(0);
    }
    let l = item.kind.as_login()?;
    let mut best = fuzzy::score(query, &l.title).map(|s| s + 20);
    let mut consider = |text: &str| {
        if let Some(s) = fuzzy::score(query, text) {
            best = Some(best.map_or(s, |b| b.max(s)));
        }
    };
    consider(&l.username);
    if let Some(u) = &l.url {
        consider(u);
    }
    for t in &l.tags {
        consider(t);
    }
    best
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use keyward_core::KdfParams;

    pub const MASTER: &str = "tui-master-pw";

    pub fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    pub fn code(k: KeyCode) -> KeyEvent {
        KeyEvent::new(k, KeyModifiers::NONE)
    }
    pub fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }
    pub fn typ(app: &mut App, s: &str, now: Instant) {
        for c in s.chars() {
            app.handle_key(key(c), now);
        }
    }

    /// A vault with three logins, unlocked.
    pub fn fixture() -> (tempfile::TempDir, App, Instant) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kwv");
        let params = KdfParams {
            m_cost_kib: KdfParams::MIN_M_COST_KIB,
            t_cost: KdfParams::MIN_T_COST,
            p_cost: 1,
        };
        let mut s = Session::create(&path, &SecretString::from(MASTER.to_owned()), params).unwrap();
        let mut add = |title: &str, user: &str, pw: &str, tags: &[&str], totp: bool| {
            let mut l = Login::new(title, user, SecretString::from(pw.to_owned()));
            l.tags = tags.iter().map(|t| (*t).to_owned()).collect();
            if totp {
                l.totp = Some(SecretString::from("GEZDGNBVGY3TQOJQ".to_owned()));
            }
            s.vault.add(ItemKind::Login(l));
        };
        add("GitHub", "octocat", "gh-secret", &["work"], true);
        add("Bank", "me", "bank-secret", &["finance"], false);
        add("Mail", "me@example.com", "mail-secret", &[], false);
        s.save().unwrap();
        drop(s);

        let now = Instant::now();
        let mut app = App::new(path, Duration::from_secs(300), now);
        typ(&mut app, MASTER, now);
        match app.handle_key(code(KeyCode::Enter), now) {
            Action::Unlock(pw) => app.unlock(&pw, now),
            other => panic!("expected unlock, got {other:?}"),
        }
        assert!(!app.is_locked());
        (dir, app, now)
    }

    fn titles(app: &App) -> Vec<String> {
        app.visible()
            .iter()
            .map(|i| i.kind.title().to_owned())
            .collect()
    }

    fn copied(a: Action) -> (String, &'static str) {
        match a {
            Action::Copy { secret, what } => (secret.expose_secret().to_owned(), what),
            other => panic!("expected copy, got {other:?}"),
        }
    }

    #[test]
    fn wrong_password_keeps_locked_and_clears_input() {
        let (_d, mut app, now) = fixture();
        app.lock();
        typ(&mut app, "nope", now);
        let Action::Unlock(pw) = app.handle_key(code(KeyCode::Enter), now) else {
            panic!()
        };
        app.unlock(&pw, now);
        assert!(app.is_locked());
        assert!(app.lock_input.is_empty());
        assert_eq!(app.status.as_ref().unwrap().kind, StatusKind::Error);
    }

    #[test]
    fn list_is_alphabetical_and_fuzzy_search_filters() {
        let (_d, mut app, now) = fixture();
        assert_eq!(titles(&app), ["Bank", "GitHub", "Mail"]);
        app.handle_key(key('/'), now);
        typ(&mut app, "ghb", now);
        assert_eq!(titles(&app), ["GitHub"]);
        app.handle_key(code(KeyCode::Esc), now);
        assert_eq!(titles(&app).len(), 3);
        // search by username, never by password
        app.handle_key(key('/'), now);
        typ(&mut app, "octo", now);
        assert_eq!(titles(&app), ["GitHub"]);
        app.handle_key(code(KeyCode::Esc), now);
        app.handle_key(key('/'), now);
        typ(&mut app, "secret", now);
        assert!(titles(&app).is_empty());
    }

    #[test]
    fn categories_filter_by_tag_and_totp() {
        let (_d, mut app, now) = fixture();
        let cats: Vec<_> = app
            .categories()
            .into_iter()
            .map(|(c, n)| (c.label(), n))
            .collect();
        assert_eq!(
            cats,
            [
                ("All items".to_owned(), 3),
                ("With TOTP".to_owned(), 1),
                ("#finance".to_owned(), 1),
                ("#work".to_owned(), 1),
                ("Untagged".to_owned(), 1),
            ]
        );
        app.focus = Focus::Categories;
        app.handle_key(code(KeyCode::Down), now);
        assert_eq!(titles(&app), ["GitHub"]);
        app.handle_key(code(KeyCode::End), now); // ignored
        app.handle_key(key('j'), now);
        app.handle_key(key('j'), now);
        app.handle_key(key('j'), now);
        assert_eq!(titles(&app), ["Mail"]);
    }

    #[test]
    fn copy_actions_carry_the_right_secret() {
        let (_d, mut app, now) = fixture();
        app.handle_key(key('j'), now); // GitHub
        assert_eq!(
            copied(app.handle_key(key('c'), now)),
            ("gh-secret".into(), "password")
        );
        assert_eq!(
            copied(app.handle_key(key('u'), now)),
            ("octocat".into(), "username")
        );
        let (code6, what) = copied(app.handle_key(key('t'), now));
        assert_eq!(what, "TOTP code");
        assert!(code6.len() == 6 && code6.chars().all(|c| c.is_ascii_digit()));
        // Bank has no TOTP
        app.handle_key(key('k'), now);
        assert!(matches!(app.handle_key(key('t'), now), Action::None));
        assert_eq!(app.status.as_ref().unwrap().kind, StatusKind::Error);
    }

    #[test]
    fn reveal_hides_after_timeout_and_on_move() {
        let (_d, mut app, now) = fixture();
        app.handle_key(key('r'), now);
        assert!(app.revealed);
        app.tick(now + REVEAL_FOR - Duration::from_secs(1));
        assert!(app.revealed);
        app.tick(now + REVEAL_FOR);
        assert!(!app.revealed);
        app.handle_key(key('r'), now);
        app.handle_key(key('j'), now);
        assert!(!app.revealed, "moving to another item hides the password");
    }

    #[test]
    fn auto_lock_after_idle_and_activity_postpones_it() {
        let (_d, mut app, now) = fixture();
        app.tick(now + Duration::from_secs(299));
        assert!(!app.is_locked());
        app.handle_key(key('j'), now + Duration::from_secs(299));
        app.tick(now + Duration::from_secs(500));
        assert!(!app.is_locked(), "activity reset the timer");
        app.tick(now + Duration::from_secs(600));
        assert!(app.is_locked());
        assert!(matches!(app.mode, Mode::Locked));
        assert!(app.visible().is_empty());
        assert_eq!(app.item_count(), 0);
    }

    #[test]
    fn manual_lock_and_quit() {
        let (_d, mut app, now) = fixture();
        app.handle_key(ctrl('l'), now);
        assert!(app.is_locked());
        app.handle_key(code(KeyCode::Esc), now);
        assert!(app.should_quit);
    }

    #[test]
    fn palette_filters_and_executes() {
        let (_d, mut app, now) = fixture();
        app.handle_key(ctrl('k'), now);
        let Mode::Palette(p) = &app.mode else {
            panic!()
        };
        assert_eq!(p.matches().len(), Command::ALL.len());
        typ(&mut app, "user", now);
        let Mode::Palette(p) = &app.mode else {
            panic!()
        };
        assert_eq!(p.matches()[0], Command::CopyUsername);
        let (v, _) = copied(app.handle_key(code(KeyCode::Enter), now));
        assert_eq!(v, "me", "Bank is selected first");
        assert!(matches!(app.mode, Mode::Browse));

        app.handle_key(ctrl('k'), now);
        typ(&mut app, "lock", now);
        app.handle_key(code(KeyCode::Enter), now);
        assert!(app.is_locked());
    }

    #[test]
    fn add_item_via_form_with_generator() {
        let (dir, mut app, now) = fixture();
        app.handle_key(key('n'), now);
        typ(&mut app, "Forum", now);
        app.handle_key(code(KeyCode::Tab), now);
        typ(&mut app, "alice", now);
        // missing password is refused
        app.handle_key(code(KeyCode::Enter), now);
        let Mode::Form(f) = &app.mode else { panic!() };
        assert!(f.error.as_deref().unwrap().contains("Password is required"));
        // generate one, accept it into the form, save
        app.handle_key(ctrl('g'), now);
        assert!(matches!(app.mode, Mode::Generator(_)));
        app.handle_key(code(KeyCode::Enter), now);
        let Mode::Form(f) = &app.mode else { panic!() };
        assert_eq!(f.fields[F_PASSWORD].value.chars().count(), 20);
        app.handle_key(code(KeyCode::Enter), now);
        assert!(matches!(app.mode, Mode::Browse));
        assert_eq!(app.selected_item().unwrap().kind.title(), "Forum");

        // persisted: reopen the file
        let s = Session::open_with(
            &dir.path().join("v.kwv"),
            &SecretString::from(MASTER.to_owned()),
        )
        .unwrap();
        assert_eq!(s.vault.len(), 4);
    }

    #[test]
    fn edit_keeps_password_when_blank_and_validates_totp() {
        let (_d, mut app, now) = fixture();
        app.handle_key(key('j'), now); // GitHub
        app.handle_key(key('e'), now);
        // title field is prefilled; append to it
        typ(&mut app, " Enterprise", now);
        // bad TOTP is rejected
        for _ in 0..F_TOTP {
            app.handle_key(code(KeyCode::Tab), now);
        }
        typ(&mut app, "!!", now);
        app.handle_key(code(KeyCode::Enter), now);
        let Mode::Form(f) = &app.mode else { panic!() };
        assert!(f.error.is_some());
        app.handle_key(code(KeyCode::Backspace), now);
        app.handle_key(code(KeyCode::Backspace), now);
        typ(&mut app, "-", now); // remove TOTP
        app.handle_key(code(KeyCode::Enter), now);
        let item = app.selected_item().unwrap();
        let l = item.kind.as_login().unwrap();
        assert_eq!(l.title, "GitHub Enterprise");
        assert_eq!(
            l.password.expose_secret(),
            "gh-secret",
            "blank keeps password"
        );
        assert!(l.totp.is_none());
        assert_eq!(l.tags, ["work"]);
        assert_eq!(item.version, 2);
    }

    #[test]
    fn delete_requires_confirmation() {
        let (_d, mut app, now) = fixture();
        app.handle_key(key('d'), now);
        app.handle_key(key('n'), now);
        assert_eq!(titles(&app).len(), 3);
        app.handle_key(key('d'), now);
        app.handle_key(key('y'), now);
        assert_eq!(titles(&app), ["GitHub", "Mail"]);
    }

    #[test]
    fn generator_options() {
        let (_d, mut app, now) = fixture();
        app.handle_key(key('g'), now);
        let len = |app: &App| match &app.mode {
            Mode::Generator(g) => g.current.expose_secret().chars().count(),
            _ => panic!(),
        };
        assert_eq!(len(&app), 20);
        app.handle_key(code(KeyCode::Right), now);
        assert_eq!(len(&app), 21);
        app.handle_key(key('p'), now);
        let Mode::Generator(g) = &app.mode else {
            panic!()
        };
        assert_eq!(g.current.expose_secret().split('-').count(), 6);
        // copy closes nothing; Esc closes
        assert!(matches!(app.handle_key(key('c'), now), Action::Copy { .. }));
        app.handle_key(code(KeyCode::Esc), now);
        assert!(matches!(app.mode, Mode::Browse));
    }

    #[test]
    fn sync_without_server_explains() {
        let (_d, mut app, now) = fixture();
        assert!(matches!(app.handle_key(key('s'), now), Action::None));
        assert!(
            app.status
                .as_ref()
                .unwrap()
                .text
                .contains("kw sync register")
        );
    }

    #[test]
    fn locked_input_is_bounded() {
        let now = Instant::now();
        let mut app = App::new(PathBuf::from("x"), Duration::from_secs(1), now);
        for _ in 0..(MAX_INPUT + 50) {
            app.handle_key(key('a'), now);
        }
        assert_eq!(app.lock_input.len(), MAX_INPUT);
        assert_eq!(app.lock_input.capacity(), MAX_INPUT, "never reallocated");
    }
}
