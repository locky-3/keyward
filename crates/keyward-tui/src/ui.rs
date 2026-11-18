//! Rendering. Pure function of [`App`] state (plus the current time).

use std::time::Instant;

use keyward_core::{ExposeSecret, Item, Login, Totp};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, Command, F_PASSWORD, Focus, Mode, StatusKind};
use crate::theme;

/// What a hidden secret looks like (fixed width: does not leak length).
pub const MASK: &str = "••••••••••";

pub fn draw(f: &mut Frame, app: &App, now: Instant, unix_now: u64) {
    let area = f.area();
    f.render_widget(Block::default().style(theme::base()), area);
    let [main, status] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);

    if app.is_locked() {
        draw_locked(f, app, main);
    } else {
        draw_browser(f, app, main, unix_now);
    }
    draw_status(f, app, status, now);

    match &app.mode {
        Mode::Palette(p) => draw_palette(f, p, area),
        Mode::Generator(g) => draw_generator(f, g, area),
        Mode::Form(form) => draw_form(f, form, area),
        Mode::ConfirmDelete(id) => {
            let title = app
                .visible()
                .iter()
                .find(|i| i.id == *id)
                .map(|i| i.kind.title().to_owned())
                .unwrap_or_default();
            draw_confirm(f, &title, area);
        }
        Mode::Help => draw_help(f, area),
        Mode::Locked | Mode::Browse => {}
    }
}

fn panel<'a>(title: &'a str, focused: bool) -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused))
        .title(Span::styled(
            format!(" {title} "),
            if focused {
                theme::accent().add_modifier(Modifier::BOLD)
            } else {
                theme::muted()
            },
        ))
        .style(theme::base())
}

fn popup_block(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::accent())
        .title(Span::styled(
            format!(" {title} "),
            theme::accent().add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme::SURFACE).fg(theme::TEXT))
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

// ---------- locked ----------

fn draw_locked(f: &mut Frame, app: &App, area: Rect) {
    let r = centered(area, 60, 11);
    let dots = "•".repeat(app.lock_input.chars().count().min(32));
    let mut lines = vec![
        Line::from(Span::styled(
            "🔒 Keyward",
            theme::accent().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(app.path.display().to_string(), theme::muted())),
        Line::from(""),
        Line::from(vec![
            Span::styled("Master password: ", theme::label()),
            Span::raw(dots),
            Span::styled("▏", theme::accent()),
        ]),
        Line::from(""),
    ];
    match app.busy {
        Some(b) => lines.push(Line::from(Span::styled(b, theme::accent()))),
        None => lines.push(Line::from(Span::styled(
            "Enter to unlock · Esc to quit",
            theme::muted(),
        ))),
    }
    f.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(popup_block("Locked")),
        r,
    );
}

// ---------- three panes ----------

fn draw_browser(f: &mut Frame, app: &App, area: Rect, unix_now: u64) {
    let [cats, list, details] = Layout::horizontal([
        Constraint::Length(24),
        Constraint::Percentage(38),
        Constraint::Min(30),
    ])
    .areas(area);
    draw_categories(f, app, cats);
    draw_list(f, app, list);
    draw_details(f, app, details, unix_now);
}

fn draw_categories(f: &mut Frame, app: &App, area: Rect) {
    let width = area.width.saturating_sub(4) as usize;
    let items: Vec<ListItem> = app
        .categories()
        .into_iter()
        .map(|(c, n)| {
            let label = c.label();
            let count = n.to_string();
            let pad = width.saturating_sub(label.chars().count() + count.len());
            ListItem::new(Line::from(vec![
                Span::raw(label),
                Span::raw(" ".repeat(pad)),
                Span::styled(count, theme::muted()),
            ]))
        })
        .collect();
    let mut state = ListState::default().with_selected(Some(app.category));
    f.render_stateful_widget(
        List::new(items)
            .block(panel("Categories", app.focus == Focus::Categories))
            .highlight_style(theme::selected()),
        area,
        &mut state,
    );
}

fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    let [search, list] = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(area);
    let query_line = if app.query.is_empty() && !app.searching {
        Line::from(Span::styled("/ to search", theme::muted()))
    } else {
        let mut spans = vec![
            Span::styled("/ ", theme::accent()),
            Span::raw(app.query.as_str()),
        ];
        if app.searching {
            spans.push(Span::styled("▏", theme::accent()));
        }
        Line::from(spans)
    };
    f.render_widget(
        Paragraph::new(query_line).block(panel("Search", app.searching)),
        search,
    );

    let visible = app.visible();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|i| {
            let l = i.kind.as_login();
            let mut spans = vec![Span::raw(i.kind.title().to_owned())];
            if let Some(l) = l
                && !l.username.is_empty()
            {
                spans.push(Span::styled(format!("  {}", l.username), theme::muted()));
            }
            if l.is_some_and(|l| l.totp.is_some()) {
                spans.push(Span::styled("  ⏱", theme::accent()));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let title = format!("Items {}/{}", visible.len(), app.item_count());
    let mut state =
        ListState::default().with_selected((!visible.is_empty()).then_some(app.selected));
    let list_widget = if items.is_empty() {
        List::new(vec![ListItem::new(Span::styled(
            "  (no matching items)",
            theme::muted(),
        ))])
    } else {
        List::new(items)
    };
    f.render_stateful_widget(
        list_widget
            .block(panel(&title, app.focus == Focus::List && !app.searching))
            .highlight_style(theme::selected())
            .highlight_symbol("▌"),
        list,
        &mut state,
    );
}

fn field<'a>(label: &'a str, value: Span<'a>) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<10}"), theme::label()),
        value,
    ])
}

fn draw_details(f: &mut Frame, app: &App, area: Rect, unix_now: u64) {
    let block = panel("Details", app.focus == Focus::Details);
    let Some(item) = app.selected_item() else {
        f.render_widget(
            Paragraph::new(Span::styled(
                "Nothing selected. Press n to add an item.",
                theme::muted(),
            ))
            .block(block),
            area,
        );
        return;
    };
    let Some(l) = item.kind.as_login() else {
        return;
    };
    let lines = detail_lines(
        item,
        l,
        app.revealed,
        unix_now,
        area.width.saturating_sub(14),
    );
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn detail_lines<'a>(
    item: &'a Item,
    l: &'a Login,
    revealed: bool,
    unix_now: u64,
    bar_width: u16,
) -> Vec<Line<'a>> {
    let mut lines = vec![
        Line::from(Span::styled(
            l.title.as_str(),
            theme::accent().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        field("Username", Span::raw(l.username.as_str())),
        field(
            "Password",
            if revealed {
                Span::styled(l.password.expose_secret().to_owned(), theme::accent())
            } else {
                Span::styled(format!("{MASK}  (r reveal · c copy)"), theme::muted())
            },
        ),
        field("URL", Span::raw(l.url.as_deref().unwrap_or("—"))),
        field(
            "Tags",
            Span::raw(if l.tags.is_empty() {
                "—".to_owned()
            } else {
                l.tags.join(", ")
            }),
        ),
    ];

    match l.totp.as_ref().map(|s| Totp::parse(s.expose_secret())) {
        Some(Ok(t)) => {
            let code = t.code_at(unix_now);
            let code = code.expose_secret();
            let shown = if code.len() == 6 {
                format!("{} {}", &code[..3], &code[3..])
            } else {
                code.to_owned()
            };
            let left = t.seconds_remaining(unix_now);
            let width = usize::from(bar_width.clamp(10, 30));
            let filled = (left as usize * width)
                .div_ceil(t.period() as usize)
                .min(width);
            lines.push(field(
                "TOTP",
                Span::styled(shown, theme::accent().add_modifier(Modifier::BOLD)),
            ));
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(10)),
                Span::styled("█".repeat(filled), theme::accent()),
                Span::styled("░".repeat(width - filled), theme::muted()),
                Span::styled(format!(" {left:>2}s"), theme::muted()),
            ]));
        }
        Some(Err(_)) => lines.push(field(
            "TOTP",
            Span::styled("invalid secret", theme::muted()),
        )),
        None => lines.push(field("TOTP", Span::raw("—"))),
    }

    lines.push(Line::from(""));
    let notes = l.notes.expose_secret();
    if notes.is_empty() {
        lines.push(field("Notes", Span::raw("—")));
    } else if revealed {
        lines.push(Line::from(Span::styled("Notes", theme::label())));
        lines.extend(notes.lines().map(|n| Line::from(n.to_owned())));
    } else {
        lines.push(field(
            "Notes",
            Span::styled(
                format!("{} line(s), hidden (r)", notes.lines().count()),
                theme::muted(),
            ),
        ));
    }
    lines.push(Line::from(""));
    lines.push(field(
        "History",
        Span::styled(
            format!("{} previous password(s)", l.history.len()),
            theme::muted(),
        ),
    ));
    lines.push(field(
        "Updated",
        Span::styled(
            item.updated
                .replace_nanosecond(0)
                .ok()
                .and_then(|t| {
                    t.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                })
                .unwrap_or_default(),
            theme::muted(),
        ),
    ));
    lines
}

fn draw_status(f: &mut Frame, app: &App, area: Rect, now: Instant) {
    let left = match (&app.busy, &app.status) {
        (Some(b), _) => Span::styled(format!(" {b}"), theme::accent()),
        (None, Some(s)) => Span::styled(
            format!(" {}", s.text),
            Style::default().fg(match s.kind {
                StatusKind::Info => theme::OK,
                StatusKind::Error => theme::ERROR,
            }),
        ),
        (None, None) if app.is_locked() => Span::styled(" Locked", theme::muted()),
        (None, None) => Span::styled(
            " Ctrl+K commands · / search · c copy · r reveal · n new · ? help · q quit",
            theme::muted(),
        ),
    };
    let right = if app.is_locked() {
        String::new()
    } else {
        let rem = app.idle_remaining(now).as_secs();
        let sync = app.sync_server().map_or("local", |_| "synced vault");
        format!("{sync} · locks in {}:{:02} ", rem / 60, rem % 60)
    };
    let [l, r] = Layout::horizontal([Constraint::Min(0), Constraint::Length(right.len() as u16)])
        .areas(area);
    f.render_widget(Paragraph::new(Line::from(left)), l);
    f.render_widget(
        Paragraph::new(Span::styled(right, theme::muted())).alignment(Alignment::Right),
        r,
    );
}

// ---------- popups ----------

fn draw_palette(f: &mut Frame, p: &crate::app::Palette, area: Rect) {
    let matches = p.matches();
    let r = centered(area, 56, (matches.len() as u16 + 5).min(18));
    f.render_widget(Clear, r);
    let block = popup_block("Commands");
    let inner = block.inner(r);
    f.render_widget(block, r);
    let [input, list] = Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).areas(inner);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("> ", theme::accent()),
            Span::raw(p.query.as_str()),
            Span::styled("▏", theme::accent()),
        ])),
        input,
    );
    let width = list.width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = matches
        .iter()
        .map(|c: &Command| {
            let pad = width.saturating_sub(c.label().len() + c.key().len());
            ListItem::new(Line::from(vec![
                Span::raw(c.label()),
                Span::raw(" ".repeat(pad)),
                Span::styled(c.key(), theme::muted()),
            ]))
        })
        .collect();
    let mut state = ListState::default().with_selected((!matches.is_empty()).then_some(p.selected));
    f.render_stateful_widget(
        List::new(items).highlight_style(theme::selected()),
        list,
        &mut state,
    );
}

fn on_off(on: bool) -> Span<'static> {
    if on {
        Span::styled("[x]", theme::accent())
    } else {
        Span::styled("[ ]", theme::muted())
    }
}

fn draw_generator(f: &mut Frame, g: &crate::app::Generator, area: Rect) {
    let r = centered(area, 78, 14);
    f.render_widget(Clear, r);
    let mut lines = vec![
        Line::from(Span::styled(
            g.current.expose_secret().to_owned(),
            theme::accent().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("{} ({})", g.entropy, g.entropy.strength()),
            theme::muted(),
        )),
        Line::from(""),
    ];
    if g.passphrase {
        lines.push(Line::from(format!(
            "Passphrase · {} words  (←/→)",
            g.phrase.words
        )));
        lines.push(Line::from(vec![
            on_off(g.phrase.capitalize),
            Span::raw(" C capitalise   "),
            on_off(g.phrase.add_digit),
            Span::raw(" n digit"),
        ]));
    } else {
        let o = &g.chars;
        lines.push(Line::from(format!(
            "Characters · length {}  (←/→)",
            o.length
        )));
        lines.push(Line::from(vec![
            on_off(o.lower),
            Span::raw(" l a-z  "),
            on_off(o.upper),
            Span::raw(" u A-Z  "),
            on_off(o.digits),
            Span::raw(" d 0-9  "),
            on_off(o.symbols),
            Span::raw(" s !#$  "),
            on_off(o.exclude_ambiguous),
            Span::raw(" a no look-alikes"),
        ]));
    }
    if let Some(e) = &g.error {
        lines.push(Line::from(Span::styled(
            e.as_str(),
            Style::default().fg(theme::ERROR),
        )));
    }
    lines.push(Line::from(""));
    let enter = if g.return_to.is_some() {
        "Enter use"
    } else {
        "Enter copy"
    };
    lines.push(Line::from(Span::styled(
        format!("r regenerate · p chars/passphrase · c copy · {enter} · Esc close"),
        theme::muted(),
    )));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(popup_block("Generator")),
        r,
    );
}

fn draw_form(f: &mut Frame, form: &crate::app::Form, area: Rect) {
    let r = centered(area, 72, form.fields.len() as u16 * 2 + 6);
    f.render_widget(Clear, r);
    let title = if form.editing.is_some() {
        "Edit item"
    } else {
        "New item"
    };
    let mut lines = Vec::new();
    for (i, fld) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let value = if fld.secret && !fld.value.is_empty() {
            if i == F_PASSWORD {
                "•".repeat(fld.value.chars().count().min(40))
            } else {
                MASK.to_owned()
            }
        } else {
            fld.value.as_str().to_owned()
        };
        let mut spans = vec![
            Span::styled(
                format!("{}{:<12}", if focused { "▶ " } else { "  " }, fld.label),
                if focused {
                    theme::accent()
                } else {
                    theme::label()
                },
            ),
            Span::raw(value),
        ];
        if focused {
            spans.push(Span::styled("▏", theme::accent()));
        }
        lines.push(Line::from(spans));
        lines.push(Line::from(Span::styled(
            format!("{:14}{}", "", fld.hint),
            theme::muted(),
        )));
    }
    if let Some(e) = &form.error {
        lines.push(Line::from(Span::styled(
            e.as_str(),
            Style::default().fg(theme::ERROR),
        )));
    }
    lines.push(Line::from(Span::styled(
        "Tab/↑↓ move · Ctrl+G generate password · Enter save · Esc cancel",
        theme::muted(),
    )));
    f.render_widget(Paragraph::new(lines).block(popup_block(title)), r);
}

fn draw_confirm(f: &mut Frame, title: &str, area: Rect) {
    let r = centered(area, 50, 6);
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(format!("Delete \"{title}\"?")),
            Line::from(""),
            Line::from(Span::styled(
                "y delete · any other key cancel",
                theme::muted(),
            )),
        ])
        .alignment(Alignment::Center)
        .block(popup_block("Confirm")),
        r,
    );
}

fn draw_help(f: &mut Frame, area: Rect) {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!("{:<14}", "Ctrl+K"), theme::accent()),
            Span::raw("Command palette"),
        ]),
        Line::from(vec![
            Span::styled(format!("{:<14}", "/"), theme::accent()),
            Span::raw("Fuzzy search (Esc clears)"),
        ]),
        Line::from(vec![
            Span::styled(format!("{:<14}", "↑↓ / j k"), theme::accent()),
            Span::raw("Move"),
        ]),
        Line::from(vec![
            Span::styled(format!("{:<14}", "Tab ← →"), theme::accent()),
            Span::raw("Switch pane"),
        ]),
    ];
    for c in Command::ALL {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<14}", c.key()), theme::accent()),
            Span::raw(c.label()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Any key closes this window",
        theme::muted(),
    )));
    let r = centered(area, 52, lines.len() as u16 + 2);
    f.render_widget(Clear, r);
    f.render_widget(Paragraph::new(lines).block(popup_block("Keys")), r);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::{code, ctrl, fixture, key};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::KeyCode;

    fn render(app: &App, now: Instant) -> String {
        let mut t = Terminal::new(TestBackend::new(120, 34)).unwrap();
        t.draw(|f| draw(f, app, now, 59)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        // `KW_TUI_DUMP=1 cargo test -p keyward-tui -- --nocapture` prints screens.
        if std::env::var_os("KW_TUI_DUMP").is_some() {
            eprintln!("{out}");
        }
        out
    }

    #[test]
    fn three_panes_with_items_and_masked_password() {
        let (_d, app, now) = fixture();
        let s = render(&app, now);
        for want in [
            "Categories",
            "All items",
            "#work",
            "Items 3/3",
            "Bank",
            "GitHub",
            "Mail",
            "Details",
        ] {
            assert!(s.contains(want), "missing {want}\n{s}");
        }
        assert!(s.contains(MASK));
        assert!(!s.contains("bank-secret"), "password must be hidden\n{s}");
        assert!(s.contains("locks in 5:00"));
    }

    #[test]
    fn reveal_shows_password_and_lock_hides_everything() {
        let (_d, mut app, now) = fixture();
        app.handle_key(key('r'), now);
        assert!(render(&app, now).contains("bank-secret"));
        app.handle_key(ctrl('l'), now);
        let s = render(&app, now);
        assert!(s.contains("Master password"));
        for leak in ["bank-secret", "Bank", "GitHub", "octocat"] {
            assert!(!s.contains(leak), "locked screen shows {leak}");
        }
    }

    #[test]
    fn totp_code_and_countdown() {
        let (_d, mut app, now) = fixture();
        app.handle_key(key('j'), now); // GitHub (TOTP secret = "12345")
        let s = render(&app, now);
        assert!(s.contains("TOTP"));
        // RFC 4226 key "12345" at t=59 (counter 1)
        let t = Totp::parse("GEZDGNBVGY3TQOJQ").unwrap();
        let c = t.code_at(59);
        let c = c.expose_secret();
        assert!(s.contains(&format!("{} {}", &c[..3], &c[3..])), "{s}");
        assert!(s.contains(" 1s"), "countdown at t=59 shows 1 s left\n{s}");
    }

    #[test]
    fn popups_render() {
        let (_d, mut app, now) = fixture();
        app.handle_key(ctrl('k'), now);
        let s = render(&app, now);
        assert!(s.contains("Commands") && s.contains("Copy password") && s.contains("Ctrl+L"));
        app.handle_key(code(KeyCode::Esc), now);

        app.handle_key(key('g'), now);
        let s = render(&app, now);
        assert!(s.contains("Generator") && s.contains("bits"));
        app.handle_key(code(KeyCode::Esc), now);

        app.handle_key(key('n'), now);
        let s = render(&app, now);
        assert!(s.contains("New item") && s.contains("Password") && s.contains("Ctrl+G"));
        app.handle_key(code(KeyCode::Esc), now);

        app.handle_key(key('d'), now);
        assert!(render(&app, now).contains("Delete \"Bank\"?"));
        app.handle_key(key('n'), now);

        app.handle_key(key('?'), now);
        assert!(render(&app, now).contains("Command palette"));
    }

    #[test]
    fn form_masks_password_field() {
        let (_d, mut app, now) = fixture();
        app.handle_key(key('n'), now);
        for _ in 0..F_PASSWORD {
            app.handle_key(code(KeyCode::Tab), now);
        }
        for c in "typed-secret".chars() {
            app.handle_key(key(c), now);
        }
        let s = render(&app, now);
        assert!(!s.contains("typed-secret"));
        assert!(s.contains("••••••••••••"));
    }

    #[test]
    fn small_terminal_does_not_panic() {
        let (_d, mut app, now) = fixture();
        for (w, h) in [(20, 5), (1, 1), (80, 10)] {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            t.draw(|f| draw(f, &app, now, 0)).unwrap();
            app.handle_key(ctrl('k'), now);
            t.draw(|f| draw(f, &app, now, 0)).unwrap();
            app.handle_key(code(KeyCode::Esc), now);
        }
    }
}
