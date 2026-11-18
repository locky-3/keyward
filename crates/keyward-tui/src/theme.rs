//! Colours: copper accent on graphite.

use ratatui::style::{Color, Modifier, Style};

/// Graphite background.
pub const BG: Color = Color::Rgb(0x14, 0x16, 0x1a);
/// Slightly lighter surface for popups.
pub const SURFACE: Color = Color::Rgb(0x1c, 0x1f, 0x24);
/// Unfocused borders.
pub const BORDER: Color = Color::Rgb(0x3a, 0x3f, 0x47);
/// Copper accent: focus, selection, highlights.
pub const ACCENT: Color = Color::Rgb(0xc8, 0x64, 0x3c);
/// Primary text.
pub const TEXT: Color = Color::Rgb(0xd7, 0xda, 0xe0);
/// Secondary text.
pub const MUTED: Color = Color::Rgb(0x8b, 0x91, 0x9a);
/// Errors.
pub const ERROR: Color = Color::Rgb(0xe0, 0x6c, 0x75);
/// Success.
pub const OK: Color = Color::Rgb(0x98, 0xc3, 0x79);

pub fn base() -> Style {
    Style::default().fg(TEXT).bg(BG)
}

pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

pub fn accent() -> Style {
    Style::default().fg(ACCENT)
}

pub fn border(focused: bool) -> Style {
    Style::default().fg(if focused { ACCENT } else { BORDER })
}

pub fn selected() -> Style {
    Style::default()
        .fg(BG)
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

pub fn label() -> Style {
    Style::default().fg(MUTED)
}
