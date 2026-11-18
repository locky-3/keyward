//! Keyward terminal UI: three panes (categories | fuzzy-searchable items |
//! details), Ctrl+K command palette, generator, add/edit forms, TOTP
//! countdown and idle auto-lock.
#![forbid(unsafe_code)]

pub mod app;
pub mod fuzzy;
pub mod theme;
pub mod ui;
