//! Vault item model.
//!
//! Decrypted item data lives only inside an unlocked vault. Every field of
//! [`Login`] is zeroized on drop: secret fields via `SecretString`, the rest
//! via `ZeroizeOnDrop`. `Debug` never prints item contents.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of previous passwords kept per login.
pub const PASSWORD_HISTORY_MAX: usize = 20;

/// Random, stable identifier of an item.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ItemId(Uuid);

impl ItemId {
    /// Fresh random (v4) id.
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    /// 16 raw bytes, used in the AAD.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// Lower-case hex without dashes (32 chars).
    pub fn to_hex(&self) -> String {
        self.0.simple().to_string()
    }

    /// First 8 hex chars, for display.
    pub fn short(&self) -> String {
        self.to_hex()[..8].to_owned()
    }
}

impl fmt::Debug for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemId({})", self.0)
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A password that was replaced, kept so it can be recovered.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordHistoryEntry {
    /// The old password.
    #[serde(with = "crate::encoding::secret_string")]
    pub password: SecretString,
    /// When it stopped being the current password.
    #[serde(with = "time::serde::rfc3339")]
    pub replaced_at: OffsetDateTime,
}

impl fmt::Debug for PasswordHistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHistoryEntry")
            .field("replaced_at", &self.replaced_at)
            .finish_non_exhaustive()
    }
}

/// A website/app login.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Login {
    /// Display name.
    pub title: String,
    /// Username or e-mail.
    pub username: String,
    /// Current password.
    #[serde(with = "crate::encoding::secret_string")]
    #[zeroize(skip)] // SecretString zeroizes itself on drop
    pub password: SecretString,
    /// Website or app URL.
    #[serde(default)]
    pub url: Option<String>,
    /// Free-form notes.
    #[serde(with = "crate::encoding::secret_string")]
    #[zeroize(skip)]
    pub notes: SecretString,
    /// Tags for grouping and search.
    #[serde(default)]
    pub tags: Vec<String>,
    /// TOTP secret: base32 or an `otpauth://` URI.
    #[serde(default, with = "crate::encoding::opt_secret_string")]
    #[zeroize(skip)]
    pub totp: Option<SecretString>,
    /// Previous passwords, oldest first.
    #[serde(default)]
    #[zeroize(skip)] // each entry holds a self-zeroizing SecretString
    pub history: Vec<PasswordHistoryEntry>,
}

impl Login {
    /// New login with empty optional fields.
    pub fn new(
        title: impl Into<String>,
        username: impl Into<String>,
        password: SecretString,
    ) -> Self {
        Self {
            title: title.into(),
            username: username.into(),
            password,
            url: None,
            notes: SecretString::from(String::new()),
            tags: Vec::new(),
            totp: None,
            history: Vec::new(),
        }
    }
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Login { [REDACTED] }")
    }
}

/// Item payload. Externally tagged so serde never buffers secrets in an
/// intermediate `Content` value while looking for a tag.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ItemKind {
    /// A login (the only kind in v1).
    Login(Login),
}

impl ItemKind {
    /// Title used for listing and sorting.
    pub fn title(&self) -> &str {
        match self {
            Self::Login(l) => &l.title,
        }
    }

    /// The login, if this is one.
    pub fn as_login(&self) -> Option<&Login> {
        match self {
            Self::Login(l) => Some(l),
        }
    }

    /// Mutable access to the login, if this is one.
    pub fn as_login_mut(&mut self) -> Option<&mut Login> {
        match self {
            Self::Login(l) => Some(l),
        }
    }

    /// Does this item match a (lower-cased) search query? Searches title,
    /// username, URL and tags; never secret fields.
    pub(crate) fn matches(&self, needle_lower: &str) -> bool {
        match self {
            Self::Login(l) => {
                l.title.to_lowercase().contains(needle_lower)
                    || l.username.to_lowercase().contains(needle_lower)
                    || l.url
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(needle_lower))
                    || l.tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(needle_lower))
            }
        }
    }

    /// Record the old password in history if it changed.
    pub(crate) fn record_password_change(&mut self, old: SecretString, at: OffsetDateTime) {
        match self {
            Self::Login(l) => {
                let same: bool = old
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(l.password.expose_secret().as_bytes())
                    .into();
                if !same {
                    l.history.push(PasswordHistoryEntry {
                        password: old,
                        replaced_at: at,
                    });
                    let excess = l.history.len().saturating_sub(PASSWORD_HISTORY_MAX);
                    l.history.drain(..excess);
                }
            }
        }
    }

    pub(crate) fn password_snapshot(&self) -> SecretString {
        match self {
            Self::Login(l) => SecretString::from(l.password.expose_secret().to_owned()),
        }
    }
}

impl fmt::Debug for ItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Login(l) => fmt::Debug::fmt(l, f),
        }
    }
}

/// A decrypted vault item.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    /// Stable id.
    pub id: ItemId,
    /// Incremented on every edit; bound into the item's AAD.
    pub version: u64,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    /// Last modification time.
    #[serde(with = "time::serde::rfc3339")]
    pub updated: OffsetDateTime,
    /// Payload.
    pub kind: ItemKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Login {
        let mut l = Login::new(
            "GitHub",
            "octo@example.com",
            SecretString::from("hunter2-very-secret".to_owned()),
        );
        l.url = Some("https://github.com".into());
        l.tags = vec!["Work".into(), "dev".into()];
        l.notes = SecretString::from("recovery codes in safe".to_owned());
        l
    }

    #[test]
    fn json_round_trip() {
        let item = Item {
            id: ItemId::random(),
            version: 3,
            created: OffsetDateTime::UNIX_EPOCH,
            updated: OffsetDateTime::now_utc(),
            kind: ItemKind::Login(login()),
        };
        let json = serde_json::to_vec(&item).unwrap();
        let back: Item = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.id, item.id);
        assert_eq!(back.version, 3);
        let l = back.kind.as_login().unwrap();
        assert_eq!(l.password.expose_secret(), "hunter2-very-secret");
        assert_eq!(l.notes.expose_secret(), "recovery codes in safe");
        assert_eq!(l.tags, ["Work", "dev"]);
    }

    #[test]
    fn debug_is_redacted() {
        let item = Item {
            id: ItemId::random(),
            version: 1,
            created: OffsetDateTime::UNIX_EPOCH,
            updated: OffsetDateTime::UNIX_EPOCH,
            kind: ItemKind::Login(login()),
        };
        let d = format!("{item:?}");
        for leak in ["hunter2", "octo@", "GitHub", "recovery", "github.com"] {
            assert!(!d.contains(leak), "Debug leaked {leak}: {d}");
        }
    }

    #[test]
    fn search_matches_public_fields_case_insensitively_but_not_secrets() {
        let k = ItemKind::Login(login());
        for q in ["github", "octo", "github.com", "work"] {
            assert!(k.matches(q), "{q}");
        }
        assert!(!k.matches("hunter2"));
        assert!(!k.matches("recovery"));
    }

    #[test]
    fn password_history_records_changes_only_and_is_capped() {
        let mut k = ItemKind::Login(login());
        let t = OffsetDateTime::UNIX_EPOCH;
        // unchanged password: nothing recorded
        let snap = k.password_snapshot();
        k.record_password_change(snap, t);
        assert!(k.as_login().unwrap().history.is_empty());

        for i in 0..(PASSWORD_HISTORY_MAX + 5) {
            let old = k.password_snapshot();
            k.as_login_mut().unwrap().password = SecretString::from(format!("pw-{i}"));
            k.record_password_change(old, t);
        }
        let h = &k.as_login().unwrap().history;
        assert_eq!(h.len(), PASSWORD_HISTORY_MAX);
        // oldest entries were dropped; newest old password is pw-(n-2)
        assert_eq!(
            h.last().unwrap().password.expose_secret(),
            format!("pw-{}", PASSWORD_HISTORY_MAX + 3)
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let j = r#"{"title":"t","username":"u","password":"p","notes":"","evil":1}"#;
        assert!(serde_json::from_str::<Login>(j).is_err());
    }
}
