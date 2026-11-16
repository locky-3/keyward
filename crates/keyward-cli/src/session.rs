//! An unlocked vault bound to its file, with conflict-checked saving.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use keyward_core::{KdfParams, SecretString, UnlockedVault};

use crate::prompt::Prompter;
use crate::storage;

/// Unlocked vault plus the file it came from.
pub struct Session {
    path: PathBuf,
    /// Revision on disk when we unlocked/last saved; used to detect
    /// concurrent modification by another process.
    base_revision: u64,
    pub vault: UnlockedVault,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("path", &self.path)
            .field("base_revision", &self.base_revision)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Read the vault file and unlock it with a prompted master password.
    pub fn open(path: &Path, prompter: Prompter) -> Result<Self> {
        // Read first so a missing file is reported before prompting.
        storage::read_vault(path)?;
        let pw = prompter.secret("Master password: ")?;
        Self::open_with(path, &pw)
    }

    /// Read the vault file and unlock it with `password`.
    pub fn open_with(path: &Path, password: &SecretString) -> Result<Self> {
        let file = storage::read_vault(path)?;
        let vault = file.unlock(password)?;
        Ok(Self {
            path: path.to_owned(),
            base_revision: file.revision(),
            vault,
        })
    }

    /// Create and write a brand-new vault. Refuses to overwrite.
    pub fn create(path: &Path, password: &SecretString, kdf: KdfParams) -> Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating directory {}", dir.display()))?;
        }
        let _lock = storage::lock(path)?;
        if path.exists() {
            bail!("a vault already exists at {}", path.display());
        }
        let mut vault = UnlockedVault::create(password, kdf)?;
        let file = vault.seal()?;
        storage::write_atomic(path, &file.to_bytes()?, storage::BACKUPS)?;
        Ok(Self {
            path: path.to_owned(),
            base_revision: file.revision(),
            vault,
        })
    }

    /// Encrypt and write the vault, unless another process changed the
    /// file since we read it (in which case nothing is written).
    pub fn save(&mut self) -> Result<()> {
        let _lock = storage::lock(&self.path)?;
        let on_disk = storage::read_vault(&self.path)?;
        if on_disk.header().vault_id != self.vault.header().vault_id
            || on_disk.revision() != self.base_revision
        {
            bail!(
                "the vault file was changed by another process since it was unlocked; \
                 your change was NOT saved — run the command again"
            );
        }
        let file = self.vault.seal()?;
        storage::write_atomic(&self.path, &file.to_bytes()?, storage::BACKUPS)?;
        self.base_revision = file.revision();
        Ok(())
    }

    /// Vault path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyward_core::{ItemKind, Login};

    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: KdfParams::MIN_M_COST_KIB,
            t_cost: KdfParams::MIN_T_COST,
            p_cost: 1,
        }
    }

    fn login(t: &str) -> ItemKind {
        ItemKind::Login(Login::new(t, "u", SecretString::from("p".to_owned())))
    }

    #[test]
    fn concurrent_modification_is_refused_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kwv");
        let pw = SecretString::from("master-pass".to_owned());
        let mut a = Session::create(&path, &pw, fast()).unwrap();
        let mut b = Session::open_with(&path, &pw).unwrap();

        b.vault.add(login("from B"));
        b.save().unwrap();

        a.vault.add(login("from A"));
        let err = a.save().unwrap_err().to_string();
        assert!(err.contains("changed by another process"), "{err}");

        // B's write survived, A's did not clobber it.
        let c = Session::open_with(&path, &pw).unwrap();
        let titles: Vec<_> = c
            .vault
            .list()
            .iter()
            .map(|i| i.kind.title().to_owned())
            .collect();
        assert_eq!(titles, ["from B"]);
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kwv");
        let pw = SecretString::from("master-pass".to_owned());
        Session::create(&path, &pw, fast()).unwrap();
        assert!(Session::create(&path, &pw, fast()).is_err());
    }
}
