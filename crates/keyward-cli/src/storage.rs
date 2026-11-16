//! Vault file I/O: atomic replace, rotating backups and an inter-process lock.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use keyward_core::VaultFile;

/// Number of rotating backups kept next to the vault (`.bak.1` is newest).
pub const BACKUPS: usize = 3;

/// `vault.kwv` -> `vault.kwv.bak.N`
pub fn backup_path(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".bak.{n}"));
    PathBuf::from(s)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

/// Read and parse a vault file (no decryption).
pub fn read_vault(path: &Path) -> Result<VaultFile> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            bail!(
                "no vault at {} (run `kw init` to create one)",
                path.display()
            )
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    VaultFile::from_bytes(&bytes).with_context(|| format!("reading {}", path.display()))
}

/// Replace `path` with `bytes` atomically:
/// 1. write a temp file in the same directory and fsync it,
/// 2. rotate backups (`.bak.2`→`.bak.3`, …) and copy the current file to `.bak.1`,
/// 3. rename the temp file over `path` (atomic on the same filesystem),
/// 4. fsync the directory (Unix) so the rename itself is durable.
///
/// A crash at any point leaves either the old or the new vault in place.
pub fn write_atomic(path: &Path, bytes: &[u8], backups: usize) -> Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    // Created with mode 0600 on Unix.
    let mut tmp = tempfile::Builder::new()
        .prefix(".kw-")
        .suffix(".tmp")
        .tempfile_in(dir)
        .with_context(|| format!("creating temporary file in {}", dir.display()))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;

    if backups > 0 && path.exists() {
        rotate_backups(path, backups)?;
    }

    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("replacing {}", path.display()))?;

    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn rotate_backups(path: &Path, keep: usize) -> Result<()> {
    for n in (1..keep).rev() {
        let from = backup_path(path, n);
        if from.exists() {
            fs::rename(&from, backup_path(path, n + 1))
                .with_context(|| format!("rotating {}", from.display()))?;
        }
    }
    let first = backup_path(path, 1);
    fs::copy(path, &first).with_context(|| format!("writing backup {}", first.display()))?;
    // FlushFileBuffers on Windows requires a handle with write access.
    OpenOptions::new().write(true).open(&first)?.sync_all()?;
    Ok(())
}

/// Exclusive lock held while a process reads-checks-writes the vault.
/// Released when dropped.
#[derive(Debug)]
pub struct VaultLock {
    _file: File,
}

/// Take the vault lock or fail immediately if another `kw` holds it.
pub fn lock(path: &Path) -> Result<VaultLock> {
    let lp = lock_path(path);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lp)
        .with_context(|| format!("opening lock file {}", lp.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(VaultLock { _file: file }),
        Err(TryLockError::WouldBlock) => {
            bail!("the vault is being modified by another kw process; try again")
        }
        Err(TryLockError::Error(e)) => Err(e).context("locking the vault"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.kwv");
        write_atomic(&p, b"one", BACKUPS).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        assert!(!backup_path(&p, 1).exists(), "no backup of a new file");
        write_atomic(&p, b"two", BACKUPS).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::read(backup_path(&p, 1)).unwrap(), b"one");
    }

    #[test]
    fn backups_rotate_and_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.kwv");
        for i in 0..6 {
            write_atomic(&p, format!("v{i}").as_bytes(), BACKUPS).unwrap();
        }
        assert_eq!(fs::read(&p).unwrap(), b"v5");
        assert_eq!(fs::read(backup_path(&p, 1)).unwrap(), b"v4");
        assert_eq!(fs::read(backup_path(&p, 2)).unwrap(), b"v3");
        assert_eq!(fs::read(backup_path(&p, 3)).unwrap(), b"v2");
        assert!(!backup_path(&p, 4).exists());
    }

    #[test]
    fn no_temp_files_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.kwv");
        write_atomic(&p, b"a", BACKUPS).unwrap();
        write_atomic(&p, b"b", BACKUPS).unwrap();
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn lock_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.kwv");
        let first = lock(&p).unwrap();
        let err = lock(&p).unwrap_err().to_string();
        assert!(err.contains("another kw process"), "{err}");
        drop(first);
        lock(&p).unwrap();
    }

    #[test]
    fn read_missing_vault_has_helpful_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_vault(&dir.path().join("nope.kwv"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("kw init"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn vault_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.kwv");
        write_atomic(&p, b"x", BACKUPS).unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
