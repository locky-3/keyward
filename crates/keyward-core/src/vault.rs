//! Vault container: on-disk [`VaultFile`] (ciphertext only) and in-memory
//! [`UnlockedVault`]. See `docs/vault-format.md` for the byte layout.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::aead::{self, Sealed, aad};
use crate::encoding::to_json_zeroizing;
use crate::error::{Error, Result};
use crate::item::{Item, ItemId, ItemKind};
use crate::kdf::{KdfParams, Salt, derive_master_key};
use crate::keys::VaultKey;

/// File magic: ASCII `KWVT`.
pub const MAGIC: [u8; 4] = *b"KWVT";
/// Current container format version.
pub const FORMAT_VERSION: u16 = 1;
/// magic (4) + format version (2) + body length (4)
const PREFIX_LEN: usize = 10;

/// Random identifier of a vault; bound into every AAD so blobs cannot be
/// moved between vaults.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VaultId(Uuid);

impl VaultId {
    /// Fresh random (v4) id.
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    /// 16 raw bytes, used in the AAD.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultId({})", self.0)
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Key-derivation algorithm. Only Argon2id exists in format v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// Argon2id, version 0x13.
    #[serde(rename = "argon2id")]
    Argon2id,
}

/// KDF section of the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfHeader {
    /// Algorithm identifier.
    pub algorithm: KdfAlgorithm,
    /// Cost parameters.
    pub params: KdfParams,
    /// Per-vault salt.
    pub salt: Salt,
}

/// Plaintext but authenticated vault header (bound into the key-wrap AAD).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    /// Vault identifier.
    pub vault_id: VaultId,
    /// How the master key is derived.
    pub kdf: KdfHeader,
}

impl Header {
    fn wrap_aad(&self) -> Vec<u8> {
        aad::wrap(
            FORMAT_VERSION,
            &self.vault_id,
            &self.kdf.salt,
            &self.kdf.params,
        )
    }
}

/// One encrypted item as stored in the file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedItem {
    /// Item id (plaintext, also bound into the AAD).
    pub id: ItemId,
    /// Item version (plaintext, also bound into the AAD).
    pub version: u64,
    blob: Sealed,
}

impl EncryptedItem {
    fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        for part in self.blob.digest_input() {
            h.update(part);
        }
        h.finalize().into()
    }
}

/// Decrypted index: the authoritative list of what the vault contains.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexPlain {
    vault_id: VaultId,
    revision: u64,
    entries: Vec<IndexEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexEntry {
    id: ItemId,
    version: u64,
    #[serde(with = "crate::encoding::b64_array")]
    digest: [u8; 32],
}

/// A vault as stored on disk. Contains only ciphertext and public metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFile {
    header: Header,
    wrapped_vault_key: Sealed,
    revision: u64,
    index: Sealed,
    items: Vec<EncryptedItem>,
}

impl VaultFile {
    /// Parse the container. Does not decrypt anything.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 || bytes[..4] != MAGIC {
            return Err(Error::NotAVault);
        }
        if bytes.len() < PREFIX_LEN {
            return Err(Error::Malformed);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let body_len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
        let body = &bytes[PREFIX_LEN..];
        if body.len() != body_len {
            return Err(Error::Malformed);
        }
        serde_json::from_slice(body).map_err(|_| Error::Malformed)
    }

    /// Serialize the container.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body = serde_json::to_vec(self).map_err(|_| Error::Crypto)?;
        let len = u32::try_from(body.len()).map_err(|_| Error::Malformed)?;
        let mut out = Vec::with_capacity(PREFIX_LEN + body.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Public header (vault id, KDF parameters).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Save counter; increases by one on every save.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Number of stored items (visible without unlocking).
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Derive the master key, unwrap the vault key, verify the index and
    /// decrypt every item. Any failure is reported as [`Error::UnlockFailed`]
    /// (except KDF parameters outside the accepted range, which are checked
    /// before any work and leak nothing about the password).
    pub fn unlock(&self, password: &SecretString) -> Result<UnlockedVault> {
        let h = &self.header;
        h.kdf.params.validate()?;
        let master = derive_master_key(password, &h.kdf.salt, &h.kdf.params)?;
        let wrap_key = master.wrap_key();
        drop(master);

        let fail = |_| Error::UnlockFailed;

        let vk_bytes =
            aead::open(wrap_key.bytes(), &self.wrapped_vault_key, &h.wrap_aad()).map_err(fail)?;
        let vault_key = VaultKey::from_slice(&vk_bytes).ok_or(Error::UnlockFailed)?;
        drop(vk_bytes);

        // Index: authenticates the exact set of (id, version, ciphertext).
        let index_pt = aead::open(
            vault_key.bytes(),
            &self.index,
            &aad::index(&h.vault_id, self.revision),
        )
        .map_err(fail)?;
        let index: IndexPlain =
            serde_json::from_slice(&index_pt).map_err(|_| Error::UnlockFailed)?;
        if index.vault_id != h.vault_id
            || index.revision != self.revision
            || index.entries.len() != self.items.len()
        {
            return Err(Error::UnlockFailed);
        }
        let expected: BTreeMap<ItemId, &IndexEntry> =
            index.entries.iter().map(|e| (e.id, e)).collect();
        if expected.len() != index.entries.len() {
            return Err(Error::UnlockFailed);
        }

        let mut items = BTreeMap::new();
        let mut sealed = BTreeMap::new();
        for enc in &self.items {
            let entry = expected.get(&enc.id).ok_or(Error::UnlockFailed)?;
            // Digests are public data, so a plain comparison is fine here.
            if entry.version != enc.version || entry.digest != enc.digest() {
                return Err(Error::UnlockFailed);
            }
            let pt = aead::open(
                vault_key.bytes(),
                &enc.blob,
                &aad::item(&h.vault_id, &enc.id, enc.version),
            )
            .map_err(fail)?;
            let item: Item = serde_json::from_slice(&pt).map_err(|_| Error::UnlockFailed)?;
            if item.id != enc.id || item.version != enc.version {
                return Err(Error::UnlockFailed);
            }
            if items.insert(enc.id, item).is_some() {
                return Err(Error::UnlockFailed);
            }
            sealed.insert(enc.id, enc.clone());
        }

        Ok(UnlockedVault {
            header: self.header,
            wrapped_vault_key: self.wrapped_vault_key.clone(),
            vault_key,
            revision: self.revision,
            items,
            sealed,
        })
    }
}

/// A decrypted vault held in memory. Dropping it zeroizes the vault key and
/// all item data.
pub struct UnlockedVault {
    header: Header,
    wrapped_vault_key: Sealed,
    vault_key: VaultKey,
    revision: u64,
    items: BTreeMap<ItemId, Item>,
    /// Ciphertext of items unchanged since the last unlock/seal, reused so
    /// that untouched items are not re-encrypted on every save.
    sealed: BTreeMap<ItemId, EncryptedItem>,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault_id", &self.header.vault_id)
            .field("revision", &self.revision)
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    /// Create a new, empty vault protected by `password`.
    pub fn create(password: &SecretString, kdf: KdfParams) -> Result<Self> {
        let header = Header {
            vault_id: VaultId::random(),
            kdf: KdfHeader {
                algorithm: KdfAlgorithm::Argon2id,
                params: kdf,
                salt: Salt::random(),
            },
        };
        let vault_key = VaultKey::generate();
        let wrapped_vault_key = wrap_vault_key(password, &header, &vault_key)?;
        Ok(Self {
            header,
            wrapped_vault_key,
            vault_key,
            revision: 0,
            items: BTreeMap::new(),
            sealed: BTreeMap::new(),
        })
    }

    /// Encrypt the vault for storage. Increments the revision.
    pub fn seal(&mut self) -> Result<VaultFile> {
        let revision = self.revision.checked_add(1).ok_or(Error::Crypto)?;
        let vid = self.header.vault_id;
        let mut encrypted = Vec::with_capacity(self.items.len());
        let mut entries = Vec::with_capacity(self.items.len());
        for (id, item) in &self.items {
            let enc = match self.sealed.get(id) {
                Some(e) if e.version == item.version => e.clone(),
                _ => {
                    let pt = to_json_zeroizing(item).map_err(|_| Error::Crypto)?;
                    EncryptedItem {
                        id: *id,
                        version: item.version,
                        blob: aead::seal(
                            self.vault_key.bytes(),
                            &pt,
                            &aad::item(&vid, id, item.version),
                        )?,
                    }
                }
            };
            entries.push(IndexEntry {
                id: *id,
                version: enc.version,
                digest: enc.digest(),
            });
            encrypted.push(enc);
        }
        let index_pt = to_json_zeroizing(&IndexPlain {
            vault_id: vid,
            revision,
            entries,
        })
        .map_err(|_| Error::Crypto)?;
        let index = aead::seal(
            self.vault_key.bytes(),
            &index_pt,
            &aad::index(&vid, revision),
        )?;

        self.revision = revision;
        self.sealed = encrypted.iter().map(|e| (e.id, e.clone())).collect();
        Ok(VaultFile {
            header: self.header,
            wrapped_vault_key: self.wrapped_vault_key.clone(),
            revision,
            index,
            items: encrypted,
        })
    }

    /// Re-wrap the vault key under a new master password (and optionally
    /// new KDF parameters). Items are not re-encrypted.
    pub fn change_master_password(&mut self, new: &SecretString, kdf: KdfParams) -> Result<()> {
        let mut header = self.header;
        header.kdf.params = kdf;
        header.kdf.salt = Salt::random();
        self.wrapped_vault_key = wrap_vault_key(new, &header, &self.vault_key)?;
        self.header = header;
        Ok(())
    }

    /// Public header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Revision of the last sealed/opened state.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when the vault holds no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Add a new item; returns its id.
    pub fn add(&mut self, kind: ItemKind) -> ItemId {
        let now = OffsetDateTime::now_utc();
        let id = ItemId::random();
        self.items.insert(
            id,
            Item {
                id,
                version: 1,
                created: now,
                updated: now,
                kind,
            },
        );
        id
    }

    /// Look up an item.
    pub fn get(&self, id: ItemId) -> Option<&Item> {
        self.items.get(&id)
    }

    /// Edit an item in place. Bumps its version and `updated` time and
    /// records the previous password in history if it changed.
    pub fn update(&mut self, id: ItemId, edit: impl FnOnce(&mut ItemKind)) -> Result<()> {
        let item = self.items.get_mut(&id).ok_or(Error::ItemNotFound)?;
        let old_password = item.kind.password_snapshot();
        edit(&mut item.kind);
        let now = OffsetDateTime::now_utc();
        item.kind.record_password_change(old_password, now);
        item.version = item.version.checked_add(1).ok_or(Error::Crypto)?;
        item.updated = now;
        Ok(())
    }

    /// Delete an item.
    pub fn remove(&mut self, id: ItemId) -> Result<()> {
        self.sealed.remove(&id);
        self.items.remove(&id).map(drop).ok_or(Error::ItemNotFound)
    }

    /// All items, sorted by title (case-insensitive), then id.
    pub fn list(&self) -> Vec<&Item> {
        let mut v: Vec<&Item> = self.items.values().collect();
        v.sort_by_cached_key(|i| (i.kind.title().to_lowercase(), i.id));
        v
    }

    /// Case-insensitive substring search over title, username, URL and tags.
    pub fn search(&self, query: &str) -> Vec<&Item> {
        let q = query.to_lowercase();
        let mut v = self.list();
        v.retain(|i| i.kind.matches(&q));
        v
    }

    /// Ids of all items (for callers that need to resolve prefixes).
    pub fn ids(&self) -> BTreeSet<ItemId> {
        self.items.keys().copied().collect()
    }
}

fn wrap_vault_key(password: &SecretString, header: &Header, vk: &VaultKey) -> Result<Sealed> {
    let master = derive_master_key(password, &header.kdf.salt, &header.kdf.params)?;
    let wrap_key = master.wrap_key();
    aead::seal(wrap_key.bytes(), vk.bytes(), &header.wrap_aad())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Login;
    use proptest::prelude::*;
    use secrecy::ExposeSecret;

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn login(title: &str, pass: &str) -> ItemKind {
        ItemKind::Login(Login::new(title, format!("{title}@example.com"), pw(pass)))
    }

    /// Vault with two items, sealed once; returns (vault, ids, file).
    fn sample() -> (UnlockedVault, [ItemId; 2], VaultFile) {
        let mut v = UnlockedVault::create(&pw("master"), KdfParams::INSECURE_TEST).unwrap();
        let a = v.add(login("Alpha", "pa"));
        let b = v.add(login("Beta", "pb"));
        let f = v.seal().unwrap();
        (v, [a, b], f)
    }

    fn reparse(f: &VaultFile) -> VaultFile {
        VaultFile::from_bytes(&f.to_bytes().unwrap()).unwrap()
    }

    fn password_of(v: &UnlockedVault, id: ItemId) -> String {
        let l = v.get(id).unwrap().kind.as_login().unwrap();
        l.password.expose_secret().to_owned()
    }

    #[test]
    fn create_seal_unlock_round_trip() {
        let (_, [a, b], f) = sample();
        let v = reparse(&f).unlock(&pw("master")).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(password_of(&v, a), "pa");
        assert_eq!(password_of(&v, b), "pb");
        assert_eq!(v.revision(), 1);
        assert_eq!(f.item_count(), 2);
    }

    #[test]
    fn empty_vault_round_trips() {
        let mut v = UnlockedVault::create(&pw("m"), KdfParams::INSECURE_TEST).unwrap();
        let f = v.seal().unwrap();
        assert!(reparse(&f).unlock(&pw("m")).unwrap().is_empty());
    }

    #[test]
    fn file_contains_no_plaintext() {
        let mut v = UnlockedVault::create(&pw("m"), KdfParams::INSECURE_TEST).unwrap();
        v.add(login("VerySecretBank", "Tr0ub4dor&3"));
        let bytes = v.seal().unwrap().to_bytes().unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(!s.contains("VerySecretBank"));
        assert!(!s.contains("Tr0ub4dor"));
        assert!(!s.contains("example.com"));
    }

    #[test]
    fn wrong_password_is_generic_error() {
        let (_, _, f) = sample();
        assert_eq!(f.unlock(&pw("Master")).unwrap_err(), Error::UnlockFailed);
        assert_eq!(f.unlock(&pw("")).unwrap_err(), Error::UnlockFailed);
    }

    #[test]
    fn header_tampering_is_detected() {
        let (_, _, f) = sample();
        let mut g = f.clone();
        g.header.vault_id = VaultId::random();
        assert_eq!(g.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);

        let mut g = f.clone();
        g.header.kdf.salt = Salt::random();
        assert_eq!(g.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);
    }

    #[test]
    fn kdf_param_downgrade_is_detected() {
        let strong = KdfParams {
            m_cost_kib: KdfParams::MIN_M_COST_KIB,
            t_cost: 3,
            p_cost: 1,
        };
        let mut v = UnlockedVault::create(&pw("m"), strong).unwrap();
        let mut f = v.seal().unwrap();
        f.header.kdf.params.t_cost = 2; // still valid, but not what was authenticated
        assert_eq!(f.unlock(&pw("m")).unwrap_err(), Error::UnlockFailed);
    }

    #[test]
    fn out_of_range_kdf_params_are_refused_before_derivation() {
        let (_, _, mut f) = sample();
        f.header.kdf.params.m_cost_kib = u32::MAX;
        assert!(matches!(
            f.unlock(&pw("master")),
            Err(Error::InvalidKdfParams(_))
        ));
    }

    #[test]
    fn swapping_item_blobs_is_detected() {
        let (_, _, mut f) = sample();
        let tmp = f.items[0].blob.clone();
        f.items[0].blob = f.items[1].blob.clone();
        f.items[1].blob = tmp;
        assert_eq!(f.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);
    }

    #[test]
    fn rolling_back_a_single_item_is_detected() {
        let (mut v, [a, _], old) = sample();
        v.update(a, |k| {
            k.as_login_mut().unwrap().password = pw("new");
        })
        .unwrap();
        let mut new = v.seal().unwrap();
        let pos = new.items.iter().position(|e| e.id == a).unwrap();
        let old_item = old.items.iter().find(|e| e.id == a).unwrap().clone();
        new.items[pos] = old_item; // consistent old id+version+blob
        assert_eq!(new.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);
    }

    #[test]
    fn deleting_an_item_from_the_file_is_detected() {
        let (_, _, mut f) = sample();
        f.items.pop();
        assert_eq!(f.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);
    }

    #[test]
    fn duplicating_an_item_is_detected() {
        let (_, _, mut f) = sample();
        let dup = f.items[0].clone();
        f.items[1] = dup;
        assert_eq!(f.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);
    }

    #[test]
    fn item_from_another_vault_is_rejected() {
        let (_, _, mut f) = sample();
        let (_, _, other) = sample(); // same password, different vault
        f.items[0] = other.items[0].clone();
        assert_eq!(f.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);
    }

    #[test]
    fn tampering_with_revision_or_index_is_detected() {
        let (mut v, _, old) = sample();
        let mut f = v.seal().unwrap();
        let mut g = f.clone();
        g.revision += 1;
        assert_eq!(g.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);

        f.index = old.index.clone(); // index from an older revision
        assert_eq!(f.unlock(&pw("master")).unwrap_err(), Error::UnlockFailed);
    }

    /// Documented limitation: replacing the whole file with an older,
    /// self-consistent copy cannot be detected offline.
    #[test]
    fn whole_file_rollback_is_not_detectable_offline() {
        let (mut v, [a, _], old) = sample();
        v.update(a, |k| k.as_login_mut().unwrap().password = pw("new"))
            .unwrap();
        v.seal().unwrap();
        let rolled_back = old.unlock(&pw("master")).unwrap();
        assert_eq!(password_of(&rolled_back, a), "pa");
    }

    #[test]
    fn unchanged_items_keep_their_ciphertext() {
        let (mut v, [a, b], first) = sample();
        v.update(a, |k| k.as_login_mut().unwrap().title = "Alpha 2".into())
            .unwrap();
        let second = v.seal().unwrap();
        let find = |f: &VaultFile, id| f.items.iter().find(|e| e.id == id).unwrap().clone();
        assert_eq!(find(&first, b), find(&second, b));
        assert_ne!(find(&first, a).blob, find(&second, a).blob);
        assert_eq!(find(&second, a).version, 2);
    }

    #[test]
    fn change_master_password_rewraps_only() {
        let (mut v, [a, _], before) = sample();
        v.change_master_password(&pw("new master"), KdfParams::INSECURE_TEST)
            .unwrap();
        let after = v.seal().unwrap();
        assert_eq!(before.items, after.items, "items must not be re-encrypted");
        assert_ne!(before.header.kdf.salt, after.header.kdf.salt);
        assert_eq!(
            after.unlock(&pw("master")).unwrap_err(),
            Error::UnlockFailed
        );
        let v2 = reparse(&after).unlock(&pw("new master")).unwrap();
        assert_eq!(password_of(&v2, a), "pa");
    }

    #[test]
    fn update_bumps_version_and_records_history() {
        let (mut v, [a, _], _) = sample();
        v.update(a, |k| k.as_login_mut().unwrap().password = pw("p2"))
            .unwrap();
        let item = v.get(a).unwrap();
        assert_eq!(item.version, 2);
        let l = item.kind.as_login().unwrap();
        assert_eq!(l.history.len(), 1);
        assert_eq!(l.history[0].password.expose_secret(), "pa");
        assert!(item.updated >= item.created);
    }

    #[test]
    fn remove_and_missing_items() {
        let (mut v, [a, _], _) = sample();
        v.remove(a).unwrap();
        assert_eq!(v.remove(a), Err(Error::ItemNotFound));
        assert_eq!(v.update(a, |_| {}), Err(Error::ItemNotFound));
        let f = v.seal().unwrap();
        assert_eq!(f.unlock(&pw("master")).unwrap().len(), 1);
    }

    #[test]
    fn list_is_sorted_and_search_filters() {
        let (mut v, _, _) = sample();
        v.add(login("aardvark", "x"));
        let titles: Vec<_> = v.list().iter().map(|i| i.kind.title().to_owned()).collect();
        assert_eq!(titles, ["aardvark", "Alpha", "Beta"]);
        let hits: Vec<_> = v.search("BETA@").iter().map(|i| i.kind.title()).collect();
        assert_eq!(hits, ["Beta"]);
        assert!(v.search("pa").is_empty(), "passwords are not searchable");
    }

    #[test]
    fn debug_does_not_leak() {
        let (v, _, _) = sample();
        let d = format!("{v:?}");
        assert!(!d.contains("Alpha") && !d.contains("pa\""), "{d}");
    }

    #[test]
    fn container_parsing_errors() {
        let (_, _, f) = sample();
        let good = f.to_bytes().unwrap();

        assert_eq!(
            VaultFile::from_bytes(b"nope").unwrap_err(),
            Error::NotAVault
        );
        assert_eq!(VaultFile::from_bytes(b"").unwrap_err(), Error::NotAVault);
        assert_eq!(
            VaultFile::from_bytes(b"KWVT\0").unwrap_err(),
            Error::Malformed
        );

        let mut v2 = good.clone();
        v2[5] = 2;
        assert_eq!(
            VaultFile::from_bytes(&v2).unwrap_err(),
            Error::UnsupportedVersion(2)
        );

        let mut trailing = good.clone();
        trailing.push(b' ');
        assert_eq!(
            VaultFile::from_bytes(&trailing).unwrap_err(),
            Error::Malformed
        );

        let truncated = &good[..good.len() - 1];
        assert_eq!(
            VaultFile::from_bytes(truncated).unwrap_err(),
            Error::Malformed
        );

        let mut extra_field = good[PREFIX_LEN..].to_vec();
        extra_field.pop(); // drop closing brace
        extra_field.extend_from_slice(br#","x":1}"#);
        let mut bytes = good[..6].to_vec();
        bytes.extend_from_slice(&(extra_field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&extra_field);
        assert_eq!(VaultFile::from_bytes(&bytes).unwrap_err(), Error::Malformed);
    }

    fn snapshot(v: &UnlockedVault) -> Vec<(ItemId, u64, String)> {
        v.list()
            .iter()
            .map(|i| (i.id, i.version, password_of(v, i.id)))
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Flip one bit anywhere in the serialized file: it must either be
        /// rejected, or (e.g. a UUID hex digit changing case) open to
        /// exactly the same contents. It must never open to different data.
        #[test]
        fn prop_bit_flip_never_yields_different_contents(
            pos in any::<prop::sample::Index>(), bit in 0u8..8
        ) {
            let (v, _, f) = sample();
            let mut bytes = f.to_bytes().unwrap();
            let i = pos.index(bytes.len());
            bytes[i] ^= 1 << bit;
            if let Ok(g) = VaultFile::from_bytes(&bytes)
                && let Ok(u) = g.unlock(&pw("master"))
            {
                prop_assert_eq!(snapshot(&u), snapshot(&v));
            }
        }
    }
}
