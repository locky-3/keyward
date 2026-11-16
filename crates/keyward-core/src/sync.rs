//! Client side of the sync protocol: login credential, wire types (DTOs)
//! and the merge logic. Pure functions only; HTTP lives in the CLI.
//!
//! # Protocol summary
//!
//! * The server never sees the master password, master key, vault key or
//!   any plaintext. It stores the vault header, the wrapped vault key and
//!   item blobs exactly as the client produced them.
//! * Login credential: `SHA-256("keyward/v1/login-hash" ‖ AuthKey)` where
//!   `AuthKey = HKDF(MasterKey, "keyward/v1/auth")`. The server stores an
//!   Argon2id hash of it, so a database leak does not let anyone log in.
//! * Every item carries a version. A push names the version it is based
//!   on; the server accepts it only if that is still current
//!   (compare-and-swap), otherwise answers 409 with its copy. The client
//!   resolves conflicts last-write-wins on the encrypted `updated` time.
//! * The client remembers the highest version it has seen per item and
//!   rejects older ones, so the server cannot roll single items back.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::{self, Sealed, aad};
use crate::error::{Error, Result};
use crate::item::{Item, ItemId};
use crate::keys::AuthKey;
use crate::vault::{Header, KdfHeader, UnlockedVault};

const LOGIN_HASH_LABEL: &[u8] = b"keyward/v1/login-hash";

/// The value a client sends to authenticate. Derived from the master key
/// but useless for decrypting anything.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LoginHash(#[serde(with = "crate::encoding::b64_array")] [u8; 32]);

impl LoginHash {
    /// `SHA-256(label ‖ AuthKey)`.
    pub fn from_auth_key(key: &AuthKey) -> Self {
        let mut h = Sha256::new();
        h.update(LOGIN_HASH_LABEL);
        h.update(key.expose_secret());
        Self(h.finalize().into())
    }

    /// Raw bytes (the server feeds these to Argon2id).
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LoginHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginHash([REDACTED])")
    }
}

/// Derive the login hash from a password and the server-provided KDF
/// header (used by `prelogin` on a new device).
pub fn login_hash_for(password: &secrecy::SecretString, kdf: &KdfHeader) -> Result<LoginHash> {
    let mk = crate::kdf::derive_master_key(password, &kdf.salt, &kdf.params)?;
    Ok(LoginHash::from_auth_key(&mk.auth_key()))
}

/// Sync bookkeeping, stored inside the encrypted vault index.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncState {
    /// Base URL of the sync server.
    pub server: String,
    /// Account name on the server.
    pub username: String,
    /// Highest server change sequence number already pulled.
    pub cursor: u64,
    /// Last server version seen for each item (the base for the next push).
    #[serde(default)]
    pub synced: BTreeMap<ItemId, u64>,
    /// Items deleted locally that still need a tombstone on the server,
    /// with the server version the deletion is based on.
    #[serde(default)]
    pub pending_deletes: BTreeMap<ItemId, u64>,
}

impl SyncState {
    /// New state for a freshly connected vault.
    pub fn new(server: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            username: username.into(),
            ..Self::default()
        }
    }
}

/// Wire types shared by the client and the server.
pub mod api {
    use super::*;

    /// `POST /api/v1/accounts/prelogin`
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PreloginRequest {
        pub username: String,
    }

    /// KDF settings needed to derive the login hash on a new device.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PreloginResponse {
        pub kdf: KdfHeader,
    }

    /// Public vault material held by the server.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RemoteVault {
        pub header: Header,
        pub wrapped_vault_key: Sealed,
    }

    /// `POST /api/v1/accounts`
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RegisterRequest {
        pub username: String,
        pub login_hash: LoginHash,
        pub vault: RemoteVault,
    }

    /// `POST /api/v1/sessions`
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LoginRequest {
        pub username: String,
        pub login_hash: LoginHash,
    }

    /// Bearer token for subsequent requests.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LoginResponse {
        pub token: String,
        /// Unix seconds.
        pub expires_at: i64,
    }

    impl fmt::Debug for LoginResponse {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("LoginResponse")
                .field("expires_at", &self.expires_at)
                .finish_non_exhaustive()
        }
    }

    /// `PUT /api/v1/account/password` — re-authenticates with the current
    /// login hash and replaces credential, KDF header and wrapped key.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ChangePasswordRequest {
        pub current_login_hash: LoginHash,
        pub new_login_hash: LoginHash,
        pub vault: RemoteVault,
    }

    /// One item state on the server (a tombstone has `deleted` and no blob).
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ItemChange {
        pub id: ItemId,
        pub version: u64,
        pub deleted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub blob: Option<Sealed>,
        /// Server change sequence number.
        pub seq: u64,
    }

    /// `GET /api/v1/items?since=N`
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PullResponse {
        pub changes: Vec<ItemChange>,
        /// Pass as `since` next time.
        pub cursor: u64,
        /// More changes are available after `cursor`.
        pub has_more: bool,
    }

    /// `PUT /api/v1/items/{id}`
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PushRequest {
        /// Server version this change is based on (0 for a new item).
        pub base_version: u64,
        /// New version; must be greater than `base_version`.
        pub version: u64,
        pub blob: Sealed,
    }

    /// Successful push or delete.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct WriteResponse {
        pub version: u64,
        pub seq: u64,
    }

    /// `DELETE /api/v1/items/{id}`
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DeleteRequest {
        pub base_version: u64,
    }

    /// Error body; `current` is set on 409 Conflict.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ErrorResponse {
        pub error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<ItemChange>,
    }
}

use api::{ItemChange, PushRequest, RemoteVault};

/// What [`UnlockedVault::apply_remote`] did with a server change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Already up to date.
    Unchanged,
    /// A new item arrived.
    Inserted,
    /// The local copy was replaced by the server's.
    Updated,
    /// The item was deleted locally because it was deleted on the server.
    Deleted,
    /// Both sides changed; the local version won and will be pushed.
    KeptLocal,
    /// Both sides changed; the server version won (last write wins).
    ReplacedLocal,
}

impl UnlockedVault {
    /// Sync state, if this vault is connected to a server.
    pub fn sync_state(&self) -> Option<&SyncState> {
        self.sync.as_ref()
    }

    /// Connect (or with `None` disconnect) this vault to a sync server.
    pub fn set_sync_state(&mut self, state: Option<SyncState>) {
        self.sync = state;
    }

    /// Header and wrapped key as the server should store them.
    pub fn remote_vault(&self) -> RemoteVault {
        RemoteVault {
            header: self.header,
            wrapped_vault_key: self.wrapped_vault_key.clone(),
        }
    }

    /// Decrypt and authenticate an item received from the server.
    fn decrypt_remote(&self, id: ItemId, version: u64, blob: &Sealed) -> Result<Item> {
        let pt = aead::open(
            self.vault_key.bytes(),
            blob,
            &aad::item(&self.header.vault_id, &id, version),
        )
        .map_err(|_| Error::RemoteIntegrity)?;
        let item: Item = serde_json::from_slice(&pt).map_err(|_| Error::RemoteIntegrity)?;
        if item.id != id || item.version != version {
            return Err(Error::RemoteIntegrity);
        }
        Ok(item)
    }

    fn install_remote(&mut self, item: Item, blob: &Sealed) {
        let enc = crate::vault::EncryptedItem {
            id: item.id,
            version: item.version,
            blob: blob.clone(),
        };
        self.sealed.insert(item.id, enc);
        self.items.insert(item.id, item);
    }

    /// Merge one change pulled from the server into the vault.
    pub fn apply_remote(&mut self, change: &ItemChange) -> Result<MergeOutcome> {
        let id = change.id;
        let sync = self.sync.as_ref().ok_or(Error::SyncNotConfigured)?;
        let known = sync.synced.get(&id).copied();
        if known.is_some_and(|k| change.version < k) {
            return Err(Error::RemoteRollback);
        }
        let pending_delete = sync.pending_deletes.get(&id).copied();
        if let Some(base) = pending_delete {
            if change.deleted {
                // Already deleted on the server too; nothing left to send.
                self.sync
                    .as_mut()
                    .expect("checked above")
                    .pending_deletes
                    .remove(&id);
                return Ok(MergeOutcome::Unchanged);
            }
            if change.version <= base {
                // The state our local deletion was based on; keep it deleted.
                return Ok(MergeOutcome::Unchanged);
            }
        }
        let local_version = self.items.get(&id).map(|i| i.version);
        // Modified locally = present and not identical to the last synced version.
        let locally_modified = local_version.is_some() && local_version != known;

        if change.deleted {
            let sync = self.sync.as_mut().expect("checked above");
            return Ok(match local_version {
                None => {
                    sync.synced.remove(&id);
                    sync.pending_deletes.remove(&id);
                    MergeOutcome::Unchanged
                }
                Some(_) if !locally_modified => {
                    sync.synced.remove(&id);
                    self.items.remove(&id);
                    self.sealed.remove(&id);
                    MergeOutcome::Deleted
                }
                Some(_) => {
                    // Local edits beat a remote delete: nothing is lost.
                    // The tombstone's version becomes the push base.
                    sync.synced.insert(id, change.version);
                    self.keep_local_above(id, change.version)?;
                    MergeOutcome::KeptLocal
                }
            });
        }

        if known == Some(change.version) && !locally_modified && local_version.is_some() {
            return Ok(MergeOutcome::Unchanged);
        }
        let blob = change.blob.as_ref().ok_or(Error::RemoteIntegrity)?;
        let remote = self.decrypt_remote(id, change.version, blob)?;

        let outcome = match self.items.get(&id) {
            None => {
                // Remote edit beats a local delete (nothing is lost).
                self.install_remote(remote, blob);
                MergeOutcome::Inserted
            }
            Some(_) if !locally_modified => {
                self.install_remote(remote, blob);
                MergeOutcome::Updated
            }
            Some(local) => {
                if remote.updated > local.updated {
                    self.install_remote(remote, blob);
                    MergeOutcome::ReplacedLocal
                } else {
                    self.keep_local_above(id, change.version)?;
                    MergeOutcome::KeptLocal
                }
            }
        };
        let sync = self.sync.as_mut().expect("checked above");
        if pending_delete.is_some() && outcome == MergeOutcome::Inserted {
            sync.pending_deletes.remove(&id);
        }
        sync.synced.insert(id, change.version);
        Ok(outcome)
    }

    /// After a conflict resolved in favour of the local copy, make sure its
    /// version is above the server's so it counts as pending and the push
    /// passes the server's version check.
    fn keep_local_above(&mut self, id: ItemId, server_version: u64) -> Result<()> {
        let item = self.items.get_mut(&id).ok_or(Error::ItemNotFound)?;
        if item.version <= server_version {
            item.version = server_version.checked_add(1).ok_or(Error::Crypto)?;
        }
        Ok(())
    }

    /// Items that are new or changed since they were last synced.
    pub fn pending_pushes(&self) -> Vec<ItemId> {
        let Some(sync) = &self.sync else {
            return Vec::new();
        };
        self.items
            .values()
            .filter(|i| sync.synced.get(&i.id) != Some(&i.version))
            .map(|i| i.id)
            .collect()
    }

    /// Build the push request for an item. If the item's version is not
    /// above the server's (e.g. after keeping a local edit in a conflict),
    /// it is bumped so the server's version check accepts it.
    pub fn prepare_push(&mut self, id: ItemId) -> Result<PushRequest> {
        let base = self
            .sync
            .as_ref()
            .ok_or(Error::SyncNotConfigured)?
            .synced
            .get(&id)
            .copied()
            .unwrap_or(0);
        let item = self.items.get_mut(&id).ok_or(Error::ItemNotFound)?;
        if item.version <= base {
            item.version = base.checked_add(1).ok_or(Error::Crypto)?;
        }
        let version = item.version;
        let enc = match self.sealed.get(&id) {
            Some(e) if e.version == version => e.clone(),
            _ => {
                let item = self.items.get(&id).ok_or(Error::ItemNotFound)?;
                let e = self.encrypt_item(item)?;
                self.sealed.insert(id, e.clone());
                e
            }
        };
        Ok(PushRequest {
            base_version: base,
            version,
            blob: enc.blob,
        })
    }

    /// Record that the server accepted `version` of `id`.
    pub fn mark_pushed(&mut self, id: ItemId, version: u64) -> Result<()> {
        let sync = self.sync.as_mut().ok_or(Error::SyncNotConfigured)?;
        sync.synced.insert(id, version);
        Ok(())
    }

    /// Tombstones still to be sent: `(id, base_version)`.
    pub fn pending_deletes(&self) -> Vec<(ItemId, u64)> {
        self.sync
            .as_ref()
            .map(|s| s.pending_deletes.iter().map(|(k, v)| (*k, *v)).collect())
            .unwrap_or_default()
    }

    /// The server processed (or no longer needs) the deletion of `id`.
    pub fn mark_delete_done(&mut self, id: ItemId) -> Result<()> {
        let sync = self.sync.as_mut().ok_or(Error::SyncNotConfigured)?;
        sync.pending_deletes.remove(&id);
        Ok(())
    }

    /// Advance the pull cursor.
    pub fn set_sync_cursor(&mut self, cursor: u64) -> Result<()> {
        let sync = self.sync.as_mut().ok_or(Error::SyncNotConfigured)?;
        sync.cursor = sync.cursor.max(cursor);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::api::*;
    use super::*;
    use crate::item::{ItemKind, Login};
    use crate::kdf::KdfParams;
    use secrecy::{ExposeSecret, SecretString};

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn login(title: &str, pass: &str) -> ItemKind {
        ItemKind::Login(Login::new(title, "u", pw(pass)))
    }

    /// In-memory stand-in for the server: latest state per item + seq log.
    #[derive(Default)]
    struct FakeServer {
        items: BTreeMap<ItemId, ItemChange>,
        seq: u64,
    }

    impl FakeServer {
        fn push(&mut self, id: ItemId, req: PushRequest) -> std::result::Result<u64, ItemChange> {
            let cur = self.items.get(&id).map_or(0, |c| c.version);
            if req.base_version != cur || req.version <= cur {
                return Err(self.items[&id].clone());
            }
            self.seq += 1;
            self.items.insert(
                id,
                ItemChange {
                    id,
                    version: req.version,
                    deleted: false,
                    blob: Some(req.blob),
                    seq: self.seq,
                },
            );
            Ok(req.version)
        }

        fn delete(&mut self, id: ItemId, base: u64) -> std::result::Result<(), ItemChange> {
            let cur = self.items[&id].clone();
            if cur.version != base {
                return Err(cur);
            }
            self.seq += 1;
            self.items.insert(
                id,
                ItemChange {
                    id,
                    version: base + 1,
                    deleted: true,
                    blob: None,
                    seq: self.seq,
                },
            );
            Ok(())
        }

        fn pull(&self, since: u64) -> Vec<ItemChange> {
            let mut v: Vec<_> = self
                .items
                .values()
                .filter(|c| c.seq > since)
                .cloned()
                .collect();
            v.sort_by_key(|c| c.seq);
            v
        }

        /// Full client sync round: pull, push, delete.
        fn sync(&mut self, v: &mut UnlockedVault) -> Vec<MergeOutcome> {
            let mut out = Vec::new();
            let since = v.sync_state().unwrap().cursor;
            for c in self.pull(since) {
                out.push(v.apply_remote(&c).unwrap());
                v.set_sync_cursor(c.seq).unwrap();
            }
            for id in v.pending_pushes() {
                let req = v.prepare_push(id).unwrap();
                let ver = self.push(id, req).expect("no conflict right after pull");
                v.mark_pushed(id, ver).unwrap();
            }
            for (id, base) in v.pending_deletes() {
                self.delete(id, base).expect("no conflict right after pull");
                v.mark_delete_done(id).unwrap();
            }
            out
        }
    }

    /// Two devices sharing one vault key, both connected.
    fn two_devices() -> (UnlockedVault, UnlockedVault, FakeServer) {
        let mut a = UnlockedVault::create(&pw("m"), KdfParams::INSECURE_TEST).unwrap();
        a.set_sync_state(Some(SyncState::new("https://s", "u")));
        let remote = a.remote_vault();
        let (mut b, hash_b) =
            UnlockedVault::from_remote(remote.header, remote.wrapped_vault_key, &pw("m")).unwrap();
        b.set_sync_state(Some(SyncState::new("https://s", "u")));
        let (_, hash_a) =
            UnlockedVault::from_remote(a.header, a.wrapped_vault_key.clone(), &pw("m")).unwrap();
        assert_eq!(hash_a, hash_b, "same password, same login hash");
        (a, b, FakeServer::default())
    }

    fn password_of(v: &UnlockedVault, id: ItemId) -> String {
        let l = v.get(id).unwrap().kind.as_login().unwrap();
        l.password.expose_secret().to_owned()
    }

    #[test]
    fn login_hash_depends_on_password_and_is_redacted() {
        let mut v = UnlockedVault::create(&pw("one"), KdfParams::INSECURE_TEST).unwrap();
        let kdf = v.header.kdf;
        let a = login_hash_for(&pw("one"), &kdf).unwrap();
        let b = login_hash_for(&pw("two"), &kdf).unwrap();
        assert_ne!(a, b);
        assert_eq!(format!("{a:?}"), "LoginHash([REDACTED])");
        // the hash returned by unlock and by change_master_password agree
        let file = v.seal().unwrap();
        let (_, from_unlock) = file.unlock_with_login_hash(&pw("one")).unwrap();
        assert_eq!(from_unlock, a);
        let new = v
            .change_master_password(&pw("two"), KdfParams::INSECURE_TEST)
            .unwrap();
        assert_eq!(new, login_hash_for(&pw("two"), &v.header.kdf).unwrap());
    }

    #[test]
    fn from_remote_rejects_wrong_password() {
        let v = UnlockedVault::create(&pw("m"), KdfParams::INSECURE_TEST).unwrap();
        let r = v.remote_vault();
        assert_eq!(
            UnlockedVault::from_remote(r.header, r.wrapped_vault_key, &pw("x")).unwrap_err(),
            Error::UnlockFailed
        );
    }

    #[test]
    fn items_propagate_between_devices() {
        let (mut a, mut b, mut s) = two_devices();
        let id = a.add(login("Shared", "p1"));
        s.sync(&mut a);
        assert_eq!(s.sync(&mut b), [MergeOutcome::Inserted]);
        assert_eq!(password_of(&b, id), "p1");

        b.update(id, |k| k.as_login_mut().unwrap().password = pw("p2"))
            .unwrap();
        s.sync(&mut b);
        // a sees its own earlier push (unchanged) and b's edit
        let out = s.sync(&mut a);
        assert!(out.contains(&MergeOutcome::Updated), "{out:?}");
        assert_eq!(password_of(&a, id), "p2");
        assert!(a.pending_pushes().is_empty());
        assert!(s.sync(&mut a).is_empty(), "nothing new");
    }

    #[test]
    fn deletion_propagates_as_tombstone() {
        let (mut a, mut b, mut s) = two_devices();
        let id = a.add(login("Gone", "p"));
        s.sync(&mut a);
        s.sync(&mut b);
        a.remove(id).unwrap();
        assert_eq!(a.pending_deletes().len(), 1);
        s.sync(&mut a);
        assert!(a.pending_deletes().is_empty());
        assert!(s.items[&id].deleted);
        assert_eq!(s.sync(&mut b), [MergeOutcome::Deleted]);
        assert!(b.get(id).is_none());
    }

    #[test]
    fn concurrent_edits_last_writer_wins() {
        let (mut a, mut b, mut s) = two_devices();
        let id = a.add(login("X", "base"));
        s.sync(&mut a);
        s.sync(&mut b);

        a.update(id, |k| k.as_login_mut().unwrap().password = pw("from-a"))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        b.update(id, |k| k.as_login_mut().unwrap().password = pw("from-b"))
            .unwrap();

        s.sync(&mut a); // a pushes first
        let out = s.sync(&mut b); // b conflicts, b's edit is newer -> kept & pushed
        assert_eq!(out, [MergeOutcome::KeptLocal]);
        s.sync(&mut a);
        assert_eq!(password_of(&a, id), "from-b");
        assert_eq!(password_of(&b, id), "from-b");
        assert!(s.items[&id].version > 2);
    }

    #[test]
    fn older_local_edit_loses_to_newer_remote() {
        let (mut a, mut b, mut s) = two_devices();
        let id = a.add(login("X", "base"));
        s.sync(&mut a);
        s.sync(&mut b);
        b.update(id, |k| k.as_login_mut().unwrap().password = pw("older-b"))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        a.update(id, |k| k.as_login_mut().unwrap().password = pw("newer-a"))
            .unwrap();
        s.sync(&mut a);
        assert_eq!(s.sync(&mut b), [MergeOutcome::ReplacedLocal]);
        assert_eq!(password_of(&b, id), "newer-a");
        assert!(b.pending_pushes().is_empty());
    }

    #[test]
    fn local_edit_survives_remote_delete() {
        let (mut a, mut b, mut s) = two_devices();
        let id = a.add(login("X", "p"));
        s.sync(&mut a);
        s.sync(&mut b);
        a.remove(id).unwrap();
        s.sync(&mut a);
        b.update(id, |k| k.as_login_mut().unwrap().password = pw("edited"))
            .unwrap();
        assert_eq!(s.sync(&mut b), [MergeOutcome::KeptLocal]);
        assert!(!s.items[&id].deleted, "b resurrected it on the server");
        s.sync(&mut a);
        assert_eq!(password_of(&a, id), "edited");
    }

    #[test]
    fn rollback_and_forgery_are_rejected() {
        let (mut a, mut b, mut s) = two_devices();
        let id = a.add(login("X", "p1"));
        s.sync(&mut a);
        let old = s.items[&id].clone();
        a.update(id, |k| k.as_login_mut().unwrap().password = pw("p2"))
            .unwrap();
        s.sync(&mut a);
        s.sync(&mut b);

        // server replays the old version
        let mut replay = old.clone();
        replay.seq = 99;
        assert_eq!(b.apply_remote(&replay), Err(Error::RemoteRollback));

        // server relabels the old blob with a newer version number
        let mut relabelled = old.clone();
        relabelled.version = 10;
        assert_eq!(b.apply_remote(&relabelled), Err(Error::RemoteIntegrity));

        // server moves a blob to another id
        let mut moved = s.items[&id].clone();
        moved.id = ItemId::random();
        assert_eq!(b.apply_remote(&moved), Err(Error::RemoteIntegrity));

        // a non-deleted change without a blob
        let mut empty = s.items[&id].clone();
        empty.version = 50;
        empty.blob = None;
        assert_eq!(b.apply_remote(&empty), Err(Error::RemoteIntegrity));
    }

    #[test]
    fn sync_state_persists_through_seal_and_unlock() {
        let (mut a, _, mut s) = two_devices();
        let id = a.add(login("X", "p"));
        s.sync(&mut a);
        let file = a.seal().unwrap();
        let reopened = file.unlock(&pw("m")).unwrap();
        let st = reopened.sync_state().unwrap();
        assert_eq!(st.synced.get(&id), Some(&1));
        assert_eq!(st.server, "https://s");
        // and the server URL is not visible in the file
        let bytes = file.to_bytes().unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("https://s"));
    }

    #[test]
    fn sync_requires_configuration() {
        let mut v = UnlockedVault::create(&pw("m"), KdfParams::INSECURE_TEST).unwrap();
        let id = v.add(login("x", "y"));
        assert!(v.pending_pushes().is_empty());
        assert_eq!(v.prepare_push(id).unwrap_err(), Error::SyncNotConfigured);
        // removing an unsynced item records no tombstone
        v.set_sync_state(Some(SyncState::new("s", "u")));
        v.remove(id).unwrap();
        assert!(v.pending_deletes().is_empty());
    }

    #[derive(Clone, Debug)]
    enum Op {
        Add(bool),
        Edit(bool, prop::sample::Index),
        Remove(bool, prop::sample::Index),
        Sync(bool),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            any::<bool>().prop_map(Op::Add),
            (any::<bool>(), any::<prop::sample::Index>()).prop_map(|(d, i)| Op::Edit(d, i)),
            (any::<bool>(), any::<prop::sample::Index>()).prop_map(|(d, i)| Op::Remove(d, i)),
            any::<bool>().prop_map(Op::Sync),
        ]
    }

    fn snapshot(v: &UnlockedVault) -> Vec<(ItemId, String)> {
        v.list()
            .iter()
            .map(|i| (i.id, password_of(v, i.id)))
            .collect()
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Whatever both devices do offline, after syncing in turn they
        /// converge to the same contents and nothing stays pending.
        #[test]
        fn prop_two_devices_converge(ops in proptest::collection::vec(op(), 1..40)) {
            let (mut a, mut b, mut s) = two_devices();
            for (n, o) in ops.into_iter().enumerate() {
                match o {
                    Op::Add(dev) => {
                        let v = if dev { &mut a } else { &mut b };
                        v.add(login(&format!("i{n}"), &format!("p{n}")));
                    }
                    Op::Edit(dev, idx) => {
                        let v = if dev { &mut a } else { &mut b };
                        let ids: Vec<_> = v.ids().into_iter().collect();
                        if !ids.is_empty() {
                            let id = ids[idx.index(ids.len())];
                            v.update(id, |k| k.as_login_mut().unwrap().password = pw(&format!("e{n}"))).unwrap();
                        }
                    }
                    Op::Remove(dev, idx) => {
                        let v = if dev { &mut a } else { &mut b };
                        let ids: Vec<_> = v.ids().into_iter().collect();
                        if !ids.is_empty() {
                            v.remove(ids[idx.index(ids.len())]).unwrap();
                        }
                    }
                    Op::Sync(dev) => {
                        s.sync(if dev { &mut a } else { &mut b });
                    }
                }
            }
            s.sync(&mut a);
            s.sync(&mut b);
            s.sync(&mut a);
            prop_assert_eq!(snapshot(&a), snapshot(&b));
            prop_assert!(a.pending_pushes().is_empty() && b.pending_pushes().is_empty());
            prop_assert!(a.pending_deletes().is_empty() && b.pending_deletes().is_empty());
        }
    }

    #[test]
    fn dto_json_shapes() {
        let v = UnlockedVault::create(&pw("m"), KdfParams::INSECURE_TEST).unwrap();
        let reg = RegisterRequest {
            username: "alice".into(),
            login_hash: login_hash_for(&pw("m"), &v.header.kdf).unwrap(),
            vault: v.remote_vault(),
        };
        let j = serde_json::to_string(&reg).unwrap();
        let back: RegisterRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back.vault, reg.vault);
        assert!(serde_json::from_str::<LoginRequest>(r#"{"username":"a"}"#).is_err());
    }
}
