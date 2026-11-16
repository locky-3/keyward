//! Thin wrapper over AES-256-GCM plus the associated-data (AAD) layouts.
//!
//! Every call to [`seal`] draws a fresh 96-bit nonce from the OS CSPRNG.
//! With random nonces the safe limit is about 2^32 encryptions per key;
//! a vault re-encrypts only changed items, so it stays far below that.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::KEY_LEN;

/// AES-GCM nonce length (96 bits).
pub const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/// A nonce together with ciphertext‖tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    #[serde(with = "crate::encoding::b64_array")]
    pub(crate) nonce: [u8; NONCE_LEN],
    #[serde(with = "crate::encoding::b64")]
    pub(crate) ct: Vec<u8>,
}

impl Sealed {
    /// Rebuild from stored parts (e.g. database columns on the sync server).
    pub fn from_parts(nonce: [u8; NONCE_LEN], ct: Vec<u8>) -> Self {
        Self { nonce, ct }
    }

    /// The 96-bit nonce.
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Ciphertext followed by the 16-byte tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ct
    }

    /// Bytes covered by the index digest: `nonce ‖ ciphertext‖tag`.
    pub(crate) fn digest_input(&self) -> impl Iterator<Item = &[u8]> {
        [self.nonce.as_slice(), self.ct.as_slice()].into_iter()
    }
}

/// Encrypt `plaintext` under `key`, binding `aad`.
pub(crate) fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    Ok(Sealed { nonce, ct })
}

/// Decrypt and authenticate. Any failure (wrong key, modified nonce,
/// ciphertext, tag or AAD) gives the same opaque [`Error::Crypto`].
pub(crate) fn open(key: &[u8; KEY_LEN], sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.ct.len() < TAG_LEN {
        return Err(Error::Crypto);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

/// Associated-data layouts. Each starts with a distinct domain label and
/// every other field is fixed-length, so two different contexts can never
/// produce the same AAD bytes.
pub(crate) mod aad {
    use crate::item::ItemId;
    use crate::kdf::{KdfParams, Salt};
    use crate::vault::VaultId;

    /// `"kw-wrap-v1" ‖ format_version u16 ‖ vault_id 16 ‖ salt 16 ‖ m u32 ‖ t u32 ‖ p u32`
    pub(crate) fn wrap(
        format_version: u16,
        vault_id: &VaultId,
        salt: &Salt,
        kdf: &KdfParams,
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(10 + 2 + 16 + 16 + 12);
        v.extend_from_slice(b"kw-wrap-v1");
        v.extend_from_slice(&format_version.to_be_bytes());
        v.extend_from_slice(vault_id.as_bytes());
        v.extend_from_slice(salt.as_bytes());
        v.extend_from_slice(&kdf.m_cost_kib.to_be_bytes());
        v.extend_from_slice(&kdf.t_cost.to_be_bytes());
        v.extend_from_slice(&kdf.p_cost.to_be_bytes());
        v
    }

    /// `"kw-index-v1" ‖ vault_id 16 ‖ revision u64`
    pub(crate) fn index(vault_id: &VaultId, revision: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(11 + 16 + 8);
        v.extend_from_slice(b"kw-index-v1");
        v.extend_from_slice(vault_id.as_bytes());
        v.extend_from_slice(&revision.to_be_bytes());
        v
    }

    /// `"kw-item-v1" ‖ vault_id 16 ‖ item_id 16 ‖ version u64`
    pub(crate) fn item(vault_id: &VaultId, item_id: &ItemId, version: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(10 + 16 + 16 + 8);
        v.extend_from_slice(b"kw-item-v1");
        v.extend_from_slice(vault_id.as_bytes());
        v.extend_from_slice(item_id.as_bytes());
        v.extend_from_slice(&version.to_be_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const K1: [u8; 32] = [1; 32];
    const K2: [u8; 32] = [2; 32];

    #[test]
    fn round_trip_and_ciphertext_shape() {
        let s = seal(&K1, b"hello", b"ctx").unwrap();
        assert_eq!(s.ct.len(), 5 + TAG_LEN);
        assert_eq!(open(&K1, &s, b"ctx").unwrap().as_slice(), b"hello");
    }

    #[test]
    fn nonces_are_fresh() {
        let a = seal(&K1, b"same", b"").unwrap();
        let b = seal(&K1, b"same", b"").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn wrong_key_or_aad_fails() {
        let s = seal(&K1, b"secret", b"ctx").unwrap();
        assert_eq!(open(&K2, &s, b"ctx"), Err(Error::Crypto));
        assert_eq!(open(&K1, &s, b"ctX"), Err(Error::Crypto));
    }

    #[test]
    fn truncated_ciphertext_fails_cleanly() {
        let mut s = seal(&K1, b"x", b"").unwrap();
        s.ct.truncate(3);
        assert_eq!(open(&K1, &s, b""), Err(Error::Crypto));
    }

    #[test]
    fn aad_layouts_have_fixed_lengths_and_distinct_labels() {
        use crate::item::ItemId;
        use crate::kdf::{KdfParams, Salt};
        use crate::vault::VaultId;
        let vid = VaultId::random();
        let iid = ItemId::random();
        let w = aad::wrap(1, &vid, &Salt::random(), &KdfParams::DEFAULT);
        let i = aad::index(&vid, 7);
        let it = aad::item(&vid, &iid, 7);
        assert_eq!(w.len(), 10 + 2 + 16 + 16 + 12);
        assert_eq!(i.len(), 11 + 16 + 8);
        assert_eq!(it.len(), 10 + 16 + 16 + 8);
        assert!(w.starts_with(b"kw-wrap-v1"));
        assert!(i.starts_with(b"kw-index-v1"));
        assert!(it.starts_with(b"kw-item-v1"));
        assert_ne!(aad::item(&vid, &iid, 1), aad::item(&vid, &iid, 2));
    }

    proptest! {
        #[test]
        fn prop_round_trip(pt in proptest::collection::vec(any::<u8>(), 0..2048),
                           ad in proptest::collection::vec(any::<u8>(), 0..64),
                           key in any::<[u8; 32]>()) {
            let s = seal(&key, &pt, &ad).unwrap();
            let back = open(&key, &s, &ad).unwrap();
            prop_assert_eq!(back.as_slice(), pt.as_slice());
        }

        /// Flipping any single bit of nonce, ciphertext/tag or AAD must fail.
        #[test]
        fn prop_tamper_fails(pt in proptest::collection::vec(any::<u8>(), 0..256),
                             ad in proptest::collection::vec(any::<u8>(), 1..32),
                             target in 0usize..3,
                             pos in any::<prop::sample::Index>(),
                             bit in 0u8..8) {
            let mut s = seal(&K1, &pt, &ad).unwrap();
            let mut ad = ad;
            let buf: &mut [u8] = match target {
                0 => s.nonce.as_mut_slice(),
                1 => s.ct.as_mut_slice(),
                _ => ad.as_mut_slice(),
            };
            let i = pos.index(buf.len());
            buf[i] ^= 1 << bit;
            prop_assert_eq!(open(&K1, &s, &ad), Err(Error::Crypto));
        }
    }
}
