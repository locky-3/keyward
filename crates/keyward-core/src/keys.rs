//! Key hierarchy.
//!
//! ```text
//! master password --Argon2id--> MasterKey
//!     MasterKey --HKDF-SHA256("keyward/v1/wrap")--> WrapKey   (wraps the VaultKey)
//!     MasterKey --HKDF-SHA256("keyward/v1/auth")--> AuthKey   (sync-server login)
//! VaultKey: 32 random bytes, encrypts items and the index.
//! ```
//!
//! The master key itself never encrypts anything. Every key type zeroizes on
//! drop and prints `[REDACTED]` in `Debug`.

use std::fmt;

use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;

/// Length of every symmetric key in Keyward (AES-256).
pub const KEY_LEN: usize = 32;

const WRAP_INFO: &[u8] = b"keyward/v1/wrap";
const AUTH_INFO: &[u8] = b"keyward/v1/auth";

type KeyBytes = SecretBox<[u8; KEY_LEN]>;

macro_rules! redacted_debug {
    ($t:ident) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($t), "([REDACTED])"))
            }
        }
    };
}

/// Output of Argon2id over the master password. Only used as HKDF input.
pub struct MasterKey(KeyBytes);
/// Key-encryption key that wraps the [`VaultKey`].
pub struct WrapKey(KeyBytes);
/// Key from which the sync-server credential ([`crate::LoginHash`]) is derived.
pub struct AuthKey(KeyBytes);
/// Random data-encryption key for items and the index.
pub struct VaultKey(KeyBytes);

redacted_debug!(MasterKey);
redacted_debug!(WrapKey);
redacted_debug!(AuthKey);
redacted_debug!(VaultKey);

fn hkdf_expand(ikm: &[u8; KEY_LEN], info: &[u8]) -> KeyBytes {
    // No salt: the IKM is already a uniformly random Argon2id output (RFC 5869 §3.1).
    let hk = Hkdf::<Sha256>::new(None, ikm);
    SecretBox::init_with_mut(|okm: &mut [u8; KEY_LEN]| {
        hk.expand(info, okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
    })
}

impl MasterKey {
    pub(crate) fn from_secret(k: KeyBytes) -> Self {
        Self(k)
    }

    /// Derive the key that wraps the vault key.
    pub fn wrap_key(&self) -> WrapKey {
        WrapKey(hkdf_expand(self.0.expose_secret(), WRAP_INFO))
    }

    /// Derive the key used for server authentication. Independent of
    /// [`MasterKey::wrap_key`]: knowing one reveals nothing about the other.
    pub fn auth_key(&self) -> AuthKey {
        AuthKey(hkdf_expand(self.0.expose_secret(), AUTH_INFO))
    }

    #[cfg(test)]
    pub(crate) fn expose_for_test(&self) -> [u8; KEY_LEN] {
        *self.0.expose_secret()
    }
}

impl WrapKey {
    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

impl AuthKey {
    /// Raw key bytes. Hashed into a [`crate::LoginHash`] before leaving the client.
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

impl VaultKey {
    /// Fresh random vault key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self(SecretBox::init_with_mut(|k: &mut [u8; KEY_LEN]| {
            OsRng.fill_bytes(k)
        }))
    }

    /// Rebuild from unwrapped bytes; returns `None` on wrong length.
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: &[u8; KEY_LEN] = bytes.try_into().ok()?;
        Some(Self(SecretBox::init_with_mut(|k: &mut [u8; KEY_LEN]| {
            k.copy_from_slice(arr)
        })))
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(byte: u8) -> MasterKey {
        MasterKey::from_secret(SecretBox::new(Box::new([byte; KEY_LEN])))
    }

    #[test]
    fn subkeys_are_deterministic() {
        assert_eq!(mk(1).wrap_key().bytes(), mk(1).wrap_key().bytes());
        assert_eq!(
            mk(1).auth_key().expose_secret(),
            mk(1).auth_key().expose_secret()
        );
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let m = mk(1);
        assert_ne!(m.wrap_key().bytes(), m.auth_key().expose_secret());
        assert_ne!(m.wrap_key().bytes(), &m.expose_for_test());
        assert_ne!(m.auth_key().expose_secret(), &m.expose_for_test());
        assert_ne!(mk(1).wrap_key().bytes(), mk(2).wrap_key().bytes());
    }

    /// Known-answer test so an accidental change to the labels or HKDF
    /// wiring (which would lock users out) is caught.
    #[test]
    fn hkdf_known_answer() {
        let m = mk(0x0b);
        assert_eq!(
            data_encoding::HEXLOWER.encode(m.wrap_key().bytes()),
            WRAP_KAT
        );
    }
    // Computed independently with Python: hmac + hashlib (RFC 5869 by hand).
    const WRAP_KAT: &str = "17d6151c2ea93d32f6fcda352c0ef67017c974d2338feb451c97e3dfe08078ae";

    #[test]
    fn vault_keys_are_random() {
        assert_ne!(VaultKey::generate().bytes(), VaultKey::generate().bytes());
    }

    #[test]
    fn vault_key_from_slice_checks_length() {
        assert!(VaultKey::from_slice(&[0; 31]).is_none());
        assert!(VaultKey::from_slice(&[0; 33]).is_none());
        assert_eq!(VaultKey::from_slice(&[5; 32]).unwrap().bytes(), &[5; 32]);
    }

    #[test]
    fn debug_never_shows_key_material() {
        let m = mk(0xab);
        for s in [
            format!("{m:?}"),
            format!("{:?}", m.wrap_key()),
            format!("{:?}", m.auth_key()),
            format!("{:?}", VaultKey::from_slice(&[0xab; 32]).unwrap()),
        ] {
            assert!(s.contains("REDACTED"), "{s}");
            assert!(!s.to_lowercase().contains("ab, ab"), "{s}");
            assert!(!s.contains("171"), "{s}");
        }
    }
}
