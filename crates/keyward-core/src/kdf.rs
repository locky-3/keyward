//! Master-password key derivation with Argon2id.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::keys::{KEY_LEN, MasterKey};

/// Length of the per-vault random salt.
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters. Stored in the vault header so they can be
/// raised later without changing the format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// Default for new vaults: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    /// Floor: OWASP's minimum Argon2id recommendation (19 MiB, t=2).
    /// Vaults below this are refused both on create and on open.
    pub const MIN_M_COST_KIB: u32 = 19 * 1024;
    /// Minimum number of passes.
    pub const MIN_T_COST: u32 = 2;
    /// Ceiling on memory (4 GiB) so a hostile file cannot exhaust RAM.
    pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
    /// Ceiling on passes so a hostile file cannot hang the client.
    pub const MAX_T_COST: u32 = 64;
    /// Ceiling on lanes.
    pub const MAX_P_COST: u32 = 16;

    /// Very cheap parameters, only available to this crate's unit tests.
    #[cfg(test)]
    pub(crate) const INSECURE_TEST: Self = Self {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    /// Check that the parameters are within the accepted range.
    pub fn validate(&self) -> Result<()> {
        #[cfg(test)]
        if *self == Self::INSECURE_TEST {
            return Ok(());
        }
        if self.m_cost_kib < Self::MIN_M_COST_KIB {
            return Err(Error::InvalidKdfParams("memory cost below 19 MiB"));
        }
        if self.m_cost_kib > Self::MAX_M_COST_KIB {
            return Err(Error::InvalidKdfParams("memory cost above 4 GiB"));
        }
        if self.t_cost < Self::MIN_T_COST {
            return Err(Error::InvalidKdfParams("fewer than 2 passes"));
        }
        if self.t_cost > Self::MAX_T_COST {
            return Err(Error::InvalidKdfParams("more than 64 passes"));
        }
        if self.p_cost == 0 || self.p_cost > Self::MAX_P_COST {
            return Err(Error::InvalidKdfParams("parallelism must be 1..=16"));
        }
        if self.m_cost_kib < 8 * self.p_cost {
            return Err(Error::InvalidKdfParams("memory too small for parallelism"));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Random per-vault salt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Salt(#[serde(with = "crate::encoding::b64_array")] [u8; SALT_LEN]);

impl Salt {
    /// Fresh salt from the OS CSPRNG.
    pub fn random() -> Self {
        let mut s = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut s);
        Self(s)
    }

    /// Wrap existing bytes (e.g. read from a file or a test vector).
    pub const fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw salt bytes.
    pub const fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

fn argon2id(params: &KdfParams) -> Result<Argon2<'static>> {
    let p = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::InvalidKdfParams("rejected by argon2"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
}

/// Derive the 32-byte master key from the master password with Argon2id.
///
/// The password is used as UTF-8 bytes exactly as typed (no normalisation).
pub fn derive_master_key(
    password: &SecretString,
    salt: &Salt,
    params: &KdfParams,
) -> Result<MasterKey> {
    params.validate()?;
    let argon = argon2id(params)?;
    let mut outcome = Ok(());
    // Derive straight into the heap-allocated, zeroize-on-drop buffer.
    let key = SecretBox::<[u8; KEY_LEN]>::init_with_mut(|out| {
        outcome = argon
            .hash_password_into(password.expose_secret().as_bytes(), salt.as_bytes(), out)
            .map_err(|_| Error::Crypto);
    });
    outcome?;
    Ok(MasterKey::from_secret(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    #[test]
    fn default_params_are_valid() {
        KdfParams::DEFAULT.validate().unwrap();
        assert_eq!(KdfParams::default(), KdfParams::DEFAULT);
    }

    #[test]
    fn floor_and_ceiling_are_enforced() {
        let ok = KdfParams {
            m_cost_kib: KdfParams::MIN_M_COST_KIB,
            t_cost: KdfParams::MIN_T_COST,
            p_cost: 1,
        };
        ok.validate().unwrap();

        let cases = [
            KdfParams {
                m_cost_kib: ok.m_cost_kib - 1,
                ..ok
            },
            KdfParams { t_cost: 1, ..ok },
            KdfParams { p_cost: 0, ..ok },
            KdfParams { p_cost: 17, ..ok },
            KdfParams {
                m_cost_kib: KdfParams::MAX_M_COST_KIB + 1,
                ..ok
            },
            KdfParams { t_cost: 65, ..ok },
        ];
        for c in cases {
            assert!(
                matches!(c.validate(), Err(Error::InvalidKdfParams(_))),
                "{c:?}"
            );
        }
    }

    #[test]
    fn derive_refuses_weak_params() {
        let weak = KdfParams {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let pw = SecretString::from("pw".to_owned());
        assert!(derive_master_key(&pw, &Salt::random(), &weak).is_err());
    }

    /// RFC 9106 §5.3 Argon2id test vector. Proves we wire up the right
    /// algorithm (id) and version (0x13). Uses a secret and associated data,
    /// which Keyward itself does not, so it builds the hasher directly.
    #[test]
    fn rfc9106_argon2id_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let secret = [0x03u8; 8];
        let argon =
            Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        argon
            .hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
            .unwrap();
        assert_eq!(
            HEXLOWER.encode(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn derivation_is_deterministic_and_salted() {
        let pw = SecretString::from("correct horse".to_owned());
        let p = KdfParams::INSECURE_TEST;
        let s1 = Salt::from_bytes([1; SALT_LEN]);
        let s2 = Salt::from_bytes([2; SALT_LEN]);
        let a = derive_master_key(&pw, &s1, &p).unwrap();
        let b = derive_master_key(&pw, &s1, &p).unwrap();
        let c = derive_master_key(&pw, &s2, &p).unwrap();
        assert_eq!(a.expose_for_test(), b.expose_for_test());
        assert_ne!(a.expose_for_test(), c.expose_for_test());
    }

    #[test]
    fn different_passwords_give_different_keys() {
        let s = Salt::from_bytes([7; SALT_LEN]);
        let p = KdfParams::INSECURE_TEST;
        let a = derive_master_key(&SecretString::from("a".to_owned()), &s, &p).unwrap();
        let b = derive_master_key(&SecretString::from("b".to_owned()), &s, &p).unwrap();
        assert_ne!(a.expose_for_test(), b.expose_for_test());
    }

    #[test]
    fn random_salts_differ() {
        assert_ne!(Salt::random(), Salt::random());
    }
}
