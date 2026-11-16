//! Credential hashing, session tokens and the authenticated-request extractor.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::anyhow;
use argon2::password_hash::rand_core::OsRng as PhOsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use data_encoding::BASE64URL_NOPAD;
use keyward_core::LoginHash;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::error::ApiError;

fn hasher(m_cost_kib: u32, t_cost: u32) -> anyhow::Result<Argon2<'static>> {
    let p = Params::new(m_cost_kib, t_cost, 1, None).map_err(|e| anyhow!("argon2 params: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
}

/// Argon2id PHC string of a login hash (random 16-byte salt).
pub fn hash_login(login: &LoginHash, m_cost_kib: u32, t_cost: u32) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut PhOsRng);
    Ok(hasher(m_cost_kib, t_cost)?
        .hash_password(login.expose_secret(), &salt)
        .map_err(|e| anyhow!("argon2: {e}"))?
        .to_string())
}

/// Constant-time verification against a stored PHC string. The cost
/// parameters come from the PHC string itself.
pub fn verify_login(login: &LoginHash, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(login.expose_secret(), &parsed)
        .is_ok()
}

/// A fresh bearer token and the SHA-256 the database stores instead of it.
pub fn new_token() -> (String, [u8; 32]) {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = BASE64URL_NOPAD.encode(&raw);
    let hash = token_hash(&token);
    (token, hash)
}

pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// An authenticated request.
#[derive(Debug, Clone, Copy)]
pub struct AuthAccount {
    pub account_id: i64,
    pub token_hash: [u8; 32],
}

impl FromRequestParts<Arc<AppState>> for AuthAccount {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty() && t.len() <= 128)
            .ok_or(ApiError::Unauthenticated)?;
        let hash = token_hash(token);
        let now = state.now_secs();
        let account_id: Option<i64> = sqlx::query_scalar(
            "SELECT account_id FROM sessions WHERE token_hash = ? AND expires_at > ?",
        )
        .bind(hash.as_slice())
        .bind(now)
        .fetch_optional(&state.db)
        .await?;
        account_id
            .map(|account_id| Self {
                account_id,
                token_hash: hash,
            })
            .ok_or(ApiError::Unauthenticated)
    }
}

/// Client IP for rate limiting: the socket peer, or (only when
/// `trust_proxy` is set) the last `X-Forwarded-For` entry, which is the
/// address the reverse proxy itself saw.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<Arc<AppState>> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if state.config.trust_proxy
            && let Some(ip) = parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .next_back()
        {
            return Ok(Self(ip));
        }
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        Ok(Self(peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyward_core::{KdfParams, UnlockedVault};
    use secrecy_shim::pw;

    mod secrecy_shim {
        pub fn pw(s: &str) -> keyward_core::SecretString {
            keyward_core::SecretString::from(s.to_owned())
        }
    }

    fn login_hash(p: &str) -> LoginHash {
        let params = KdfParams {
            m_cost_kib: KdfParams::MIN_M_COST_KIB,
            t_cost: KdfParams::MIN_T_COST,
            p_cost: 1,
        };
        let v = UnlockedVault::create(&pw(p), params).unwrap();
        keyward_core::sync::login_hash_for(&pw(p), &v.header().kdf).unwrap()
    }

    #[test]
    fn hash_and_verify() {
        let h = login_hash("a");
        let phc = hash_login(&h, 8, 1).unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=8,t=1,p=1$"));
        assert!(verify_login(&h, &phc));
        assert!(!verify_login(&login_hash("b"), &phc));
        assert!(!verify_login(&h, "garbage"));
        // stored value does not contain the credential itself
        let raw = data_encoding::BASE64_NOPAD.encode(h.expose_secret());
        assert!(!phc.contains(&raw));
    }

    #[test]
    fn tokens_are_random_and_hashed() {
        let (t1, h1) = new_token();
        let (t2, _) = new_token();
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 43);
        assert_eq!(token_hash(&t1), h1);
    }
}
