//! Server configuration, read from `KW_*` environment variables.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};

/// Runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address (`KW_BIND`, default `0.0.0.0:8080`).
    pub bind: SocketAddr,
    /// sqlx SQLite URL (`KW_DATABASE_URL`, default `sqlite://data/keyward.db`).
    pub database_url: String,
    /// Session lifetime in seconds (`KW_SESSION_TTL_SECS`, default 12 h).
    pub session_ttl_secs: i64,
    /// Whether `POST /accounts` is allowed (`KW_REGISTRATION=open|closed`).
    pub registration_open: bool,
    /// Take the client IP from the last `X-Forwarded-For` entry
    /// (`KW_TRUST_PROXY=true`). Enable only behind a reverse proxy.
    pub trust_proxy: bool,
    /// Auth requests (prelogin/register/login) allowed per IP per minute
    /// (`KW_AUTH_RATE_PER_MIN`, default 20).
    pub auth_rate_per_min: u32,
    /// Failed logins per username before lockout (`KW_LOCKOUT_THRESHOLD`, default 5).
    pub lockout_threshold: u32,
    /// Lockout duration in seconds (`KW_LOCKOUT_SECS`, default 900).
    pub lockout_secs: i64,
    /// Argon2id cost for hashing login hashes (memory KiB, passes).
    pub hash_m_cost_kib: u32,
    /// Argon2id passes for hashing login hashes.
    pub hash_t_cost: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 8080)),
            database_url: "sqlite://data/keyward.db".into(),
            session_ttl_secs: 12 * 3600,
            registration_open: true,
            trust_proxy: false,
            auth_rate_per_min: 20,
            lockout_threshold: 5,
            lockout_secs: 15 * 60,
            // OWASP minimum for Argon2id; the input is already a 256-bit
            // value, so this mainly makes a stolen DB useless for login.
            hash_m_cost_kib: 19 * 1024,
            hash_t_cost: 2,
        }
    }
}

impl Config {
    /// Read the configuration from the environment.
    pub fn from_env() -> Result<Self> {
        let mut c = Self::default();
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        if let Some(v) = var("KW_BIND") {
            c.bind = v.parse().context("KW_BIND")?;
        }
        if let Some(v) = var("KW_DATABASE_URL") {
            c.database_url = v;
        }
        if let Some(v) = var("KW_SESSION_TTL_SECS") {
            c.session_ttl_secs = v.parse().context("KW_SESSION_TTL_SECS")?;
        }
        if let Some(v) = var("KW_REGISTRATION") {
            c.registration_open = match v.to_ascii_lowercase().as_str() {
                "open" => true,
                "closed" => false,
                _ => bail!("KW_REGISTRATION must be `open` or `closed`"),
            };
        }
        if let Some(v) = var("KW_TRUST_PROXY") {
            c.trust_proxy = v.parse().context("KW_TRUST_PROXY must be true/false")?;
        }
        if let Some(v) = var("KW_AUTH_RATE_PER_MIN") {
            c.auth_rate_per_min = v.parse().context("KW_AUTH_RATE_PER_MIN")?;
        }
        if let Some(v) = var("KW_LOCKOUT_THRESHOLD") {
            c.lockout_threshold = v.parse().context("KW_LOCKOUT_THRESHOLD")?;
        }
        if let Some(v) = var("KW_LOCKOUT_SECS") {
            c.lockout_secs = v.parse().context("KW_LOCKOUT_SECS")?;
        }
        c.validate()?;
        Ok(c)
    }

    /// Fast, in-memory configuration for tests. Never use in production:
    /// the Argon2 cost is minimal.
    pub fn for_tests() -> Self {
        Self {
            database_url: "sqlite::memory:".into(),
            hash_m_cost_kib: 8,
            hash_t_cost: 1,
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<()> {
        if self.session_ttl_secs <= 0 {
            bail!("KW_SESSION_TTL_SECS must be positive");
        }
        if self.auth_rate_per_min == 0 || self.lockout_threshold == 0 {
            bail!("rate limit and lockout threshold must be at least 1");
        }
        Ok(())
    }
}
