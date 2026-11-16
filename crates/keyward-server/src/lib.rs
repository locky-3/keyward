//! Keyward sync server: a zero-knowledge store for encrypted vault items.
//!
//! The server holds only what the client already treats as public or
//! ciphertext: the vault header, the wrapped vault key, item blobs, and an
//! Argon2id hash of each account's login hash.
#![forbid(unsafe_code)]

mod auth;
pub mod config;
mod error;
mod ratelimit;
mod routes;

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::Router;
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

pub use config::Config;
use ratelimit::{LoginLockout, RateLimiter};

/// Source of the current time in Unix milliseconds (injectable for tests).
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Wall-clock time.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    })
}

/// Shared state for all handlers.
pub struct AppState {
    pub(crate) db: SqlitePool,
    pub(crate) config: Config,
    clock: Clock,
    pub(crate) auth_limiter: RateLimiter,
    pub(crate) lockout: LoginLockout,
    /// Server-wide secret for deterministic fake prelogin salts.
    pub(crate) prelogin_secret: [u8; 32],
    /// PHC hash verified against for unknown usernames, so their login
    /// takes as long as a real one.
    pub(crate) dummy_phc: String,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

impl AppState {
    pub(crate) fn now_ms(&self) -> i64 {
        (self.clock)()
    }

    pub(crate) fn now_secs(&self) -> i64 {
        self.now_ms() / 1000
    }
}

/// A built application: the router plus a handle to its database.
#[derive(Debug, Clone)]
pub struct App {
    pub router: Router,
    pub db: SqlitePool,
}

/// Connect to the database, run migrations and build the router.
pub async fn build(config: Config, clock: Clock) -> Result<App> {
    let in_memory = config.database_url.contains(":memory:");
    let mut opts = SqliteConnectOptions::from_str(&config.database_url)
        .context("parsing KW_DATABASE_URL")?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    if !in_memory {
        opts = opts.journal_mode(SqliteJournalMode::Wal);
        if let Some(dir) = config
            .database_url
            .trim_start_matches("sqlite://")
            .trim_start_matches("sqlite:")
            .rsplit_once('/')
            .map(|(d, _)| d)
            .filter(|d| !d.is_empty())
        {
            std::fs::create_dir_all(dir).ok();
        }
    }
    let pool_opts = if in_memory {
        // One connection that never closes, or the database would vanish.
        SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
    } else {
        SqlitePoolOptions::new().max_connections(8)
    };
    let db = pool_opts
        .connect_with(opts)
        .await
        .context("opening database")?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("running migrations")?;

    let prelogin_secret = load_or_create_secret(&db).await?;
    let dummy_phc = {
        let fake = fake_login_hash();
        let (m, t) = (config.hash_m_cost_kib, config.hash_t_cost);
        tokio::task::spawn_blocking(move || auth::hash_login(&fake, m, t)).await??
    };

    let state = Arc::new(AppState {
        auth_limiter: RateLimiter::per_minute(config.auth_rate_per_min),
        lockout: LoginLockout::new(config.lockout_threshold, config.lockout_secs),
        db: db.clone(),
        config,
        clock,
        prelogin_secret,
        dummy_phc,
    });
    Ok(App {
        router: routes::router(state),
        db,
    })
}

fn fake_login_hash() -> keyward_core::LoginHash {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    let enc = data_encoding::BASE64.encode(&b);
    serde_json::from_value(serde_json::Value::String(enc)).expect("32 bytes is a valid LoginHash")
}

async fn load_or_create_secret(db: &SqlitePool) -> Result<[u8; 32]> {
    let existing: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM server_meta WHERE key = 'prelogin_secret'")
            .fetch_optional(db)
            .await?;
    if let Some(v) = existing {
        return v
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt prelogin secret"));
    }
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    sqlx::query("INSERT INTO server_meta (key, value) VALUES ('prelogin_secret', ?)")
        .bind(s.as_slice())
        .execute(db)
        .await?;
    Ok(s)
}
