//! HTTP handlers. All bodies are JSON (see `keyward_core::sync::api`).

use std::sync::Arc;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use keyward_core::sync::api::{
    ChangePasswordRequest, DeleteRequest, ItemChange, LoginRequest, LoginResponse, PreloginRequest,
    PreloginResponse, PullResponse, PushRequest, RegisterRequest, RemoteVault, WriteResponse,
};
use keyward_core::{ItemId, KdfAlgorithm, KdfHeader, KdfParams, LoginHash, Salt, Sealed};
use serde::Deserialize;
use sha2::Sha256;
use sqlx::Row;
use tower_http::trace::TraceLayer;

use crate::AppState;
use crate::auth::{self, AuthAccount, ClientIp};
use crate::error::{ApiError, ApiResult};

/// Largest accepted item ciphertext (1 MiB).
const MAX_BLOB: usize = 1024 * 1024;
const PULL_DEFAULT: i64 = 500;
const PULL_MAX: i64 = 1000;

type St = State<Arc<AppState>>;

/// Shown to anyone opening the server in a browser. Reveals no version or
/// configuration details.
const ROOT_TEXT: &str = "Keyward sync server

This is an API for the `kw` command-line client; there is no web interface.
Connect with:  kw sync register --server <this URL> --username <name>
Health check:  /healthz
";

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(|| async { ROOT_TEXT }))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/v1/accounts/prelogin", post(prelogin))
        .route("/api/v1/accounts", post(register))
        .route("/api/v1/sessions", post(login))
        .route("/api/v1/sessions/current", delete(logout))
        .route("/api/v1/vault", get(get_vault))
        .route("/api/v1/account/password", put(change_password))
        .route("/api/v1/items", get(pull))
        .route("/api/v1/items/{id}", put(push).delete(delete_item))
        .layer(DefaultBodyLimit::max(2 * MAX_BLOB))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ---------- helpers ----------

fn normalise_username(raw: &str) -> ApiResult<String> {
    let u = raw.trim().to_lowercase();
    let ok_len = (3..=64).contains(&u.chars().count());
    let ok_chars = u
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '+'));
    if ok_len && ok_chars {
        Ok(u)
    } else {
        Err(ApiError::BadRequest(
            "username must be 3-64 characters of a-z 0-9 . _ - @ +",
        ))
    }
}

fn rate_limit(s: &AppState, ip: ClientIp) -> ApiResult<()> {
    s.auth_limiter
        .check(ip.0, s.now_ms())
        .map_err(|retry_after_secs| ApiError::TooManyRequests { retry_after_secs })
}

fn validate_remote_vault(v: &RemoteVault) -> ApiResult<()> {
    v.header
        .kdf
        .params
        .validate()
        .map_err(|_| ApiError::BadRequest("KDF parameters out of range"))?;
    if v.wrapped_vault_key.ciphertext().len() != 32 + 16 {
        return Err(ApiError::BadRequest("wrapped vault key has the wrong size"));
    }
    Ok(())
}

fn to_i64(v: u64) -> ApiResult<i64> {
    i64::try_from(v).map_err(|_| ApiError::BadRequest("number too large"))
}

async fn hash_blocking(s: &AppState, login: LoginHash) -> ApiResult<String> {
    let (m, t) = (s.config.hash_m_cost_kib, s.config.hash_t_cost);
    Ok(
        tokio::task::spawn_blocking(move || auth::hash_login(&login, m, t))
            .await
            .context("hash task")??,
    )
}

async fn verify_blocking(login: LoginHash, phc: String) -> ApiResult<bool> {
    Ok(
        tokio::task::spawn_blocking(move || auth::verify_login(&login, &phc))
            .await
            .context("verify task")?,
    )
}

fn row_to_change(r: &sqlx::sqlite::SqliteRow) -> ApiResult<ItemChange> {
    let id: String = r.try_get("item_id")?;
    let deleted: bool = r.try_get::<i64, _>("deleted")? != 0;
    let blob = if deleted {
        None
    } else {
        let nonce: Vec<u8> = r.try_get("nonce")?;
        let ct: Vec<u8> = r.try_get("ciphertext")?;
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt nonce in database"))?;
        Some(Sealed::from_parts(nonce, ct))
    };
    Ok(ItemChange {
        id: id
            .parse()
            .map_err(|_| anyhow::anyhow!("corrupt item id in database"))?,
        version: u64::try_from(r.try_get::<i64, _>("version")?).unwrap_or(0),
        deleted,
        blob,
        seq: u64::try_from(r.try_get::<i64, _>("seq")?).unwrap_or(0),
    })
}

async fn current_item(s: &AppState, account: i64, id: &str) -> ApiResult<Option<ItemChange>> {
    let row = sqlx::query(
        "SELECT item_id, version, deleted, nonce, ciphertext, seq FROM items \
         WHERE account_id = ? AND item_id = ?",
    )
    .bind(account)
    .bind(id)
    .fetch_optional(&s.db)
    .await?;
    row.as_ref().map(row_to_change).transpose()
}

fn parse_item_id(raw: &str) -> ApiResult<String> {
    raw.parse::<ItemId>()
        .map(|id| id.to_string())
        .map_err(|_| ApiError::BadRequest("invalid item id"))
}

// ---------- accounts & sessions ----------

async fn prelogin(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    rate_limit(&s, ip)?;
    let username = normalise_username(&req.username)?;
    let stored: Option<String> =
        sqlx::query_scalar("SELECT vault_json FROM accounts WHERE username = ?")
            .bind(&username)
            .fetch_optional(&s.db)
            .await?;
    let kdf = match stored {
        Some(json) => {
            serde_json::from_str::<RemoteVault>(&json)
                .context("stored vault")?
                .header
                .kdf
        }
        None => {
            // Unknown user: a stable fake salt so the answer looks the same
            // every time and gives no hint that the account does not exist.
            let mut mac = Hmac::<Sha256>::new_from_slice(&s.prelogin_secret)
                .expect("HMAC takes any key length");
            mac.update(b"keyward/prelogin-salt/");
            mac.update(username.as_bytes());
            let tag = mac.finalize().into_bytes();
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&tag[..16]);
            KdfHeader {
                algorithm: KdfAlgorithm::Argon2id,
                params: KdfParams::DEFAULT,
                salt: Salt::from_bytes(salt),
            }
        }
    };
    Ok(Json(PreloginResponse { kdf }))
}

async fn register(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<StatusCode> {
    rate_limit(&s, ip)?;
    if !s.config.registration_open {
        return Err(ApiError::Forbidden("registration is closed on this server"));
    }
    let username = normalise_username(&req.username)?;
    validate_remote_vault(&req.vault)?;
    let phc = hash_blocking(&s, req.login_hash).await?;
    let vault_json = serde_json::to_string(&req.vault).context("serialising vault")?;
    let res = sqlx::query(
        "INSERT INTO accounts (username, login_phc, vault_json, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&username)
    .bind(&phc)
    .bind(&vault_json)
    .bind(s.now_secs())
    .execute(&s.db)
    .await;
    match res {
        Ok(_) => {
            tracing::info!(%username, "account registered");
            Ok(StatusCode::CREATED)
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(ApiError::UsernameTaken),
        Err(e) => Err(e.into()),
    }
}

async fn login(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    rate_limit(&s, ip)?;
    let username = normalise_username(&req.username)?;
    let now_ms = s.now_ms();
    s.lockout
        .check(&username, now_ms)
        .map_err(|retry_after_secs| ApiError::TooManyRequests { retry_after_secs })?;

    let row = sqlx::query("SELECT id, login_phc FROM accounts WHERE username = ?")
        .bind(&username)
        .fetch_optional(&s.db)
        .await?;
    let (account_id, phc) = match &row {
        Some(r) => (Some(r.try_get::<i64, _>("id")?), r.try_get("login_phc")?),
        None => (None, s.dummy_phc.clone()),
    };
    let valid = verify_blocking(req.login_hash, phc).await?;
    let Some(account_id) = account_id.filter(|_| valid) else {
        s.lockout.record_failure(&username, now_ms);
        tracing::warn!(%username, ip = %ip.0, "failed login");
        return Err(ApiError::InvalidCredentials);
    };
    s.lockout.record_success(&username);

    let now = s.now_secs();
    let expires_at = now + s.config.session_ttl_secs;
    let (token, hash) = auth::new_token();
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(now)
        .execute(&s.db)
        .await?;
    sqlx::query(
        "INSERT INTO sessions (token_hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(hash.as_slice())
    .bind(account_id)
    .bind(now)
    .bind(expires_at)
    .execute(&s.db)
    .await?;
    Ok(Json(LoginResponse { token, expires_at }))
}

async fn logout(State(s): St, a: AuthAccount) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(a.token_hash.as_slice())
        .execute(&s.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_vault(State(s): St, a: AuthAccount) -> ApiResult<Json<RemoteVault>> {
    let json: String = sqlx::query_scalar("SELECT vault_json FROM accounts WHERE id = ?")
        .bind(a.account_id)
        .fetch_one(&s.db)
        .await?;
    Ok(Json(serde_json::from_str(&json).context("stored vault")?))
}

async fn change_password(
    State(s): St,
    a: AuthAccount,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    validate_remote_vault(&req.vault)?;
    let row = sqlx::query("SELECT username, login_phc, vault_json FROM accounts WHERE id = ?")
        .bind(a.account_id)
        .fetch_one(&s.db)
        .await?;
    let username: String = row.try_get("username")?;
    let now_ms = s.now_ms();
    s.lockout
        .check(&username, now_ms)
        .map_err(|retry_after_secs| ApiError::TooManyRequests { retry_after_secs })?;
    if !verify_blocking(req.current_login_hash, row.try_get("login_phc")?).await? {
        s.lockout.record_failure(&username, now_ms);
        return Err(ApiError::InvalidCredentials);
    }
    let stored: RemoteVault =
        serde_json::from_str(&row.try_get::<String, _>("vault_json")?).context("stored vault")?;
    if stored.header.vault_id != req.vault.header.vault_id {
        return Err(ApiError::BadRequest("vault id cannot change"));
    }
    let phc = hash_blocking(&s, req.new_login_hash).await?;
    let vault_json = serde_json::to_string(&req.vault).context("serialising vault")?;
    let mut tx = s.db.begin().await?;
    sqlx::query("UPDATE accounts SET login_phc = ?, vault_json = ? WHERE id = ?")
        .bind(&phc)
        .bind(&vault_json)
        .bind(a.account_id)
        .execute(&mut *tx)
        .await?;
    // Every existing session (including this one) is revoked.
    sqlx::query("DELETE FROM sessions WHERE account_id = ?")
        .bind(a.account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(%username, "master password changed; sessions revoked");
    Ok(StatusCode::NO_CONTENT)
}

// ---------- items ----------

#[derive(Debug, Deserialize)]
struct PullQuery {
    #[serde(default)]
    since: u64,
    limit: Option<i64>,
}

async fn pull(
    State(s): St,
    a: AuthAccount,
    Query(q): Query<PullQuery>,
) -> ApiResult<Json<PullResponse>> {
    let limit = q.limit.unwrap_or(PULL_DEFAULT).clamp(1, PULL_MAX);
    let rows = sqlx::query(
        "SELECT item_id, version, deleted, nonce, ciphertext, seq FROM items \
         WHERE account_id = ? AND seq > ? ORDER BY seq LIMIT ?",
    )
    .bind(a.account_id)
    .bind(to_i64(q.since)?)
    .bind(limit + 1)
    .fetch_all(&s.db)
    .await?;
    let has_more = rows.len() as i64 > limit;
    let changes = rows
        .iter()
        .take(limit as usize)
        .map(row_to_change)
        .collect::<ApiResult<Vec<_>>>()?;
    let cursor = changes.last().map_or(q.since, |c| c.seq);
    Ok(Json(PullResponse {
        changes,
        cursor,
        has_more,
    }))
}

async fn push(
    State(s): St,
    a: AuthAccount,
    Path(raw_id): Path<String>,
    Json(req): Json<PushRequest>,
) -> ApiResult<Json<WriteResponse>> {
    let id = parse_item_id(&raw_id)?;
    if req.version <= req.base_version {
        return Err(ApiError::BadRequest(
            "version must be greater than base_version",
        ));
    }
    let ct = req.blob.ciphertext();
    if ct.len() < 16 || ct.len() > MAX_BLOB {
        return Err(ApiError::BadRequest("ciphertext size out of range"));
    }
    let (version, base) = (to_i64(req.version)?, to_i64(req.base_version)?);
    let now = s.now_secs();

    let mut tx = s.db.begin().await?;
    // Writing first takes SQLite's write lock for the whole transaction.
    let seq: i64 =
        sqlx::query_scalar("UPDATE accounts SET seq = seq + 1 WHERE id = ? RETURNING seq")
            .bind(a.account_id)
            .fetch_one(&mut *tx)
            .await?;
    // Compare-and-swap on the version: the write happens only if the
    // client's base is still the server's current version.
    let affected = if base == 0 {
        sqlx::query(
            "INSERT INTO items (account_id, item_id, version, deleted, nonce, ciphertext, seq, updated_at) \
             VALUES (?, ?, ?, 0, ?, ?, ?, ?) ON CONFLICT (account_id, item_id) DO NOTHING",
        )
        .bind(a.account_id)
        .bind(&id)
        .bind(version)
        .bind(req.blob.nonce().as_slice())
        .bind(ct)
        .bind(seq)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        sqlx::query(
            "UPDATE items SET version = ?, deleted = 0, nonce = ?, ciphertext = ?, seq = ?, updated_at = ? \
             WHERE account_id = ? AND item_id = ? AND version = ?",
        )
        .bind(version)
        .bind(req.blob.nonce().as_slice())
        .bind(ct)
        .bind(seq)
        .bind(now)
        .bind(a.account_id)
        .bind(&id)
        .bind(base)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    };
    if affected != 1 {
        tx.rollback().await?;
        let current = current_item(&s, a.account_id, &id).await?;
        return Err(ApiError::Conflict(current.map(Box::new)));
    }
    tx.commit().await?;
    Ok(Json(WriteResponse {
        version: req.version,
        seq: u64::try_from(seq).unwrap_or(0),
    }))
}

async fn delete_item(
    State(s): St,
    a: AuthAccount,
    Path(raw_id): Path<String>,
    Json(req): Json<DeleteRequest>,
) -> ApiResult<Json<WriteResponse>> {
    let id = parse_item_id(&raw_id)?;
    let base = to_i64(req.base_version)?;
    let now = s.now_secs();
    let mut tx = s.db.begin().await?;
    let seq: i64 =
        sqlx::query_scalar("UPDATE accounts SET seq = seq + 1 WHERE id = ? RETURNING seq")
            .bind(a.account_id)
            .fetch_one(&mut *tx)
            .await?;
    let new_version: Option<i64> = sqlx::query_scalar(
        "UPDATE items SET version = version + 1, deleted = 1, nonce = NULL, ciphertext = NULL, \
         seq = ?, updated_at = ? \
         WHERE account_id = ? AND item_id = ? AND version = ? AND deleted = 0 RETURNING version",
    )
    .bind(seq)
    .bind(now)
    .bind(a.account_id)
    .bind(&id)
    .bind(base)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(version) = new_version else {
        tx.rollback().await?;
        return match current_item(&s, a.account_id, &id).await? {
            None => Err(ApiError::NotFound),
            Some(cur) => Err(ApiError::Conflict(Some(Box::new(cur)))),
        };
    };
    tx.commit().await?;
    Ok(Json(WriteResponse {
        version: u64::try_from(version).unwrap_or(0),
        seq: u64::try_from(seq).unwrap_or(0),
    }))
}
