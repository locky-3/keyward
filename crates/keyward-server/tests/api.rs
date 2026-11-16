//! HTTP-level tests of the sync server against in-memory SQLite, with a
//! controllable clock for session expiry and lockout.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use keyward_core::sync::api::{RegisterRequest, RemoteVault};
use keyward_core::sync::login_hash_for;
use keyward_core::{ItemId, KdfParams, LoginHash, SecretString, UnlockedVault};
use keyward_server::Config;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tower::ServiceExt;

struct Srv {
    router: Router,
    db: SqlitePool,
    clock: Arc<AtomicI64>,
}

struct Resp {
    status: StatusCode,
    retry_after: Option<String>,
    body: Value,
}

/// Credentials of a test account.
struct Acct {
    username: String,
    login: LoginHash,
    vault: RemoteVault,
}

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn floor() -> KdfParams {
    KdfParams {
        m_cost_kib: KdfParams::MIN_M_COST_KIB,
        t_cost: KdfParams::MIN_T_COST,
        p_cost: 1,
    }
}

fn account(username: &str, password: &str) -> Acct {
    let v = UnlockedVault::create(&pw(password), floor()).unwrap();
    Acct {
        username: username.into(),
        login: login_hash_for(&pw(password), &v.header().kdf).unwrap(),
        vault: v.remote_vault(),
    }
}

fn blob(byte: u8) -> Value {
    json!({ "nonce": "AQEBAQEBAQEBAQEB", "ct": data_encoding::BASE64.encode(&[byte; 48]) })
}

impl Srv {
    async fn new() -> Self {
        Self::with(|_| {}).await
    }

    async fn with(f: impl FnOnce(&mut Config)) -> Self {
        let mut cfg = Config::for_tests();
        cfg.trust_proxy = true; // lets tests pick the client IP
        cfg.auth_rate_per_min = 1000;
        f(&mut cfg);
        let clock = Arc::new(AtomicI64::new(1_700_000_000_000));
        let c = clock.clone();
        let app = keyward_server::build(cfg, Arc::new(move || c.load(Ordering::SeqCst)))
            .await
            .unwrap();
        Self {
            router: app.router,
            db: app.db,
            clock,
        }
    }

    fn advance_secs(&self, s: i64) {
        self.clock.fetch_add(s * 1000, Ordering::SeqCst);
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Resp {
        self.call_from("203.0.113.7", method, uri, token, body)
            .await
    }

    async fn call_from(
        &self,
        ip: &str,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Resp {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-forwarded-for", ip);
        if let Some(t) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Resp {
            status,
            retry_after,
            body,
        }
    }

    async fn register(&self, a: &Acct) -> Resp {
        let req = RegisterRequest {
            username: a.username.clone(),
            login_hash: a.login.clone(),
            vault: a.vault.clone(),
        };
        self.call(
            Method::POST,
            "/api/v1/accounts",
            None,
            Some(serde_json::to_value(req).unwrap()),
        )
        .await
    }

    async fn login_raw(&self, username: &str, login: &LoginHash) -> Resp {
        self.call(
            Method::POST,
            "/api/v1/sessions",
            None,
            Some(json!({ "username": username, "login_hash": login })),
        )
        .await
    }

    async fn login(&self, a: &Acct) -> String {
        let r = self.login_raw(&a.username, &a.login).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        r.body["token"].as_str().unwrap().to_owned()
    }

    async fn push(&self, tok: &str, id: ItemId, base: u64, version: u64, b: u8) -> Resp {
        self.call(
            Method::PUT,
            &format!("/api/v1/items/{id}"),
            Some(tok),
            Some(json!({ "base_version": base, "version": version, "blob": blob(b) })),
        )
        .await
    }

    async fn pull(&self, tok: &str, since: u64) -> Resp {
        self.call(
            Method::GET,
            &format!("/api/v1/items?since={since}"),
            Some(tok),
            None,
        )
        .await
    }
}

#[tokio::test]
async fn health() {
    let s = Srv::new().await;
    assert_eq!(
        s.call(Method::GET, "/healthz", None, None).await.status,
        StatusCode::OK
    );
    // The root explains what this is instead of a bare 404.
    let root = s.call(Method::GET, "/", None, None).await;
    assert_eq!(root.status, StatusCode::OK);
}

#[tokio::test]
async fn register_and_prelogin() {
    let s = Srv::new().await;
    let a = account("Alice", "master-a");
    assert_eq!(s.register(&a).await.status, StatusCode::CREATED);

    let r = s
        .call(
            Method::POST,
            "/api/v1/accounts/prelogin",
            None,
            Some(json!({"username": "ALICE"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body["kdf"],
        serde_json::to_value(a.vault.header.kdf).unwrap()
    );

    // duplicate (case-insensitive) and invalid usernames
    assert_eq!(
        s.register(&account("alice", "x")).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        s.register(&account("a b", "x")).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn prelogin_for_unknown_users_is_stable_and_plausible() {
    let s = Srv::new().await;
    let ask = |u: &'static str| {
        let s = &s;
        async move {
            s.call(
                Method::POST,
                "/api/v1/accounts/prelogin",
                None,
                Some(json!({"username": u})),
            )
            .await
        }
    };
    let a1 = ask("nobody").await;
    let a2 = ask("nobody").await;
    let b = ask("someone-else").await;
    assert_eq!(a1.status, StatusCode::OK);
    assert_eq!(a1.body, a2.body, "deterministic");
    assert_ne!(a1.body["kdf"]["salt"], b.body["kdf"]["salt"]);
    assert_eq!(
        a1.body["kdf"]["params"],
        serde_json::to_value(KdfParams::DEFAULT).unwrap()
    );
}

#[tokio::test]
async fn registration_can_be_closed() {
    let s = Srv::with(|c| c.registration_open = false).await;
    assert_eq!(
        s.register(&account("bob", "x")).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn register_rejects_weak_kdf() {
    let s = Srv::new().await;
    let mut a = account("carol", "x");
    a.vault.header.kdf.params.m_cost_kib = 1024;
    assert_eq!(s.register(&a).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_success_failure_and_no_user_enumeration() {
    let s = Srv::new().await;
    let a = account("dave", "right");
    s.register(&a).await;
    s.login(&a).await;

    let wrong = account("dave", "wrong").login;
    let bad = s.login_raw("dave", &wrong).await;
    let unknown = s.login_raw("nobody", &wrong).await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad.body, unknown.body, "same error for unknown user");
}

#[tokio::test]
async fn database_stores_only_argon2_hash_of_login() {
    let s = Srv::new().await;
    let a = account("erin", "pw");
    s.register(&a).await;
    let token = s.login(&a).await;
    let phc: String = sqlx::query_scalar("SELECT login_phc FROM accounts")
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert!(phc.starts_with("$argon2id$"));
    let raw = serde_json::to_value(&a.login).unwrap();
    assert!(!phc.contains(raw.as_str().unwrap()));
    let stored_token: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM sessions")
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert_ne!(stored_token, token.as_bytes(), "tokens are stored hashed");
}

#[tokio::test]
async fn lockout_after_repeated_failures_also_for_unknown_users() {
    let s = Srv::new().await;
    let a = account("frank", "right");
    s.register(&a).await;
    let wrong = account("x", "wrong").login;
    for _ in 0..5 {
        assert_eq!(
            s.login_raw("frank", &wrong).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            s.login_raw("ghost", &wrong).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    // locked: even the right credential is refused, with Retry-After
    let r = s.login_raw("frank", &a.login).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.retry_after.as_deref(), Some("900"));
    assert_eq!(
        s.login_raw("ghost", &wrong).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "unknown users lock the same way"
    );
    s.advance_secs(901);
    s.login(&a).await;
}

#[tokio::test]
async fn per_ip_rate_limit() {
    let s = Srv::with(|c| c.auth_rate_per_min = 3).await;
    let ask = || {
        s.call_from(
            "198.51.100.1",
            Method::POST,
            "/api/v1/accounts/prelogin",
            None,
            Some(json!({"username": "zed"})),
        )
    };
    for _ in 0..3 {
        assert_eq!(ask().await.status, StatusCode::OK);
    }
    let r = ask().await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.retry_after.is_some());
    // a different client is unaffected
    let other = s
        .call_from(
            "198.51.100.2",
            Method::POST,
            "/api/v1/accounts/prelogin",
            None,
            Some(json!({"username": "zed"})),
        )
        .await;
    assert_eq!(other.status, StatusCode::OK);
    s.advance_secs(20);
    assert_eq!(ask().await.status, StatusCode::OK);
}

#[tokio::test]
async fn sessions_expire_and_logout_revokes() {
    let s = Srv::with(|c| c.session_ttl_secs = 60).await;
    let a = account("gina", "pw");
    s.register(&a).await;

    assert_eq!(
        s.call(Method::GET, "/api/v1/vault", None, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        s.call(Method::GET, "/api/v1/vault", Some("garbage"), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    let t = s.login(&a).await;
    let v = s.call(Method::GET, "/api/v1/vault", Some(&t), None).await;
    assert_eq!(v.status, StatusCode::OK);
    assert_eq!(v.body, serde_json::to_value(&a.vault).unwrap());
    s.advance_secs(61);
    assert_eq!(
        s.call(Method::GET, "/api/v1/vault", Some(&t), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    let t = s.login(&a).await;
    assert_eq!(
        s.call(Method::DELETE, "/api/v1/sessions/current", Some(&t), None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        s.call(Method::GET, "/api/v1/vault", Some(&t), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn push_pull_versions_and_conflicts() {
    let s = Srv::new().await;
    let a = account("hank", "pw");
    s.register(&a).await;
    let t = s.login(&a).await;
    let id = ItemId::random();

    let r = s.push(&t, id, 0, 1, 1).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["seq"], 1);

    // second "create" conflicts and returns the current state
    let r = s.push(&t, id, 0, 1, 2).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.body["current"]["version"], 1);
    assert_eq!(r.body["current"]["blob"], blob(1));

    // stale base conflicts; correct base succeeds
    assert_eq!(s.push(&t, id, 5, 6, 3).await.status, StatusCode::CONFLICT);
    assert_eq!(s.push(&t, id, 1, 2, 3).await.status, StatusCode::OK);
    // version must increase
    assert_eq!(
        s.push(&t, id, 2, 2, 4).await.status,
        StatusCode::BAD_REQUEST
    );

    let p = s.pull(&t, 0).await;
    let changes = p.body["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "only the latest state per item");
    assert_eq!(changes[0]["version"], 2);
    assert_eq!(changes[0]["blob"], blob(3));
    assert_eq!(p.body["cursor"], changes[0]["seq"]);
    let cursor = p.body["cursor"].as_u64().unwrap();
    assert!(
        s.pull(&t, cursor).await.body["changes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn delete_creates_tombstone() {
    let s = Srv::new().await;
    let a = account("ivy", "pw");
    s.register(&a).await;
    let t = s.login(&a).await;
    let id = ItemId::random();
    s.push(&t, id, 0, 1, 1).await;

    let uri = format!("/api/v1/items/{id}");
    let del = |base: u64| {
        s.call(
            Method::DELETE,
            &uri,
            Some(&t),
            Some(json!({"base_version": base})),
        )
    };
    assert_eq!(del(7).await.status, StatusCode::CONFLICT);
    let r = del(1).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["version"], 2);
    let c = &s.pull(&t, 0).await.body["changes"][0];
    assert_eq!(c["deleted"], true);
    assert!(c.get("blob").is_none());
    // deleting again: conflict showing the tombstone
    let again = del(2).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.body["current"]["deleted"], true);
    // unknown item
    let other = ItemId::random();
    let r = s
        .call(
            Method::DELETE,
            &format!("/api/v1/items/{other}"),
            Some(&t),
            Some(json!({"base_version": 1})),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // a tombstoned item can be resurrected from its tombstone version
    assert_eq!(s.push(&t, id, 2, 3, 9).await.status, StatusCode::OK);
}

#[tokio::test]
async fn invalid_item_requests() {
    let s = Srv::new().await;
    let a = account("jack", "pw");
    s.register(&a).await;
    let t = s.login(&a).await;
    let r = s
        .call(
            Method::PUT,
            "/api/v1/items/not-a-uuid",
            Some(&t),
            Some(json!({"base_version": 0, "version": 1, "blob": blob(1)})),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = s
        .call(Method::PUT, &format!("/api/v1/items/{}", ItemId::random()), Some(&t),
            Some(json!({"base_version": 0, "version": 1, "blob": {"nonce": "AQEBAQEBAQEBAQEB", "ct": "AAAA"}})))
        .await;
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "ciphertext shorter than a tag"
    );
}

#[tokio::test]
async fn accounts_are_isolated() {
    let s = Srv::new().await;
    let (a, b) = (account("kate", "pw"), account("liam", "pw"));
    s.register(&a).await;
    s.register(&b).await;
    let (ta, tb) = (s.login(&a).await, s.login(&b).await);
    let id = ItemId::random();
    s.push(&ta, id, 0, 1, 1).await;
    assert!(
        s.pull(&tb, 0).await.body["changes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // same id in another account is independent
    assert_eq!(s.push(&tb, id, 0, 1, 2).await.status, StatusCode::OK);
    assert_eq!(s.pull(&ta, 0).await.body["changes"][0]["blob"], blob(1));
}

#[tokio::test]
async fn pull_paginates() {
    let s = Srv::new().await;
    let a = account("mia", "pw");
    s.register(&a).await;
    let t = s.login(&a).await;
    for _ in 0..5 {
        s.push(&t, ItemId::random(), 0, 1, 1).await;
    }
    let p = s
        .call(Method::GET, "/api/v1/items?since=0&limit=2", Some(&t), None)
        .await;
    assert_eq!(p.body["changes"].as_array().unwrap().len(), 2);
    assert_eq!(p.body["has_more"], true);
    let p = s
        .call(Method::GET, "/api/v1/items?since=4&limit=2", Some(&t), None)
        .await;
    assert_eq!(p.body["changes"].as_array().unwrap().len(), 1);
    assert_eq!(p.body["has_more"], false);
}

#[tokio::test]
async fn change_password_rotates_credentials_and_revokes_sessions() {
    let s = Srv::new().await;
    let a = account("nina", "old-pw");
    s.register(&a).await;
    let t = s.login(&a).await;

    // build the new credential the way the client does
    let mut v = UnlockedVault::from_remote(
        a.vault.header,
        a.vault.wrapped_vault_key.clone(),
        &pw("old-pw"),
    )
    .unwrap()
    .0;
    let new_login = v.change_master_password(&pw("new-pw"), floor()).unwrap();
    let body = |current: &LoginHash, vault: RemoteVault| json!({ "current_login_hash": current, "new_login_hash": new_login, "vault": vault });

    let wrong = account("x", "nope").login;
    let r = s
        .call(
            Method::PUT,
            "/api/v1/account/password",
            Some(&t),
            Some(body(&wrong, v.remote_vault())),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let mut other_vault = v.remote_vault();
    other_vault.header.vault_id = account("y", "z").vault.header.vault_id;
    let r = s
        .call(
            Method::PUT,
            "/api/v1/account/password",
            Some(&t),
            Some(body(&a.login, other_vault)),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    let r = s
        .call(
            Method::PUT,
            "/api/v1/account/password",
            Some(&t),
            Some(body(&a.login, v.remote_vault())),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    assert_eq!(
        s.call(Method::GET, "/api/v1/vault", Some(&t), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        s.login_raw("nina", &a.login).await.status,
        StatusCode::UNAUTHORIZED
    );
    let t2 = s.login_raw("nina", &new_login).await.body["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let vault = s.call(Method::GET, "/api/v1/vault", Some(&t2), None).await;
    assert_eq!(vault.body, serde_json::to_value(v.remote_vault()).unwrap());
}
