//! Blocking HTTP client for the Keyward sync server.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use keyward_core::sync::api::{
    ChangePasswordRequest, DeleteRequest, ErrorResponse, ItemChange, LoginRequest, LoginResponse,
    PreloginRequest, PreloginResponse, PullResponse, PushRequest, RegisterRequest, RemoteVault,
    WriteResponse,
};
use keyward_core::{ItemId, LoginHash};
use reqwest::StatusCode;
use reqwest::blocking::{Client as Http, RequestBuilder, Response};
use reqwest::header::RETRY_AFTER;
use zeroize::Zeroizing;

/// Result of a write that may conflict.
#[derive(Debug)]
pub enum WriteOutcome {
    Ok(WriteResponse),
    Conflict(Option<ItemChange>),
    NotFound,
}

/// Connection to one server, optionally logged in.
pub struct Client {
    http: Http,
    base: String,
    token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("logged_in", &self.token.is_some())
            .finish()
    }
}

/// Normalise a server URL; require HTTPS except for loopback addresses.
pub fn normalise_server_url(raw: &str) -> Result<String> {
    let url = reqwest::Url::parse(raw.trim()).context("invalid server URL")?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => bail!("refusing plain http:// for a non-local server; use https://"),
        other => bail!("unsupported URL scheme `{other}`"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("do not put credentials in the server URL");
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

impl Client {
    pub fn new(server: &str) -> Result<Self> {
        let base = normalise_server_url(server)?;
        let http = Http::builder()
            .user_agent(concat!("kw/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .https_only(!base.starts_with("http://"))
            .build()?;
        Ok(Self {
            http,
            base,
            token: None,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn authed(&self, rb: RequestBuilder) -> Result<RequestBuilder> {
        let t = self.token.as_ref().context("not logged in")?;
        Ok(rb.bearer_auth(t.as_str()))
    }

    pub fn prelogin(&self, username: &str) -> Result<PreloginResponse> {
        let r = self
            .http
            .post(self.url("/api/v1/accounts/prelogin"))
            .json(&PreloginRequest {
                username: username.to_owned(),
            })
            .send()
            .context("contacting the sync server")?;
        Ok(ok(r)?.json()?)
    }

    pub fn register(&self, req: &RegisterRequest) -> Result<()> {
        let r = self
            .http
            .post(self.url("/api/v1/accounts"))
            .json(req)
            .send()
            .context("contacting the sync server")?;
        ok(r)?;
        Ok(())
    }

    pub fn login(&mut self, username: &str, login_hash: &LoginHash) -> Result<()> {
        let r = self
            .http
            .post(self.url("/api/v1/sessions"))
            .json(&LoginRequest {
                username: username.to_owned(),
                login_hash: login_hash.clone(),
            })
            .send()
            .context("contacting the sync server")?;
        if r.status() == StatusCode::UNAUTHORIZED {
            bail!(
                "the server rejected the login (wrong username, or the master password \
                 was changed on another device — then use `kw sync clone` into a new file)"
            );
        }
        let resp: LoginResponse = ok(r)?.json()?;
        self.token = Some(Zeroizing::new(resp.token));
        Ok(())
    }

    /// Best effort: the session expires anyway.
    pub fn logout(&mut self) {
        if let Ok(rb) = self.authed(self.http.delete(self.url("/api/v1/sessions/current"))) {
            let _ = rb.send();
        }
        self.token = None;
    }

    pub fn vault(&self) -> Result<RemoteVault> {
        let r = self
            .authed(self.http.get(self.url("/api/v1/vault")))?
            .send()?;
        Ok(ok(r)?.json()?)
    }

    pub fn change_password(&self, req: &ChangePasswordRequest) -> Result<()> {
        let r = self
            .authed(self.http.put(self.url("/api/v1/account/password")))?
            .json(req)
            .send()?;
        ok(r)?;
        Ok(())
    }

    pub fn pull(&self, since: u64) -> Result<PullResponse> {
        let r = self
            .authed(self.http.get(self.url("/api/v1/items")))?
            .query(&[("since", since)])
            .send()?;
        Ok(ok(r)?.json()?)
    }

    pub fn push(&self, id: ItemId, req: &PushRequest) -> Result<WriteOutcome> {
        let r = self
            .authed(self.http.put(self.url(&format!("/api/v1/items/{id}"))))?
            .json(req)
            .send()?;
        write_outcome(r)
    }

    pub fn delete(&self, id: ItemId, base_version: u64) -> Result<WriteOutcome> {
        let r = self
            .authed(self.http.delete(self.url(&format!("/api/v1/items/{id}"))))?
            .json(&DeleteRequest { base_version })
            .send()?;
        write_outcome(r)
    }
}

fn write_outcome(r: Response) -> Result<WriteOutcome> {
    match r.status() {
        StatusCode::CONFLICT => {
            let e: ErrorResponse = r.json()?;
            Ok(WriteOutcome::Conflict(e.current))
        }
        StatusCode::NOT_FOUND => Ok(WriteOutcome::NotFound),
        _ => Ok(WriteOutcome::Ok(ok(r)?.json()?)),
    }
}

/// Turn non-2xx responses into readable errors.
fn ok(r: Response) -> Result<Response> {
    let status = r.status();
    if status.is_success() {
        return Ok(r);
    }
    let retry = r
        .headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let msg = r
        .json::<ErrorResponse>()
        .map(|e| e.error)
        .unwrap_or_else(|_| status.canonical_reason().unwrap_or("error").to_owned());
    match retry {
        Some(s) => bail!(
            "server: {msg} (HTTP {}; retry after {s} s)",
            status.as_u16()
        ),
        None => bail!("server: {msg} (HTTP {})", status.as_u16()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        assert_eq!(
            normalise_server_url("https://vault.example.com/").unwrap(),
            "https://vault.example.com"
        );
        assert_eq!(
            normalise_server_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        normalise_server_url("http://localhost:1/").unwrap();
        assert!(normalise_server_url("http://example.com").is_err());
        assert!(normalise_server_url("ftp://example.com").is_err());
        assert!(normalise_server_url("https://user:pw@example.com").is_err());
        assert!(normalise_server_url("not a url").is_err());
    }
}
