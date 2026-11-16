//! API errors and their HTTP mapping. Messages never include secrets.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use keyward_core::sync::api::{ErrorResponse, ItemChange};

/// Everything a handler can fail with.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("authentication required")]
    Unauthenticated,
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("not found")]
    NotFound,
    #[error("username is already taken")]
    UsernameTaken,
    #[error("conflict")]
    Conflict(Option<Box<ItemChange>>),
    #[error("too many requests")]
    TooManyRequests { retry_after_secs: u64 },
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::InvalidCredentials | Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::UsernameTaken | Self::Conflict(_) => StatusCode::CONFLICT,
            Self::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(e) => {
                tracing::error!(error = %e, "request failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let retry_after = match &self {
            Self::TooManyRequests { retry_after_secs } => Some(*retry_after_secs),
            _ => None,
        };
        let body = ErrorResponse {
            error: self.to_string(),
            current: match self {
                Self::Conflict(c) => c.map(|b| *b),
                _ => None,
            },
        };
        let mut resp = (status, Json(body)).into_response();
        if let Some(s) = retry_after
            && let Ok(v) = HeaderValue::from_str(&s.max(1).to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        resp
    }
}

/// Handler result.
pub type ApiResult<T> = Result<T, ApiError>;
