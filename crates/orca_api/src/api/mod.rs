use std::sync::Arc;

use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use base64::{Engine, prelude::BASE64_STANDARD};
use hyper::{StatusCode, header};

use crate::app_state::AppState;

pub mod oci;
pub mod orca;

/// Extractor for HTTP Basic Authorization.
/// 
/// This will return `BAD_REQUEST` if
/// * the header does not start with 'Basic'
/// * the base64 fails to decode,
/// * the decoded base64 is not valid utf8,
/// * or if there was no password in the decoded string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub struct BasicAuthorization {
    pub username: String,
    pub password: String,
}

#[inline(always)]
fn from_header_value(auth: &str) -> Result<BasicAuthorization, StatusCode> {
    if auth.starts_with("Basic") {
        let auth = &auth["Basic ".len()..];
        
        // base64 decode the token and get it as a string
        let auth_decoded = BASE64_STANDARD.decode(auth)
            .ok().ok_or(StatusCode::BAD_REQUEST)?;
        let auth = std::str::from_utf8(&auth_decoded)
            .ok().ok_or(StatusCode::BAD_REQUEST)?;

        let (user, pass) = auth.split_once(":")
            .ok_or(StatusCode::BAD_REQUEST)?;

        Ok(BasicAuthorization {
            username: user.into(),
            password: pass.into(),
        })
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

impl FromRequestParts<Arc<AppState>> for BasicAuthorization {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts.headers.get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::BAD_REQUEST)?;
        
        from_header_value(auth)
    }
}

impl OptionalFromRequestParts<Arc<AppState>> for BasicAuthorization {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &Arc<AppState>,
    ) -> Result<Option<Self>, Self::Rejection> {
        let auth = parts.headers.get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());

        if let Some(auth) = auth {
            from_header_value(auth)
                .map(|v| Some(v))
        } else {
            Ok(None)
        }
    }
}