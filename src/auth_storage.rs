use std::{collections::HashSet, ops::Deref, sync::Arc};

use axum::{extract::State, http::{StatusCode, HeaderMap, header, HeaderName, Request}, middleware::Next, response::{Response, IntoResponse}};

use tracing::debug;

use crate::app_state::AppState;

/// Temporary struct for storing auth information in memory.
pub struct MemoryAuthStorage {
    pub valid_tokens: HashSet<String>,
}

impl MemoryAuthStorage {
    pub fn new() -> Self {
        Self {
            valid_tokens: HashSet::new(),
        }
    }
}

#[derive(Clone)]
pub struct AuthToken(pub String);

impl Deref for AuthToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

type Rejection = (StatusCode, HeaderMap);

pub async fn require_auth<B>(State(state): State<Arc<AppState>>, mut request: Request<B>, next: Next<B>) -> Result<Response, Rejection> {
    let bearer = format!("Bearer realm=\"http://localhost:3000/auth\"");
    let mut failure_headers = HeaderMap::new();
    failure_headers.append(header::WWW_AUTHENTICATE, bearer.parse().unwrap());
    failure_headers.append(HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".parse().unwrap());

    let auth = String::from(
        request.headers().get(header::AUTHORIZATION)
        .ok_or((StatusCode::UNAUTHORIZED, failure_headers.clone()))?
        .to_str()
        .map_err(|_| (StatusCode::UNAUTHORIZED, failure_headers.clone()))?
    ); // TODO: Don't unwrap

    let token = match auth.split_once(' ') {
        Some((auth, token)) if auth == "Bearer" => token,
        // This line would allow empty tokens
        //_ if auth == "Bearer" => Ok(AuthToken(None)),
        _ => return Err( (StatusCode::UNAUTHORIZED, failure_headers) ),
    };

    // If the token is not valid, return an unauthorized response
    let auth_storage = state.auth_storage.lock().await;
    if !auth_storage.valid_tokens.contains(token) {
        let bearer = format!("Bearer realm=\"http://localhost:3000/auth\"");
        return Ok((
            StatusCode::UNAUTHORIZED,
            [
                ( header::WWW_AUTHENTICATE, bearer ),
                ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() )
            ]
        ).into_response());

    } else {
        debug!("Client successfully authenticated!");
    }
    drop(auth_storage);

    request.extensions_mut().insert(AuthToken(String::from(token)));

    Ok(next.run(request).await)
}