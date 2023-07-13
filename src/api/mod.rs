use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::http::{StatusCode, HeaderName, HeaderMap, header};
use tracing::debug;

use crate::app_state::AppState;

pub mod blobs;
pub mod uploads;
pub mod manifests;
pub mod tags;
pub mod catalog;
pub mod auth;

use crate::dto::user::UserAuth;

/// https://docs.docker.com/registry/spec/api/#api-version-check
/// full endpoint: `/v2/`
pub async fn version_check(_state: State<Arc<AppState>>) -> Response {
    let bearer = format!("Bearer realm=\"{}/auth\"", _state.config.url());
    (
        StatusCode::UNAUTHORIZED,
        [
            ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0" ),
            //( header::WWW_AUTHENTICATE, &bearer ),
        ]
    ).into_response()
}