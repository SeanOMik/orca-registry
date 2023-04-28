use std::sync::Arc;

use axum::Extension;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::http::{StatusCode, HeaderName};

use crate::app_state::AppState;

pub mod blobs;
pub mod uploads;
pub mod manifests;
pub mod tags;
pub mod catalog;
pub mod auth;

use crate::auth_storage::AuthToken;

/// https://docs.docker.com/registry/spec/api/#api-version-check
/// full endpoint: `/v2/`
pub async fn version_check(Extension(AuthToken(_token)): Extension<AuthToken>, _state: State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        [( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0" )]
    ).into_response()
}