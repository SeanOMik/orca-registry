use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::app_state::AppState;

pub mod auth;
pub mod blobs;
pub mod catalog;
pub mod manifests;
pub mod tags;
pub mod uploads;

/// https://docs.docker.com/registry/spec/api/#api-version-check
/// full endpoint: `/v2/`
pub async fn version_check(_state: State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        [(
            HeaderName::from_static("docker-distribution-api-version"),
            "registry/2.0",
        )],
    )
        .into_response()
}
