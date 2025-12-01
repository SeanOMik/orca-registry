use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::app_state::AppState;
use crate::auth::auth_challenge_response;
use crate::dto::user::UserAuth;
use crate::error::OciRegistryError;

pub mod auth;
pub mod blobs;
pub mod catalog;
pub mod manifests;
pub mod referrers;
pub mod tags;
pub mod uploads;

/// https://web.archive.org/web/20230524163916/https://docs.docker.com/registry/spec/api/#api-version-check
/// full endpoint: `/v2/`
pub async fn version_check(
    state: State<Arc<AppState>>,
    auth: Option<UserAuth>,
) -> Response {
    // If the client is authenticated, respond with registry v2 support,
    // else respond with an auth challenge.
    if auth.is_some() {
        (
            StatusCode::OK,
            [(
                HeaderName::from_static("docker-distribution-api-version"),
                "registry/2.0",
            )],
        )
            .into_response()
    } else {
        auth_challenge_response(
            &state.config,
            None,
            vec![OciRegistryError::Unauthorized.as_error_message(None, None)],
        )
    }
}
