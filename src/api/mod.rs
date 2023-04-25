use axum::response::IntoResponse;
use axum::http::{StatusCode, header, HeaderName};

pub mod blobs;
pub mod uploads;
pub mod manifests;
pub mod tags;
pub mod catalog;

/// https://docs.docker.com/registry/spec/api/#api-version-check
/// full endpoint: `/v2/`
pub async fn version_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        [( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0" )]
    )
}