use axum::extract::Query;
use axum::response::{IntoResponse, Response};
use axum::http::{StatusCode, HeaderName, header};
use tracing::debug;

use self::auth::TokenAuthRequest;

pub mod blobs;
pub mod uploads;
pub mod manifests;
pub mod tags;
pub mod catalog;
pub mod auth;

/// https://docs.docker.com/registry/spec/api/#api-version-check
/// full endpoint: `/v2/`
pub async fn version_check(params: Option<Query<TokenAuthRequest>>, body: String) -> Response {
    debug!("Got body: {}", body);

    /* (
        StatusCode::OK,
        [( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0" )]
    ) */

    //Www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:samalba/my-app:pull,push"

    let bearer = format!("Bearer realm=\"http://localhost:3000/auth\"");/* match params {
        Some(Query(params)) => format!("Bearer realm=\"http://localhost:3000/token\",scope=\"{}\"", params.scope),
        None => format!("Bearer realm=\"http://localhost:3000/token\""),
    }; */

    (
        StatusCode::UNAUTHORIZED,
        [
            ( header::WWW_AUTHENTICATE, bearer ),
            ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() )
        ]
    ).into_response()
}