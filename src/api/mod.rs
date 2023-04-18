pub mod blobs;
pub mod uploads;
pub mod manifests;
pub mod tags;

use actix_web::{HttpResponse, get};

/// https://docs.docker.com/registry/spec/api/#api-version-check
/// full endpoint: `/v2/`
#[get("/")]
pub async fn version_check() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .finish()
}