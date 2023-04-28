mod api;
mod app_state;
mod database;
mod dto;
mod storage;
mod byte_stream;
mod config;
mod query;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::http::{Request, StatusCode, header, HeaderName};
use axum::middleware::Next;
use axum::response::{Response, IntoResponse};
use axum::{Router, routing};
use axum::ServiceExt;
use tower_layer::Layer;

use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::Mutex;
use tower_http::normalize_path::NormalizePathLayer;
use tracing::{debug, Level};

use app_state::AppState;
use database::Database;

use crate::storage::StorageDriver;
use crate::storage::filesystem::FilesystemDriver;

use crate::config::Config;

use tower_http::trace::TraceLayer;

/// Encode the 'name' path parameter in the url
async fn change_request_paths<B>(mut request: Request<B>, next: Next<B>) -> Response {
    // Attempt to find the name using regex in the url
    let regex = regex::Regex::new(r"/v2/([\w/]+)/(blobs|tags|manifests)").unwrap();
    let captures = match regex.captures(request.uri().path()) {
        Some(captures) => captures,
        None => return next.run(request).await,
    };

    // Find the name in the request and encode it in the url
    let name = captures.get(1).unwrap().as_str().to_string();
    let encoded_name = name.replace('/', "%2F");

    // Replace the name in the uri
    let uri_str = request.uri().to_string().replace(&name, &encoded_name);
    debug!("Rewrote request url to: '{}'", uri_str);

    *request.uri_mut() = uri_str.parse().unwrap();

    next.run(request).await
}

pub async fn auth_failure() -> impl IntoResponse {
    let bearer = format!("Bearer realm=\"http://localhost:3000/token\"");

    (
        StatusCode::UNAUTHORIZED,
        
        [
            ( header::WWW_AUTHENTICATE, bearer ),
            ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() )
        ]
    ).into_response()
    //StatusCode::UNAUTHORIZED
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(15)
        .connect("test.db").await.unwrap();

    pool.create_schema().await.unwrap();

    let storage_driver: Mutex<Box<dyn StorageDriver>> = Mutex::new(Box::new(FilesystemDriver::new("registry/blobs")));

    let config = Config::new().expect("Failure to parse config!");
    let app_addr = SocketAddr::from_str(&format!("{}:{}", config.listen_address, config.listen_port)).unwrap();

    let state = Arc::new(AppState::new(pool, storage_driver, config));

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let path_middleware = axum::middleware::from_fn(change_request_paths);

    let app = Router::new()
        .route("/auth", routing::get(api::auth::auth_basic_get)
            .post(api::auth::auth_basic_get))
        .fallback(auth_failure)
        .nest("/v2", Router::new()
            .route("/", routing::get(api::version_check))
            /* .route("/_catalog", routing::get(api::catalog::list_repositories))
            .route("/:name/tags/list", routing::get(api::tags::list_tags))
            .nest("/:name/blobs", Router::new()
                .route("/:digest", routing::get(api::blobs::pull_digest_get)
                    .head(api::blobs::digest_exists_head)
                    .delete(api::blobs::delete_digest))
                .nest("/uploads", Router::new()
                    .route("/", routing::post(api::uploads::start_upload_post))
                    .route("/:uuid", routing::patch(api::uploads::chunked_upload_layer_patch)
                        .put(api::uploads::finish_chunked_upload_put)
                        .delete(api::uploads::cancel_upload_delete)
                        .get(api::uploads::check_upload_status_get)
                    )
                )
            )
            .route("/:name/manifests/:reference", routing::get(api::manifests::pull_manifest_get)
                .put(api::manifests::upload_manifest_put)
                .head(api::manifests::manifest_exists_head)
                .delete(api::manifests::delete_manifest)) */
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let layered_app = NormalizePathLayer::trim_trailing_slash().layer(path_middleware.layer(app));

    debug!("Starting http server, listening on {}", app_addr);
    axum::Server::bind(&app_addr)
        .serve(layered_app.into_make_service())
        .await
        .unwrap();

    Ok(())
}