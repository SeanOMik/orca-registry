mod api;
mod app_state;
mod database;
mod dto;
mod storage;
mod byte_stream;

use std::net::SocketAddr;
use std::sync::Arc;

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

use tower_http::trace::TraceLayer;

pub const REGISTRY_URL: &'static str = "http://localhost:3000"; // TODO: Move into configuration or something (make sure it doesn't end in /)

//#[actix_web::main]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(15)
        .connect("test.db").await.unwrap();

    pool.create_schema().await.unwrap();

    let storage_driver: Mutex<Box<dyn StorageDriver>> = Mutex::new(Box::new(FilesystemDriver::new("registry/blobs")));

    let state = Arc::new(AppState::new(pool, storage_driver));

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let app = NormalizePathLayer::trim_trailing_slash().layer(Router::new()
        .nest("/v2", Router::new()
            .route("/", routing::get(api::version_check))
            .route("/_catalog", routing::get(api::catalog::list_repositories))
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
                .delete(api::manifests::delete_manifest))
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    debug!("Starting http server, listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}