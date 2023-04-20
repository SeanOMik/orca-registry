mod api;
mod app_state;
mod database;
mod dto;
mod storage;

use std::sync::Arc;

use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;

use bytes::Bytes;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, Level};

use app_state::AppState;
use database::Database;

use crate::storage::StorageDriver;
use crate::storage::filesystem::{FilesystemDriver, FilesystemStreamer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(15)
        .connect("test.db").await.unwrap();

    pool.create_schema().await.unwrap();

    let storage_path = String::from("registry/blobs");
    let (send, recv) = mpsc::channel::<(String, Bytes)>(50);
    let storage_driver: Mutex<Box<dyn StorageDriver>> = Mutex::new(Box::new(FilesystemDriver::new(storage_path.clone(), send)));

    // create the storage streamer
    {
        let path_clone = storage_path.clone();
        actix_rt::spawn(async {
            let mut streamer = FilesystemStreamer::new(path_clone, recv);
            streamer.start_handling_streams().await.unwrap();
        });
    }

    let state = web::Data::new(AppState::new(pool, storage_driver));

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    // TODO: Make configurable by deployment
    let payload_config = web::PayloadConfig::new(5 * 1024 * 1024 * 1024); // 5Gb 

    debug!("Starting http server...");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(state.clone())
            .app_data(payload_config.clone())
            .service(
                web::scope("/v2")
                    .service(api::version_check)
                    .service(
                        web::scope("/_catalog")
                            .service(api::catalog::list_repositories)
                    )
                    .service(
                        web::scope("/{name}")
                            .service(
                                web::scope("/tags")
                                    .service(api::tags::list_tags)
                            )
                            .service(
                                web::scope("/manifests")
                                    .service(api::manifests::upload_manifest)
                                    .service(api::manifests::pull_manifest)
                                    .service(api::manifests::manifest_exists)
                                    .service(api::manifests::delete_manifest) // delete image
                            )
                            .service(
                                web::scope("/blobs")
                                    .service(api::blobs::digest_exists)
                                    .service(api::blobs::pull_digest)
                                    .service(api::blobs::delete_digest)
                                    .service(
                                        web::scope("/uploads")
                                            .service(api::uploads::start_upload)
                                            .service(api::uploads::chunked_upload_layer)
                                            .service(api::uploads::finish_chunked_upload)
                                            .service(api::uploads::cancel_upload)
                                            .service(api::uploads::check_upload_status)
                                            // TODO: Cross Repository Blob Mount
                                    )
                            )
                        
                    )
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}