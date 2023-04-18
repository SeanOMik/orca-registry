mod api;
mod app_state;
mod database;
mod dto;

use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;

use sqlx::sqlite::SqlitePoolOptions;
use tracing::{debug, Level};

use app_state::AppState;
use database::Database;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("test.db").await.unwrap();

    pool.create_schema().await.unwrap();

    //let db_conn: Mutex<dyn Database> = Mutex::new(SqliteConnection::establish("test.db").unwrap());
    //let db = Mutex::new(Database::new_sqlite_connection("test.db").unwrap());
    let state = web::Data::new(AppState::new(pool));

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let payload_config = web::PayloadConfig::new(31_460_000); // 30mb

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
                                    .service(api::manifests::delete_manifest)
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