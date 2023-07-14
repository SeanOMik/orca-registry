mod api;
mod app_state;
mod database;
mod dto;
mod storage;
mod byte_stream;
mod config;
mod auth;
mod error;

use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use auth::{AuthDriver, ldap_driver::LdapAuthDriver};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::{Router, routing};
use axum::ServiceExt;
use axum_server::tls_rustls::RustlsConfig;
use lazy_static::lazy_static;
use regex::Regex;
use tokio::fs::File;
use tower_layer::Layer;

use sqlx::sqlite::{SqlitePoolOptions, SqliteConnectOptions, SqliteJournalMode};
use tokio::sync::Mutex;
use tower_http::normalize_path::NormalizePathLayer;
use tracing::{debug, info};

use app_state::AppState;
use database::Database;

use crate::storage::StorageDriver;
use crate::storage::filesystem::FilesystemDriver;

use crate::config::{Config, DatabaseConfig, StorageConfig};

use tower_http::trace::TraceLayer;

lazy_static! {
    static ref REGISTRY_URL_REGEX: Regex = regex::Regex::new(r"/v2/([\w\-_./]+)/(blobs|tags|manifests)").unwrap();
}

/// Encode the 'name' path parameter in the url
async fn change_request_paths<B>(mut request: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    // Attempt to find the name using regex in the url
    let regex = &REGISTRY_URL_REGEX;
    let captures = match regex.captures(request.uri().path()) {
        Some(captures) => captures,
        None => return Ok(next.run(request).await),
    };

    // Find the name in the request and encode it in the url
    let name = captures.get(1).unwrap().as_str().to_string();
    let encoded_name = name.replace('/', "%2F");

    // Replace the name in the uri
    let uri_str = request.uri().to_string().replace(&name, &encoded_name);
    debug!("Rewrote request url to: '{}'", uri_str);

    *request.uri_mut() = uri_str.parse()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(next.run(request).await)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::new()
        .expect("Failure to parse config!");

    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .init();

    let sqlite_config = match &config.database {
        DatabaseConfig::Sqlite(sqlite) => sqlite,
    };

    // Create a database file if it doesn't exist already
    if !Path::new(&sqlite_config.path).exists() {
        File::create(&sqlite_config.path).await?;
    }
    
    let connection_options = SqliteConnectOptions::from_str(&format!("sqlite://{}", &sqlite_config.path))?
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(15)
        .connect_with(connection_options).await?;
    pool.create_schema().await?;

    let storage_driver: Mutex<Box<dyn StorageDriver>> = match &config.storage {
        StorageConfig::Filesystem(fs) => {
            Mutex::new(Box::new(FilesystemDriver::new(&fs.path)))
        }
    };
    
    // figure out the auth driver depending on whats specified in the config,
    // the fallback is a database auth driver.
    let auth_driver: Mutex<Box<dyn AuthDriver>> = match config.ldap.clone() {
        Some(ldap) => {
            let ldap_driver = LdapAuthDriver::new(ldap, pool.clone()).await?;
            Mutex::new(Box::new(ldap_driver))
        },
        None => {
            Mutex::new(Box::new(pool.clone()))
        }
    };

    let app_addr = SocketAddr::from_str(&format!("{}:{}", config.listen_address, config.listen_port))?;

    let tls_config = config.tls.clone();
    let state = Arc::new(AppState::new(pool, storage_driver, config, auth_driver));
   
    //let auth_middleware = axum::middleware::from_fn_with_state(state.clone(), auth::require_auth);
    let auth_middleware = axum::middleware::from_fn_with_state(state.clone(), auth::check_auth);
    let path_middleware = axum::middleware::from_fn(change_request_paths);

    let app = Router::new()
        .route("/auth", routing::get(api::auth::auth_basic_get)
            .post(api::auth::auth_basic_get))
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
            .layer(auth_middleware) // require auth for ALL v2 routes
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let layered_app = NormalizePathLayer::trim_trailing_slash().layer(path_middleware.layer(app));

    match tls_config {
        Some(tls) if tls.enable => {
            info!("Starting https server, listening on {}", app_addr);
        
            let config = RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;

            axum_server::bind_rustls(app_addr, config)
                .serve(layered_app.into_make_service())
                .await?;
        },
        _ => {
            info!("Starting http server, listening on {}", app_addr);
            axum::Server::bind(&app_addr)
                .serve(layered_app.into_make_service())
                .await?;
        }
    }

    Ok(())
}