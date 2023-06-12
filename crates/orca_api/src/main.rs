mod api;
mod app_state;
mod database;
mod dto;
mod storage;
mod byte_stream;
mod config;
mod auth;
mod error;

use std::{fs, io};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
use tracing::metadata::LevelFilter;
use tracing::{debug, info};

use app_state::AppState;
use database::Database;
use tracing_subscriber::{filter, EnvFilter};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth::static_driver::StaticAuthDriver;
use crate::dto::user::Permission;
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

/// Create directory tree up to the file in `path`.
fn create_path_to(path: &str) -> io::Result<()> {
    let path = PathBuf::from(path);

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config = Config::new()
        .expect("Failure to parse config!");

    let mut logging_guards = Vec::new();
    {
        let logc = &config.log;

        // Create log directory if it doesn't exist
        let log_path = &logc.path;
        create_path_to(&log_path)?;

        // Get a rolling file appender depending on the config
        let file_appender = match logc.roll_period {
            config::RollPeriod::Minutely => tracing_appender::rolling::minutely(log_path, "orca.log"),
            config::RollPeriod::Hourly => tracing_appender::rolling::hourly(log_path, "orca.log"),
            config::RollPeriod::Daily => tracing_appender::rolling::daily(log_path, "orca.log"),
            config::RollPeriod::Never => tracing_appender::rolling::never(log_path, "orca.log"),
        };

        // Create non blocking loggers
        let (file_appender_nb, _file_guard) = tracing_appender::non_blocking(file_appender);
        let (stdout_nb, _stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        logging_guards.push(_file_guard);
        logging_guards.push(_stdout_guard);

        // TODO: Is there a way for this to be less ugly?
        // Get json or text layers
        let (json_a, json_b, plain_a, plain_b) = match logc.format {
            config::LogFormat::Json => (
                Some(
                    tracing_subscriber::fmt::layer()
                        .with_writer(file_appender_nb)
                        .json()
                ),
                Some(
                    tracing_subscriber::fmt::layer()
                        .with_writer(stdout_nb)
                        .json()
                ),
                None,
                None
            ),
            config::LogFormat::Human => (
                None,
                None,
                Some(
                    tracing_subscriber::fmt::layer()
                        .with_writer(file_appender_nb)
                ),
                Some(
                    tracing_subscriber::fmt::layer()
                        .with_writer(stdout_nb)
                )
            )
        };

        // Change filter to only log orca_api or everything
        let targets_filter = if logc.env_filter.is_some() {
            None
        } else {
            Some(
                filter::Targets::new()
                    .with_target("orca_api", logc.level)
                    .with_default(LevelFilter::INFO)
            )
        };

        // Get env filter if specified
        let env_filter = if let Some(env_filter) = &logc.env_filter {
            Some(EnvFilter::from_str(env_filter).unwrap())
        } else { None };

        tracing_subscriber::registry()
            .with(json_a)
            .with(json_b)
            .with(plain_a)
            .with(plain_b)
            .with(targets_filter)
            .with(env_filter)
            .init();
    }

    let sqlite_config = match &config.database {
        DatabaseConfig::Sqlite(sqlite) => sqlite,
    };

    // Create a database file if it doesn't exist already
    if !Path::new(&sqlite_config.path).exists() {
        create_path_to(&sqlite_config.path)?;
        File::create(&sqlite_config.path).await?;
    }
    
    let connection_options = SqliteConnectOptions::from_str(&format!("sqlite://{}", &sqlite_config.path))?
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(15)
        .connect_with(connection_options).await?;
    pool.create_schema().await?;

    {
        let mut driver = StaticAuthDriver::from_file(&config.path.clone().unwrap()).unwrap();

        if driver.verify_user_login("admin".to_string(), "test1234".to_string()).await? {
            info!("LOGGED IN!");

            if driver.user_has_permission("admin".to_string(), "admin/alpine".to_string(), Permission::PULL, None).await? {
                info!("user can do that!")
            } else {
                info!("user can not do that :(")
            }
        } else {
            info!("not logged in :(");
        }
        
    }

    {
        let mut driver = StaticAuthDriver::from_file(&config.path.clone().unwrap()).unwrap();

        if driver.verify_user_login("admin".to_string(), "test1234".to_string()).await? {
            info!("LOGGED IN!");

            if driver.user_has_permission("admin".to_string(), "admin/alpine".to_string(), Permission::PULL, None).await? {
                info!("user can do that!")
            } else {
                info!("user can not do that :(")
            }
        } else {
            info!("not logged in :(");
        }
        
    }

    // set jwt key
    config.jwt_key = pool.get_jwt_secret().await?;

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
   
    let auth_middleware = axum::middleware::from_fn_with_state(state.clone(), auth::check_auth);
    let path_middleware = axum::middleware::from_fn(change_request_paths);
    
    let app = Router::new()
        .route("/token", routing::get(api::oci::auth::auth_basic_get)
            .post(api::oci::auth::auth_basic_post))
        .nest("/v2", Router::new()
            .route("/", routing::get(api::oci::version_check))
            .route("/_catalog", routing::get(api::oci::catalog::list_repositories))
            .route("/:name/referrers/:digest", routing::get(api::oci::referrers::list_referrers_get))
            .route("/:name/tags/list", routing::get(api::oci::tags::list_tags))
            .nest("/:name/blobs", Router::new()
                .route("/:digest", routing::get(api::oci::blobs::pull_digest_get)
                    .head(api::oci::blobs::digest_exists_head)
                    .delete(api::oci::blobs::delete_digest))
                .nest("/uploads", Router::new()
                    .route("/", routing::post(api::oci::uploads::start_upload_post))
                    .route("/:uuid", routing::patch(api::oci::uploads::chunked_upload_layer_patch)
                        .put(api::oci::uploads::finish_chunked_upload_put)
                        .delete(api::oci::uploads::cancel_upload_delete)
                        .get(api::oci::uploads::check_upload_status_get)
                    )
                )
            )
            .route("/:name/manifests/:reference", routing::get(api::oci::manifests::pull_manifest_get)
                .put(api::oci::manifests::upload_manifest_put)
                .head(api::oci::manifests::manifest_exists_head)
                .delete(api::oci::manifests::delete_manifest))
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