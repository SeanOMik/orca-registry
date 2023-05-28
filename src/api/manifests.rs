use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, State};
use axum::response::{Response, IntoResponse};
use axum::http::{StatusCode, HeaderMap, HeaderName, header};
use tracing::log::warn;
use tracing::{debug, info};

use crate::auth_storage::{unauthenticated_response, AuthDriver};
use crate::app_state::AppState;
use crate::database::Database;
use crate::dto::RepositoryVisibility;
use crate::dto::digest::Digest;
use crate::dto::manifest::Manifest;
use crate::dto::user::{UserAuth, Permission};

pub async fn upload_manifest_put(Path((name, reference)): Path<(String, String)>, state: State<Arc<AppState>>, Extension(auth): Extension<UserAuth>, body: String) -> Response {
    let auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PUSH, None).await.unwrap() {
        return unauthenticated_response(&state.config);
    }
    drop(auth_driver);

    // Calculate the sha256 digest for the manifest.
    let calculated_hash = sha256::digest(body.clone());
    let calculated_digest = format!("sha256:{}", calculated_hash);

    let database = &state.database;

    // Create the image repository and save the image manifest. This repository will be private by default
    database.save_repository(&name, RepositoryVisibility::Private, None).await.unwrap();
    database.save_manifest(&name, &calculated_digest, &body).await.unwrap();

    // If the reference is not a digest, then it must be a tag name.
    if !Digest::is_digest(&reference) {
        database.save_tag(&name, &reference, &calculated_digest).await.unwrap();
    }

    info!("Saved manifest {}", calculated_digest);

    match serde_json::from_str(&body).unwrap() {
        Manifest::Image(image) => {
            // Link the manifest to the image layer
            database.link_manifest_layer(&calculated_digest, &image.config.digest).await.unwrap();
            debug!("Linked manifest {} to layer {}", calculated_digest, image.config.digest);

            for layer in image.layers {
                database.link_manifest_layer(&calculated_digest, &layer.digest).await.unwrap();
                debug!("Linked manifest {} to layer {}", calculated_digest, image.config.digest);
            }

            (
                StatusCode::CREATED,
                [ (HeaderName::from_static("docker-content-digest"), calculated_digest) ]
            ).into_response()
        },
        Manifest::List(_list) => {
            warn!("ManifestList request was received!");

            StatusCode::NOT_IMPLEMENTED.into_response()
        }
    }
}

pub async fn pull_manifest_get(Path((name, reference)): Path<(String, String)>, state: State<Arc<AppState>>, Extension(auth): Extension<UserAuth>) -> Response {
    // Check if the user has permission to pull, or that the repository is public
    let auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PULL, Some(RepositoryVisibility::Public)).await.unwrap() {
        return unauthenticated_response(&state.config);
    }
    drop(auth_driver);
    
    let database = &state.database;
    let digest = match Digest::is_digest(&reference) {
        true => reference.clone(),
        false => {
            debug!("Attempting to get manifest digest using tag (repository={}, reference={})", name, reference);
            if let Some(tag) = database.get_tag(&name, &reference).await.unwrap() {
                tag.manifest_digest
            } else {
                return StatusCode::NOT_FOUND.into_response();
            }
        }
    };

    let manifest_content = database.get_manifest(&name, &digest).await.unwrap();
    if manifest_content.is_none() {
        debug!("Failed to get manifest in repo {}, for digest {}", name, digest);
        // The digest that was provided in the request was invalid.
        // NOTE: This could also mean that there's a bug and the tag pointed to an invalid manifest.
        return StatusCode::NOT_FOUND.into_response();
    }
    let manifest_content = manifest_content.unwrap();

    (
        StatusCode::OK,
        [
            (HeaderName::from_static("docker-content-digest"), digest),
            (header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json".to_string()),
            (header::CONTENT_LENGTH, manifest_content.len().to_string()),
            (header::ACCEPT, "application/vnd.docker.distribution.manifest.v2+json".to_string()),
            (HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string()),
        ],
        manifest_content
    ).into_response()
}

pub async fn manifest_exists_head(Path((name, reference)): Path<(String, String)>, state: State<Arc<AppState>>, Extension(auth): Extension<UserAuth>) -> Response {
    // Check if the user has permission to pull, or that the repository is public
    let auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PULL, Some(RepositoryVisibility::Public)).await.unwrap() {
        return unauthenticated_response(&state.config);
    }
    drop(auth_driver);
    
    // Get the digest from the reference path.
    let database = &state.database;
    let digest = match Digest::is_digest(&reference) {
        true => reference.clone(),
        false => {
            if let Some(tag) = database.get_tag(&name, &reference).await.unwrap() {
                tag.manifest_digest
            } else {
                return StatusCode::NOT_FOUND.into_response();
            }
        }
    };

    let manifest_content = database.get_manifest(&name, &digest).await.unwrap();
    if manifest_content.is_none() {
        // The digest that was provided in the request was invalid.
        // NOTE: This could also mean that there's a bug and the tag pointed to an invalid manifest.
        return StatusCode::NOT_FOUND.into_response();
    }
    let manifest_content = manifest_content.unwrap();

    (
        StatusCode::OK,
        [
            (HeaderName::from_static("docker-content-digest"), digest),
            (header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json".to_string()),
            (header::CONTENT_LENGTH, manifest_content.len().to_string()),
            (HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string()),
        ],
        manifest_content
    ).into_response()
}

pub async fn delete_manifest(Path((name, reference)): Path<(String, String)>, headers: HeaderMap, state: State<Arc<AppState>>, Extension(auth): Extension<UserAuth>) -> Response {
    let auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PUSH, None).await.unwrap() {
        return unauthenticated_response(&state.config);
    }
    drop(auth_driver);
    
    let _authorization = headers.get("Authorization").unwrap(); // TODO: use authorization header

    let database = &state.database;
    let digest = match Digest::is_digest(&reference) {
        true => {
            // Check if the manifest exists
            if database.get_manifest(&name, &reference).await.unwrap().is_none() {
                return StatusCode::NOT_FOUND.into_response();
            }

            reference.clone()
        },
        false => {
            if let Some(tag) = database.get_tag(&name, &reference).await.unwrap() {
                tag.manifest_digest
            } else {
                return StatusCode::NOT_FOUND.into_response();
            }
        }
    };

    database.delete_manifest(&name, &digest).await.unwrap();

    (
        StatusCode::ACCEPTED,
        [
            (header::CONTENT_LENGTH, "None"),
        ],
    ).into_response()
}