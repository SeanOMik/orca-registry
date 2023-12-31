use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{Response, IntoResponse};
use axum::http::{StatusCode, HeaderName, header};
use tracing::log::warn;
use tracing::{debug, info};

use crate::app_state::AppState;
use crate::database::Database;
use crate::dto::RepositoryVisibility;
use crate::dto::digest::Digest;
use crate::dto::manifest::Manifest;
use crate::dto::user::UserAuth;
use crate::error::AppError;

pub async fn upload_manifest_put(Path((name, reference)): Path<(String, String)>, state: State<Arc<AppState>>, auth: UserAuth, body: String) -> Result<Response, AppError> {
    // Calculate the sha256 digest for the manifest.
    let calculated_hash = sha256::digest(body.clone());
    let calculated_digest = format!("sha256:{}", calculated_hash);

    // anonymous users wouldn't be able to get to this point, so it should be safe to unwrap.
    let user = auth.user.unwrap();

    let database = &state.database;

    // Create the image repository and save the image manifest. This repository will be private by default
    database.save_repository(&name, RepositoryVisibility::Private, Some(user.email), None).await?;
    database.save_manifest(&name, &calculated_digest, &body).await?;

    // If the reference is not a digest, then it must be a tag name.
    if !Digest::is_digest(&reference) {
        database.save_tag(&name, &reference, &calculated_digest).await?;
    }

    info!("Saved manifest {}", calculated_digest);

    match serde_json::from_str(&body)? {
        Manifest::Image(image) => {
            // Link the manifest to the image layer
            database.link_manifest_layer(&calculated_digest, &image.config.digest).await?;
            debug!("Linked manifest {} to layer {}", calculated_digest, image.config.digest);

            for layer in image.layers {
                database.link_manifest_layer(&calculated_digest, &layer.digest).await?;
                debug!("Linked manifest {} to layer {}", calculated_digest, image.config.digest);
            }

            Ok((
                StatusCode::CREATED,
                [ (HeaderName::from_static("docker-content-digest"), calculated_digest) ]
            ).into_response())
        },
        Manifest::List(_list) => {
            warn!("ManifestList request was received!");

            Ok(StatusCode::NOT_IMPLEMENTED.into_response())
        }
    }
}

pub async fn pull_manifest_get(Path((name, reference)): Path<(String, String)>, state: State<Arc<AppState>>) -> Result<Response, AppError> {
    let database = &state.database;
    let digest = match Digest::is_digest(&reference) {
        true => reference.clone(),
        false => {
            debug!("Attempting to get manifest digest using tag (repository={}, reference={})", name, reference);
            if let Some(tag) = database.get_tag(&name, &reference).await? {
                tag.manifest_digest
            } else {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }
        }
    };

    let manifest_content = database.get_manifest(&name, &digest).await?;
    if manifest_content.is_none() {
        debug!("Failed to get manifest in repo {}, for digest {}", name, digest);
        // The digest that was provided in the request was invalid.
        // NOTE: This could also mean that there's a bug and the tag pointed to an invalid manifest.
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let manifest_content = manifest_content.unwrap();

    debug!("Pulled manifest: {}", manifest_content);

    Ok((
        StatusCode::OK,
        [
            (HeaderName::from_static("docker-content-digest"), digest),
            (header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json".to_string()),
            (header::CONTENT_LENGTH, manifest_content.len().to_string()),
            (header::ACCEPT, "application/vnd.docker.distribution.manifest.v2+json".to_string()),
            (HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string()),
        ],
        manifest_content
    ).into_response())
}

pub async fn manifest_exists_head(Path((name, reference)): Path<(String, String)>, state: State<Arc<AppState>>) -> Result<Response, AppError> {
    debug!("start of head");
    // Get the digest from the reference path.
    let database = &state.database;
    let digest = match Digest::is_digest(&reference) {
        true => reference.clone(),
        false => {
            if let Some(tag) = database.get_tag(&name, &reference).await? {
                tag.manifest_digest
            } else {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }
        }
    };
    debug!("found digest: {}", digest);

    let manifest_content = database.get_manifest(&name, &digest).await?;
    if manifest_content.is_none() {
        // The digest that was provided in the request was invalid.
        // NOTE: This could also mean that there's a bug and the tag pointed to an invalid manifest.
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let manifest_content = manifest_content.unwrap();

    debug!("got content");

    Ok((
        StatusCode::OK,
        [
            (HeaderName::from_static("docker-content-digest"), digest),
            (header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json".to_string()),
            (header::CONTENT_LENGTH, manifest_content.len().to_string()),
            (HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string()),
        ],
        manifest_content
    ).into_response())
}

pub async fn delete_manifest(Path((name, reference)): Path<(String, String)>, state: State<Arc<AppState>>) -> Result<Response, AppError> {
    let database = &state.database;
    let digest = match Digest::is_digest(&reference) {
        true => {
            // Check if the manifest exists
            if database.get_manifest(&name, &reference).await?.is_none() {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }

            reference.clone()
        },
        false => {
            if let Some(tag) = database.get_tag(&name, &reference).await? {
                tag.manifest_digest
            } else {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }
        }
    };

    database.delete_manifest(&name, &digest).await?;

    Ok((
        StatusCode::ACCEPTED,
        [
            (header::CONTENT_LENGTH, "None"),
        ],
    ).into_response())
}