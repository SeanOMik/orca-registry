use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tracing::{debug, error, info};

use crate::app_state::AppState;
use crate::database::Database;
use crate::dto::digest::Digest;
use crate::dto::manifest::{Manifest, Referrer};
use crate::dto::user::UserAuth;
use crate::dto::RepositoryVisibility;
use crate::error::{AppError, OciRegistryError};

pub async fn upload_manifest_put(
    Path((name, reference)): Path<(String, String)>,
    state: State<Arc<AppState>>,
    auth: UserAuth,
    body: String,
) -> Result<Response, AppError> {
    // enforce manifest size limit
    if body.len() > state.config.limits.manifest_limit {
        debug!("Rejecting manifest since its is larger than the limit: {} > {}", body.len(), state.config.limits.manifest_limit);
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }

    // Calculate the sha256 digest for the manifest.
    let calculated_hash = sha256::digest(body.clone());
    let calculated_digest = format!("sha256:{}", calculated_hash);

    // anonymous users wouldn't be able to get to this point, so it should be safe to unwrap.
    let user = auth.user.unwrap();
    let database = &state.database;
    let storage = &state.storage;

    // if the manifest already exists, respond now and don't try to make it again.
    if storage.lock().await.get_manifest(&name, &calculated_digest)
        .await?
        .is_some()
    {
        if !Digest::is_digest(&reference) && storage.lock().await.get_tag(&name, &reference).await?.map(|t| t.manifest_digest != calculated_digest).unwrap_or(true) {
            storage.lock().await
                .save_tag(&name, &reference, &calculated_digest)
                .await?;
        }

        // no need to check the contents of the manifest since the calculated_digest
        // will match the content of it.
        return Ok((
            StatusCode::CREATED,
            [
                (
                    HeaderName::from_static("docker-content-digest"),
                    calculated_digest,
                ),
                (
                    header::LOCATION,
                    format!("/v2/{name}/manifests/{reference}"),
                ),
            ],
        )
            .into_response());
    }

    let manifest = serde_json::from_str(&body)
        .map_err(|e| {
            debug!("Manifest deserialize error: {e}");
            OciRegistryError::ManifestInvalid
        })?;

    match manifest {
        Manifest::Image(image) => {
            let subject_digest = image.subject.as_ref().map(|s| &s.digest);

            // Create the image repository and save the image manifest. This repository will be private by default
            database
                .save_repository(&name, RepositoryVisibility::Private, Some(user.email), None)
                .await?;
            storage.lock().await
                .save_manifest(&name, &calculated_digest, &body, subject_digest)
                .await?;

            debug!("Saved ImageManifest {calculated_digest}");

            // If the reference is not a digest, then it must be a tag name.
            if !Digest::is_digest(&reference) {
                debug!("Tagging manifest as {reference}");

                storage.lock().await
                    .save_tag(&name, &reference, &calculated_digest)
                    .await?;
            }

            if let Some(subject) = subject_digest {
                debug!("Manifest has a subject, adding this manifest as a referrer to '{}'", subject);

                let storage = state.storage.lock().await;
                let r = Referrer::from_image_manifest(&name, &calculated_digest, &image);
                storage.add_referrer(&subject, r).await?;
            }

            let resp = Response::builder()
                .status(StatusCode::CREATED)
                .header(HeaderName::from_static("docker-content-digest"), calculated_digest)
                .header(header::LOCATION, format!("/v2/{name}/manifests/{reference}"));

            let resp = if let Some(subject) = subject_digest {
                resp.header(HeaderName::from_static("oci-subject"), subject)
            } else { resp };

            Ok(resp.body(Body::default()).unwrap())
        }
        Manifest::Index(index) => {
            let subject_digest = index.subject.as_ref().map(|s| &s.digest);

            // Create the image repository and save the image manifest. This repository will be private by default
            database
                .save_repository(&name, RepositoryVisibility::Private, Some(user.email), None)
                .await?;
            storage.lock().await
                .save_manifest(&name, &calculated_digest, &body, subject_digest)
                .await?;

            debug!("Saved IndexManifest {calculated_digest}");

            // If the reference is not a digest, then it must be a tag name.
            if !Digest::is_digest(&reference) {
                debug!("Tagging manifest as {reference}");
                storage.lock().await
                    .save_tag(&name, &reference, &calculated_digest)
                    .await?;
            }

            if let Some(subject) = subject_digest {
                debug!("Manifest has a subject, adding this manifest as a referrer to '{}'", subject);

                let storage = state.storage.lock().await;
                let r = Referrer::from_index_manifest(&name, &calculated_digest, &index);
                storage.add_referrer(&subject, r).await?;
            }

            let resp = Response::builder()
                .status(StatusCode::CREATED)
                .header(HeaderName::from_static("docker-content-digest"), calculated_digest)
                .header(header::LOCATION, format!("/v2/{name}/manifests/{reference}"));

            let resp = if let Some(subject) = subject_digest {
                resp.header(HeaderName::from_static("oci-subject"), subject)
            } else { resp };

            Ok(resp.body(Body::default()).unwrap())
        }
    }
}

pub async fn pull_manifest_get(
    Path((name, reference)): Path<(String, String)>,
    state: State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let storage = &state.storage;

    let digest = match Digest::is_digest(&reference) {
        true => reference.clone(),
        false => {
            debug!(
                "Attempting to get manifest digest using tag (repository={}, reference={})",
                name, reference
            );
            if let Some(tag) = storage.lock().await.get_tag(&name, &reference).await? {
                tag.manifest_digest
            } else {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }
        }
    };

    let manifest = storage.lock().await.get_manifest(&name, &digest).await?;
    if manifest.is_none() {
        info!("Unknown manifest in repo {} for digest {}", name, digest);
        return Err(OciRegistryError::ManifestUnknown.into());
    }
    let manifest = manifest.unwrap();

    // Find the content type from the manifest
    let content_type = {
        let m = serde_json::from_str::<Manifest>(&manifest)
            .map_err(|e| {
                error!("Failed to serialize manifest retrieved from database: {e}");
                AppError::Internal
            })?;
        m.content_type()
    };

    Ok((
        StatusCode::OK,
        [
            (HeaderName::from_static("docker-content-digest"), digest),
            (
                header::CONTENT_TYPE,
                content_type,
            ),
            (header::CONTENT_LENGTH, manifest.len().to_string()),
            (
                HeaderName::from_static("docker-distribution-api-version"),
                "registry/2.0".to_string(),
            ),
        ],
        manifest,
    )
        .into_response())
}

pub async fn manifest_exists_head(
    Path((name, reference)): Path<(String, String)>,
    state: State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let storage = &state.storage;

    // Get the digest from the reference path.
    let digest = match Digest::is_digest(&reference) {
        true => reference.clone(),
        false => {
            if let Some(tag) = storage.lock().await.get_tag(&name, &reference).await? {
                tag.manifest_digest
            } else {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }
        }
    };
    debug!("found digest: {}", digest);

    let manifest = storage.lock().await.get_manifest(&name, &digest).await?;
    if manifest.is_none() {
        // The digest that was provided in the request was invalid.
        // NOTE: This could also mean that there's a bug and the tag pointed to an invalid manifest.
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let manifest = manifest.unwrap();

    // Find the content type from the manifest
    let content_type = {
        let m = serde_json::from_str::<Manifest>(&manifest)
            .map_err(|e| {
                error!("Failed to serialize manifest retrieved from database: {e}");
                AppError::Internal
            })?;
        m.content_type()
    };

    Ok((
        StatusCode::OK,
        [
            (HeaderName::from_static("docker-content-digest"), digest),
            (
                header::CONTENT_TYPE,
                content_type,
            ),
            (header::CONTENT_LENGTH, manifest.len().to_string()),
            (
                HeaderName::from_static("docker-distribution-api-version"),
                "registry/2.0".to_string(),
            ),
        ],
        manifest,
    )
        .into_response())
}

pub async fn delete_manifest(
    Path((name, reference)): Path<(String, String)>,
    state: State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let storage = &state.storage;
    
    let digest = match Digest::is_digest(&reference) {
        true => {
            // Check if the manifest exists
            if storage.lock().await.get_manifest(&name, &reference).await?.is_none() {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }

            reference.clone()
        }
        false => {
            if let Some(tag) = storage.lock().await.get_tag(&name, &reference).await? {
                tag.manifest_digest
            } else {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }
        }
    };

    storage.lock().await.delete_manifest(&name, &digest).await?;

    Ok((StatusCode::ACCEPTED, [(header::CONTENT_LENGTH, "None")]).into_response())
}
