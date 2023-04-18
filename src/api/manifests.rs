use actix_web::{HttpResponse, HttpRequest, web, put, get, head};
use tracing::log::warn;
use tracing::{debug, trace, info};

use crate::app_state::AppState;

use crate::database::Database;
use crate::dto::digest::Digest;
use crate::dto::manifest::{Manifest, ImageManifest};

#[put("/{reference}")]
pub async fn upload_manifest(path: web::Path<(String, String)>, body: String, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let (name, reference) = (path.0.to_owned(), path.1.to_owned());

    // Calculate the sha256 digest for the manifest.
    let calculated_hash = sha256::digest(body.clone());
    let calculated_digest = format!("sha256:{}", calculated_hash);

    let database = &state.database;

    // Create the image repository and save the image manifest.
    database.save_repository(&name).await.unwrap();
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

            HttpResponse::Created()
                .append_header(("Docker-Content-Digest", calculated_digest))
                .finish()
        },
        Manifest::List(_list) => {
            warn!("ManifestList request was received!");

            HttpResponse::NotImplemented()
                .finish()
        }
    }
}

#[get("/{reference}")]
pub async fn pull_manifest(path: web::Path<(String, String)>, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let (name, reference) = (path.0.to_owned(), path.1.to_owned());

    let database = &state.database;
    let digest = match Digest::is_digest(&reference) {
        true => reference.clone(),
        false => {
            debug!("Attempting to get manifest digest using tag (name={}, reference={})", name, reference);
            if let Some(tag) = database.get_tag(&name, &reference).await.unwrap() {
                tag.manifest_digest
            } else {
                return HttpResponse::NotFound()
                    .finish();
            }
        }
    };

    let manifest_content = database.get_manifest(&name, &digest).await.unwrap();
    if manifest_content.is_none() {
        debug!("Failed to get manifest in repo {}, for digest {}", name, digest);
        // The digest that was provided in the request was invalid.
        // NOTE: This could also mean that there's a bug and the tag pointed to an invalid manifest.
        return HttpResponse::NotFound()
            .finish();
    }
    let manifest_content = manifest_content.unwrap();

    HttpResponse::Ok()
        .append_header(("Docker-Content-Digest", digest))
        .append_header(("Content-Type", "application/vnd.docker.distribution.manifest.v2+json"))
        .append_header(("Accept", "application/vnd.docker.distribution.manifest.v2+json"))
        .append_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .body(manifest_content)
}

#[head("/{reference}")]
pub async fn manifest_exists(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (name, reference) = (path.0.to_owned(), path.1.to_owned());

    // Get the digest from the reference path.
    let database = &state.database;
    let digest = match Digest::is_digest(&reference) {
        true => reference.clone(),
        false => {
            if let Some(tag) = database.get_tag(&name, &reference).await.unwrap() {
                tag.manifest_digest
            } else {
                return HttpResponse::NotFound()
                    .finish();
            }
        }
    };

    let manifest_content = database.get_manifest(&name, &digest).await.unwrap();
    if manifest_content.is_none() {
        // The digest that was provided in the request was invalid.
        // NOTE: This could also mean that there's a bug and the tag pointed to an invalid manifest.
        return HttpResponse::NotFound()
            .finish();
    }
    let manifest_content = manifest_content.unwrap();

    HttpResponse::Ok()
        .append_header(("Docker-Content-Digest", digest))
        .append_header(("Content-Type", "application/vnd.docker.distribution.manifest.v2+json"))
        .append_header(("Content-Length", manifest_content.len()))
        .append_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .body(manifest_content)
}