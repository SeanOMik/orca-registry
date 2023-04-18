use actix_web::{HttpResponse, HttpRequest, post, web, patch, put, delete, get};
use bytes::{BytesMut, Bytes, BufMut};
use qstring::QString;
use tokio::io::AsyncWriteExt;
use tracing::{debug};

use crate::app_state::AppState;

use crate::database::Database;
use crate::storage::filesystem::FilesystemDriver;

/// Starting an upload
#[post("/")]
pub async fn start_upload(path: web::Path<(String, )>) -> HttpResponse {
    debug!("Upload starting");
    let name = path.0.to_owned();
    let uuid = uuid::Uuid::new_v4();

    debug!("Requesting upload of image {}, generated uuid: {}", name, uuid);

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid.to_string());
    debug!("Constructed upload url: {}", location);

    HttpResponse::Accepted()
        .insert_header(("Location", location))
        .finish()
}

#[patch("/{uuid}")]
pub async fn chunked_upload_layer(body: Bytes, path: web::Path<(String, String)>, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let full_uri = req.uri().to_string();
    let (_name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());

    debug!("Read body of size: {}", body.len());

    let storage = state.storage.lock().await;

    let current_size = storage.digest_length(&layer_uuid).await.unwrap();
    let (starting, ending) = if let Some(current_size) = current_size {
        let body_size = body.len();

        storage.save_digest(&layer_uuid, &body, true).await.unwrap();

        (current_size, current_size + body_size)
    } else {
        let body_size = body.len();

        storage.save_digest(&layer_uuid, &body, true).await.unwrap();

        (0, body_size)
    };

    debug!("s={}, e={}, uuid={}, uri={}", starting, ending, layer_uuid, full_uri);

    HttpResponse::Accepted()
        .insert_header(("Location", full_uri))
        .insert_header(("Range", format!("{}-{}", starting, ending)))
        .insert_header(("Content-Length", 0))
        .insert_header(("Docker-Upload-UUID", layer_uuid))
        .finish()
}

#[put("/{uuid}")]
pub async fn finish_chunked_upload(body: Bytes, path: web::Path<(String, String)>, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let (name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());

    let qs = QString::from(req.query_string());
    let digest = qs.get("digest").unwrap();

    let storage = state.storage.lock().await;
    if !body.is_empty() {
        storage.save_digest(&layer_uuid, &body, true).await.unwrap();
    } else {
        // TODO: Validate layer with all digest params
    }

    storage.replace_digest(&layer_uuid, &digest).await.unwrap();
    debug!("Completed upload, finished uuid {} to digest {}", layer_uuid, digest);

    HttpResponse::Created()
        .insert_header(("Location", format!("/v2/{}/blobs/{}", name, digest)))
        .insert_header(("Content-Length", 0))
        .insert_header(("Docker-Upload-Digest", digest))
        .finish()
}

#[delete("/{uuid}")]
pub async fn cancel_upload(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (_name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());

    let storage = state.storage.lock().await;
    storage.delete_digest(&layer_uuid).await.unwrap();
    
    // I'm not sure what this response should be, its not specified in the registry spec.
    HttpResponse::Ok()
        .finish()
}

#[get("/{uuid}")]
pub async fn check_upload_status(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());
    
    let storage = state.storage.lock().await;
    let ending = storage.digest_length(&layer_uuid).await.unwrap().unwrap_or(0);

    HttpResponse::Created()
        .insert_header(("Location", format!("/v2/{}/blobs/uploads/{}", name, layer_uuid)))
        .insert_header(("Range", format!("0-{}", ending)))
        .insert_header(("Docker-Upload-Digest", layer_uuid))
        .finish()
}