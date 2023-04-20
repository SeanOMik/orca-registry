use actix_web::{HttpResponse, HttpRequest, post, web, patch, put, delete, get};
use bytes::{BytesMut, Bytes, BufMut};
use futures::{StreamExt, TryStreamExt};
use qstring::QString;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use crate::app_state::AppState;

use crate::database::Database;
use crate::storage::{StorageDriver, StorageDriverStreamer};

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
pub async fn chunked_upload_layer(/* body: Bytes */mut payload: web::Payload, path: web::Path<(String, String)>, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let full_uri = req.uri().to_string();
    let (_name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());

    let storage = state.storage.lock().await;
    let current_size = storage.digest_length(&layer_uuid).await.unwrap();

    let written_size = match storage.supports_streaming() {
        true => {
            let sender = storage.start_stream_channel();
            let mut written_size = 0;
            while let Some(item) = payload.next().await {
                if let Ok(bytes) = item {
                    written_size += bytes.len();
                    sender.send((layer_uuid.clone(), bytes)).await.unwrap();
                }
            }

            written_size
        },
        false => {
            warn!("This storage driver does not support streaming! This means high memory usage during image pushes!");

            let mut bytes = web::BytesMut::new();
            while let Some(item) = payload.next().await {
                bytes.extend_from_slice(&item.unwrap());
            }

            let bytes_len = bytes.len();
            storage.save_digest(&layer_uuid, &bytes.into(), true).await.unwrap();
            bytes_len
        }
    };

    let (starting, ending) = if let Some(current_size) = current_size {
        (current_size, current_size + written_size)
    } else {
        (0, written_size)
    };

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