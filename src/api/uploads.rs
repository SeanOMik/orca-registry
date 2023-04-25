use std::collections::HashMap;
use std::sync::Arc;

use axum::http::{StatusCode, header, HeaderName};
use axum::extract::{Path, BodyStream, State, Query};
use axum::response::{IntoResponse, Response};

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use tracing::{debug, warn};

use crate::app_state::AppState;

/// Starting an upload
pub async fn start_upload_post(Path((name, )): Path<(String, )>) -> impl IntoResponse {
    debug!("Upload starting");
    let uuid = uuid::Uuid::new_v4();

    debug!("Requesting upload of image {}, generated uuid: {}", name, uuid);

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid.to_string());
    debug!("Constructed upload url: {}", location);

    (
        StatusCode::ACCEPTED,
        [ (header::LOCATION, location) ]
    )
}

pub async fn chunked_upload_layer_patch(Path((name, layer_uuid)): Path<(String, String)>, state: State<Arc<AppState>>, mut body: BodyStream) -> Response {
    let storage = state.storage.lock().await;
    let current_size = storage.digest_length(&layer_uuid).await.unwrap();

    let written_size = match /* storage.supports_streaming() */ false {
        true => {
            // TODO: Make less bad
            let sender = storage.start_stream_channel();
            let mut written_size = 0;
            while let Some(item) = body.next().await {
                if let Ok(bytes) = item {
                    written_size += bytes.len();
                    sender.send((layer_uuid.clone(), bytes)).await.unwrap();
                }
            }

            written_size
        },
        false => {
            warn!("This storage driver does not support streaming! This means high memory usage during image pushes!");

            let mut bytes = BytesMut::new();
            while let Some(item) = body.next().await {
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

    let full_uri = format!("{}/v2/{}/blobs/uploads/{}", crate::REGISTRY_URL, name, layer_uuid);
    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, full_uri),
            (header::RANGE, format!("{}-{}", starting, ending)),
            (header::CONTENT_LENGTH, "0".to_string()),
            (HeaderName::from_static("docker-upload-uuid"), layer_uuid)
        ]
    ).into_response()
}

pub async fn finish_chunked_upload_put(Path((name, layer_uuid)): Path<(String, String)>, Query(query): Query<HashMap<String, String>>, state: State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    let digest = query.get("digest").unwrap();

    let storage = state.storage.lock().await;
    if !body.is_empty() {
        storage.save_digest(&layer_uuid, &body, true).await.unwrap();
    } else {
        // TODO: Validate layer with all digest params
    }

    storage.replace_digest(&layer_uuid, &digest).await.unwrap();
    debug!("Completed upload, finished uuid {} to digest {}", layer_uuid, digest);

    (
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{}/blobs/{}", name, digest)),
            (header::CONTENT_LENGTH, "0".to_string()),
            (HeaderName::from_static("docker-upload-digest"), digest.to_owned())
        ]
    )
}

pub async fn cancel_upload_delete(Path((name, layer_uuid)): Path<(String, String)>, state: State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    storage.delete_digest(&layer_uuid).await.unwrap();
    
    // I'm not sure what this response should be, its not specified in the registry spec.
    StatusCode::OK
}

pub async fn check_upload_status_get(Path((name, layer_uuid)): Path<(String, String)>, state: State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    let ending = storage.digest_length(&layer_uuid).await.unwrap().unwrap_or(0);

    (
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{}/blobs/uploads/{}", name, layer_uuid)),
            (header::RANGE, format!("0-{}", ending)),
            (HeaderName::from_static("docker-upload-digest"), layer_uuid)
        ]
    )
}