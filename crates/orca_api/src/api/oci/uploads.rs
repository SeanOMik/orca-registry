use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;

use axum::extract::{BodyStream, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use tracing::{debug, warn};

use crate::app_state::AppState;
use crate::byte_stream::ByteStream;
use crate::error::{AppError, OciRegistryError};

/// Starting an upload
pub async fn start_upload_post(Path((name,)): Path<(String,)>) -> Result<Response, AppError> {
    let uuid = uuid::Uuid::new_v4();
    debug!(
        "Requesting upload of image {}, generated session id: {}",
        name, uuid
    );

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid.to_string());
    debug!("Constructed upload url: {}", location);

    return Ok((StatusCode::ACCEPTED, [(header::LOCATION, location)]).into_response());
}

pub async fn chunked_upload_layer_patch(
    Path((name, layer_uuid)): Path<(String, String)>,
    headers: HeaderMap,
    state: State<Arc<AppState>>,
    mut body: BodyStream,
) -> Result<Response, AppError> {
    let storage = state.storage.lock().await;
    let current_size = storage.digest_length(&layer_uuid).await?;

    // verify request range is correct
    // this ensures that out-of-order uploads are not attempted, and that
    // previous blobs are not overwritten
    if let Some(range) = headers.get("content-range") {
        let range = range.to_str().map_err(|_| AppError::BadRequest)?;
        let (start, end) = range.split_once("-").ok_or(AppError::BadRequest)?;

        let start = start.parse::<usize>().map_err(|_| AppError::BadRequest)?;
        let end = end.parse::<usize>().map_err(|_| AppError::BadRequest)?;

        let current_size = current_size.unwrap_or(0);
        if start != current_size {
            debug!(
                "Out-of-order blob upload caught, range: {}-{}, current size: {}",
                start, end, current_size
            );
            return Ok(StatusCode::RANGE_NOT_SATISFIABLE.into_response());
        }
    }

    let written_size = match storage.supports_streaming().await {
        true => {
            // ByteStream takes a stream of Item, io::Error so this stream needs to be converted to that
            let io_stream = async_stream::stream! {
                while let Some(bytes) = body.next().await {
                    yield match bytes {
                        Ok(b) => Ok(b),
                        Err(e) => Err(std::io::Error::new(ErrorKind::Other, e))
                    };
                }
            };

            let byte_stream = ByteStream::new(io_stream);
            let len = storage
                .save_digest_stream(&layer_uuid, byte_stream, true)
                .await?;

            len
        }
        false => {
            warn!("This storage driver does not support streaming! This means high memory usage during image pushes!");

            let mut bytes = BytesMut::new();
            while let Some(item) = body.next().await {
                let item = item.map_err(|_| OciRegistryError::BlobUploadInvalid)?;
                bytes.extend_from_slice(&item);
            }

            let bytes_len = bytes.len();
            storage
                .save_digest(&layer_uuid, &bytes.into(), true)
                .await?;
            bytes_len
        }
    };

    let ending = if let Some(current_size) = current_size {
        current_size + written_size
    } else {
        written_size
    };

    if let Some(content_length) = headers.get(header::CONTENT_LENGTH) {
        let content_length = content_length.to_str().map(|cl| cl.parse::<usize>());

        if let Ok(Ok(content_length)) = content_length {
            debug!("Client specified a content length of {}", content_length);

            if content_length != written_size {
                warn!("The content length that was received from the client did not match the amount written to disk!");
            }
        }
    }

    let full_uri = format!(
        "{}/v2/{}/blobs/uploads/{}",
        state.config.url(),
        name,
        layer_uuid
    );
    Ok((
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, full_uri),
            (header::RANGE, format!("0-{}", ending - 1)),
            (header::CONTENT_LENGTH, "0".to_string()),
            (HeaderName::from_static("docker-upload-uuid"), layer_uuid),
        ],
    )
        .into_response())
}

pub async fn finish_chunked_upload_put(
    Path((name, layer_uuid)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    state: State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, AppError> {
    let digest = query.get("digest").unwrap();

    let storage = state.storage.lock().await;
    if !body.is_empty() {
        storage.save_digest(&layer_uuid, &body, true).await?;
    } else {
        // TODO: Validate layer with all digest params
    }

    storage.replace_digest(&layer_uuid, &digest).await?;
    debug!(
        "Completed upload, finished uuid {} to digest {}",
        layer_uuid, digest
    );

    Ok((
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{}/blobs/{}", name, digest)),
            (header::CONTENT_LENGTH, "0".to_string()),
            (
                HeaderName::from_static("docker-upload-digest"),
                digest.to_owned(),
            ),
        ],
    )
        .into_response())
}

pub async fn cancel_upload_delete(
    Path((_name, layer_uuid)): Path<(String, String)>,
    state: State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let storage = state.storage.lock().await;
    storage.delete_digest(&layer_uuid).await?;

    // I'm not sure what this response should be, its not specified in the registry spec.
    Ok(StatusCode::OK.into_response())
}

pub async fn check_upload_status_get(
    Path((name, layer_uuid)): Path<(String, String)>,
    state: State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let storage = state.storage.lock().await;
    if let Some(len) = storage.digest_length(&layer_uuid).await? {
        Ok((
            StatusCode::NO_CONTENT,
            [
                (
                    header::LOCATION,
                    format!("/v2/{}/blobs/uploads/{}", name, layer_uuid),
                ),
                (header::RANGE, format!("0-{}", len - 1)),
                // must always be zero, per the spec
                (header::CONTENT_LENGTH, "0".to_string()),
                //(HeaderName::from_static("Blob-Upload-Session-ID"), layer_uuid)
            ],
        )
            .into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}
