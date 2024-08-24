use std::io::ErrorKind;
use std::sync::Arc;

use axum::body::StreamBody;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;
use tracing::debug;

use crate::app_state::AppState;
use crate::error::AppError;

pub async fn digest_exists_head(
    Path((_name, layer_digest)): Path<(String, String)>,
    state: State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let storage = state.storage.lock().await;

    if storage.has_digest(&layer_digest).await? {
        if let Some(size) = storage.digest_length(&layer_digest).await? {
            return Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_LENGTH, size.to_string()),
                    (header::ACCEPT_RANGES, "true".to_string()),
                    (
                        HeaderName::from_static("docker-content-digest"),
                        layer_digest,
                    ),
                ],
            )
                .into_response());
        }
    }

    Ok(StatusCode::NOT_FOUND.into_response())
}

pub async fn pull_digest_get(
    Path((_name, layer_digest)): Path<(String, String)>,
    header_map: HeaderMap,
    state: State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let storage = state.storage.lock().await;

    if let Some(len) = storage.digest_length(&layer_digest).await? {
        let mut stream = match storage.get_digest_stream(&layer_digest).await? {
            Some(s) => s,
            None => {
                // returns None when the digest was not found
                return Ok(StatusCode::NOT_FOUND.into_response());
            }
        };

        if let Some(range) = header_map.get(header::CONTENT_RANGE) {
            let range = range.to_str().unwrap();
            debug!("Range request received: {}", range);
            let range = &range[6..];

            let (starting, ending) = range.split_once("-").unwrap();
            let (starting, ending) = (
                starting.parse::<i32>().unwrap(),
                ending.parse::<i32>().unwrap(),
            );

            // recreate the ByteStream, skipping elements
            stream = stream.skip_recreate(starting as usize);

            // convert the `AsyncRead` into a `Stream`
            let stream = ReaderStream::new(stream.into_async_read());
            // convert the `Stream` into an `axum::body::HttpBody`
            let body = StreamBody::new(stream);

            debug!("length of range request: {}", starting - ending);

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_LENGTH, (starting - ending).to_string()),
                    (
                        header::RANGE,
                        format!("bytes {}-{}/{}", starting, ending, len),
                    ),
                    (
                        HeaderName::from_static("docker-content-digest"),
                        layer_digest,
                    ),
                ],
                body,
            )
                .into_response())
        } else {
            // convert the `AsyncRead` into a `Stream`
            let stream = ReaderStream::new(stream.into_async_read());
            // convert the `Stream` into an `axum::body::HttpBody`
            let body = StreamBody::new(stream);

            debug!("length of streamed request: {}", len);

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_LENGTH, len.to_string()),
                    (
                        HeaderName::from_static("docker-content-digest"),
                        layer_digest,
                    ),
                ],
                body,
            )
                .into_response())
        }
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}

pub async fn delete_digest(
    Path((_name, layer_digest)): Path<(String, String)>,
    state: State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let storage = state.storage.lock().await;

    match storage.delete_digest(&layer_digest).await {
        Ok(()) => Ok(StatusCode::ACCEPTED.into_response()),
        Err(e) => match e {
            crate::storage::StorageDriverError::IoError(e) => {
                if e.kind() == ErrorKind::NotFound {
                    Ok(StatusCode::NOT_FOUND.into_response())
                } else {
                    Err(AppError::Other(e.into()))
                }
            }
            crate::storage::StorageDriverError::Other(e) => Err(AppError::Other(e.into())),
        },
    }
}
