use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;

use axum::Extension;
use axum::http::{StatusCode, header, HeaderName};
use axum::extract::{Path, BodyStream, State, Query};
use axum::response::{IntoResponse, Response};

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use tracing::{debug, warn};

use crate::app_state::AppState;
use crate::auth::access_denied_response;
use crate::byte_stream::ByteStream;
use crate::dto::user::{UserAuth, Permission};
use crate::error::AppError;

/// Starting an upload
pub async fn start_upload_post(Path((name, )): Path<(String, )>, auth: UserAuth, state: State<Arc<AppState>>) -> Result<Response, AppError> {
    let mut auth_driver = state.auth_checker.lock().await;
    if auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PUSH, None).await? {
        debug!("Upload requested");
        let uuid = uuid::Uuid::new_v4();

        debug!("Requesting upload of image {}, generated uuid: {}", name, uuid);

        let location = format!("/v2/{}/blobs/uploads/{}", name, uuid.to_string());
        debug!("Constructed upload url: {}", location);

        return Ok((
            StatusCode::ACCEPTED,
            [ (header::LOCATION, location) ]
        ).into_response());
    }

    Ok(access_denied_response(&state.config))
}

pub async fn chunked_upload_layer_patch(Path((name, layer_uuid)): Path<(String, String)>, auth: UserAuth, state: State<Arc<AppState>>, mut body: BodyStream) -> Result<Response, AppError> {
    let mut auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PUSH, None).await? {
        return Ok(access_denied_response(&state.config));
    }
    drop(auth_driver);

    let storage = state.storage.lock().await;
    let current_size = storage.digest_length(&layer_uuid).await?;

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
            let len = storage.save_digest_stream(&layer_uuid, byte_stream, true).await?;

            len
        },
        false => {
            warn!("This storage driver does not support streaming! This means high memory usage during image pushes!");

            let mut bytes = BytesMut::new();
            while let Some(item) = body.next().await {
                bytes.extend_from_slice(&item?);
            }

            let bytes_len = bytes.len();
            storage.save_digest(&layer_uuid, &bytes.into(), true).await?;
            bytes_len
        }
    };

    let (starting, ending) = if let Some(current_size) = current_size {
        (current_size, current_size + written_size)
    } else {
        (0, written_size)
    };

    let full_uri = format!("{}/v2/{}/blobs/uploads/{}", state.config.url(), name, layer_uuid);
    Ok((
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, full_uri),
            (header::RANGE, format!("{}-{}", starting, ending)),
            (header::CONTENT_LENGTH, "0".to_string()),
            (HeaderName::from_static("docker-upload-uuid"), layer_uuid)
        ]
    ).into_response())
}

pub async fn finish_chunked_upload_put(Path((name, layer_uuid)): Path<(String, String)>, Query(query): Query<HashMap<String, String>>, auth: UserAuth, state: State<Arc<AppState>>, body: Bytes) -> Result<Response, AppError> {
    let mut auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PUSH, None).await? {
        return Ok(access_denied_response(&state.config));
    }
    drop(auth_driver);
    
    let digest = query.get("digest").unwrap();

    let storage = state.storage.lock().await;
    if !body.is_empty() {
        storage.save_digest(&layer_uuid, &body, true).await?;
    } else {
        // TODO: Validate layer with all digest params
    }

    storage.replace_digest(&layer_uuid, &digest).await?;
    debug!("Completed upload, finished uuid {} to digest {}", layer_uuid, digest);

    Ok((
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{}/blobs/{}", name, digest)),
            (header::CONTENT_LENGTH, "0".to_string()),
            (HeaderName::from_static("docker-upload-digest"), digest.to_owned())
        ]
    ).into_response())
}

pub async fn cancel_upload_delete(Path((name, layer_uuid)): Path<(String, String)>, state: State<Arc<AppState>>, auth: UserAuth) -> Result<Response, AppError> {
    let mut auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PUSH, None).await? {
        return Ok(access_denied_response(&state.config));
    }
    drop(auth_driver);
    
    let storage = state.storage.lock().await;
    storage.delete_digest(&layer_uuid).await?;
    
    // I'm not sure what this response should be, its not specified in the registry spec.
    Ok(StatusCode::OK.into_response())
}

pub async fn check_upload_status_get(Path((name, layer_uuid)): Path<(String, String)>, state: State<Arc<AppState>>, auth: UserAuth) -> Result<Response, AppError> {
    let mut auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PUSH, None).await? {
        return Ok(access_denied_response(&state.config));
    }
    drop(auth_driver);
    
    let storage = state.storage.lock().await;
    let ending = storage.digest_length(&layer_uuid).await?.unwrap_or(0);

    Ok((
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{}/blobs/uploads/{}", name, layer_uuid)),
            (header::RANGE, format!("0-{}", ending)),
            (HeaderName::from_static("docker-upload-digest"), layer_uuid)
        ]
    ).into_response())
}