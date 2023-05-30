use std::sync::Arc;

use axum::Extension;
use axum::body::StreamBody;
use axum::extract::{State, Path};
use axum::http::{StatusCode, header, HeaderName};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;

use crate::app_state::AppState;
use crate::auth::unauthenticated_response;
use crate::dto::RepositoryVisibility;
use crate::dto::user::{Permission, UserAuth};
use crate::error::AppError;

pub async fn digest_exists_head(Path((name, layer_digest)): Path<(String, String)>, state: State<Arc<AppState>>, Extension(auth): Extension<UserAuth>) -> Result<Response, AppError> {
    // Check if the user has permission to pull, or that the repository is public
    let mut auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PULL, Some(RepositoryVisibility::Public)).await? {
        return Ok(unauthenticated_response(&state.config));
    }
    drop(auth_driver);

    let storage = state.storage.lock().await;

    if storage.has_digest(&layer_digest).await? {
        if let Some(size) = storage.digest_length(&layer_digest).await? {
            return Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_LENGTH, size.to_string()),
                    (HeaderName::from_static("docker-content-digest"), layer_digest)
                ]
            ).into_response());
        }
    }

    Ok(StatusCode::NOT_FOUND.into_response())
}

pub async fn pull_digest_get(Path((name, layer_digest)): Path<(String, String)>, state: State<Arc<AppState>>, Extension(auth): Extension<UserAuth>) -> Result<Response, AppError> {
    // Check if the user has permission to pull, or that the repository is public
    let mut auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PULL, Some(RepositoryVisibility::Public)).await? {
        return Ok(unauthenticated_response(&state.config));
    }
    drop(auth_driver);

    let storage = state.storage.lock().await;

    if let Some(len) = storage.digest_length(&layer_digest).await? {
        let stream = match storage.get_digest_stream(&layer_digest).await? {
            Some(s) => s,
            None => {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }
        };

        // convert the `AsyncRead` into a `Stream`
        let stream = ReaderStream::new(stream.into_async_read());
        // convert the `Stream` into an `axum::body::HttpBody`
        let body = StreamBody::new(stream);

        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, len.to_string()),
                (HeaderName::from_static("docker-content-digest"), layer_digest)
            ],
            body
        ).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}

pub async fn delete_digest(_state: State<Arc<AppState>>) -> impl IntoResponse {
    todo!()
}