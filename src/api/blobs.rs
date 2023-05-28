use std::sync::Arc;

use axum::Extension;
use axum::body::StreamBody;
use axum::extract::{State, Path};
use axum::http::{StatusCode, header, HeaderName};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;

use crate::app_state::AppState;
use crate::auth_storage::{unauthenticated_response, AuthDriver};
use crate::database::Database;
use crate::dto::RepositoryVisibility;
use crate::dto::user::{Permission, RegistryUserType, UserAuth};

pub async fn digest_exists_head(Path((name, layer_digest)): Path<(String, String)>, state: State<Arc<AppState>>, Extension(auth): Extension<UserAuth>) -> Response {
    // Check if the user has permission to pull, or that the repository is public
    let auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PULL, Some(RepositoryVisibility::Public)).await.unwrap() {        
        return unauthenticated_response(&state.config);
    }
    drop(auth_driver);

    let storage = state.storage.lock().await;

    if storage.has_digest(&layer_digest).await.unwrap() {
        if let Some(size) = storage.digest_length(&layer_digest).await.unwrap() {
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_LENGTH, size.to_string()),
                    (HeaderName::from_static("docker-content-digest"), layer_digest)
                ]
            ).into_response();
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

pub async fn pull_digest_get(Path((name, layer_digest)): Path<(String, String)>, state: State<Arc<AppState>>, Extension(auth): Extension<UserAuth>) -> Response {
    // Check if the user has permission to pull, or that the repository is public
    let auth_driver = state.auth_checker.lock().await;
    if !auth_driver.user_has_permission(auth.user.username, name.clone(), Permission::PULL, Some(RepositoryVisibility::Public)).await.unwrap() {        
        return unauthenticated_response(&state.config);
    }
    drop(auth_driver);

    let storage = state.storage.lock().await;

    if let Some(len) = storage.digest_length(&layer_digest).await.unwrap() {
        let stream = storage.get_digest_stream(&layer_digest).await.unwrap().unwrap();

        // convert the `AsyncRead` into a `Stream`
        let stream = ReaderStream::new(stream.into_async_read());
        // convert the `Stream` into an `axum::body::HttpBody`
        let body = StreamBody::new(stream);

        (
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, len.to_string()),
                (HeaderName::from_static("docker-content-digest"), layer_digest)
            ],
            body
        ).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

pub async fn delete_digest(_state: State<Arc<AppState>>) -> impl IntoResponse {
    todo!()
}