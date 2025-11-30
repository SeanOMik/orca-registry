use axum::{http::StatusCode, response::{IntoResponse, Response}};
use serde::Serialize;

use crate::{database::DatabaseError, storage::StorageDriverError};
use tracing::error;

#[allow(dead_code)]
#[derive(Debug, thiserror::Error, Clone)]
pub enum OciRegistryError {
    #[error("blob unknown to registry")]
    BlobUnknown,
    #[error("blob upload invalid")]
    BlobUploadInvalid,
    #[error("blob upload unknown to registry")]
    BlobUploadUnknown,
    #[error("invalid digest, specified: {specified}, expected: {expected}")]
    DigestInvalid {
        specified: String,
        expected: String,
    },
    #[error("manifest references a manifest or blob unknown to registry")]
    ManifestBlobUnknown,
    #[error("manifest invalid")]
    ManifestInvalid,
    #[error("manifest unknown to registry")]
    ManifestUnknown,
    #[error("invalid repository name")]
    NameInvalid,
    #[error("repository name not known to registry")]
    NameUnknown,
    #[error("provided length did not match content length")]
    SizeInvalid,
    #[error("authentication required")]
    Unauthorized,
    #[error("requested access to the resource is denied")]
    Denied,
    #[error("the operation is unsupported")]
    Unsupported,
    #[error("too many requests")]
    TooManyRequests,
}

// Make our own error that wraps `anyhow::Error`.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    OciRegistry(#[from] OciRegistryError),
    #[error("{0}")]
    Storage(#[from] StorageDriverError),
    #[error("{0}")]
    Database(#[from] DatabaseError),
    #[error("Bad client request")]
    BadRequest,
    #[error("Internal error")]
    Internal,
    #[error("{0}")]
    Other(anyhow::Error),
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::OciRegistry(e) => {
                let (status_code, message) = match &e {
                    OciRegistryError::BlobUnknown => (StatusCode::NOT_FOUND, None),
                    OciRegistryError::BlobUploadInvalid => (StatusCode::BAD_REQUEST, None),
                    OciRegistryError::BlobUploadUnknown => (StatusCode::NOT_FOUND, None),
                    OciRegistryError::DigestInvalid { specified, expected } => (StatusCode::BAD_REQUEST, Some(format!("invalid digest, received {specified}, expected {expected}"))),
                    OciRegistryError::ManifestBlobUnknown => (StatusCode::NOT_FOUND, None),
                    OciRegistryError::ManifestInvalid => (StatusCode::BAD_REQUEST, None),
                    OciRegistryError::ManifestUnknown => (StatusCode::NOT_FOUND, None),
                    OciRegistryError::NameInvalid => (StatusCode::BAD_REQUEST, None),
                    OciRegistryError::NameUnknown => (StatusCode::NOT_FOUND, None),
                    OciRegistryError::SizeInvalid => (StatusCode::BAD_REQUEST, None),
                    OciRegistryError::Unauthorized => (StatusCode::UNAUTHORIZED, None),
                    OciRegistryError::Denied => (StatusCode::FORBIDDEN, None),
                    OciRegistryError::Unsupported => (StatusCode::NOT_IMPLEMENTED, None),
                    OciRegistryError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, None),
                };
                
                let err_msg = e.as_error_message(message, None);

                (
                    status_code,
                    axum::Json(err_msg),
                ).into_response()
            }
            //AppError::Storage(e) => todo!(),
            //AppError::Database(e) => todo!(),
            AppError::BadRequest => {
                StatusCode::BAD_REQUEST.into_response()
            },
            AppError::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            },
            _ => {
                error!("Unhandled internal error: {}", self);

                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Something went wrong: {}", self),
                ).into_response()
            }
        }
    }
}

impl OciRegistryError {
    pub fn as_string(&self) -> String {
        match self {
            OciRegistryError::BlobUnknown => "BLOB_UNKNOWN".into(),
            OciRegistryError::BlobUploadInvalid => "BLOB_UPLOAD_INVALID".into(),
            OciRegistryError::BlobUploadUnknown => "BLOB_UPLOAD_UNKNOWN".into(),
            OciRegistryError::DigestInvalid { .. } => "DIGEST_INVALID".into(),
            OciRegistryError::ManifestBlobUnknown => "MANIFEST_BLOB_UNKNOWN".into(),
            OciRegistryError::ManifestInvalid => "MANIFEST_INVALID".into(),
            OciRegistryError::ManifestUnknown => "MANIFEST_UNKNOWN".into(),
            OciRegistryError::NameInvalid => "NAME_INVALID".into(),
            OciRegistryError::NameUnknown => "NAME_UNKNOWN".into(),
            OciRegistryError::SizeInvalid => "SIZE_INVALID".into(),
            OciRegistryError::Unauthorized => "UNAUTHORIZED".into(),
            OciRegistryError::Denied => "DENIED".into(),
            OciRegistryError::Unsupported => "UNSUPPORTED".into(),
            OciRegistryError::TooManyRequests => "TOOMANYREQUESTS".into(),
        }
    }

    pub fn as_error_message(&self, message: Option<String>, detail: Option<String>) -> ErrorMessage {
        ErrorMessage { code: self.clone(), message, detail }
    }
}

impl Serialize for OciRegistryError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer
    {
        serializer.serialize_str(&self.as_string())
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorMessage {
    pub code: OciRegistryError,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
