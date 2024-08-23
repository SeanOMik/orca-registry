use axum::{http::StatusCode, response::{IntoResponse, Response}};
use serde::{Deserialize, Serialize};

use crate::{database::DatabaseError, storage::StorageDriverError};

#[derive(Debug, thiserror::Error)]
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
    #[error("{0}")]
    Other(anyhow::Error),
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        //todo!()

        match self {
            AppError::OciRegistry(e) => todo!(),
            //AppError::Storage(e) => todo!(),
            //AppError::Database(e) => todo!(),
            AppError::BadRequest => todo!(),
            //AppError::Other(e) => todo!(),
            _ => {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Something went wrong: {}", self),
                ).into_response()
            }
        }
        /* (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response() */
    }
}

impl Serialize for OciRegistryError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer
    {
        match self {
            OciRegistryError::BlobUnknown => serializer.serialize_str("BLOB_UNKNOWN"),
            OciRegistryError::BlobUploadInvalid => serializer.serialize_str("BLOB_UPLOAD_INVALID"),
            OciRegistryError::BlobUploadUnknown => serializer.serialize_str("BLOB_UPLOAD_UNKNOWN"),
            OciRegistryError::DigestInvalid { .. } => serializer.serialize_str("DIGEST_INVALID"),
            OciRegistryError::ManifestBlobUnknown => serializer.serialize_str("MANIFEST_BLOB_UNKNOWN"),
            OciRegistryError::ManifestInvalid => serializer.serialize_str("MANIFEST_INVALID"),
            OciRegistryError::ManifestUnknown => serializer.serialize_str("MANIFEST_UNKNOWN"),
            OciRegistryError::NameInvalid => serializer.serialize_str("NAME_INVALID"),
            OciRegistryError::NameUnknown => serializer.serialize_str("NAME_UNKNOWN"),
            OciRegistryError::SizeInvalid => serializer.serialize_str("SIZE_INVALID"),
            OciRegistryError::Unauthorized => serializer.serialize_str("UNAUTHORIZED"),
            OciRegistryError::Denied => serializer.serialize_str("DENIED"),
            OciRegistryError::Unsupported => serializer.serialize_str("UNSUPPORTED"),
            OciRegistryError::TooManyRequests => serializer.serialize_str("TOOMANYREQUESTS"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorMessage {
    pub code: OciRegistryError,
    pub message: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorsMessage {
    pub errors: Vec<ErrorMessage>,
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
/* impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
} */