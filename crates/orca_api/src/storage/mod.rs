pub mod filesystem;

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

use crate::byte_stream::ByteStream;

#[derive(Debug, Error)]
pub enum StorageDriverError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[async_trait]
pub trait StorageDriver: Send + Sync {
    async fn get_digest(&self, digest: &str) -> Result<Option<Bytes>, StorageDriverError>;
    async fn get_digest_stream(&self, digest: &str) -> Result<Option<ByteStream>, StorageDriverError>;
    async fn digest_length(&self, digest: &str) -> Result<Option<usize>, StorageDriverError>;
    async fn save_digest(&self, digest: &str, bytes: &Bytes, append: bool) -> Result<(), StorageDriverError>;
    async fn save_digest_stream(&self, digest: &str, stream: ByteStream, append: bool) -> Result<usize, StorageDriverError>;
    async fn delete_digest(&self, digest: &str) -> Result<(), StorageDriverError>;
    async fn replace_digest(&self, uuid: &str, digest: &str) -> Result<(), StorageDriverError>;

    async fn supports_streaming(&self) -> bool;
    async fn has_digest(&self, digest: &str) -> Result<bool, StorageDriverError>;
}