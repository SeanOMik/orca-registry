pub mod filesystem;

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

use crate::{byte_stream::ByteStream, dto::manifest::Referrer};

#[derive(Debug, Error)]
pub enum StorageDriverError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[async_trait]
pub trait StorageDriver: Send + Sync {
    #[allow(dead_code)]
    async fn get_digest(&self, digest: &str) -> Result<Option<Bytes>, StorageDriverError>;
    async fn get_digest_stream(&self, digest: &str) -> Result<Option<ByteStream>, StorageDriverError>;
    async fn digest_length(&self, digest: &str) -> Result<Option<usize>, StorageDriverError>;
    
    /// Refer to a digest with a `descriptor` and store the referrer list.
    /// 
    /// Parameters:
    /// * `referred_digest` - The digest of what is being referred to.
    /// * `referrer` - The [`Referrer`](crate::dto::manifest::Referrer) that refers to the `referred_digest`.
    async fn add_referrer(&self, referred_digest: &str, referrer: Referrer) -> Result<(), StorageDriverError>;
    /// Get referrers that refer to `referred_digest`
    /// 
    /// Parameters:
    /// * `referred_digest` - The digest to get referrers of.
    async fn get_referrers(&self, referred_digest: &str) -> Result<Vec<Referrer>, StorageDriverError>;

    async fn save_digest(&self, digest: &str, bytes: &Bytes, append: bool) -> Result<(), StorageDriverError>;
    async fn save_digest_stream(&self, digest: &str, stream: ByteStream, append: bool) -> Result<usize, StorageDriverError>;
    async fn delete_digest(&self, digest: &str) -> Result<(), StorageDriverError>;
    async fn replace_digest(&self, uuid: &str, digest: &str) -> Result<(), StorageDriverError>;

    async fn supports_streaming(&self) -> bool;
    async fn has_digest(&self, digest: &str) -> Result<bool, StorageDriverError>;
}