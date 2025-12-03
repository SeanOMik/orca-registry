pub mod filesystem;

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

use crate::{byte_stream::ByteStream, dto::{Tag, manifest::Referrer}};

#[derive(Debug, Error)]
pub enum StorageDriverError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[allow(unused)]
#[async_trait]
pub trait StorageDriver: Send + Sync {
    /// Get the bytes of a layer from it's digest.
    async fn get_layer(&self, digest: &str) -> Result<Option<Bytes>, StorageDriverError>;
    /// Get a byte stream of a layer from it's digest.
    async fn get_layer_stream(&self, digest: &str) -> Result<Option<ByteStream>, StorageDriverError>;
    /// Get the size of the layer from it's digest.
    async fn layer_size(&self, digest: &str) -> Result<Option<usize>, StorageDriverError>;
    
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

    /// Store bytes as a layer.
    async fn save_layer(&self, digest: &str, bytes: &Bytes, append: bool) -> Result<(), StorageDriverError>;
    /// Store a stream of bytes as a layer.
    /// 
    /// > Note: Not all drivers support byte streaming, check [`StorageDriver::supports_streaming`] before calling it.
    async fn save_layer_stream(&self, digest: &str, stream: ByteStream, append: bool) -> Result<usize, StorageDriverError>;
    /// Delete a layer.
    async fn delete_layer(&self, digest: &str) -> Result<bool, StorageDriverError>;
    /// Rename a layer.
    /// 
    /// This is used during chunked uploading of layers. Temporary uploads receive UUIDs which
    /// are used to identify the layers until the digest can be calculated on the server.
    /// 
    /// Parameters:
    /// * `old` - The old name of the layer to rename from.
    /// * `new` - The new name of the layer.
    async fn rename_layer(&self, old: &str, new: &str) -> Result<(), StorageDriverError>;

    /// Returns `true` if the driver supports streaming.
    /// 
    /// Do not call [`StorageDriver::save_digest_stream`] if it returns false.
    async fn supports_streaming(&self) -> bool;
    /// Returns `true` if the layer is stored.
    async fn has_layer(&self, digest: &str) -> Result<bool, StorageDriverError>;

    /// Returns the full reference of a tag.
    /// 
    /// Parameters:
    /// * `repository` - The repository the tag is part of.
    /// * `tag` - The name of the tag to find.
    /// 
    /// Returns `None` if the tag was not found in the `repository`.
    async fn get_tag(&self, repository: &str, tag: &str) -> Result<Option<Tag>, StorageDriverError>;
    /// Create a tag that targets the `manifest_digest`.
    /// 
    /// Parameters:
    /// * `repository` - The repository the tag will be created inside.
    /// * `tag` - The name of the tag to create.
    /// * `manifest_digest` - The digest of the manifest to point the tag to.
    async fn save_tag(&self, repository: &str, tag: &str, manifest_digest: &str) -> Result<(), StorageDriverError>;
    /// Delete a tag.
    /// 
    /// Parameters:
    /// * `repository` - The repository the tag will be created inside.
    /// * `tag` - The name of the tag to create.
    async fn delete_tag(&self, repository: &str, tag: &str) -> Result<bool, StorageDriverError>;
    /// List the tags for the repository in lexical order.
    /// 
    /// Parameters:
    /// * `repository` - The repository the tag will be created inside.
    async fn list_tags(&self, repository: &str) -> Result<Vec<Tag>, StorageDriverError>;
    /// Paginated listing of tags for the repository.
    /// 
    /// The tags are returned in lexical order.
    /// 
    /// Parameters:
    /// * `repository` - The repository the tag will be created inside.
    /// * `limit` - The max amount of tags to retrieve.
    /// * `last_tag` - The tag that was at the end of the last page of tags. This next page will start right after this tag.
    /// 
    /// Returns the tags for the repository in laxical order.
    async fn list_tags_page(&self, repository: &str, limit: u32, last_tag: Option<String>) -> Result<Vec<Tag>, StorageDriverError>;

    /// Get a manifest.
    /// 
    /// Parameters:
    /// * `repository` - The repository the manifest is contained in.
    /// * `digest` - The digest of the manifest.
    /// 
    /// Returns the content of the manifest, or `None` if it was not found.
    async fn get_manifest(&self, repository: &str, digest: &str) -> Result<Option<String>, StorageDriverError>;
    /// Save the manifest.
    /// 
    /// Parameters:
    /// * `repository` - The repository the manifest is contained in.
    /// * `digest` - The digest of the manifest.
    /// * `content` - The content of the manifest.
    /// * `subject` - The subject of the manifest for referrers api.
    async fn save_manifest(&self, repository: &str, digest: &str, content: &str, subject: Option<&String>) -> Result<(), StorageDriverError>;
    /// Delete the manifest.
    /// 
    /// Parameters:
    /// * `repository` - The repository the manifest is contained in.
    /// * `digest` - The digest of the manifest to delete.
    async fn delete_manifest(&self, repository: &str, digest: &str) -> Result<bool, StorageDriverError>;
}