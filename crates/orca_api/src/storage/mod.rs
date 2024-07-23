pub mod filesystem;

use async_trait::async_trait;
use bytes::Bytes;

use crate::byte_stream::ByteStream;

#[async_trait]
pub trait StorageDriver: Send + Sync {
    async fn get_digest(&self, digest: &str) -> anyhow::Result<Option<Bytes>>;
    async fn get_digest_stream(&self, digest: &str) -> anyhow::Result<Option<ByteStream>>;
    async fn digest_length(&self, digest: &str) -> anyhow::Result<Option<usize>>;
    async fn save_digest(&self, digest: &str, bytes: &Bytes, append: bool) -> anyhow::Result<()>;
    async fn save_digest_stream(&self, digest: &str, stream: ByteStream, append: bool) -> anyhow::Result<usize>;
    async fn delete_digest(&self, digest: &str) -> anyhow::Result<()>;
    async fn replace_digest(&self, uuid: &str, digest: &str) -> anyhow::Result<()>;

    async fn supports_streaming(&self) -> bool;
    async fn has_digest(&self, digest: &str) -> anyhow::Result<bool>;
}