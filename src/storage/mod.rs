pub mod filesystem;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncWrite, AsyncRead};

#[async_trait]
pub trait StorageDriver: Send/* : AsyncWrite + AsyncRead */ {
    async fn has_digest(&self, digest: &str) -> anyhow::Result<bool>;
    async fn get_digest(&self, digest: &str) -> anyhow::Result<Option<Bytes>>;
    async fn digest_length(&self, digest: &str) -> anyhow::Result<Option<usize>>;
    async fn save_digest(&self, digest: &str, bytes: &Bytes, append: bool) -> anyhow::Result<()>;
    async fn delete_digest(&self, digest: &str) -> anyhow::Result<()>;
    async fn replace_digest(&self, uuid: &str, digest: &str) -> anyhow::Result<()>;
}