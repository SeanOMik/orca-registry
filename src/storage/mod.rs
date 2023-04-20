pub mod filesystem;

use std::{pin::Pin, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use tokio::{io::{AsyncWrite, AsyncRead}, sync::{Mutex, mpsc}};

use actix_web::web;

pub trait Streamer {
    fn start(&'static mut self) -> anyhow::Result<()>;
}

pub trait StorageDriverStreamer {
    /// Write an actix-web payload into the StorageDriver
    /// Returns the amount of bytes written
    fn write_payload(&self, digest: &str, payload: actix_web::web::Payload, append: bool) -> anyhow::Result<usize>;

    fn supports_streaming(&self) -> bool;
    fn start_streaming_thread(&self) -> anyhow::Result<()>;
    fn start_stream_channel(&self) -> mpsc::Sender<(String, Bytes)>;
}

#[async_trait]
pub trait StorageDriver: Send + StorageDriverStreamer/* : AsyncWrite + AsyncRead */ {
    async fn has_digest(&self, digest: &str) -> anyhow::Result<bool>;
    async fn get_digest(&self, digest: &str) -> anyhow::Result<Option<Bytes>>;
    async fn digest_length(&self, digest: &str) -> anyhow::Result<Option<usize>>;
    async fn save_digest(&self, digest: &str, bytes: &Bytes, append: bool) -> anyhow::Result<()>;
    async fn delete_digest(&self, digest: &str) -> anyhow::Result<()>;
    async fn replace_digest(&self, uuid: &str, digest: &str) -> anyhow::Result<()>;

    //async fn write_payload(&self, payload: Mutex<web::Payload>) -> anyhow::Result<()>;
    //async fn write_stream<T, S: Stream<Item = T>>(&self, stream: S) -> anyhow::Result<()>;
}