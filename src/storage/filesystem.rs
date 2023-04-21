use std::{path::Path, io::ErrorKind, sync::Arc, collections::HashMap};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{executor::block_on, StreamExt};
use tokio::{fs, io::{AsyncWriteExt, AsyncReadExt}, task::spawn_blocking, sync::{Mutex, mpsc}};
use tracing::debug;

use super::{StorageDriver, StorageDriverStreamer, Streamer};

pub struct FilesystemStreamer {
    /* new_streams_channel: mpsc::Receiver<(String, mpsc::Receiver<Bytes>)>,
    // (digest, receiver)
    streaming_channels: Vec<(String, )>, */

    storage_path: String,
    chunk_channel: mpsc::Receiver<(String, Bytes)>,
    cached_files: HashMap<String, fs::File>,
}

impl FilesystemStreamer {
    pub fn new(storage_path: String, chunk_channel: mpsc::Receiver<(String, Bytes)>) -> Self {
        Self {
            storage_path,
            chunk_channel,
            cached_files: HashMap::new(),
        }
    }

    pub async fn start_handling_streams(&mut self) -> anyhow::Result<()> {
        while let Some((digest, mut bytes)) = self.chunk_channel.recv().await {
            let mut temp;
            let file = match self.cached_files.get_mut(&digest) {
                Some(f) => f,
                None => {
                    let path = format!("{}/{}", self.storage_path, digest);
                    temp = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open(path).await?;
                    &mut temp
                }
            };

            file.write_all(&mut bytes).await.unwrap();
        }

        Ok(())
    }
}

impl Streamer for FilesystemStreamer {
    fn start(&'static mut self) -> anyhow::Result<()> {
        tokio::spawn(self.start_handling_streams());

        Ok(())
    }
}

pub struct FilesystemDriver {
    storage_path: String,
    // (digest, receiver)
    streaming_channels: Vec<(String, mpsc::Receiver<Bytes>)>,
    streamer_sender: mpsc::Sender<(String, Bytes)>,
}

impl FilesystemDriver {
    //pub fn new(storage_path: &str) -> FilesystemDriver {
    pub fn new(storage_path: String, stream_sender: mpsc::Sender<(String, Bytes)>) -> FilesystemDriver {
        /* let (send, recv) = mpsc::channel::<(String, Bytes)>(50);
        let streamer = Arc::new(FilesystemStreamer::new(storage_path.to_string(), recv)); */

        Self {
            storage_path,
            streaming_channels: vec![],
            streamer_sender: stream_sender,
        }
    }

    fn get_digest_path(&self, digest: &str) -> String {
        format!("{}/{}", self.storage_path, digest)
    }

    async fn write_payload(&self, digest: &str, mut payload: actix_web::web::Payload, append: bool) -> anyhow::Result<usize> {
        let path = self.get_digest_path(digest);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create(true)
            .open(path).await?;

        let mut total_size = 0;
        while let Some(item) = payload.next().await {
            let item = item?;

            total_size += item.len();
            file.write_all(&item).await?;
        }

        Ok(total_size)
    }
}

impl StorageDriverStreamer for FilesystemDriver {
    fn supports_streaming(&self) -> bool {
        true
    }

    fn start_stream_channel(&self) -> mpsc::Sender<(String, Bytes)> {
        self.streamer_sender.clone()
    }
}

#[async_trait]
impl StorageDriver for FilesystemDriver {
    async fn has_digest(&self, digest: &str) -> anyhow::Result<bool> {
        let path = self.get_digest_path(digest);

        spawn_blocking(move || {
            return Path::new(&path).exists()
        }).await.context("FilesystemDriver: Failure to spawn blocking thread to check digest")
    }

    async fn get_digest(&self, digest: &str) -> anyhow::Result<Option<Bytes>> {
        let mut file = match fs::File::open(self.get_digest_path(digest))
            .await {
            
            Ok(f) => f,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e)
                        .context("FilesystemDriver: Failure to open digest file");
                }
            }
        };

        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;

        Ok(Some(Bytes::from_iter(buf)))
    }

    async fn digest_length(&self, digest: &str) -> anyhow::Result<Option<usize>> {
        let file = match fs::File::open(self.get_digest_path(digest))
            .await {
            
            Ok(f) => f,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e)
                        .context("FilesystemDriver: Failure to open digest file");
                }
            }
        };

        Ok(Some(file.metadata().await?.len() as usize))
    }

    async fn save_digest(&self, digest: &str, bytes: &Bytes, append: bool) -> anyhow::Result<()> {
        let path = self.get_digest_path(digest);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create(true)
            .open(path).await?;

        file.write_all(&bytes).await?;

        Ok(())
    }

    async fn delete_digest(&self, digest: &str) -> anyhow::Result<()> {
        let path = self.get_digest_path(digest);
        fs::remove_file(path).await?;

        Ok(())
    }

    async fn replace_digest(&self, uuid: &str, digest: &str) -> anyhow::Result<()> {
        let path = self.get_digest_path(uuid);
        let path = Path::new(&path);
        let parent = path.clone().parent().unwrap();

        fs::rename(path, format!("{}/{}", parent.as_os_str().to_str().unwrap(), digest)).await?;

        Ok(())
    }
}