use std::{path::Path, io::ErrorKind};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use tokio::{fs, io::{AsyncWriteExt, AsyncReadExt}};
use tokio_util::io::ReaderStream;
use tracing::error;

use crate::byte_stream::ByteStream;

use super::{StorageDriver, StorageDriverError};

pub struct FilesystemDriver {
    storage_path: String,
}

impl FilesystemDriver {
    pub fn new(storage_path: &str) -> FilesystemDriver {
        Self {
            storage_path: storage_path.to_string(),
        }
    }

    fn get_digest_path(&self, digest: &str) -> String {
        format!("{}/{}", self.storage_path, digest)
    }

    fn ensure_storage_path(&self) -> std::io::Result<()>
    {
        std::fs::create_dir_all(&self.storage_path)
    }
}

#[async_trait]
impl StorageDriver for FilesystemDriver {
    async fn supports_streaming(&self) -> bool {
        true
    }

    async fn has_digest(&self, digest: &str) -> Result<bool, StorageDriverError> {
        let path = self.get_digest_path(digest);

        Ok(Path::new(&path).exists())
    }

    async fn save_digest_stream(&self, digest: &str, mut stream: ByteStream, append: bool) -> Result<usize, StorageDriverError> {
        self.ensure_storage_path()?;

        let path = self.get_digest_path(digest);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create(true)
            .open(path).await?;

        let mut len = 0;
        while let Some(bytes) = stream.next().await {
            let bytes = bytes?;

            len += bytes.len();

            file.write_all(&bytes).await?;
        }

        Ok(len)
    }

    async fn get_digest(&self, digest: &str) -> Result<Option<Bytes>, StorageDriverError> {
        let mut file = match fs::File::open(self.get_digest_path(digest))
            .await {
            
            Ok(f) => f,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    return Ok(None)
                },
                _ => {
                    error!("Failure attempting to open digest file: {:?}", e);
                    return Err(e.into());
                }
            }
        }; 

        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;

        Ok(Some(Bytes::from_iter(buf)))
    }

    async fn get_digest_stream(&self, digest: &str) -> Result<Option<ByteStream>, StorageDriverError> {
        let file = match fs::File::open(self.get_digest_path(digest)).await {
            Ok(f) => f,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    return Ok(None)
                },
                _ => {
                    error!("Failure attempting to open digest file: {:?}", e);
                    return Err(e.into());
                }
            }
        };

        let s = ReaderStream::new(file);
        Ok(Some(ByteStream::new(s)))
    }

    async fn digest_length(&self, digest: &str) -> Result<Option<usize>, StorageDriverError> {
        let file = match fs::File::open(self.get_digest_path(digest))
            .await {
            
            Ok(f) => f,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    return Ok(None)
                },
                _ => {
                    error!("Failure attempting to open digest file: {:?}", e);
                    return Err(e.into());
                }
            }
        };

        Ok(Some(file.metadata().await?.len() as usize))
    }

    async fn save_digest(&self, digest: &str, bytes: &Bytes, append: bool) -> Result<(), StorageDriverError> {
        let path = self.get_digest_path(digest);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create(true)
            .open(path).await?;

        file.write_all(&bytes).await?;

        Ok(())
    }

    async fn delete_digest(&self, digest: &str) -> Result<(), StorageDriverError> {
        let path = self.get_digest_path(digest);
        fs::remove_file(path).await?;

        Ok(())
    }

    async fn replace_digest(&self, uuid: &str, digest: &str) -> Result<(), StorageDriverError> {
        let path = self.get_digest_path(uuid);
        let path = Path::new(&path);
        let parent = path
            .clone()
            .parent()
            .expect("Failed to get parent path of digest file");

        fs::rename(path, format!("{}/{}", parent.display(), digest)).await?;

        Ok(())
    }
}