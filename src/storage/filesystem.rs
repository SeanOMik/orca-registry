use std::{path::Path, io::ErrorKind};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::{fs, io::{AsyncWriteExt, AsyncReadExt}, task::spawn_blocking};
use tracing::debug;

use super::StorageDriver;

pub struct FilesystemDriver {
    storage_path: String,
}

impl FilesystemDriver {
    pub fn new(storage_path: &str) -> Self {
        Self {
            storage_path: storage_path.to_string(),
        }
    }

    fn get_digest_path(&self, digest: &str) -> String {
        format!("{}/{}", self.storage_path, digest)
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