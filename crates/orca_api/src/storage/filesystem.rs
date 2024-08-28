use std::{io::ErrorKind, path::Path};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tokio_util::io::ReaderStream;
use tracing::error;

use crate::{
    byte_stream::ByteStream,
    dto::manifest::{media_types, Descriptor, ImageIndex, ImageManifest, Manifest, Referrer, ReferrersList},
};

use super::{StorageDriver, StorageDriverError};

pub struct FilesystemDriver {
    storage_path: String,
}

impl FilesystemDriver {
    fn ensure_dir<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
        let path = Path::new(path.as_ref());
        if !path.exists() {
            std::fs::create_dir_all(path).unwrap();
        }

        Ok(())
    }

    pub fn new(storage_path: &str) -> FilesystemDriver {
        let path = format!("{}/layers", storage_path);
        Self::ensure_dir(path).unwrap();

        let path = format!("{}/manifests", storage_path);
        Self::ensure_dir(path).unwrap();

        Self {
            storage_path: storage_path.to_string(),
        }
    }

    /// Ensures that the path to the referrers file exists, and returns it.
    ///
    /// The format of the path is `{base_storage_path}/manifests/{digest}/referrers.json`.
    /// The contents of the file is an [`ImageIndex`](orca_api::dto::manifest::ImageIndex).
    async fn ensure_referrers_path(&self, digest: &str) -> std::io::Result<String> {
        let path = format!("{}/manifests/{}", self.storage_path, digest);
        let path = Path::new(&path);
        if !path.exists() {
            fs::create_dir_all(path).await?;
        }

        Ok(format!("{}/manifests/{}/referrers.json", self.storage_path, digest))
    }

    fn get_digest_path(&self, digest: &str) -> String {
        format!("{}/layers/{}", self.storage_path, digest)
    }

    fn ensure_storage_path(&self) -> std::io::Result<()> {
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

    async fn save_digest_stream(
        &self,
        digest: &str,
        mut stream: ByteStream,
        append: bool,
    ) -> Result<usize, StorageDriverError> {
        self.ensure_storage_path()?;

        let path = self.get_digest_path(digest);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create(true)
            .open(path)
            .await?;

        let mut len = 0;
        while let Some(bytes) = stream.next().await {
            let bytes = bytes?;

            len += bytes.len();

            file.write_all(&bytes).await?;
        }

        Ok(len)
    }

    async fn get_digest(&self, digest: &str) -> Result<Option<Bytes>, StorageDriverError> {
        let mut file = match fs::File::open(self.get_digest_path(digest)).await {
            Ok(f) => f,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => return Ok(None),
                _ => {
                    error!("Failure attempting to open digest file: {:?}", e);
                    return Err(e.into());
                }
            },
        };

        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;

        Ok(Some(Bytes::from_iter(buf)))
    }

    async fn get_digest_stream(
        &self,
        digest: &str,
    ) -> Result<Option<ByteStream>, StorageDriverError> {
        let file = match fs::File::open(self.get_digest_path(digest)).await {
            Ok(f) => f,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => return Ok(None),
                _ => {
                    error!("Failure attempting to open digest file: {:?}", e);
                    return Err(e.into());
                }
            },
        };

        let s = ReaderStream::new(file);
        Ok(Some(ByteStream::new(s)))
    }

    async fn digest_length(&self, digest: &str) -> Result<Option<usize>, StorageDriverError> {
        let file = match fs::File::open(self.get_digest_path(digest)).await {
            Ok(f) => f,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => return Ok(None),
                _ => {
                    error!("Failure attempting to open digest file: {:?}", e);
                    return Err(e.into());
                }
            },
        };

        Ok(Some(file.metadata().await?.len() as usize))
    }

    async fn add_referrer(
        &self,
        referred_digest: &str,
        mut referrer: Referrer,
    ) -> Result<(), StorageDriverError> {
        let path = self.ensure_referrers_path(referred_digest).await?;
        let path = Path::new(&path);

        if path.exists() {
            // if the file already exists, read the contents and append to the
            // manifest list

            let old_list = fs::read_to_string(path).await?;
            let mut ref_list: ReferrersList = serde_json::from_str(&old_list)
                .expect("invalid ReferrersList found in storage!");
            ref_list.referrers.push(referrer);

            let json = serde_json::to_string(&ref_list)
                .expect("failed to serialize ReferrersList");
            let json = json.as_bytes();

            // Truncate the old file and write new contents
            let mut file = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .await?;

            file.write_all(&json).await?;
        } else {
            let rlist = ReferrersList {
                schema_version: 2,
                media_type: media_types::IMAGE_INDEX.into(),
                referrers: vec![referrer],
            };
            let json = serde_json::to_string(&rlist)
                .expect("failed to serialize ReferrersList");
            let json = json.as_bytes();

            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(path)
                .await?;

            file.write_all(&json).await?;
            //fs::write(path, json).await?;
        }

        Ok(())
    }

    async fn get_referrers(&self, referred_digest: &str) -> Result<Vec<Referrer>, StorageDriverError> {
        let path = self.ensure_referrers_path(referred_digest).await?;
        let path = Path::new(&path);

        match fs::read_to_string(path).await {
            Ok(s) => {
                let rlist: ReferrersList = serde_json::from_str(&s)
                    .context("tried to read ReferrersList from file system")?;
                Ok(rlist.referrers)
            },
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(vec![]),
                _ => Err(e.into())
            }
        }
    }

    async fn save_digest(
        &self,
        digest: &str,
        bytes: &Bytes,
        append: bool,
    ) -> Result<(), StorageDriverError> {
        let path = self.get_digest_path(digest);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create(true)
            .open(path)
            .await?;

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
