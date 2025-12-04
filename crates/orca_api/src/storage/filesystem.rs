use std::{io::ErrorKind, path::Path};

use anyhow::Context;
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
    dto::{
        Tag,
        manifest::{Referrer, ReferrersList, media_types},
    },
};

use super::{StorageDriver, StorageDriverError};

fn ensure_dir<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    let path = Path::new(path.as_ref());
    if !path.exists() {
        std::fs::create_dir_all(path).unwrap();
    }

    Ok(())
}

async fn async_ensure_dir<P: AsRef<Path>>(path: P) -> tokio::io::Result<()> {
    let path = Path::new(path.as_ref());
    if !path.exists() {
        fs::create_dir_all(path).await?;
    }

    Ok(())
}

#[inline(always)]
fn escape_repository(repository: &str) -> String {
    repository.replace("/", "%2F")
}

pub struct FilesystemDriver {
    storage_path: String,
}

impl FilesystemDriver {
    pub fn new(storage_path: &str) -> FilesystemDriver {
        let path = format!("{}/layers", storage_path);
        ensure_dir(path).unwrap();

        let path = format!("{}/manifests", storage_path);
        ensure_dir(path).unwrap();

        Self {
            storage_path: storage_path.to_string(),
        }
    }

    /// Ensures that the path to the referrers file exists, and returns it.
    ///
    /// The format of the path is `{base_storage_path}/manifests/{digest}/referrers.json`.
    /// The contents of the file is an [`ImageIndex`](orca_api::dto::manifest::ImageIndex).
    #[inline(always)]
    async fn ensure_referrers_path(&self, digest: &str) -> std::io::Result<String> {
        let path = format!("{}/manifests/{}", self.storage_path, digest);
        async_ensure_dir(path).await?;

        Ok(format!(
            "{}/manifests/{}/referrers.json",
            self.storage_path, digest
        ))
    }

    #[inline(always)]
    fn layer_path(&self, digest: &str) -> String {
        format!("{}/layers/{}", self.storage_path, digest)
    }

    /// The path to the manifest.json for the manifest digest.
    ///
    /// This will also ensure that the  directory that contains the file exists.
    #[inline(always)]
    async fn manifest_path(&self, digest: &str) -> tokio::io::Result<String> {
        let path = self.manifest_dir(digest).await?;

        Ok(format!("{path}/manifest.json"))
    }

    /// The path to the manifest directory for the digest.
    ///
    /// This will also ensure that the path exists.
    #[inline(always)]
    async fn manifest_dir(&self, digest: &str) -> tokio::io::Result<String> {
        let path = format!("{}/manifests/{}", self.storage_path, digest);
        async_ensure_dir(&path).await?;

        Ok(path)
    }

    /// Return the path of the file that stores the tag's manifest reference.
    ///
    /// This will also ensure that the directory that contains the file exists.
    #[inline(always)]
    async fn tag_path(&self, repository: &str, tag: &str) -> tokio::io::Result<String> {
        let repo = escape_repository(repository);
        let path = format!("{}/repository/{}/tags", self.storage_path, repo);
        async_ensure_dir(&path).await?;

        Ok(format!("{path}/{tag}"))
    }

    /// Return the path of the directory that stores repository tags.
    ///
    /// This will also ensure that it exists.
    #[inline(always)]
    async fn tags_dir(&self, repository: &str) -> tokio::io::Result<String> {
        let repo = escape_repository(repository);
        let path = format!("{}/repository/{}/tags", self.storage_path, repo);
        async_ensure_dir(&path).await?;

        Ok(path)
    }

    #[inline(always)]
    fn ensure_storage_path(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.storage_path)
    }
}

#[async_trait]
impl StorageDriver for FilesystemDriver {
    async fn supports_streaming(&self) -> bool {
        true
    }

    async fn has_layer(&self, digest: &str) -> Result<bool, StorageDriverError> {
        let path = self.layer_path(digest);

        Ok(Path::new(&path).exists())
    }

    async fn save_layer_stream(
        &self,
        digest: &str,
        mut stream: ByteStream,
        append: bool,
    ) -> Result<usize, StorageDriverError> {
        self.ensure_storage_path()?;

        let path = self.layer_path(digest);
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

    async fn get_layer(&self, digest: &str) -> Result<Option<Bytes>, StorageDriverError> {
        let mut file = match fs::File::open(self.layer_path(digest)).await {
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

    async fn get_layer_stream(
        &self,
        digest: &str,
    ) -> Result<Option<ByteStream>, StorageDriverError> {
        let file = match fs::File::open(self.layer_path(digest)).await {
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

    async fn layer_size(&self, digest: &str) -> Result<Option<usize>, StorageDriverError> {
        let file = match fs::File::open(self.layer_path(digest)).await {
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
        referrer: Referrer,
    ) -> Result<(), StorageDriverError> {
        let path = self.ensure_referrers_path(referred_digest).await?;
        let path = Path::new(&path);

        if path.exists() {
            // if the file already exists, read the contents and append to the
            // manifest list

            let old_list = fs::read_to_string(path).await?;
            let mut ref_list: ReferrersList =
                serde_json::from_str(&old_list).expect("invalid ReferrersList found in storage!");
            ref_list.referrers.push(referrer);

            let json = serde_json::to_string(&ref_list).expect("failed to serialize ReferrersList");
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
            let json = serde_json::to_string(&rlist).expect("failed to serialize ReferrersList");
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

    async fn get_referrers(
        &self,
        referred_digest: &str,
    ) -> Result<Vec<Referrer>, StorageDriverError> {
        let path = self.ensure_referrers_path(referred_digest).await?;
        let path = Path::new(&path);

        match fs::read_to_string(path).await {
            Ok(s) => {
                let rlist: ReferrersList = serde_json::from_str(&s)
                    .context("tried to read ReferrersList from file system")?;
                Ok(rlist.referrers)
            }
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(vec![]),
                _ => Err(e.into()),
            },
        }
    }

    async fn save_layer(
        &self,
        digest: &str,
        bytes: &Bytes,
        append: bool,
    ) -> Result<(), StorageDriverError> {
        let path = self.layer_path(digest);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create(true)
            .open(path)
            .await?;

        file.write_all(&bytes).await?;

        Ok(())
    }

    async fn delete_layer(&self, digest: &str) -> Result<bool, StorageDriverError> {
        let path = self.layer_path(digest);

        if fs::try_exists(&path).await? {
            fs::remove_file(path).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn rename_layer(&self, uuid: &str, digest: &str) -> Result<(), StorageDriverError> {
        let path = self.layer_path(uuid);
        let path = Path::new(&path);
        let parent = path
            .parent()
            .expect("Failed to get parent path of digest file");

        fs::rename(path, format!("{}/{}", parent.display(), digest)).await?;

        Ok(())
    }

    async fn get_tag(
        &self,
        repository: &str,
        tag: &str,
    ) -> Result<Option<Tag>, StorageDriverError> {
        let path = self.tag_path(repository, tag).await?;

        if fs::try_exists(&path).await? {
            let metadata = fs::metadata(&path).await?;
            let last_updated = metadata.modified()?;
            let last_updated = chrono::DateTime::<chrono::Utc>::from(last_updated);

            let manifest_digest = fs::read_to_string(&path).await?;

            Ok(Some(Tag {
                name: tag.into(),
                repository: repository.into(),
                last_updated,
                manifest_digest,
            }))
        } else {
            Ok(None)
        }
    }

    async fn save_tag(
        &self,
        repository: &str,
        tag: &str,
        manifest_digest: &str,
    ) -> Result<(), StorageDriverError> {
        let path = self.tag_path(repository, tag).await?;
        fs::write(&path, manifest_digest).await?;

        Ok(())
    }

    async fn delete_tag(&self, repository: &str, tag: &str) -> Result<bool, StorageDriverError> {
        let path = self.tag_path(repository, tag).await?;

        if fs::try_exists(&path).await? {
            fs::remove_file(&path).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn list_tags(&self, repository: &str) -> Result<Vec<Tag>, StorageDriverError> {
        let path = self.tags_dir(repository).await?;
        let mut dir = fs::read_dir(&path).await?;

        let mut tag_files = vec![];

        while let Some(entry) = dir.next_entry().await? {
            if entry.file_type().await?.is_file() {
                match tag_files.binary_search(&entry.path()) {
                    Ok(_) => {} // element exists already
                    Err(pos) => tag_files.insert(pos, entry.path()),
                }
            }
        }

        let mut tags = vec![];

        for tag_file in tag_files {
            if tag_file.is_file() {
                let name = match tag_file.file_name().unwrap().to_str() {
                    Some(name) => name,
                    None => {
                        error!(
                            "Failed to read tag name from file, skipping tag: '{:?}'",
                            tag_file.file_name().unwrap()
                        );
                        continue;
                    }
                };

                let path = tag_file.as_path();
                let metadata = fs::metadata(path).await?;
                let last_updated = metadata.modified()?;
                let last_updated = chrono::DateTime::<chrono::Utc>::from(last_updated);

                let manifest_digest = fs::read_to_string(path).await?;

                tags.push(Tag {
                    name: name.into(),
                    repository: repository.to_string(),
                    last_updated,
                    manifest_digest,
                });
            }
        }

        Ok(tags)
    }

    async fn list_tags_page(
        &self,
        repository: &str,
        limit: u32,
        last_tag: Option<String>,
    ) -> Result<Vec<Tag>, StorageDriverError> {
        let path = self.tags_dir(repository).await?;
        let mut dir = fs::read_dir(&path).await?;

        let mut tag_files = vec![];

        while let Some(entry) = dir.next_entry().await? {
            if entry.file_type().await?.is_file() {
                match tag_files.binary_search(&entry.path()) {
                    Ok(_) => {} // element exists already
                    Err(pos) => tag_files.insert(pos, entry.path()),
                }
            }
        }

        let mut tags = vec![];

        match last_tag {
            Some(last_tag) => {
                // find the index of the last tag in the list
                let last_tag_pos = tag_files.iter().position(|path| path.ends_with(&last_tag));

                if last_tag_pos.is_none() {
                    return Ok(vec![]);
                }
                let pos = last_tag_pos.unwrap();

                for tag in tag_files.iter().skip(pos + 1).take(limit as usize) {
                    let name = match tag.file_name().unwrap().to_str() {
                        Some(name) => name,
                        None => {
                            error!(
                                "Failed to read tag name from file, skipping tag: '{:?}'",
                                tag.file_name().unwrap()
                            );
                            continue;
                        }
                    };

                    let metadata = fs::metadata(tag).await?;
                    let last_updated = metadata.modified()?;
                    let last_updated = chrono::DateTime::<chrono::Utc>::from(last_updated);

                    let manifest_digest = fs::read_to_string(tag).await?;

                    tags.push(Tag {
                        name: name.into(),
                        repository: repository.to_string(),
                        last_updated,
                        manifest_digest,
                    });
                }
            }
            None => {
                for tag_file in tag_files {
                    if tag_file.is_file() {
                        let name = match tag_file.file_name().unwrap().to_str() {
                            Some(name) => name,
                            None => {
                                error!(
                                    "Failed to read tag name from file, skipping tag: '{:?}'",
                                    tag_file.file_name().unwrap()
                                );
                                continue;
                            }
                        };

                        let path = tag_file.as_path();
                        let metadata = fs::metadata(path).await?;
                        let last_updated = metadata.modified()?;
                        let last_updated = chrono::DateTime::<chrono::Utc>::from(last_updated);

                        let manifest_digest = fs::read_to_string(path).await?;

                        tags.push(Tag {
                            name: name.into(),
                            repository: repository.to_string(),
                            last_updated,
                            manifest_digest,
                        });
                    }
                }
            }
        }

        Ok(tags)
    }

    async fn get_manifest(
        &self,
        _: &str,
        digest: &str,
    ) -> Result<Option<String>, StorageDriverError> {
        let path = self.manifest_path(digest).await?;

        if fs::try_exists(&path).await? {
            let manifest = fs::read_to_string(&path).await?;
            Ok(Some(manifest))
        } else {
            Ok(None)
        }
    }

    async fn save_manifest(
        &self,
        _: &str,
        digest: &str,
        content: &str,
        subject: Option<&String>,
    ) -> Result<(), StorageDriverError> {
        let path = self.manifest_dir(digest).await?;
        fs::write(format!("{path}/manifest.json"), content).await?;

        if let Some(subject) = subject {
            fs::write(format!("{path}/subject"), subject).await?;
        }

        Ok(())
    }

    async fn delete_manifest(&self, _: &str, digest: &str) -> Result<bool, StorageDriverError> {
        let path = self.manifest_path(digest).await?;

        if fs::try_exists(&path).await? {
            fs::remove_dir_all(path).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
