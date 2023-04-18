use std::io::Read;

use async_trait::async_trait;
use bytes::Bytes;
use sqlx::{Sqlite, Pool};
use tracing::debug;

use chrono::{DateTime, Utc, NaiveDateTime};

use crate::dto::Tag;

#[async_trait]
pub trait Database {

    // Digest related functions

    /// Create the tables in the database
    async fn create_schema(&self) -> sqlx::Result<()>;
    /// Get the digest bytes
    async fn get_digest(&self, digest: &str) -> sqlx::Result<Option<Bytes>>;
    /// Get the length of the digest
    async fn digest_length(&self, digest: &str) -> sqlx::Result<usize>;
    /// Save digest bytes
    async fn save_digest(&self, digest: &str, bytes: &Bytes) -> sqlx::Result<()>;
    /// Delete digest
    async fn delete_digest(&self, digest: &str) -> sqlx::Result<()>;
    /// Replace the uuid with a digest
    async fn replace_digest(&self, uuid: &str, new_digest: &str) -> sqlx::Result<()>;
    async fn link_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> sqlx::Result<()>;
    async fn unlink_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> sqlx::Result<()>;

    // Tag related functions

    /// Get tags associated with a repository
    async fn list_repository_tags(&self, repository: &str,) -> sqlx::Result<Vec<Tag>>;
    async fn list_repository_tags_page(&self, repository: &str, limit: u32, last_tag: Option<String>) -> sqlx::Result<Vec<Tag>>;
    /// Get a manifest digest using the tag name.
    async fn get_tag(&self, repository: &str, tag: &str) -> sqlx::Result<Option<Tag>>;
    /// Save a tag and reference it to the manifest digest.
    async fn save_tag(&self, repository: &str, tag: &str, manifest_digest: &str) -> sqlx::Result<()>;
    /// Delete a tag.
    async fn delete_tag(&self, repository: &str, tag: &str) -> sqlx::Result<()>;

    // Manifest related functions

    /// Get a manifest's content.
    async fn get_manifest(&self, repository: &str, digest: &str) -> sqlx::Result<Option<String>>;
    /// Save a manifest's content.
    async fn save_manifest(&self, repository: &str, digest: &str, content: &str) -> sqlx::Result<()>;
    /// Delete a manifest
    async fn delete_manifest(&self, repository: &str, digest: &str) -> sqlx::Result<()>;

    // Repository related functions

    /// Create a repository
    async fn save_repository(&self, repository: &str) -> sqlx::Result<()>;
    /// List all repositories. 
    /// If limit is not specified, a default limit of 1000 will be returned.
    async fn list_repositories(&self, limit: Option<u32>, last_repo: Option<String>) -> sqlx::Result<Vec<String>>;
}

#[async_trait]
impl Database for Pool<Sqlite> {
    async fn create_schema(&self) -> sqlx::Result<()> {
        sqlx::query(include_str!("schemas/schema.sql"))
            .execute(self).await?;

        debug!("Created database schema");

        Ok(())
    }

    async fn get_digest(&self, digest: &str) -> sqlx::Result<Option<Bytes>> {
        // Handle RowNotFound errors
        let row: (Vec<u8>, ) = match sqlx::query_as("SELECT blob FROM layer_blobs WHERE digest = ?")
                .bind(digest)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e);
                }
            }
        };

        let bytes = Bytes::from(row.0);

        debug!("Got digest {}, {} bytes", digest, bytes.len());

        Ok(Some(bytes))
    }

    async fn digest_length(&self, digest: &str) -> sqlx::Result<usize> {
        let row: (i64, ) = sqlx::query_as("SELECT length(blob) FROM layer_blobs WHERE digest = ?")
            .bind(digest)
            .fetch_one(self).await?;

        Ok(row.0 as usize)
    }

    async fn save_digest(&self, digest: &str, bytes: &Bytes) -> sqlx::Result<()> {
        let bytes_len = bytes.len();
        let bytes = bytes.bytes().map(|b| b.unwrap()).collect::<Vec<u8>>();

        sqlx::query("INSERT INTO layer_blobs (digest, blob) VALUES (?, ?)")
            .bind(digest)
            .bind(bytes)
            .execute(self).await?;

        debug!("Saved digest {}, {} bytes", digest, bytes_len);

        Ok(())
    }

    async fn delete_digest(&self, digest: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM layer_blobs WHERE digest = ?")
            .bind(digest)
            .execute(self).await?;

        debug!("Deleted digest {}", digest);

        Ok(())
    }

    async fn replace_digest(&self, uuid: &str, new_digest: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE layer_blobs SET digest = ? WHERE digest = ?")
            .bind(new_digest)
            .bind(uuid)
            .execute(self).await?;

        debug!("Replaced digest uuid {} to digest {}", uuid, new_digest);

        Ok(())
    }

    async fn link_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO manifest_layers(manifest, layer_digest) VALUES (?, ?)")
            .bind(manifest_digest)
            .bind(layer_digest)
            .execute(self).await?;

        debug!("Linked manifest {} to layer {}", manifest_digest, layer_digest);

        Ok(())
    }

    async fn unlink_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM manifest_layers WHERE manifest = ? AND layer_digest = ?")
            .bind(manifest_digest)
            .bind(layer_digest)
            .execute(self).await?;

        debug!("Removed link between manifest {} and layer {}", manifest_digest, layer_digest);

        Ok(())
    }

    async fn list_repository_tags(&self, repository: &str,) -> sqlx::Result<Vec<Tag>> {
        let rows: Vec<(String, String, i64, )> = sqlx::query_as("SELECT name, image_manifest, last_updated FROM image_tags WHERE repository = ?")
                .bind(repository)
                .fetch_all(self).await?;

        // Convert the rows into `Tag`
        let tags: Vec<Tag> = rows.into_iter().map(|row| {
            let last_updated: DateTime<Utc> = DateTime::from_utc(NaiveDateTime::from_timestamp_opt(row.2, 0).unwrap(), Utc);
            Tag::new(row.0, repository.to_string(), last_updated, row.1)
        }).collect();

        Ok(tags)
    }

    async fn list_repository_tags_page(&self, repository: &str, limit: u32, last_tag: Option<String>) -> sqlx::Result<Vec<Tag>> {
        // Query differently depending on if `last_tag` was specified
        let rows: Vec<(String, String, i64, )> = match last_tag {
            Some(last_tag) => {
                sqlx::query_as("SELECT name, image_manifest, last_updated FROM image_tags WHERE repository = ? AND name > ? ORDER BY name LIMIT ?")
                    .bind(repository)
                    .bind(last_tag)
                    .bind(limit)
                    .fetch_all(self).await?
            },
            None => {
                sqlx::query_as("SELECT name, image_manifest, last_updated FROM image_tags WHERE repository = ? ORDER BY name LIMIT ?")
                    .bind(repository)
                    .bind(limit)
                    .fetch_all(self).await?
            }
        };

        // Convert the rows into `Tag`
        let tags: Vec<Tag> = rows.into_iter().map(|row| {
            let last_updated: DateTime<Utc> = DateTime::from_utc(NaiveDateTime::from_timestamp_opt(row.2, 0).unwrap(), Utc);
            Tag::new(row.0, repository.to_string(), last_updated, row.1)
        }).collect();

        Ok(tags)
    }

    async fn get_tag(&self, repository: &str, tag: &str) -> sqlx::Result<Option<Tag>> {
        let row: (String, i64, ) = match sqlx::query_as("SELECT image_manifest, last_updated FROM image_tags WHERE name = ? AND repository = ?")
                .bind(tag)
                .bind(repository)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e);
                }
            }
        };

        let last_updated: DateTime<Utc> = DateTime::from_utc(NaiveDateTime::from_timestamp_opt(row.1, 0).unwrap(), Utc);

        Ok(Some(Tag::new(tag.to_string(), repository.to_string(), last_updated, row.0)))
    }
    
    async fn save_tag(&self, repository: &str, tag: &str, digest: &str) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO image_tags (name, repository, image_manifest, last_updated) VALUES (?, ?, ?, ?)")
            .bind(tag)
            .bind(repository)
            .bind(digest)
            .bind(chrono::Utc::now().timestamp())
            .execute(self).await?;

        Ok(())
    }

    async fn delete_tag(&self, repository: &str, tag: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM image_tags WHERE name = ? AND repository = ?")
            .bind(tag)
            .bind(repository)
            .execute(self).await?;

        Ok(())
    }

    async fn get_manifest(&self, repository: &str, digest: &str) -> sqlx::Result<Option<String>> {
        let row: (String, ) = match sqlx::query_as("SELECT content FROM image_manifests where digest = ? AND repository = ?")
                .bind(digest)
                .bind(repository)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e);
                }
            }
        };

        Ok(Some(row.0))
    }

    async fn save_manifest(&self, repository: &str, digest: &str, manifest: &str) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO image_manifests (digest, repository, content) VALUES (?, ?, ?)")
            .bind(digest)
            .bind(repository)
            .bind(manifest)
            .execute(self).await?;

        Ok(())
    }

    async fn delete_manifest(&self, repository: &str, digest: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM image_manifests where digest = ? AND repository = ?")
            .bind(digest)
            .bind(repository)
            .execute(self).await?;

        debug!("Deleted manifest {} in repository {}", digest, repository);

        let rows: Vec<(String, )> = sqlx::query_as("DELETE FROM manifest_layers WHERE manifest = ? RETURNING layer_digest")
            .bind(digest)
            .fetch_all(self).await?;
        
        debug!("Unlinked manifest {} from all linked layers", digest);

        for row in rows.into_iter() {
            let layer_digest = row.0;

            self.delete_digest(&layer_digest).await?;
        }

        debug!("Deleted all digests for manifest {}", digest);

        sqlx::query("DELETE FROM image_tags where image_manifest = ?")
            .bind(digest)
            .execute(self).await?;

        debug!("Deleted all image tags for manifest {}", digest);

        Ok(())
    }

    async fn save_repository(&self, repository: &str) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO repositories (name) VALUES (?)")
            .bind(repository)
            .execute(self).await?;
        
        Ok(())
    }

    //async fn list_repositories(&self) -> sqlx::Result<Vec<String>> {
    async fn list_repositories(&self, limit: Option<u32>, last_repo: Option<String>) -> sqlx::Result<Vec<String>> {
        let limit = limit.unwrap_or(1000); // set default limit

        // Query differently depending on if `last_repo` was specified
        let rows: Vec<(String, )> = match last_repo {
            Some(last_repo) => {
                sqlx::query_as("SELECT name FROM repositories WHERE name > ? ORDER BY name LIMIT ?")
                    .bind(last_repo)
                    .bind(limit)
                    .fetch_all(self).await?
            },
            None => {
                sqlx::query_as("SELECT name FROM repositories ORDER BY name LIMIT ?")
                    .bind(limit)
                    .fetch_all(self).await?
            }
        };

        // "unwrap" the tuple from the rows
        let repos: Vec<String> = rows.into_iter().map(|row| row.0).collect();

        Ok(repos)
    }
}