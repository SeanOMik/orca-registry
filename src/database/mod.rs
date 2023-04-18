use std::io::Read;

use async_trait::async_trait;
use bytes::Bytes;
use sqlx::{sqlite::SqliteConnection, Sqlite, Pool};
use tokio::sync::Mutex;
use tracing::debug;

use chrono::{DateTime, Utc, NaiveDateTime};

use crate::dto::Tag;

#[async_trait]
pub trait Database {

    // Digest related functions

    /// Create the tables in the database
    async fn create_schema(&self) -> sqlx::Result<()>;
    /// Check if the database is storing the digest.
    async fn has_digest(&self, digest: &str) -> bool;
    /// Get the digest bytes
    async fn get_digest(&self, digest: &str) -> sqlx::Result<Option<Bytes>>;
    /// Get the length of the digest
    async fn digest_length(&self, digest: &str) -> usize;
    /// Save digest bytes
    async fn save_digest(&self, digest: &str, bytes: &Bytes) -> sqlx::Result<()>;
    /// Delete digest
    async fn delete_digest(&self, digest: &str) -> sqlx::Result<()>;
    /// Replace the uuid with a digest
    async fn replace_digest(&self, uuid: &str, new_digest: &str) -> sqlx::Result<()>;
    async fn link_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> sqlx::Result<()>;
    async fn unlink_manifest_layer(&self, repository: &str, layer_digest: &str);

    // Tag related functions

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
}

#[async_trait]
impl Database for Pool<Sqlite> {
    async fn create_schema(&self) -> sqlx::Result<()> {
        sqlx::query(include_str!("schemas/schema.sql"))
            .execute(self).await?;

        debug!("Created database schema");

        Ok(())
    }

    async fn has_digest(&self, digest: &str) -> bool {
        todo!()
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

    async fn digest_length(&self, digest: &str) -> usize {
        todo!()
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

    async fn unlink_manifest_layer(&self, repository: &str, layer_digest: &str) {
        todo!()
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

        Ok(())
    }

    async fn save_repository(&self, repository: &str) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO repositories (name) VALUES (?)")
            .bind(repository)
            .execute(self).await?;
        
        Ok(())
    }
}