use std::io::Read;

use async_trait::async_trait;
use bytes::Bytes;
use sqlx::{sqlite::SqliteConnection, Sqlite, Pool};
use tokio::sync::Mutex;

#[async_trait]
pub trait Database {
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
    async fn associate_manifest_blob(&self, manifest_digest: &str, layer_digest: &str);
    async fn disassociate_manifest_blob(&self, repository: &str, layer_digest: &str);
}

#[async_trait]
impl Database for Pool<Sqlite> {
    async fn create_schema(&self) -> sqlx::Result<()> {
        sqlx::query(include_str!("schemas/schema.sql"))
            .execute(self).await?;

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

        Ok(Some(bytes))
    }

    async fn digest_length(&self, digest: &str) -> usize {
        todo!()
    }

    async fn save_digest(&self, digest: &str, bytes: &Bytes) -> sqlx::Result<()> {
        let bytes = bytes.bytes().map(|b| b.unwrap()).collect::<Vec<u8>>();

        sqlx::query("INSERT INTO layer_blobs (digest, blob) VALUES (?, ?)")
            .bind(digest)
            .bind(bytes)
            .execute(self).await?;

        Ok(())
    }

    async fn delete_digest(&self, digest: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM layer_blobs WHERE digest = ?")
            .bind(digest)
            .execute(self).await?;

        Ok(())
    }

    async fn replace_digest(&self, uuid: &str, new_digest: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE layer_blobs SET digest = ? WHERE digest = ?")
            .bind(new_digest)
            .bind(uuid)
            .execute(self).await?;

        Ok(())
    }

    async fn associate_manifest_blob(&self, manifest_digest: &str, layer_digest: &str) {
        todo!()
    }

    async fn disassociate_manifest_blob(&self, repository: &str, layer_digest: &str) {
        todo!()
    }
}

/* pub enum DatabaseConnection {
    Sqlite(SqliteConnection),
    Postgres(PgConnection),
}

pub struct Database {
    connection: DatabaseConnection,
}

impl Database {
    pub fn from_connection(connection: DatabaseConnection) -> Self {
        Self {
            connection,
        }
    }

    pub fn new_sqlite_connection(url: &str) -> ConnectionResult<Self> {
        let connection = DatabaseConnection::Sqlite(SqliteConnection::establish(url)?);

        Ok(Self {
            connection,
        })
    }

    pub fn new_postgres_connection(url: &str) -> ConnectionResult<Self> {
        let connection = DatabaseConnection::Postgres(PgConnection::establish(url)?);

        Ok(Self {
            connection,
        })
    }
} */