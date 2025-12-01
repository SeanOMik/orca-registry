use async_trait::async_trait;
use rand::{Rng, distr::Alphanumeric};
use sqlx::{Sqlite, Pool};
use thiserror::Error;
use tracing::{debug, warn};

use chrono::{DateTime, Utc, NaiveDateTime};

use crate::dto::{Tag, user::{User, RepositoryPermissions, RegistryUserType, Permission, UserAuth, LoginSource}, RepositoryVisibility};

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("{0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("password error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

#[async_trait]
pub trait Database {
    // Digest related functions

    /// Create the tables in the database
    async fn create_schema(&self) -> Result<(), DatabaseError>;

    async fn get_jwt_secret(&self) -> Result<String, DatabaseError>;

    // Tag related functions

    /// Get tags associated with a repository
    async fn list_repository_tags(&self, repository: &str,) -> Result<Vec<Tag>, DatabaseError>;
    async fn list_repository_tags_page(&self, repository: &str, limit: u32, last_tag: Option<String>) -> Result<Vec<Tag>, DatabaseError>;
    /// Get a manifest digest using the tag name.
    async fn get_tag(&self, repository: &str, tag: &str) -> Result<Option<Tag>, DatabaseError>;
    /// Save a tag and reference it to the manifest digest.
    async fn save_tag(&self, repository: &str, tag: &str, manifest_digest: &str) -> Result<(), DatabaseError>;
    /// Delete a tag.
    async fn delete_tag(&self, repository: &str, tag: &str) -> Result<(), DatabaseError>;
    async fn update_tag(&self, repository: &str, tag: &str, manifest_digest: &str) -> Result<(), DatabaseError>;

    // Manifest related functions

    /// Get a manifest's content.
    async fn get_manifest(&self, repository: &str, digest: &str) -> Result<Option<String>, DatabaseError>;
    /// Save a manifest's content.
    async fn save_manifest(&self, repository: &str, digest: &str, content: &str, subject: Option<&String>) -> Result<(), DatabaseError>;
    /// Delete a manifest
    /// Returns digests that this manifest pointed to.
    async fn delete_manifest(&self, repository: &str, digest: &str) -> Result<Vec<String>, DatabaseError>;
    async fn link_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> Result<(), DatabaseError>;
    async fn unlink_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> Result<(), DatabaseError>;

    // Repository related functions

    async fn has_repository(&self, repository: &str) -> Result<bool, DatabaseError>;
    async fn get_repository_visibility(&self, repository: &str) -> Result<Option<RepositoryVisibility>, DatabaseError>;
    async fn get_repository_owner(&self, repository: &str) -> Result<Option<String>, DatabaseError>;
    /// Create a repository
    async fn save_repository(&self, repository: &str, visibility: RepositoryVisibility, owner_email: Option<String>, owning_project: Option<String>) -> Result<(), DatabaseError>;
    /// List all repositories. 
    /// If limit is not specified, a default limit of 1000 will be returned.
    async fn list_repositories(&self, limit: Option<u32>, last_repo: Option<String>) -> Result<Vec<String>, DatabaseError>;


    /// User stuff
    async fn does_user_exist(&self, email: String) -> Result<bool, DatabaseError>;
    async fn create_user(&self, email: String, username: String, login_source: LoginSource) -> Result<User, DatabaseError>;
    async fn get_user(&self, email: String) -> Result<Option<User>, DatabaseError>;
    async fn add_user_auth(&self, email: String, password_hash: String, password_salt: String) -> Result<(), DatabaseError>;
    async fn set_user_registry_type(&self, email: String, user_type: RegistryUserType) -> Result<(), DatabaseError>;
    async fn verify_user_login(&self, email: String, password: String) -> Result<bool, DatabaseError>;
    async fn get_user_registry_type(&self, email: String) -> Result<Option<RegistryUserType>, DatabaseError>;
    async fn get_user_repo_permissions(&self, email: String, repository: String) -> Result<Option<RepositoryPermissions>, DatabaseError>;
    async fn get_user_registry_usertype(&self, email: String) -> Result<Option<RegistryUserType>, DatabaseError>;
    async fn store_user_token(&self, token: String, email: String, expiry: DateTime<Utc>, created_at: DateTime<Utc>) -> Result<(), DatabaseError>;
    #[deprecated = "Tokens are now verified using a secret"]
    async fn verify_user_token(&self, token: String) -> Result<Option<UserAuth>, DatabaseError>;
}

#[async_trait]
impl Database for Pool<Sqlite> {
    async fn create_schema(&self) -> Result<(), DatabaseError> {
        let orca_version = "0.1.0";
        let schema_version = "0.0.1";

        let row: Option<(u32, )> = match sqlx::query_as("SELECT COUNT(1) FROM orca WHERE \"schema_version\" = ?")
                .bind(schema_version)
                .fetch_one(self).await {
            Ok(row) => Some(row),
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    None
                },
                // ignore no such table errors
                sqlx::Error::Database(b) if b.message().starts_with("no such table") => None,
                _ => {
                    return Err(e.into());
                }
            }
        };

        sqlx::query(include_str!("schemas/schema.sql"))
            .execute(self).await?;
        debug!("Created database schema");

        if row.is_none() || row.unwrap().0 == 0 {
            let jwt_sec: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();

            // create schema
            // TODO: Check if needed
            /* sqlx::query(include_str!("schemas/schema.sql"))
                .execute(self).await?;
            debug!("Created database schema"); */

            sqlx::query("INSERT INTO orca(orca_version, schema_version, jwt_secret) VALUES (?, ?, ?)")
                .bind(orca_version)
                .bind(schema_version)
                .bind(jwt_sec)
                .execute(self).await?;
            debug!("Inserted information about orca!");
        }

        Ok(())
    }

    async fn get_jwt_secret(&self) -> Result<String, DatabaseError> {
        let rows: (String, ) = sqlx::query_as("SELECT jwt_secret FROM orca WHERE id = (SELECT max(id) FROM orca)")
            .fetch_one(self).await?;

        Ok(rows.0)
    }

    async fn link_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> Result<(), DatabaseError> {
        sqlx::query("INSERT INTO manifest_layers(manifest, layer_digest) VALUES (?, ?)")
            .bind(manifest_digest)
            .bind(layer_digest)
            .execute(self).await?;

        debug!("Linked manifest {} to layer {}", manifest_digest, layer_digest);

        Ok(())
    }

    async fn unlink_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> Result<(), DatabaseError> {
        sqlx::query("DELETE FROM manifest_layers WHERE manifest = ? AND layer_digest = ?")
            .bind(manifest_digest)
            .bind(layer_digest)
            .execute(self).await?;

        debug!("Removed link between manifest {} and layer {}", manifest_digest, layer_digest);

        Ok(())
    }

    async fn list_repository_tags(&self, repository: &str,) -> Result<Vec<Tag>, DatabaseError> {
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

    async fn list_repository_tags_page(&self, repository: &str, limit: u32, last_tag: Option<String>) -> Result<Vec<Tag>, DatabaseError> {
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

    async fn get_tag(&self, repository: &str, tag: &str) -> Result<Option<Tag>, DatabaseError> {
        debug!("get tag");
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
                    return Err(e.into());
                }
            }
        };

        let last_updated: DateTime<Utc> = DateTime::from_utc(NaiveDateTime::from_timestamp_opt(row.1, 0).unwrap(), Utc);

        Ok(Some(Tag::new(tag.to_string(), repository.to_string(), last_updated, row.0)))
    }
    
    async fn save_tag(&self, repository: &str, tag: &str, digest: &str) -> Result<(), DatabaseError> {
        sqlx::query("INSERT INTO image_tags (name, repository, image_manifest, last_updated) VALUES (?, ?, ?, ?)")
            .bind(tag)
            .bind(repository)
            .bind(digest)
            .bind(chrono::Utc::now().timestamp())
            .execute(self).await?;

        Ok(())
    }

    async fn delete_tag(&self, repository: &str, tag: &str) -> Result<(), DatabaseError> {
        sqlx::query("DELETE FROM image_tags WHERE name = ? AND repository = ?")
            .bind(tag)
            .bind(repository)
            .execute(self).await?;

        Ok(())
    }

    async fn update_tag(&self, repository: &str, tag: &str, manifest_digest: &str) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE image_tags SET image_manifest = ?, last_updated = ? WHERE name = ? AND repository = ?")
            .bind(manifest_digest)
            .bind(chrono::Utc::now().timestamp())
            .bind(tag)
            .bind(repository)
            .execute(self).await?;
        Ok(())
    }

    async fn get_manifest(&self, repository: &str, digest: &str) -> Result<Option<String>, DatabaseError> {
        let row: Option<(String,)> = sqlx::query_as("SELECT content FROM image_manifests where digest = ? AND repository = ?")
            .bind(digest)
            .bind(repository)
            .fetch_optional(self).await?;

        Ok(row.map(|(c,)| c))
    }

    async fn save_manifest(&self, repository: &str, digest: &str, manifest: &str, subject_digest: Option<&String>) -> Result<(), DatabaseError> {
        sqlx::query("INSERT INTO image_manifests (digest, repository, subject_digest, content) VALUES (?, ?, ?, ?)")
            .bind(digest)
            .bind(repository)
            .bind(subject_digest)
            .bind(manifest)
            .execute(self).await?;

        Ok(())
    }

    async fn delete_manifest(&self, repository: &str, digest: &str) -> Result<Vec<String>, DatabaseError> {
        sqlx::query("DELETE FROM image_manifests where digest = ? AND repository = ?")
            .bind(digest)
            .bind(repository)
            .execute(self).await?;

        debug!("Deleted manifest {} in repository {}", digest, repository);

        let rows: Vec<(String, )> = sqlx::query_as("DELETE FROM manifest_layers WHERE manifest = ? RETURNING layer_digest")
            .bind(digest)
            .fetch_all(self).await?;
        
        debug!("Unlinked manifest {} from all linked layers", digest);


        let digests = rows.into_iter().map(|r| r.0).collect();

        debug!("Deleted all digests for manifest {}", digest);

        sqlx::query("DELETE FROM image_tags where image_manifest = ?")
            .bind(digest)
            .execute(self).await?;

        debug!("Deleted all image tags for manifest {}", digest);

        Ok(digests)
    }

    async fn has_repository(&self, repository: &str) -> Result<bool, DatabaseError> {
        let row: (u32, ) = match sqlx::query_as("SELECT COUNT(1) FROM repositories WHERE \"name\" = ?")
                .bind(repository)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(false)
                },
                _ => {
                    return Err(e.into());
                }
            }
        };

        Ok(row.0 > 0)
    }

    async fn get_repository_visibility(&self, repository: &str) -> Result<Option<RepositoryVisibility>, DatabaseError> {
        let row: (u32, ) = match sqlx::query_as("SELECT visibility FROM repositories WHERE name = ?")
                .bind(repository)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e.into());
                }
            }
        };

        Ok(RepositoryVisibility::try_from(row.0).ok())
    }

    async fn get_repository_owner(&self, repository: &str) -> Result<Option<String>, DatabaseError> {
        let row: (String, ) = match sqlx::query_as("SELECT owner_email FROM repositories WHERE name = ?")
                .bind(repository)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e.into());
                }
            }
        };

        Ok(Some(row.0))
    }

    async fn save_repository(&self, repository: &str, visibility: RepositoryVisibility, owner_email: Option<String>, owning_project: Option<String>) -> Result<(), DatabaseError> {
        // ensure that the repository was not already created
        if self.has_repository(repository).await? {
            debug!("Skipping creation of repository since it already exists");
            return Ok(());
        }

        // unwrap None values to empty for inserting into database
        let owner_email = owner_email.unwrap_or(String::new());
        let owning_project = owning_project.unwrap_or(String::new());

        sqlx::query("INSERT INTO repositories (name, visibility, owner_email, owning_project) VALUES (?, ?, ?, ?)")
            .bind(repository)
            .bind(visibility as u32)
            .bind(owner_email)
            .bind(owning_project)
            .execute(self).await?;

        Ok(())
    }

    //async fn list_repositories(&self) -> Result<Vec<String>, DatabaseError> {
    async fn list_repositories(&self, limit: Option<u32>, last_repo: Option<String>) -> Result<Vec<String>, DatabaseError> {
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

    async fn does_user_exist(&self, email: String) -> Result<bool, DatabaseError> {
        let row: (u32, ) = match sqlx::query_as("SELECT COUNT(1) FROM users WHERE \"email\" = ?")
                .bind(email)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(false)
                },
                _ => {
                    return Err(e.into());
                }
            }
        };

        Ok(row.0 > 0)
    }

    async fn create_user(&self, email: String, username: String, login_source: LoginSource) -> Result<User, DatabaseError> {
        let username = username.to_lowercase();
        let email = email.to_lowercase();
        sqlx::query("INSERT INTO users (username, email, login_source) VALUES (?, ?, ?)")
            .bind(username.clone())
            .bind(email.clone())
            .bind(login_source as u32)
            .execute(self).await?;

        Ok(User::new(username, email, login_source))
    }

    async fn get_user(&self, email: String) -> Result<Option<User>, DatabaseError> {
        let email = email.to_lowercase();
        let row: (String, u32) = match sqlx::query_as("SELECT username, login_source FROM users WHERE email = ?")
            .bind(email.clone())
            .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e.into());
                }
            }
        };

        Ok(Some(User::new(row.0, email, LoginSource::try_from(row.1)?)))
    }

    async fn add_user_auth(&self, email: String, password_hash: String, password_salt: String) -> Result<(), DatabaseError> {
        let email = email.to_lowercase();
        sqlx::query("INSERT INTO user_logins (email, password_hash, password_salt) VALUES (?, ?, ?)")
            .bind(email.clone())
            .bind(password_hash)
            .bind(password_salt)
            .execute(self).await?;

        Ok(())
    }

    async fn set_user_registry_type(&self, email: String, user_type: RegistryUserType) -> Result<(), DatabaseError> {
        let email = email.to_lowercase();
        sqlx::query("INSERT INTO user_registry_permissions (email, user_type) VALUES (?, ?)")
            .bind(email.clone())
            .bind(user_type as u32)
            .execute(self).await?;

        Ok(())
    }

    async fn verify_user_login(&self, email: String, password: String) -> Result<bool, DatabaseError> {
        let email = email.to_lowercase();

        let row: (String,) = match sqlx::query_as("SELECT password_hash FROM user_logins WHERE email = ?")
            .bind(email)
            .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(false)
                },
                _ => {
                    return Err(e.into());
                }
            }
        };

        Ok(bcrypt::verify(password, &row.0)?)
    }

    async fn get_user_registry_type(&self, email: String) -> Result<Option<RegistryUserType>, DatabaseError> {
        let email = email.to_lowercase();
        
        let row: (u32, ) = match sqlx::query_as("SELECT user_type FROM user_registry_permissions WHERE email = ?")
                .bind(email)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e.into());
                }
            }
        };

        Ok(RegistryUserType::try_from(row.0).ok())
    }

    async fn get_user_repo_permissions(&self, email: String, repository: String) -> Result<Option<RepositoryPermissions>, DatabaseError> {
        let email = email.to_lowercase();

        debug!("email: {email}, repo: {repository}");
        
        let row: (u32, ) = match sqlx::query_as("SELECT repository_permissions FROM user_repo_permissions WHERE email = ? AND repository_name = ?")
                .bind(email.clone())
                .bind(repository.clone())
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(e.into());
                }
            }
        };

        let vis = match self.get_repository_visibility(&repository).await? {
            Some(v) => v,
            None => {
                warn!("Failure to find visibility for repository '{}'", repository);
                return Ok(None)
            },
        };

        // Also get the user type for the registry, if its admin return admin repository permissions
        let utype = match self.get_user_registry_usertype(email).await? {
            Some(t) => t,
            // assume a regular user is their type is not found
            None => RegistryUserType::Regular,
        };

        if utype == RegistryUserType::Admin {
            Ok(Some(RepositoryPermissions::new(Permission::ADMIN.bits(), vis)))
        } else {
            Ok(Some(RepositoryPermissions::new(row.0, vis)))
        }
    }

    async fn get_user_registry_usertype(&self, email: String) -> Result<Option<RegistryUserType>, DatabaseError> {
        let email = email.to_lowercase();
        let row: (u32, ) = sqlx::query_as("SELECT user_type FROM user_registry_permissions WHERE email = ?")
            .bind(email)
            .fetch_one(self).await?;

        Ok(RegistryUserType::try_from(row.0).ok())
    }

    async fn store_user_token(&self, token: String, email: String, expiry: DateTime<Utc>, created_at: DateTime<Utc>) -> Result<(), DatabaseError> {
        let email = email.to_lowercase();
        let expiry = expiry.timestamp();
        let created_at = created_at.timestamp();
        sqlx::query("INSERT INTO user_tokens (token, email, expiry, created_at) VALUES (?, ?, ?, ?)")
            .bind(token)
            .bind(email)
            .bind(expiry)
            .bind(created_at)
            .execute(self).await?;

        Ok(())
    }
    
    async fn verify_user_token(&self, _token: String) -> Result<Option<UserAuth>, DatabaseError> {
        panic!("ERR: Database::verify_user_token is deprecated!")
    }
}