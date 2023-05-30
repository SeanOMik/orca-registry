use async_trait::async_trait;
use sqlx::{Sqlite, Pool};
use tracing::debug;

use chrono::{DateTime, Utc, NaiveDateTime, TimeZone};

use crate::dto::{Tag, user::{User, RepositoryPermissions, RegistryUserType, Permission, UserAuth, TokenInfo, LoginSource}, RepositoryVisibility};

#[async_trait]
pub trait Database {

    // Digest related functions

    /// Create the tables in the database
    async fn create_schema(&self) -> anyhow::Result<()>;

    // Tag related functions

    /// Get tags associated with a repository
    async fn list_repository_tags(&self, repository: &str,) -> anyhow::Result<Vec<Tag>>;
    async fn list_repository_tags_page(&self, repository: &str, limit: u32, last_tag: Option<String>) -> anyhow::Result<Vec<Tag>>;
    /// Get a manifest digest using the tag name.
    async fn get_tag(&self, repository: &str, tag: &str) -> anyhow::Result<Option<Tag>>;
    /// Save a tag and reference it to the manifest digest.
    async fn save_tag(&self, repository: &str, tag: &str, manifest_digest: &str) -> anyhow::Result<()>;
    /// Delete a tag.
    async fn delete_tag(&self, repository: &str, tag: &str) -> anyhow::Result<()>;

    // Manifest related functions

    /// Get a manifest's content.
    async fn get_manifest(&self, repository: &str, digest: &str) -> anyhow::Result<Option<String>>;
    /// Save a manifest's content.
    async fn save_manifest(&self, repository: &str, digest: &str, content: &str) -> anyhow::Result<()>;
    /// Delete a manifest
    /// Returns digests that this manifest pointed to.
    async fn delete_manifest(&self, repository: &str, digest: &str) -> anyhow::Result<Vec<String>>;
    async fn link_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> anyhow::Result<()>;
    async fn unlink_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> anyhow::Result<()>;

    // Repository related functions

    async fn has_repository(&self, repository: &str) -> anyhow::Result<bool>;
    async fn get_repository_visibility(&self, repository: &str) -> anyhow::Result<Option<RepositoryVisibility>>;
    /// Create a repository
    async fn save_repository(&self, repository: &str, visibility: RepositoryVisibility, owning_project: Option<String>) -> anyhow::Result<()>;
    /// List all repositories. 
    /// If limit is not specified, a default limit of 1000 will be returned.
    async fn list_repositories(&self, limit: Option<u32>, last_repo: Option<String>) -> anyhow::Result<Vec<String>>;


    /// User stuff
    async fn does_user_exist(&self, email: String) -> anyhow::Result<bool>;
    async fn create_user(&self, email: String, username: String, login_source: LoginSource) -> anyhow::Result<User>;
    async fn add_user_auth(&self, email: String, password_hash: String, password_salt: String) -> anyhow::Result<()>;
    async fn set_user_registry_type(&self, email: String, user_type: RegistryUserType) -> anyhow::Result<()>;
    async fn verify_user_login(&self, email: String, password: String) -> anyhow::Result<bool>;
    async fn get_user_registry_type(&self, email: String) -> anyhow::Result<Option<RegistryUserType>>;
    async fn get_user_repo_permissions(&self, email: String, repository: String) -> anyhow::Result<Option<RepositoryPermissions>>;
    async fn get_user_registry_usertype(&self, email: String) -> anyhow::Result<Option<RegistryUserType>>;
    async fn store_user_token(&self, token: String, email: String, expiry: DateTime<Utc>, created_at: DateTime<Utc>) -> anyhow::Result<()>;
    async fn verify_user_token(&self, token: String) -> anyhow::Result<Option<UserAuth>>;
}

#[async_trait]
impl Database for Pool<Sqlite> {
    async fn create_schema(&self) -> anyhow::Result<()> {
        sqlx::query(include_str!("schemas/schema.sql"))
            .execute(self).await?;

        debug!("Created database schema");

        Ok(())
    }

    async fn link_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO manifest_layers(manifest, layer_digest) VALUES (?, ?)")
            .bind(manifest_digest)
            .bind(layer_digest)
            .execute(self).await?;

        debug!("Linked manifest {} to layer {}", manifest_digest, layer_digest);

        Ok(())
    }

    async fn unlink_manifest_layer(&self, manifest_digest: &str, layer_digest: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM manifest_layers WHERE manifest = ? AND layer_digest = ?")
            .bind(manifest_digest)
            .bind(layer_digest)
            .execute(self).await?;

        debug!("Removed link between manifest {} and layer {}", manifest_digest, layer_digest);

        Ok(())
    }

    async fn list_repository_tags(&self, repository: &str,) -> anyhow::Result<Vec<Tag>> {
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

    async fn list_repository_tags_page(&self, repository: &str, limit: u32, last_tag: Option<String>) -> anyhow::Result<Vec<Tag>> {
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

    async fn get_tag(&self, repository: &str, tag: &str) -> anyhow::Result<Option<Tag>> {
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
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        let last_updated: DateTime<Utc> = DateTime::from_utc(NaiveDateTime::from_timestamp_opt(row.1, 0).unwrap(), Utc);

        Ok(Some(Tag::new(tag.to_string(), repository.to_string(), last_updated, row.0)))
    }
    
    async fn save_tag(&self, repository: &str, tag: &str, digest: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO image_tags (name, repository, image_manifest, last_updated) VALUES (?, ?, ?, ?)")
            .bind(tag)
            .bind(repository)
            .bind(digest)
            .bind(chrono::Utc::now().timestamp())
            .execute(self).await?;

        Ok(())
    }

    async fn delete_tag(&self, repository: &str, tag: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM image_tags WHERE 'name' = ? AND repository = ?")
            .bind(tag)
            .bind(repository)
            .execute(self).await?;

        Ok(())
    }

    async fn get_manifest(&self, repository: &str, digest: &str) -> anyhow::Result<Option<String>> {
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
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        Ok(Some(row.0))
    }

    async fn save_manifest(&self, repository: &str, digest: &str, manifest: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO image_manifests (digest, repository, content) VALUES (?, ?, ?)")
            .bind(digest)
            .bind(repository)
            .bind(manifest)
            .execute(self).await?;

        Ok(())
    }

    async fn delete_manifest(&self, repository: &str, digest: &str) -> anyhow::Result<Vec<String>> {
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

    async fn has_repository(&self, repository: &str) -> anyhow::Result<bool> {
        let row: (u32, ) = match sqlx::query_as("SELECT COUNT(1) FROM repositories WHERE \"name\" = ?")
                .bind(repository)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(false)
                },
                _ => {
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        Ok(row.0 > 0)
    }

    async fn get_repository_visibility(&self, repository: &str) -> anyhow::Result<Option<RepositoryVisibility>> {
        let row: (u32, ) = match sqlx::query_as("SELECT visibility FROM repositories WHERE 'name' = ?")
                .bind(repository)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        Ok(Some(RepositoryVisibility::try_from(row.0)?))
    }

    async fn save_repository(&self, repository: &str, visibility: RepositoryVisibility, owning_project: Option<String>) -> anyhow::Result<()> {
        // ensure that the repository was not already created
        if self.has_repository(repository).await? {
            debug!("repo exists");
            return Ok(());
        }
        debug!("repo does not exist");

        match owning_project {
            Some(owner) => {
                sqlx::query("INSERT INTO repositories (name, visibility, owning_project) VALUES (?, ?, ?)")
                    .bind(repository)
                    .bind(visibility as u32)
                    .bind(owner)
                    .execute(self).await?;
            },
            None => {
                sqlx::query("INSERT INTO repositories (name, visibility) VALUES (?, ?)")
                    .bind(repository)
                    .bind(visibility as u32)
                    .execute(self).await?;
            }
        }

        Ok(())
    }

    //async fn list_repositories(&self) -> anyhow::Result<Vec<String>> {
    async fn list_repositories(&self, limit: Option<u32>, last_repo: Option<String>) -> anyhow::Result<Vec<String>> {
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

    async fn does_user_exist(&self, email: String) -> anyhow::Result<bool> {
        let row: (u32, ) = match sqlx::query_as("SELECT COUNT(1) FROM users WHERE \"email\" = ?")
                .bind(email)
                .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(false)
                },
                _ => {
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        Ok(row.0 > 0)
    }

    async fn create_user(&self, email: String, username: String, login_source: LoginSource) -> anyhow::Result<User> {
        let username = username.to_lowercase();
        let email = email.to_lowercase();
        sqlx::query("INSERT INTO users (username, email, login_source) VALUES (?, ?, ?)")
            .bind(username.clone())
            .bind(email.clone())
            .bind(login_source as u32)
            .execute(self).await?;

        Ok(User::new(username, email, login_source))
    }

    async fn add_user_auth(&self, email: String, password_hash: String, password_salt: String) -> anyhow::Result<()> {
        let email = email.to_lowercase();
        sqlx::query("INSERT INTO user_logins (email, password_hash, password_salt) VALUES (?, ?, ?)")
            .bind(email.clone())
            .bind(password_hash)
            .bind(password_salt)
            .execute(self).await?;

        Ok(())
    }

    async fn set_user_registry_type(&self, email: String, user_type: RegistryUserType) -> anyhow::Result<()> {
        let email = email.to_lowercase();
        sqlx::query("INSERT INTO user_registry_permissions (email, user_type) VALUES (?, ?)")
            .bind(email.clone())
            .bind(user_type as u32)
            .execute(self).await?;

        Ok(())
    }

    async fn verify_user_login(&self, email: String, password: String) -> anyhow::Result<bool> {
        let email = email.to_lowercase();
        let row: (String, ) = sqlx::query_as("SELECT password_hash FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(self).await?;

        Ok(bcrypt::verify(password, &row.0)?)
    }

    async fn get_user_registry_type(&self, email: String) -> anyhow::Result<Option<RegistryUserType>> {
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
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        Ok(Some(RegistryUserType::try_from(row.0)?))
    }

    async fn get_user_repo_permissions(&self, email: String, repository: String) -> anyhow::Result<Option<RepositoryPermissions>> {
        let email = email.to_lowercase();
        
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
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        let vis = match self.get_repository_visibility(&repository).await? {
            Some(v) => v,
            None => return Ok(None),
        };

        // Also get the user type for the registry, if its admin return admin repository permissions
        let utype = match self.get_user_registry_usertype(email).await? {
            Some(t) => t,
            None => return Ok(None),
        };

        if utype == RegistryUserType::Admin {
            Ok(Some(RepositoryPermissions::new(Permission::ADMIN.bits(), vis)))
        } else {
            Ok(Some(RepositoryPermissions::new(row.0, vis)))
        }
    }

    async fn get_user_registry_usertype(&self, email: String) -> anyhow::Result<Option<RegistryUserType>> {
        let email = email.to_lowercase();
        let row: (u32, ) = sqlx::query_as("SELECT user_type FROM user_registry_permissions WHERE email = ?")
            .bind(email)
            .fetch_one(self).await?;

        Ok(Some(RegistryUserType::try_from(row.0)?))
    }

    async fn store_user_token(&self, token: String, email: String, expiry: DateTime<Utc>, created_at: DateTime<Utc>) -> anyhow::Result<()> {
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
    
    async fn verify_user_token(&self, token: String) -> anyhow::Result<Option<UserAuth>> {
        let token_row: (String, i64, i64,) = match sqlx::query_as("SELECT email, expiry, created_at FROM user_tokens WHERE token = ?")
            .bind(token.clone())
            .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        let (email, expiry, created_at) = (token_row.0, token_row.1, token_row.2);

        let user_row: (String, u32) = match sqlx::query_as("SELECT username, login_source FROM users WHERE email = ?")
            .bind(email.clone())
            .fetch_one(self).await {
            Ok(row) => row,
            Err(e) => match e {
                sqlx::Error::RowNotFound => {
                    return Ok(None)
                },
                _ => {
                    return Err(anyhow::Error::new(e));
                }
            }
        };

        /* let user_row: (String, u32) = sqlx::query_as("SELECT email, login_source FROM users WHERE email = ?")
            .bind(email.clone())
            .fetch_one(self).await?; */

        let (expiry, created_at) = (Utc.timestamp_millis_opt(expiry).single(), Utc.timestamp_millis_opt(created_at).single());
        if let (Some(expiry), Some(created_at)) = (expiry, created_at) {
            let user = User::new(email, user_row.0, LoginSource::try_from(user_row.1)?);
            let token = TokenInfo::new(token, expiry, created_at);
            let auth = UserAuth::new(user, token);

            Ok(Some(auth))
        } else {
            Ok(None)
        }
    }
}