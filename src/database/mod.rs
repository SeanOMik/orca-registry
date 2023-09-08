use async_trait::async_trait;
use rand::{Rng, distributions::Alphanumeric};
use sqlx::{Sqlite, Pool};
use tracing::{debug, warn};

use chrono::{DateTime, Utc, NaiveDateTime};

use crate::dto::{Tag, user::{User, RepositoryPermissions, RegistryUserType, Permission, UserAuth, LoginSource}, RepositoryVisibility};

pub mod sqlite;

#[async_trait]
pub trait Database {
    // Digest related functions

    /// Create the tables in the database
    async fn create_schema(&self) -> anyhow::Result<()>;

    async fn get_jwt_secret(&self) -> anyhow::Result<String>;

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
    async fn get_repository_owner(&self, repository: &str) -> anyhow::Result<Option<String>>;
    /// Create a repository
    async fn save_repository(&self, repository: &str, visibility: RepositoryVisibility, owner_email: Option<String>, owning_project: Option<String>) -> anyhow::Result<()>;
    /// List all repositories. 
    /// If limit is not specified, a default limit of 1000 will be returned.
    async fn list_repositories(&self, limit: Option<u32>, last_repo: Option<String>) -> anyhow::Result<Vec<String>>;


    /// User stuff
    async fn does_user_exist(&self, email: String) -> anyhow::Result<bool>;
    async fn create_user(&self, email: String, username: String, login_source: LoginSource) -> anyhow::Result<User>;
    async fn get_user(&self, email: String) -> anyhow::Result<Option<User>>;
    async fn add_user_auth(&self, email: String, password_hash: String, password_salt: String) -> anyhow::Result<()>;
    async fn set_user_registry_type(&self, email: String, user_type: RegistryUserType) -> anyhow::Result<()>;
    async fn verify_user_login(&self, email: String, password: String) -> anyhow::Result<bool>;
    async fn get_user_registry_type(&self, email: String) -> anyhow::Result<Option<RegistryUserType>>;
    async fn get_user_repo_permissions(&self, email: String, repository: String) -> anyhow::Result<Option<RepositoryPermissions>>;
    async fn get_user_registry_usertype(&self, email: String) -> anyhow::Result<Option<RegistryUserType>>;
    async fn store_user_token(&self, token: String, email: String, expiry: DateTime<Utc>, created_at: DateTime<Utc>) -> anyhow::Result<()>;
    #[deprecated = "Tokens are now verified using a secret"]
    async fn verify_user_token(&self, token: String) -> anyhow::Result<Option<UserAuth>>;
}