use async_trait::async_trait;
use thiserror::Error;

use chrono::{DateTime, Utc};

use crate::dto::{user::{User, RepositoryPermissions, RegistryUserType, LoginSource}, RepositoryVisibility};

mod sqlite;
mod postgres;

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
pub trait Database: Send + Sync {
    async fn run_migrations(&self) -> Result<(), DatabaseError>;

    // Repository related functions

    async fn has_repository(&self, repository: &str) -> Result<bool, DatabaseError>;
    async fn get_repository_visibility(&self, repository: &str) -> Result<Option<RepositoryVisibility>, DatabaseError>;
    async fn get_repository_owner(&self, repository: &str) -> Result<Option<String>, DatabaseError>;
    /// Create a repository
    async fn save_repository(&self, repository: &str, visibility: RepositoryVisibility, owner_email: Option<String>, owning_project: Option<String>) -> Result<(), DatabaseError>;
    /// List all repositories. 
    /// 
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
}