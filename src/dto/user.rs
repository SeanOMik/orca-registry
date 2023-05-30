use std::collections::HashMap;

use bitflags::bitflags;
use chrono::{DateTime, Utc};

use super::RepositoryVisibility;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoginSource {
    Database = 0,
    LDAP = 1
}

impl TryFrom<u32> for LoginSource {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Database),
            1 => Ok(Self::LDAP),
            _ => Err(anyhow::anyhow!("Invalid value for LoginSource: `{}`", value)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub username: String,
    pub email: String,
    pub source: LoginSource,
}

impl User {
    pub fn new(username: String, email: String, source: LoginSource) -> Self {
        Self {
            username,
            email,
            source,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TokenInfo {
    pub token: String,
    pub expiry: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl TokenInfo {
    pub fn new(token: String, expiry: DateTime<Utc>, created_at: DateTime<Utc>) -> Self {
        Self {
            token,
            expiry,
            created_at
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UserAuth {
    pub user: User,
    pub token: TokenInfo,
}

impl UserAuth {
    pub fn new(user: User, token: TokenInfo) -> Self {
        Self {
            user,
            token,
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Permission: u32 {
        const PULL = 0b0001;
        const PUSH = 0b0010;
        const EDIT = 0b0111;
        const ADMIN = 0b1111;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RepositoryPermissions {
    perms: u32,
    visibility: RepositoryVisibility
}

impl RepositoryPermissions {
    pub fn new(perms: u32, visibility: RepositoryVisibility) -> Self {
        Self {
            perms,
            visibility
        }
    }

    /// Check if this struct has this permission, use `RepositoryPermission`
    /// which has constants for the permissions.
    pub fn has_permission(&self, perm: Permission) -> bool {
        let perm = perm.bits();
        self.perms & perm == perm
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegistryUserType {
    Regular = 0,
    Admin = 1
}

impl TryFrom<u32> for RegistryUserType {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Regular),
            1 => Ok(Self::Admin),
            _ => Err(anyhow::anyhow!("Invalid value for RegistryUserType: `{}`", value)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegistryUser {
    user_type: RegistryUserType,
    repository_permissions: HashMap<String, RepositoryPermissions>,
}

#[allow(dead_code)]
impl RegistryUser {
    pub fn new(user_type: RegistryUserType, repository_permissions: HashMap<String, RepositoryPermissions>) -> Self {
        Self {
            user_type,
            repository_permissions,
        }
    }
}