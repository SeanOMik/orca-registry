use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use axum::{http::{StatusCode, header, HeaderName, HeaderMap, request::Parts}, extract::FromRequestParts};
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{app_state::AppState, database::Database};

use super::{RepositoryVisibility, scope::Scope};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthToken {
    #[serde(rename = "iss")]
    pub issuer: String,

    #[serde(rename = "sub")]
    pub subject: String,

    #[serde(rename = "aud")]
    pub audience: String,

    #[serde(rename = "exp")]
    #[serde(with = "chrono::serde::ts_seconds")]
    pub expiration: DateTime<Utc>,

    #[serde(rename = "nbf")]
    #[serde(with = "chrono::serde::ts_seconds")]
    pub not_before: DateTime<Utc>,

    #[serde(rename = "iat")]
    #[serde(with = "chrono::serde::ts_seconds")]
    pub issued_at: DateTime<Utc>,

    #[serde(rename = "jti")]
    pub jwt_id: String,

    pub access: Vec<Scope>,
}

impl AuthToken {
    pub fn new(issuer: String, subject: String, audience: String, expiration: DateTime<Utc>, not_before: DateTime<Utc>, issued_at: DateTime<Utc>, jwt_id: String, access: Vec<Scope>) -> Self {
        Self {
            issuer,
            subject,
            audience,
            expiration,
            not_before,
            issued_at,
            jwt_id,
            access
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

#[async_trait]
impl FromRequestParts<Arc<AppState>> for UserAuth {
    type Rejection = (StatusCode, HeaderMap);

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let bearer = format!("Bearer realm=\"{}/auth\"", state.config.url());
        let mut failure_headers = HeaderMap::new();
        failure_headers.append(header::WWW_AUTHENTICATE, bearer.parse().unwrap());
        failure_headers.append(HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".parse().unwrap());

        debug!("starting UserAuth request parts");

        let auth = String::from(
            parts.headers
                .get(header::AUTHORIZATION)
                .ok_or((StatusCode::UNAUTHORIZED, failure_headers.clone()))?
                .to_str()
                .map_err(|_| (StatusCode::UNAUTHORIZED, failure_headers.clone()))?
        );

        debug!("got auth header");

        let token = match auth.split_once(' ') {
            Some((auth, token)) if auth == "Bearer" => token,
            // This line would allow empty tokens
            //_ if auth == "Bearer" => Ok(AuthToken(None)),
            _ => return Err( (StatusCode::UNAUTHORIZED, failure_headers) ),
        };

        debug!("got token");

        // If the token is not valid, return an unauthorized response
        let database = &state.database;
        if let Ok(Some(user)) = database.verify_user_token(token.to_string()).await {
            debug!("Authenticated user through request extractor: {}", user.user.username);

            Ok(user)
        } else {
            debug!("Failure to verify user token, responding with auth realm");

            Err((
                StatusCode::UNAUTHORIZED,
                failure_headers
            ))
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Permission: u32 {
        const NONE = 0b0000;
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