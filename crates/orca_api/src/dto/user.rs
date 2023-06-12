use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use axum::{http::{StatusCode, header, HeaderName, HeaderMap, request::Parts}, extract::FromRequestParts};
use anyhow::anyhow;
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use hmac::{Hmac, digest::KeyInit};
use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
    pub user: Option<User>,
    pub token: AuthToken,
}

impl UserAuth {
    pub fn new(user: Option<User>, token: AuthToken) -> Self {
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
        let bearer = format!("Bearer realm=\"{}/token\"", state.config.url());
        let mut failure_headers = HeaderMap::new();
        failure_headers.append(header::WWW_AUTHENTICATE, bearer.parse().unwrap());
        failure_headers.append(HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".parse().unwrap());

        let auth = String::from(
            parts.headers
                .get(header::AUTHORIZATION)
                .ok_or((StatusCode::UNAUTHORIZED, failure_headers.clone()))?
                .to_str()
                .map_err(|_| (StatusCode::UNAUTHORIZED, failure_headers.clone()))?
        );

        let token = match auth.split_once(' ') {
            Some((auth, token)) if auth == "Bearer" => token,
            // This line would allow empty tokens
            //_ if auth == "Bearer" => Ok(AuthToken(None)),
            _ => return Err( (StatusCode::UNAUTHORIZED, failure_headers) ),
        };

        // If the token is not valid, return an unauthorized response
        let jwt_key: Hmac<Sha256> = Hmac::new_from_slice(state.config.jwt_key.as_bytes())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new()) )?;

        match VerifyWithKey::<AuthToken>::verify_with_key(token, &jwt_key) {
            Ok(token) => {
                // attempt to get the user
                if !token.subject.is_empty() {
                    let database = &state.database;
                    if let Ok(Some(user)) = database.get_user(token.subject.clone()).await {
                        return Ok(UserAuth::new(Some(user), token));
                    } else {
                        debug!("failure to get user from token: {:?}", token);
                    }
                } else {
                    return Ok(UserAuth::new(None, token));
                }

                /* let database = &state.database;
                if let Ok(user) = database.get_user(token.subject.clone()).await {
                    return Ok(UserAuth::new(user, token));
                } else {
                    debug!("failure to get user from token: {:?}", token);
                } */
            },
            Err(e) => {
                debug!("Failure to verify user token: '{}'", e);
            }
        }

        debug!("Failure to verify user token, responding with auth realm");

        Err((
            StatusCode::UNAUTHORIZED,
            failure_headers
        ))
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Permission: u32 {
        const NONE = 0b00000;
        const PULL = 0b00001;
        const PUSH = 0b00010;
        const EDIT = 0b00111;
        const DELETE = 0b01111;
        const ADMIN = 0b11111;
    }
}

impl TryFrom<&str> for Permission {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pull" => Ok(Self::PULL),
            "push" => Ok(Self::PUSH),
            "edit" => Ok(Self::EDIT),
            "admin" => Ok(Self::ADMIN),
            "*" => Ok(Self::ADMIN),
            _ => Err(anyhow!("Unknown permission name '{}'!", value)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
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

    pub fn add_permission(&mut self, perm: Permission) {
        let perm = perm.bits();

        self.perms |= perm;
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