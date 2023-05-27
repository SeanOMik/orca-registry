use std::{collections::HashSet, ops::Deref, sync::Arc};

use axum::{extract::{State, Path}, http::{StatusCode, HeaderMap, header, HeaderName, Request}, middleware::Next, response::{Response, IntoResponse}};

use tracing::debug;

use crate::{app_state::AppState, dto::{user::{Permission, RegistryUserType}, RepositoryVisibility}, config::Config};
use crate::database::Database;

/// Temporary struct for storing auth information in memory.
pub struct MemoryAuthStorage {
    pub valid_tokens: HashSet<String>,
}

impl MemoryAuthStorage {
    pub fn new() -> Self {
        Self {
            valid_tokens: HashSet::new(),
        }
    }
}

#[derive(Clone)]
pub struct AuthToken(pub String);

impl Deref for AuthToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

type Rejection = (StatusCode, HeaderMap);

pub async fn require_auth<B>(State(state): State<Arc<AppState>>, mut request: Request<B>, next: Next<B>) -> Result<Response, Rejection> {
    let bearer = format!("Bearer realm=\"{}/auth\"", state.config.get_url());
    let mut failure_headers = HeaderMap::new();
    failure_headers.append(header::WWW_AUTHENTICATE, bearer.parse().unwrap());
    failure_headers.append(HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".parse().unwrap());

    let auth = String::from(
        request.headers().get(header::AUTHORIZATION)
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
    let database = &state.database;
    if let Some(user) = database.verify_user_token(token.to_string()).await.unwrap() {
        debug!("Authenticated user through middleware: {}", user.user.username);

        request.extensions_mut().insert(user);

        Ok(next.run(request).await)
    } else {
        let bearer = format!("Bearer realm=\"{}/auth\"", state.config.get_url());
        Ok((
            StatusCode::UNAUTHORIZED,
            [
                ( header::WWW_AUTHENTICATE, bearer ),
                ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() )
            ]
        ).into_response())
    }
}

pub async fn does_user_have_permission(database: &impl Database, username: String, repository: String, permission: Permission) -> anyhow::Result<bool> {
    does_user_have_repository_permission(database, username, repository, permission, None).await
}

/// Checks if a user has permission to do something in a repository.
/// 
/// * `database`: Database connection.
/// * `username`: Name of the user.
/// * `repository`: Name of the repository.
/// * `permissions`: Permission to check for.
/// * `required_visibility`: Specified if there is a specific visibility of the repository that will give the user permission.
pub async fn does_user_have_repository_permission(database: &impl Database, username: String, repository: String, permission: Permission, required_visibility: Option<RepositoryVisibility>) -> anyhow::Result<bool> {
    let allowed_to = {
        match database.get_user_registry_type(username.clone()).await? {
            Some(RegistryUserType::Admin) => true,
            _ => {
                if let Some(perms) = database.get_user_repo_permissions(username, repository.clone()).await? {
                    if perms.has_permission(permission) {
                        return Ok(true);
                    }
                }

                if let Some(vis) = required_visibility {
                    if let Some(repo_vis) = database.get_repository_visibility(&repository).await? {
                        if vis == repo_vis {
                            return Ok(true);
                        }
                    }
                }

                false
            }
            /* match database.get_user_repo_permissions(username, repository).await.unwrap() {
                Some(perms) => if perms.has_permission(permission) { true } else { false },
                _ => false,
            } */
        }
    };

    Ok(allowed_to)
}

pub fn get_unauthenticated_response(config: &Config) -> Response {
    let bearer = format!("Bearer realm=\"{}/auth\"", config.get_url());
    (
        StatusCode::UNAUTHORIZED,
        [
            ( header::WWW_AUTHENTICATE, bearer ),
            ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() )
        ]
    ).into_response()
}