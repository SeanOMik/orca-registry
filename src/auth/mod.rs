pub mod ldap_driver;

use std::sync::Arc;

use axum::{extract::State, http::{StatusCode, HeaderMap, header, HeaderName, Request, Method}, middleware::Next, response::{Response, IntoResponse}};

use tracing::{debug, warn, error};

use crate::{app_state::AppState, dto::{user::{Permission, RegistryUserType, UserAuth}, RepositoryVisibility, scope::{Scope, ScopeType, Action}}, config::Config};
use crate::database::Database;

use async_trait::async_trait;

#[async_trait]
pub trait AuthDriver: Send + Sync {
    /// Checks if a user has permission to do something in a repository.
    /// 
    /// * `username`: Name of the user.
    /// * `repository`: Name of the repository.
    /// * `permissions`: Permission to check for.
    /// * `required_visibility`: Specified if there is a specific visibility of the repository that will give the user permission.
    async fn user_has_permission(&mut self, email: String, repository: String, permission: Permission, required_visibility: Option<RepositoryVisibility>) -> anyhow::Result<bool>;
    async fn verify_user_login(&mut self, email: String, password: String) -> anyhow::Result<bool>;
}

// Implement AuthDriver for anything the implements Database
#[async_trait]
impl<T> AuthDriver for T 
where
    T: Database + Send + Sync
{
    async fn user_has_permission(&mut self, email: String, repository: String, permission: Permission, required_visibility: Option<RepositoryVisibility>) -> anyhow::Result<bool> {
        match self.get_repository_owner(&repository).await? {
            Some(owner) if owner == email => return Ok(true),
            Some(_other_owner) => {
                match self.get_user_registry_type(email.clone()).await? {
                    Some(RegistryUserType::Admin) => return Ok(true),
                    _ => {
                        return Ok(check_user_permissions(self, email, repository, permission, required_visibility).await?);
                    }
                }
            },
            None => {
                // If the repository does not exist, see if its the per-user repositories and autocreate it.
                if let Some(user) = self.get_user(email.clone()).await? {
                    let username = user.username.to_lowercase();
                    if repository.starts_with(&username) {
                        self.save_repository(&repository, RepositoryVisibility::Private, Some(email), None).await?;
                        return Ok(true);
                    }
                }
            },
        }

        Ok(false)
    }

    async fn verify_user_login(&mut self, email: String, password: String) -> anyhow::Result<bool> {
        Database::verify_user_login(self, email, password).await
    }
}

// This ONLY checks permissions, does not check user type
pub async fn check_user_permissions<D>(database: &D, email: String, repository: String, permission: Permission, required_visibility: Option<RepositoryVisibility>) -> anyhow::Result<bool>
where
    D: Database
{
    if let Some(perms) = database.get_user_repo_permissions(email, repository.clone()).await? {
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

    Ok(false)
}

type Rejection = (StatusCode, HeaderMap);

/// Creates a response with an Unauthorized (401) status code.
/// The www-authenticate header is set to notify the client of where to authorize with.
#[inline(always)]
pub fn auth_challenge_response(config: &Config, scope: Option<Scope>) -> Response {
    let bearer = match scope {
        Some(scope) => format!("Bearer realm=\"{}/auth\",scope=\"{}\"", config.url(), scope),
        None => format!("Bearer realm=\"{}/auth\"", config.url())
    };
    debug!("responding with www-authenticate header of: \"{}\"", bearer);

    (
        StatusCode::UNAUTHORIZED,
        [
            ( header::WWW_AUTHENTICATE, bearer ),
            ( header::CONTENT_TYPE, "application/json".to_string() ),
            ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() )
        ],
        //"{\"errors\":[{\"code\":\"UNAUTHORIZED\",\"message\":\"access to the requested resource is not authorized\",\"detail\":[{\"Type\":\"repository\",\"Name\":\"samalba/my-app\",\"Action\":\"pull\"},{\"Type\":\"repository\",\"Name\":\"samalba/my-app\",\"Action\":\"push\"}]}]}"
    ).into_response()
}

/// Creates a response with a Forbidden (403) status code.
/// No other headers are set.
#[inline(always)]
pub fn access_denied_response(_config: &Config) -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() )
        ]
    ).into_response()
}

pub async fn check_auth<B>(State(state): State<Arc<AppState>>, auth: Option<UserAuth>, request: Request<B>, next: Next<B>) -> Result<Response, Rejection> {
    let config = &state.config;
    // note: url is relative to /v2
    let url = request.uri().to_string();

    if url == "/" {
        // if auth is none, then the client needs to authenticate
        if auth.is_none() {
            debug!("Responding to /v2/ with an auth challenge");
            return Ok(auth_challenge_response(config, None));
        }

        debug!("user is authed");

        // the client is authenticating right now
        return Ok(next.run(request).await);
    }
    
    let url_split: Vec<&str> = url.split("/").skip(1).collect();
    let target_name = url_split[0].replace("%2F", "/");
    let target_type = url_split[1];

    // check if the request is targeting something inside an image repository
    if target_type == "blobs" || target_type == "uploads" || target_type == "manifests" {
        let scope_actions: &[Action] = match request.method().clone() {
            Method::GET | Method::HEAD => &[Action::Pull],
            Method::POST | Method::PATCH | Method::PUT => &[Action::Pull, Action::Push],
            _ => &[],
        };
        let scope = Scope::new(ScopeType::Repository, target_name.clone(), scope_actions);

        // respond with an auth challenge if there is no auth header.
        //if !headers.contains_key(header::AUTHORIZATION) && auth.is_none() {
        if auth.is_none() {
            debug!("User is not authenticated, sending challenge");
            return Ok(auth_challenge_response(config, Some(scope)));
        }
        let auth = auth.unwrap();

        let mut auth_checker = state.auth_checker.lock().await;

        // Check permission for each action
        for action in scope_actions {
            // action to permission
            let permission = match action {
                Action::Pull => Permission::PULL,
                Action::Push => Permission::PUSH,
                _ => Permission::NONE,
            };

            // get optional required visibility from action
            let vis = match action {
                Action::Pull => Some(RepositoryVisibility::Public),
                _ => None,
            };

            if let Some(user) = &auth.user {
                match auth_checker.user_has_permission(user.email.clone(), target_name.clone(), permission, vis).await {
                    Ok(false) => return Ok(auth_challenge_response(config, Some(scope))),
                    Ok(true) => { },
                    Err(e) => {
                        error!("Error when checking user permissions! {}", e);

                        return Err((StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new()));
                    },
                }
            } else {
                // anonymous users can ONLY pull from public repos
                if permission != Permission::PULL {
                    return Ok(access_denied_response(config));
                }

                // ensure the repo is public
                let database = &state.database;
                if let Some(RepositoryVisibility::Private) = database.get_repository_visibility(&target_name).await
                        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new()))? {
                    return Ok(access_denied_response(config));
                }
            }
        }
    } else {
        warn!("Unhandled auth check for '{target_type}'!!"); // TODO
    }

    Ok(next.run(request).await)
}