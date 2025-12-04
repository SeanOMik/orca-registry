pub mod ldap_driver;

use std::{collections::HashMap, sync::Arc};

use axum::{extract::{OriginalUri, Request, State}, http::{HeaderMap, HeaderName, Method, StatusCode, header}, middleware::Next, response::{IntoResponse, Response}};

use tracing::{debug, error};

use crate::{app_state::AppState, config::Config, dto::{scope::{Action, Scope, ScopeType}, user::{Permission, RegistryUserType, UserAuth}, RepositoryVisibility}, error::{ErrorMessage, OciRegistryError}};
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

pub trait DatabaseAuthDriver: AuthDriver + Database {}

#[async_trait]
impl<T> DatabaseAuthDriver for T 
where
    T: Database + AuthDriver {}

// Implement AuthDriver for anything the implements Database
#[async_trait]
impl<T> AuthDriver for T 
where
    T: Database
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
        Ok(Database::verify_user_login(self, email, password).await?)
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
pub fn auth_challenge_response(config: &Config, scope: Option<Scope>, errors: Vec<ErrorMessage>) -> Response {
    let bearer = match scope {
        Some(scope) => format!("Bearer realm=\"{}/token\",scope=\"{}\"", config.url(), scope),
        None => format!("Bearer realm=\"{}/token\"", config.url())
    };
    debug!("responding with www-authenticate header of: \"{}\"", bearer);

    let mut body = HashMap::new();
    if !errors.is_empty() {
        body.insert("errors", errors);
    }

    (
        StatusCode::UNAUTHORIZED,
        [
            ( header::WWW_AUTHENTICATE, bearer ),
            ( header::CONTENT_TYPE, "application/json".to_string() ),
            ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() )
        ],
        axum::Json(body),
    ).into_response()
}

/// Creates a response with a Forbidden (403) status code.
/// No other headers are set.
#[inline(always)]
pub fn access_denied_response(_config: &Config, scope: &Scope) -> Response {
    let details = serde_json::to_string(&scope.to_error_details()).unwrap();
    let e = ErrorMessage {
        code: OciRegistryError::Denied,
        message: Some("access to the requested resource is denied".into()),
        detail: Some(details),
    };

    let mut body = HashMap::new();
    body.insert("errors", vec![e]);

    (
        StatusCode::FORBIDDEN,
        [
            ( HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".to_string() ),
            ( header::CONTENT_TYPE, "application/json".to_string() )
        ],
        axum::Json(body),
    ).into_response()
}

pub async fn check_auth(State(state): State<Arc<AppState>>, auth: Option<UserAuth>, uri: OriginalUri, request: Request, next: Next) -> Result<Response, Rejection> {
    let config = &state.config;
    let path = uri.path();

    let url_split: Vec<&str> = path.split("/").skip(2).collect(); // skip 2 to remove /v2/ from vec
    let target_name = url_split[0].replace("%2F", "/");
    let target_type = url_split[1];

    // check if the request is targeting something inside an image repository
    if target_type == "blobs" || target_type == "uploads" || target_type == "manifests" || target_type == "tags" {
        let scope_actions: &[Action] = match request.method().clone() {
            Method::GET | Method::HEAD => &[Action::Pull],
            Method::POST | Method::PATCH | Method::PUT => &[Action::Pull, Action::Push],
            Method::DELETE => &[Action::Pull, Action::Push, Action::Delete],
            _ => {
                error!("Unexpected method ({:?}), unable to create scope actions", request.method());
                return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
            },
        };
        let scope = Scope::new(ScopeType::Repository, target_name.clone(), scope_actions);

        // respond with an auth challenge if there is no auth header.
        if auth.is_none() {
            debug!("User is not authenticated, sending challenge");
            return Ok(auth_challenge_response(config, Some(scope), vec![]));
        }
        let auth = auth.unwrap();

        let mut auth_checker = state.auth_checker.lock().await;

        // Check permission for each action
        for action in scope_actions {
            // action to permission
            let permission = match action {
                Action::Pull => Permission::PULL,
                Action::Push => Permission::PUSH,
                Action::Delete => Permission::DELETE,
                _ => Permission::NONE,
            };

            // get optional required visibility from action
            let vis = match action {
                Action::Pull => Some(RepositoryVisibility::Public),
                _ => None,
            };

            if let Some(user) = &auth.user {
                match auth_checker.user_has_permission(user.email.clone(), target_name.clone(), permission, vis).await {
                    Ok(false) => {
                        debug!("User does not have permission for repository");

                        ////"{\"errors\":[{\"code\":\"UNAUTHORIZED\",\"message\":\"access to the requested resource is not authorized\",\"detail\":[{\"Type\":\"repository\",\"Name\":\"samalba/my-app\",\"Action\":\"pull\"},{\"Type\":\"repository\",\"Name\":\"samalba/my-app\",\"Action\":\"push\"}]}]}"
                        /* let details = serde_json::to_string(&scope.to_error_details()).unwrap();
                        let e = ErrorMessage {
                            code: OciRegistryError::Denied,
                            message: Some("access to the requested resource is denied".into()),
                            detail: Some(details),
                        }; */
                        //return Ok(auth_challenge_response(config, Some(scope), vec![e]));
                        return Ok(access_denied_response(config, &scope));
                    }
                    Ok(true) => { },
                    Err(e) => {
                        error!("Error when checking user permissions! {}", e);

                        return Err((StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new()));
                    },
                }
            } else {
                // anonymous users can ONLY pull from public repos
                if permission != Permission::PULL {
                    return Ok(access_denied_response(config, &scope));
                }

                // ensure the repo is public
                let database = &state.database;
                if let Some(RepositoryVisibility::Private) = database.get_repository_visibility(&target_name).await
                        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new()))? {
                    return Ok(access_denied_response(config, &scope));
                }
            }
        }
    } else {
        debug!("Unknown auth target type! '{target_type}'");
        return Err((StatusCode::BAD_REQUEST, HeaderMap::default()));
    }

    Ok(next.run(request).await)
}