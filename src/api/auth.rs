use std::{
    collections::HashMap,
    sync::Arc,
    time::SystemTime,
};

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Form,
};
use axum_auth::AuthBasic;
use chrono::{DateTime, Days, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, span, Level};

use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use sha2::Sha256;

use rand::Rng;

use crate::{database::Database, dto::scope::Action};
use crate::{
    app_state::AppState,
    dto::{
        scope::{Scope, ScopeType},
        user::{AuthToken, TokenInfo},
        RepositoryVisibility,
    },
};

use crate::auth::auth_challenge_response;

#[derive(Debug)]
pub struct TokenAuthRequest {
    user: Option<String>,
    password: Option<String>,
    account: Option<String>,
    /// The name of the service which hosts the resource.
    /// I don't think this is necessary since the auth service is embedded with the registry.
    pub service: Option<String>,
    pub scope: Vec<Scope>,
    offline_token: Option<bool>,
    client_id: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct AuthForm {
    username: String,
    password: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AuthResponse {
    token: String,
    expires_in: u32,
    issued_at: String,
}

fn create_jwt_token(jwt_key: String, account: Option<&str>, scopes: Vec<Scope>) -> anyhow::Result<TokenInfo> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(jwt_key.as_bytes())?;

    let now = chrono::offset::Utc::now();

    // Expire the token in a day
    let expiration = now.checked_add_days(Days::new(1)).unwrap();

    let mut rng = rand::thread_rng();
    let jwtid = format!("{}", rng.gen::<u64>());

    // empty account if they are not authenticated
    let account = account.map(|a| a.to_string()).unwrap_or(String::new());

    // Construct the claims for the token
    // TODO: Verify the token!
    let token = AuthToken::new(
        String::from("orca-registry__DEV"),
        account,
        String::from("reg"),
        expiration,
        now.clone(),
        now.clone(),
        jwtid,
        scopes,
    );

    let token_str = token.sign_with_key(&key)?;
    Ok(TokenInfo::new(token_str, expiration, now))
}

pub async fn auth_basic_get(
    basic_auth: Option<AuthBasic>,
    state: State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    form: Option<Form<AuthForm>>,
) -> Result<Response, StatusCode> {
    let mut auth = TokenAuthRequest {
        user: None,
        password: None,
        account: None,
        service: None,
        scope: Vec::new(),
        offline_token: None,
        client_id: None,
    };

    let auth_method;

    // Process all the scopes
    if let Some(scope) = params.get("scope") {
        // TODO: Handle multiple scopes
        match Scope::try_from(&scope[..]) {
            Ok(scope) => {
                auth.scope.push(scope);
            }
            Err(_) => {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    // If BasicAuth is provided, set the fields to it
    if let Some(AuthBasic((username, pass))) = basic_auth {
        auth.user = Some(username.clone());
        auth.password = pass;

        // I hate having to create this span here multiple times, but its the only
        // way I could think of
        /* let span = span!(Level::DEBUG, "auth", username = auth.user.clone());
        let _enter = span.enter();
        debug!("Read user authentication from an AuthBasic"); */

        auth_method = "basic-auth";
    }
    // Username and password could be passed in forms
    // If there was a way to also check if the Method was "POST", this is where
    // we would do it.
    else if let Some(Form(form)) = form {
        auth.user = Some(form.username.clone());
        auth.password = Some(form.password);

        let span = span!(Level::DEBUG, "auth", username = auth.user.clone());
        let _enter = span.enter();
        debug!("Read user authentication from a Form");

        auth_method = "form";
    } else {
        // If no auth parameters were specified, check if the repository is public. if it is, respond with a token.

        let is_public_access = {
            let mut res = vec![];

            for scope in auth.scope.iter() {
                match scope.scope_type {
                    ScopeType::Repository => {
                        // check repository visibility
                        let database = &state.database;
                        match database.get_repository_visibility(&scope.name).await {
                            Ok(Some(RepositoryVisibility::Public)) => res.push(Ok(true)),
                            Ok(_) => res.push(Ok(false)),
                            Err(e) => {
                                error!(
                                    "Failure to check repository visibility for {}! Err: {}",
                                    scope.name, e
                                );

                                res.push(Err(StatusCode::INTERNAL_SERVER_ERROR));
                            }
                        }
                    }
                    _ => res.push(Ok(false)),
                }
            }

            // merge the booleans into a single bool, respond with errors if there are any.
            let res: Result<Vec<bool>, StatusCode> = res.into_iter().collect();
            res?.iter().all(|b| *b)
        };

        if is_public_access {
            for scope in auth.scope.iter_mut() {
                // only retain Action::Pull
                scope.actions.retain(|a| *a == Action::Pull);
            }

            let token = create_jwt_token(state.config.jwt_key.clone(), None, auth.scope)
                .map_err(|_| {
                    error!("Failed to create jwt token!");

                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            let token_str = token.token;
            let now_format = format!("{}", token.created_at.format("%+"));

            let auth_response = AuthResponse {
                token: token_str.clone(),
                expires_in: 86400, // 1 day
                issued_at: now_format,
            };
    
            let json_str = serde_json::to_string(&auth_response)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
    
            debug!("Created anonymous token for public scopes!");

            return Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::AUTHORIZATION, &format!("Bearer {}", token_str)),
                ],
                json_str,
            ).into_response());
        } else {
            info!("Auth failure! Auth was not provided in either AuthBasic or Form!");

            // Maybe BAD_REQUEST should be returned?
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Create logging span for the rest of this request
    let span = span!(
        Level::DEBUG,
        "auth",
        username = auth.user.clone(),
        auth_method
    );
    let _enter = span.enter();

    debug!("Parsed user auth request");

    // Get account from query string, if its specified, ensure that its the same as the user if
    // that is also specified.
    if let Some(account) = params.get("account") {
        if let Some(user) = &auth.user {
            if account != user {
                error!(
                    "`user` and `account` are not the same!!! (user: {}, account: {})",
                    user, account
                );

                return Err(StatusCode::BAD_REQUEST);
            }
        }

        auth.account = Some(account.clone());
    }

    // Get service from query string
    if let Some(service) = params.get("service") {
        auth.service = Some(service.clone());
    }

    // Get offline token and attempt to convert it to a boolean
    if let Some(offline_token) = params.get("offline_token") {
        if let Ok(b) = offline_token.parse::<bool>() {
            auth.offline_token = Some(b);
        }
    }

    if let Some(client_id) = params.get("client_id") {
        auth.client_id = Some(client_id.clone());
    }

    debug!("Constructed auth request");

    if let (Some(account), Some(password)) = (&auth.account, auth.password) {
        // Ensure that the password is correct
        let mut auth_driver = state.auth_checker.lock().await;
        if !auth_driver
            .verify_user_login(account.clone(), password)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            debug!("Authentication failed, incorrect password!");

            // TODO: Multiple scopes
            let scope = auth.scope
                .first()
                .and_then(|s| Some(s.clone()));

            // TODO: Dont unwrap, find a way to return multiple scopes
            return Ok(auth_challenge_response(
                &state.config,
                scope,
            ));
        }
        drop(auth_driver);

        debug!("User password is correct");

        let now = SystemTime::now();
        let token = create_jwt_token(state.config.jwt_key.clone(), Some(account), vec![])
            .map_err(|_| {
                error!("Failed to create jwt token!");

                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        let token_str = token.token;

        debug!("Created jwt token");

        // ISO8601 time format
        let now_dt: DateTime<Utc> = now.into();
        let now_format = format!("{}", now_dt.format("%+"));

        // Construct the auth response
        let auth_response = AuthResponse {
            token: token_str.clone(),
            expires_in: 20,
            issued_at: now_format,
        };

        let json_str =
            serde_json::to_string(&auth_response).map_err(|_| StatusCode::BAD_REQUEST)?;

        let database = &state.database;
        database
            .store_user_token(
                token_str.clone(),
                account.clone(),
                token.expiry,
                token.created_at,
            )
            .await
            .map_err(|_| {
                error!("Failed to store user token in database!");

                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        return Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::AUTHORIZATION, &format!("Bearer {}", token_str)),
            ],
            json_str,
        )
            .into_response());
    }

    info!("Auth failure! Not enough information given to create auth token!");
    // If we didn't get fields required to make a token, then the client did something bad
    Err(StatusCode::UNAUTHORIZED)
}
