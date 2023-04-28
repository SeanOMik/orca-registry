use std::{sync::Arc, collections::{HashMap, BTreeMap}, time::{SystemTime, UNIX_EPOCH}};

use axum::{extract::{Query, State}, response::{IntoResponse, Response}, http::{StatusCode, Request, Method, HeaderName, header}, Form};
use axum_auth::AuthBasic;
use chrono::{DateTime, Utc};
use qstring::QString;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, info, span, Level};

use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use sha2::Sha256;

use rand::Rng;

use crate::{dto::scope::Scope, app_state::AppState, query::Qs};

#[derive(Deserialize, Debug)]
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

fn create_jwt_token(account: String) -> anyhow::Result<String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret")?;
    
    let now = SystemTime::now();
    let now_secs = now
        .duration_since(UNIX_EPOCH)?
        .as_secs();

    // Construct the claims for the token
    let mut claims = BTreeMap::new();
    claims.insert("issuer", "orca-registry__DEV");
    claims.insert("subject", &account);
    //claims.insert("audience", auth.service);

    let notbefore = format!("{}", now_secs - 10);
    let issuedat = format!("{}", now_secs);
    let expiration = format!("{}", now_secs + 20);
    claims.insert("notbefore", &notbefore);
    claims.insert("issuedat", &issuedat);
    claims.insert("expiration", &expiration); // TODO: 20 seconds expiry for testing

    // Create a randomized jwtid
    let mut rng = rand::thread_rng();
    let jwtid = format!("{}", rng.gen::<u64>());
    claims.insert("jwtid", &jwtid);

    Ok(claims.sign_with_key(&key)?)
}

pub async fn auth_basic_get(basic_auth: Option<AuthBasic>, state: State<Arc<AppState>>, Query(params): Query<HashMap<String, String>>, form: Option<Form<AuthForm>>) -> Response {
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
        info!("Auth failure! Auth was not provided in either AuthBasic or Form!");

        // Maybe BAD_REQUEST should be returned?
        return (StatusCode::UNAUTHORIZED).into_response();
    }

    // Create logging span for the rest of this request
    let span = span!(Level::DEBUG, "auth", username = auth.user.clone(), auth_method);
    let _enter = span.enter();

    debug!("Parsed user auth request");

    // Get account from query string, if its specified, ensure that its the same as the user if
    // that is also specified.
    if let Some(account) = params.get("account") {
        if let Some(user) = &auth.user {
            if account != user {
                error!("`user` and `account` are not the same!!! (user: {}, account: {})", user, account);
                
                return (StatusCode::BAD_REQUEST).into_response();
            }
        }

        auth.account = Some(account.clone());
    }

    // Get service from query string
    if let Some(service) = params.get("service") {
        auth.service = Some(service.clone());
    }

    // Process all the scopes
    if let Some(scope) = params.get("scope") {
        // TODO: Handle multiple scopes
        auth.scope.push(Scope::try_from(&scope[..]).unwrap());
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

    if let Some(account) = auth.account {
        let now = SystemTime::now();
        let token_str = create_jwt_token(account).unwrap();

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

        let json_str = serde_json::to_string(&auth_response).unwrap();

        return (
            StatusCode::OK,
            [
                ( header::CONTENT_TYPE, "application/json" ),
                ( header::AUTHORIZATION, &format!("Bearer {}", token_str) )
            ],
            json_str
        ).into_response();
    }

    info!("Auth failure! Not enough information given to create auth token!");
    // If we didn't get fields required to make a token, then the client did something bad
    (StatusCode::UNAUTHORIZED).into_response()
}