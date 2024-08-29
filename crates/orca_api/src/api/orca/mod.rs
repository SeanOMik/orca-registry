use std::sync::Arc;

use axum::{extract::State, http::{header, StatusCode}, response::{IntoResponse, Response}};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, database::Database, error::AppError};

use super::oci::auth::create_jwt_token;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginBody {
    email: String,
    password: String,
}

pub async fn login_post(
    state: State<Arc<AppState>>,
    axum::Json(body): axum::Json<LoginBody>
) -> Result<Response, AppError> {
    if state.database.verify_user_login(body.email.clone(), body.password).await? {
        let config = &state.config;
        let token_info = create_jwt_token(&config.jwt_key, config.token_max_age, Some(&body.email), vec![])
            .expect("failed to create auth token");
        let token = token_info.token;

        Ok((
            StatusCode::OK,
            [
                (header::SET_COOKIE, format!("TOKEN={}; Max-Age={}", token, config.token_max_age))
            ]
        ).into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}
