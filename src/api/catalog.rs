use std::sync::Arc;

use axum::{extract::{State, Query}, http::{StatusCode, header, HeaderMap, HeaderName}, response::{IntoResponse, Response}};
use serde::{Serialize, Deserialize};

use crate::{app_state::AppState, database::Database, error::AppError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryList {
    repositories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRepositoriesParams {
    #[serde(rename = "n")]
    limit: Option<u32>,

    #[serde(rename = "last")]
    last_repo: Option<String>,
}

pub async fn list_repositories(Query(params): Query<ListRepositoriesParams>, state: State<Arc<AppState>>) -> Result<Response, AppError> {
    let mut link_header = None;

    // Paginate tag results if n was specified, else just pull everything.
    let database = &state.database;
    let repositories = match params.limit {
        Some(limit) => {

            // Convert the last param to a String, and list all the repos
            let last_repo = params.last_repo.and_then(|t| Some(t.to_string()));
            let repos = database.list_repositories(Some(limit), last_repo).await?;

            // Get the new last repository for the response
            let last_repo = repos.last().and_then(|s| Some(s.clone()));

            // Construct the link header
            let url = &state.config.get_url();
            let mut url = format!("<{}/v2/_catalog?n={}", url, limit);
            if let Some(last_repo) = last_repo {
                url += &format!("&limit={}", last_repo);
            }
            url += ">; rel=\"next\"";
            link_header = Some(url);

            repos
        },
        None => {
            database.list_repositories(None, None).await?
        }
    };

    // Convert the `Vec<Tag>` to a `TagList` which will be serialized to json.
    let repo_list = RepositoryList {
        repositories,
    };
    let response_body = serde_json::to_string(&repo_list)?;
    
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse()?);
    headers.insert(HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".parse()?);

    if let Some(link_header) = link_header {
        headers.insert(header::LINK, link_header.parse()?);
    }

    // Construct the response, optionally adding the Link header if it was constructed.
    Ok((
        StatusCode::OK,
        headers,
        response_body
    ).into_response())
}