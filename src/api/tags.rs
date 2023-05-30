use std::sync::Arc;

use axum::{extract::{Path, Query, State}, response::{IntoResponse, Response}, http::{StatusCode, header, HeaderMap, HeaderName}};
use serde::{Serialize, Deserialize};

use crate::{app_state::AppState, database::Database, error::AppError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TagList {
    name: String,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRepositoriesParams {
    #[serde(rename = "n")]
    limit: Option<u32>,

    #[serde(rename = "last")]
    last_tag: Option<String>,
}

pub async fn list_tags(Path((name, )): Path<(String, )>, Query(params): Query<ListRepositoriesParams>, state: State<Arc<AppState>>) -> Result<Response, AppError> {
    let mut link_header = None;

    // Paginate tag results if n was specified, else just pull everything.
    let database = &state.database;
    let tags = match params.limit {
        Some(limit) => {

            // Convert the last param to a String, and list all the tags
            let last_tag = params.last_tag.and_then(|t| Some(t.to_string()));
            let tags = database.list_repository_tags_page(&name, limit, last_tag).await?;

            // Get the new last repository for the response
            let last_tag = tags.last();

            // Construct the link header
            let url = &state.config.get_url();
            let mut url = format!("<{}/v2/{}/tags/list?n={}", url, name, limit);
            if let Some(last_tag) = last_tag {
                url += &format!("&limit={}", last_tag.name);
            }
            url += ">; rel=\"next\"";
            link_header = Some(url);

            tags
        },
        None => {
            database.list_repository_tags(&name).await?
        }
    };

    // Convert the `Vec<Tag>` to a `TagList` which will be serialized to json.
    let tag_list = TagList {
        name,
        tags: tags.into_iter().map(|t| t.name).collect(),
    };
    let response_body = serde_json::to_string(&tag_list)?;

    // Create headers
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse()?);
    headers.insert(HeaderName::from_static("docker-distribution-api-version"), "registry/2.0".parse()?);

    // Add the link header if it was constructed
    if let Some(link_header) = link_header {
        headers.insert(header::LINK, link_header.parse()?);
    }

    Ok((
        StatusCode::OK,
        headers,
        response_body
    ).into_response())
}