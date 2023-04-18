use actix_web::{HttpResponse, web, get, HttpRequest};
use qstring::QString;
use serde::{Serialize, Deserialize};

use crate::{app_state::AppState, database::Database};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryList {
    repositories: Vec<String>,
}

#[get("")]
pub async fn list_repositories(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    // Get limit and last tag from query params if present.
    let qs = QString::from(req.query_string());
    let limit = qs.get("n");
    let last_repo = qs.get("last");

    let mut link_header = None;

    // Paginate tag results if n was specified, else just pull everything.
    let database = &state.database;
    let repositories = match limit {
        Some(limit) => {
            let limit: u32 = limit.parse().unwrap();

            // Convert the last param to a String, and list all the repos
            let last_repo = last_repo.and_then(|t| Some(t.to_string()));
            let repos = database.list_repositories(Some(limit), last_repo).await.unwrap();

            // Get the new last repository for the response
            let last_repo = repos.last().and_then(|s| Some(s.clone()));

            // Construct the link header
            let url = req.uri().to_string();
            let mut url = format!("<{}/v2/_catalog?n={}", url, limit);
            if let Some(last_repo) = last_repo {
                url += &format!("&limit={}", last_repo);
            }
            url += ">; rel=\"next\"";
            link_header = Some(url);

            repos
        },
        None => {
            database.list_repositories(None, None).await.unwrap()
        }
    };

    // Convert the `Vec<Tag>` to a `TagList` which will be serialized to json.
    let repo_list = RepositoryList {
        repositories,
    };
    let response_body = serde_json::to_string(&repo_list).unwrap();
    
    // Construct the response, optionally adding the Link header if it was constructed.
    let mut resp = HttpResponse::Ok();
    resp.append_header(("Content-Type", "application/json"));

    if let Some(link_header) = link_header {
        resp.append_header(("Link", link_header));
    }
        
    resp.body(response_body)
}