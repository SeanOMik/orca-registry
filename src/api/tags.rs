use actix_web::{HttpResponse, web, get, HttpRequest};
use qstring::QString;
use serde::{Serialize, Deserialize};

use crate::{app_state::AppState, database::Database};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TagList {
    name: String,
    tags: Vec<String>,
}

#[get("/list")]
pub async fn list_tags(path: web::Path<(String, )>, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let name = path.0.to_owned();
    
    // Get limit and last tag from query params if present.
    let qs = QString::from(req.query_string());
    let limit = qs.get("n");
    let last_tag = qs.get("last");

    let mut link_header = None;

    // Paginate tag results if n was specified, else just pull everything.
    let database = &state.database;
    let tags = match limit {
        Some(limit) => {
            let limit: u32 = limit.parse().unwrap();

            let last_tag = last_tag.and_then(|t| Some(t.to_string()));

            // Construct the link header
            let mut url = format!("/v2/{}/tags/list?n={}", name, limit);
            if let Some(last_tag) = last_tag.clone() {
                url += &format!("&limit={}", last_tag);
            }
            url += ";rel=\"next\"";
            link_header = Some(url);

            database.list_repository_tags_page(&name, limit, last_tag).await.unwrap()
        },
        None => {
            let database = &state.database;
            database.list_repository_tags(&name).await.unwrap()
        }
    };

    // Convert the `Vec<Tag>` to a `TagList` which will be serialized to json.
    let tag_list = TagList {
        name,
        tags: tags.into_iter().map(|t| t.name).collect(),
    };
    let response_body = serde_json::to_string(&tag_list).unwrap();
    
    // Construct the response, optionally adding the Link header if it was constructed.
    let mut resp = HttpResponse::Ok();
    resp.append_header(("Content-Type", "application/json"));

    if let Some(link_header) = link_header {
        resp.append_header(("Link", link_header));
    }
        
    resp.body(response_body)
}