use actix_web::{HttpResponse, get, HttpRequest, web, head, delete};

use crate::app_state::AppState;

use crate::database::Database;

#[head("/{digest}")]
pub async fn digest_exists(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (_name, layer_digest) = (path.0.to_owned(), path.1.to_owned());

    let database = &state.database;
    if let Some(bytes) = database.get_digest(&layer_digest).await.unwrap() {
        HttpResponse::Ok()
            .insert_header(("Content-Length", bytes.len()))
            .insert_header(("Docker-Content-Digest", layer_digest))
            .finish()
    } else {
        HttpResponse::NotFound().finish()
    }
}

#[get("/{digest}")]
pub async fn pull_digest(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (_name, layer_digest) = (path.0.to_owned(), path.1.to_owned());

    let database = &state.database;
    if let Some(bytes) = database.get_digest(&layer_digest).await.unwrap() {
        HttpResponse::Ok()
            .insert_header(("Content-Length", bytes.len()))
            .insert_header(("Docker-Content-Digest", layer_digest))
            .body(bytes)
    } else {
        HttpResponse::NotFound()
            .finish()
    }
}

#[delete("/{digest}")]
pub async fn delete_digest(_req: HttpRequest, _state: web::Data<AppState>) -> HttpResponse {
    todo!()
}