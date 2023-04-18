use actix_web::{HttpResponse, get, HttpRequest, web, head, delete};

use crate::app_state::AppState;

use crate::database::Database;
use crate::storage::filesystem::FilesystemDriver;

#[head("/{digest}")]
pub async fn digest_exists(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (_name, layer_digest) = (path.0.to_owned(), path.1.to_owned());

    let storage = state.storage.lock().await;

    if storage.has_digest(&layer_digest).await.unwrap() {
        if let Some(size) = storage.digest_length(&layer_digest).await.unwrap() {
            return HttpResponse::Ok()
                .insert_header(("Content-Length", size))
                .insert_header(("Docker-Content-Digest", layer_digest))
                .finish();
        }
    }

    HttpResponse::NotFound()
        .finish()
}

#[get("/{digest}")]
pub async fn pull_digest(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (_name, layer_digest) = (path.0.to_owned(), path.1.to_owned());

    let storage = state.storage.lock().await;
    if let Some(bytes) = storage.get_digest(&layer_digest).await.unwrap() {
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