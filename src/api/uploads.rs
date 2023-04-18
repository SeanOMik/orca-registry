use actix_web::{HttpResponse, HttpRequest, post, web, patch, put, delete, get};
use bytes::{BytesMut, Bytes, BufMut};
use qstring::QString;
use tracing::{debug};

use crate::app_state::AppState;

use crate::database::Database;

/// Starting an upload
#[post("/")]
pub async fn start_upload(path: web::Path<(String, )>) -> HttpResponse {
    debug!("Upload starting");
    let name = path.0.to_owned();
    let uuid = uuid::Uuid::new_v4();

    debug!("Requesting upload of image {}, generated uuid: {}", name, uuid);

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid.to_string());
    debug!("Constructed upload url: {}", location);

    HttpResponse::Accepted()
        .insert_header(("Location", location))
        .finish()
}

#[patch("/{uuid}")]
pub async fn chunked_upload_layer(body: Bytes, path: web::Path<(String, String)>, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let full_uri = req.uri().to_string();
    let (_name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());

    debug!("Read body of size: {}", body.len());

    let database = &state.database;
    let (starting, ending) = match database.get_digest(&layer_uuid).await.unwrap() {
        Some(current_bytes) => {
            let mut combined = BytesMut::new();
            let body_size = body.len();
            let current_size = current_bytes.len();

            combined.put(current_bytes);
            combined.put(body);

            database.save_digest(&layer_uuid, &combined.into()).await.unwrap();

            (current_size, current_size + body_size)
        },
        None => {
            let body_size = body.len();
            database.save_digest(&layer_uuid, &body.into()).await.unwrap();
            (0, body_size)
        }
    };

    debug!("s={}, e={}, uuid={}, uri={}", starting, ending, layer_uuid, full_uri);

    HttpResponse::Accepted()
        .insert_header(("Location", full_uri))
        .insert_header(("Range", format!("{}-{}", starting, ending)))
        .insert_header(("Content-Length", 0))
        .insert_header(("Docker-Upload-UUID", layer_uuid))
        .finish()
}

#[put("/{uuid}")]
pub async fn finish_chunked_upload(body: Bytes, path: web::Path<(String, String)>, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let (name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());

    let qs = QString::from(req.query_string());
    let digest = qs.get("digest").unwrap();

    let database = &state.database;
    if !body.is_empty() {
        let current_bytes = database.get_digest(&layer_uuid).await.unwrap().unwrap();
        let mut combined = BytesMut::new();

        combined.put(current_bytes);
        combined.put(body);

        database.save_digest(&layer_uuid, &combined.into()).await.unwrap();
    } else {
        // TODO: Validate layer with all digest params
    }

    database.replace_digest(&layer_uuid, &digest).await.unwrap();

    HttpResponse::Created()
        .insert_header(("Location", format!("/v2/{}/blobs/{}", name, digest)))
        .insert_header(("Content-Length", 0))
        .insert_header(("Docker-Upload-Digest", digest))
        .finish()
}

#[delete("/{uuid}")]
pub async fn cancel_upload(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (_name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());

    let database = &state.database;
    database.delete_digest(&layer_uuid).await.unwrap();
    
    // I'm not sure what this response should be, its not specified in the registry spec.
    HttpResponse::Ok()
        .finish()
}

#[get("/{uuid}")]
pub async fn check_upload_status(path: web::Path<(String, String)>, state: web::Data<AppState>) -> HttpResponse {
    let (name, layer_uuid) = (path.0.to_owned(), path.1.to_owned());
    
    let database = &state.database;
    let ending = match database.get_digest(&layer_uuid).await.unwrap() {
        Some(current_bytes) => {
            current_bytes.len()
        },
        None => {
            0
        }
    };

    HttpResponse::Created()
        .insert_header(("Location", format!("/v2/{}/blobs/uploads/{}", name, layer_uuid)))
        .insert_header(("Range", format!("0-{}", ending)))
        .insert_header(("Docker-Upload-Digest", layer_uuid))
        .finish()
}