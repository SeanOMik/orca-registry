use actix_web::{HttpResponse, HttpRequest, web, put};
use tracing::{debug, trace};

use crate::app_state::AppState;

use crate::database::Database;

#[put("/{reference}")]
pub async fn upload_manifest(path: web::Path<(String, String)>, req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let (_name, layer_digest) = (path.0.to_owned(), path.1.to_owned());

    


    todo!()
}