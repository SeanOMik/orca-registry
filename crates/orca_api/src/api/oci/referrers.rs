use std::{collections::HashMap, sync::Arc};

use axum::{body::Body, extract::{Path, Query, State}, http::{header, StatusCode}, response::Response};
use tracing::debug;

use crate::{app_state::AppState, dto::manifest::{media_types, ImageIndex, IndexItem}, error::AppError};

pub async fn list_referrers_get(
    Path((name, digest)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    state: State<Arc<AppState>>,
    //body: Bytes,
) -> Result<Response<Body>, AppError> {

    let filter_artifact_type = query.get("artifactType")
        .map(|at| at.to_owned());
    debug!("filtering with {:?}", filter_artifact_type);
    //let mut filter_applied = false;

    let storage = state.storage.lock().await;
    let refs: Vec<IndexItem> = storage.get_referrers(&digest).await?
        .into_iter()
        .filter_map(|mut r| {
            // only respond with referrers in this namespace
            if r.namespace == name {
                // per the spec, if artifactType is missing, it must be set to mediaType if the manifest
                // is an image manifest. If its an index, omit it.
                if r.artifact_type.is_none() && r.media_type == media_types::IMAGE_MANIFEST {
                    r.artifact_type = Some(r.media_type.clone());
                }

                // apply query param artifactType filter if it was provided.
                let mut allow = true;
                if let (Some(filter_at), Some(ref_at)) = (&filter_artifact_type, &r.artifact_type) {
                    if filter_at != ref_at {
                        debug!("filtering {} based off of artifact type: {}", r.digest, ref_at);
                        allow = false;
                    }
                }
    
                if allow {
                    Some(IndexItem {
                        descriptor: r.descriptor,
                        platform: None,
                    })
                } else { None }
            } else {
                debug!("filtering {} based off of namespace: type='{:?}',namespace='{}'", r.digest, r.artifact_type, r.namespace);

                None
            }
        })
        .collect();

    let index = ImageIndex {
        schema_version: 2,
        media_type: media_types::IMAGE_INDEX.into(),
        artifact_type: None,
        manifests: refs,
        subject: None,
        annotations: HashMap::new(),
    };
    let index_json = serde_json::to_string(&index)
        .expect("failed to serialize ImageIndex as json string");

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.oci.image.index.v1+json");

    // TODO: Link header if the descriptor list cannot be returned in a single manifest.
    // RFC5988 https://www.rfc-editor.org/rfc/rfc5988.html

    if filter_artifact_type.is_some() {
        resp = resp.header("oci-filters-applied", "artifactType");
    }

    Ok(resp.body(Body::from(index_json)).unwrap())
}