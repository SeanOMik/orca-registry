table! {
    image_manifests (digest) {
        digest -> Text,
        repository -> Text,
        value -> Text,
    }
}

table! {
    image_tags (name, repository) {
        name -> Text,
        repository -> Text,
        image_manifest -> Text,
        last_updated -> Int8,
    }
}

table! {
    layer_blobs (digest) {
        digest -> Text,
        value -> Bytea,
    }
}

table! {
    manifest_blobs (manifest, blob) {
        manifest -> Text,
        blob -> Text,
    }
}

table! {
    repositories (name) {
        name -> Text,
    }
}

allow_tables_to_appear_in_same_query!(
    image_manifests,
    image_tags,
    layer_blobs,
    manifest_blobs,
    repositories,
);
