CREATE TABLE IF NOT EXISTS repositories (
    name TEXT NOT NULL UNIQUE PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS image_manifests (
    digest TEXT NOT NULL PRIMARY KEY,
    repository TEXT NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS layer_blobs (
    digest TEXT NOT NULL PRIMARY KEY,
    blob BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS image_tags (
    name TEXT NOT NULL,
    repository TEXT NOT NULL,
    image_manifest TEXT NOT NULL,
    last_updated BIGINT NOT NULL,
    PRIMARY KEY (name, repository)
);

CREATE TABLE IF NOT EXISTS manifest_blobs (
    manifest TEXT NOT NULL,
    blob TEXT NOT NULL,
    PRIMARY KEY (manifest, blob)
);
