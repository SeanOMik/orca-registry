CREATE TABLE IF NOT EXISTS orca (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    orca_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    jwt_secret TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    name TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- 0 = private, 1 = public
    visibility INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS repositories (
    name TEXT NOT NULL UNIQUE PRIMARY KEY,
    owning_project TEXT,
    owner_email TEXT,
    -- 0 = private, 1 = public
    visibility INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS image_manifests (
    digest TEXT NOT NULL PRIMARY KEY,
    repository TEXT NOT NULL,
    subject_digest TEXT,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS image_tags (
    name TEXT NOT NULL,
    repository TEXT NOT NULL,
    -- the image manifest for this tag
    image_manifest TEXT NOT NULL,
    -- the epoch timestamp fo when this image tag was last updated
    last_updated BIGINT NOT NULL,
    PRIMARY KEY (name, repository)
);

CREATE TABLE IF NOT EXISTS manifest_layers (
    manifest TEXT NOT NULL,
    -- the digest of the layer for this manifest
    layer_digest TEXT NOT NULL,
    PRIMARY KEY (manifest, layer_digest)
);

CREATE TABLE IF NOT EXISTS users (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    username TEXT NOT NULL,
    -- 0 = local, 1 = ldap
    login_source BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_logins (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- bcrypt hashed password
    password_hash TEXT NOT NULL,
    -- the salt generated along side the password hash
    password_salt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_registry_permissions (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- 0 = regular user, 1 = admin
    user_type INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_repo_permissions (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- name of repository that this user has these permissions in
    repository_name TEXT NOT NULL,
    -- bitwised integer storing permissions
    repository_permissions INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_tokens (
    token TEXT NOT NULL UNIQUE PRIMARY KEY,
    email TEXT NOT NULL,
    expiry BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

-- create admin user (password is 'admin')
INSERT OR IGNORE INTO users (username, email, login_source) VALUES ('admin', 'admin@example.com', 0);
INSERT OR IGNORE INTO user_logins (email, password_hash, password_salt) VALUES ('admin@example.com', '$2y$05$v9ND7dQKvfkOtY4XpnKVaOpvV0F5RDnW1Ec.nfkZ0vmEjLX5D5S8e', 'x5ECk0jUmOSfBWxW52wsyO');
INSERT OR IGNORE INTO user_registry_permissions (email, user_type) VALUES ('admin@example.com', 1);

-- create other repository owned by admin user
INSERT OR IGNORE INTO repositories (name, owning_project, owner_email, visibility) VALUES ('conformance-test', '', 'admin@example.com', 0);