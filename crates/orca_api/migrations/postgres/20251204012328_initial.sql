CREATE TABLE _orca_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    orca_version TEXT NOT NULL
);
INSERT INTO _orca_meta(orca_version) VALUES('0.1.1');

CREATE TABLE projects (
    name TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- 0 = private, 1 = public
    visibility INTEGER NOT NULL
);

CREATE TABLE repositories (
    name TEXT NOT NULL UNIQUE PRIMARY KEY,
    owning_project TEXT,
    owner_email TEXT,
    -- 0 = private, 1 = public
    visibility INTEGER NOT NULL
);

CREATE TABLE users (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    username TEXT NOT NULL,
    -- 0 = local, 1 = ldap
    login_source BIGINT NOT NULL
);

CREATE TABLE user_logins (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- bcrypt hashed password
    password_hash TEXT NOT NULL,
    -- the salt generated along side the password hash
    password_salt TEXT NOT NULL
);

CREATE TABLE user_registry_permissions (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- 0 = regular user, 1 = admin
    user_type INTEGER NOT NULL
);

CREATE TABLE user_repo_permissions (
    email TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- name of repository that this user has these permissions in
    repository_name TEXT NOT NULL,
    -- bitwised integer storing permissions
    repository_permissions INTEGER NOT NULL
);

CREATE TABLE user_tokens (
    token TEXT NOT NULL UNIQUE PRIMARY KEY,
    email TEXT NOT NULL,
    expiry BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE user_sessions (
    session TEXT NOT NULL UNIQUE PRIMARY KEY,
    email TEXT NOT NULL,
    expiry BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

-- create admin user (password is 'admin')
INSERT INTO users (username, email, login_source) VALUES ('admin', 'admin@example.com', 0);
INSERT INTO user_logins (email, password_hash, password_salt) VALUES ('admin@example.com', '$2y$05$v9ND7dQKvfkOtY4XpnKVaOpvV0F5RDnW1Ec.nfkZ0vmEjLX5D5S8e', 'x5ECk0jUmOSfBWxW52wsyO');
INSERT INTO user_registry_permissions (email, user_type) VALUES ('admin@example.com', 1);

-- create other repository owned by admin user
INSERT INTO repositories (name, owning_project, owner_email, visibility) VALUES ('admin', '', 'admin@example.com', 0);
INSERT INTO repositories (name, owning_project, owner_email, visibility) VALUES ('conformance-test', '', 'admin@example.com', 0);
