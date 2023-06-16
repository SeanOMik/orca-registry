--- Creates a regular user with the password 'test'
INSERT OR IGNORE INTO users (username, email, login_source) VALUES ('test', 'test@example.com', 0);
INSERT OR IGNORE INTO user_logins (email, password_hash, password_salt) VALUES ('test@example.com', '$2y$05$k3gn.RxGxh59NhtyyiWPeeQ2J9kqVaImiL3GPuBjMsiJ51Bn3js.K', 'x5ECk0jUmOSfBWxW52wsyO');
INSERT OR IGNORE INTO user_registry_permissions (email, user_type) VALUES ('test@example.com', 0);

-- example of giving this user pull access to a repository
--INSERT OR IGNORE INTO user_repo_permissions (email, repository_name, repository_permissions) VALUES ('test@example.com', 'admin/alpine', 1);