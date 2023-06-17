# Orca registry
Orca is a pure-rust implementation of a Docker Registry.

Note: Orca is still in early development ([status](#status)).

## Features
* Low resource consumption
* Easy to deploy
* Single application and executable

## Status
The project is still in early development, use at your own risk. Although the registry does work, and you can push and pull images from it, there is no simple way to modify user permissions and to add users to the registry. Currently, the only way to add a user and, modify their permissions, is to edit the sqlite database.

### Adding users
These instructions are assuming the user is stored in the database, if you use LDAP auth, users are created automatically and you don't need all this. 

> Note: These instructions are subject to change or quickly become outdated without notes in the instructions.

1. Open the sqlite database in an editor.

2. Create a bcrypt password hash for the new user:
```shell
$ htpasswd -nB
```

3. Insert the new user's email, password hash into the `user_logins` table. The salt is not used, so you can put whatever there
```sql
INSERT INTO user_logins (email, password_hash, password_salt) VALUES ("example@email.com", "some password", "random salt")
```

4. Insert the new user into another table, `users` so the registry knows the source of the user
```sql
INSERT INTO users (username, email, login_source) VALUES ("example", "example@email.com", 0)
```
a `login_source` of `0` means database

5. Give the user registry permissions
```sql
INSERT INTO user_registry_permissions (email, user_type) VALUES ("example@email.com", 1)
```
a `user_type` of `1` means admin, they have permission for all image repositories.