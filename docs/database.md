## user_permissions table
The field `repository_custom_scope` is an integer created by using bitwise operations. 

* pull - `0b0001`
* push - `0b0010`
* edit - `0b0111`
* admin - `0b1111`

### Predefined user permission scopes:
* limited
  * pull image
* developer
  * pull and push image
* master
  * retag images
* project_admin
  * configure repository access

## user_registry_permissions

user_type:
* regular user = 0
* admin = 1