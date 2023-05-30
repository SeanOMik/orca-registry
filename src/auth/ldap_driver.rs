use async_trait::async_trait;
use ldap3::{LdapConnAsync, Ldap, Scope, SearchEntry};
use sqlx::{Pool, Sqlite};
use tracing::{debug, warn};

use crate::{config::LdapConnectionConfig, dto::{user::{Permission, LoginSource, RegistryUserType}, RepositoryVisibility}, database::Database};

use super::AuthDriver;

pub struct LdapAuthDriver {
    ldap_config: LdapConnectionConfig,
    ldap: Ldap,
    database: Pool<Sqlite>,
}

impl LdapAuthDriver {
    pub async fn new(config: LdapConnectionConfig, database: Pool<Sqlite>) -> anyhow::Result<Self> {
        debug!("connecting to ldap");
        let (conn, ldap) = LdapConnAsync::new(&config.connection_url).await?;
        ldap3::drive!(conn);

        debug!("Created ldap connection!");

        Ok(Self {
            ldap_config: config,
            ldap,
            database,
        })
    }

    async fn bind(&mut self) -> anyhow::Result<()> {
        let res = self.ldap.simple_bind(&self.ldap_config.bind_dn, &self.ldap_config.bind_password).await?;
        res.success()?;

        Ok(())
    }

    async fn is_user_admin(&mut self, email: String) -> anyhow::Result<bool> {
        self.bind().await?;

        // Send a request to LDAP to check if the user is an admin

        let filter = format!("(&({}={}){})", &self.ldap_config.login_attribute, email, &self.ldap_config.admin_filter);
        let res = self.ldap.search(&self.ldap_config.group_base_dn, Scope::Subtree, &filter, vec!["*"]).await?;
        let (entries, _res) = res.success()?;

        let entries: Vec<SearchEntry> = entries
            .into_iter()
            .map(|e| SearchEntry::construct(e))
            .collect();

        Ok(entries.len() > 0)
    }
}

#[async_trait]
impl AuthDriver for LdapAuthDriver {
    async fn user_has_permission(&mut self, email: String, repository: String, permission: Permission, required_visibility: Option<RepositoryVisibility>) -> anyhow::Result<bool> {
        if self.is_user_admin(email.clone()).await? {
            Ok(true)
        } else {
            debug!("LDAP is falling back to database");
            // fall back to database auth since this user might be local
            self.database.user_has_permission(email, repository, permission, required_visibility).await
        }
    }

    async fn verify_user_login(&mut self, email: String, password: String) -> anyhow::Result<bool> {
        self.bind().await?;

        let filter = self.ldap_config.user_search_filter.replace("%s", &email);
        let res = self.ldap.search(&self.ldap_config.user_base_dn, Scope::Subtree, &filter,
            vec!["userPassword", "uid", "cn", "mail", "displayName"]).await?;
        let (entries, _res) = res.success()?;

        let entries: Vec<SearchEntry> = entries
            .into_iter()
            .map(|e| SearchEntry::construct(e))
            .collect();

        if entries.is_empty() {
            Ok(false)
        } else if entries.len() > 1 {
            warn!("Got multiple DNs for user ({}), unsure which one to use!!", email);
            Ok(false)
        } else {
            let entry = entries.first().unwrap(); // there will be an entry

            let res = self.ldap.simple_bind(&entry.dn, &password).await?;
            if res.rc == 0 {
                // The user was authenticated through ldap!
                // Check if the user is stored in the database, if not, add it.
                let database = &self.database;
                if !database.does_user_exist(email.clone()).await? {
                    let display_name = match entry.attrs.get(&self.ldap_config.display_name_attribute) {
                        // theres no way the vector would be empty
                        Some(display) => display.first().unwrap().clone(),
                        None => return Ok(false),
                    };

                    database.create_user(email.clone(), display_name, LoginSource::LDAP).await?;
                    drop(database);

                    // Set the user registry type
                    let user_type = match self.is_user_admin(email.clone()).await? {
                        true => RegistryUserType::Admin,
                        false => RegistryUserType::Regular
                    };

                    self.database.set_user_registry_type(email, user_type).await?;
                }

                Ok(true)
            } else if res.rc == 49 {
                warn!("User failed to auth (invalidCredentials, rc=49)!");
                Ok(false)
            } else {
                // this would fail, its just here to propagate the error down
                res.success()?;

                Ok(false)
            }
        }
    }
}