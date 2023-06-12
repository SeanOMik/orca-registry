use std::{path::Path, collections::HashMap, error::Error};

use anyhow::anyhow;
use async_trait::async_trait;
use serde::{de::{Visitor, MapAccess}, Deserialize, Deserializer};
use toml::Table;
use tracing::{info, debug};

use crate::dto::{scope::Action, user::{Permission, RepositoryPermissions}, RepositoryVisibility};

use super::AuthDriver;

enum PermissionMatch {
    Account(String),
    Repository(String)
}

impl TryFrom<&str> for PermissionMatch {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (perm_type, perm_val) = value.split_once("=")
            .ok_or(anyhow!("No delimiter found!"))?;

        match perm_type {
            "account" => Ok(Self::Account(perm_val.to_string())),
            "repository" => Ok(Self::Repository(perm_val.to_string())),
            _ => Err(anyhow!("Unknown permission type '{}'", perm_type))
        }
    }
}

struct PermissionMatches(Vec<PermissionMatch>);

#[derive(Deserialize)]
struct UserEntry {
    name: String,
    #[serde(rename = "password")]
    password_hash: String,
}

struct Users(HashMap<String, String>);

struct UsersVisitor;

impl<'de> Visitor<'de> for UsersVisitor {
    type Value = Users;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a Scope in the format of `repository:samalba/my-app:pull,push`.")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut users = HashMap::new();

        while let Some((key, value)) = access.next_entry()? {
            users.insert(key, value);
        }

        Ok(Users(users))
    }
}

impl<'de> Deserialize<'de> for Users {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        deserializer.deserialize_map(UsersVisitor {})
    }
}

struct AclPermissions(u32);

impl AclPermissions {
    fn has_permission(&self, perm: Permission) -> bool {
        let perm = perm.bits();
        self.0 & perm == perm
    }
}

#[derive(Deserialize)]
struct AclEntry {
    #[serde(rename = "match")]
    matches: PermissionMatches,
    #[serde(rename = "permissions")]
    perms: AclPermissions,
}

/// Auth from a configuration file
#[derive(Deserialize)]
pub struct StaticAuthDriver {
    //users: Vec<UserEntry>,
    // email, password hash
    #[serde(deserialize_with = "from_user_entries")]
    users: HashMap<String, String>,
    acl: Vec<AclEntry>,
}

/// Custom deserializer to convert Vec<UserEntry> into HashMap<String, String>
fn from_user_entries<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<UserEntry> = Deserialize::deserialize(deserializer)?;
    
    let mut map = HashMap::new();
    for entry in v.into_iter() {
        map.insert(entry.name, entry.password_hash);
    }

    Ok(map)
}

impl StaticAuthDriver {
    pub fn from_file<P>(path: P) -> anyhow::Result<Self>
    where
        P: AsRef<Path>
    {
        let content = std::fs::read_to_string(path)?;
        let toml = toml::from_str::<Table>(&content)?;
        let toml = toml.get("static_auth")
            .ok_or(anyhow!("Missing `static_auth` at root of toml file!"))?
            .as_table()
            .unwrap()
            .clone();

        Ok(toml.try_into()?)
    }
}

#[async_trait]
impl AuthDriver for StaticAuthDriver {
    async fn user_has_permission(&mut self, email: String, repository: String, permission: Permission, required_visibility: Option<RepositoryVisibility>) -> anyhow::Result<bool> {
        info!("TODO: StaticAuthDriver::user_has_permission");
        Ok(true)
    }

    async fn verify_user_login(&mut self, email: String, password: String) -> anyhow::Result<bool> {
        if let Some(hash) = self.users.get(&email) {
            Ok(bcrypt::verify(password, hash)?)
        } else {
            Ok(false)
        }
    }
}

struct PermissionMatchesVisitor;

impl<'de> Visitor<'de> for PermissionMatchesVisitor {
    type Value = PermissionMatches;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("permission matches in the format of `account=guest,repository=public`.")
    }

    fn visit_str<E>(self, mut v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error
    {
        let matches: anyhow::Result<Vec<PermissionMatch>> = v.split(",")
            .map(|m| PermissionMatch::try_from(m))
            .collect();

        match matches {
            Ok(matches) => Ok(PermissionMatches(matches)),
            Err(e) => Err(serde::de::Error::custom(format!("Failure to parse match! {:?}", e))),
        }
    }
}

impl<'de> Deserialize<'de> for PermissionMatches {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        deserializer.deserialize_str(PermissionMatchesVisitor {})
    }
}

struct AclPermissionsVisitor;

impl<'de> Visitor<'de> for AclPermissionsVisitor {
    type Value = AclPermissions;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a Scope in the format of `repository:samalba/my-app:pull,push`.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>
    {
        let mut bitset_raw = 0;

        while let Some(perm) = seq.next_element::<String>()? {
            let perm: &str = &perm;
            let perm = Permission::try_from(perm)
                .map_err(|e| serde::de::Error::custom(format!("Failure to parse match! {:?}", e)))?;

            let perm = perm.bits();
            bitset_raw |= perm;
        }

        Ok(AclPermissions(bitset_raw))
    }
}

impl<'de> Deserialize<'de> for AclPermissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        deserializer.deserialize_seq(AclPermissionsVisitor {})
    }
}