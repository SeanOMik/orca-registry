use chrono::{DateTime, Utc};

pub mod manifest;
pub mod digest;
pub mod scope;
pub mod user;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tag {
    pub name: String,
    pub repository: String,
    pub last_updated: DateTime<Utc>,
    pub manifest_digest: String,
}

impl Tag {
    pub fn new(name: String, repository: String, last_updated: DateTime<Utc>, manifest_digest: String) -> Self {
        Self {
            name,
            repository,
            last_updated,
            manifest_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RepositoryVisibility {
    Private = 0,
    Public = 1
}

impl TryFrom<u32> for RepositoryVisibility {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Private),
            1 => Ok(Self::Public),
            _ => Err(anyhow::anyhow!("Invalid value for RepositoryVisibility: `{}`", value)),
        }
    }
}

impl Into<u32> for RepositoryVisibility {
    fn into(self) -> u32 {
        self as u32
    }
}