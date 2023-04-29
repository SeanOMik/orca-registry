use chrono::{DateTime, Utc};

pub mod manifest;
pub mod digest;
pub mod scope;
pub mod user;

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