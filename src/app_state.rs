use sqlx::{Sqlite, Pool};

use crate::auth_storage::MemoryAuthStorage;
use crate::storage::StorageDriver;
use crate::config::Config;

use tokio::sync::Mutex;

pub struct AppState {
    pub database: Pool<Sqlite>,
    pub storage: Mutex<Box<dyn StorageDriver>>,
    pub config: Config,
    pub auth_storage: Mutex<MemoryAuthStorage>,
}

impl AppState {
    pub fn new(database: Pool<Sqlite>, storage: Mutex<Box<dyn StorageDriver>>, config: Config) -> Self
    {
        Self {
            database,
            storage,
            config,
            auth_storage: Mutex::new(MemoryAuthStorage::new()),
        }
    }
}