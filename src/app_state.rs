use sqlx::{Sqlite, Pool};

use crate::auth_storage::AuthDriver;
use crate::storage::StorageDriver;
use crate::config::Config;

use tokio::sync::Mutex;

pub struct AppState {
    pub database: Pool<Sqlite>,
    pub storage: Mutex<Box<dyn StorageDriver>>,
    pub config: Config,
    pub auth_checker: Mutex<Box<dyn AuthDriver>>,
}

impl AppState {
    pub fn new(database: Pool<Sqlite>, storage: Mutex<Box<dyn StorageDriver>>, config: Config, auth_checker: Mutex<Box<dyn AuthDriver>>) -> Self
    {
        Self {
            database,
            storage,
            config,
            auth_checker,
        }
    }
}