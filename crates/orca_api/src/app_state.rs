use std::sync::Arc;

use crate::auth::AuthDriver;
use crate::database::Database;
use crate::storage::StorageDriver;
use crate::config::Config;

use tokio::sync::Mutex;

pub struct AppState {
    pub database: Arc<dyn Database>,
    pub storage: Mutex<Box<dyn StorageDriver>>,
    pub config: Config,
    pub auth_checker: Arc<Mutex<dyn AuthDriver>>,
}

impl AppState {
    pub fn new(database: Arc<dyn Database>, storage: Mutex<Box<dyn StorageDriver>>, config: Config, auth_checker: Arc<Mutex<dyn AuthDriver>>) -> Self
    {
        Self {
            database,
            storage,
            config,
            auth_checker,
        }
    }
}