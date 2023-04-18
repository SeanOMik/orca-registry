use sqlx::{Sqlite, Pool};

use crate::storage::StorageDriver;

use tokio::sync::Mutex;

pub struct AppState {
    pub database: Pool<Sqlite>,
    pub storage: Mutex<Box<dyn StorageDriver>>,
}

impl AppState {
    pub fn new/* <S> */(database: Pool<Sqlite>, storage: Mutex<Box<dyn StorageDriver>>) -> Self
    /* where
        S: StorageDriver, */
    {
        Self {
            database,
            storage
        }
    }
}