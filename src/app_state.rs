use sqlx::{Sqlite, Pool};

pub struct AppState {
    pub database: Pool<Sqlite>,
}

impl AppState {
    pub fn new(database: Pool<Sqlite>) -> Self {
        Self {
            database,
        }
    }
}