use std::ops::Deref;

use axum::extract::FromRequest;
use axum::http::{self, Request};

use async_trait::async_trait;
use serde::de::DeserializeOwned;

pub struct Qs<T>(pub T);

impl<T> Deref for Qs<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S, B, T> FromRequest<S, B> for Qs<T>
where
    // these bounds are required by `async_trait`
    B: Send + 'static,
    S: Send + Sync,
    T: DeserializeOwned
{
    type Rejection = http::StatusCode;

    async fn from_request(req: Request<B>, _state: &S) -> Result<Self, Self::Rejection> {
        let query = req.uri().query().unwrap();
        Ok(Self(serde_qs::from_str(query).unwrap()))
    }
}