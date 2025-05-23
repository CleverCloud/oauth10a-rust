use std::{convert::Infallible, sync::Arc};

use reqwest::Request;

pub mod any;
pub mod basic;
pub mod bearer;
pub mod oauth1;

pub trait Authorization {
    type Error;

    /// Returns the value for the authorization header.
    ///
    /// # Errors
    ///
    /// Upon failed to build the authorization header value.
    fn authorization(&self, request: &Request) -> Result<Option<String>, Self::Error>;
}

impl Authorization for () {
    type Error = Infallible;

    fn authorization(&self, _request: &Request) -> Result<Option<String>, Self::Error> {
        Ok(None)
    }
}

impl<T: Authorization> Authorization for Option<T> {
    type Error = T::Error;

    fn authorization(&self, request: &Request) -> Result<Option<String>, Self::Error> {
        match self {
            None => Ok(None),
            Some(v) => v.authorization(request),
        }
    }
}

impl<T: Authorization> Authorization for Arc<T> {
    type Error = T::Error;

    fn authorization(&self, request: &Request) -> Result<Option<String>, Self::Error> {
        self.as_ref().authorization(request)
    }
}
