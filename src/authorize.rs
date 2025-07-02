use core::fmt;
use std::sync::Arc;

use reqwest::Request;

use crate::credentials::{AuthorizationError, Credentials};

// AUTHORIZE ///////////////////////////////////////////////////////////////////

pub trait Authorize: fmt::Debug + Send + Sync + 'static {
    type Error: Send + 'static;

    /// Appends an `Authorization` header to the `request`, if this authorizer
    /// has credentials and unless it is already set.
    ///
    /// Returns `true` if the `Authorization` header was inserted.
    ///
    /// # Errors
    ///
    /// Upon failure to produce the `Authorization` header value or if the request
    /// has too many headers.
    fn authorize(&self, request: &mut Request) -> Result<bool, Self::Error>;
}

impl Authorize for Credentials {
    type Error = AuthorizationError;

    #[inline]
    fn authorize(&self, request: &mut Request) -> Result<bool, Self::Error> {
        self.as_ref().authorize(request)
    }
}

impl<T: Authorize> Authorize for Option<T> {
    type Error = T::Error;

    #[inline]
    fn authorize(&self, request: &mut Request) -> Result<bool, Self::Error> {
        match self.as_ref() {
            None => Ok(false),
            Some(authorizer) => authorizer.authorize(request),
        }
    }
}

impl<T: Authorize> Authorize for Arc<T> {
    type Error = T::Error;

    #[inline]
    fn authorize(&self, request: &mut Request) -> Result<bool, Self::Error> {
        (&**self).authorize(request)
    }
}
