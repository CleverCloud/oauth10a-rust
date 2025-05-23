//! HTTP client

use core::fmt;

use reqwest::{Request, Response};

use crate::{
    credentials::{AuthorizationError, Credentials},
    execute::ExecuteRequest,
};

// CLIENT ERROR ////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum ClientError<E = reqwest::Error> {
    #[error("failed to authorize request, {0}")]
    Authorize(#[from] AuthorizationError),
    #[error("failed to execute request, {0}")]
    Execute(E),
}

// CLIENT //////////////////////////////////////////////////////////////////////

/// HTTP client with optional [`Credentials`].
///
/// When credentials are provided, the client, will ensure requests are authorized
/// before they are executed.
#[derive(Debug, Default, Clone)]
#[must_use]
pub struct Client<T = reqwest::Client> {
    inner: T,
    credentials: Option<Credentials>,
}

impl<T> From<T> for Client<T> {
    fn from(value: T) -> Self {
        Self {
            inner: value,
            credentials: None,
        }
    }
}

impl From<&Credentials> for Client {
    fn from(value: &Credentials) -> Self {
        Self::from(value.clone())
    }
}

impl<T: Into<Box<str>>> From<Credentials<T>> for Client {
    fn from(value: Credentials<T>) -> Self {
        Self {
            inner: reqwest::Client::new(),
            credentials: Some(value.into()),
        }
    }
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T: fmt::Debug> Client<T> {
    /// Sets the `credentials` to be used by the client to authorize HTTP request,
    /// discarding the current value, if any.
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn set_credentials(&mut self, credentials: Option<Credentials>) {
        self.credentials = credentials;
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn set_credentials_from<U: Into<Box<str>> + fmt::Debug>(
        &mut self,
        credentials: Option<Credentials<U>>,
    ) {
        self.credentials = credentials.map(Credentials::into);
    }

    /// Fills the `credentials` to be used by the client to authorize HTTP request,
    /// discarding the current value, if any.
    pub fn with_credentials<U: Into<Box<str>> + fmt::Debug>(
        mut self,
        credentials: impl Into<Option<Credentials<U>>>,
    ) -> Self {
        self.set_credentials_from(credentials.into());
        self
    }

    /// Returns the credentials that will be used by this client to authorized
    /// subsequent HTTP requests.
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn credentials(&self) -> Option<Credentials<&str>> {
        self.credentials.as_ref().map(Credentials::as_ref)
    }

    /// Returns a shared reference to the inner HTTP client.
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Appends an `Authorization` header to the `request`, if this client has credentials and unless it is already set.
    ///
    /// Returns `true` if the `Authorization` header was inserted.
    ///
    /// # Errors
    ///
    /// Upon failure to produce the header value.
    ///
    /// If the client doesn't have credentials, this method is infallible.
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn authorize(&self, request: &mut Request) -> Result<bool, AuthorizationError> {
        match self.credentials() {
            None => Ok(false),
            Some(credentials) => credentials.authorize(request),
        }
    }
}

impl<T: ExecuteRequest> ExecuteRequest for Client<T> {
    type Error = ClientError<T::Error>;

    fn execute_request(
        &self,
        mut request: Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send + 'static {
        let result = self
            .authorize(&mut request)
            .map(|_| self.inner.execute_request(request));

        async move { result?.await.map_err(ClientError::Execute) }
    }
}

#[cfg(feature = "zeroize")]
impl<T> Drop for Client<T> {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        if let Some(mut credentials) = self.credentials.take() {
            credentials.zeroize();
        }
    }
}
