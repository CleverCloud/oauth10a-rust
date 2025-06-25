use core::fmt;

use reqwest::{Request, Response};

use crate::{authorize::Authorize, credentials::Credentials, execute::ExecuteRequest};

// CLIENT ERROR ////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum ClientError<E, A> {
    #[error("failed to authorize request, {0}")]
    Authorize(A),
    #[error("failed to execute request, {0}")]
    Execute(E),
}

// CLIENT //////////////////////////////////////////////////////////////////////

/// HTTP client that authorize requests before execution.
#[derive(Debug, Clone)]
#[must_use]
pub struct Client<T = reqwest::Client, A = Option<Credentials>> {
    executer: T,
    authorizer: A,
}

impl<T, A: Default> From<T> for Client<T, A> {
    fn from(value: T) -> Self {
        Self {
            executer: value,
            authorizer: A::default(),
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::from(reqwest::Client::default())
    }
}

impl<T: fmt::Debug, A: fmt::Debug> Client<T, A> {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn new(executer: T, authorizer: A) -> Self {
        Self {
            executer,
            authorizer,
        }
    }

    pub fn executer(&self) -> &T {
        &self.executer
    }

    pub fn executer_mut(&mut self) -> &mut T {
        &mut self.executer
    }

    pub fn authorizer(&self) -> &A {
        &self.authorizer
    }

    pub fn authorizer_mut(&mut self) -> &mut A {
        &mut self.authorizer
    }
}

impl<T: ExecuteRequest, A: Authorize> ExecuteRequest for Client<T, A> {
    type Error = ClientError<T::Error, A::Error>;

    fn execute_request(
        &self,
        mut request: Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send + 'static {
        let result = self
            .authorizer
            .authorize(&mut request)
            .map_err(ClientError::Authorize)
            .map(|_| self.executer.execute_request(request));

        async move { result?.await.map_err(ClientError::Execute) }
    }
}
