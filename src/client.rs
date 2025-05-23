use core::fmt;
use std::sync::Arc;

#[cfg(feature = "metrics")]
use prometheus::{CounterVec, opts, register_counter_vec};
use reqwest::{
    Response,
    header::{self, HeaderValue, InvalidHeaderValue, MaxSizeReached},
};
#[cfg(feature = "metrics")]
use std::sync::LazyLock;
#[cfg(feature = "metrics")]
use tokio::time::Instant;
use tracing::trace;

use crate::{
    credentials::{Authorization, any},
    execute::Execute,
};

// TELEMETRY ///////////////////////////////////////////////////////////////////

#[cfg(feature = "metrics")]
static CLIENT_REQUEST: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        opts!("oauth10a_client_request", "number of request on api"),
        &["endpoint", "method", "status"]
    )
    .expect("metrics 'oauth10a_client_request' to not be initialized")
});

#[cfg(feature = "metrics")]
static CLIENT_REQUEST_DURATION: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        opts!(
            "oauth10a_client_request_duration",
            "duration of request on api"
        ),
        &["endpoint", "method", "status", "unit"]
    )
    .expect("metrics 'oauth10a_client_request_duration' to not be initialized")
});

// CLIENT ERROR ////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum ClientError<T, A> {
    #[error(transparent)]
    Execute(T),
    #[error(transparent)]
    Authorization(A),
    #[error(transparent)]
    ParseHeaderValue(#[from] InvalidHeaderValue),
    #[error("too many headers")]
    TooManyHeader(#[from] MaxSizeReached),
}

// CLIENT //////////////////////////////////////////////////////////////////////

/// HTTP client.
#[derive(Debug, Clone)]
pub struct Client<T = reqwest::Client, A = any::Credentials> {
    inner: T,
    credentials: A,
}

pub type DefaultClient = Client<reqwest::Client, Option<Arc<any::Credentials>>>;

impl<T: Execute + fmt::Debug, A: Authorization + fmt::Debug> Client<T, A> {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn new(inner: T, credentials: A) -> Self {
        Self { inner, credentials }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn set_credentials(&mut self, credentials: A) {
        self.credentials = credentials;
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn with_credentials<B>(self, credentials: B) -> Client<T, B>
    where
        B: Authorization + fmt::Debug,
    {
        Client::new(self.inner, credentials)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T, A> Default for Client<T, A>
where
    T: Execute + Default + fmt::Debug,
    A: Authorization + Default + fmt::Debug,
{
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn default() -> Self {
        Self::new(T::default(), A::default())
    }
}

impl<T, A> From<A> for Client<T, A>
where
    T: Execute + Default + fmt::Debug,
    A: Authorization + fmt::Debug,
{
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn from(credentials: A) -> Self {
        Self::new(T::default(), credentials)
    }
}

impl<T> From<T> for Client<T, ()>
where
    T: Execute + fmt::Debug,
{
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn from(client: T) -> Self {
        Self::new(client, ())
    }
}

impl<T, A> Execute for Client<T, A>
where
    T: Execute<Error: Send> + Send + Sync + 'static,
    A: Authorization<Error: Send> + Send + Sync + 'static,
    Self: Clone,
{
    type Error = ClientError<<T as Execute>::Error, <A as Authorization>::Error>;

    #[allow(clippy::cast_precision_loss)]
    fn execute(
        &self,
        mut request: reqwest::Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send + 'static {
        let this = self.clone();

        async move {
            if !request.headers().contains_key(header::AUTHORIZATION) {
                if let Some(authorization) = this
                    .credentials
                    .authorization(&request)
                    .map_err(ClientError::Authorization)?
                {
                    let val = {
                        let mut val = authorization.parse::<HeaderValue>()?;
                        val.set_sensitive(true);
                        val
                    };
                    request
                        .headers_mut()
                        .try_insert(header::AUTHORIZATION, val)?;
                }
            }

            #[cfg(any(feature = "logging", feature = "metrics"))]
            let (method, endpoint) = (request.method().to_string(), request.url().to_string());

            #[cfg(feature = "logging")]
            trace!(%endpoint, %method, "execute request");

            #[cfg(feature = "metrics")]
            let instant = Instant::now();

            let response = this
                .inner
                .execute(request)
                .await
                .map_err(ClientError::Execute)?;

            #[cfg(feature = "metrics")]
            {
                let status_code = response.status().as_u16().to_string();

                CLIENT_REQUEST
                    .with_label_values(&[&endpoint, &method, &status_code])
                    .inc();

                CLIENT_REQUEST_DURATION
                    .with_label_values(&[&endpoint, &method, &status_code, &"us".to_string()])
                    .inc_by(Instant::now().duration_since(instant).as_micros() as f64);
            }

            Ok(response)
        }
    }
}
