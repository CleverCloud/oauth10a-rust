use core::fmt;
use std::sync::Arc;
#[cfg(feature = "metrics")]
use std::time::Instant;

#[cfg(feature = "metrics")]
use crate::metrics;

/// HTTP Client.
pub trait ExecuteRequest: fmt::Debug + Send + Sync + 'static {
    type Error: Send + 'static;

    /// Execute the HTTP request.
    ///
    /// # Errors
    ///
    /// If the client fails to send the request.
    fn execute_request(
        &self,
        request: reqwest::Request,
    ) -> impl Future<Output = Result<reqwest::Response, Self::Error>> + Send + 'static;
}

impl ExecuteRequest for reqwest::Client {
    type Error = reqwest::Error;

    #[inline]
    fn execute_request(
        &self,
        request: reqwest::Request,
    ) -> impl Future<Output = Result<reqwest::Response, Self::Error>> + Send + 'static {
        execute_request(self.clone(), request)
    }
}

#[inline]
#[cfg_attr(feature = "tracing", tracing::instrument)]
#[allow(clippy::cast_precision_loss)]
async fn execute_request(
    client: reqwest::Client,
    request: reqwest::Request,
) -> Result<reqwest::Response, reqwest::Error> {
    #[cfg(any(feature = "logging", feature = "metrics"))]
    let (endpoint, method) = (request.url().to_string(), request.method().to_string());

    #[cfg(feature = "logging")]
    trace!(%endpoint, %method, "execute request");

    #[cfg(feature = "metrics")]
    let instant = Instant::now();

    let response = client.execute(request).await?;

    #[cfg(any(feature = "logging", feature = "metrics"))]
    let status_code = response.status();

    #[cfg(feature = "logging")]
    trace!(
        endpoint,
        method = %method,
        status_code = %status_code,
        "received response",
    );

    #[cfg(feature = "metrics")]
    {
        let status_code = status_code.as_u16().to_string();

        metrics::CLIENT_REQUEST
            .with_label_values(&[&*endpoint, &*method, &*status_code])
            .inc();

        metrics::CLIENT_REQUEST_DURATION
            .with_label_values(&[&*endpoint, &*method, &*status_code, "us"])
            .inc_by(Instant::now().duration_since(instant).as_micros() as f64);
    }

    Ok(response)
}

impl<T: ExecuteRequest> ExecuteRequest for Arc<T> {
    type Error = T::Error;

    #[inline]
    fn execute_request(
        &self,
        request: reqwest::Request,
    ) -> impl Future<Output = Result<reqwest::Response, Self::Error>> + Send + 'static {
        self.as_ref().execute_request(request)
    }
}
