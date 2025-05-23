use core::fmt;

use bytes::Buf;
use reqwest::{
    IntoUrl, Method, StatusCode,
    header::{self, HeaderValue, MaxSizeReached},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::trace;

use crate::execute::Execute;

pub const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");

pub const UTF8: HeaderValue = HeaderValue::from_static("utf-8");

// REST ERROR //////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum RestError<E> {
    #[error(transparent)]
    Execute(E),
    #[error("")]
    Serialize(serde_json::Error),
    #[error("")]
    Url(reqwest::Error),
    #[error("")]
    BodyAggregation(reqwest::Error),
    #[error("")]
    TooManyHeaders(#[from] MaxSizeReached),
    #[error("")]
    Deserialize(serde_json::Error),
}

// ERROR RESPONSE //////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ErrorResponse<E> {
    pub status_code: StatusCode,
    pub value: E,
}

// REST CLIENT /////////////////////////////////////////////////////////////////

pub trait RestClient<X>: Execute {
    fn request<I, O, E>(
        &self,
        method: &Method,
        endpoint: X,
        payload: &I,
    ) -> impl Future<Output = Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        I: ?Sized + Serialize + fmt::Debug + Send + Sync,
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync;

    fn get<O, E>(
        &self,
        endpoint: X,
    ) -> impl Future<Output = Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync;

    fn post<I, O, E>(
        &self,
        endpoint: X,
        payload: &I,
    ) -> impl Future<Output = Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        I: ?Sized + Serialize + fmt::Debug + Send + Sync,
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync,
    {
        self.request(&Method::POST, endpoint, payload)
    }

    fn put<I, O, E>(
        &self,
        endpoint: X,
        payload: &I,
    ) -> impl Future<Output = Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        I: ?Sized + Serialize + fmt::Debug + Send + Sync,
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync,
    {
        self.request(&Method::PUT, endpoint, payload)
    }

    fn patch<I, O, E>(
        &self,
        endpoint: X,
        payload: &I,
    ) -> impl Future<Output = Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        I: ?Sized + Serialize + fmt::Debug + Send + Sync,
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync,
    {
        self.request(&Method::PATCH, endpoint, payload)
    }

    fn delete<E>(
        &self,
        endpoint: X,
    ) -> impl Future<Output = Result<Result<(), ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        E: DeserializeOwned + fmt::Debug + Send + Sync;
}

impl<X, T> RestClient<X> for T
where
    X: IntoUrl + fmt::Debug + Send,
    T: fmt::Debug + Execute<Error: Send> + Send + Sync,
{
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn request<I, O, E>(
        &self,
        method: &Method,
        endpoint: X,
        payload: &I,
    ) -> Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>
    where
        I: ?Sized + Serialize + fmt::Debug + Send + Sync,
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync,
    {
        let buf = serde_json::to_vec(payload).map_err(RestError::Serialize)?;

        let url = endpoint.into_url().map_err(RestError::Url)?;

        #[cfg(feature = "logging")]
        let endpoint = url.as_str().to_owned();

        let mut request = reqwest::Request::new(method.to_owned(), url);

        let headers = request.headers_mut();
        let _ = headers.try_insert(header::CONTENT_TYPE, APPLICATION_JSON)?;
        let _ = headers.try_insert(header::CONTENT_LENGTH, HeaderValue::from(buf.len()))?;
        let _ = headers.try_insert(header::ACCEPT_CHARSET, UTF8)?;
        let _ = headers.try_insert(header::ACCEPT, APPLICATION_JSON)?;

        *request.body_mut() = Some(buf.into());

        let response = self.execute(request).await.map_err(RestError::Execute)?;

        let status_code = response.status();

        let rdr = response
            .bytes()
            .await
            .map_err(RestError::BodyAggregation)?
            .reader();

        #[cfg(feature = "logging")]
        trace!(
            endpoint,
            method = %method,
            status_code = status_code.as_u16(),
            "received response",
        );

        if !status_code.is_success() {
            let value = serde_json::from_reader(rdr).map_err(RestError::Deserialize)?;
            return Ok(Err(ErrorResponse { status_code, value }));
        }

        let value = serde_json::from_reader(rdr).map_err(RestError::Deserialize)?;

        Ok(Ok(value))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn get<O, E>(
        &self,
        endpoint: X,
    ) -> Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>
    where
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync,
    {
        let url = endpoint.into_url().map_err(RestError::Url)?;

        let mut request = reqwest::Request::new(Method::GET, url);

        let headers = request.headers_mut();
        let _ = headers.try_insert(header::ACCEPT_CHARSET, UTF8)?;
        let _ = headers.try_insert(header::ACCEPT, APPLICATION_JSON)?;

        let response = self.execute(request).await.map_err(RestError::Execute)?;

        let status_code = response.status();

        let rdr = response
            .bytes()
            .await
            .map_err(RestError::BodyAggregation)?
            .reader();

        if !status_code.is_success() {
            let value = serde_json::from_reader(rdr).map_err(RestError::Deserialize)?;
            return Ok(Err(ErrorResponse { status_code, value }));
        }

        let value = serde_json::from_reader(rdr).map_err(RestError::Deserialize)?;

        Ok(Ok(value))
    }

    async fn delete<E>(
        &self,
        endpoint: X,
    ) -> Result<Result<(), ErrorResponse<E>>, RestError<Self::Error>>
    where
        E: DeserializeOwned + fmt::Debug + Send + Sync,
    {
        let url = endpoint.into_url().map_err(RestError::Url)?;

        let request = reqwest::Request::new(Method::DELETE, url);

        let response = self.execute(request).await.map_err(RestError::Execute)?;

        let status_code = response.status();

        let bytes = response.bytes().await.map_err(RestError::BodyAggregation)?;

        if !status_code.is_success() {
            let value = serde_json::from_reader(bytes.reader()).map_err(RestError::Deserialize)?;
            return Ok(Err(ErrorResponse { status_code, value }));
        }

        Ok(Ok(()))
    }
}
