//! `RESTful` API client.

use core::fmt;

use reqwest::{
    IntoUrl, Method, StatusCode,
    header::{self, HeaderValue},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::execute::ExecuteRequest;

pub const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");

pub const UTF8: HeaderValue = HeaderValue::from_static("utf-8");

// REST ERROR //////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum RestError<E> {
    #[error(transparent)]
    Execute(E),
    #[error("failed to serialize body, {0}")]
    Serialize(serde_json::Error),
    #[error("invalid url endpoint, {0}")]
    Url(reqwest::Error),
    #[error("failed to aggregate body, {0}")]
    BodyAggregation(reqwest::Error),
    #[error("failed to insert header: too many entries")]
    TooManyHeaders(#[from] header::MaxSizeReached),
    #[error("failed to deserialize body, {0}")]
    Deserialize(serde_json::Error),
}

// ERROR RESPONSE //////////////////////////////////////////////////////////////

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("error response with status code {status_code}, {value:?}")]
pub struct ErrorResponse<E = serde_json::Value> {
    pub status_code: StatusCode,
    pub value: E,
}

// REST CLIENT /////////////////////////////////////////////////////////////////

/// Extension trait for HTTP clients for working with `RESTful` web APIs.
pub trait RestClient<X>: ExecuteRequest {
    /// Creates and executes an HTTP request that expects to receive a response
    /// which JSON body deserializes to `O` if status code is success and to `E`
    /// otherwise.
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
        E: DeserializeOwned + fmt::Debug + Send + Sync;

    fn put<I, O, E>(
        &self,
        endpoint: X,
        payload: &I,
    ) -> impl Future<Output = Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        I: ?Sized + Serialize + fmt::Debug + Send + Sync,
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync;

    fn patch<I, O, E>(
        &self,
        endpoint: X,
        payload: &I,
    ) -> impl Future<Output = Result<Result<O, ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        I: ?Sized + Serialize + fmt::Debug + Send + Sync,
        O: DeserializeOwned + fmt::Debug + Send + Sync,
        E: DeserializeOwned + fmt::Debug + Send + Sync;

    fn delete<E>(
        &self,
        endpoint: X,
    ) -> impl Future<Output = Result<Result<(), ErrorResponse<E>>, RestError<Self::Error>>> + Send
    where
        E: DeserializeOwned + fmt::Debug + Send + Sync;
}

impl<X: IntoUrl + fmt::Debug + Send, T: ExecuteRequest> RestClient<X> for T {
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

        let mut request = reqwest::Request::new(method.to_owned(), url);

        let headers = request.headers_mut();
        let _ = headers.try_insert(header::CONTENT_TYPE, APPLICATION_JSON)?;
        let _ = headers.try_insert(header::CONTENT_LENGTH, HeaderValue::from(buf.len()))?;
        let _ = headers.try_insert(header::ACCEPT_CHARSET, UTF8)?;
        let _ = headers.try_insert(header::ACCEPT, APPLICATION_JSON)?;

        *request.body_mut() = Some(buf.into());

        let response = self
            .execute_request(request)
            .await
            .map_err(RestError::Execute)?;

        let status_code = response.status();

        let full = response.bytes().await.map_err(RestError::BodyAggregation)?;

        if !status_code.is_success() {
            let value = serde_json::from_slice(&full).map_err(RestError::Deserialize)?;
            return Ok(Err(ErrorResponse { status_code, value }));
        }

        let value = serde_json::from_slice(&full).map_err(RestError::Deserialize)?;

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

        let response = self
            .execute_request(request)
            .await
            .map_err(RestError::Execute)?;

        let status_code = response.status();

        let full = response.bytes().await.map_err(RestError::BodyAggregation)?;

        if !status_code.is_success() {
            let value = serde_json::from_slice(&full).map_err(RestError::Deserialize)?;
            return Ok(Err(ErrorResponse { status_code, value }));
        }

        let value = serde_json::from_slice(&full).map_err(RestError::Deserialize)?;

        Ok(Ok(value))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
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

    #[cfg_attr(feature = "tracing", tracing::instrument)]
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

    #[cfg_attr(feature = "tracing", tracing::instrument)]
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

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn delete<E>(
        &self,
        endpoint: X,
    ) -> Result<Result<(), ErrorResponse<E>>, RestError<Self::Error>>
    where
        E: DeserializeOwned + fmt::Debug + Send + Sync,
    {
        let url = endpoint.into_url().map_err(RestError::Url)?;

        let request = reqwest::Request::new(Method::DELETE, url);

        let response = self
            .execute_request(request)
            .await
            .map_err(RestError::Execute)?;

        let status_code = response.status();

        if !status_code.is_success() {
            let full = response.bytes().await.map_err(RestError::BodyAggregation)?;
            let value = serde_json::from_slice(&full).map_err(RestError::Deserialize)?;
            return Ok(Err(ErrorResponse { status_code, value }));
        }

        Ok(Ok(()))
    }
}
