//! # OAuth 1.0a client
//!
//! This module provide an oauth1a client implementation. It was firstly designed
//! to interact with the Clever-Cloud's api, but has been extended to be more
//! generic.

#[cfg(feature = "metrics")]
use std::time::Instant;
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    time::{SystemTime, SystemTimeError},
};

use async_trait::async_trait;
use bytes::Buf;
use crypto_common::InvalidLength;
use hmac::{Hmac, Mac};
use hyper::{
    client::{
        connect::{dns::GaiResolver, Connect},
        HttpConnector,
    },
    header, Body, Method, StatusCode,
};
use hyper_tls::HttpsConnector;
#[cfg(feature = "metrics")]
use lazy_static::lazy_static;
#[cfg(feature = "logging")]
use log::{error, log_enabled, trace, Level};
#[cfg(feature = "metrics")]
use prometheus::{opts, register_counter_vec, CounterVec};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha512;
use uuid::Uuid;

pub mod connector;

// -----------------------------------------------------------------------------
// Telemetry

#[cfg(feature = "metrics")]
lazy_static! {
    static ref CLIENT_REQUEST: CounterVec = register_counter_vec!(
        opts!("oauth10a_client_request", "number of request on api"),
        &["endpoint", "method", "status"]
    )
    .expect("metrics 'oauth10a_client_request' to not be initialized");
    static ref CLIENT_REQUEST_DURATION: CounterVec = register_counter_vec!(
        opts!(
            "oauth10a_client_request_duration",
            "duration of request on api"
        ),
        &["endpoint", "method", "status", "unit"]
    )
    .expect("metrics 'oauth10a_client_request_duration' to not be initialized");
}

// -----------------------------------------------------------------------------
// Types
type HmacSha512 = Hmac<Sha512>;

// -----------------------------------------------------------------------------
// Request trait

#[async_trait]
pub trait Request {
    type Error;

    async fn request<T, U>(
        &self,
        method: &Method,
        endpoint: &str,
        payload: &T,
    ) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync;
}

// -----------------------------------------------------------------------------
// RestClient trait

#[async_trait]
pub trait RestClient
where
    Self: Debug,
{
    type Error;

    async fn get<T>(&self, endpoint: &str) -> Result<T, Self::Error>
    where
        T: DeserializeOwned + Debug + Send + Sync;

    async fn post<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync;

    async fn put<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync;

    async fn patch<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync;

    async fn delete(&self, endpoint: &str) -> Result<(), Self::Error>;
}

// -----------------------------------------------------------------------------
// ClientCredentials structure

#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct Credentials {
    pub token: String,
    pub secret: String,
    pub consumer_key: String,
    pub consumer_secret: String,
}

// -----------------------------------------------------------------------------
// OAuth1 trait

pub const OAUTH1_CONSUMER_KEY: &str = "oauth_consumer_key";
pub const OAUTH1_NONCE: &str = "oauth_nonce";
pub const OAUTH1_SIGNATURE: &str = "oauth_signature";
pub const OAUTH1_SIGNATURE_METHOD: &str = "oauth_signature_method";
pub const OAUTH1_SIGNATURE_HMAC_SHA512: &str = "HMAC-SHA512";
pub const OAUTH1_TIMESTAMP: &str = "oauth_timestamp";
pub const OAUTH1_VERSION: &str = "oauth_version";
pub const OAUTH1_VERSION_1: &str = "1.0";
pub const OAUTH1_TOKEN: &str = "oauth_token";

pub trait OAuth1
where
    Self: Debug,
{
    type Error;

    // `params` returns OAuth1 parameters without the signature one
    fn params(&self) -> BTreeMap<String, String>;

    // `signature` returns the computed signature from given parameters
    fn signature(&self, method: &str, endpoint: &str) -> Result<String, Self::Error>;

    // `signing_key` returns the key that is used to signed the signature
    fn signing_key(&self) -> String;

    #[cfg_attr(feature = "trace", tracing::instrument)]
    // `sign` returns OAuth1 formatted Authorization header value
    fn sign(&self, method: &str, endpoint: &str) -> Result<String, Self::Error> {
        let signature = self.signature(method, endpoint)?;
        let mut params = self.params();

        params.insert(OAUTH1_SIGNATURE.to_string(), signature);

        let mut base = params
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, urlencoding::encode(v)))
            .collect::<Vec<_>>();

        base.sort();

        Ok(format!("OAuth {}", base.join(", ")))
    }
}

// -----------------------------------------------------------------------------
// ResponseError structure

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseError {
    #[serde(rename = "id")]
    pub id: u32,
    #[serde(rename = "message")]
    pub message: String,
    #[serde(rename = "type")]
    pub kind: String,
}

impl Display for ResponseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "got response {} {}, {}",
            self.kind, self.id, self.message
        )
    }
}

impl Error for ResponseError {}

// -----------------------------------------------------------------------------
// SignerError enum

#[derive(thiserror::Error, Debug)]
pub enum SignerError {
    #[error("failed to compute invalid key length, {0}")]
    Digest(InvalidLength),
    #[error("failed to compute time since unix epoch, {0}")]
    UnixEpochTime(SystemTimeError),
    #[error("failed to parse signature paramater, {0}")]
    Parse(String),
}

// -----------------------------------------------------------------------------
// Signer structure

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Signer {
    pub nonce: String,
    pub timestamp: u64,
    pub credentials: Credentials,
}

impl OAuth1 for Signer {
    type Error = SignerError;

    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn params(&self) -> BTreeMap<String, String> {
        let mut params = BTreeMap::new();

        params.insert(
            OAUTH1_CONSUMER_KEY.to_string(),
            self.credentials.consumer_key.to_string(),
        );
        params.insert(OAUTH1_NONCE.to_string(), self.nonce.to_string());
        params.insert(
            OAUTH1_SIGNATURE_METHOD.to_string(),
            OAUTH1_SIGNATURE_HMAC_SHA512.to_string(),
        );
        params.insert(OAUTH1_TIMESTAMP.to_string(), self.timestamp.to_string());
        params.insert(OAUTH1_VERSION.to_string(), OAUTH1_VERSION_1.to_string());
        params.insert(OAUTH1_TOKEN.to_string(), self.credentials.token.to_string());
        params
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn signing_key(&self) -> String {
        format!(
            "{}&{}",
            urlencoding::encode(&self.credentials.consumer_secret.to_owned()),
            urlencoding::encode(&self.credentials.secret.to_owned())
        )
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn signature(&self, method: &str, endpoint: &str) -> Result<String, Self::Error> {
        let (host, query) = match endpoint.find(|c| '?' == c) {
            None => (endpoint, ""),
            // split one character further to not get the '?' character
            Some(position) => endpoint.split_at(position),
        };

        let query = query.strip_prefix('?').unwrap_or(query);
        let mut params = self.params();

        if !query.is_empty() {
            for qparam in query.split('&') {
                let (k, v) = qparam.split_at(qparam.find('=').ok_or_else(|| {
                    SignerError::Parse(format!("failed to parse query parameter, {}", qparam))
                })?);

                if !params.contains_key(k) {
                    params.insert(k.to_string(), v.strip_prefix('=').unwrap_or(v).to_owned());
                }
            }
        }

        let mut params = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>();

        params.sort();

        let base = format!(
            "{}&{}&{}",
            urlencoding::encode(method),
            urlencoding::encode(host),
            urlencoding::encode(&params.join("&"))
        );

        let mut hasher = HmacSha512::new_from_slice(self.signing_key().as_bytes())
            .map_err(SignerError::Digest)?;

        hasher.update(base.as_bytes());

        let digest = hasher.finalize().into_bytes();
        Ok(base64::encode(digest.as_slice()))
    }
}

impl TryFrom<Credentials> for Signer {
    type Error = SignerError;

    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn try_from(credentials: Credentials) -> Result<Self, Self::Error> {
        let nonce = Uuid::new_v4().to_string();
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(SignerError::UnixEpochTime)?
            .as_secs();

        Ok(Self {
            nonce,
            timestamp,
            credentials,
        })
    }
}

// -----------------------------------------------------------------------------
// ClientError enum

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("failed to build request, {0}")]
    RequestBuilder(hyper::http::Error),
    #[error("failed to execute request, {0}")]
    Request(hyper::Error),
    #[error("failed to execute request, got status code {0}, {1}")]
    StatusCode(StatusCode, ResponseError),
    #[error("failed to aggregate body, {0}")]
    BodyAggregation(hyper::Error),
    #[error("failed to serialize body, {0}")]
    Serialize(serde_json::Error),
    #[error("failed to deserialize body, {0}")]
    Deserialize(serde_json::Error),
    #[error("failed to create request signer, {0}")]
    Signer(SignerError),
    #[error("failed to compute request digest, {0}")]
    Digest(SignerError),
}

// -----------------------------------------------------------------------------
// Client structure

#[derive(Clone, Debug)]
pub struct Client<C>
where
    C: Connect + Clone + Debug + Send + Sync + 'static,
{
    inner: hyper::Client<C, Body>,
    credentials: Option<Credentials>,
}

#[async_trait]
impl<C> Request for Client<C>
where
    C: Connect + Clone + Debug + Send + Sync + 'static,
{
    type Error = ClientError;

    #[cfg_attr(feature = "trace", tracing::instrument)]
    async fn request<T, U>(
        &self,
        method: &Method,
        endpoint: &str,
        payload: &T,
    ) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync,
    {
        let buf = serde_json::to_vec(payload).map_err(ClientError::Serialize)?;
        let mut builder = hyper::Request::builder();
        if let Some(credentials) = &self.credentials {
            let signer = Signer::try_from(credentials.to_owned()).map_err(ClientError::Signer)?;

            builder = builder.header(
                header::AUTHORIZATION,
                signer
                    .sign(method.as_str(), endpoint)
                    .map_err(ClientError::Digest)?,
            );
        }

        let req = builder
            .method(method)
            .uri(endpoint)
            .body(Body::from(buf.to_owned()))
            .map_err(ClientError::RequestBuilder)?;

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Trace) {
            trace!(
                "execute request, endpoint: '{}', method: '{}', body: '{}'",
                endpoint,
                method.to_string(),
                String::from_utf8_lossy(&buf).to_string()
            );
        }

        #[cfg(feature = "metrics")]
        let instant = Instant::now();
        let res = self
            .inner
            .request(req)
            .await
            .map_err(ClientError::Request)?;

        let status = res.status();
        let buf = hyper::body::aggregate(res.into_body())
            .await
            .map_err(ClientError::BodyAggregation)?;

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Trace) {
            trace!(
                "received response, endpoint: '{}', method: '{}', status: '{}'",
                endpoint,
                method.to_string(),
                status.as_u16()
            );
        }

        #[cfg(feature = "metrics")]
        CLIENT_REQUEST
            .with_label_values(&[endpoint, &method.to_string(), &status.as_u16().to_string()])
            .inc();

        #[cfg(feature = "metrics")]
        CLIENT_REQUEST_DURATION
            .with_label_values(&[
                endpoint,
                &method.to_string(),
                &status.as_u16().to_string(),
                "us",
            ])
            .inc_by(Instant::now().duration_since(instant).as_micros() as f64);

        if !status.is_success() {
            return Err(ClientError::StatusCode(
                status,
                serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)?,
            ));
        }

        Ok(serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)?)
    }
}

#[async_trait]
impl<C> RestClient for Client<C>
where
    C: Connect + Clone + Debug + Send + Sync + 'static,
{
    type Error = ClientError;

    #[cfg_attr(feature = "trace", tracing::instrument)]
    async fn get<T>(&self, endpoint: &str) -> Result<T, Self::Error>
    where
        T: DeserializeOwned + Debug + Send + Sync,
    {
        let method = &Method::GET;
        let mut builder = hyper::Request::builder();
        if let Some(credentials) = &self.credentials {
            let signer = Signer::try_from(credentials.to_owned()).map_err(ClientError::Signer)?;

            builder = builder.header(
                header::AUTHORIZATION,
                signer
                    .sign(method.as_str(), endpoint)
                    .map_err(ClientError::Digest)?,
            );
        }

        let req = builder
            .method(method)
            .uri(endpoint)
            .body(Body::empty())
            .map_err(ClientError::RequestBuilder)?;

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Trace) {
            trace!(
                "execute request, endpoint: '{}', method: '{}', body: '<none>'",
                endpoint,
                method.to_string()
            );
        }

        #[cfg(feature = "metrics")]
        let instant = Instant::now();
        let res = self
            .inner
            .request(req)
            .await
            .map_err(ClientError::Request)?;

        let status = res.status();
        let buf = hyper::body::aggregate(res.into_body())
            .await
            .map_err(ClientError::BodyAggregation)?;

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Trace) {
            trace!(
                "received response, endpoint: '{}', method: '{}', status: '{}'",
                endpoint,
                method.to_string(),
                status.as_u16()
            );
        }

        #[cfg(feature = "metrics")]
        CLIENT_REQUEST
            .with_label_values(&[endpoint, &method.to_string(), &status.as_u16().to_string()])
            .inc();

        #[cfg(feature = "metrics")]
        CLIENT_REQUEST_DURATION
            .with_label_values(&[
                endpoint,
                &method.to_string(),
                &status.as_u16().to_string(),
                "us",
            ])
            .inc_by(Instant::now().duration_since(instant).as_micros() as f64);

        if !status.is_success() {
            return Err(ClientError::StatusCode(
                status,
                serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)?,
            ));
        }

        Ok(serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)?)
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    async fn post<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync,
    {
        self.request(&Method::POST, endpoint, payload).await
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    async fn put<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync,
    {
        self.request(&Method::PUT, endpoint, payload).await
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    async fn patch<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync,
    {
        self.request(&Method::PATCH, endpoint, payload).await
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    async fn delete(&self, endpoint: &str) -> Result<(), Self::Error> {
        let method = &Method::DELETE;
        let mut builder = hyper::Request::builder();
        if let Some(credentials) = &self.credentials {
            let signer = Signer::try_from(credentials.to_owned()).map_err(ClientError::Signer)?;

            builder = builder.header(
                header::AUTHORIZATION,
                signer
                    .sign(method.as_str(), endpoint)
                    .map_err(ClientError::Digest)?,
            );
        }

        let req = builder
            .method(method)
            .uri(endpoint)
            .body(Body::empty())
            .map_err(ClientError::RequestBuilder)?;

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Trace) {
            trace!(
                "execute request, endpoint: '{}', method: '{}', body: '<none>'",
                endpoint,
                method.to_string()
            );
        }

        #[cfg(feature = "metrics")]
        let instant = Instant::now();
        let res = self
            .inner
            .request(req)
            .await
            .map_err(ClientError::Request)?;

        let status = res.status();
        let buf = hyper::body::aggregate(res.into_body())
            .await
            .map_err(ClientError::BodyAggregation)?;

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Trace) {
            trace!(
                "received response, endpoint: '{}', method: '{}', status: '{}'",
                endpoint,
                method.to_string(),
                status.as_u16()
            );
        }

        #[cfg(feature = "metrics")]
        CLIENT_REQUEST
            .with_label_values(&[endpoint, &method.to_string(), &status.as_u16().to_string()])
            .inc();

        #[cfg(feature = "metrics")]
        CLIENT_REQUEST_DURATION
            .with_label_values(&[
                endpoint,
                &method.to_string(),
                &status.as_u16().to_string(),
                "us",
            ])
            .inc_by(Instant::now().duration_since(instant).as_micros() as f64);

        if !status.is_success() {
            return Err(ClientError::StatusCode(
                status,
                serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)?,
            ));
        }

        Ok(())
    }
}

impl Default for Client<HttpsConnector<HttpConnector<GaiResolver>>> {
    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn default() -> Self {
        Self::from(HttpsConnector::new())
    }
}

impl From<Credentials> for Client<HttpsConnector<HttpConnector<GaiResolver>>> {
    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn from(credentials: Credentials) -> Self {
        Self::new(HttpsConnector::new(), Some(credentials))
    }
}

impl<C> From<C> for Client<C>
where
    C: Connect + Clone + Debug + Send + Sync + 'static,
{
    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn from(connector: C) -> Self {
        Self::new(connector, None)
    }
}

impl<C> Client<C>
where
    C: Connect + Clone + Debug + Send + Sync + 'static,
{
    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn new(connector: C, credentials: Option<Credentials>) -> Self {
        let inner = hyper::Client::builder().build(connector);

        Self { inner, credentials }
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn set_credentials(&mut self, credentials: Option<Credentials>) {
        self.credentials = credentials;
    }
}
