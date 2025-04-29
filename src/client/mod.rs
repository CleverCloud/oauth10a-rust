//! # OAuth 1.0a client
//!
//! This module provides an OAuth 1.0a client implementation. It was firstly designed
//! to interact with the Clever-Cloud's api, but has been extended to be more
//! generic.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    future::Future,
    time::{SystemTime, SystemTimeError},
};
#[cfg(feature = "metrics")]
use std::{sync::LazyLock, time::Instant};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use bytes::Buf;
use crypto_common::InvalidLength;
use hmac::{Hmac, Mac};
#[cfg(feature = "logging")]
use log::{Level, error, log_enabled, trace};
#[cfg(feature = "metrics")]
use prometheus::{CounterVec, opts, register_counter_vec};
use reqwest::{
    Method, StatusCode,
    header::{self, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha512;
use uuid::Uuid;

// -----------------------------------------------------------------------------
// Exports

/// Export reqwest create to ease client creation if needed
pub use bytes;
pub use reqwest;
pub use url;

// -----------------------------------------------------------------------------
// Telemetry

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

// -----------------------------------------------------------------------------
// Types

type HmacSha512 = Hmac<Sha512>;

// -----------------------------------------------------------------------------
// Request trait

pub trait Request {
    type Error;

    fn request<T, U>(
        &self,
        method: &Method,
        endpoint: &str,
        payload: &T,
    ) -> impl Future<Output = Result<U, Self::Error>> + Send
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync;

    fn execute(
        &self,
        request: reqwest::Request,
    ) -> impl Future<Output = Result<reqwest::Response, Self::Error>> + Send;
}

// -----------------------------------------------------------------------------
// RestClient trait

pub trait RestClient: Debug {
    type Error;

    fn get<T>(&self, endpoint: &str) -> impl Future<Output = Result<T, Self::Error>> + Send
    where
        T: DeserializeOwned + Debug + Send + Sync;

    fn post<T, U>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> impl Future<Output = Result<U, Self::Error>> + Send
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync;

    fn put<T, U>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> impl Future<Output = Result<U, Self::Error>> + Send
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync;

    fn patch<T, U>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> impl Future<Output = Result<U, Self::Error>> + Send
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync;

    fn delete(&self, endpoint: &str) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

// -----------------------------------------------------------------------------
// ClientCredentials structure

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
#[serde(untagged)]
pub enum Credentials {
    OAuth1 {
        #[serde(rename = "token")]
        token: String,
        #[serde(rename = "secret")]
        secret: String,
        #[serde(rename = "consumer-key")]
        consumer_key: String,
        #[serde(rename = "consumer-secret")]
        consumer_secret: String,
    },
    Basic {
        #[serde(rename = "username")]
        username: String,
        #[serde(rename = "password")]
        password: String,
    },
    Bearer {
        #[serde(rename = "token")]
        token: String,
    },
}

impl Default for Credentials {
    fn default() -> Self {
        Self::OAuth1 {
            token: String::new(),
            secret: String::new(),
            consumer_key: String::new(),
            consumer_secret: String::new(),
        }
    }
}

impl Credentials {
    #[tracing::instrument(skip_all)]
    pub fn bearer(token: String) -> Self {
        Self::Bearer { token }
    }

    #[tracing::instrument(skip_all)]
    pub fn basic(username: String, password: String) -> Self {
        Self::Basic { username, password }
    }

    #[tracing::instrument(skip_all)]
    pub fn oauth1(
        token: String,
        secret: String,
        consumer_key: String,
        consumer_secret: String,
    ) -> Self {
        Self::OAuth1 {
            token,
            secret,
            consumer_key,
            consumer_secret,
        }
    }
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

pub trait OAuth1: Debug {
    type Error;

    // `params` returns OAuth1 parameters without the signature one
    fn params(&self) -> BTreeMap<String, String>;

    // `signature` returns the computed signature from given parameters
    fn signature(&self, method: &str, endpoint: &str) -> Result<String, Self::Error>;

    // `signing_key` returns the key that is used to sign the signature
    fn signing_key(&self) -> String;

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    // `sign` returns OAuth1 formatted Authorization header value
    fn sign(&self, method: &str, endpoint: &str) -> Result<String, Self::Error> {
        let signature = self.signature(method, endpoint)?;
        let mut params = self.params();

        params.insert(
            OAUTH1_SIGNATURE.to_string(),
            urlencoding::encode(&signature).into_owned(),
        );

        let mut base = params
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
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
            "got response {} ({}), {}",
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
    #[error("failed to parse signature parameter, {0}")]
    Parse(String),
    #[error(
        "failed to create signer as credentials are invalid, credentials have to be of type OAuth1, got bearer or basic"
    )]
    InvalidCredentials,
}

// -----------------------------------------------------------------------------
// Signer structure

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Signer {
    pub nonce: String,
    pub timestamp: u64,
    pub token: String,
    pub secret: String,
    pub consumer_key: String,
    pub consumer_secret: String,
}

impl OAuth1 for Signer {
    type Error = SignerError;

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn params(&self) -> BTreeMap<String, String> {
        let mut params = BTreeMap::new();

        params.insert(
            OAUTH1_CONSUMER_KEY.to_string(),
            self.consumer_key.to_string(),
        );
        params.insert(OAUTH1_NONCE.to_string(), self.nonce.to_string());
        params.insert(
            OAUTH1_SIGNATURE_METHOD.to_string(),
            OAUTH1_SIGNATURE_HMAC_SHA512.to_string(),
        );
        params.insert(OAUTH1_TIMESTAMP.to_string(), self.timestamp.to_string());
        params.insert(OAUTH1_VERSION.to_string(), OAUTH1_VERSION_1.to_string());
        params.insert(OAUTH1_TOKEN.to_string(), self.token.to_string());
        params
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn signature(&self, method: &str, endpoint: &str) -> Result<String, Self::Error> {
        let (host, query) = match endpoint.find('?') {
            None => (endpoint, ""),
            // split one character further to not get the '?' character
            Some(position) => endpoint.split_at(position),
        };

        let query = query.strip_prefix('?').unwrap_or(query);
        let mut params = self.params();

        if !query.is_empty() {
            for qparam in query.split('&') {
                let (k, v) = qparam.split_at(qparam.find('=').ok_or_else(|| {
                    SignerError::Parse(format!("failed to parse query parameter, {qparam}"))
                })?);

                if !params.contains_key(k) {
                    params.insert(k.to_string(), v.strip_prefix('=').unwrap_or(v).to_owned());
                }
            }
        }

        let mut params = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
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
        Ok(BASE64_ENGINE.encode(digest.as_slice()))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn signing_key(&self) -> String {
        format!(
            "{}&{}",
            urlencoding::encode(&self.consumer_secret),
            urlencoding::encode(&self.secret)
        )
    }
}

impl TryFrom<Credentials> for Signer {
    type Error = SignerError;

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn try_from(credentials: Credentials) -> Result<Self, Self::Error> {
        let nonce = Uuid::new_v4().to_string();
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(SignerError::UnixEpochTime)?
            .as_secs();

        match credentials {
            Credentials::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            } => Ok(Self {
                nonce,
                timestamp,
                token,
                secret,
                consumer_key,
                consumer_secret,
            }),
            _ => Err(SignerError::InvalidCredentials),
        }
    }
}

// -----------------------------------------------------------------------------
// ClientError enum

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("failed to execute request, {0}")]
    Request(reqwest::Error),
    #[error("failed to execute request, got status code {0}, {1}")]
    StatusCode(StatusCode, ResponseError),
    #[error("failed to aggregate body, {0}")]
    BodyAggregation(reqwest::Error),
    #[error("failed to serialize body, {0}")]
    Serialize(serde_json::Error),
    #[error("failed to deserialize body, {0}")]
    Deserialize(serde_json::Error),
    #[error("failed to create request signer, {0}")]
    Signer(SignerError),
    #[error("failed to compute request digest, {0}")]
    Digest(SignerError),
    #[error("failed to serialize signature as header value, {0}")]
    SerializeHeaderValue(header::InvalidHeaderValue),
    #[error("failed to parse url endpoint, {0}")]
    ParseUrlEndpoint(url::ParseError),
}

// -----------------------------------------------------------------------------
// Client structure

pub const APPLICATION_JSON: &str = "application/json";
pub const UTF8: &str = "utf-8";

#[derive(Clone, Debug)]
pub struct Client {
    inner: reqwest::Client,
    credentials: Option<Credentials>,
}

impl Request for Client {
    type Error = ClientError;

    #[cfg_attr(feature = "tracing", tracing::instrument)]
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
        let mut request = reqwest::Request::new(
            method.to_owned(),
            endpoint.parse().map_err(ClientError::ParseUrlEndpoint)?,
        );

        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(APPLICATION_JSON),
        );

        request
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(buf.len()));

        request
            .headers_mut()
            .insert(header::ACCEPT_CHARSET, HeaderValue::from_static(UTF8));

        request
            .headers_mut()
            .insert(header::ACCEPT, HeaderValue::from_static(APPLICATION_JSON));

        *request.body_mut() = Some(buf.into());

        let res = self.execute(request).await?;
        let status = res.status();
        let buf = res.bytes().await.map_err(ClientError::BodyAggregation)?;

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Trace) {
            trace!(
                "received response, endpoint: '{endpoint}', method: '{method}', status: '{}'",
                status.as_u16()
            );
        }

        if !status.is_success() {
            return Err(ClientError::StatusCode(
                status,
                serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)?,
            ));
        }

        serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn execute(
        &self,
        mut request: reqwest::Request,
    ) -> Result<reqwest::Response, Self::Error> {
        let method = request.method().to_string();
        let endpoint = request.url().to_string();
        if !request.headers().contains_key(&header::AUTHORIZATION) {
            match &self.credentials {
                Some(Credentials::Bearer { token }) => {
                    request.headers_mut().insert(
                        header::AUTHORIZATION,
                        HeaderValue::from_str(&format!("Bearer {token}"))
                            .map_err(ClientError::SerializeHeaderValue)?,
                    );
                }
                Some(Credentials::Basic { username, password }) => {
                    let token = BASE64_ENGINE.encode(format!("{username}:{password}"));

                    request.headers_mut().insert(
                        header::AUTHORIZATION,
                        HeaderValue::from_str(&format!("Basic {token}"))
                            .map_err(ClientError::SerializeHeaderValue)?,
                    );
                }
                Some(credentials) => {
                    let signer =
                        Signer::try_from(credentials.to_owned()).map_err(ClientError::Signer)?;

                    request.headers_mut().insert(
                        header::AUTHORIZATION,
                        signer
                            .sign(&method, &endpoint)
                            .map_err(ClientError::Digest)?
                            .parse()
                            .map_err(ClientError::SerializeHeaderValue)?,
                    );
                }
                _ => {}
            }
        }

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Trace) {
            trace!("execute request, endpoint: '{endpoint}', method: '{method}'");
        }

        #[cfg(feature = "metrics")]
        let instant = Instant::now();
        let res = self
            .inner
            .execute(request)
            .await
            .map_err(ClientError::Request)?;

        #[cfg(feature = "metrics")]
        {
            let status = res.status();

            CLIENT_REQUEST
                .with_label_values(&[&endpoint, &method, &status.as_u16().to_string()])
                .inc();

            CLIENT_REQUEST_DURATION
                .with_label_values(&[
                    &endpoint,
                    &method,
                    &status.as_u16().to_string(),
                    &"us".to_string(),
                ])
                .inc_by(Instant::now().duration_since(instant).as_micros() as f64);
        }

        Ok(res)
    }
}

impl RestClient for Client {
    type Error = ClientError;

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn get<T>(&self, endpoint: &str) -> Result<T, Self::Error>
    where
        T: DeserializeOwned + Debug + Send + Sync,
    {
        let mut req = reqwest::Request::new(
            Method::GET,
            endpoint.parse().map_err(ClientError::ParseUrlEndpoint)?,
        );

        req.headers_mut()
            .insert(header::ACCEPT_CHARSET, HeaderValue::from_static(UTF8));

        req.headers_mut()
            .insert(header::ACCEPT, HeaderValue::from_static(APPLICATION_JSON));

        let res = self.execute(req).await?;
        let status = res.status();
        let buf = res.bytes().await.map_err(ClientError::BodyAggregation)?;

        if !status.is_success() {
            return Err(ClientError::StatusCode(
                status,
                serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)?,
            ));
        }

        serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn post<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync,
    {
        self.request(&Method::POST, endpoint, payload).await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn put<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync,
    {
        self.request(&Method::PUT, endpoint, payload).await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn patch<T, U>(&self, endpoint: &str, payload: &T) -> Result<U, Self::Error>
    where
        T: Serialize + Debug + Send + Sync,
        U: DeserializeOwned + Debug + Send + Sync,
    {
        self.request(&Method::PATCH, endpoint, payload).await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn delete(&self, endpoint: &str) -> Result<(), Self::Error> {
        let req = reqwest::Request::new(
            Method::DELETE,
            endpoint.parse().map_err(ClientError::ParseUrlEndpoint)?,
        );

        let res = self.execute(req).await?;
        let status = res.status();
        let buf = res.bytes().await.map_err(ClientError::BodyAggregation)?;

        if !status.is_success() {
            return Err(ClientError::StatusCode(
                status,
                serde_json::from_reader(buf.reader()).map_err(ClientError::Deserialize)?,
            ));
        }

        Ok(())
    }
}

impl Default for Client {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn default() -> Self {
        Self::new(reqwest::Client::new(), None)
    }
}

impl From<Credentials> for Client {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn from(credentials: Credentials) -> Self {
        Self::new(reqwest::Client::new(), Some(credentials))
    }
}

impl From<reqwest::Client> for Client {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn from(client: reqwest::Client) -> Self {
        Self::new(client, None)
    }
}

impl Client {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn new(inner: reqwest::Client, credentials: Option<Credentials>) -> Self {
        Self { inner, credentials }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn set_credentials(&mut self, credentials: Option<Credentials>) {
        self.credentials = credentials;
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }
}
