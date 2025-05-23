use core::fmt;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    time::{Duration, SystemTime, SystemTimeError},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use hmac::{Hmac, Mac};
use reqwest::{Method, Request};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use url::Url;
use uuid::Uuid;

use super::Authorization;

type HmacSha512 = Hmac<Sha512>;

// ERROR ///////////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("failed to compute time since Unix Epoch, {0}")]
    Clock(SystemTimeError),
    #[error("failed to compute invalid key length, {0}")]
    Digest(crypto_common::InvalidLength),
    #[error("missing host")]
    MissingHost,
}

// SIGNER //////////////////////////////////////////////////////////////////////

pub const OAUTH1_CONSUMER_KEY: &str = "oauth_consumer_key";
pub const OAUTH1_NONCE: &str = "oauth_nonce";
pub const OAUTH1_SIGNATURE: &str = "oauth_signature";
pub const OAUTH1_SIGNATURE_METHOD: &str = "oauth_signature_method";
pub const OAUTH1_SIGNATURE_HMAC_SHA512: &str = "HMAC-SHA512";
pub const OAUTH1_TIMESTAMP: &str = "oauth_timestamp";
pub const OAUTH1_VERSION: &str = "oauth_version";
pub const OAUTH1_VERSION_1: &str = "1.0";
pub const OAUTH1_TOKEN: &str = "oauth_token";

pub struct OAuth1Signer<'a> {
    pub nonce: Uuid,
    pub timestamp: Duration,
    pub credentials: Credentials<&'a str>,
}

impl OAuth1Signer<'_> {
    /// Returns OAuth1 parameters without the signature.
    fn params(&self) -> BTreeMap<Cow<'_, str>, Cow<'_, str>> {
        let mut params = BTreeMap::new();
        let _ = params.insert(
            Cow::Borrowed(OAUTH1_CONSUMER_KEY),
            self.credentials.consumer_key.into(),
        );
        let _ = params.insert(
            Cow::Borrowed(OAUTH1_NONCE),
            Cow::Owned(self.nonce.to_string()),
        );
        let _ = params.insert(
            Cow::Borrowed(OAUTH1_SIGNATURE_METHOD),
            Cow::Borrowed(OAUTH1_SIGNATURE_HMAC_SHA512),
        );
        let _ = params.insert(
            Cow::Borrowed(OAUTH1_TIMESTAMP),
            Cow::Owned(self.timestamp.as_secs().to_string()),
        );
        let _ = params.insert(
            Cow::Borrowed(OAUTH1_VERSION),
            Cow::Borrowed(OAUTH1_VERSION_1),
        );
        let _ = params.insert(
            Cow::Borrowed(OAUTH1_TOKEN),
            Cow::Borrowed(self.credentials.token),
        );
        params
    }

    /// Returns the key that is used to sign the signature.
    fn signing_key(&self) -> String {
        format!(
            "{}&{}",
            urlencoding::encode(self.credentials.consumer_secret),
            urlencoding::encode(self.credentials.secret)
        )
    }

    // Returns the computed signature from given parameters.
    fn signature(&self, method: &Method, endpoint: &Url) -> Result<String, AuthorizationError> {
        let mut params = self.params();

        params.extend(endpoint.query_pairs());

        let host = endpoint.host_str().ok_or(AuthorizationError::MissingHost)?;

        let mut params = params
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
            .collect::<Vec<_>>();

        params.sort();

        let base = format!(
            "{}&{}&{}",
            urlencoding::encode(method.as_str()),
            urlencoding::encode(host),
            urlencoding::encode(&params.join("&"))
        );

        let mut hasher = HmacSha512::new_from_slice(self.signing_key().as_bytes())
            .map_err(AuthorizationError::Digest)?;

        hasher.update(base.as_bytes());

        let digest = hasher.finalize().into_bytes();

        Ok(urlencoding::encode(&BASE64_ENGINE.encode(digest.as_slice())).into_owned())
    }

    /// Returns OAuth1 formatted Authorization header value.
    fn sign(&self, method: &Method, endpoint: &Url) -> Result<String, AuthorizationError> {
        let signature = self.signature(method, endpoint)?;

        let mut params = self.params();

        let _ = params.insert(
            Cow::Borrowed(OAUTH1_SIGNATURE),
            urlencoding::encode(&signature),
        );

        let mut base = params
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>();

        base.sort();

        Ok(format!("OAuth {}", base.join(", ")))
    }
}

// CREDENTIALS /////////////////////////////////////////////////////////////////

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials<T = String> {
    #[serde(rename = "token")]
    token: T,
    #[serde(rename = "secret")]
    secret: T,
    #[serde(rename = "consumer-key")]
    consumer_key: T,
    #[serde(rename = "consumer-secret")]
    consumer_secret: T,
}

impl<T> Credentials<T> {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
    pub fn new(token: T, secret: T, consumer_key: T, consumer_secret: T) -> Self {
        Self {
            token,
            secret,
            consumer_key,
            consumer_secret,
        }
    }
}

impl<T: AsRef<str>> Credentials<T> {
    pub fn as_ref(&self) -> Credentials<&str> {
        let Self {
            token,
            secret,
            consumer_key,
            consumer_secret,
        } = self;
        Credentials {
            token: token.as_ref(),
            secret: secret.as_ref(),
            consumer_key: consumer_key.as_ref(),
            consumer_secret: consumer_secret.as_ref(),
        }
    }

    fn signer(&self) -> Result<OAuth1Signer<'_>, AuthorizationError> {
        let nonce = Uuid::new_v4();
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(AuthorizationError::Clock)?;

        Ok(OAuth1Signer {
            nonce,
            timestamp,
            credentials: self.as_ref(),
        })
    }
}

impl<T> fmt::Debug for Credentials<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth1Credentials").finish_non_exhaustive()
    }
}

impl<T: AsRef<str>> Authorization for Credentials<T> {
    type Error = AuthorizationError;

    fn authorization(&self, request: &Request) -> Result<Option<String>, Self::Error> {
        Ok(Some(self.signer()?.sign(request.method(), request.url())?))
    }
}
