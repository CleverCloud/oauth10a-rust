//! OAuth 1.0a signature implementation.

use std::{
    collections::BTreeMap,
    marker::PhantomData,
    time::{SystemTime, SystemTimeError},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use crypto_common::InvalidLength;
use hmac::{Hmac, Mac};
use reqwest::{Method, Url};
use sha2::Sha512;
use uuid::Uuid;

// SIGNATURE METHOD ////////////////////////////////////////////////////////////

pub trait SignatureMethod {
    type Error;

    const SIGNATURE_METHOD: &'static str;

    /// Returns the base64-encoded signature.
    ///
    /// # Errors
    ///
    /// If digestion failed.
    fn digest(key: &str, signature: &str) -> Result<String, Self::Error>;
}

// HMAC-SHA512 /////////////////////////////////////////////////////////////////

pub type HmacSha512 = Hmac<Sha512>;

impl SignatureMethod for HmacSha512 {
    type Error = InvalidLength;

    const SIGNATURE_METHOD: &'static str = "HMAC-SHA512";

    #[inline]
    fn digest(key: &str, signature: &str) -> Result<String, Self::Error> {
        let key = key.as_bytes();
        let hash_value = {
            let mut hasher = HmacSha512::new_from_slice(key)?;
            hasher.update(signature.as_bytes());
            hasher.finalize().into_bytes()
        };
        Ok(BASE64_ENGINE.encode(hash_value))
    }
}

// ERROR ///////////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum SignError<T: SignatureMethod = HmacSha512> {
    #[error("failed to compute time since Unix Epoch, {0}")]
    Clock(#[from] SystemTimeError),
    #[error("failed to generate signature for {method}, {0}", method = T::SIGNATURE_METHOD)]
    Digest(T::Error),
}

// SIGNER //////////////////////////////////////////////////////////////////////

pub const OAUTH1_CONSUMER_KEY: &str = "oauth_consumer_key";
pub const OAUTH1_NONCE: &str = "oauth_nonce";
pub const OAUTH1_SIGNATURE: &str = "oauth_signature";
pub const OAUTH1_SIGNATURE_METHOD: &str = "oauth_signature_method";
pub const OAUTH1_TIMESTAMP: &str = "oauth_timestamp";
pub const OAUTH1_VERSION: &str = "oauth_version";
pub const OAUTH1_VERSION_1: &str = "1.0";
pub const OAUTH1_TOKEN: &str = "oauth_token";

/// OAuth1.0a signer.
#[derive(Debug)]
pub struct Signer<'a, T> {
    nonce: String,
    timestamp: String,
    token: &'a str,
    secret: &'a str,
    consumer_key: &'a str,
    consumer_secret: &'a str,
    _marker: PhantomData<T>,
}

impl<'a, T: SignatureMethod> Signer<'a, T> {
    /// Returns a new `Signer`.
    ///
    /// # Errors
    ///
    /// If system's clock went backwards.
    pub fn new(
        token: &'a str,
        secret: &'a str,
        consumer_key: &'a str,
        consumer_secret: &'a str,
    ) -> Result<Self, SignError<T>> {
        let nonce = Uuid::new_v4().to_string();

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            .to_string();

        Ok(Self {
            nonce,
            timestamp,
            token,
            secret,
            consumer_key,
            consumer_secret,
            _marker: PhantomData,
        })
    }

    /// Returns OAuth1.0a parameters without the signature.
    fn params(&self) -> BTreeMap<&str, &str> {
        let mut params = BTreeMap::new();
        let _ = params.insert(OAUTH1_CONSUMER_KEY, self.consumer_key);
        let _ = params.insert(OAUTH1_NONCE, &self.nonce);
        let _ = params.insert(OAUTH1_SIGNATURE_METHOD, T::SIGNATURE_METHOD);
        let _ = params.insert(OAUTH1_TIMESTAMP, &self.timestamp);
        let _ = params.insert(OAUTH1_TOKEN, self.token);
        let _ = params.insert(OAUTH1_VERSION, OAUTH1_VERSION_1);
        params
    }

    fn signature(&self, method: &Method, endpoint: &Url) -> String {
        let mut params = self.params();

        let pairs = endpoint.query_pairs().collect::<Vec<_>>();
        params.extend(pairs.iter().map(|(k, v)| (k.as_ref(), v.as_ref())));

        let mut params = params
            .into_iter()
            .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
            .collect::<Vec<_>>();

        params.sort();

        let base_url = format!(
            "{}{}",
            endpoint.origin().unicode_serialization(),
            endpoint.path()
        );

        format!(
            "{}&{}&{}",
            urlencoding::encode(method.as_str()),
            urlencoding::encode(&base_url),
            urlencoding::encode(&params.join("&"))
        )
    }

    fn signing_key(&self) -> String {
        format!(
            "{}&{}",
            urlencoding::encode(self.consumer_secret),
            urlencoding::encode(self.secret)
        )
    }

    /// Returns the formatted value for the Authorization header.
    ///
    /// # Errors
    ///
    /// If signature failed.
    pub fn sign(self, method: &Method, endpoint: &Url) -> Result<String, SignError<T>> {
        let signing_key = self.signing_key();
        let signature = self.signature(method, endpoint);
        let signature = T::digest(&signing_key, &signature).map_err(SignError::Digest)?;
        let signature = urlencoding::encode(&signature);

        let mut params = self.params();
        let _ = params.insert(OAUTH1_SIGNATURE, &signature);

        let mut params = params
            .into_iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>();

        params.sort();

        Ok(format!("OAuth {}", params.join(", ")))
    }
}
