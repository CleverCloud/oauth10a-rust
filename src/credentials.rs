//! Credentials.

use core::fmt;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use reqwest::{Method, Url, header};

use crate::signer::{HmacSha512, SignError, Signer};

// CREDENTIALS ERROR ///////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    #[error("missing consumer key")]
    MissingConsumerKey,
    #[error("missing consumer secret")]
    MissingConsumerSecret,
}

// AUTHORIZATION ERROR /////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error(transparent)]
    OAuth10a(#[from] SignError<HmacSha512>),
    #[error(transparent)]
    ParseHeaderValue(#[from] header::InvalidHeaderValue),
    #[error("too many headers")]
    TooManyHeader(#[from] header::MaxSizeReached),
}

// CREDENTIALS KIND ////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CredentialsKind {
    Bearer,
    Basic,
    OAuth1,
}

// CREDENTIALS BUILDER /////////////////////////////////////////////////////////

/// Utility type for handling credentials with optional consumer key and secret.
pub type CredentialsBuilder<T = Box<str>> = Credentials<T, Option<T>>;

impl<T> CredentialsBuilder<T> {
    /// Builds the credentials, filling missing consumer data with the provided default values.
    pub fn with_consumer(
        self,
        default_consumer_key: impl Into<T>,
        default_consumer_secret: impl Into<T>,
    ) -> Credentials<T> {
        match self {
            Self::Bearer { token } => Credentials::Bearer { token },
            Self::Basic { username, password } => Credentials::Basic { username, password },
            Self::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            } => Credentials::OAuth1 {
                token,
                secret,
                consumer_key: consumer_key.unwrap_or_else(|| default_consumer_key.into()),
                consumer_secret: consumer_secret.unwrap_or_else(|| default_consumer_secret.into()),
            },
        }
    }

    /// Builds the credentials.
    ///
    /// # Errors
    ///
    /// If one of `consumer_key` and `consumer_secret` is missing.
    pub fn build(self) -> Result<Credentials<T>, CredentialsError> {
        self.try_into()
    }
}

impl<T, U: Into<T>> From<Credentials<U>> for CredentialsBuilder<T> {
    fn from(value: Credentials<U>) -> Self {
        match value.into() {
            Credentials::Bearer { token } => Self::Bearer { token },
            Credentials::Basic { username, password } => Self::Basic { username, password },
            Credentials::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            } => Self::OAuth1 {
                token,
                secret,
                consumer_key: Some(consumer_key),
                consumer_secret: Some(consumer_secret),
            },
        }
    }
}

impl<T, U: Into<T>> TryFrom<CredentialsBuilder<U>> for Credentials<T> {
    type Error = CredentialsError;

    fn try_from(value: CredentialsBuilder<U>) -> Result<Self, Self::Error> {
        Ok(match value {
            Credentials::Bearer { token } => Credentials::Bearer {
                token: token.into(),
            },
            Credentials::Basic { username, password } => Credentials::Basic {
                username: username.into(),
                password: password.map(Into::into),
            },
            Credentials::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            } => Credentials::OAuth1 {
                token: token.into(),
                secret: secret.into(),
                consumer_key: consumer_key
                    .ok_or(CredentialsError::MissingConsumerKey)?
                    .into(),
                consumer_secret: consumer_secret
                    .ok_or(CredentialsError::MissingConsumerSecret)?
                    .into(),
            },
        })
    }
}

// CREDENTIALS /////////////////////////////////////////////////////////////////

/// Credentials used to authorize an HTTP request.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
#[cfg_attr(
    feature = "zeroize",
    zeroize(bound = "T: zeroize::Zeroize, U: zeroize::Zeroize")
)]
pub enum Credentials<T = Box<str>, U = T> {
    Bearer {
        #[cfg_attr(feature = "serde", serde(rename = "token"))]
        token: T,
    },
    Basic {
        #[cfg_attr(feature = "serde", serde(rename = "username"))]
        username: T,
        #[cfg_attr(feature = "serde", serde(rename = "password"))]
        password: Option<T>,
    },
    OAuth1 {
        #[cfg_attr(feature = "serde", serde(rename = "token"))]
        token: T,
        #[cfg_attr(feature = "serde", serde(rename = "secret"))]
        secret: T,
        #[cfg_attr(feature = "serde", serde(rename = "consumer-key"))]
        consumer_key: U,
        #[cfg_attr(feature = "serde", serde(rename = "consumer-secret"))]
        consumer_secret: U,
    },
}

impl<T, U> fmt::Debug for Credentials<T, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.kind(), f)
    }
}

impl<T, U> Credentials<T, U> {
    pub const fn kind(&self) -> CredentialsKind {
        match self {
            Self::Bearer { .. } => CredentialsKind::Bearer,
            Self::Basic { .. } => CredentialsKind::Basic,
            Self::OAuth1 { .. } => CredentialsKind::OAuth1,
        }
    }

    pub const fn bearer(token: T) -> Self {
        Self::Bearer { token }
    }

    pub fn bearer_from(token: impl Into<T>) -> Self {
        Self::bearer(token.into())
    }

    pub fn basic(username: T, password: Option<T>) -> Self {
        Self::Basic { username, password }
    }

    pub fn basic_from<P: Into<T>>(username: impl Into<T>, password: Option<P>) -> Self {
        Self::basic(username.into(), password.map(Into::into))
    }

    pub fn oauth1(token: T, secret: T, consumer_key: U, consumer_secret: U) -> Self {
        Self::OAuth1 {
            token,
            secret,
            consumer_key,
            consumer_secret,
        }
    }

    pub fn oauth1_from(
        token: impl Into<T>,
        secret: impl Into<T>,
        consumer_key: impl Into<U>,
        consumer_secret: impl Into<U>,
    ) -> Self {
        Self::oauth1(
            token.into(),
            secret.into(),
            consumer_key.into(),
            consumer_secret.into(),
        )
    }
}

impl<T> Credentials<T> {
    pub fn from<X>(credentials: Credentials<X>) -> Self
    where
        T: From<X>,
    {
        credentials.into()
    }

    pub fn into<X>(self) -> Credentials<X>
    where
        T: Into<X>,
    {
        match self {
            Self::Bearer { token } => Credentials::Bearer {
                token: token.into(),
            },
            Self::Basic { username, password } => Credentials::Basic {
                username: username.into(),
                password: password.map(Into::into),
            },
            Self::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            } => Credentials::OAuth1 {
                token: token.into(),
                secret: secret.into(),
                consumer_key: consumer_key.into(),
                consumer_secret: consumer_secret.into(),
            },
        }
    }
}

impl Credentials {
    pub const fn as_ref(&self) -> Credentials<&str> {
        match self {
            Self::Bearer { token } => Credentials::Bearer { token },
            Self::Basic { username, password } => Credentials::Basic {
                username,
                password: match password {
                    None => None,
                    Some(password) => Some(password),
                },
            },
            Self::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            } => Credentials::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            },
        }
    }
}

impl Credentials<&str> {
    /// Returns the value for the `Authorization` header.
    ///
    /// Note: currently, only `HMAC-SHA512` signature method is supported.
    ///
    /// # Errors
    ///
    /// Upon failure to produce the header value.
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn authorization(
        self,
        method: &Method,
        endpoint: &Url,
    ) -> Result<String, AuthorizationError> {
        Ok(match self {
            Self::Bearer { token } => format!("Bearer {token}"),
            Self::Basic { username, password } => {
                let input = if let Some(password) = password {
                    format!("{username}:{password}")
                } else {
                    format!("{username}:")
                };
                format!("Basic {}", BASE64_ENGINE.encode(input.as_bytes()))
            }
            Self::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            } => Signer::<HmacSha512>::new(token, secret, consumer_key, consumer_secret)?
                .sign(method, endpoint)?,
        })
    }

    /// Appends an `Authorization` header to the `request`, unless it is already set.
    ///
    /// Returns `true` if the `Authorization` header was inserted.
    ///
    /// # Errors
    ///
    /// Upon failure to produce the header value.
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn authorize(&self, request: &mut reqwest::Request) -> Result<bool, AuthorizationError> {
        if !request.headers().contains_key(header::AUTHORIZATION) {
            let authorization = self.authorization(request.method(), request.url())?;

            let mut value = authorization.parse::<header::HeaderValue>()?;
            value.set_sensitive(true);

            request
                .headers_mut()
                .try_append(header::AUTHORIZATION, value)?;

            #[cfg(feature = "logging")]
            trace!(request = ?request, "authorized request");

            return Ok(true);
        }
        Ok(false)
    }
}
