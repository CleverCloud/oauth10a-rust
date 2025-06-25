//! Credentials.

use core::fmt;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use reqwest::{Request, header};

use crate::signer::{HmacSha512, SignError, Signer};

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

// CREDENTIALS /////////////////////////////////////////////////////////////////

/// Credentials used to authorize an HTTP request.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
#[cfg_attr(
    feature = "zeroize",
    zeroize(bound = "T: zeroize::Zeroize, U: zeroize::Zeroize")
)]
pub enum Credentials<T = Box<str>, U = T> {
    OAuth1 {
        #[cfg_attr(
            feature = "serde",
            serde(rename = "token", alias = "oauth-token", alias = "oauth_token")
        )]
        token: T,
        #[cfg_attr(
            feature = "serde",
            serde(rename = "secret", alias = "oauth-secret", alias = "oauth_secret")
        )]
        secret: T,
        #[cfg_attr(
            feature = "serde",
            serde(
                rename = "consumer-key",
                alias = "consumer_key",
                alias = "oauth-consumer-key",
                alias = "oauth_consumer_key",
                default
            )
        )]
        consumer_key: U,
        #[cfg_attr(
            feature = "serde",
            serde(
                rename = "consumer-secret",
                alias = "consumer_secret",
                alias = "oauth-consumer-secret",
                alias = "oauth_consumer_secret",
                default
            )
        )]
        consumer_secret: U,
    },
    Basic {
        #[cfg_attr(feature = "serde", serde(rename = "username"))]
        username: T,
        #[cfg_attr(feature = "serde", serde(rename = "password", default))]
        password: Option<T>,
    },
    Bearer {
        #[cfg_attr(feature = "serde", serde(rename = "token"))]
        token: T,
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

    pub const fn basic(username: T, password: Option<T>) -> Self {
        Self::Basic { username, password }
    }

    pub fn basic_from<P: Into<T>>(username: impl Into<T>, password: Option<P>) -> Self {
        Self::basic(username.into(), password.map(Into::into))
    }

    pub const fn oauth1(token: T, secret: T, consumer_key: U, consumer_secret: U) -> Self {
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
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn authorize(&self, request: &mut Request) -> Result<bool, AuthorizationError> {
        if request.headers().contains_key(header::AUTHORIZATION) {
            return Ok(false);
        }

        let authorization = match *self {
            Self::OAuth1 {
                token,
                secret,
                consumer_key,
                consumer_secret,
            } => Signer::<HmacSha512>::new(token, secret, consumer_key, consumer_secret)?
                .sign(request.method(), request.url())?,
            Self::Basic { username, password } => {
                let input = if let Some(password) = password {
                    format!("{username}:{password}")
                } else {
                    format!("{username}:")
                };
                format!("Basic {}", BASE64_ENGINE.encode(input.as_bytes()))
            }
            Self::Bearer { token } => format!("Bearer {token}"),
        };

        let mut value = authorization.parse::<header::HeaderValue>()?;
        value.set_sensitive(true);

        request
            .headers_mut()
            .try_append(header::AUTHORIZATION, value)?;

        trace!(request = ?request, "authorized request");

        Ok(true)
    }
}
