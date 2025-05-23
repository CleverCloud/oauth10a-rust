use serde::{Deserialize, Serialize};

use super::{Authorization, basic, bearer, oauth1};

// ERROR ///////////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error(transparent)]
    Basic(#[from] basic::AuthorizationError),
    #[error(transparent)]
    Bearer(#[from] bearer::AuthorizationError),
    #[error(transparent)]
    OAuth1(#[from] oauth1::AuthorizationError),
}

// CREDENTIALS /////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Credentials<T = String> {
    Basic(basic::Credentials<T>),
    Bearer(bearer::Credentials<T>),
    OAuth1(oauth1::Credentials<T>),
}

impl Default for Credentials {
    fn default() -> Self {
        Self::OAuth1(oauth1::Credentials::default())
    }
}

impl<T> Credentials<T> {
    pub fn bearer(token: T) -> Self {
        Self::Bearer(bearer::Credentials::new(token))
    }

    pub fn basic(username: T, password: T) -> Self {
        Self::Basic(basic::Credentials::new(username, password))
    }

    pub fn oauth1(token: T, secret: T, consumer_key: T, consumer_secret: T) -> Self {
        Self::OAuth1(oauth1::Credentials::new(
            token,
            secret,
            consumer_key,
            consumer_secret,
        ))
    }
}

impl<T: AsRef<str>> Authorization for Credentials<T> {
    type Error = AuthorizationError;

    fn authorization(&self, request: &reqwest::Request) -> Result<Option<String>, Self::Error> {
        Ok(match self {
            Self::Basic(credentials) => credentials.authorization(request)?,
            Self::Bearer(credentials) => credentials.authorization(request)?,
            Self::OAuth1(credentials) => credentials.authorization(request)?,
        })
    }
}
