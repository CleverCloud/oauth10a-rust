use core::fmt;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use serde::{Deserialize, Serialize};

use super::Authorization;

// ERROR ///////////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {}

// CREDENTIALS /////////////////////////////////////////////////////////////////

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials<T = String> {
    #[serde(rename = "username")]
    username: T,
    #[serde(rename = "password")]
    password: T,
}

impl<T> fmt::Debug for Credentials<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicCredentials").finish_non_exhaustive()
    }
}

impl<T> Credentials<T> {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
    pub fn new(username: T, password: T) -> Self {
        Self { username, password }
    }
}

impl<T: AsRef<str>> Credentials<T> {
    pub fn as_ref(&self) -> Credentials<&str> {
        let Self { username, password } = self;
        Credentials::new(username.as_ref(), password.as_ref())
    }
}

impl<T: AsRef<str>> Authorization for Credentials<T> {
    type Error = AuthorizationError;

    fn authorization(&self, _request: &reqwest::Request) -> Result<Option<String>, Self::Error> {
        let Credentials { username, password } = self.as_ref();
        let token = BASE64_ENGINE.encode(format!("{username}:{password}"));
        Ok(Some(format!("Basic {token}")))
    }
}
