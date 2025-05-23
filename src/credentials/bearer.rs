use core::fmt;

use serde::{Deserialize, Serialize};

use super::Authorization;

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials<T = String> {
    #[serde(rename = "token")]
    token: T,
}

impl<T> Credentials<T> {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
    pub fn new(token: T) -> Self {
        Self { token }
    }
}

impl<T: AsRef<str>> Credentials<T> {
    pub fn as_ref(&self) -> Credentials<&str> {
        Credentials::new(self.token.as_ref())
    }
}

impl<T> fmt::Debug for Credentials<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerCredentials").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {}

impl<T: AsRef<str>> Authorization for Credentials<T> {
    type Error = AuthorizationError;

    fn authorization(&self, _request: &reqwest::Request) -> Result<Option<String>, Self::Error> {
        Ok(Some(format!("Bearer {}", self.token.as_ref())))
    }
}
