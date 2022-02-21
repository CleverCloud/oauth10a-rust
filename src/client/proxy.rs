//! # Proxy module
//!
//! This module provide proxy connector and helpers to set up a oauth1.0a client
//! with proxy capabilities

use std::{
    fmt::{self, Debug, Display, Formatter},
    marker::PhantomData,
    net::IpAddr,
    str::FromStr,
};

use cidr::IpCidr;
use headers::{authorization::InvalidBearerToken, Authorization};
use hyper::{
    client::{
        connect::{dns::GaiResolver, Connect},
        HttpConnector,
    },
    Uri,
};
use hyper_proxy::{Custom, Intercept, Proxy, ProxyConnector};
use hyper_tls::HttpsConnector;
#[cfg(feature = "logging")]
use log::{debug, info, log_enabled, trace, Level};
use url::Url;

// -----------------------------------------------------------------------------
// Error structure

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to build connector, {0}")]
    BuildConnector(std::io::Error),
    #[error("failed to build proxy uri, {0}")]
    BuildUri(hyper::http::Error),
    #[error("failed to build proxy, invalid bearer token, {0}")]
    InvalidBearerToken(InvalidBearerToken),
    #[error("failed to parse '{0}' as uri, ip address or cidr")]
    ParseDirect(String),
    #[error("failed to parse '{0}' as url, {1}")]
    ParseUrl(String, url::ParseError),
}

// -----------------------------------------------------------------------------
// Direct enum

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Direct {
    IpAddr(IpAddr),
    Uri(Uri),
    Cidr(IpCidr),
}

impl Display for Direct {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::IpAddr(addr) => write!(f, "{}", addr),
            Self::Cidr(cidr) => write!(f, "{}", cidr),
            Self::Uri(uri) => write!(f, "{}", uri),
        }
    }
}

impl From<IpAddr> for Direct {
    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn from(addr: IpAddr) -> Self {
        Self::IpAddr(addr)
    }
}

impl From<Uri> for Direct {
    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn from(uri: Uri) -> Self {
        Self::Uri(uri)
    }
}

impl From<IpCidr> for Direct {
    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn from(cidr: IpCidr) -> Self {
        Self::Cidr(cidr)
    }
}

impl FromStr for Direct {
    type Err = Error;

    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse() {
            Ok(uri) => {
                return Ok(Self::Uri(uri));
            }
            Err(err) =>
            {
                #[cfg(feature = "logging")]
                if log_enabled!(Level::Debug) {
                    debug!("failed to parse direct rule as uri, {}", err);
                }
            }
        }

        match s.parse() {
            Ok(uri) => {
                return Ok(Self::IpAddr(uri));
            }
            Err(err) =>
            {
                #[cfg(feature = "logging")]
                if log_enabled!(Level::Debug) {
                    debug!("failed to parse direct rule as ip address, {}", err);
                }
            }
        }

        match s.parse() {
            Ok(uri) => {
                return Ok(Self::Cidr(uri));
            }
            Err(err) =>
            {
                #[cfg(feature = "logging")]
                if log_enabled!(Level::Debug) {
                    debug!("failed to parse direct rule as cidr, {}", err);
                }
            }
        }

        Err(Error::ParseDirect(s.to_string()))
    }
}

// -----------------------------------------------------------------------------
// Environment structure

#[derive(Clone, Debug)]
pub struct Environment {}

impl Environment {
    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn http_proxy() -> Option<String> {
        if let Ok(http_proxy) = std::env::var("HTTP_PROXY") {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("found 'HTTP_PROXY' environment variable: {}", http_proxy);
            }

            Some(http_proxy)
        } else if let Ok(http_proxy) = std::env::var("http_proxy") {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("found 'http_proxy' environment variable: {}", http_proxy);
            }

            Some(http_proxy)
        } else {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("did not find any of 'HTTP_PROXY' or 'http_proxy' environment variable");
            }

            None
        }
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn https_proxy() -> Option<String> {
        if let Ok(https_proxy) = std::env::var("HTTPS_PROXY") {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("found 'HTTPS_PROXY' environment variable: {}", https_proxy);
            }

            Some(https_proxy)
        } else if let Ok(https_proxy) = std::env::var("https_proxy") {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("found 'https_proxy' environment variable: {}", https_proxy);
            }

            Some(https_proxy)
        } else {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("did not find any of 'HTTPS_PROXY' or 'https_proxy' environment variable");
            }

            None
        }
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn no_proxy() -> Option<String> {
        if let Ok(no_proxy) = std::env::var("NO_PROXY") {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("found 'NO_PROXY' environment variable: {}", no_proxy);
            }

            Some(no_proxy)
        } else if let Ok(no_proxy) = std::env::var("no_proxy") {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("found 'no_proxy' environment variable: {}", no_proxy);
            }

            Some(no_proxy)
        } else {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Trace) {
                trace!("did not find any of 'NO_PROXY' or 'no_proxy' environment variable");
            }

            None
        }
    }
}

// -----------------------------------------------------------------------------
// Authentication module

#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) enum Authentication {
    Basic(String, String),
    Bearer(String),
}

// -----------------------------------------------------------------------------
// ProxyBuilder structure

#[derive(Clone, Debug)]
pub struct ProxyBuilder {
    uri: Uri,
    authentication: Option<Authentication>,
    directs: Vec<Direct>,
}

impl ProxyBuilder {
    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn try_from_env() -> Result<Option<Proxy>, Error> {
        let url = if let Some(https_proxy) = Environment::https_proxy() {
            https_proxy
        } else if let Some(http_proxy) = Environment::http_proxy() {
            http_proxy
        } else {
            return Ok(None);
        };

        let directs = if let Some(no_proxy) = Environment::no_proxy() {
            no_proxy.split(',').map(ToString::to_string).collect()
        } else {
            vec![]
        };

        Self::try_from(url, directs).map(Some)
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn try_from(url: String, directs: Vec<String>) -> Result<Proxy, Error> {
        let url = Url::from_str(&url).map_err(|err| Error::ParseUrl(url, err))?;

        let mut p_and_q = url.path().to_string();
        if let Some(q) = url.query() {
            p_and_q += &format!("?{}", q);
        }

        let uri = Uri::builder()
            .scheme(url.scheme())
            .authority(
                url.domain()
                    .unwrap_or_else(|| {
                        url.host_str()
                            .expect("An url must contains a domain or at least a host")
                    })
                    .to_string()
                    + &url
                        .port()
                        .map(|p| format!(":{}", p))
                        .unwrap_or_else(String::new),
            )
            .path_and_query(p_and_q)
            .build()
            .map_err(Error::BuildUri)?;

        #[cfg(feature = "logging")]
        if log_enabled!(Level::Info) {
            info!("Create connector with proxy url '{}'", uri);
        }

        let mut builder = ProxyBuilder::new(uri.to_owned());
        for direct in directs {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Info) {
                info!(
                    "Add direct access rule to connector with proxy url '{}', {}",
                    uri, direct
                );
            }

            builder = builder.with_direct(Direct::from_str(&direct)?);
        }

        if let (username, Some(password)) = (url.username(), url.password()) {
            #[cfg(feature = "logging")]
            if log_enabled!(Level::Info) {
                info!(
                    "Add basic authentication to connector with proxy url '{}'",
                    uri
                );
            }

            builder = builder.with_basic(username.to_string(), password.to_string());
        }

        builder.build()
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn new(uri: Uri) -> Self {
        Self {
            uri,
            authentication: None,
            directs: vec![],
        }
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn with_basic(mut self, username: String, password: String) -> Self {
        self.authentication = Some(Authentication::Basic(username, password));
        self
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn with_bearer(mut self, token: String) -> Self {
        self.authentication = Some(Authentication::Bearer(token));
        self
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn with_direct(mut self, direct: Direct) -> Self {
        self.directs.push(direct);
        self
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn build(self) -> Result<Proxy, Error> {
        let directs = self.directs;
        let custom = Custom::from(
            move |scheme: Option<&str>, host: Option<&str>, port: Option<u16>| -> bool {
                for direct in &directs {
                    match direct {
                        Direct::Uri(uri) => match (uri.scheme_str(), uri.port_u16()) {
                            (Some(s), Some(p))
                                if Some(s) == scheme && Some(p) == port && uri.host() == host =>
                            {
                                return false;
                            }
                            (Some(s), None) if Some(s) == scheme && uri.host() == host => {
                                return false;
                            }
                            (None, Some(p)) if uri.host() == host && Some(p) == port => {
                                return false;
                            }
                            (None, None) if uri.host() == host => {
                                return false;
                            }
                            _ => {}
                        },
                        Direct::IpAddr(addr) => {
                            if Some(addr.to_string().as_str()) == host {
                                return false;
                            }
                        }
                        Direct::Cidr(cidr) => {
                            if let Some(Ok(addr)) = host.map(|h| h.parse()) {
                                if cidr.contains(&addr) {
                                    return false;
                                }
                            }
                        }
                    }
                }

                true
            },
        );

        let mut proxy = Proxy::new(Intercept::Custom(custom), self.uri);

        match self.authentication {
            Some(Authentication::Basic(username, password)) => {
                proxy.set_authorization(Authorization::basic(&username, &password));
            }
            Some(Authentication::Bearer(token)) => {
                proxy.set_authorization(
                    Authorization::bearer(&token).map_err(Error::InvalidBearerToken)?,
                );
            }
            None => {}
        }

        Ok(proxy)
    }
}

// -----------------------------------------------------------------------------
// ProxyConnectorBuilder structure

#[derive(Clone, Debug)]
pub struct ProxyConnectorBuilder<C>
where
    C: Connect + Clone + Debug + Send + Sync + 'static,
{
    proxies: Vec<Proxy>,
    phantom: PhantomData<C>,
}

impl<C> Default for ProxyConnectorBuilder<C>
where
    C: Connect + Clone + Debug + Send + Sync + 'static,
{
    #[cfg_attr(feature = "trace", tracing::instrument)]
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyConnectorBuilder<HttpsConnector<HttpConnector<GaiResolver>>> {
    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn try_from_env(
    ) -> Result<ProxyConnector<HttpsConnector<HttpConnector<GaiResolver>>>, Error> {
        let mut builder = Self::new();
        if let Some(proxy) = ProxyBuilder::try_from_env()? {
            builder = builder.with_proxy(proxy);
        }

        builder.build(HttpsConnector::new())
    }
}

impl<C> ProxyConnectorBuilder<C>
where
    C: Connect + Clone + Debug + Send + Sync + 'static,
{
    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn new() -> Self {
        Self {
            proxies: vec![],
            phantom: PhantomData::default(),
        }
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn with_proxy(mut self, proxy: Proxy) -> Self {
        self.proxies.push(proxy);
        self
    }

    #[cfg_attr(feature = "trace", tracing::instrument)]
    pub fn build(self, connector: C) -> Result<ProxyConnector<C>, Error> {
        let mut pc = ProxyConnector::new(connector).map_err(Error::BuildConnector)?;

        for proxy in self.proxies {
            pc.add_proxy(proxy);
        }

        Ok(pc)
    }
}
