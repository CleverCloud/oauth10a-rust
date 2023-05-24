//! # Connector module
//!
//! This module provides connectors to easily configure the http client

pub use hyper::client::{
    connect::{dns::GaiResolver, Connect},
    HttpConnector,
};
#[cfg(feature = "proxy")]
pub use hyper_proxy::ProxyConnector;
pub use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
