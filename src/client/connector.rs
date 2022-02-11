//! # Connector module
//!
//! This module provides connectors to easily configure the http client

pub use hyper::client::{
    connect::{dns::GaiResolver, Connect},
    HttpConnector,
};
pub use hyper_tls::HttpsConnector;
