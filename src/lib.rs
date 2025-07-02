//! # OAuth 1.0a crate
//!
//! This crate provides an oauth 1.0a client implementation.
//! It was firstly designed to interact with the Clever-Cloud's API,
//! but has been extended to be more generic.

pub use reqwest;
pub use url;

#[macro_use]
mod logging;

#[cfg(feature = "metrics")]
mod metrics;

pub mod signer;

pub mod credentials;

pub mod authorize;

#[cfg(feature = "execute")]
pub mod execute;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "rest")]
pub mod rest;

#[cfg(feature = "sse")]
pub mod sse;
