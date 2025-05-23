//! # OAuth 1.0a crate
//!
//! This crate provides an oauth 1.0a client implementation. It was firstly
//! designed to interact with the Clever-Cloud's API, but has been extended to
//! be more generic.

pub mod credentials;

pub mod execute;

pub mod client;

#[cfg(feature = "rest")]
pub mod rest;

#[cfg(feature = "sse")]
pub mod sse;
