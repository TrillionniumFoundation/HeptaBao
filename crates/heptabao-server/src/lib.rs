#![forbid(unsafe_code)]
//! A bounded, single-node TLS secrets service. All mutations, including login
//! and finite-use token consumption, commit encrypted state before any result
//! is delivered. Unsupported OpenBao operations remain explicit errors.
pub mod auth;
mod crypto;
pub mod engines;
pub mod http;
mod service;
pub use service::{Response, Service};
