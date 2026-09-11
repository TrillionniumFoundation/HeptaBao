#![forbid(unsafe_code)]
//! A bounded TLS secrets service. All mutations, including login and finite-use
//! token consumption, commit encrypted state before any result is delivered.
//! Unsupported OpenBao operations remain explicit errors.
//!
//! The raw authentication state and per-request capability are intentionally
//! crate-private. External callers must enter through [`Service`], which creates
//! the capability inside one request transaction and never returns it.
//!
//! ```compile_fail
//! use heptabao_server::auth::Principal;
//! ```
mod auth;
mod crypto;
pub mod engines;
#[allow(clippy::expect_used, clippy::unwrap_used)]
pub mod federated_auth;
pub mod ha_state;
pub mod http;
mod service;
pub use service::{Response, Service};
