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

/// One shared bound for serialized application state across local chunked storage
/// and HA replication. Keeping one constant prevents a state from being locally
/// durable but impossible to replicate after HA is enabled.
pub(crate) const MAX_APPLICATION_STATE_BYTES: usize = 16 * 1024 * 1024;

mod auth;
mod crypto;
pub mod engines;
#[allow(clippy::expect_used, clippy::unwrap_used)]
pub mod federated_auth;
pub mod ha;
mod ha_forward;
pub mod ha_state;
pub mod http;
pub mod outbound;
mod postgres_wire;
mod service;
pub use service::ServiceRequest;
pub use service::{AuditConfig, AuditSocketConfig, AuditSyslogConfig};
pub use service::{PluginAuthConfig, PluginSecretConfig};
pub use service::{Response, Service};

#[cfg(test)]
mod cubbyhole_service_tests;
