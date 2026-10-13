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
#[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
pub mod fixture_native_restore;
pub mod ha;
mod ha_forward;
mod ha_forward_completion;
mod ha_observation;
pub mod ha_state;
pub mod http;
mod mount_listing_visibility;
pub mod namespace_custody;
mod namespace_record_graph;
pub mod outbound;
pub mod postgres_durable;
pub mod postgres_storage;
mod postgres_wire;
mod request_deadline;
mod request_metadata;
mod service;
mod snapshot_archive;
mod snapshot_file;
#[cfg(test)]
mod test_support;
mod tls_key_exchange;
mod valkey_wire;
mod workflow_runtime;
pub use service::ServiceRequest;
pub use service::{AuditConfig, AuditSocketConfig, AuditSyslogConfig};
#[cfg(target_os = "linux")]
pub use service::{
    OpenBaoWrapperCompletion, OpenBaoWrapperOperationPlan, WrapperCleanupState, WrapperOperation,
    WrapperReply,
};
pub use service::{OpenBaoWrapperConfig, OpenBaoWrapperLaunchPlan, OpenBaoWrapperTransport};
pub use service::{
    PluginAuthConfig, PluginDatabaseConfig, PluginExternalKmsConfig, PluginKmsConfig,
    PluginSecretConfig,
};
pub use service::{Response, Service};

#[cfg(test)]
mod cubbyhole_service_tests;

mod secret_serde;
pub(crate) mod state_record_root;
pub(crate) mod state_record_root_v6;
mod state_records;
pub mod v6_read_validation;
pub mod v6_record_resources;
pub mod v6_native_custody;
// Format validation only, no production V6 authority or route.
mod kv2_v6_record_codec;
// Format/graph read validation only: no Service writer, HA or migration authority.
mod kv2_v6_shard_validator;
pub mod kv2_v6_validation;

#[cfg(test)]
#[path = "kv2_v6_record_trial.rs"]
mod kv2_v6_record_trial;

mod login_metadata;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use service::SdkBackendConfig;

#[path = "server_config.rs"]
pub mod configuration;
