//! Bounded HTTP/1.1 and multiplexed HTTP/2 over verified Rustls TLS.
//! Both transports share logical request admission and fixed request deadlines.
use crate::request_deadline::{LockWaitError, RequestDeadlineScope, lock_until};
use crate::{
    Response, Service, ServiceRequest, crypto,
    ha::HaProcess,
    service::{RequestExecution, WireRejection},
};
use rustls::pki_types::CertificateRevocationListDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, StreamOwned};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "http_api_alpn_tests.rs"]
mod api_alpn_tests;
#[path = "http_h2.rs"]
mod h2_transport;
#[path = "http_logical.rs"]
mod logical;
#[path = "http_sanitized_config.rs"]
mod sanitized_config;
use zeroize::{Zeroize, Zeroizing};

#[path = "http_approle_form.rs"]
mod approle_form;
#[cfg(test)]
#[path = "http_approle_mount_tests.rs"]
mod approle_mount_tests;
#[path = "http_help.rs"]
pub(crate) mod help;
#[path = "http_ocsp.rs"]
pub(crate) mod ocsp;
#[path = "http_pki_role_fields.rs"]
pub(crate) mod pki_role_fields;
#[path = "http_snapshot.rs"]
mod snapshot;
#[path = "http_token_fields.rs"]
pub(crate) mod token_fields;
#[path = "http_ui.rs"]
mod ui;

#[path = "http_consistency.rs"]
pub(crate) mod consistency;
#[path = "http_leader.rs"]
mod leader;
#[cfg(target_os = "linux")]
#[path = "http_local_control.rs"]
mod local_control;
#[cfg(target_os = "linux")]
pub use local_control::LocalControlConfig;

const MAX_HEADERS: usize = 16 * 1024;
// Bounded JSON transport for OpenBao 2.7.1 KV2 up to 1536 KiB.
// This is ingress-only: V5 owner, value, and graph limits are unchanged.
// Calls exceeding this bound never enter Service or commit state.
pub(crate) const MAX_BODY: usize = 2 * 1024 * 1024;
// OpenBao 2.7.1 accepts the 2560 KiB KV2 payload rejected by our 2 MiB
// JSON front door. Only syntactically unambiguous KV2 data writes get a
// narrowly larger budget. This is NOT a new state capacity, role, or writer.
pub(crate) const MAX_KV2_JSON_WRITE_BODY: usize = 3 * 1024 * 1024;

// RFC 9110 Section 8.3.1 defines type and subtype tokens as case-insensitive.
// Only the media *type* is compared here: retain the existing parameter
// framing and all independent route, method, ACL, and size restrictions.
fn media_type_is(media: Option<&str>, expected: &str) -> bool {
    media
        .and_then(|value| value.split(';').next())
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

// Both HTTP/1.1 and HTTP/2 use precisely this predicate before accepting
// body bytes. No TLS, authentication, namespaces or method semantics change.
// It is an ingress grammar, not a grant that a path is actually a KV2 mount:
// the Service still independently verifies mount ownership and ACLs.
pub(crate) fn json_ingress_body_limit(
    method: &str,
    route: &str,
    content_type: Option<&str>,
) -> usize {
    if !matches!(method, "POST" | "PUT")
        || !media_type_is(content_type, "application/json")
        || route
            .bytes()
            .any(|byte| matches!(byte, b'%' | b'?' | b'#' | b'\\'))
        || route.contains("//")
    {
        return MAX_BODY;
    }
    // A KV2 mount may have several canonical path components. This syntactic
    // allowance does not decide mount ownership or grant write authority:
    // Service must still independently resolve the live mount and ACL.
    let Some((mount, item)) = route.rsplit_once("/data/") else {
        return MAX_BODY;
    };
    let top = mount.split('/').next().unwrap_or_default();
    if mount.is_empty()
        || mount.len() > 512
        || matches!(
            top,
            "sys" | "auth" | "identity" | "cubbyhole" | "pki" | "transit" | "database" | "ssh"
        )
        || mount.split('/').any(|segment| {
            segment.is_empty()
                || segment.len() > 128
                || matches!(segment, "." | "..")
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        || item.is_empty()
        || item.len() > 4096
        || item
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return MAX_BODY;
    }
    MAX_KV2_JSON_WRITE_BODY
}

const MAX_SNAPSHOT_BODY: usize = 32 * 1024 * 1024;
const MAX_RESPONSE: usize = 32 * 1024 * 1024;

fn default_disable_unauthed_rekey_endpoints() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Serve a deployment-owned build of the official UI. The complete asset
    /// table is pinned and loaded before opening the listener.
    #[serde(default)]
    pub ui: bool,
    #[serde(default)]
    pub ui_assets_dir: Option<PathBuf>,
    #[serde(default)]
    pub ui_assets_manifest: Option<PathBuf>,
    #[serde(default)]
    pub ui_assets_manifest_sha256: Option<String>,
    /// Listener-only opt-in for deprecated unauthenticated recovery rekey.
    /// Root-key legacy rekey still requires its separate root-key consumer.
    #[serde(default = "default_disable_unauthed_rekey_endpoints")]
    pub disable_unauthed_rekey_endpoints: bool,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Deployment-owned storage selector, checked before filesystem or HA effects.
    #[serde(default)]
    pub storage: Option<crate::configuration::StorageConfig>,
    pub audit_file: PathBuf,
    #[serde(default)]
    pub audit: crate::AuditConfig,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
    /// OpenBao 2.7 named groups; absent, null and empty use provider defaults.
    #[serde(default)]
    pub tls_key_exchange_preferences: Option<Vec<String>>,
    #[serde(default)]
    pub tls_min_version: Option<String>,
    #[serde(default)]
    pub tls_max_version: Option<String>,
    /// Deployment-owned client trust roots. A configured bundle requires a
    /// valid client certificate unless optional client authentication is set.
    #[serde(default)]
    pub tls_client_ca_file: Option<PathBuf>,
    /// Allow connections without a certificate while still verifying every
    /// presented chain. Requires explicit trust roots; defaults to mandatory.
    #[serde(default)]
    pub tls_client_auth_optional: bool,
    /// Optional CRL bundle applied to the client certificate chain. A CRL is
    /// never accepted without an explicit client CA bundle.
    #[serde(default)]
    pub tls_client_crl_file: Option<PathBuf>,
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub consistency_max_index_wait: Option<String>,
    #[serde(default)]
    pub consistency_fallback_behavior: Option<String>,
    #[serde(default)]
    pub consistency_missing_header_forward: bool,
    #[serde(default = "default_rate_limit_per_second")]
    pub rate_limit_per_second: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
    #[serde(default = "default_rate_limit_entries")]
    pub rate_limit_entries: usize,
    /// Zero explicitly disables idle maintenance. Active request checks remain mandatory.
    #[serde(default = "default_lifecycle_interval")]
    pub lifecycle_interval_seconds: u64,
    /// Deployment-owned egress allowlist; API configuration cannot widen it.
    #[serde(default)]
    pub outbound_endpoints: Vec<crate::outbound::EndpointConfig>,
    /// Optional mandatory HTTPS audit collector. The URL must resolve only
    /// through `outbound_endpoints`; API requests cannot replace it.
    #[serde(default)]
    pub audit_http_url: Option<String>,
    /// Optional deployment-owned TCP socket audit collector. The mandatory
    /// authenticated file sink remains enabled even if this collector fails.
    #[serde(default)]
    pub audit_socket: Option<crate::AuditSocketConfig>,
    /// Optional deployment-owned local Unix syslog audit device.
    #[serde(default)]
    pub audit_syslog: Option<crate::AuditSyslogConfig>,
    /// Optional deployment-owned PostgreSQL durable backend. The password is
    /// process configuration and is never accepted from an HTTP request.
    #[serde(default)]
    pub postgres_durable: Option<crate::postgres_storage::PgStorageConfig>,
    #[serde(default)]
    pub plugin_auth: Vec<crate::PluginAuthConfig>,
    #[serde(default)]
    pub plugin_database: Vec<crate::PluginDatabaseConfig>,
    #[serde(default)]
    pub plugin_kms: Vec<crate::PluginKmsConfig>,
    #[serde(default)]
    pub external_kms: Vec<crate::PluginExternalKmsConfig>,
    #[serde(default)]
    pub plugin_secrets: Vec<crate::PluginSecretConfig>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[serde(default)]
    pub openbao_sdk: Option<crate::SdkBackendConfig>,
    /// Optional, deployment-owned SDK Wrapper runtime with per-launch AutoMTLS.
    /// This does not select a KMS/barrier consumer or the HBP1 transport.
    #[serde(default)]
    pub openbao_wrapper: Option<crate::OpenBaoWrapperConfig>,
    /// Explicit local deployment authority. No HTTP route creates this control.
    #[cfg(target_os = "linux")]
    #[serde(default)]
    pub local_control: Option<LocalControlConfig>,
    /// Qualification-only lower bound seam. Ordinary binaries reject this
    /// field because the feature is absent; feature builds may only reduce the
    /// canonical 16 MiB opaque-owner ceiling, never raise it.
    #[cfg(feature = "fixture-capacity-limit")]
    #[serde(default)]
    pub fixture_opaque_owner_limit_bytes: Option<usize>,
}
fn default_lifecycle_interval() -> u64 {
    5
}
fn default_connections() -> usize {
    16
}
fn default_timeout() -> u64 {
    15
}
fn default_rate_limit_per_second() -> u32 {
    200
}
fn default_rate_limit_burst() -> u32 {
    400
}
fn default_rate_limit_entries() -> usize {
    4_096
}

const TOKEN_SCALE: u128 = 1_000_000_000;
const RATE_BUCKET_IDLE_NANOS: u128 = 60 * TOKEN_SCALE;

#[derive(Clone, Copy)]
struct RateBucket {
    tokens: u128,
    last_nanos: u128,
}

struct RateLimiter {
    rate_per_second: u128,
    burst_tokens: u128,
    max_entries: usize,
    started: Instant,
    buckets: BTreeMap<IpAddr, RateBucket>,
}

impl RateLimiter {
    fn new(rate_per_second: u32, burst: u32, max_entries: usize) -> Result<Self, String> {
        if rate_per_second == 0
            || rate_per_second > 100_000
            || burst == 0
            || burst > 1_000_000
            || !(64..=65_536).contains(&max_entries)
        {
            return Err("invalid bounded rate-limit policy".into());
        }
        Ok(Self {
            rate_per_second: u128::from(rate_per_second),
            burst_tokens: u128::from(burst) * TOKEN_SCALE,
            max_entries,
            started: Instant::now(),
            buckets: BTreeMap::new(),
        })
    }

    fn allow(&mut self, peer: IpAddr) -> bool {
        self.allow_at(peer, self.started.elapsed().as_nanos())
    }

    fn allow_at(&mut self, peer: IpAddr, now_nanos: u128) -> bool {
        if !self.buckets.contains_key(&peer) && self.buckets.len() >= self.max_entries {
            self.buckets.retain(|_, bucket| {
                now_nanos.saturating_sub(bucket.last_nanos) < RATE_BUCKET_IDLE_NANOS
            });
            if self.buckets.len() >= self.max_entries {
                return false;
            }
        }
        let bucket = self.buckets.entry(peer).or_insert(RateBucket {
            tokens: self.burst_tokens,
            last_nanos: now_nanos,
        });
        let elapsed = now_nanos.saturating_sub(bucket.last_nanos);
        let refill = elapsed.saturating_mul(self.rate_per_second);
        bucket.tokens = bucket.tokens.saturating_add(refill).min(self.burst_tokens);
        bucket.last_nanos = now_nanos;
        if bucket.tokens < TOKEN_SCALE {
            return false;
        }
        bucket.tokens -= TOKEN_SCALE;
        true
    }
}

pub fn serve(config: Config) -> Result<(), String> {
    serve_inner(
        config,
        None,
        #[cfg(feature = "fixture-native-v6-service")]
        false,
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        None,
    )
}

pub fn serve_with_ha(config: Config, ha: Arc<Mutex<HaProcess>>) -> Result<(), String> {
    serve_inner(
        config,
        Some(ha),
        #[cfg(feature = "fixture-native-v6-service")]
        false,
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        None,
    )
}

#[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
pub fn serve_with_ha_fixture(
    config: Config,
    ha: Arc<Mutex<HaProcess>>,
    fixture: crate::fixture_native_restore::NativeRestoreFaultGate,
) -> Result<(), String> {
    serve_inner(
        config,
        Some(ha),
        #[cfg(feature = "fixture-native-v6-service")]
        false,
        Some(fixture),
    )
}

#[cfg(feature = "fixture-native-v6-service")]
pub fn serve_native_v6_candidate(config: Config) -> Result<(), String> {
    serve_inner(
        config,
        None,
        true,
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        None,
    )
}

fn configure_api_alpn(tls: &mut ServerConfig) {
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
}

fn serve_inner(
    config: Config,
    ha: Option<Arc<Mutex<HaProcess>>>,
    #[cfg(feature = "fixture-native-v6-service")] native_candidate: bool,
    #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))] fixture: Option<
        crate::fixture_native_restore::NativeRestoreFaultGate,
    >,
) -> Result<(), String> {
    crate::configuration::validate_storage_runtime(&config, ha.is_some())?;
    // Only an allowlisted projection survives the ownership transfer below.
    let sanitized_configuration = sanitized_config::project(&config);
    if let Some(ha) = ha.as_ref() {
        let consumer = ha.lock().map_err(|_| "HA process lock is unavailable")?;
        crate::configuration::validate_storage_running(&config, &consumer)?;
    }
    if !(1..=128).contains(&config.max_connections) || !(1..=60).contains(&config.timeout_seconds) {
        return Err("invalid bounded connection policy".into());
    }
    if config.lifecycle_interval_seconds > 60 {
        return Err("lifecycle interval must be zero or 1..=60 seconds".into());
    }
    if config.tls_client_auth_optional && config.tls_client_ca_file.is_none() {
        return Err("optional TLS client authentication requires a client CA bundle".into());
    }
    #[cfg(target_os = "linux")]
    let mut local_control = if let Some(control) = config.local_control.as_ref() {
        if ha.is_some()
            || config.postgres_durable.is_some()
            || !config.plugin_auth.is_empty()
            || !config.plugin_database.is_empty()
            || !config.plugin_kms.is_empty()
            || !config.external_kms.is_empty()
            || !config.plugin_secrets.is_empty()
            || !config
                .openbao_wrapper
                .as_ref()
                .is_some_and(|wrapper| wrapper.seal_barrier)
        {
            return Err("local control requires the standalone Wrapper seal profile".into());
        }
        Some(local_control::Control::open(control)?)
    } else {
        None
    };
    let ui_assets = ui::Assets::configured(&config)?;
    let consistency_settings = consistency::Settings::checked(
        config.consistency_max_index_wait.as_deref(),
        config.consistency_fallback_behavior.as_deref(),
        config.consistency_missing_header_forward,
    )?;
    let limiter = Arc::new(Mutex::new(RateLimiter::new(
        config.rate_limit_per_second,
        config.rate_limit_burst,
        config.rate_limit_entries,
    )?));
    if !config.tls_cert_file.is_absolute() || !config.tls_key_file.is_absolute() {
        return Err("TLS paths must be absolute".into());
    }
    if config.tls_cert_file.starts_with(&config.data_dir)
        || config.tls_key_file.starts_with(&config.data_dir)
    {
        return Err("TLS material must live outside the data directory".into());
    }
    let certificates = bounded_file(&config.tls_cert_file, false)?;
    let mut cert_reader = BufReader::new(certificates.as_slice());
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid TLS certificate chain")?;
    if certificates.is_empty() {
        return Err("TLS certificate chain is empty".into());
    }
    let key_bytes = bounded_file(&config.tls_key_file, true)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .map_err(|_| "invalid TLS key")?
        .ok_or("missing TLS private key")?;
    let provider = Arc::new(crate::tls_key_exchange::provider(
        config.tls_key_exchange_preferences.as_deref(),
    )?);
    let versions = crate::tls_key_exchange::protocol_versions(
        config.tls_min_version.as_deref(),
        config.tls_max_version.as_deref(),
    )?;
    if config.tls_client_crl_file.is_some() && config.tls_client_ca_file.is_none() {
        return Err("TLS client CRL requires a client CA bundle".into());
    }
    let verifier = match config.tls_client_ca_file.as_ref() {
        Some(path) => Some(load_client_verifier(
            path,
            config.tls_client_crl_file.as_ref(),
            config.tls_client_auth_optional,
            &config.data_dir,
            Arc::clone(&provider),
        )?),
        None => None,
    };
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|_| "TLS versions unavailable")?;
    let mut tls = match verifier {
        Some(verifier) => builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
            .map_err(|_| "TLS key and certificate do not match")?,
        None => builder
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|_| "TLS key and certificate do not match")?,
    };
    configure_api_alpn(&mut tls);
    let tls = Arc::new(tls);
    #[cfg(feature = "fixture-capacity-limit")]
    let fixture_opaque_owner_limit_bytes = config.fixture_opaque_owner_limit_bytes;
    let ha_enabled = ha.is_some();
    let forwarding_ha = ha.clone();
    let service = Arc::new(Mutex::new(
        match ha {
            Some(ha) => Service::new_with_ha_audit_config(
                config.data_dir,
                &config.audit_file,
                ha,
                config.audit,
            ),
            None => {
                Service::new_with_audit_config(config.data_dir, &config.audit_file, config.audit)
            }
        }
        .map_err(str::to_owned)?,
    ));
    let wrapper_launch = {
        let mut service = service.lock().map_err(|_| "service lock unavailable")?;
        service.install_recovery_listener_policy(config.disable_unauthed_rekey_endpoints)?;
        service.install_sanitized_configuration(sanitized_configuration)?;
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        {
            service.native_restore_fault = fixture;
        }
        #[cfg(feature = "fixture-capacity-limit")]
        service.install_fixture_opaque_owner_limit(fixture_opaque_owner_limit_bytes)?;
        service.install_outbound_endpoints(config.outbound_endpoints)?;
        service.install_auth_plugins(config.plugin_auth)?;
        service.install_database_plugins(config.plugin_database)?;
        service.install_kms_plugins(config.plugin_kms)?;
        service.install_external_kms_plugins(config.external_kms)?;
        service.install_secret_plugins(config.plugin_secrets)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        service.install_sdk_backend(config.openbao_sdk)?;
        service.install_audit_http_endpoint(config.audit_http_url)?;
        service.install_audit_socket(config.audit_socket)?;
        service.install_audit_syslog(config.audit_syslog)?;
        if let Some(postgres) = config.postgres_durable {
            service.install_postgres_durable_storage(postgres)?;
        }
        service.install_openbao_wrapper(config.openbao_wrapper)?
    };
    #[cfg(feature = "fixture-native-v6-service")]
    if native_candidate {
        service
            .lock()
            .map_err(|_| "service lock unavailable")?
            .configure_native_v6_candidate()?;
    }

    // Startup process work is outside the Service writer; no API can install or
    // reattach an endpoint. Failed admission aborts listener startup explicitly.
    let startup: Result<(), String> = (|| {
        if let Some(plan) = wrapper_launch {
            plan.execute().map_err(|error| error.to_string())?;
        }
        #[cfg(target_os = "linux")]
        {
            let activation = service
                .lock()
                .map_err(|_| "service lock unavailable")?
                .prepare_wrapper_barrier_activation()?;
            if let Some(plan) = activation {
                let completion = plan.execute();
                service
                    .lock()
                    .map_err(|_| "service lock unavailable")?
                    .finish_wrapper_barrier_activation(completion)?;
            }
        }
        Ok(())
    })();
    #[cfg(target_os = "linux")]
    if let Err(error) = startup {
        #[cfg(target_os = "linux")]
        if let Some(control) = local_control.as_ref() {
            return control.shutdown(&service, &AtomicUsize::new(0), Some(error), || {});
        }
        return Err(error);
    }
    #[cfg(not(target_os = "linux"))]
    startup?;
    if let Some(ha) = forwarding_ha {
        let forward_timeout = ha
            .lock()
            .map_err(|_| "HA process lock is unavailable".to_owned())?
            .forward_timeout()
            .min(Duration::from_secs(config.timeout_seconds));
        let weak_service = Arc::downgrade(&service);
        let handler: crate::ha::ForwardHandler = Arc::new(move |mut request| {
            let Some(service) = weak_service.upgrade() else {
                return Response::error(503, "HA forward service is unavailable");
            };
            let response = execute_service_request(
                &service,
                ServiceRequest {
                    method: &request.method,
                    path: &request.path,
                    namespace: &request.namespace,
                    token: &request.token,
                    body: std::mem::take(&mut request.body),
                    wrap_ttl_seconds: request.wrap_ttl_seconds,
                    origin_peer: request.origin_peer,
                    client_certificates: request.client_certificates.take(),
                },
                crate::ha_forward_completion::CompletionScope::deadline().map_or_else(
                    || Instant::now() + forward_timeout,
                    |original| original.min(Instant::now() + forward_timeout),
                ),
                true,
            );
            request.token.zeroize();
            response
        });
        ha.lock()
            .map_err(|_| "HA process lock is unavailable".to_owned())?
            .register_forward_handler(handler)?;
    }
    let listener = match TcpListener::bind(config.listen) {
        Ok(value) => value,
        Err(_) => {
            #[cfg(target_os = "linux")]
            if let Some(control) = local_control.as_ref() {
                return control.shutdown(
                    &service,
                    &AtomicUsize::new(0),
                    Some("cannot bind configured listener".into()),
                    || {},
                );
            }
            return Err("cannot bind configured listener".into());
        }
    };
    let _native_remount = match crate::service::start_native_remount_worker(&service) {
        Ok(worker) => worker,
        Err(error) => {
            #[cfg(target_os = "linux")]
            if let Some(control) = local_control.as_ref() {
                drop(listener);
                return control.shutdown(&service, &AtomicUsize::new(0), Some(error), || {});
            }
            return Err(error);
        }
    };
    let _namespace_deletion = match crate::service::start_namespace_deletion_worker(&service) {
        Ok(worker) => worker,
        Err(error) => {
            #[cfg(target_os = "linux")]
            if let Some(control) = local_control.as_ref() {
                drop(listener);
                return control.shutdown(&service, &AtomicUsize::new(0), Some(error), || {});
            }
            return Err(error);
        }
    };
    // AppRole's once-per-minute cleanup is independent of generic lifecycle settings.
    let _approle_tidy = match crate::service::start_approle_tidy_worker(&service) {
        Ok(worker) => worker,
        Err(error) => {
            #[cfg(target_os = "linux")]
            if let Some(control) = local_control.as_ref() {
                drop(listener);
                return control.shutdown(&service, &AtomicUsize::new(0), Some(error), || {});
            }
            return Err(error);
        }
    };
    let _lifecycle = match crate::service::start_lifecycle_worker(
        &service,
        Duration::from_secs(config.lifecycle_interval_seconds),
    ) {
        Ok(value) => value,
        Err(error) => {
            #[cfg(target_os = "linux")]
            if let Some(control) = local_control.as_ref() {
                drop(listener);
                return control.shutdown(&service, &AtomicUsize::new(0), Some(error), || {
                    drop(_namespace_deletion);
                });
            }
            return Err(error);
        }
    };
    let _mfa_janitor = match crate::service::start_mfa_janitor_worker(&service) {
        Ok(value) => value,
        Err(error) => {
            #[cfg(target_os = "linux")]
            if let Some(control) = local_control.as_ref() {
                drop(listener);
                return control.shutdown(&service, &AtomicUsize::new(0), Some(error), || {
                    drop(_namespace_deletion);
                    drop(_lifecycle);
                });
            }
            return Err(error);
        }
    };
    let _ha_activation = match crate::service::start_ha_activation_worker_with_budget(
        &service,
        Duration::from_secs(config.timeout_seconds),
    ) {
        Ok(value) => value,
        Err(error) => {
            #[cfg(target_os = "linux")]
            if let Some(control) = local_control.as_ref() {
                drop(listener);
                return control.shutdown(&service, &AtomicUsize::new(0), Some(error), || {
                    drop(_namespace_deletion);
                    drop(_lifecycle);
                    drop(_mfa_janitor);
                });
            }
            return Err(error);
        }
    };
    let connections = Arc::new(AtomicUsize::new(0));
    eprintln!(
        "HeptaBao {} TLS listener ready at {}",
        if ha_enabled { "HA" } else { "single-node" },
        config.listen
    );
    #[cfg(target_os = "linux")]
    if let Some(control) = local_control.as_ref() {
        let admission = listener
            .set_nonblocking(true)
            .map_err(|_| "cannot bound private control accept polling".to_owned())
            .and_then(|()| control.ready(&service));
        if let Err(error) = admission {
            drop(listener);
            return control.shutdown(&service, &connections, Some(error), || {
                drop(_namespace_deletion);
                drop(_lifecycle);
                drop(_mfa_janitor);
                drop(_ha_activation);
            });
        }
    }
    loop {
        #[cfg(target_os = "linux")]
        if let Some(control) = local_control.as_mut()
            && control.poll(&service)
        {
            drop(listener);
            return control.shutdown(&service, &connections, None, || {
                drop(_namespace_deletion);
                drop(_lifecycle);
                drop(_mfa_janitor);
                drop(_ha_activation);
            });
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            Err(_) => {
                #[cfg(target_os = "linux")]
                if let Some(control) = local_control.as_ref() {
                    drop(listener);
                    return control.shutdown(
                        &service,
                        &connections,
                        Some("listener accept failed".into()),
                        || {
                            drop(_namespace_deletion);
                            drop(_lifecycle);
                            drop(_mfa_janitor);
                            drop(_ha_activation);
                        },
                    );
                }
                return Err("listener accept failed".into());
            }
        };
        let timeout = Duration::from_secs(config.timeout_seconds);
        // One budget from accept, including worker scheduling, TLS/body reads,
        // service lock waiting, forwarding, provider work, and response writes.
        let deadline = Instant::now() + timeout;
        if connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value < config.max_connections).then_some(value + 1)
            })
            .is_err()
        {
            drop(stream);
            continue;
        }
        let guard = ConnectionGuard(Arc::clone(&connections));
        let peer = match stream.peer_addr() {
            Ok(peer) => peer.ip(),
            Err(_) => {
                drop(guard);
                drop(stream);
                #[cfg(target_os = "linux")]
                if let Some(control) = local_control.as_ref() {
                    drop(listener);
                    return control.shutdown(
                        &service,
                        &connections,
                        Some("cannot identify accepted peer".into()),
                        || {
                            drop(_namespace_deletion);
                            drop(_lifecycle);
                            drop(_mfa_janitor);
                            drop(_ha_activation);
                        },
                    );
                }
                return Err("cannot identify accepted peer".into());
            }
        };
        let rate_limited = limiter
            .lock()
            .map_or(true, |mut limiter| !limiter.allow(peer));
        let request_service = Arc::clone(&service);
        let rate_limiter = Arc::clone(&limiter);
        let tls = Arc::clone(&tls);
        let request_ui_assets = ui_assets.clone();
        let spawn = std::thread::Builder::new()
            .name("heptabao-request".into())
            .spawn(move || {
                let service = request_service;
                let _guard = guard;
                if stream.set_read_timeout(Some(timeout)).is_err()
                    || stream.set_write_timeout(Some(timeout)).is_err()
                {
                    return;
                }
                let Some(mut stream) = h2_transport::negotiate(
                    stream,
                    tls,
                    deadline,
                    timeout,
                    Arc::clone(&service),
                    rate_limiter,
                    peer,
                    consistency_settings,
                    request_ui_assets.clone(),
                    rate_limited,
                ) else {
                    return;
                };
                let attempt_id = match crypto::random::<16>() {
                    Ok(value) => value,
                    Err(_) => return,
                };
                if rate_limited {
                    let response = audited_wire_rejection(
                        &service,
                        &attempt_id,
                        WireRejection::RateLimited,
                        429,
                        "request rate limit exceeded",
                        deadline,
                    );
                    write_http1_reply(
                        &mut stream,
                        snapshot::NativeReply::Json(response),
                        false,
                        "",
                        deadline,
                    );
                    return;
                }
                // Parsing and a bounded rejected-body discard must leave time for
                // the negative response inside the original accepted connection.
                stream.sock.deadline =
                    execution_deadline_with_response_reserve(Instant::now(), deadline);
                let read_budget = stream
                    .sock
                    .deadline
                    .saturating_duration_since(Instant::now());
                let parsed = read_request_with_ui(
                    &mut stream,
                    read_budget,
                    true,
                    request_ui_assets.is_some(),
                );
                stream.sock.deadline = deadline;
                let client_certificates = stream.conn.peer_certificates().map(|certificates| {
                    certificates
                        .iter()
                        .map(|certificate| certificate.as_ref().to_vec())
                        .collect()
                });
                let (reply, head, namespace) = process_parsed_request(
                    &service,
                    request_ui_assets.as_deref(),
                    parsed,
                    &mut stream,
                    client_certificates,
                    peer,
                    &attempt_id,
                    consistency_settings,
                    deadline,
                );
                write_http1_reply(&mut stream, reply, head, &namespace, deadline);
            });
        if spawn.is_err() {
            #[cfg(target_os = "linux")]
            if let Some(control) = local_control.as_ref() {
                drop(listener);
                return control.shutdown(
                    &service,
                    &connections,
                    Some("cannot create bounded request worker".into()),
                    || {
                        drop(_namespace_deletion);
                        drop(_lifecycle);
                        drop(_mfa_janitor);
                        drop(_ha_activation);
                    },
                );
            }
            return Err("cannot create bounded request worker".into());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_parsed_request(
    service: &Arc<Mutex<Service>>,
    ui_assets: Option<&ui::Assets>,
    parsed: Result<ParsedRequest, ParseError>,
    source: &mut impl Read,
    client_certificates: Option<Vec<Vec<u8>>>,
    peer: IpAddr,
    attempt_id: &[u8; 16],
    consistency_settings: consistency::Settings,
    deadline: Instant,
) -> (snapshot::NativeReply, bool, String) {
    match parsed {
        Ok(ParsedRequest::Ui(request)) => {
            let head = request.head;
            let reply = match ui_assets {
                Some(assets) => snapshot::NativeReply::Ui(assets.reply(&request)),
                None => snapshot::NativeReply::Json(Response::error(404, "UI is disabled")),
            };
            (reply, head, String::new())
        }
        Ok(ParsedRequest::Api(request)) => {
            let mut request = *request;
            let _raw_reply_ingress = crate::auth::IngressReplyScope::listener_wrapping(
                attempt_id,
                request.lexical_wrapping_body.take(),
            );
            request.client_certificates = client_certificates;
            let is_head = request.method == "HEAD"
                || help::request(&request.method, &request.path, &request.body.0)
                    .is_some_and(|(method, _, _)| method == "HEAD");
            let native_snapshot = request.native_snapshot.take();
            // Index admission precedes logical dispatch and any snapshot body I/O.
            // It never authenticates the caller or creates permission to retry.
            let consistency = consistency::admit(
                service,
                &request.consistency,
                consistency_settings,
                deadline,
            );
            let mut service_request = ServiceRequest {
                method: if request.method == "HEAD"
                    && request.path != "sys/leader"
                    && request.path != "sys/internal/ui/mounts"
                    && !request.path.starts_with("sys/internal/ui/mounts/")
                    && request.wrap_ttl_seconds.is_none_or(|ttl| ttl == 0)
                    && ocsp::query_request("HEAD", &request.path, &request.body.0).is_none()
                {
                    "GET"
                } else {
                    &request.method
                },
                path: &request.path,
                namespace: &request.namespace,
                token: &request.token,
                body: std::mem::take(&mut request.body.0),
                wrap_ttl_seconds: request.wrap_ttl_seconds,
                origin_peer: Some(peer),
                client_certificates: request.client_certificates.take(),
            };
            let _logical_data = match crate::request_metadata::Scope::enter(
                request.logical_data.take(),
                service_request.method,
                service_request.path,
                service_request.namespace,
                &service_request.body,
            ) {
                Ok(scope) => scope,
                Err(_) => {
                    crate::service::erase_json(&mut service_request.body);
                    return (
                        snapshot::NativeReply::Json(Response::error(
                            400,
                            "invalid request-owned logical data",
                        )),
                        is_head,
                        request.namespace,
                    );
                }
            };
            let mut reply = if let Err(response) = &consistency {
                let mut rejected = audited_wire_rejection(
                    service,
                    attempt_id,
                    WireRejection::ParseRejected,
                    response.status,
                    "consistency prerequisite was not satisfied",
                    execution_deadline_with_response_reserve(Instant::now(), deadline),
                );
                if rejected.status == response.status {
                    rejected.body = response.body.clone();
                }
                crate::service::erase_json(&mut service_request.body);
                snapshot::NativeReply::Json(rejected)
            } else if let Some(native) = native_snapshot {
                snapshot::execute(service, service_request, native, source, deadline)
            } else if matches!(consistency, Ok(true)) {
                snapshot::NativeReply::Json(consistency::forward(
                    service,
                    service_request,
                    deadline,
                ))
            } else {
                snapshot::NativeReply::Json(execute_service_request(
                    service,
                    service_request,
                    deadline,
                    false,
                ))
            };
            logical::project(&mut reply, attempt_id, &request.path);
            (reply, is_head, request.namespace)
        }
        Err(error) => {
            let mut response = if error.health_head.is_some() {
                Response::error(error.status, error.message)
            } else {
                audited_wire_rejection(
                    service,
                    attempt_id,
                    WireRejection::ParseRejected,
                    error.status,
                    error.message,
                    execution_deadline_with_response_reserve(Instant::now(), deadline),
                )
            };
            if error.empty_errors && response.status == error.status {
                response.body = json!({"errors": []});
            }
            let reply = if error.outer_bad_request && response.status == 400 {
                snapshot::NativeReply::HttpBadRequest
            } else {
                snapshot::NativeReply::Json(response)
            };
            (reply, error.health_head == Some(true), String::new())
        }
    }
}

fn execute_external_without_writer<T, P, R, E, F>(
    state: &Arc<Mutex<T>>,
    pending: P,
    deadline: Instant,
    execute: E,
    finish: F,
) -> Response
where
    E: FnOnce(&P) -> R,
    F: FnOnce(&mut T, P, R) -> Response,
{
    let _scope = RequestDeadlineScope::enter(deadline);
    // Deliberately execute before acquiring the state writer. This helper is the
    // production boundary that prevents slow enrolled providers from monopolizing
    // unrelated service state while their external effect/readback is in flight.
    let result = execute(&pending);
    match lock_until(state, deadline) {
        Ok(mut writer) => finish(&mut writer, pending, result),
        Err(LockWaitError::Busy) => Response::error(
            503,
            "provider result awaits durable reconciliation; service finalize deadline exceeded",
        ),
        Err(LockWaitError::Poisoned) => Response::error(
            503,
            "provider result awaits durable reconciliation; service state unavailable",
        ),
    }
}

/// Leave a bounded part of the existing transport budget for the JSON reply.
/// This shortens execution; it never resets or extends the connection deadline,
/// grants read authority, or cancels an already-started durable/provider effect.
fn execution_deadline_with_response_reserve(now: Instant, transport_deadline: Instant) -> Instant {
    let Some(remaining) = transport_deadline.checked_duration_since(now) else {
        return transport_deadline;
    };
    let reserve = (remaining / 4).min(Duration::from_secs(1));
    transport_deadline - reserve
}

fn execute_service_request(
    service: &Arc<Mutex<Service>>,
    mut request: ServiceRequest<'_>,
    deadline: Instant,
    forwarded: bool,
) -> Response {
    // The caller retains the original deadline for TLS/frame response writes.
    // A negative execution result must not consume the last response byte's time.
    let deadline = execution_deadline_with_response_reserve(Instant::now(), deadline);
    let health_probe = request.path == "sys/health" && matches!(request.method, "GET" | "HEAD");
    let deadline = if health_probe {
        deadline.min(Instant::now() + crate::request_deadline::HEALTH_PROBE_BUDGET)
    } else {
        deadline
    };
    let unavailable = |message| {
        let mut response = Response::error(503, message);
        if health_probe {
            // Only a negative readiness result is known without the owner.
            // Do not invent initialization, seal state, role or cluster identity.
            response.body["ha_active"] = json!(false);
            response.body["ha_application_ready"] = json!(false);
        }
        response
    };
    let execution = match lock_until(service, deadline) {
        Ok(mut writer) => {
            let execution = writer.begin_request_before(request, deadline, forwarded);
            if let RequestExecution::Complete(response) = &execution {
                let _original_deadline =
                    crate::request_deadline::RequestDeadlineScope::enter(deadline);
                writer.seal_forward_completion(response);
            }
            execution
        }
        Err(LockWaitError::Busy) => {
            crate::service::erase_json(&mut request.body);
            return unavailable("service state lock deadline exceeded");
        }
        Err(LockWaitError::Poisoned) => {
            crate::service::erase_json(&mut request.body);
            return unavailable("service state is unavailable");
        }
    };
    match execution {
        RequestExecution::Complete(response) => response,
        RequestExecution::External(pending) => execute_external_without_writer(
            service,
            pending,
            deadline,
            |pending| pending.execute_with_service_before(service, deadline),
            |writer, pending, result| {
                let response = writer.finish_external_request(*pending, result);
                writer.seal_forward_completion(&response);
                response
            },
        ),
    }
}

fn audited_wire_rejection(
    service: &Arc<Mutex<Service>>,
    attempt_id: &[u8; 16],
    rejection: WireRejection,
    status: u16,
    message: &'static str,
    deadline: Instant,
) -> Response {
    match lock_until(service, deadline) {
        Ok(mut service) => service.handle_wire_rejection(attempt_id, rejection, status, message),
        Err(LockWaitError::Busy) => Response::error(503, "service state lock deadline exceeded"),
        Err(LockWaitError::Poisoned) => Response::error(503, "service state is unavailable"),
    }
}

struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

struct ResponseWriteObservation<'a, W> {
    writer: &'a mut W,
    accepted_plaintext_bytes: usize,
    flush_attempted: bool,
}
impl<W: Write> Write for ResponseWriteObservation<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.writer.write(bytes)?;
        self.accepted_plaintext_bytes = self.accepted_plaintext_bytes.saturating_add(count);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flush_attempted = true;
        self.writer.flush()
    }
}

// Diagnostic observations do not acknowledge network delivery or grant retry.
// Preserve the original deadline and each underlying write/flush exactly.
fn write_http1_reply(
    writer: &mut impl Write,
    reply: snapshot::NativeReply,
    head: bool,
    namespace: &str,
    deadline: Instant,
) {
    let mut observation = ResponseWriteObservation {
        writer,
        accepted_plaintext_bytes: 0,
        flush_attempted: false,
    };
    if let Err(error) = reply.write_with_namespace(&mut observation, head, namespace) {
        // Error text can carry peer/provider bytes. Only closed error kinds and
        // counters are emitted; no path, token, headers, body or parser line.
        eprintln!(
            "HBHTTP-RESPONSE-WRITE-FAILURE io_kind={} accepted_plaintext_bytes={} flush_attempted={} original_deadline_expired={}",
            match error.kind() {
                io::ErrorKind::TimedOut => "timed_out",
                io::ErrorKind::WouldBlock => "would_block",
                io::ErrorKind::BrokenPipe => "broken_pipe",
                io::ErrorKind::ConnectionReset => "connection_reset",
                io::ErrorKind::ConnectionAborted => "connection_aborted",
                io::ErrorKind::WriteZero => "write_zero",
                io::ErrorKind::Interrupted => "interrupted",
                io::ErrorKind::UnexpectedEof => "unexpected_eof",
                io::ErrorKind::InvalidInput => "invalid_input",
                io::ErrorKind::InvalidData => "invalid_data",
                _ => "other",
            },
            observation.accepted_plaintext_bytes,
            observation.flush_attempted,
            Instant::now() >= deadline
        );
    }
}

struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "connection deadline exceeded"))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

fn bounded_file(path: &PathBuf, private: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "cannot open TLS file")?;
    let meta = file.metadata().map_err(|_| "cannot inspect TLS file")?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return Err("invalid bounded TLS file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && meta.permissions().mode() & 0o077 != 0 {
            return Err("TLS key must be owner only".into());
        }
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read TLS file")?;
    if data.len() > 1024 * 1024 {
        return Err("TLS file grew beyond limit".into());
    }
    Ok(data)
}

fn load_client_verifier(
    ca_path: &PathBuf,
    crl_path: Option<&PathBuf>,
    optional: bool,
    data_dir: &PathBuf,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, String> {
    if !ca_path.is_absolute() || ca_path.starts_with(data_dir) {
        return Err("TLS client CA path must be absolute and outside the data directory".into());
    }
    if crl_path.is_some_and(|path| !path.is_absolute() || path.starts_with(data_dir)) {
        return Err("TLS client CRL path must be absolute and outside the data directory".into());
    }
    let ca_bytes = bounded_file(ca_path, false)?;
    let mut roots = RootCertStore::empty();
    let certificates = rustls_pemfile::certs(&mut BufReader::new(ca_bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid TLS client CA bundle")?;
    if certificates.is_empty() {
        return Err("TLS client CA bundle is empty".into());
    }
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| "invalid TLS client CA certificate")?;
    }
    let mut builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    if optional {
        builder = builder.allow_unauthenticated();
    }
    if let Some(crl_path) = crl_path {
        let crl_bytes = bounded_file(crl_path, false)?;
        let crls = rustls_pemfile::crls(&mut BufReader::new(crl_bytes.as_slice()))
            .collect::<Result<Vec<CertificateRevocationListDer<'static>>, _>>()
            .map_err(|_| "invalid TLS client CRL bundle")?;
        if crls.is_empty() {
            return Err("TLS client CRL bundle is empty".into());
        }
        builder = builder
            .with_crls(crls)
            .only_check_end_entity_revocation()
            .enforce_revocation_expiration();
    }
    builder
        .build()
        .map_err(|_| "invalid TLS client certificate verifier".to_owned())
}

struct SecretJson(Value);
impl Drop for SecretJson {
    fn drop(&mut self) {
        crate::service::erase_json(&mut self.0);
    }
}
enum ParsedRequest {
    Api(Box<Request>),
    Ui(ui::Request),
}
struct Request {
    lexical_wrapping_body: Option<crate::auth::LexicalJson>,
    logical_data: Option<crate::request_metadata::DataFrame>,
    consistency: consistency::Headers,
    native_snapshot: Option<snapshot::NativeRequest>,
    method: String,
    path: String,
    namespace: String,
    token: Zeroizing<String>,
    body: SecretJson,
    wrap_ttl_seconds: Option<u64>,
    client_certificates: Option<Vec<Vec<u8>>>,
}
struct ParseError {
    status: u16,
    message: &'static str,
    // The dedicated leader handler's global selector rejection has no logical
    // error message. Do not replace an audit failure with this empty shape.
    empty_errors: bool,
    // A semantic rejection after valid method/route/header admission can still
    // belong to the public health diagnostic. None retains mandatory wire audit.
    health_head: Option<bool>,
    // Go rejects malformed URI paths and conflicting lengths before logical dispatch.
    outer_bad_request: bool,
}
impl ParseError {
    fn with_health_context(mut self, method: &str, route: &str) -> Self {
        if route == "sys/health" && matches!(method, "GET" | "HEAD") {
            self.health_head = Some(method == "HEAD");
        }
        self
    }
}
impl From<io::Error> for ParseError {
    fn from(_: io::Error) -> Self {
        Self {
            status: 400,
            message: "incomplete or timed out HTTP request",
            empty_errors: false,
            health_head: None,
            outer_bad_request: false,
        }
    }
}
fn bad(message: &'static str) -> ParseError {
    ParseError {
        status: 400,
        message,
        empty_errors: false,
        health_head: None,
        outer_bad_request: false,
    }
}

fn outer_bad(message: &'static str) -> ParseError {
    ParseError {
        outer_bad_request: true,
        ..bad(message)
    }
}

fn valid_uri_path_escapes(path: &str) -> bool {
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && (!bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit()))
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
fn read_request(reader: &mut impl Read, timeout: Duration) -> Result<Request, ParseError> {
    read_request_mode(reader, timeout, false)
}

// The parser can reject an otherwise well-framed body before reading it.
// Writing 413 with TLS plaintext still pending can cause the peer to observe
// a truncated response when the connection closes. Drain only a small,
// authenticated-independent window; never parse rejected bytes or allocate
// the caller-advertised length. Requests larger than this fixed budget remain
// fail-closed and may have no reliably delivered response.
// A fixed 4 MiB maximum is small relative to the 32 MiB snapshot lane.
// Draining only resolves TLS close/413 delivery; bytes are never decoded.
const MAX_413_DRAIN_BODY_BYTES: usize = 2 * MAX_BODY;

fn drain_bounded_413_body(
    reader: &mut impl Read,
    declared: usize,
    received: usize,
    accepted_max: usize,
    start: Instant,
    timeout: Duration,
) {
    if declared <= accepted_max || declared > MAX_413_DRAIN_BODY_BYTES || received > declared {
        return;
    }
    let mut remaining = declared - received;
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    while remaining != 0 && start.elapsed() < timeout {
        match reader.read(&mut buffer[..remaining.min(4096)]) {
            Ok(0) | Err(_) => break,
            Ok(count) => remaining -= count,
        }
    }
}

// Only discard an unambiguous, already bounded ordinary body. This operation
// has no JSON decoding, credentials, storage owner or authority to execute.
fn discard_rejected_ordinary_body(
    reader: &mut impl Read,
    headers: &BTreeMap<String, Zeroizing<String>>,
    already_received: usize,
    started: Instant,
    timeout: Duration,
) {
    if headers.contains_key("transfer-encoding") || headers.contains_key("expect") {
        return;
    }
    let Some(length) = headers
        .get("content-length")
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length <= MAX_BODY && already_received <= *length)
    else {
        return;
    };
    let mut remaining = length - already_received;
    let mut discard = Zeroizing::new([0_u8; 4096]);
    while remaining != 0 && started.elapsed() < timeout {
        let bound = remaining.min(discard.len());
        match reader.read(&mut discard[..bound]) {
            Ok(0) | Err(_) => return,
            Ok(count) => remaining -= count,
        }
    }
}

#[cfg(test)]
fn read_request_mode(
    reader: &mut impl Read,
    timeout: Duration,
    native_wire: bool,
) -> Result<Request, ParseError> {
    match read_request_with_ui(reader, timeout, native_wire, false)? {
        ParsedRequest::Api(request) => Ok(*request),
        ParsedRequest::Ui(_) => Err(bad("request must use /v1/ API")),
    }
}

/// Run the actual HTTP parser/data ingress into the ordinary Service boundary.
/// The fixed fixture time is caller-owned; this does not reset its auth clock.
#[cfg(test)]
pub(crate) fn logical_data_wire_fixture(
    service: &mut Service,
    bytes: &[u8],
    now: u64,
) -> Result<Response, &'static str> {
    let started = Instant::now();
    let deadline = crate::request_deadline::current().unwrap_or(started + Duration::from_secs(5));
    let _deadline = RequestDeadlineScope::enter(deadline);
    let mut reader = bytes;
    let mut parsed = read_request_mode(
        &mut reader,
        deadline.saturating_duration_since(started),
        false,
    )
    .map_err(|error| error.message)?;
    let body = std::mem::take(&mut parsed.body.0);
    let _data = crate::request_metadata::Scope::enter(
        parsed.logical_data.take(),
        &parsed.method,
        &parsed.path,
        &parsed.namespace,
        &body,
    )?;
    Ok(service.handle_http_fixture_at(
        crate::service::ServiceRequest {
            method: &parsed.method,
            path: &parsed.path,
            namespace: &parsed.namespace,
            token: &parsed.token,
            body,
            wrap_ttl_seconds: parsed.wrap_ttl_seconds,
            origin_peer: Some(std::net::IpAddr::from([127, 0, 0, 1])),
            client_certificates: None,
        },
        now,
    ))
}

/// Actual parser, Service mandatory audit, logical projection and wire writer.
/// No test JSON marker creates the native output owner.
#[cfg(test)]
pub(crate) fn workflow_output_wire_fixture(
    service: &mut Service,
    bytes: &[u8],
    now: u64,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let started = Instant::now();
    let deadline = crate::request_deadline::current().unwrap_or(started + Duration::from_secs(5));
    let _deadline = RequestDeadlineScope::enter(deadline);
    let mut reader = bytes;
    let mut parsed = read_request_mode(
        &mut reader,
        deadline.saturating_duration_since(started),
        false,
    )
    .map_err(|error| error.message)?;
    let attempt = [0xb1; 16];
    let _ingress = crate::auth::IngressReplyScope::listener_wrapping(
        &attempt,
        parsed.lexical_wrapping_body.take(),
    );
    let body = std::mem::take(&mut parsed.body.0);
    let _data = crate::request_metadata::Scope::enter(
        parsed.logical_data.take(),
        &parsed.method,
        &parsed.path,
        &parsed.namespace,
        &body,
    )?;
    let response = service.handle_http_fixture_at(
        crate::service::ServiceRequest {
            method: &parsed.method,
            path: &parsed.path,
            namespace: &parsed.namespace,
            token: &parsed.token,
            body,
            wrap_ttl_seconds: parsed.wrap_ttl_seconds,
            origin_peer: Some(std::net::IpAddr::from([127, 0, 0, 1])),
            client_certificates: None,
        },
        now,
    );
    let mut reply = snapshot::NativeReply::Json(response);
    logical::project(&mut reply, &attempt, &parsed.path);
    let snapshot::NativeReply::Json(response) = reply else {
        return Err("workflow returned non-JSON native reply");
    };
    let mut writer = Zeroizing::new(Vec::new());
    write_response(&mut *writer, response, false)
        .map_err(|_| "actual HTTP output writer rejected")?;
    Ok(writer)
}

#[cfg(test)]
pub(crate) fn parsed_api_request_for_test(
    bytes: &[u8],
) -> Result<(String, String, String, Zeroizing<String>, ocsp::CarrierBody), String> {
    let mut reader = bytes;
    let mut request = read_request_mode(&mut reader, Duration::from_secs(5), false)
        .map_err(|error| error.message.to_owned())?;
    Ok((
        request.method,
        request.path,
        request.namespace,
        request.token,
        ocsp::CarrierBody(std::mem::take(&mut request.body.0)),
    ))
}

fn read_request_with_ui(
    reader: &mut impl Read,
    timeout: Duration,
    native_wire: bool,
    ui_enabled: bool,
) -> Result<ParsedRequest, ParseError> {
    let start = Instant::now();
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0; 4096]);
    let header_end = loop {
        if start.elapsed() > timeout {
            return Err(bad("request deadline exceeded"));
        }
        if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            if index > MAX_HEADERS {
                return Err(bad("headers too large"));
            }
            break index + 4;
        }
        if bytes.len() > MAX_HEADERS {
            return Err(bad("headers too large"));
        }
        let count = reader.read(buffer.as_mut())?;
        if count == 0 {
            return Err(bad("incomplete headers"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    };
    let headers =
        std::str::from_utf8(&bytes[..header_end]).map_err(|_| bad("headers must be ASCII"))?;
    if !headers.is_ascii() {
        return Err(bad("headers must be ASCII"));
    }
    let mut lines = headers[..headers.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or_else(|| bad("missing request line"))?;
    let parts: Vec<_> = request_line.split(' ').collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err(bad("unsupported HTTP method or version"));
    }
    let method = parts[0].to_owned();
    let target = Zeroizing::new(parts[1].to_owned());
    let ui_target = ui_enabled && ui::selected(&target);
    if target.len() > 8192 || (!target.starts_with("/v1/") && !ui_target) {
        return Err(bad("request must use /v1/ API"));
    }
    let api_target = target.strip_prefix("/v1/").unwrap_or("");
    if !valid_uri_path_escapes(api_target.split('?').next().unwrap_or_default()) {
        return Err(outer_bad("invalid URI path escape"));
    }
    let leader_route = api_target.split('?').next() == Some("sys/leader");
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "DELETE" | "LIST" | "SCAN" | "PATCH" | "HEAD" | "HELP"
    ) && !(leader_route && leader::valid_method(&method))
        && !ui_target
    {
        return Err(bad("unsupported HTTP method or version"));
    }
    let mut map = BTreeMap::new();
    let mut consistency_headers = consistency::RawHeaders::default();
    for (count, line) in lines.enumerate() {
        if count >= 100 || line.starts_with([' ', '\t']) {
            return Err(bad("invalid header framing"));
        }
        let (name, value) = line.split_once(':').ok_or_else(|| bad("invalid header"))?;
        if name.is_empty()
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || value.bytes().any(|c| c < 32 && c != b'\t')
        {
            return Err(bad("invalid header bytes"));
        }
        let name = name.to_ascii_lowercase();
        if consistency_headers.push(&name, value.trim())? {
            continue;
        }
        if name == "content-length"
            && map
                .get(&name)
                .is_some_and(|previous: &Zeroizing<String>| previous.as_str() != value.trim())
        {
            return Err(outer_bad("conflicting content length"));
        }
        if map
            .insert(name, Zeroizing::new(value.trim().to_owned()))
            .is_some()
        {
            return Err(bad("duplicate headers are not supported"));
        }
    }
    let consistency = match consistency_headers.finish() {
        Ok(value) => value,
        Err(error) => {
            // An ordinary request body can arrive in a separate TLS record.
            // Closing with those bytes unread can truncate the 400 response.
            // Never enter logical parsing/authentication, inspect the body, or
            // read a native snapshot upload before its own admission boundary.
            let native_upload = native_wire
                && matches!(
                    api_target.split('?').next(),
                    Some("sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
                        | "sys/storage/raft/snapshot-repair")
                );
            if !native_upload {
                discard_rejected_ordinary_body(
                    reader,
                    &map,
                    bytes.len().saturating_sub(header_end),
                    start,
                    timeout,
                );
            }
            return Err(error);
        }
    };
    if !map.contains_key("host") {
        return Err(bad("Host header is required"));
    }
    if ui_target {
        // Static resources retain the same bounded header grammar, duplicate
        // header and Host admission. They have no logical JSON body, token
        // authority, response wrapping, or consistency-index operation.
        if map.contains_key("transfer-encoding") || map.contains_key("expect") {
            return Err(bad("UI resources do not accept transfer or Expect framing"));
        }
        let length = match map.get("content-length") {
            Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                value
                    .parse::<usize>()
                    .map_err(|_| bad("invalid content length"))?
            }
            None => 0,
            _ => return Err(bad("invalid content length")),
        };
        if length != 0 || bytes.len() != header_end {
            return Err(bad("UI resources do not accept a body or pipelining"));
        }
        return ui::request(&method, &target).map(ParsedRequest::Ui);
    }
    let route = target[4..].split('?').next().unwrap_or_default();
    if !leader_route
        && map.keys().any(|name| {
            (name.starts_with("x-vault-") || name.starts_with("x-bao-"))
                && !matches!(
                    name.as_str(),
                    "x-vault-token"
                        | "x-vault-namespace"
                        | "x-vault-request"
                        | "x-vault-wrap-ttl"
                        | "x-vault-wrap-format"
                )
        })
    {
        return Err(ParseError {
            status: 501,
            message: "requested OpenBao header semantics are not implemented",
            empty_errors: false,
            health_head: None,
            outer_bad_request: false,
        });
    }
    if !leader_route
        && map
            .get("x-vault-wrap-format")
            .is_some_and(|value| value.as_str() != "uuid")
    {
        return Err(ParseError {
            status: 501,
            message: "only opaque response wrapping tokens are supported",
            empty_errors: false,
            health_head: None,
            outer_bad_request: false,
        });
    }
    let raw_query = target[4..].split_once('?').map_or("", |(_, query)| query);
    let help_selected = !leader_route && help::requested(&method, raw_query);
    let health_probe = route == "sys/health" && matches!(method.as_str(), "GET" | "HEAD");
    let wrap_ttl_seconds = if leader_route || health_probe || help_selected {
        None
    } else {
        map.get("x-vault-wrap-ttl")
            .map(|value| parse_wrap_ttl(value))
            .transpose()?
            .flatten()
    };
    let snapshot_route = matches!(
        route,
        "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
            | "sys/storage/raft/snapshot-repair"
    );
    let download =
        matches!(method.as_str(), "GET" | "HEAD") && route == "sys/storage/raft/snapshot";
    let json_body = media_type_is(
        map.get("content-type").map(|value| value.as_str()),
        "application/json",
    );
    let native_snapshot = native_wire
        && !help_selected
        && snapshot_route
        && ((download
            && !map
                .get("accept")
                .is_some_and(|value| value.as_str() == "application/json"))
            || (matches!(method.as_str(), "POST" | "PUT") && !json_body));
    let chunked = match map.get("transfer-encoding") {
        Some(value)
            if native_snapshot
                && !download
                && value.eq_ignore_ascii_case("chunked")
                && !map.contains_key("content-length") =>
        {
            true
        }
        Some(_) => return Err(bad("unsupported or ambiguous transfer framing")),
        None => false,
    };
    if map.contains_key("expect") {
        return Err(bad("Expect framing is not supported"));
    }
    let length = match map.get("content-length") {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => v
            .parse::<usize>()
            .map_err(|_| bad("invalid content length"))?,
        None => 0,
        _ => return Err(bad("invalid content length")),
    };
    let ocsp_get = ocsp::get_carrier(&method, route)?;
    let ocsp_post = ocsp::raw_post(
        &method,
        route,
        map.get("content-type").map(|media| media.as_str()),
    );
    let ocsp_form_media = ocsp::post_route(&method, route)
        && ocsp::form_media(map.get("content-type").map(|media| media.as_str()));
    // Decode only a bounded login carrier. Body-bound media metadata makes
    // the actual synchronized AppRole mount kind a Service admission condition,
    // including on the active node after ordinary standby forwarding.
    let approle_form = approle_form::selected(
        &method,
        route,
        map.get("content-type").map(|media| media.as_str()),
    );
    if approle_form && !raw_query.is_empty() {
        discard_rejected_ordinary_body(
            reader,
            &map,
            bytes.len().saturating_sub(header_end),
            start,
            timeout,
        );
        return Err(bad("AppRole form must not combine query credentials"));
    }
    let maximum_body = if native_snapshot {
        crate::snapshot_file::MAX_NATIVE_ARCHIVE as usize
    } else if snapshot_route {
        MAX_SNAPSHOT_BODY
    } else {
        json_ingress_body_limit(
            &method,
            route,
            map.get("content-type").map(|value| value.as_str()),
        )
    };
    if length > maximum_body {
        if !native_snapshot && !map.contains_key("transfer-encoding") && !map.contains_key("expect")
        {
            drain_bounded_413_body(
                reader,
                length,
                bytes.len().saturating_sub(header_end),
                maximum_body,
                start,
                timeout,
            );
        }
        return Err(ParseError {
            status: 413,
            message: "request body exceeds limit",
            empty_errors: false,
            health_head: None,
            outer_bad_request: false,
        });
    }
    let raw_namespace = if leader_route {
        ""
    } else {
        map.get("x-vault-namespace").map_or("", |s| s.as_str())
    };
    if raw_namespace == "/" || raw_namespace.contains("//") {
        return Err(bad("ambiguous namespace segments").with_health_context(&method, route));
    }
    let namespace = raw_namespace
        .strip_suffix('/')
        .unwrap_or(raw_namespace)
        .to_owned();
    let token = if leader_route {
        Zeroizing::new(String::new())
    } else {
        map.remove("x-vault-token").unwrap_or_default()
    };
    if token.len() > 16 * 1024 {
        return Err(bad("token header exceeds limit"));
    }
    let query_only = matches!(method.as_str(), "GET" | "HEAD" | "DELETE" | "LIST" | "SCAN");
    // A media type is only a body codec. The Service still resolves the actual
    // PKI mount and verifies its durable public JWS account owner.
    let jose_acme = method == "POST"
        && route.split('/').any(|part| part == "acme")
        && map
            .get("content-type")
            .is_some_and(|media| media.split(';').next() == Some("application/jose+json"));
    if length > 0
        && !leader_route
        && !native_snapshot
        && !ocsp_post
        && !ocsp_form_media
        && !approle_form
        && !ocsp::post_route(&method, route)
        && !query_only
        && !help_selected
        && !jose_acme
        && map.get("content-type").is_some_and(|v| {
            !media_type_is(Some(v.as_str()), "application/json")
                && v.split(';').next() != Some("application/merge-patch+json")
        })
    {
        discard_rejected_ordinary_body(
            reader,
            &map,
            bytes.len().saturating_sub(header_end),
            start,
            timeout,
        );
        return Err(bad("JSON content type required"));
    }
    while !native_snapshot && bytes.len() < header_end + length {
        if start.elapsed() > timeout {
            return Err(bad("request deadline exceeded"));
        }
        let remaining = (header_end + length - bytes.len()).min(buffer.len());
        let count = reader.read(&mut buffer[..remaining])?;
        if count == 0 {
            return Err(bad("incomplete body"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if !native_snapshot && bytes.len() != header_end + length {
        return Err(bad("pipelining and trailing bytes are not supported"));
    }
    // Help ignores logical body bytes after ordinary framing and body bounds.
    if help_selected {
        let body = help::carrier(&method, route, raw_query)?;
        if (route.contains('%') || route.contains('#'))
            && !help::opaque_request("HELP", route, &body)
        {
            return Err(bad("ambiguous encoded paths are not supported"));
        }
        return Ok(ParsedRequest::Api(Box::new(Request {
            lexical_wrapping_body: None,
            logical_data: None,
            consistency,
            native_snapshot: None,
            method: "HELP".to_owned(),
            path: route.to_owned(),
            namespace,
            token,
            body: SecretJson(body),
            wrap_ttl_seconds,
            client_certificates: None,
        })));
    }
    // Public UI preflight has no PATCH operation. Its JSON media boundary is
    // still evaluated before dispatch, after ordinary framing/size fences.
    if method == "PATCH"
        && (route == "sys/internal/ui/mounts" || route.starts_with("sys/internal/ui/mounts/"))
    {
        if length == 0 {
            return Err(bad("PATCH requires a JSON body"));
        }
        if !map
            .get("content-type")
            .is_some_and(|value| value.split(';').next() == Some("application/merge-patch+json"))
        {
            return Err(ParseError {
                status: 415,
                message: "PATCH requires merge-patch JSON",
                empty_errors: false,
                health_head: None,
                outer_bad_request: false,
            });
        }
    }
    if leader_route {
        leader::validate_selectors(&method, &target)?;
        return Ok(ParsedRequest::Api(Box::new(Request {
            lexical_wrapping_body: None,
            logical_data: None,
            consistency,
            native_snapshot: None,
            method,
            path: "sys/leader".to_owned(),
            namespace: String::new(),
            token,
            body: SecretJson(json!({})),
            wrap_ttl_seconds: None,
            client_certificates: None,
        })));
    }
    // OpenBao reads fields for these operations from the query string only.
    // Still consume and bound the complete body above so ignored bytes cannot
    // become a second request or evade the framing and deadline checks.
    let query = target[4..].split_once('?').map_or("", |(_, query)| query);
    let ocsp_form = ocsp_form_media
        && ocsp::form_request(
            map.get("content-type").map(|media| media.as_str()),
            &bytes[header_end..],
        );
    if ocsp_form {
        ocsp::validate_form(&bytes[header_end..])?;
        ocsp::validate_form(query.as_bytes())?;
    }
    let carrier = ocsp::carrier_body(
        ocsp_get.as_ref(),
        ocsp_post || ocsp_form,
        route,
        map.get("content-type").map(|media| media.as_str()),
        &bytes[header_end..],
        query,
    );
    let mut lexical_wrapping_body = if carrier.is_none()
        && !native_snapshot
        && length > 0
        && !query_only
        && matches!(method.as_str(), "POST" | "PUT")
        && decode_native_logical_path(route)? == "sys/wrapping/wrap"
    {
        Some(
            crate::auth::LexicalJson::parse_listener(&bytes[header_end..])
                .map_err(|_| bad("invalid JSON object"))?,
        )
    } else {
        None
    };
    let mut body = SecretJson(if let Some(carrier) = carrier {
        carrier
    } else if native_snapshot || length == 0 || query_only {
        json!({})
    } else if approle_form {
        approle_form::parse(&bytes[header_end..]).map_err(bad)?
    } else if let Some(lexical) = &lexical_wrapping_body {
        lexical
            .wrapping_view()
            .map_err(|_| bad("invalid JSON object"))?
    } else {
        crate::auth::parse_strict_json(&bytes[header_end..])
            .map_err(|_| bad("invalid JSON object"))?
    });
    if body.0.is_null()
        && matches!(method.as_str(), "POST" | "PUT")
        && decode_native_logical_path(route)?.starts_with("sys/workflows/execute/")
    {
        body.0 = json!({});
    }
    if !body.0.is_object() {
        return Err(bad("JSON object required"));
    }
    let Some(object) = body.0.as_object_mut() else {
        return Err(bad("JSON object required"));
    };
    let (raw_path, query) = target[4..].split_once('?').unwrap_or((&target[4..], ""));
    let decoded_path = if ocsp_get.is_some() || ocsp::head_candidate(&method, raw_path) {
        std::borrow::Cow::Borrowed(raw_path)
    } else {
        decode_native_logical_path(raw_path)?
    };
    let path = decoded_path.as_ref();
    if (path.contains('%') || path.contains('#'))
        && ocsp_get.is_none()
        && !ocsp::head_candidate(&method, path)
    {
        return Err(bad("ambiguous encoded paths are not supported"));
    }
    // Kerberos uses the standard HTTP Negotiate carrier rather than a JSON
    // credential. Keep the provider token request-local and let the auth
    // route's strict body schema reject it everywhere else.
    if path.starts_with("auth/")
        && path.ends_with("/login")
        && let Some(authorization) = map.remove("authorization")
    {
        if !authorization.starts_with("Negotiate ")
            || authorization.len() > crate::outbound::MAX_KERBEROS_TOKEN * 2 + 16
            || !authorization.is_ascii()
        {
            return Err(bad("invalid Kerberos authorization header"));
        }
        if object.contains_key("kerberos_authorization") {
            return Err(bad("duplicate Kerberos authorization"));
        }
        object.insert(
            "kerberos_authorization".into(),
            Value::String(authorization.to_string()),
        );
    }
    // These fields are request-owned data only. Credential, namespace,
    // consistency and framing headers retain their independent admission paths.
    let mut logical_data = crate::request_metadata::DataFrame::default();
    if !snapshot_route {
        for (name, value) in &map {
            if name == crate::request_metadata::AUTH_FORM_CODEC_HEADER
                || matches!(
                    name.as_str(),
                    "authorization"
                        | "x-vault-token"
                        | "x-vault-namespace"
                        | "x-vault-wrap-ttl"
                        | "content-length"
                        | "content-type"
                        | "host"
                        | "connection"
                        | "transfer-encoding"
                        | "expect"
                )
            {
                continue;
            }
            logical_data
                .headers
                .insert(name.clone(), vec![value.to_string()]);
        }
    }
    let workflow_query = path.starts_with("sys/workflows/execute/");
    if workflow_query {
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair
                .split_once('=')
                .ok_or_else(|| bad("workflow query requires values"))?;
            logical_data
                .query
                .entry(decode_query(name)?)
                .or_default()
                .push(decode_query(value)?);
        }
    }
    if approle_form {
        // A fixed reserved data-only codec marker is bound to this method/path/namespace
        // and decoded body. Existing authenticated forwarding preserves it.
        // It grants no auth authority; the live mount is checked before effects.
        logical_data.headers.insert(
            crate::request_metadata::AUTH_FORM_CODEC_HEADER.to_owned(),
            vec!["approle-form-v1".to_owned()],
        );
    }
    logical_data.validate().map_err(bad)?;
    let logical_data = (!logical_data.headers.is_empty() || !logical_data.query.is_empty())
        .then_some(logical_data);
    let invalid_query = |message| bad(message).with_health_context(&method, path);
    let private_query = if ocsp_get.is_none() {
        ocsp::query_carrier_body(&method, path, query)
    } else {
        None
    };
    let has_private_query = private_query.is_some();
    if let Some(carrier) = private_query {
        crate::service::erase_json(&mut body.0);
        body.0 = carrier;
    } else if !workflow_query && ocsp_get.is_none() && !ocsp::post_route(&method, route) {
        merge_query_fields(&method, path, query, &mut body.0)?;
    }
    let Some(object) = body.0.as_object_mut() else {
        return Err(bad("JSON object required"));
    };
    let method = if ocsp_get.is_some() || (has_private_query && method == "GET") {
        ocsp::get_query_method(query)?.to_owned()
    } else if method == "GET" {
        let list = object.get("list") == Some(&Value::Bool(true));
        let scan = object.get("scan") == Some(&Value::Bool(true));
        if list && scan {
            return Err(invalid_query("list and scan are mutually exclusive"));
        }
        if list {
            object.remove("list");
            "LIST".to_owned()
        } else if scan {
            object.remove("scan");
            "SCAN".to_owned()
        } else {
            method
        }
    } else {
        method
    };
    if ocsp::post_route(&method, route) && !ocsp_post && !ocsp_form {
        body.0 = ocsp::normal_json_post(
            route,
            std::mem::take(&mut body.0),
            map.get("content-type").map(|media| media.as_str()),
            length != 0,
            query,
        );
    }
    token_fields::transport_body(&method, path, &mut body.0, &bytes[header_end..]).map_err(bad)?;
    if method == "PATCH" && pki_role_fields::eligible(&method, path) {
        if length == 0 {
            return Err(bad("PATCH requires a JSON body"));
        }
        if !map
            .get("content-type")
            .is_some_and(|value| value.split(';').next() == Some("application/merge-patch+json"))
        {
            return Err(ParseError {
                status: 415,
                message: "PATCH requires merge-patch JSON",
                empty_errors: false,
                health_head: None,
                outer_bad_request: false,
            });
        }
    }
    pki_role_fields::transport_body(&method, path, &mut body.0, &bytes[header_end..])
        .map_err(bad)?;
    let native_snapshot = if native_snapshot {
        if download && (length != 0 || bytes.len() != header_end) {
            return Err(bad("snapshot download does not accept a body"));
        }
        Some(snapshot::NativeRequest {
            target: snapshot::NativeTarget::checked(&target)?,
            body: snapshot::NativeBody {
                framing: if download {
                    snapshot::Framing::Download
                } else if chunked {
                    snapshot::Framing::Chunked
                } else {
                    snapshot::Framing::Length(length as u64)
                },
                prefix: Zeroizing::new(bytes[header_end..].to_vec()),
            },
        })
    } else {
        None
    };
    if let Some(lexical) = &mut lexical_wrapping_body {
        lexical
            .bind_transport_fields(&body.0)
            .map_err(|_| bad("invalid lexical transport body"))?;
    }
    Ok(ParsedRequest::Api(Box::new(Request {
        lexical_wrapping_body,
        logical_data,
        consistency,
        native_snapshot,
        method,
        path: path.to_owned(),
        namespace,
        token,
        body,
        wrap_ttl_seconds,
        client_certificates: None,
    })))
}

fn parse_wrap_ttl(value: &str) -> Result<Option<u64>, ParseError> {
    let invalid = || bad("invalid or unsupported wrapping TTL");
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return Err(invalid());
    }
    let mut total = 0u64;
    let mut number = 0u64;
    let mut digits = false;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            number = number
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                .ok_or_else(invalid)?;
            digits = true;
        } else {
            if !digits {
                return Err(invalid());
            }
            let unit = match byte {
                b'h' => 3600,
                b'm' => 60,
                b's' => 1,
                _ => return Err(invalid()),
            };
            total = total
                .checked_add(number.checked_mul(unit).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
            number = 0;
            digits = false;
        }
    }
    if digits {
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        total = number;
    }
    if total > 32 * 24 * 3600 {
        return Err(invalid());
    }
    Ok(Some(total))
}

fn merge_query_fields(
    method: &str,
    path: &str,
    query: &str,
    body: &mut Value,
) -> Result<(), ParseError> {
    let Some(object) = body.as_object_mut() else {
        return Err(bad("JSON object required"));
    };
    let invalid_query = |message| bad(message).with_health_context(method, path);
    for pair in query.split('&').filter(|v| !v.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| invalid_query("query parameters require values"))?;
        let key = decode_query(key).map_err(|error| error.with_health_context(method, path))?;
        let value = Zeroizing::new(
            decode_query(value).map_err(|error| error.with_health_context(method, path))?,
        );
        // OpenBao's health handler consumes these five query fields. Its Go
        // client also sends compatibility fields (including "haunhealhty")
        // which that handler ignores; they do not select an unimplemented mode.
        if path == "sys/health"
            && !matches!(
                key.as_str(),
                "standbyok" | "uninitcode" | "sealedcode" | "standbycode" | "activecode"
            )
        {
            continue;
        }
        // Preserve the actual URL field for the OpenAPI backend's weak bool
        // parser. Discovery does not turn this field into a global query grant.
        if path == "sys/internal/specs/openapi" && key == "generic_mount_paths" {
            if object.contains_key(&key) {
                return Err(invalid_query("duplicate body/query parameter"));
            }
            object.insert(key, Value::String(value.to_string()));
            continue;
        }
        #[cfg(feature = "experimental-native-v6-ha")]
        if path == "sys/storage/raft/snapshot"
            && matches!(method, "POST" | "PUT")
            && key == "cancel_pending_restore"
        {
            // Preserve only this explicit native reconciliation selector.
            // Service still checks the live native owner, original root Actor,
            // canonical reference and empty streamed body before any effect.
            if object.contains_key(&key) {
                return Err(invalid_query("duplicate body/query parameter"));
            }
            object.insert(key, Value::String(value.to_string()));
            continue;
        }
        if !matches!(
            key.as_str(),
            "version"
                | "depth"
                | "limit"
                | "list"
                | "scan"
                | "after"
                | "exclude_deleted"
                | "standbyok"
                | "perfstandbyok"
                | "uninitcode"
                | "sealedcode"
                | "standbycode"
                | "activecode"
        ) {
            return Err(invalid_query(
                "unsupported query parameter; request fields belong in JSON body",
            ));
        }
        if object.contains_key(&key) {
            return Err(invalid_query("duplicate body/query parameter"));
        }
        let parsed = if key == "limit" {
            // Endpoints that declare this field validate its type. KV v1
            // ignores it entirely, including values outside the signed range.
            value
                .parse::<i64>()
                .map_or_else(|_| Value::String(value.to_string()), |limit| json!(limit))
        } else if key == "version" && path.starts_with("sys/plugins/catalog/") {
            Value::String(value.to_string())
        } else if matches!(key.as_str(), "version" | "depth") {
            json!(
                value
                    .parse::<u64>()
                    .map_err(|_| invalid_query("invalid numeric query"))?
            )
        } else if matches!(
            key.as_str(),
            "uninitcode" | "sealedcode" | "standbycode" | "activecode"
        ) {
            let status = value
                .parse::<u16>()
                .ok()
                .filter(|status| (100..=999).contains(status))
                .ok_or_else(|| invalid_query("invalid health status code"))?;
            json!(status)
        } else if matches!(key.as_str(), "standbyok" | "perfstandbyok")
            && matches!(value.as_str(), "true" | "1")
        {
            Value::Bool(true)
        } else if matches!(key.as_str(), "standbyok" | "perfstandbyok")
            && matches!(value.as_str(), "false" | "0")
        {
            Value::Bool(false)
        } else if matches!(key.as_str(), "standbyok" | "perfstandbyok") {
            return Err(invalid_query("invalid health boolean query"));
        } else if method == "GET" && matches!(key.as_str(), "list" | "scan") {
            Value::Bool(match value.as_str() {
                "true" | "True" | "TRUE" | "t" | "T" | "1" => true,
                "" | "false" | "False" | "FALSE" | "f" | "F" | "0" => false,
                _ => return Err(invalid_query("invalid list or scan query")),
            })
        } else if key == "after" {
            Value::String(value.to_string())
        } else if matches!(value.as_str(), "true" | "false") {
            Value::Bool(value.as_str() == "true")
        } else {
            Value::String(value.to_string())
        };
        object.insert(key, parsed);
    }
    Ok(())
}

fn decode_query(value: &str) -> Result<String, ParseError> {
    let mut result = Zeroizing::new(Vec::new());
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let a = bytes.next().ok_or_else(|| bad("invalid query escape"))?;
                let b = bytes.next().ok_or_else(|| bad("invalid query escape"))?;
                let digits = [a, b];
                let text = std::str::from_utf8(&digits).map_err(|_| bad("invalid query escape"))?;
                result.push(u8::from_str_radix(text, 16).map_err(|_| bad("invalid query escape"))?);
            }
            b'+' => result.push(b' '),
            _ => result.push(b),
        }
    }
    if result.iter().any(|b| *b < 32 || *b == 127) {
        return Err(bad("invalid query bytes"));
    }
    std::str::from_utf8(&result)
        .map(str::to_owned)
        .map_err(|_| bad("invalid query text"))
}

// Match Go net/http Header.writeSubset without changing stored/audit values.
// Only the ASCII space bytes accepted by textproto.TrimString are trimmed;
// CR and LF inside the value each become one space, so they cannot add a header.
fn write_go_content_type_header(writer: &mut impl Write, value: &str) -> io::Result<()> {
    let value = value.trim_matches([' ', '\t', '\r', '\n']);
    writer.write_all(b"Content-Type: ")?;
    for (index, part) in value.split(['\r', '\n']).enumerate() {
        if index != 0 {
            writer.write_all(b" ")?;
        }
        writer.write_all(part.as_bytes())?;
    }
    writer.write_all(b"\r\n")
}

#[cfg(test)]
fn write_response(writer: &mut impl Write, response: Response, head: bool) -> io::Result<()> {
    write_response_with_namespace(writer, response, head, "")
}

// Reflect the parsed namespace even when the logical service rejects it. This
// transport field does not establish namespace membership or caller authority.
fn write_standard_headers(writer: &mut impl Write, namespace: &str) -> io::Result<()> {
    write_standard_headers_with_date(writer, namespace, false)
}

fn write_standard_headers_with_date(
    writer: &mut impl Write,
    namespace: &str,
    custom_date: bool,
) -> io::Result<()> {
    if !namespace.is_ascii() || namespace.bytes().any(|byte| byte < 32 || byte == 127) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid response namespace",
        ));
    }
    write!(
        writer,
        "Cache-Control: no-store\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\n",
    )?;
    if !custom_date {
        write!(
            writer,
            "Date: {}\r\n",
            chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT")
        )?;
    }
    writer.write_all(b"Connection: close\r\n")?;
    if !namespace.is_empty() {
        write!(writer, "X-Vault-Namespace: {namespace}\r\n")?;
    }
    Ok(())
}

fn write_response_with_namespace(
    writer: &mut impl Write,
    response: Response,
    head: bool,
    namespace: &str,
) -> io::Result<()> {
    // Only the engine's closed certificate envelope selects these constants.
    // Neither caller data nor provider JSON supplies an arbitrary MIME type.
    let raw_certificate = if response.status == 200
        && response
            .body
            .as_object()
            .is_some_and(|body| body.len() == 2)
    {
        let media = match response.body["format"].as_str() {
            Some("der" | "chain") => Some("application/pkix-cert"),
            Some("pem") => Some("application/pem-certificate-chain"),
            _ => None,
        };
        media.and_then(|media| {
            response.body["__heptabao_pki_certificate"]
                .as_str()
                .and_then(|text| {
                    use base64::Engine as _;
                    let base64 = base64::engine::general_purpose::STANDARD;
                    if text.len() > 256 * 1024 {
                        return None;
                    }
                    let bytes = base64.decode(text).ok()?;
                    (bytes.len() <= 128 * 1024 && base64.encode(&bytes) == text)
                        .then_some((bytes, media))
                })
        })
    } else {
        None
    };
    // Only this closed, bounded CRL transport envelope can select a raw public
    // body. The content types are constants and never come from provider JSON.
    let raw_crl = if matches!(response.status, 200 | 204)
        && response
            .body
            .as_object()
            .is_some_and(|body| body.len() == 2)
        && response.body["pem"].is_boolean()
    {
        response.body["__heptabao_pki_crl"]
            .as_str()
            .and_then(|text| {
                use base64::Engine as _;
                let base64 = base64::engine::general_purpose::STANDARD;
                if text.len() > 1024 * 1024 {
                    return None;
                }
                let bytes = base64.decode(text).ok()?;
                (bytes.len() <= 512 * 1024
                    && base64.encode(&bytes) == text
                    && (response.status == 200 || bytes.is_empty()))
                .then_some(bytes)
            })
    } else {
        None
    };
    let raw_acme = if response
        .body
        .as_object()
        .is_some_and(|body| body.len() == 2 && body.contains_key("__heptabao_acme"))
    {
        match response.body["media"].as_str() {
            Some("empty") if response.body["__heptabao_acme"].is_null() => {
                Some((Vec::new(), "application/json"))
            }
            Some("certificate") if response.status == 200 => response.body["__heptabao_acme"]
                .as_str()
                .filter(|pem| {
                    pem.len() <= 512 * 1024
                        && pem.starts_with("-----BEGIN CERTIFICATE-----\n")
                        && pem.ends_with("-----END CERTIFICATE-----\n")
                })
                .map(|pem| (pem.as_bytes().to_vec(), "application/pem-certificate-chain")),
            Some("json" | "problem") if response.body["__heptabao_acme"].is_object() => {
                let payload = &response.body["__heptabao_acme"];
                #[derive(serde::Serialize)]
                struct AcmeProblem<'a> {
                    #[serde(rename = "type")]
                    kind: &'a str,
                    detail: &'a str,
                }
                let mut bytes = if response.body["media"] == "problem" {
                    let map = payload
                        .as_object()
                        .filter(|map| map.len() == 2)
                        .ok_or_else(|| io::Error::other("invalid ACME problem transport"))?;
                    let kind = map
                        .get("type")
                        .and_then(Value::as_str)
                        .ok_or_else(|| io::Error::other("invalid ACME problem type"))?;
                    let detail = map
                        .get("detail")
                        .and_then(Value::as_str)
                        .ok_or_else(|| io::Error::other("invalid ACME problem detail"))?;
                    serde_json::to_vec(&AcmeProblem { kind, detail })?
                } else {
                    serde_json::to_vec(payload)?
                };
                // Go's JSON encoder escapes HTML and JavaScript separators even
                // in these closed logical raw responses. Bound the final bytes
                // before HTTP computes Content-Length or chooses chunked framing.
                bytes = String::from_utf8(bytes)
                    .map_err(io::Error::other)?
                    .replace('&', "\\u0026")
                    .replace('<', "\\u003c")
                    .replace('>', "\\u003e")
                    .replace('\u{2028}', "\\u2028")
                    .replace('\u{2029}', "\\u2029")
                    .into_bytes();
                if bytes.len() <= 128 * 1024 {
                    Some((
                        std::mem::take(&mut bytes),
                        if response.body["media"] == "problem" {
                            "application/problem+json"
                        } else {
                            "application/json"
                        },
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    };
    let raw_ocsp = crate::engines::raw_ocsp_response(response.status, &response.body);
    let stored_raw_transport = if response.status == 200 {
        response
            .unwrapped_json
            .as_ref()
            .map(|origin| origin.raw_http_transport(&response.body))
            .transpose()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored raw HTTP transport rejected",
                )
            })?
            .flatten()
    } else {
        None
    };
    let admitted_http_status = stored_raw_transport.map_or(response.status, |(status, _)| status);
    let content_type = if let Some((_, media)) = stored_raw_transport {
        media
    } else if let Some((_, media)) = &raw_acme {
        *media
    } else if raw_ocsp.is_some() {
        "application/ocsp-response"
    } else if let Some((_, media)) = &raw_certificate {
        *media
    } else if raw_crl.is_some() {
        if response.body["pem"] == true {
            "application/x-pem-file"
        } else {
            "application/pkix-crl"
        }
    } else {
        "application/json"
    };
    // ACME's closed logical JSON carries no explicit native Content-Length.
    // Certificate/CRL/OCSP producers retain their admitted fixed-length framing.
    let fixed_raw_body = stored_raw_transport.is_some()
        || raw_ocsp.is_some()
        || raw_certificate.is_some()
        || raw_crl.is_some();
    let acme_empty = raw_acme.as_ref().is_some_and(|(bytes, _)| bytes.is_empty());
    let acme_no_media = acme_empty && matches!(response.status, 200 | 204);

    let stored_unwrap = if response.status == 200 {
        response
            .unwrapped_json
            .as_ref()
            .map(|origin| origin.raw_bytes(&response.body))
            .transpose()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored unwrap representation rejected",
                )
            })?
            .flatten()
    } else {
        None
    };
    let mut bytes = Zeroizing::new(if let Some(raw) = stored_unwrap {
        raw.to_vec()
    } else if let Some((raw, _)) = raw_acme {
        raw
    } else if let Some(raw) = raw_ocsp {
        raw
    } else if let Some((raw, _)) = raw_certificate {
        raw
    } else if let Some(raw) = raw_crl {
        raw
    } else if response.status == 204 {
        Vec::new()
    } else {
        let complete_envelope = response.status == 200
            && response.body.as_object().is_some_and(|object| {
                object.len() == 8
                    && [
                        "request_id",
                        "lease_id",
                        "renewable",
                        "lease_duration",
                        "data",
                        "wrap_info",
                        "warnings",
                        "auth",
                    ]
                    .iter()
                    .all(|name| object.contains_key(*name))
            });
        let mut json = if complete_envelope {
            crate::auth::encode_http_envelope(&response.body, MAX_RESPONSE)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "logical envelope encoding rejected",
                    )
                })?
                .to_vec()
        } else {
            serde_json::to_vec(&response.body)?
        };
        // The admitted Auth unwrap producer carries stored JSON. OpenBao writes
        // those bytes directly. Other JSON, including every error, keeps the
        // encoder newline. No request URL or body key selects this branch.
        if response.status != 200 || response.unwrapped_json.is_none() {
            json.push(b'\n');
        }
        json
    });
    let status = if bytes.len() > MAX_RESPONSE {
        bytes = Zeroizing::new(b"{\"errors\":[\"response exceeds limit\"]}\n".to_vec());
        500
    } else {
        admitted_http_status
    };
    // Use Go HTTP status text, including its custom health-code fallback.
    let reason = match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    };
    let reason = if reason.is_empty() {
        format!("status code {status}")
    } else {
        reason.to_owned()
    };
    let retry_after = if status == 429 {
        "Retry-After: 1\r\n"
    } else {
        ""
    };
    let index = if status == admitted_http_status {
        response
            .consistency_index
            .as_ref()
            .map(|index| format!("X-Vault-Index: {}\r\n", index.as_str()))
            .unwrap_or_default()
    } else {
        String::new()
    };
    // Go net/http buffers 2048 bytes before choosing framing. A completed
    // small response gets Content-Length; a larger HTTP/1.1 response uses
    // chunked encoding. HEAD has the same small-body length, with no chunks.
    // https://github.com/golang/go/blob/go1.25.1/src/net/http/server.go
    let no_body = status == 204 || status == 304 || (100..200).contains(&status);
    let chunked = !no_body && !head && !fixed_raw_body && bytes.len() > 2048;
    write!(writer, "HTTP/1.1 {status} {reason}\r\n")?;
    if !acme_no_media && !content_type.is_empty() {
        write_go_content_type_header(writer, content_type)?;
    }
    if !no_body && !(head && acme_empty) && (fixed_raw_body || bytes.len() <= 2048) {
        write!(writer, "Content-Length: {}\r\n", bytes.len())?;
    } else if chunked {
        writer.write_all(b"Transfer-Encoding: chunked\r\n")?;
    }
    if let Some(origin) = &response.unwrapped_json
        && let Some(error) = origin
            .raw_error_header(&response.body)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "raw error custody rejected"))?
    {
        write!(writer, "X-Vault-Raw-Error: {error}\r\n")?;
    }
    write!(writer, "{retry_after}{index}")?;
    write_standard_headers_with_date(
        writer,
        namespace,
        status == admitted_http_status && response.response_headers.has_date(),
    )?;
    if status == admitted_http_status {
        response.response_headers.write(writer)?;
    }
    writer.write_all(b"\r\n")?;
    if !head && !no_body {
        if chunked {
            write!(writer, "{:x}\r\n", bytes.len())?;
            writer.write_all(&bytes)?;
            writer.write_all(b"\r\n0\r\n\r\n")?;
        } else {
            writer.write_all(&bytes)?;
        }
    }
    writer.flush()
}

#[cfg(test)]
#[path = "http_unwrap_framing_tests.rs"]
mod unwrap_framing_tests;

#[cfg(test)]
#[path = "http_response_framing_tests.rs"]
mod response_framing_tests;

#[cfg(test)]
#[path = "http_ocsp_service_tests.rs"]
mod ocsp_service_tests;

#[cfg(test)]
mod tests {

    #[test]
    fn raw113_actual_listener_parse_private_wrap_and_http_writer_keep_unquoted_number_lexicals()
    -> Result<(), Box<dyn std::error::Error>> {
        for number in ["1.0", "1E+0", "-0", "-0.0", "18446744073709551616", "1e309"] {
            let body = format!("{{\"number\":{number},\"string\":\"{number}\"}}");
            let wire = format!(
                "POST /v1/sys/wrapping/wrap HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Vault-Wrap-TTL: 60\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body,
            );
            let mut request = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
                .map_err(|_| io::Error::other("actual listener rejected literal"))?;
            let tree = request
                .lexical_wrapping_body
                .take()
                .ok_or("private tree absent")?;
            tree.validate_wrapping_view(&request.body.0)?;
            let _ingress =
                crate::auth::IngressReplyScope::listener_wrapping(&[0x88; 16], Some(tree));
            let (mut state, root) = crate::auth::AuthState::bootstrap(100)?;
            let admin = state.authenticate(&root, 100)?;
            let wrapped = state.wrap_logical_response(
                "",
                &request.path,
                60,
                &json!({"data":request.body.0.clone()}),
                100,
            )?;
            let token = wrapped.body["wrap_info"]["token"]
                .as_str()
                .ok_or("actual wrapper")?;
            let unwrapped = state.wrapping_route(
                Some(&admin),
                "",
                "POST",
                "sys/wrapping/unwrap",
                &json!({"token":token}),
                100,
            )?;
            let mut output = zeroize::Zeroizing::new(Vec::new());
            write_response(
                &mut *output,
                Response {
                    status: unwrapped.status,
                    body: unwrapped.body,
                    unwrapped_json: unwrapped.unwrapped_json,
                    response_headers: Default::default(),
                    consistency_index: None,
                },
                false,
            )?;
            let boundary = output
                .windows(4)
                .position(|b| b == b"\r\n\r\n")
                .ok_or("HTTP boundary")?;
            let bytes = &output[boundary + 4..];
            let parsed = crate::auth::LexicalJson::parse_listener(bytes)?;
            let crate::auth::LexicalJson::Object(fields) = &parsed else {
                return Err("full object".into());
            };
            assert_eq!(fields.len(), 8);
            let crate::auth::LexicalJson::Object(data) = &fields["data"] else {
                return Err("real data".into());
            };
            assert!(
                matches!(&data["number"],crate::auth::LexicalJson::Number(value) if value==number)
            );
            assert!(
                matches!(&data["string"],crate::auth::LexicalJson::String(value) if value==number)
            );
            assert_eq!(bytes.last(), Some(&b'}')); // Stored generic JSON has no added LF.
            assert!(
                state
                    .wrapping_route(
                        Some(&admin),
                        "",
                        "POST",
                        "sys/wrapping/unwrap",
                        &json!({"token":token}),
                        100
                    )
                    .is_err()
            );
        }
        Ok(())
    }
    #[test]
    fn raw113_actual_listener_carrier_is_opaque_wrap_only_and_cannot_be_claimed_by_data()
    -> Result<(), Box<dyn std::error::Error>> {
        for body in [
            r#"{"$serde_json::private::Number":"1.0"}"#,
            r#"{"number":"1.0","kind":"general-json-envelope-v1"}"#,
        ] {
            let wire = format!(
                "POST /v1/sys/wrapping/wrap HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let request = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
                .map_err(|_| io::Error::other("literal object rejected"))?;
            let tree = request
                .lexical_wrapping_body
                .as_ref()
                .ok_or("actual body tree")?;
            let crate::auth::LexicalJson::Object(fields) = tree else {
                return Err("object".into());
            };
            assert!(
                fields
                    .values()
                    .all(|value| matches!(value, crate::auth::LexicalJson::String(_)))
            );
        }
        let overflow = r#"{"number":1e309}"#;
        let ordinary = format!(
            "POST /v1/some-sdk-float HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            overflow.len(),
            overflow
        );
        assert!(read_request(&mut ordinary.as_bytes(), Duration::from_secs(1)).is_err());
        let ordinary = r#"{"number":1.0}"#;
        let wire = format!(
            "POST /v1/some-sdk-float HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            ordinary.len(),
            ordinary
        );
        let request = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
            .map_err(|_| io::Error::other("ordinary typed input"))?;
        assert!(request.lexical_wrapping_body.is_none());
        assert_eq!(request.body.0["number"].as_f64(), Some(1.0));
        let duplicate = r#"{"number":1,"number":2}"#;
        let wire = format!(
            "POST /v1/sys/wrapping/wrap HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            duplicate.len(),
            duplicate
        );
        let request = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
            .map_err(|_| io::Error::other("primary duplicate map input"))?;
        assert_eq!(request.path, "sys/wrapping/wrap");
        let tree = request
            .lexical_wrapping_body
            .as_ref()
            .ok_or("actual listener tree")?;
        let crate::auth::LexicalJson::Object(fields) = tree else {
            return Err("actual listener object".into());
        };
        assert_eq!(fields.len(), 1);
        assert!(matches!(
            fields.get("number"), Some(crate::auth::LexicalJson::Number(number)) if number == "2"
        ));
        assert_eq!(request.body.0["number"].as_i64(), Some(2));
        tree.validate_wrapping_view(&request.body.0)?;
        let mut forged_string = request.body.0.clone();
        forged_string["number"] = json!("2");
        assert!(tree.validate_wrapping_view(&forged_string).is_err());
        crate::service::erase_json(&mut forged_string);
        Ok(())
    }

    #[test]
    fn pki_acme99_owned_raw_json_native_chunk_boundary_retains_exact_body() -> io::Result<()> {
        for length in [2048, 2049] {
            let payload = json!({"text":"x".repeat(length-11)});
            let bytes = serde_json::to_vec(&payload)?;
            assert_eq!(bytes.len(), length);
            for head in [false, true] {
                let response = Response {
                    status: 200,
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    body: json!({"__heptabao_acme":payload,"media":"json"}),
                };
                let mut output = Vec::new();
                write_response(&mut output, response, head)?;
                let marker = output
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .ok_or_else(|| io::Error::other("missing response framing"))?;
                let headers = std::str::from_utf8(&output[..marker]).map_err(io::Error::other)?;
                let body = &output[marker + 4..];
                assert!(headers.contains("Content-Type: application/json\r\n"));
                if length == 2048 {
                    assert!(headers.contains("Content-Length: 2048\r\n"));
                    assert!(!headers.contains("Transfer-Encoding"));
                    assert_eq!(body, if head { &[][..] } else { bytes.as_slice() });
                } else if head {
                    assert!(
                        !headers.contains("Content-Length")
                            && !headers.contains("Transfer-Encoding")
                    );
                    assert!(body.is_empty());
                } else {
                    assert!(
                        headers.contains("Transfer-Encoding: chunked\r\n")
                            && !headers.contains("Content-Length")
                    );
                    let mut framed = format!("{:x}\r\n", bytes.len()).into_bytes();
                    framed.extend_from_slice(&bytes);
                    framed.extend_from_slice(b"\r\n0\r\n\r\n");
                    assert_eq!(body, framed);
                }
            }
        }
        Ok(())
    }
    #[test]
    fn pki_acme99_untrusted_sdk_data_cannot_select_raw_media_or_empty_body()
    -> Result<(), Box<dyn std::error::Error>> {
        // finalize_sdk_transaction places plugin-controlled Data under this
        // server-owned data key. Test the actual transport writer with both
        // valid raw marker shapes nested exactly at that untrusted boundary.
        for data in [
            json!({"__heptabao_acme":{"type":"urn:untrusted:problem","detail":"plugin-controlled"},"media":"problem"}),
            json!({"__heptabao_acme":null,"media":"empty"}),
            json!({"__heptabao_acme":{"nested":"plugin-controlled"},"media":"json"}),
            json!({"__heptabao_acme":"-----BEGIN CERTIFICATE-----\nplugin controlled\n-----END CERTIFICATE-----\n","media":"certificate"}),
        ] {
            let body = json!({"data":data});
            let mut wire = Vec::new();
            write_response(
                &mut wire,
                Response {
                    status: 200,
                    body: body.clone(),
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                },
                false,
            )?;
            let separator = wire
                .windows(4)
                .position(|v| v == b"\r\n\r\n")
                .ok_or("HTTP separator")?;
            let headers = std::str::from_utf8(&wire[..separator])?;
            assert!(
                headers.contains("Content-Type: application/json\r\n")
                    || headers.ends_with("Content-Type: application/json")
            );
            assert!(!headers.contains("application/problem+json"));
            let actual = &wire[separator + 4..];
            assert_eq!(serde_json::from_slice::<Value>(actual)?, body);
            assert!(
                actual.ends_with(b"\n"),
                "ordinary logical JSON keeps its framing"
            );
        }
        // The real closed producer marker still selects the exact compact
        // Problem encoding, so the negative cases exercise an active branch.
        let mut wire = Vec::new();
        write_response(
            &mut wire,
            Response {
                status: 400,
                body: json!({"__heptabao_acme":{"type":"urn:ietf:params:acme:error:malformed","detail":"actual closed producer"},"media":"problem"}),
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
            },
            false,
        )?;
        assert!(
            wire.windows(b"Content-Type: application/problem+json".len())
                .any(|v| v == b"Content-Type: application/problem+json")
        );
        assert!(wire.ends_with(
            br#"{"type":"urn:ietf:params:acme:error:malformed","detail":"actual closed producer"}"#
        ));
        Ok(())
    }

    #[test]
    fn pki_acme99_jose_json_codec_keeps_framing_namespace_and_actual_route() -> io::Result<()> {
        let body = r#"{"protected":"actual","payload":"","signature":"actual"}"#;
        let wire = format!(
            "POST /v1/nested/pki/acme/new-account HTTP/1.1\r\nHost: localhost\r\nX-Vault-Namespace: team/\r\nContent-Type: application/jose+json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let request = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
            .map_err(|_| io::Error::other("ACME JWS body codec"))?;
        assert_eq!(request.path, "nested/pki/acme/new-account");
        assert_eq!(request.namespace, "team");
        assert!(request.token.is_empty());
        assert_eq!(request.body.0, serde_json::from_str::<Value>(body)?);
        let trailing = format!("{wire}extra");
        assert!(read_request(&mut trailing.as_bytes(), Duration::from_secs(1)).is_err());
        let ordinary = wire.replace("nested/pki/acme/new-account", "secret/item");
        assert!(read_request(&mut ordinary.as_bytes(), Duration::from_secs(1)).is_err());
        Ok(())
    }
    #[test]
    fn head_operation_keeps_original_query_values_and_does_not_select_list() -> io::Result<()> {
        let wire = "HEAD /v1/secret/ocsp/plainkey?list=true&unknown=one&unknown=two&help= HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n";
        let request = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
            .map_err(|_| io::Error::other("bounded HEAD query"))?;
        assert_eq!(request.method, "HEAD");
        let carrier = ocsp::query_request("HEAD", &request.path, &request.body.0)
            .ok_or_else(|| io::Error::other("request-local header carrier"))?;
        let (method, body) = carrier
            .resolve(true)
            .map_err(|_| io::Error::other("Go query values"))?;
        assert_eq!(method, "HEAD");
        assert_eq!(body.0["unknown"], json!(["one", "two"]));
        assert_eq!(body.0["list"], "true");
        assert!(body.0.get("help").is_none());
        Ok(())
    }

    #[test]
    fn kv2_320k_json_is_delivered_by_original_http_parser_but_larger_framing_is_still_denied()
    -> io::Result<()> {
        let value = "K".repeat(320 * 1024);
        let encoded = serde_json::to_vec(&json!({"data":{"payload":value}}))?;
        assert!(encoded.len() > 256 * 1024 && encoded.len() <= MAX_BODY);
        let mut wire = format!(
            "POST /v1/synthetic/data/large HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        ).into_bytes();
        wire.extend_from_slice(&encoded);
        let request = read_request_mode(&mut wire.as_slice(), Duration::from_secs(3), false)
            .map_err(|_| io::Error::other("320 KiB KV2 JSON failed bounded parser"))?;
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "synthetic/data/large");
        assert_eq!(
            request.body.0["data"]["payload"].as_str().map(str::len),
            Some(320 * 1024)
        );
        // A request above the transport cap is rejected and never decoded.
        let oversized = MAX_KV2_JSON_WRITE_BODY + 1;
        let mut header = format!(
            "POST /v1/synthetic/data/exceeded HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {oversized}\r\n\r\n"
        ).into_bytes();
        header.extend(std::iter::repeat_n(b'X', oversized));
        let mut input = header.as_slice();
        let denial = read_request_mode(&mut input, Duration::from_secs(3), false)
            .err()
            .ok_or_else(|| io::Error::other("oversized request unexpectedly accepted"))?;
        assert_eq!(denial.status, 413);
        assert!(
            input.is_empty(),
            "bounded rejection must drain the declared body"
        );
        Ok(())
    }

    #[test]
    fn kv2_768k_json_keeps_full_body_and_a_strict_scoped_transport_fence() -> io::Result<()> {
        // OpenBao 2.7.1 accepts this 768 KiB KV2 payload, while the former
        // 512 KiB front-door limit returned 413 before any Service decision.
        // Retain exactly one bounded JSON parser and reject larger requests.
        let value = "R".repeat(768 * 1024);
        let encoded = serde_json::to_vec(&json!({"data":{"payload":value}}))?;
        assert!(encoded.len() > 512 * 1024 && encoded.len() <= MAX_BODY);
        const { assert!(MAX_413_DRAIN_BODY_BYTES > MAX_BODY) };
        let mut wire = format!(
            "POST /v1/secret/data/768k HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        ).into_bytes();
        wire.extend_from_slice(&encoded);
        let request = read_request_mode(&mut wire.as_slice(), Duration::from_secs(3), false)
            .map_err(|_| io::Error::other("768 KiB KV2 JSON failed bounded parser"))?;
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "secret/data/768k");
        assert_eq!(
            request.body.0["data"]["payload"].as_str().map(str::len),
            Some(768 * 1024)
        );
        Ok(())
    }

    #[test]
    fn kv2_2560k_ingress_matches_bounded_official_271_without_global_relaxation() -> io::Result<()>
    {
        let payload = "R".repeat(2560 * 1024);
        let encoded = serde_json::to_vec(&json!({"data":{"payload":payload}}))?;
        assert!(encoded.len() > MAX_BODY && encoded.len() < MAX_KV2_JSON_WRITE_BODY);
        assert_eq!(
            json_ingress_body_limit("POST", "secret/data/large", Some("application/json")),
            MAX_KV2_JSON_WRITE_BODY,
        );
        assert_eq!(
            json_ingress_body_limit("PUT", "openclaw-auth/data/large", Some("application/json")),
            MAX_KV2_JSON_WRITE_BODY,
        );
        let mut input = format!(
            "POST /v1/secret/data/large HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        ).into_bytes();
        input.extend_from_slice(&encoded);
        let parsed = read_request_mode(&mut input.as_slice(), Duration::from_secs(7), false)
            .map_err(|_| io::Error::other("official KV2 2560K input rejected by scoped ingress"))?;
        assert_eq!(parsed.path, "secret/data/large");
        assert_eq!(
            parsed.body.0["data"]["payload"].as_str(),
            Some(payload.as_str())
        );
        Ok(())
    }

    #[test]
    fn kv2_2560k_json_media_case_parity_fixture() -> io::Result<()> {
        // Official OpenBao 2.7.1 HTTPS oracle returns 200 for each media
        // variant. This fixture must not broaden privileged routes.
        for media in [
            "application/json",
            "Application/JSON",
            "application/JSON",
            "APPLICATION/JSON",
        ] {
            assert_eq!(
                json_ingress_body_limit("POST", "r752/team-secret/data/test", Some(media)),
                MAX_KV2_JSON_WRITE_BODY,
                "KV2 media rejected: {media}",
            );
            for denied in [
                "sys/mounts/r752/data/item",
                "auth/approle/data/item",
                "pki/data/item",
                "r752/../secret/data/item",
                "r752//secret/data/item",
                "r752/%2e/data/item",
            ] {
                assert_eq!(
                    json_ingress_body_limit("POST", denied, Some(media)),
                    MAX_BODY,
                    "privileged/ambiguous route widened: {denied}",
                );
            }
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "data": {"payload": "J".repeat(2560 * 1024)}
        }))?;
        assert!(body.len() > MAX_BODY && body.len() < MAX_KV2_JSON_WRITE_BODY);
        let mut frame = format!(
            "POST /v1/r752/team-secret/data/item HTTP/1.1\r\nHost: localhost\r\nContent-Type: Application/JSON\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ).into_bytes();
        frame.extend_from_slice(&body);
        let parsed = read_request_mode(&mut frame.as_slice(), Duration::from_secs(10), false)
            .map_err(|err| io::Error::other(format!("scoped JSON parse status {}", err.status)))?;
        assert_eq!(parsed.path, "r752/team-secret/data/item");
        assert_eq!(
            parsed.body.0["data"]["payload"].as_str().map(str::len),
            Some(2560 * 1024),
        );
        // The scoped large body does not permit a privileged API request.
        let mut denied = format!(
            "POST /v1/sys/mounts/r752/data/item HTTP/1.1\r\nHost: localhost\r\nContent-Type: Application/JSON\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ).into_bytes();
        denied.extend_from_slice(&body);
        let rejected = read_request_mode(&mut denied.as_slice(), Duration::from_secs(10), false)
            .err()
            .ok_or_else(|| io::Error::other("privileged large JSON admitted"))?;
        assert_eq!(rejected.status, 413);
        Ok(())
    }

    #[test]
    fn kv2_nested_mount_2560k_keeps_scoped_json_ingress_parity() {
        // OpenBao 2.7.1 writes 2560 KiB at multi-segment mounts. A
        // single-prefix-only parser must fail this regression before Service.
        assert_eq!(
            json_ingress_body_limit(
                "POST",
                "r721/team-secret/data/value-2560",
                Some("application/json"),
            ),
            MAX_KV2_JSON_WRITE_BODY,
        );
        for route in ["tenant/secret/data/nested", "tenant/data/secret/data/item"] {
            assert_eq!(
                json_ingress_body_limit("PUT", route, Some("application/json")),
                MAX_KV2_JSON_WRITE_BODY,
            );
        }
        for route in [
            "sys/secret/data/item",
            "auth/tenant/data/item",
            "tenant/../secret/data/item",
            "tenant//secret/data/item",
            "tenant/%73ecret/data/item",
            "tenant/secret/data/../item",
            "tenant/secret/data",
        ] {
            assert_eq!(
                json_ingress_body_limit("POST", route, Some("application/json")),
                MAX_BODY,
                "ambiguous or reserved path admitted: {route}",
            );
        }
    }

    #[test]
    fn scoped_kv2_larger_json_does_not_promote_other_routes_or_ambiguous_framing() -> io::Result<()>
    {
        for (method, route, media) in [
            ("POST", "sys/health", "application/json"),
            ("POST", "auth/approle/login", "application/json"),
            ("POST", "pki/data/large", "application/json"),
            ("POST", "transit/data/large", "application/json"),
            ("POST", "secret/data/large", "application/merge-patch+json"),
            ("PATCH", "secret/data/large", "application/json"),
            ("GET", "secret/data/large", "application/json"),
            ("POST", "secret/%64ata/large", "application/json"),
            ("POST", "secret/data/../large", "application/json"),
            ("POST", "secret/data//large", "application/json"),
        ] {
            assert_eq!(
                json_ingress_body_limit(method, route, Some(media)),
                MAX_BODY
            );
        }
        let count = MAX_BODY + 1;
        for route in ["sys/health", "auth/approle/login", "pki/data/large"] {
            let mut input = format!(
                "POST /v1/{route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {count}\r\n\r\n"
            ).into_bytes();
            input.extend(std::iter::repeat_n(b'Q', count));
            let err = read_request_mode(&mut input.as_slice(), Duration::from_secs(5), false)
                .err()
                .ok_or_else(|| io::Error::other("non-KV2 body exceeded 2 MiB without rejection"))?;
            assert_eq!(err.status, 413);
        }
        assert_eq!(
            json_ingress_body_limit(
                "POST",
                "secret/data/item",
                Some("application/json; charset=utf-8")
            ),
            MAX_KV2_JSON_WRITE_BODY,
        );
        assert_eq!(
            json_ingress_body_limit("POST", "secret/data/item", None),
            MAX_BODY
        );
        Ok(())
    }

    #[test]
    fn kv2_1536k_json_preserves_all_bytes_but_over_kv_bound_is_413() -> io::Result<()> {
        // Pinned OpenBao 2.7.1 accepted this previously rejected input.
        // The codec has no implicit truncation, rounding, or Service grant.
        let payload = "J".repeat(1536 * 1024);
        let encoded = serde_json::to_vec(&json!({"data":{"payload":payload}}))?;
        assert!(encoded.len() > 1024 * 1024 && encoded.len() < MAX_BODY);
        assert_eq!(MAX_BODY, 2 * 1024 * 1024);
        assert_eq!(MAX_413_DRAIN_BODY_BYTES, 2 * MAX_BODY);
        let mut wire = format!(
            "POST /v1/secret/data/1536k HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        ).into_bytes();
        wire.extend_from_slice(&encoded);
        let parsed = read_request_mode(&mut wire.as_slice(), Duration::from_secs(5), false)
            .map_err(|_| io::Error::other("1536 KiB OpenBao KV2 control rejected"))?;
        assert_eq!(parsed.path, "secret/data/1536k");
        assert_eq!(
            parsed.body.0["data"]["payload"].as_str(),
            Some(payload.as_str())
        );

        // First byte over the new cap is not parsed; declared bodies within the
        // independent drain budget can still yield a complete TLS 413 response.
        let exceeded = MAX_KV2_JSON_WRITE_BODY + 1;
        let mut oversized = format!(
            "POST /v1/secret/data/over-limit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {exceeded}\r\n\r\n"
        ).into_bytes();
        oversized.extend(std::iter::repeat_n(b'x', exceeded));
        let mut remaining = oversized.as_slice();
        let denial = read_request_mode(&mut remaining, Duration::from_secs(5), false)
            .err()
            .ok_or_else(|| io::Error::other("scoped KV2 JSON cap bypass"))?;
        assert_eq!(denial.status, 413);
        assert!(remaining.is_empty(), "bounded 413 body not drained");
        Ok(())
    }

    #[test]
    fn oversized_json_413_drains_only_bounded_unambiguous_framing() -> io::Result<()> {
        for count in [
            MAX_KV2_JSON_WRITE_BODY + 1,
            MAX_KV2_JSON_WRITE_BODY + 64 * 1024,
            MAX_413_DRAIN_BODY_BYTES,
        ] {
            let mut wire = format!(
                "POST /v1/secret/data/denied HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {count}\r\n\r\n"
            )
            .into_bytes();
            wire.extend(std::iter::repeat_n(b'x', count));
            let mut reader = wire.as_slice();
            let err = read_request_mode(&mut reader, Duration::from_secs(3), false)
                .err()
                .ok_or_else(|| io::Error::other("oversized body must not enter service"))?;
            assert_eq!(err.status, 413);
            assert!(
                reader.is_empty(),
                "bounded body must be consumed before 413"
            );
        }
        let count = MAX_413_DRAIN_BODY_BYTES + 1;
        let mut wire = format!(
            "POST /v1/secret/data/denied HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {count}\r\n\r\n"
        ).into_bytes();
        wire.extend(std::iter::repeat_n(b'x', count));
        let mut reader = wire.as_slice();
        let err = read_request_mode(&mut reader, Duration::from_secs(3), false)
            .err()
            .ok_or_else(|| io::Error::other("oversized body must be rejected"))?;
        assert_eq!(err.status, 413);
        assert!(!reader.is_empty(), "large bodies must not be fully drained");

        // A malformed framing claim is never an instruction to swallow bytes.
        let mut invalid = b"POST /v1/secret/data/denied HTTP/1.1\r\nHost: localhost\r\nContent-Length: 400000\r\nTransfer-Encoding: chunked\r\n\r\nbody".as_slice();
        let error = read_request_mode(&mut invalid, Duration::from_secs(1), false)
            .err()
            .ok_or_else(|| io::Error::other("ambiguous framing rejected"))?;
        assert_eq!(error.status, 400);
        // The bounded header read may already contain the short trailing body.
        // The framing itself must be rejected before parsing any JSON.
        Ok(())
    }

    #[test]
    fn invalid_uri_path_and_conflicting_lengths_remain_outer_failures() -> io::Result<()> {
        for method in ["GET", "HEAD", "HELP"] {
            let wire = format!(
                "{method} /v1/pki/ocsp/%GG HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
            );
            let error = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
                .err()
                .ok_or_else(|| io::Error::other("bad URI admitted"))?;
            assert_eq!(error.status, 400);
            assert!(error.outer_bad_request);
        }
        let wire = "HEAD /v1/secret/a?help=true HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n";
        let error = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
            .err()
            .ok_or_else(|| io::Error::other("conflicting framing admitted"))?;
        assert!(error.outer_bad_request);
        let mut raw = Vec::new();
        snapshot::NativeReply::HttpBadRequest.write(&mut raw, true)?;
        assert!(raw.ends_with(b"\r\n\r\n400 Bad Request"));
        Ok(())
    }

    #[test]
    fn ocsp_raw_transport_retains_framing_mount_namespace_and_closed_output() -> io::Result<()> {
        use base64::Engine as _;
        for suffix in ["AA+/=", "AA%2B%2F%3D"] {
            let wire = format!(
                "GET /v1/nested/pki/ocsp/{suffix} HTTP/1.1\r\nHost: localhost\r\nX-Vault-Namespace: team/\r\nContent-Length: 2\r\n\r\n{{}}"
            );
            let request = read_request(&mut wire.as_bytes(), Duration::from_secs(1))
                .map_err(|_| io::Error::other("bounded OCSP GET"))?;
            assert_eq!(request.path, format!("nested/pki/ocsp/{suffix}"));
            assert_eq!(request.namespace, "team");
            assert_eq!(
                request.body.0["__heptabao_pki_ocsp_get_path"]["path"],
                request.path
            );
            assert_eq!(request.body.0["__heptabao_pki_ocsp_get_path"]["query"], "");
        }
        for size in [0, 4, 2047, 2048, 4096] {
            let mut wire=format!("POST /v1/pki/ocsp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ocsp-request\r\nContent-Length: {size}\r\n\r\n").into_bytes();
            wire.extend(vec![7; size]);
            let request = read_request(&mut wire.as_slice(), Duration::from_secs(1))
                .map_err(|_| io::Error::other("bounded OCSP POST"))?;
            assert_eq!(request.path, "pki/ocsp");
            let encoded = request.body.0["__heptabao_pki_ocsp_raw_post"]["encoded"]
                .as_str()
                .ok_or_else(|| io::Error::other("OCSP marker"))?;
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .ok(),
                Some(vec![7; size])
            );
        }
        for wire in [
            "POST /v1/pki/ocsp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ocsp-request\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nDER!",
            "POST /v1/pki/ocsp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ocsp-request\r\nContent-Length: 4\r\n\r\nDER!tail",
            "GET /v1/pki/ocsp/AA== HTTP/1.1\r\nHost: localhost\r\nX-Vault-Namespace: team//other\r\n\r\n",
            "GET /v1/p%6bi/ocsp/AA== HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ] {
            assert!(read_request(&mut wire.as_bytes(), Duration::from_secs(1)).is_err());
        }
        for (status, byte) in [(400, 1u8), (401, 6), (500, 2)] {
            let payload = [0x30, 3, 0x0a, 1, byte];
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
            let mut output = Vec::new();
            write_response(
                &mut output,
                Response {
                    status,
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    body: json!({"__heptabao_pki_ocsp_response":encoded}),
                },
                false,
            )?;
            assert!(
                output
                    .windows(b"Content-Type: application/ocsp-response".len())
                    .any(|v| v == b"Content-Type: application/ocsp-response")
            );
            assert!(output.ends_with(&payload));
            let mut invalid = Vec::new();
            write_response(
                &mut invalid,
                Response {
                    status,
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    body: json!({"__heptabao_pki_ocsp_response":encoded,"extra":true}),
                },
                false,
            )?;
            assert!(
                invalid
                    .windows(b"Content-Type: application/json".len())
                    .any(|v| v == b"Content-Type: application/json")
            );
        }
        Ok(())
    }
    #[test]
    fn pki_public_certificate_transport_has_closed_mime_and_canonical_bounds() -> io::Result<()> {
        use base64::Engine as _;
        let payload = [0x30, 0x00];
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        for (format, media) in [
            ("der", "application/pkix-cert"),
            ("pem", "application/pem-certificate-chain"),
            ("chain", "application/pkix-cert"),
        ] {
            let response = || Response {
                status: 200,
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
                body: json!({"__heptabao_pki_certificate":encoded,"format":format}),
            };
            let mut wire = Vec::new();
            write_response(&mut wire, response(), false)?;
            let header = format!("Content-Type: {media}\r\n");
            assert!(
                wire.windows(header.len())
                    .any(|bytes| bytes == header.as_bytes()),
                "closed public certificate MIME"
            );
            assert!(
                wire.ends_with(&payload),
                "public certificate transport preserves exact bytes"
            );
            let mut head = Vec::new();
            write_response(&mut head, response(), true)?;
            assert!(
                head.ends_with(b"\r\n\r\n"),
                "HEAD withholds all public certificate payload"
            );
        }
        for body in [
            json!({"__heptabao_pki_certificate":encoded,"format":"text/html"}),
            json!({"__heptabao_pki_certificate":"MAA","format":"der"}),
            json!({"__heptabao_pki_certificate":encoded,"format":"der","extra":true}),
            json!({"__heptabao_pki_certificate":base64::engine::general_purpose::STANDARD.encode(vec![0;128*1024+1]),"format":"der"}),
        ] {
            let mut wire = Vec::new();
            write_response(
                &mut wire,
                Response {
                    status: 200,
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    body,
                },
                false,
            )?;
            assert!(
                wire.windows(b"Content-Type: application/json".len())
                    .any(|bytes| bytes == b"Content-Type: application/json"),
                "unknown/noncanonical/oversize envelope remains JSON"
            );
        }
        Ok(())
    }
    #[test]
    fn raw_acme_problem_uses_go_html_escape_and_final_content_length() -> io::Result<()> {
        let detail = "actual <nil> & > \u{2028} \u{2029}";
        let mut wire = Vec::new();
        write_response(
            &mut wire,
            Response {
                status: 400,
                body: json!({"__heptabao_acme":{"type":"urn:ietf:params:acme:error:malformed","detail":detail},"media":"problem"}),
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
            },
            false,
        )?;
        let boundary = wire
            .windows(4)
            .position(|b| b == b"\r\n\r\n")
            .ok_or_else(|| io::Error::other("missing actual HTTP response boundary"))?
            + 4;
        let headers = String::from_utf8_lossy(&wire[..boundary]);
        let body = &wire[boundary..];
        assert!(headers.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(
            body.windows(b"\\u003cnil\\u003e".len())
                .any(|v| v == b"\\u003cnil\\u003e")
        );
        for escaped in [b"\\u0026", b"\\u2028", b"\\u2029"] {
            assert!(body.windows(escaped.len()).any(|v| v == escaped));
        }
        let decoded: Value = serde_json::from_slice(body)?;
        assert_eq!(decoded["detail"], detail);
        Ok(())
    }

    #[test]
    fn deleted_pki_root_empty_crl_retains_only_closed_raw_content_type() -> io::Result<()> {
        for (encoded, expected) in [("", "application/pkix-crl"), ("MAA=", "application/json")] {
            let mut wire = Vec::new();
            write_response(
                &mut wire,
                Response {
                    status: 204,
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    body: json!({"__heptabao_pki_crl":encoded,"pem":false}),
                },
                false,
            )?;
            let head = wire.split(|byte| *byte == b'\n').collect::<Vec<_>>();
            assert!(
                head.iter()
                    .any(|line| line.starts_with(format!("Content-Type: {expected}").as_bytes())),
                "204 can select CRL MIME only for the canonical empty envelope"
            );
            assert!(wire.ends_with(b"\r\n\r\n"), "204 emits no public body");
        }
        Ok(())
    }

    #[test]
    fn external_pki_crl_transport_is_bounded_and_has_a_closed_content_type() -> io::Result<()> {
        use base64::Engine as _;
        let der = [0x30, 0x00];
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        let response = || Response {
            status: 200,
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
            body: json!({"__heptabao_pki_crl":encoded,"pem":false}),
        };
        let mut wire = Vec::new();
        write_response(&mut wire, response(), false)?;
        assert!(
            wire.windows(b"Content-Type: application/pkix-crl".len())
                .any(|bytes| bytes == b"Content-Type: application/pkix-crl"),
            "closed CRL MIME type"
        );
        assert!(wire.ends_with(&der), "raw CRL bytes are preserved");
        let mut head = Vec::new();
        write_response(&mut head, response(), true)?;
        assert!(
            head.ends_with(b"\r\n\r\n") && !head.ends_with(&der),
            "HEAD has no raw CRL payload"
        );
        let mut rejected = Vec::new();
        write_response(
            &mut rejected,
            Response {
                status: 200,
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
                body: json!({"__heptabao_pki_crl":encoded,"pem":"text/html"}),
            },
            false,
        )?;
        assert!(
            rejected
                .windows(b"Content-Type: application/json".len())
                .any(|bytes| bytes == b"Content-Type: application/json"),
            "untrusted content type stays JSON"
        );
        Ok(())
    }

    #[test]
    fn capacity_guard_config_requires_explicit_fixture_feature() {
        let value = json!({
            "listen":"127.0.0.1:8200", "data_dir":"/synthetic/data",
            "audit_file":"/synthetic/audit.jsonl",
            "tls_cert_file":"/synthetic/cert.pem", "tls_key_file":"/synthetic/key.pem",
            "fixture_opaque_owner_limit_bytes": 2 * 1024 * 1024
        });
        #[cfg(not(feature = "fixture-capacity-limit"))]
        assert!(serde_json::from_value::<Config>(value).is_err());
        #[cfg(feature = "fixture-capacity-limit")]
        assert_eq!(
            serde_json::from_value::<Config>(value)
                .ok()
                .and_then(|config| config.fixture_opaque_owner_limit_bytes),
            Some(2 * 1024 * 1024)
        );
    }
    use super::*;

    #[test]
    fn optional_client_auth_requires_explicit_roots_and_keeps_mandatory_default()
    -> Result<(), String> {
        let mut value = json!({
            "listen":"127.0.0.1:0", "data_dir":"/unused-data", "audit_file":"/unused-audit",
            "tls_cert_file":"/unused-cert", "tls_key_file":"/unused-key"
        });
        let config: Config = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        assert!(!config.tls_client_auth_optional);
        value["tls_client_auth_optional"] = json!(true);
        let config: Config = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        assert_eq!(
            serve(config),
            Err("optional TLS client authentication requires a client CA bundle".into())
        );
        value["tls_client_auth_optional"] = Value::Null;
        assert!(serde_json::from_value::<Config>(value).is_err());
        Ok(())
    }

    #[test]
    fn optional_client_verifier_still_requests_and_checks_presented_certificates()
    -> Result<(), String> {
        use rustls::pki_types::{CertificateDer, UnixTime};
        let ca =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/testdata/kubernetes-api-ca.pem");
        let data = PathBuf::from("/unused-data");
        for optional in [false, true] {
            let verifier = load_client_verifier(
                &ca,
                None,
                optional,
                &data,
                Arc::new(rustls::crypto::ring::default_provider()),
            )?;
            assert!(verifier.offer_client_auth());
            assert_eq!(verifier.client_auth_mandatory(), !optional);
            assert!(!verifier.root_hint_subjects().is_empty());
            // Optional authentication must never turn a supplied invalid chain
            // into an anonymous connection. Real chain/EKU cases run over TLS.
            assert!(
                verifier
                    .verify_client_cert(
                        &CertificateDer::from(vec![0_u8; 32]),
                        &[],
                        UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000))
                    )
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn rate_limiter_enforces_burst_refill_and_bounded_peer_table() -> Result<(), String> {
        let mut limiter = RateLimiter::new(2, 3, 64)?;
        let first: IpAddr = "192.0.2.1".parse().map_err(|_| "invalid test address")?;
        assert!(limiter.allow_at(first, 0));
        assert!(limiter.allow_at(first, 0));
        assert!(limiter.allow_at(first, 0));
        assert!(!limiter.allow_at(first, 0));
        assert!(!limiter.allow_at(first, TOKEN_SCALE / 4));
        assert!(limiter.allow_at(first, TOKEN_SCALE / 2));

        for suffix in 2..=64 {
            let peer: IpAddr = format!("192.0.2.{suffix}")
                .parse()
                .map_err(|_| "invalid test address")?;
            assert!(limiter.allow_at(peer, TOKEN_SCALE / 2));
        }
        let overflow: IpAddr = "198.51.100.1".parse().map_err(|_| "invalid test address")?;
        assert!(!limiter.allow_at(overflow, TOKEN_SCALE / 2));
        assert!(limiter.allow_at(overflow, RATE_BUCKET_IDLE_NANOS + TOKEN_SCALE));
        Ok(())
    }

    #[test]
    fn rate_limit_configuration_rejects_disabled_or_unbounded_values() {
        assert!(RateLimiter::new(0, 1, 64).is_err());
        assert!(RateLimiter::new(10, 10, 63).is_err());
        assert!(RateLimiter::new(100_001, 100_001, 64).is_err());
    }
    #[test]
    fn rejects_smuggling_duplicate_headers_and_ambiguous_paths() {
        for request in [
            "POST /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "POST /v1/a HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET /v1/a%2fb HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /v1/a HTTP/1.1\r\nHost: localhost\r\n\r\nignored",
        ] {
            assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        }
    }
    #[test]
    fn reads_versioned_request_without_mutating_secret_body() -> Result<(), String> {
        let text = "GET /v1/secret/data/a?version=2 HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: synthetic\r\n\r\n";
        let r = read_request(&mut text.as_bytes(), Duration::from_secs(1))
            .map_err(|e| e.message.to_owned())?;
        assert_eq!(r.path, "secret/data/a");
        let carrier =
            ocsp::query_request(&r.method, &r.path, &r.body.0).ok_or("private query carrier")?;
        let (method, strict) = carrier.resolve(false).map_err(|_| "strict owner query")?;
        assert_eq!(method, "GET");
        assert_eq!(strict.0, json!({"version":2}));
        assert_eq!(r.body.0["__heptabao_kv_read_query"]["query"], "version=2");
        Ok(())
    }

    #[test]
    fn rejects_duplicate_json_and_ambiguous_namespaces() {
        for namespace in ["/", "a//", "a//b", "///"] {
            let request = format!(
                "GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nX-Vault-Namespace: {namespace}\r\n\r\n"
            );
            assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        }
        let payload = r#"{"data":{"value":"first","value":"second"}}"#;
        let request = format!(
            "POST /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        for header in ["X-Vault-MFA", "X-Vault-Policy-Override"] {
            let request = format!(
                "GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n{header}: synthetic\r\n\r\n"
            );
            let result = read_request(&mut request.as_bytes(), Duration::from_secs(1));
            assert!(
                result.is_err_and(|error| error.status == 501),
                "unsupported security semantics must not silently return a raw secret"
            );
        }
        let request = "GET /v1/secret/data/a?token=synthetic HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let parsed = read_request(&mut request.as_bytes(), Duration::from_secs(1));
        assert!(parsed.is_ok_and(|request| {
            request.token.is_empty()
                && ocsp::query_request(&request.method, &request.path, &request.body.0)
                    .is_some_and(|carrier| carrier.resolve(false).is_err())
        }));
    }

    #[test]
    fn repeated_socket_reads_cannot_extend_connection_deadline() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (stream, _) = listener.accept()?;
        let mut stream = DeadlineStream {
            stream,
            deadline: Instant::now() + Duration::from_millis(80),
        };
        let sender = std::thread::spawn(move || {
            let mut client = client;
            for _ in 0..8 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let mut byte = [0; 1];
        let mut received = 0;
        while stream.read(&mut byte).is_ok_and(|count| count == 1) {
            received += 1;
        }
        assert!(received < 8, "slow fragments extended the fixed deadline");
        assert!(started.elapsed() < Duration::from_millis(400));
        drop(stream);
        sender
            .join()
            .map_err(|_| io::Error::other("sender thread failed"))?;
        Ok(())
    }
}

#[cfg(test)]
mod service_lock_deadline_tests {
    use super::*;

    #[test]
    fn slow_body_and_writer_wait_share_budget_before_mutating_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Directory(std::env::temp_dir().join(format!(
            "heptabao-http-deadline-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crypto::random::<8>()?),
        )));
        std::fs::create_dir(&root.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
        }
        let service = Arc::new(Mutex::new(Service::new(
            root.0.join("data"),
            &root.0.join("audit.jsonl"),
        )?));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (stream, _) = listener.accept()?;
        let deadline = Instant::now() + Duration::from_millis(250);
        let mut stream = DeadlineStream { stream, deadline };
        let sender = std::thread::spawn(move || -> io::Result<()> {
            let body = br#"{"secret_shares":1,"secret_threshold":1}"#;
            write!(
                client,
                "POST /v1/sys/init HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )?;
            std::thread::sleep(Duration::from_millis(40));
            client.write_all(body)
        });
        let mut parsed = read_request(&mut stream, Duration::from_secs(1))
            .map_err(|_| "synthetic slow request failed parsing")?;
        sender.join().map_err(|_| "synthetic sender panicked")??;
        // The body has consumed part of the accepted connection's budget.
        // Keep the writer busy beyond the remaining budget; no dispatch may run.
        let held = service.lock().map_err(|_| "test service poisoned")?;
        let response = execute_service_request(
            &service,
            ServiceRequest::new(
                &parsed.method,
                &parsed.path,
                &parsed.namespace,
                &parsed.token,
                std::mem::take(&mut parsed.body.0),
            ),
            deadline,
            false,
        );
        assert_eq!(response.status, 503);
        drop(held);
        let read = execute_service_request(
            &service,
            ServiceRequest::new("GET", "sys/init", "", "", Value::Null),
            Instant::now() + Duration::from_secs(1),
            false,
        );
        assert_eq!(read.status, 200);
        assert_eq!(read.body["initialized"], false);
        // A new connection is allowed a new budget: the same valid mutation
        // succeeds, proving the timed-out request was not a rejected test input.
        let mut initialized = execute_service_request(
            &service,
            ServiceRequest::new(
                "POST",
                "sys/init",
                "",
                "",
                json!({"secret_shares":1,"secret_threshold":1}),
            ),
            Instant::now() + Duration::from_secs(5),
            false,
        );
        assert_eq!(initialized.status, 200);
        crate::service::erase_json(&mut initialized.body);
        Ok(())
    }

    #[test]
    fn health_busy_writer_returns_negative_readiness_without_inventing_owner_state()
    -> Result<(), Box<dyn std::error::Error>> {
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Directory(std::env::temp_dir().join(format!(
            "heptabao-health-writer-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crypto::random::<8>()?),
        )));
        std::fs::create_dir(&root.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
        }
        let service = Arc::new(Mutex::new(Service::new(
            root.0.join("data"),
            &root.0.join("audit.jsonl"),
        )?));
        let held = service.lock().map_err(|_| "service lock")?;
        let start = Instant::now();
        let response = execute_service_request(
            &service,
            ServiceRequest::new("GET", "sys/health", "", "", json!({})),
            start + Duration::from_secs(5),
            false,
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(response.status, 503);
        assert_eq!(response.body["ha_active"], false);
        assert_eq!(response.body["ha_application_ready"], false);
        for unknown in [
            "initialized",
            "sealed",
            "standby",
            "cluster_id",
            "ha_enabled",
            "data",
            "auth",
        ] {
            assert!(response.body.get(unknown).is_none());
        }
        let response = execute_service_request(
            &service,
            ServiceRequest::new("POST", "sys/init", "", "", json!({})),
            Instant::now() + Duration::from_millis(10),
            false,
        );
        assert_eq!(response.status, 503);
        assert!(response.body.get("ha_active").is_none());
        drop(held);
        let response = execute_service_request(
            &service,
            ServiceRequest::new("GET", "sys/init", "", "", json!({})),
            Instant::now() + Duration::from_secs(1),
            false,
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["initialized"], false);
        Ok(())
    }

    #[test]
    fn response_reserve_only_shortens_one_existing_absolute_budget() {
        let now = Instant::now();
        for (remaining, reserved) in [
            (Duration::ZERO, Duration::ZERO),
            (Duration::from_millis(4), Duration::from_millis(1)),
            (Duration::from_millis(200), Duration::from_millis(50)),
            (Duration::from_secs(1), Duration::from_millis(250)),
            (Duration::from_secs(5), Duration::from_secs(1)),
            (Duration::from_secs(60), Duration::from_secs(1)),
        ] {
            let original = now + remaining;
            let execute = execution_deadline_with_response_reserve(now, original);
            assert_eq!(original.duration_since(execute), reserved);
            assert!(execute >= now && execute <= original);
        }
        let past = now - Duration::from_millis(1);
        assert_eq!(execution_deadline_with_response_reserve(now, past), past);
        let original = now + Duration::from_secs(1);
        let late = now + Duration::from_millis(960);
        assert_eq!(
            execution_deadline_with_response_reserve(late, original),
            original - Duration::from_millis(10)
        );
    }

    #[test]
    fn bounded_read_denial_retains_original_transport_for_late_audit_and_tcp()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let (socket, _) = listener.accept()?;
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        let execution = execution_deadline_with_response_reserve(now, deadline);
        // No caller may extend this five-second budget. A read that has
        // consumed its admitted execution window must still be able to send
        // a negative audited response through the original TCP writer.
        assert!(
            deadline.saturating_duration_since(execution) >= Duration::from_millis(900),
            "bounded read execution left insufficient response delivery reserve",
        );
        std::thread::sleep(execution.saturating_duration_since(Instant::now()));
        // Fault-only model of a slow mandatory audit/fsync after a negative
        // read; no state, credential or mutation is ever published here.
        std::thread::sleep(Duration::from_millis(400));
        let mut transport = DeadlineStream {
            stream: socket,
            deadline,
        };
        let reply = Response::error(503, "synthetic bounded read rejected");
        write_response(&mut transport, reply, false)?;
        assert!(Instant::now() < deadline);
        drop(transport);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes)?;
        assert!(bytes.starts_with(b"HTTP/1.1 503 "));
        assert!(
            bytes
                .windows(b"synthetic bounded read rejected".len())
                .any(|window| window == b"synthetic bounded read rejected")
        );
        Ok(())
    }

    #[test]
    fn ordinary_expired_execution_still_delivers_503_inside_original_transport_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Directory(std::env::temp_dir().join(format!(
            "heptabao-response-reserve-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crypto::random::<8>()?),
        )));
        std::fs::create_dir(&root.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
        }
        let service = Arc::new(Mutex::new(Service::new(
            root.0.join("data"),
            &root.0.join("audit.jsonl"),
        )?));
        let held = service.lock().map_err(|_| "service lock")?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let (socket, _) = listener.accept()?;
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut transport = DeadlineStream {
            stream: socket,
            deadline,
        };
        let response = execute_service_request(
            &service,
            ServiceRequest::new("GET", "secret/data/synthetic", "", "", json!({})),
            deadline,
            false,
        );
        assert_eq!(response.status, 503);
        assert!(response.body.get("data").is_none());
        // This is the actual production response writer and bounded TCP stream,
        // not an in-memory renderer that would ignore the transport deadline.
        write_response(&mut transport, response, false)?;
        assert!(Instant::now() < deadline);
        drop(transport);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes)?;
        assert!(bytes.starts_with(b"HTTP/1.1 503 "));
        assert!(
            bytes
                .windows(b"service state lock deadline exceeded".len())
                .any(|window| window == b"service state lock deadline exceeded")
        );
        drop(held);
        let response = execute_service_request(
            &service,
            ServiceRequest::new("GET", "sys/init", "", "", json!({})),
            Instant::now() + Duration::from_secs(1),
            false,
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["initialized"], false);
        Ok(())
    }

    #[test]
    fn quorum_read_deadline_retains_time_for_mandatory_audit_and_tcp_rejection()
    -> Result<(), Box<dyn std::error::Error>> {
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Directory(std::env::temp_dir().join(format!(
            "heptabao-quorum-reply-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crypto::random::<8>()?),
        )));
        std::fs::create_dir(&root.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut service = Service::new(root.0.join("data"), &root.0.join("audit.jsonl"))?;
        let cluster = crate::ha::snapshot_test_support::Cluster::new(
            &root.0.join("raft"),
            "quorum-reply-audit",
        )?;
        let process = cluster.processes[0].lock().map_err(|_| "HA lock")?;
        process.ensure_linearizable()?;
        cluster.isolate_all_peers(true);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let (socket, _) = listener.accept()?;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(5);
        let execution = execution_deadline_with_response_reserve(started, deadline);
        let _scope = RequestDeadlineScope::enter(execution);
        let error = process
            .ensure_linearizable()
            .err()
            .ok_or("quorum read succeeded")?;
        assert!(error.contains("linearizable read deadline exceeded"));
        assert!(cluster.blocked_probes() > 0);
        assert!(started.elapsed() >= Duration::from_secs(3));
        assert_eq!(crate::request_deadline::current(), Some(execution));
        eprintln!(
            "quorum-reply: stage=read_index elapsed_ms={}",
            started.elapsed().as_millis()
        );
        // The live failure completed mandatory response fsync after its read
        // deadline and exhausted the 5s transport. Model that completion latency
        // here, then use actual signed audit fsyncs and the production TCP writer.
        std::thread::sleep(Duration::from_millis(350));
        let response = service.handle_wire_rejection(
            &[42; 16],
            WireRejection::ParseRejected,
            503,
            "synthetic quorum read rejected",
        );
        assert_eq!(response.status, 503);
        assert!(response.body.get("data").is_none());
        let audit = std::fs::read_to_string(root.0.join("audit.jsonl"))?;
        assert_eq!(audit.lines().count(), 2);
        eprintln!(
            "quorum-reply: stage=audit_complete elapsed_ms={}",
            started.elapsed().as_millis()
        );
        let mut transport = DeadlineStream {
            stream: socket,
            deadline,
        };
        write_response(&mut transport, response, false)?;
        assert!(Instant::now() < deadline);
        drop(transport);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes)?;
        assert!(bytes.starts_with(b"HTTP/1.1 503 "));
        assert!(
            bytes
                .windows(b"synthetic quorum read rejected".len())
                .any(|window| window == b"synthetic quorum read rejected")
        );
        Ok(())
    }

    #[test]
    fn service_lock_wait_is_bounded_when_another_request_holds_the_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        let lock = Mutex::new(());
        let _held = lock.lock().map_err(|_| "test mutex poisoned")?;
        assert!(matches!(
            lock_until(&lock, Instant::now() + Duration::from_millis(5)),
            Err(LockWaitError::Busy)
        ));
        Ok(())
    }

    #[test]
    fn external_effect_phase_does_not_hold_the_shared_state_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = Arc::new(Mutex::new(0_u64));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let worker_state = Arc::clone(&state);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let deadline = Instant::now() + Duration::from_secs(2);
        let worker = std::thread::spawn(move || {
            execute_external_without_writer(
                &worker_state,
                (),
                deadline,
                |_| {
                    assert_eq!(crate::request_deadline::current(), Some(deadline));
                    worker_entered.wait();
                    worker_release.wait();
                    41_u64
                },
                |value, (), result| {
                    assert_eq!(crate::request_deadline::current(), Some(deadline));
                    *value = result + 1;
                    Response {
                        unwrapped_json: None,
                        response_headers: Default::default(),
                        consistency_index: None,
                        status: 200,
                        body: json!({"data":{"completed":true}}),
                    }
                },
            )
        });
        entered.wait();
        let observed = state
            .try_lock()
            .map(|guard| *guard)
            .map_err(|_| "external effect held the shared writer");
        release.wait();
        let response = worker
            .join()
            .map_err(|_| "external effect worker panicked")?;
        assert_eq!(observed?, 0);
        assert_eq!(response.status, 200);
        assert_eq!(
            *state
                .lock()
                .map_err(|_| "state poisoned after external effect")?,
            42
        );
        Ok(())
    }

    #[test]
    fn expired_deadline_rejects_an_uncontended_writer() {
        let lock = Mutex::new(());
        let deadline = Instant::now() - Duration::from_millis(1);
        assert!(matches!(
            lock_until(&lock, deadline),
            Err(LockWaitError::Busy)
        ));
    }

    #[test]
    fn gated_external_result_after_deadline_never_calls_finish_even_when_writer_is_free()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = Arc::new(Mutex::new(0_u64));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let worker_state = Arc::clone(&state);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let worker = std::thread::spawn(move || {
            execute_external_without_writer(
                &worker_state,
                (),
                Instant::now() + Duration::from_millis(40),
                |_| {
                    worker_entered.wait();
                    worker_release.wait();
                    99_u64
                },
                |value, (), observed| {
                    worker_finished.store(true, Ordering::Release);
                    *value = observed;
                    Response {
                        unwrapped_json: None,
                        response_headers: Default::default(),
                        consistency_index: None,
                        status: 200,
                        body: json!({"data":{"completed":true}}),
                    }
                },
            )
        });
        entered.wait();
        let concurrent = state
            .try_lock()
            .map(|mut value| {
                *value = 7;
            })
            .map_err(|_| "external effect held writer");
        // The provider gate opens after the original request budget. The
        // writer remains free, which exposed the old try_lock-before-deadline bug.
        std::thread::sleep(Duration::from_millis(60));
        release.wait();
        let response = worker.join().map_err(|_| "external worker panicked")?;
        concurrent?;
        assert_eq!(response.status, 503);
        assert!(!finished.load(Ordering::Acquire));
        assert_eq!(*state.lock().map_err(|_| "state poisoned")?, 7);
        Ok(())
    }

    #[test]
    fn poisoned_service_lock_fails_without_waiting_for_the_deadline() {
        let lock = Arc::new(Mutex::new(()));
        let worker = Arc::clone(&lock);
        let poisoned = std::thread::spawn(move || {
            if let Ok(_held) = worker.lock() {
                // Deliberately unwind while holding the lock: this is the fault
                // being tested, not an assertion failure or production panic.
                std::panic::resume_unwind(Box::new("poison test mutex"));
            }
        })
        .join();
        assert!(poisoned.is_err());
        assert!(matches!(
            lock_until(&lock, Instant::now() + Duration::from_secs(1)),
            Err(LockWaitError::Poisoned)
        ));
    }
}

#[cfg(test)]
mod wrapping_header_tests {
    use super::*;
    #[test]
    fn wrapping_duration_is_bounded_and_rejects_silent_rounding() {
        for (input, expected) in [
            ("60", Some(60)),
            ("1h30m5s", Some(5405)),
            ("0s", Some(0)),
            ("0", Some(0)),
        ] {
            assert!(parse_wrap_ttl(input).is_ok_and(|actual| actual == expected));
        }
        for input in [
            "",
            "-1",
            "1.5s",
            "1ms",
            "1d",
            "1s5",
            "s",
            " 60",
            "18446744073709551616",
            "768h1s",
        ] {
            assert!(parse_wrap_ttl(input).is_err());
        }
    }
    #[test]
    fn wrapping_zero_header_keeps_acl_presence_without_requesting_a_wrapper() {
        for header in ["0", "0s", "0m0s"] {
            let request = format!(
                "GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nX-Vault-Wrap-TTL: {header}\r\n\r\n"
            );
            assert!(
                read_request(&mut request.as_bytes(), Duration::from_secs(1))
                    .is_ok_and(|request| request.wrap_ttl_seconds == Some(0))
            );
        }
        let absent = b"GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert!(
            read_request(&mut absent.as_slice(), Duration::from_secs(1))
                .is_ok_and(|request| request.wrap_ttl_seconds.is_none())
        );
    }

    #[test]
    fn wrapping_headers_are_retained_and_duplicates_or_jwt_reject() {
        let valid =
            b"GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nX-Vault-Wrap-TTL: 60s\r\n\r\n";
        assert!(
            read_request(&mut valid.as_slice(), Duration::from_secs(1))
                .is_ok_and(|r| r.wrap_ttl_seconds == Some(60))
        );
        for header in [
            "X-Vault-Wrap-TTL: 60s\r\nx-vault-wrap-ttl: 1s",
            "X-Vault-Wrap-TTL: invalid",
            "X-Vault-Wrap-Format: jwt",
        ] {
            let request =
                format!("GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n{header}\r\n\r\n");
            assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        }
    }

    #[test]
    fn health_probe_query_flags_are_parsed_as_booleans() {
        for query in ["standbyok=1", "standbyok=true"] {
            let request = format!("GET /v1/sys/health?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(
                read_request(&mut request.as_bytes(), Duration::from_secs(1))
                    .is_ok_and(|r| r.body.0["standbyok"] == Value::Bool(true))
            );
        }
        for query in ["perfstandbyok=true", "perfstandbyok=maybe"] {
            let request = format!("GET /v1/sys/health?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(
                read_request(&mut request.as_bytes(), Duration::from_secs(1))
                    .is_ok_and(|r| r.body.0 == json!({}))
            );
        }
        let request = b"GET /v1/sys/health?standbyok=maybe HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert!(read_request(&mut request.as_slice(), Duration::from_secs(1)).is_err());
    }

    #[test]
    fn openapi_query_ingress_preserves_actual_weak_bool_values_and_route_scope()
    -> Result<(), &'static str> {
        for value in ["true", "True", "1", "false", "0", "", "yes"] {
            let request = format!(
                "GET /v1/sys/internal/specs/openapi?generic_mount_paths={value} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            );
            assert!(
                read_request(&mut request.as_bytes(), Duration::from_secs(1))
                    .is_ok_and(|r| r.body.0["generic_mount_paths"] == Value::String(value.into()))
            );
        }
        for path in ["sys/health", "sys/mounts"] {
            let request = format!(
                "GET /v1/{path}?generic_mount_paths=true HTTP/1.1\r\nHost: localhost\r\n\r\n"
            );
            if path == "sys/health" {
                // Health's existing ignore-unknown contract remains unchanged.
                assert!(
                    read_request(&mut request.as_bytes(), Duration::from_secs(1))
                        .is_ok_and(|r| r.body.0 == json!({}))
                );
            } else {
                assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
            }
        }
        // Ordinary secret routes retain the existing private URL carrier. Its
        // actual backend decides whether unknown fields are ignored or rejected.
        let ordinary = b"GET /v1/secret/data/item?generic_mount_paths=true HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let ordinary = read_request(&mut ordinary.as_slice(), Duration::from_secs(1))
            .map_err(|_| "actual existing secret query carrier")?;
        let carrier = ocsp::query_request(&ordinary.method, &ordinary.path, &ordinary.body.0)
            .ok_or("private query remains bound to its original route")?;
        assert!(carrier.resolve(false).is_err());
        let duplicate = b"GET /v1/sys/internal/specs/openapi?generic_mount_paths=true&generic_mount_paths=false HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert!(read_request(&mut duplicate.as_slice(), Duration::from_secs(1)).is_err());
        Ok(())
    }

    #[test]
    fn ordinary_boolean_queries_keep_their_boolean_shape() {
        for (method, query, key) in [
            ("POST", "list=true", "list"),
            ("GET", "exclude_deleted=false", "exclude_deleted"),
        ] {
            let request = format!(
                "{method} /v1/secret/metadata/a?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            );
            assert!(
                read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_ok_and(|r| {
                    if let Some(carrier) = ocsp::query_request(&r.method, &r.path, &r.body.0) {
                        carrier
                            .resolve(false)
                            .is_ok_and(|(_, body)| body.0[key].is_boolean())
                    } else {
                        r.body.0[key].is_boolean()
                    }
                })
            );
        }
    }

    #[test]
    fn list_queries_preserve_signed_limits_and_literal_cursors() {
        for (query, expected) in [
            ("limit=-1", json!({"limit": -1})),
            ("limit=0", json!({"limit": 0})),
            ("limit=9223372036854775807", json!({"limit": i64::MAX})),
            ("limit=-9223372036854775808", json!({"limit": i64::MIN})),
            ("after=true", json!({"after": "true"})),
            ("after=false", json!({"after": "false"})),
            ("limit=", json!({"limit": ""})),
            (
                "limit=9223372036854775808",
                json!({"limit": "9223372036854775808"}),
            ),
            (
                "limit=-9223372036854775809",
                json!({"limit": "-9223372036854775809"}),
            ),
            ("limit=1.5", json!({"limit": "1.5"})),
        ] {
            let request =
                format!("LIST /v1/secret/metadata/?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(
                read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_ok_and(|r| {
                    ocsp::query_request(&r.method, &r.path, &r.body.0).is_some_and(|carrier| {
                        carrier
                            .resolve(false)
                            .is_ok_and(|(_, body)| body.0 == expected)
                    })
                })
            );
        }
        for query in ["version=-1", "depth=-1"] {
            let request =
                format!("LIST /v1/secret/metadata/?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(
                read_request(&mut request.as_bytes(), Duration::from_secs(1))
                    .is_ok_and(|r| ocsp::query_request(&r.method, &r.path, &r.body.0)
                        .is_some_and(|carrier| carrier.resolve(false).is_err()))
            );
        }
    }

    #[test]
    fn query_operations_ignore_framed_bodies_and_get_selects_list_or_scan() {
        for (method, query, selected) in [
            ("GET", "list=1", "LIST"),
            ("GET", "scan=True", "SCAN"),
            ("GET", "scan=", "GET"),
            ("LIST", "limit=-2", "LIST"),
            ("SCAN", "limit=-2", "SCAN"),
            ("HEAD", "limit=-2", "HEAD"),
            ("DELETE", "limit=-2", "DELETE"),
        ] {
            for payload in [r#"{"limit":3,"after":"body","list":true}"#, "not JSON"] {
                let request = format!(
                    "{method} /v1/secret/metadata/?{query} HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{payload}",
                    payload.len()
                );
                assert!(
                    read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_ok_and(|r| r
                        .method
                        == selected
                        && r.body.0.get("after").is_none()
                        && r.body.0.get("list").is_none())
                );
            }
        }
        for query in ["list=true&scan=true", "scan=invalid", "list=invalid"] {
            let request =
                format!("GET /v1/secret/metadata/?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        }
    }

    #[test]
    fn health_status_code_queries_are_bounded_integers() {
        let request = b"GET /v1/sys/health?uninitcode=204&sealedcode=499&standbycode=430&activecode=201 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let parsed = read_request(&mut request.as_slice(), Duration::from_secs(1));
        assert!(parsed.is_ok());
        let parsed = match parsed {
            Ok(request) => request,
            Err(_) => return,
        };
        assert_eq!(parsed.body.0["uninitcode"], json!(204));
        assert_eq!(parsed.body.0["sealedcode"], json!(499));
        assert_eq!(parsed.body.0["standbycode"], json!(430));
        assert_eq!(parsed.body.0["activecode"], json!(201));
        for query in ["activecode=99", "sealedcode=1000", "standbycode=nope"] {
            let request = format!("GET /v1/sys/health?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        }
    }

    #[test]
    fn official_go_api_health_compatibility_queries_keep_only_consumed_fields() -> io::Result<()> {
        let query = "drsecondarycode=299&haunhealhty=299&performancestandbycode=299&removedcode=299&sealedcode=299&standbycode=299&uninitcode=299";
        let request = format!("GET /v1/sys/health?{query} HTTP/1.1\r\nHost: local\r\n\r\n");
        let parsed = read_request(&mut request.as_bytes(), Duration::from_secs(1))
            .map_err(|_| io::Error::other("official Go API health request rejected"))?;
        assert_eq!(
            parsed.body.0,
            json!({"sealedcode":299,"standbycode":299,"uninitcode":299})
        );
        let request = b"GET /v1/sys/health?haunhealhty=not-a-code&removedcode=ignored&standbyok=true HTTP/1.1\r\nHost: local\r\n\r\n";
        let parsed = read_request(&mut request.as_slice(), Duration::from_secs(1))
            .map_err(|_| io::Error::other("unused health options incorrectly rejected"))?;
        assert_eq!(parsed.body.0, json!({"standbyok":true}));
        let request = b"GET /v1/sys/init?haunhealhty=299 HTTP/1.1\r\nHost: local\r\n\r\n";
        assert!(read_request(&mut request.as_slice(), Duration::from_secs(1)).is_err());
        Ok(())
    }

    #[test]
    fn only_health_semantic_rejections_skip_wire_audit_and_retain_head() {
        for method in ["GET", "HEAD"] {
            for (target, headers, status) in [
                ("sys/health?standbyok=maybe", "", 400),
                ("sys/health?activecode=99", "", 400),
                ("sys/health?sealedcode=1000", "", 400),
                ("sys/health", "X-Vault-Namespace: a//b\r\n", 400),
            ] {
                let wire =
                    format!("{method} /v1/{target} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n");
                assert!(
                    read_request(&mut wire.as_bytes(), Duration::from_secs(1))
                        .is_err_and(|error| error.status == status
                            && error.health_head == Some(method == "HEAD"))
                );
            }
        }
        for method in ["GET", "HEAD"] {
            for ttl in ["invalid", "60", "0", "999999999999999999999999999999"] {
                let wire = format!(
                    "{method} /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nX-Vault-Wrap-TTL: {ttl}\r\n\r\n"
                );
                assert!(
                    read_request(&mut wire.as_bytes(), Duration::from_secs(1))
                        .is_ok_and(|request| request.wrap_ttl_seconds.is_none())
                );
            }
        }
        // Other methods/routes and malformed framing retain mandatory wire
        // rejection audit; an untrusted request line alone does not exempt it.
        for wire in [
            "POST /v1/sys/health?standbyok=maybe HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /v1/sys/healthy?standbyok=maybe HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /v1/secret/data/private HTTP/1.1\r\nHost: localhost\r\nX-Vault-Wrap-TTL: invalid\r\n\r\n",
            "GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nX-Vault-Wrap-Format: jwt\r\n\r\n",
            "GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nX-Vault-Index: malformed\r\n\r\n",
            "GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 262145\r\n\r\n",
            "POST /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nX-Vault-Wrap-TTL: invalid\r\n\r\n",
            "GET /v1/sys/health?activecode=99 HTTP/1.1\r\n\r\n",
            "GET /v1/sys/health HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert!(
                read_request(&mut wire.as_bytes(), Duration::from_secs(1))
                    .is_err_and(|error| error.health_head.is_none())
            );
        }
    }
}

#[cfg(test)]
#[path = "http_consistency_tests.rs"]
mod consistency_tests;

#[cfg(test)]
#[path = "http_ui_mounts_tests.rs"]
mod ui_mounts_tests;

#[cfg(test)]
mod recovery_listener_policy_tests {
    use super::*;
    #[test]
    fn legacy_recovery_requires_explicit_listener_false_and_rejects_non_boolean()
    -> Result<(), serde_json::Error> {
        let mut body = serde_json::json!({"listen": "127.0.0.1:8200", "data_dir": "/synthetic/data",
            "audit_file": "/synthetic/audit", "tls_cert_file": "/synthetic/cert", "tls_key_file": "/synthetic/key"});
        let default: Config = serde_json::from_value(body.clone())?;
        assert!(default.disable_unauthed_rekey_endpoints);
        body["disable_unauthed_rekey_endpoints"] = serde_json::json!(false);
        let enabled: Config = serde_json::from_value(body.clone())?;
        assert!(!enabled.disable_unauthed_rekey_endpoints);
        body["disable_unauthed_rekey_endpoints"] = serde_json::json!("false");
        assert!(serde_json::from_value::<Config>(body).is_err());
        Ok(())
    }
}

// Go's official API encodes literal stars and UTF-8 path characters. Decode
// that carrier once before admission; encoded separators and traversal bytes
// retain the existing rejection boundary and never become another route.
fn decode_native_logical_path(path: &str) -> Result<std::borrow::Cow<'_, str>, ParseError> {
    if !path.contains('%') {
        return Ok(std::borrow::Cow::Borrowed(path));
    }
    if path.len() > 12 * 1024 {
        return Err(bad("encoded logical path exceeds limit"));
    }
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let high = bytes.next().and_then(|b| (b as char).to_digit(16));
        let low = bytes.next().and_then(|b| (b as char).to_digit(16));
        let byte = high
            .zip(low)
            .map(|(h, l)| (h * 16 + l) as u8)
            .ok_or_else(|| bad("invalid encoded logical path"))?;
        if byte != b'*' && byte < 0x80 {
            return Err(bad("ambiguous encoded paths are not supported"));
        }
        decoded.push(byte);
    }
    let decoded = String::from_utf8(decoded).map_err(|_| bad("invalid UTF-8 logical path"))?;
    if decoded
        .chars()
        .any(|c| !c.is_ascii() && !c.is_alphanumeric())
    {
        return Err(bad("unsupported encoded logical path character"));
    }
    Ok(std::borrow::Cow::Owned(decoded))
}

#[cfg(test)]
mod encoded_sdk_path_tests {
    use super::*;
    #[test]
    fn sdk_auth100_encoded_native_characters_do_not_decode_separators_or_traversal() {
        assert_eq!(
            decode_native_logical_path("auth/sdk/root%2Aliteral")
                .map(|v| v.into_owned())
                .ok()
                .as_deref(),
            Some("auth/sdk/root*literal")
        );
        assert_eq!(
            decode_native_logical_path("auth/sdk/root/%E7%94%A8%E6%88%B7")
                .map(|v| v.into_owned())
                .ok()
                .as_deref(),
            Some("auth/sdk/root/用户")
        );
        for path in [
            "auth/sdk/%2Fprivate",
            "auth/sdk/%2E%2E/private",
            "auth/sdk/%5Cprivate",
            "auth/sdk/%25private",
            "auth/sdk/%00private",
            "auth/sdk/%FF",
            "auth/sdk/%E7%94",
            "auth/sdk/%2",
            "auth/sdk/%20private",
        ] {
            assert!(decode_native_logical_path(path).is_err());
        }
    }
}

#[cfg(test)]
pub(crate) fn write_raw110_reply_for_test(
    writer: &mut impl Write,
    response: Response,
    head: bool,
) -> io::Result<()> {
    write_response(writer, response, head)
}

#[cfg(test)]
mod raw113_terminal_media_tests {
    use super::*;

    #[test]
    fn raw113_terminal_content_type_matches_go_header_write_without_header_injection()
    -> io::Result<()> {
        for (original, expected) in [
            ("text/plain", "text/plain"),
            (" \ttext/plain\r\n ", "text/plain"),
            ("text/plain\r\nInjected: no", "text/plain  Injected: no"),
            ("text/plain\nx\ry", "text/plain x y"),
            ("\t \r\n", ""),
            ("\u{0b}text/plain\u{0c}", "\u{0b}text/plain\u{0c}"),
            ("\u{a0}text/plain\u{a0}", "\u{a0}text/plain\u{a0}"),
            // Go preserves NUL in the output value. This asserts original wire
            // behavior, not acceptance of that header by an HTTP client parser.
            ("text/plain\0suffix", "text/plain\0suffix"),
        ] {
            let mut output = Vec::new();
            write_go_content_type_header(&mut output, original)?;
            assert_eq!(
                output.as_slice(),
                format!("Content-Type: {expected}\r\n").as_bytes()
            );
            assert_eq!(output.windows(2).filter(|part| *part == b"\r\n").count(), 1);
            assert!(
                !output
                    .windows(b"\r\nInjected:".len())
                    .any(|p| p == b"\r\nInjected:")
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod transit_export_query_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ml_dsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn wire(
        service: &mut Service,
        root: &str,
        method: &str,
        path: &str,
        body: Value,
    ) -> TestResult<Response> {
        let payload = Zeroizing::new(serde_json::to_vec(&body)?);
        let header = format!(
            "{method} /v1/{path} HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {root}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        );
        let mut bytes = Zeroizing::new(header.into_bytes());
        bytes.extend_from_slice(&payload);
        let mut request = match read_request(&mut bytes.as_slice(), Duration::from_secs(1)) {
            Ok(request) => request,
            Err(error) => return Ok(Response::error(error.status, error.message)),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        Ok(service.handle_at(
            &request.method,
            &request.path,
            &request.namespace,
            request.token.as_str(),
            std::mem::take(&mut request.body.0),
            now,
        ))
    }

    #[test]
    fn mldsa270_http_query_standard_export_reaches_actual_nested_transit_owner() -> TestResult {
        let directory = Directory(std::env::temp_dir().join(format!(
            "heptabao-mldsa-http-export-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crypto::random::<8>()?)
        )));
        std::fs::create_dir(&directory.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut service = Service::new(directory.0.join("data"), &directory.0.join("audit.jsonl"))?;
        let initialized = wire(
            &mut service,
            "",
            "POST",
            "sys/init",
            json!({"secret_shares":1,"secret_threshold":1}),
        )?;
        assert_eq!(initialized.status, 200);
        let root = initialized.body["root_token"]
            .as_str()
            .ok_or("root token")?
            .to_owned();
        let key = initialized.body["keys_base64"][0]
            .as_str()
            .ok_or("unseal key")?
            .to_owned();
        assert_eq!(
            wire(&mut service, "", "POST", "sys/unseal", json!({"key":key}))?.status,
            200
        );
        assert_eq!(
            wire(
                &mut service,
                &root,
                "POST",
                "sys/mounts/nested/crypto",
                json!({"type":"transit"})
            )?
            .status,
            204
        );
        let created = wire(
            &mut service,
            &root,
            "POST",
            "nested/crypto/keys/key",
            json!({"type":"mldsa-44","exportable":true}),
        )?;
        assert_eq!(created.status, 200);
        assert_eq!(created.body["data"]["type"], "mldsa-44");
        assert_eq!(created.body["data"]["latest_version"], 1);
        assert_eq!(
            created.body["data"]["keys"]
                .as_object()
                .ok_or("public descriptor")?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["1"]
        );
        let public = wire(
            &mut service,
            &root,
            "GET",
            "nested/crypto/export/public-key/key/latest?%66ormat=%64er",
            // The actual GET parser ignores this framed body and uses the URL.
            json!({"format":"pem"}),
        )?;
        assert_eq!(public.status, 200);
        let public = STANDARD.decode(public.body["data"]["keys"]["1"].as_str().ok_or("SPKI")?)?;
        let public = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::from_public_key_der(&public)
            .map_err(|_| "actual HTTP SPKI")?;
        assert_eq!(public.encode().len(), 1312);
        let private = wire(
            &mut service,
            &root,
            "GET",
            "nested/crypto/export/signing-key/key/1?format=der",
            json!({}),
        )?;
        assert_eq!(private.status, 200);
        let private = Zeroizing::new(
            STANDARD.decode(private.body["data"]["keys"]["1"].as_str().ok_or("PKCS8")?)?,
        );
        let private = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_pkcs8_der(&private)
            .map_err(|_| "actual HTTP PKCS8")?;
        use ml_dsa::Keypair as _;
        assert_eq!(private.verifying_key().encode(), public.encode());
        for path in [
            "nested/crypto/export/public-key/key?format=unknown",
            "nested/crypto/export/public-key/key?format=der&format=pem",
            "nested/crypto/keys/key?format=der",
        ] {
            assert_eq!(
                wire(&mut service, &root, "GET", path, json!({}))?.status,
                400
            );
        }
        // A nonexistent mount cannot use a transit-shaped suffix to admit format.
        assert_eq!(
            wire(
                &mut service,
                &root,
                "GET",
                "unknown/export/public-key/key?format=der",
                json!({})
            )?
            .status,
            400
        );
        assert_eq!(
            wire(
                &mut service,
                &root,
                "POST",
                "nested/crypto/export/public-key/key?format=der",
                json!({})
            )?
            .status,
            400
        );
        Ok(())
    }

    fn unwrap_byok_query(
        private: &openssl::pkey::PKey<openssl::pkey::Private>,
        value: &Value,
        hash: openssl::hash::MessageDigest,
    ) -> TestResult<Zeroizing<Vec<u8>>> {
        use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
        use openssl::{encrypt::Decrypter, rsa::Padding};
        let encoded = Zeroizing::new(STANDARD.decode(value.as_str().ok_or("HTTP wrapped value")?)?);
        assert!(encoded.len() >= private.size() + 16);
        let mut decoder = Decrypter::new(private)?;
        decoder.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decoder.set_rsa_oaep_md(hash)?;
        decoder.set_rsa_mgf1_md(hash)?;
        let mut kek = Zeroizing::new(vec![0; private.size()]);
        let n = decoder.decrypt(&encoded[..private.size()], &mut kek)?;
        assert_eq!(n, 32);
        kek.truncate(n);
        let kwp = AesKek::new(&AES_256, &kek).map_err(|_| "HTTP independent KWP key")?;
        let mut material = Zeroizing::new(vec![0; encoded.len() - private.size()]);
        let n = kwp
            .unwrap_with_padding(&encoded[private.size()..], &mut material)
            .map_err(|_| "HTTP independent KWP authentication")?
            .len();
        material.truncate(n);
        Ok(material)
    }

    #[test]
    fn byok270_http_query_hash_reaches_actual_nested_transit_owner_and_survives_encrypted_reopen()
    -> TestResult {
        use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa};
        let private = PKey::from_rsa(Rsa::generate(4096)?)?;
        let public = String::from_utf8(private.public_key_to_pem()?)?;
        let directory = Directory(std::env::temp_dir().join(format!(
            "heptabao-byok-http-export-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crypto::random::<8>()?)
        )));
        std::fs::create_dir(&directory.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700))?;
        }
        let data = directory.0.join("data");
        let audit = directory.0.join("audit.jsonl");
        let mut service = Service::new(data.clone(), &audit)?;
        let initialized = wire(
            &mut service,
            "",
            "POST",
            "sys/init",
            json!({"secret_shares":1,"secret_threshold":1}),
        )?;
        assert_eq!(initialized.status, 200);
        let root = Zeroizing::new(
            initialized.body["root_token"]
                .as_str()
                .ok_or("root token")?
                .to_owned(),
        );
        let unseal = Zeroizing::new(
            initialized.body["keys_base64"][0]
                .as_str()
                .ok_or("unseal key")?
                .to_owned(),
        );
        assert_eq!(
            wire(
                &mut service,
                "",
                "POST",
                "sys/unseal",
                json!({"key":unseal.as_str()})
            )?
            .status,
            200
        );
        assert_eq!(
            wire(
                &mut service,
                &root,
                "POST",
                "sys/mounts/nested/crypto",
                json!({"type":"transit"})
            )?
            .status,
            204
        );
        assert_eq!(
            wire(
                &mut service,
                &root,
                "POST",
                "nested/crypto/keys/destination/import",
                json!({"type":"rsa-4096","public_key":public})
            )?
            .status,
            204
        );
        assert_eq!(
            wire(
                &mut service,
                &root,
                "POST",
                "nested/crypto/keys/source",
                json!({"type":"aes256-gcm96","exportable":true})
            )?
            .status,
            200
        );
        let rotated = wire(
            &mut service,
            &root,
            "POST",
            "nested/crypto/keys/source/rotate",
            json!({}),
        )?;
        assert_eq!(rotated.status, 200);
        assert!(rotated.body["data"]["latest_version"] == 2);
        let raw = wire(
            &mut service,
            &root,
            "GET",
            "nested/crypto/export/encryption-key/source",
            json!({}),
        )?;
        assert_eq!(raw.status, 200);
        let descriptor = wire(
            &mut service,
            &root,
            "GET",
            "nested/crypto/keys/source",
            json!({}),
        )?;
        assert_eq!(descriptor.status, 200);
        for (hash, digest) in [
            ("SHA1", MessageDigest::sha1()),
            ("SHA224", MessageDigest::sha224()),
            ("SHA256", MessageDigest::sha256()),
            ("SHA384", MessageDigest::sha384()),
            ("SHA512", MessageDigest::sha512()),
        ] {
            let result = wire(
                &mut service,
                &root,
                "GET",
                &format!("nested/crypto/byok-export/destination/source?%68ash={hash}"),
                // GET uses the URL carrier; this conflicting framed body cannot choose SHA1.
                json!({"hash":"bad"}),
            )?;
            assert_eq!(result.status, 200);
            assert!(result.body["data"]["name"] == "source");
            let keys = result.body["data"]["keys"]
                .as_object()
                .ok_or("HTTP exported versions")?;
            assert_eq!(
                keys.keys().map(String::as_str).collect::<Vec<_>>(),
                vec!["1", "2"]
            );
            for (number, encoded) in keys {
                let decoded = unwrap_byok_query(&private, encoded, digest)?;
                let expected = Zeroizing::new(
                    STANDARD.decode(
                        raw.body["data"]["keys"][number]
                            .as_str()
                            .ok_or("raw source")?,
                    )?,
                );
                assert!(decoded.len() == 32 && decoded.as_slice() == expected.as_slice());
            }
        }
        for (suffix, version) in [("/1", "1"), ("/latest", "2")] {
            let result = wire(
                &mut service,
                &root,
                "GET",
                &format!("nested/crypto/byok-export/destination/source{suffix}"),
                json!({}),
            )?;
            assert_eq!(result.status, 200);
            let keys = result.body["data"]["keys"]
                .as_object()
                .ok_or("single HTTP version")?;
            assert_eq!(
                keys.keys().map(String::as_str).collect::<Vec<_>>(),
                vec![version]
            );
            let decoded = unwrap_byok_query(&private, &keys[version], MessageDigest::sha256())?;
            let expected = Zeroizing::new(
                STANDARD.decode(
                    raw.body["data"]["keys"][version]
                        .as_str()
                        .ok_or("raw version")?,
                )?,
            );
            assert!(decoded.as_slice() == expected.as_slice());
        }
        for (path, status) in [
            ("nested/crypto/byok-export/destination/source?hash=bad", 500),
            (
                "nested/crypto/byok-export/destination/source?hash=SHA256&%68ash=SHA512",
                400,
            ),
            ("nested/crypto/keys/source?hash=SHA256", 400),
            ("unknown/byok-export/destination/source?hash=SHA256", 404),
        ] {
            assert_eq!(
                wire(&mut service, &root, "GET", path, json!({}))?.status,
                status,
                "{path}"
            );
        }
        assert_eq!(
            wire(
                &mut service,
                &root,
                "POST",
                "sys/mounts/sibling/data",
                json!({"type":"kv"})
            )?
            .status,
            204
        );
        assert_eq!(
            wire(
                &mut service,
                &root,
                "GET",
                "sibling/data/byok-export/destination/source?hash=SHA256",
                json!({})
            )?
            .status,
            404
        );
        assert_eq!(
            wire(
                &mut service,
                "invalid-token",
                "GET",
                "nested/crypto/byok-export/destination/source?hash=SHA256",
                json!({})
            )?
            .status,
            403
        );
        let after = wire(
            &mut service,
            &root,
            "GET",
            "nested/crypto/keys/source",
            json!({}),
        )?;
        assert!(after.body["data"] == descriptor.body["data"]);
        drop(service);
        let mut reopened = Service::new(data, &audit)?;
        assert_eq!(
            wire(
                &mut reopened,
                "",
                "POST",
                "sys/unseal",
                json!({"key":unseal.as_str()})
            )?
            .status,
            200
        );
        let result = wire(
            &mut reopened,
            &root,
            "GET",
            "nested/crypto/byok-export/destination/source/latest?hash=SHA512",
            json!({}),
        )?;
        assert_eq!(result.status, 200);
        let decoded = unwrap_byok_query(
            &private,
            &result.body["data"]["keys"]["2"],
            MessageDigest::sha512(),
        )?;
        let expected = Zeroizing::new(
            STANDARD.decode(
                raw.body["data"]["keys"]["2"]
                    .as_str()
                    .ok_or("reopened raw source")?,
            )?,
        );
        assert!(decoded.as_slice() == expected.as_slice());
        let after = wire(
            &mut reopened,
            &root,
            "GET",
            "nested/crypto/keys/source",
            json!({}),
        )?;
        assert!(after.body["data"] == descriptor.body["data"]);
        Ok(())
    }
}

#[cfg(test)]
#[path = "http_lossless_json_tests.rs"]
mod lossless_json_tests;
