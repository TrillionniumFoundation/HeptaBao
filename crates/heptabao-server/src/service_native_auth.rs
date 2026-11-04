//! AuthBus operations use the existing Auth dispatcher and V6 root transaction.
//! The request owner survives publication and the ordinary mandatory response audit.
use super::*;
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use crate::v6_native_custody::OriginalDeadline;

#[cfg(test)]
#[path = "service_native_batch_issuer_test_observer.rs"]
pub(super) mod batch_issuer_test_observer;
#[path = "service_native_batch_lifecycle.rs"]
mod native_batch;
#[path = "service_native_pki.rs"]
mod native_pki;
#[path = "service_native_identity.rs"]
mod root_identity;
pub(super) use native_pki::NativePkiIdleCheckpoint;

#[path = "service_native_capabilities.rs"]
mod capabilities;
#[path = "service_native_missing_route.rs"]
mod missing_route;
#[path = "service_native_wrapping.rs"]
mod ordinary_wrapping;

pub(super) fn is_native_capabilities_route(path: &str) -> bool {
    capabilities::route(path)
}

pub(super) fn is_native_identity_route(method: &str, path: &str) -> bool {
    root_identity::route(method, path)
}

/// OpenAPI discovery is an immutable metadata operation. The existing domain
/// handler admits GET/POST/PUT and rejects other methods; exact-path selection
/// cannot grant a backend writer or an Auth mutation.
pub(super) fn is_native_openapi_metadata(path: &str) -> bool {
    path == "sys/internal/specs/openapi"
}

fn openapi_catalog_digest(
    state: &State,
    principal: Option<&Principal>,
    namespace: &str,
    now: u64,
    deadline: OriginalDeadline,
) -> Result<[u8; 32], Response> {
    deadline.check().map_err(|_| rejected())?;
    let catalog = Service::listed_mount_catalog(state, principal, namespace, now)?;
    let catalog = serde_json::to_value(catalog).map_err(|_| rejected())?;
    transit_reply_digest(200, &catalog, deadline)
}

/// Exact read-only catalog routes. This selects the existing audited owner;
/// it grants neither a mutation nor a new actor, clock or native read proof.
pub(super) fn is_native_metadata_read(method: &str, path: &str) -> bool {
    (method == "GET"
        && matches!(
            path,
            "sys/mounts" | "sys/mounts/" | "sys/auth" | "sys/auth/"
        ))
        || namespaces::native_empty::is_catalog_read(method, path)
        || is_native_openapi_metadata(path)
}

fn rejected() -> Response {
    Response::error(
        503,
        "native authentication publication or delivery unavailable",
    )
}

// The domain dispatcher retains its original input/batch limits. Binding its
// already produced reply must not allocate a second plaintext image or add a
// smaller, unrelated owner-serialization limit to that public API.
fn transit_reply_digest(
    status: u16,
    body: &Value,
    deadline: OriginalDeadline,
) -> Result<[u8; 32], Response> {
    use sha2::{Digest, Sha256};
    struct Sink {
        deadline: OriginalDeadline,
        digest: Sha256,
    }
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.deadline
                .check()
                .map_err(|_| std::io::Error::other("native Transit reply deadline expired"))?;
            self.digest.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    deadline.check().map_err(|_| rejected())?;
    let mut sink = Sink {
        deadline,
        digest: Sha256::new(),
    };
    serde_json::to_writer(&mut sink, &(status, body)).map_err(|_| rejected())?;
    deadline.check().map_err(|_| rejected())?;
    Ok(sink.digest.finalize().into())
}

enum NativeLocalOwner {
    Auth,
    Userpass(Box<crate::auth::NativeUserpassOwner>),
    Wrapping(Box<crate::auth::NativeWrappingOwner>),
    Pki(Box<native_pki::NativePkiOwner>),
    Mount(Box<crate::engines::NativeKv2MountOwner>),
    Transit(Box<crate::engines::NativeTransitOwner>),
    Kv1(Box<crate::engines::NativeKv1Owner>),
    Totp(Box<crate::engines::NativeTotpOwner>),
    EmptyNamespace(Box<namespaces::native_empty::NativeEmptyNamespaceDraft>),
    Identity(Box<root_identity::NativeIdentityOwner>),
    MissingRoute(Box<missing_route::NativeMissingRouteOwner>),
    RaftObservation(Box<native_raft_observation::NativeRaftObservationOwner>),
    Capabilities(Box<capabilities::NativeCapabilitiesOwner>),
}

pub(super) struct NativeAuthDelivery {
    scope: namespaces::native_plain::PlainNamespaceScope,
    principal: Option<Principal>,
    method: String,
    path: String,
    body: Value,
    clock: RequestClock,
    deadline: OriginalDeadline,
    source_auth_digest: [u8; 32],
    // Preserve pre-operation actor and target lifetimes. A committed renewal
    // cannot extend the authority of the request that produced that renewal.
    source_auth: CowOwner<AuthState>,
    // Userpass retains the actual mounted operation and exact response through
    // native publication, the original terminal clock and mandatory audit.
    userpass_owner: Option<crate::auth::NativeUserpassOwner>,
    userpass_reply: Option<[u8; 32]>,
    batch_lifecycle_owner: Option<native_batch::NativeBatchLifecycleOwner>,
    // A separate typed issuer binds real unwrapped AppRole/Token API batches;
    // this is not a Userpass, wrapping, SDK or arbitrary Auth grant.
    batch_issuer_owner: Option<crate::auth::NativeBatchIssuerOwner>,
    batch_issuer_reply: Option<[u8; 32]>,
    pki_owner: Option<Box<native_pki::NativePkiOwner>>,
    // Independent engine/graph constraint for the root KV2 registry route.
    // Authentication routes retain their original identity-only constraint.
    mount_owner: Option<crate::engines::NativeKv2MountOwner>,
    // Transit is an independent engine operation owner. It is never admitted
    // through the Auth identity-only or empty self-revocation exceptions.
    transit_owner: Option<crate::engines::NativeTransitOwner>,
    transit_reply: Option<[u8; 32]>,
    // KV1 owns one actual registry delta in the existing protected graph.
    // It keeps source selection and exact replies through the original audit.
    kv1_owner: Option<crate::engines::NativeKv1Owner>,
    kv1_reply: Option<[u8; 32]>,
    // The TOTP owner alone controls its selected backend and persisted replay
    // delta. Transit and Auth grants never authorize a TOTP operation.
    totp_owner: Option<crate::engines::NativeTotpOwner>,
    totp_reply: Option<[u8; 32]>,
    // Ordinary wrapping has exact Auth delta, TTL and affine plaintext custody.
    wrapping_owner: Option<crate::auth::NativeWrappingOwner>,
    // Output composition retains this same Auth actor and the actual inner
    // response; it never selects another domain route or dispatcher.
    response_wrapping_owner: Option<crate::auth::NativeResponseWrappingOwner>,
    // Root cubbyhole is an Auth-owner operation with its own original ACL,
    // exact token delta and response bytes. It never inherits Transit grants.
    cubbyhole_owner: Option<crate::auth::NativeCubbyholeOwner>,
    cubbyhole_reply: Option<[u8; 32]>,
    namespace_owner: Option<namespaces::native_empty::NativeEmptyNamespaceDraft>,
    namespace_reply: Option<[u8; 32]>,
    identity_owner: Option<Box<root_identity::NativeIdentityOwner>>,
    // An absent mount is an immutable negative observation. It receives no
    // Identity, Auth or engine mutation grant and protects all reply statuses.
    missing_route_owner: Option<Box<missing_route::NativeMissingRouteOwner>>,
    // Immutable Auth/Identity inspection retains the actual target without a
    // second Principal, token use or post-audit result recomputation.
    capabilities_owner: Option<Box<capabilities::NativeCapabilitiesOwner>>,
    // Five exact GETs retain actual HA observation custody and original sudo
    // authorization. They never inherit any Auth or engine mutation allowance.
    raft_observation_owner: Option<native_raft_observation::NativeRaftObservationOwner>,
    raft_observation_reply: Option<[u8; 32]>,
    // Exact metadata response bytes, held through the same source proof,
    // terminal observation receipt and mandatory audit as protected reads.
    metadata_reply: Option<[u8; 32]>,
    // Exact discovery inputs are retained separately from the actual reply.
    // Recheck their current visibility without regenerating a domain response.
    openapi_catalog: Option<[u8; 32]>,
    cert_lifetime: Option<crate::auth::NativeV6CertLifetime>,
    cluster_id: String,
    activation: String,
    data_dir: PathBuf,
    origin_peer: Option<std::net::IpAddr>,
    issued_token: Option<Zeroizing<String>>,
    publication_generation: u64,
    // The actual post-Auth local/Raft frontier. Only the affine receipt from
    // this request's terminal observation may advance it before proof capture.
    delivery_checkpoint: Option<(
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    )>,
    // This is the actual request's process owner, never a reconstructed node ID.
    ha: Option<Arc<Mutex<HaProcess>>>,
    // HA binds consensus; local Transit binds the actual file selection. Each
    // additional proof is minted once
    // after the terminal observation publication, before audit, and never
    // renewed after audit. The checkpoint above is not itself this proof.
    proof: Option<native_v6_reader::NativeProof>,
}

impl Drop for NativeAuthDelivery {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

impl NativeAuthDelivery {
    // Diagnostic only: emit after an original error has already been selected.
    // Do not delay a successful short-lived grant with diagnostic I/O.
    #[cfg(test)]
    fn token_create_diagnostic_selected(&self) -> bool {
        self.path == "auth/token/create"
            && matches!(self.method.as_str(), "POST" | "PUT")
            && self.batch_issuer_owner.is_none()
            && self.response_wrapping_owner.is_none()
    }

    #[cfg(test)]
    fn record_token_create_failure(&self, stage: &'static str, status: u16) {
        if !self.token_create_diagnostic_selected() {
            return;
        }
        use std::io::Write as _;
        let observed = Instant::now();
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-DIAG-SERVICE-CREATE stage={stage} status={status} elapsed_us={} remaining_us={} deadline_expired_at_diagnostic={} issued_present={} ha={} proof_present={} thread={:?}",
            observed
                .saturating_duration_since(self.clock.started())
                .as_micros(),
            self.deadline
                .instant()
                .checked_duration_since(observed)
                .map_or(0, |remaining| remaining.as_micros()),
            observed >= self.deadline.instant(),
            self.issued_token.is_some(),
            self.ha.is_some(),
            self.proof.is_some(),
            std::thread::current().id(),
        );
    }

    #[cfg(test)]
    fn record_missing_route_stage(&self, stage: &'static str, status: Option<u16>) {
        if self.missing_route_owner.is_some() {
            missing_route::record_stage(stage, status, self.clock, self.deadline);
        }
    }

    fn metadata_read(&self) -> bool {
        is_native_metadata_read(&self.method, &self.path)
    }

    fn immutable_local_read(&self) -> bool {
        if self.response_wrapping_owner.is_some() {
            return false;
        }
        self.metadata_read()
            || self
                .kv1_owner
                .as_ref()
                .is_some_and(|owner| owner.read_only())
            || self
                .pki_owner
                .as_ref()
                .is_some_and(|owner| owner.read_only())
            || self
                .wrapping_owner
                .as_ref()
                .is_some_and(|owner| owner.read_only())
            || self
                .identity_owner
                .as_ref()
                .is_some_and(|owner| owner.read_only())
            || self.missing_route_owner.is_some()
            || self.capabilities_owner.is_some()
            || self.raft_observation_owner.is_some()
            || self
                .totp_owner
                .as_ref()
                .is_some_and(|owner| owner.read_only())
    }

    fn authorization_method(&self) -> &str {
        if let Some(owner) = self.kv1_owner.as_ref() {
            owner.authorization_method()
        } else if let Some(owner) = self.pki_owner.as_ref() {
            owner.authorization_method()
        } else if let Some(owner) = self.identity_owner.as_ref() {
            owner.authorization_method()
        } else if let Some(owner) = self.totp_owner.as_ref() {
            owner.authorization_method()
        } else if let Some(owner) = self.missing_route_owner.as_ref() {
            owner.authorization_method()
        } else if let Some(owner) = self.capabilities_owner.as_ref() {
            owner.authorization_method()
        } else {
            self.transit_owner
                .as_ref()
                .map_or(self.method.as_str(), |owner| owner.authorization_method())
        }
    }

    fn requires_local_proof(&self) -> bool {
        !self.scope.namespace().is_empty()
            || self.userpass_owner.is_some()
            || self.batch_issuer_owner.is_some()
            || self.pki_owner.is_some()
            || self.transit_owner.is_some()
            || self.kv1_owner.is_some()
            || self.totp_owner.is_some()
            || self.wrapping_owner.is_some()
            || self.response_wrapping_owner.is_some()
            || self.cubbyhole_owner.is_some()
            || self.namespace_owner.is_some()
            || self.identity_owner.is_some()
            || self.missing_route_owner.is_some()
            || self.capabilities_owner.is_some()
            || self.raft_observation_owner.is_some()
            || self.metadata_read()
    }

    fn tracks_terminal_checkpoint(&self) -> bool {
        !self.scope.namespace().is_empty()
            || self.userpass_owner.is_some()
            || self.batch_issuer_owner.is_some()
            || self.pki_owner.is_some()
            || self.ha.is_some()
            || self.wrapping_owner.is_some()
            || self.response_wrapping_owner.is_some()
            || self.mount_owner.is_some()
            || self.transit_owner.is_some()
            || self.kv1_owner.is_some()
            || self.totp_owner.is_some()
            || self.cubbyhole_owner.is_some()
            || self.namespace_owner.is_some()
            || self.identity_owner.is_some()
            || self.missing_route_owner.is_some()
            || self.capabilities_owner.is_some()
            || self.raft_observation_owner.is_some()
            || self.metadata_read()
    }

    fn time(&self, auth: &AuthState) -> Result<AuthorityTime, Response> {
        self.deadline.check().map_err(|_| rejected())?;
        let at = self.clock.observed_at().map_err(|_| rejected())?;
        Ok(auth.token_api_observed_time(AuthorityTime::Precise(at)))
    }

    fn check_source(&self, auth: &AuthState) -> Result<(), Response> {
        let time = self.time(auth)?;
        if let Some(owner) = self.pki_owner.as_ref() {
            owner.authorize(auth, self.principal.as_ref(), time)?;
        }
        if let Some(owner) = self.userpass_owner.as_ref() {
            owner
                .check_source(auth)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.batch_issuer_owner.as_ref() {
            owner
                .check_source(auth)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.response_wrapping_owner.as_ref() {
            owner
                .check_source(auth)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.wrapping_owner.as_ref() {
            owner
                .check_source(auth, self.principal.as_ref())
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.namespace_owner.as_ref() {
            owner.check_source_auth(auth)?;
        }
        auth.validate_native_v6_approle_login_lifetime_observed(
            self.scope.namespace(),
            &self.method,
            &self.path,
            &self.body,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        if let Some(lifetime) = self.cert_lifetime.as_ref() {
            lifetime
                .check_at(time)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        let bytes = owner_store::serialize_owner(auth).map_err(|_| rejected())?;
        if crypto::digest(&bytes) != self.source_auth_digest {
            return Err(rejected());
        }
        if let Some(principal) = self.principal.as_ref() {
            if let Some(owner) = self.raft_observation_owner.as_ref() {
                owner.authorize(auth, principal, time)?;
            }
            if let Some(owner) = self.cubbyhole_owner.as_ref() {
                owner
                    .authorize(auth, principal, time)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            // The actual native handler already checked its operation-specific
            // ACL. Exact source equality preserves that decision; observe the
            // original actor's lifetime and request parameters again at fsync.
            auth.authorize_request_parameters_observed(
                principal,
                self.scope.namespace(),
                self.authorization_method(),
                &self.path,
                &self.body,
                time,
            )
            .map_err(|error| {
                #[cfg(test)]
                self.record_token_create_failure("source-actor-parameters", error.status);
                Response::error(error.status, &error.message)
            })?;
            if let Some(owner) = self.identity_owner.as_ref() {
                owner.authorize(auth, principal, time)?;
            }
            if let Some(owner) = self.missing_route_owner.as_ref() {
                owner.authorize(auth, principal, time)?;
            }
            if let Some(owner) = self.capabilities_owner.as_ref() {
                owner.authorize(auth, principal, time)?;
            }
            if self.metadata_read() {
                self.check_metadata_acl(auth, principal, time)?;
            }
            if self.mount_owner.is_some() {
                self.check_mount_acl(auth, principal, time)?;
            }
            if self.transit_owner.is_some() {
                self.check_transit_acl(auth, principal, time)?;
            }
            if self.kv1_owner.is_some() {
                self.check_kv1_acl(auth, principal, time)?;
            }
            if self.totp_owner.is_some() {
                self.check_totp_acl(auth, principal, time)?;
            }
            if self.path.starts_with("auth/token/")
                && !self
                    .path
                    .strip_prefix("auth/token/")
                    .is_some_and(|operation| operation.starts_with("revoke"))
            {
                auth.authorize_request_observed(
                    principal,
                    self.scope.namespace(),
                    &self.path,
                    token_delivery::capability(&self.method, &self.path),
                    time,
                )
                .map_err(|error| {
                    #[cfg(test)]
                    self.record_token_create_failure("source-token-capability", error.status);
                    Response::error(error.status, &error.message)
                })?;
                // Read has no lookup-accessor callback in the fixed 2.7.1
                // backend. Retain the actor ACL above, but let the real route
                // reject it before any accessor/target decoding.
                if !(self.method == "GET" && self.path == "auth/token/lookup-accessor") {
                    auth.validate_token_api_delivery_target(
                        principal,
                        self.scope.namespace(),
                        &self.path,
                        &self.body,
                        time,
                    )
                    .map_err(|error| {
                        #[cfg(test)]
                        self.record_token_create_failure("source-token-target", error.status);
                        Response::error(error.status, &error.message)
                    })?;
                }
            }
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_metadata_acl(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        if !self.metadata_read() {
            return Err(rejected());
        }
        if is_native_openapi_metadata(&self.path) {
            // OpenAPI is public discovery, exactly as in the established domain
            // dispatcher. Bearer admission, original actor lifetime/parameters,
            // current mount ACL filtering, source proof and reply digest remain
            // mandatory; a catalog-read ACL must not turn this public endpoint
            // into an authorization grant or deny a valid unrelated token.
            return self.deadline.check().map_err(|_| rejected());
        }
        if namespaces::native_empty::is_catalog_read(&self.method, &self.path) {
            namespaces::native_empty::authorize_catalog_read(
                auth,
                actor,
                self.scope.namespace(),
                &self.method,
                &self.path,
                time,
            )?;
            return self.deadline.check().map_err(|_| rejected());
        }
        // The Auth domain canonicalizes only its bare catalog suffix. Mount
        // listing retains the exact path used by the engine dispatcher.
        let path = if self.path == "sys/auth/" {
            "sys/auth"
        } else {
            &self.path
        };
        auth.authorize_request_observed(actor, self.scope.namespace(), path, "read", time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_mount_acl(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        let capability = match self.method.as_str() {
            "GET" => "read",
            "DELETE" => "delete",
            _ => "update",
        };
        auth.authorize_request_observed(
            actor,
            self.scope.namespace(),
            &self.path,
            capability,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        if self.method != "GET" {
            auth.authorize_request_observed(
                actor,
                self.scope.namespace(),
                &self.path,
                "sudo",
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_kv1_acl(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        let owner = self.kv1_owner.as_ref().ok_or_else(rejected)?;
        auth.authorize_request_observed(
            actor,
            self.scope.namespace(),
            &self.path,
            owner.capability(),
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        if owner.requires_sudo() {
            auth.authorize_request_observed(
                actor,
                self.scope.namespace(),
                &self.path,
                "sudo",
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_transit_acl(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        let owner = self.transit_owner.as_ref().ok_or_else(rejected)?;
        auth.authorize_request_observed(
            actor,
            self.scope.namespace(),
            &self.path,
            owner.capability(),
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        if owner.requires_sudo() {
            auth.authorize_request_observed(
                actor,
                self.scope.namespace(),
                &self.path,
                "sudo",
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_totp_acl(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        let owner = self.totp_owner.as_ref().ok_or_else(rejected)?;
        owner
            .check_observed_time(Service::kv2_request_timestamp(time)?)
            .map_err(Response::from_engine_error)?;
        auth.authorize_request_observed(
            actor,
            self.scope.namespace(),
            &self.path,
            owner.capability(),
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        if owner.requires_sudo() {
            auth.authorize_request_observed(
                actor,
                self.scope.namespace(),
                &self.path,
                "sudo",
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_environment(&self, service: &mut Service) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        self.scope
            .check(service.state.as_ref().ok_or_else(rejected)?)?;
        if let Some(expected) = self.openapi_catalog {
            let state = service.state.as_ref().ok_or_else(rejected)?;
            let now = self.time(&state.auth)?.seconds();
            let observed = openapi_catalog_digest(
                state,
                self.principal.as_ref(),
                self.scope.namespace(),
                now,
                self.deadline,
            )?;
            if observed != expected {
                return Err(rejected());
            }
        }
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.activation
            || service.data_dir != self.data_dir
            || service.native_root.is_none()
            || service
                .state
                .as_ref()
                .is_none_or(|state| state.cluster_id != self.cluster_id)
        {
            return Err(rejected());
        }
        if let Some(owner) = self.namespace_owner.as_ref() {
            owner.check_installed(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
            )?;
        }
        if let Some(owner) = self.identity_owner.as_ref() {
            owner.check_installed(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
            )?;
        }
        if let Some(owner) = self.missing_route_owner.as_ref() {
            owner.check_installed(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
            )?;
        }
        if let Some(owner) = self.capabilities_owner.as_ref() {
            owner.check_installed(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
            )?;
        }
        if let Some(owner) = self.raft_observation_owner.as_ref() {
            owner.check_installed(service)?;
        }
        if let Some(owner) = self.pki_owner.as_ref() {
            owner.check_installed(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
            )?;
        }
        match (&self.ha, &service.ha) {
            (None, None) => {}
            #[cfg(feature = "native-v6-ha")]
            (Some(original), Some(current)) if Arc::ptr_eq(original, current) => {}
            _ => return Err(rejected()),
        }
        if let Some(owner) = self.mount_owner.as_ref() {
            // HA keeps the same process owner checked above. Its exact local
            // installed mount/root is still checked here; check_owner also
            // requires the original post-terminal HA proof before delivery.
            #[cfg(not(feature = "native-v6-ha"))]
            if service.ha.is_some() {
                return Err(rejected());
            }
            owner
                .check_installed(
                    &service.state.as_ref().ok_or_else(rejected)?.engines,
                    service.native_root.as_ref().ok_or_else(rejected)?,
                    &|| self.deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)?;
        }
        if let Some(owner) = self.kv1_owner.as_ref() {
            owner
                .check_installed(
                    &service.state.as_ref().ok_or_else(rejected)?.engines,
                    service.native_root.as_ref().ok_or_else(rejected)?,
                    &|| self.deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)?;
        }
        if let Some(owner) = self.transit_owner.as_ref() {
            owner
                .check_installed(
                    &service.state.as_ref().ok_or_else(rejected)?.engines,
                    service.native_root.as_ref().ok_or_else(rejected)?,
                    &|| self.deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)?;
        }
        if let Some(owner) = self.totp_owner.as_ref() {
            owner
                .check_installed(
                    &service.state.as_ref().ok_or_else(rejected)?.engines,
                    service.native_root.as_ref().ok_or_else(rejected)?,
                    &|| self.deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)?;
        }
        let durable = service.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        let generation = durable.generation();
        if self.tracks_terminal_checkpoint() && generation != self.publication_generation
            // Keep the existing standalone delivery contract; it has no HA
            // proof and independently validates current Auth at final delivery.
            || !self.tracks_terminal_checkpoint() && generation < self.publication_generation
        {
            return Err(rejected());
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_owner(&self, service: &mut Service) -> Result<(), Response> {
        self.check_environment(service)?;
        if let Some(owner) = self.batch_lifecycle_owner.as_ref() {
            owner.check_installed(service.state.as_ref().ok_or_else(rejected)?)?;
        }
        if (!self.scope.namespace().is_empty()
            || self.userpass_owner.is_some()
            || self.batch_issuer_owner.is_some()
            || self.pki_owner.is_some()
            || self.mount_owner.is_some()
            || self.wrapping_owner.is_some()
            || self.response_wrapping_owner.is_some()
            || self.transit_owner.is_some()
            || self.kv1_owner.is_some()
            || self.totp_owner.is_some()
            || self.cubbyhole_owner.is_some()
            || self.namespace_owner.is_some()
            || self.identity_owner.is_some()
            || self.missing_route_owner.is_some()
            || self.capabilities_owner.is_some()
            || self.raft_observation_owner.is_some()
            || self.metadata_read())
            && self.delivery_checkpoint.as_ref() != Some(&Self::current_checkpoint(service)?)
        {
            return Err(rejected());
        }
        match (&self.ha, &self.proof) {
            (None, None) if !self.requires_local_proof() => Ok(()),
            (None, Some(proof @ native_v6_reader::NativeProof::Single(_)))
                if self.requires_local_proof() =>
            {
                proof.check_warm(service)
            }
            #[cfg(feature = "native-v6-ha")]
            (Some(_), Some(proof @ native_v6_reader::NativeProof::Ha(_))) => {
                proof.check_warm(service)
            }
            _ => Err(rejected()),
        }
    }

    fn current_checkpoint(
        service: &Service,
    ) -> Result<
        (
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        ),
        Response,
    > {
        let identity = service.current_state_identity()?;
        if !matches!(
            identity,
            crate::state_record_root::StateIdentity::RecordsV6(_)
        ) {
            return Err(rejected());
        }
        Ok((identity, service.external_effect_generation()?))
    }

    fn stage_publication(&mut self, service: &mut Service) -> Result<(), Response> {
        if !self.tracks_terminal_checkpoint()
            || self.delivery_checkpoint.is_some()
            || self.proof.is_some()
        {
            return Err(rejected());
        }
        self.check_environment(service)?;
        self.check_source(&self.source_auth)?;
        self.delivery_checkpoint = Some(Self::current_checkpoint(service)?);
        self.check_checkpoint(service)
    }

    fn check_checkpoint(&self, service: &mut Service) -> Result<(), Response> {
        self.check_environment(service)?;
        self.check_source(&self.source_auth)?;
        if !self.tracks_terminal_checkpoint()
            || self.delivery_checkpoint.as_ref() != Some(&Self::current_checkpoint(service)?)
        {
            return Err(rejected());
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn bind_after_terminal_observation(
        &mut self,
        service: &mut Service,
        receipt: Option<token_precision::TerminalClockReceipt>,
    ) -> Result<(), Response> {
        if !self.tracks_terminal_checkpoint()
            || self.proof.is_some()
            || self.delivery_checkpoint.is_none()
        {
            return Err(rejected());
        }
        self.check_source(&self.source_auth)?;
        let terminal_write = receipt.is_some();
        if let Some(receipt) = receipt {
            receipt.advance_native_auth(&mut self.delivery_checkpoint)?;
            // Current local state must be exactly the receipt's resulting
            // identity/frontier before its generation may replace the prior
            // one. Reading a newer integer alone would admit unrelated work.
            if self.delivery_checkpoint.as_ref() != Some(&Self::current_checkpoint(service)?) {
                return Err(rejected());
            }
            self.publication_generation =
                service.durable.as_ref().ok_or_else(rejected)?.generation();
        }
        if self.delivery_checkpoint.as_ref() != Some(&Self::current_checkpoint(service)?) {
            return Err(rejected());
        }
        if let Some(owner) = self.mount_owner.as_mut() {
            let engines = &service.state.as_ref().ok_or_else(rejected)?.engines;
            let root = service.native_root.as_ref().ok_or_else(rejected)?;
            if terminal_write {
                owner
                    .admit_terminal_clock_successor(engines, root, &|| {
                        self.deadline.check().is_ok()
                    })
                    .map_err(Response::from_engine_error)?;
            } else {
                owner
                    .finish_terminal_unchanged(engines, root, &|| self.deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
            }
        }
        if let Some(owner) = self.kv1_owner.as_mut() {
            let engines = &service.state.as_ref().ok_or_else(rejected)?.engines;
            let root = service.native_root.as_ref().ok_or_else(rejected)?;
            if terminal_write {
                owner
                    .admit_terminal_clock_successor(engines, root, &|| {
                        self.deadline.check().is_ok()
                    })
                    .map_err(Response::from_engine_error)?;
            } else {
                owner
                    .finish_terminal_unchanged(engines, root, &|| self.deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
            }
        }
        if let Some(owner) = self.transit_owner.as_mut() {
            let engines = &service.state.as_ref().ok_or_else(rejected)?.engines;
            let root = service.native_root.as_ref().ok_or_else(rejected)?;
            if terminal_write {
                owner
                    .admit_terminal_clock_successor(engines, root, &|| {
                        self.deadline.check().is_ok()
                    })
                    .map_err(Response::from_engine_error)?;
            } else {
                owner
                    .finish_terminal_unchanged(engines, root, &|| self.deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
            }
        }
        if let Some(owner) = self.totp_owner.as_mut() {
            let engines = &service.state.as_ref().ok_or_else(rejected)?.engines;
            let root = service.native_root.as_ref().ok_or_else(rejected)?;
            if terminal_write {
                owner
                    .admit_terminal_clock_successor(engines, root, &|| {
                        self.deadline.check().is_ok()
                    })
                    .map_err(Response::from_engine_error)?;
            } else {
                owner
                    .finish_terminal_unchanged(engines, root, &|| self.deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
            }
        }
        if let Some(owner) = self.pki_owner.as_mut() {
            owner.bind_terminal(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
                terminal_write,
            )?;
        }
        if let Some(owner) = self.identity_owner.as_mut() {
            owner.bind_terminal(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
                terminal_write,
            )?;
        }
        if let Some(owner) = self.missing_route_owner.as_mut() {
            owner.bind_terminal(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
                terminal_write,
            )?;
        }
        if let Some(owner) = self.capabilities_owner.as_mut() {
            owner.bind_terminal(
                service.state.as_ref().ok_or_else(rejected)?,
                service.native_root.as_ref().ok_or_else(rejected)?,
                terminal_write,
            )?;
        }
        self.check_checkpoint(service)?;
        self.bind_publication(service)?;
        self.check_checkpoint(service)
    }

    fn bind_publication(&mut self, service: &mut Service) -> Result<(), Response> {
        let _original_deadline =
            crate::request_deadline::RequestDeadlineScope::enter(self.deadline.instant());
        self.check_environment(service)?;
        if self.proof.is_some() {
            return Err(rejected());
        }
        if self.ha.is_some() || self.requires_local_proof() {
            // Capture under the same thread-local original request budget and
            // the retained pre-operation Auth owner. A successful renewal does
            // not extend that owner; a public login does not invent an Actor.
            let proof = service
                .capture_native_request_proof(&mut || self.check_source(&self.source_auth))?
                .ok_or_else(rejected)?;
            let valid_kind = match (&self.ha, &proof) {
                (None, native_v6_reader::NativeProof::Single(_)) => self.requires_local_proof(),
                #[cfg(feature = "native-v6-ha")]
                (Some(_), native_v6_reader::NativeProof::Ha(_)) => true,
                _ => false,
            };
            if !valid_kind || proof.generation() != self.publication_generation {
                return Err(rejected());
            }
            self.proof = Some(proof);
        }
        self.check_owner(service)
    }

    fn check_current_identity_actor(&mut self, state: &State) -> Result<(), Response> {
        if let Some(owner) = self.pki_owner.as_ref() {
            let time = self.time(&state.auth)?;
            owner.authorize_current(state, self.principal.as_mut(), time)
        } else if let Some(owner) = self.identity_owner.as_ref() {
            let time = self.time(&state.auth)?;
            owner.authorize_current(state, self.principal.as_mut().ok_or_else(rejected)?, time)
        } else if let Some(owner) = self.missing_route_owner.as_ref() {
            let time = self.time(&state.auth)?;
            owner.authorize_current(state, self.principal.as_mut().ok_or_else(rejected)?, time)
        } else if let Some(owner) = self.capabilities_owner.as_ref() {
            let time = self.time(&state.auth)?;
            owner.authorize_current(state, self.principal.as_mut().ok_or_else(rejected)?, time)
        } else {
            Ok(())
        }
    }

    fn check_reply_auth(&self, auth: &AuthState, status: u16) -> Result<(), Response> {
        let time = self.time(auth)?;
        if let Some(owner) = self.pki_owner.as_ref() {
            owner.authorize(auth, self.principal.as_ref(), time)?;
        }
        if let Some(owner) = self.userpass_owner.as_ref() {
            owner
                .authorize_reply(auth, self.principal.as_ref(), status, time)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.batch_issuer_owner.as_ref() {
            owner
                .check_current(auth, time)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.response_wrapping_owner.as_ref() {
            owner
                .check_current_auth(auth)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.wrapping_owner.as_ref() {
            owner
                .authorize_reply(auth, self.principal.as_ref())
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(owner) = self.namespace_owner.as_ref() {
            owner.authorize_current(auth)?;
        }
        // A successful empty revoke/policy response may intentionally have
        // removed its own actor. It carries no credential or private payload.
        if (status != 204
            || self.pki_owner.is_some()
            || self
                .userpass_owner
                .as_ref()
                .is_some_and(|owner| !owner.permits_empty_actor_retirement())
            || self.wrapping_owner.is_some()
            || self.mount_owner.is_some()
            || self.transit_owner.is_some()
            || self.kv1_owner.is_some()
            || self.totp_owner.is_some()
            || self.identity_owner.is_some()
            || self.missing_route_owner.is_some()
            || self.capabilities_owner.is_some()
            || self.raft_observation_owner.is_some()
            || (self.cubbyhole_owner.is_some() || self.namespace_owner.is_some()))
            && let Some(principal) = self.principal.as_ref()
        {
            if let Some(owner) = self.raft_observation_owner.as_ref() {
                owner.authorize(auth, principal, time)?;
            }
            if let Some(owner) = self.cubbyhole_owner.as_ref() {
                owner
                    .authorize(auth, principal, time)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            auth.authorize_request_parameters_observed(
                principal,
                self.scope.namespace(),
                self.authorization_method(),
                &self.path,
                &self.body,
                time,
            )
            .map_err(|error| {
                #[cfg(test)]
                self.record_token_create_failure("reply-actor-parameters", error.status);
                Response::error(error.status, &error.message)
            })?;
            if let Some(owner) = self.identity_owner.as_ref() {
                owner.authorize(auth, principal, time)?;
            }
            if let Some(owner) = self.missing_route_owner.as_ref() {
                owner.authorize(auth, principal, time)?;
            }
            if let Some(owner) = self.capabilities_owner.as_ref() {
                owner.authorize(auth, principal, time)?;
            }
            if self.metadata_read() {
                self.check_metadata_acl(auth, principal, time)?;
            }
            if self.mount_owner.is_some() {
                self.check_mount_acl(auth, principal, time)?;
            }
            if self.transit_owner.is_some() {
                self.check_transit_acl(auth, principal, time)?;
            }
            if self.kv1_owner.is_some() {
                self.check_kv1_acl(auth, principal, time)?;
            }
            if self.totp_owner.is_some() {
                self.check_totp_acl(auth, principal, time)?;
            }
            if self.path.starts_with("auth/token/")
                && (status < 300 || self.userpass_owner.is_none())
            {
                auth.authorize_request_observed(
                    principal,
                    self.scope.namespace(),
                    &self.path,
                    token_delivery::capability(&self.method, &self.path),
                    time,
                )
                .map_err(|error| {
                    #[cfg(test)]
                    self.record_token_create_failure("reply-token-capability", error.status);
                    Response::error(error.status, &error.message)
                })?;
                if self.method == "GET" && self.path == "auth/token/lookup-accessor" {
                    // The target-free branch can preserve only an error.
                    // It must never admit a successful accessor description.
                    if status < 300 {
                        return Err(rejected());
                    }
                } else {
                    auth.validate_token_api_delivery_target(
                        principal,
                        self.scope.namespace(),
                        &self.path,
                        &self.body,
                        time,
                    )
                    .map_err(|error| {
                        #[cfg(test)]
                        self.record_token_create_failure("reply-token-target", error.status);
                        Response::error(error.status, &error.message)
                    })?;
                }
            }
        }
        if let Some(token) = self.issued_token.as_ref()
            && !self
                .batch_issuer_owner
                .as_ref()
                .is_some_and(|owner| owner.owns_issued_reply(token))
        {
            // Other owners retain their original delivery contract. The typed
            // batch issuer above validates its real grant independently from
            // admission: Token API may legally issue an already inert batch.
            let mut checked = auth.clone();
            checked
                .authenticate_from_observed(token, time, self.origin_peer)
                .map_err(|error| {
                    #[cfg(test)]
                    if self.token_create_diagnostic_selected() {
                        self.record_token_create_failure("reply-issued-token", error.status);
                        auth.record_service_token_delivery_failure_for_test(token, time);
                    }
                    Response::error(error.status, &error.message)
                })?;
        }
        self.deadline.check().map_err(|_| rejected())
    }
}

pub(super) fn auth_only_root_change(
    prior: &RecordStateRootV6,
    next: &RecordStateRootV6,
    allow_identity_owner: bool,
) -> Result<(), Response> {
    if next.state_schema < prior.state_schema
        || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
    {
        return Err(rejected());
    }
    let mut normalized = next.clone();
    normalized.state_schema = prior.state_schema;
    normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
    for (old, new) in prior.owners.iter().zip(normalized.owners.iter_mut()) {
        if old.domain == new.domain
            && (old.domain == OwnerDomain::Auth
                || allow_identity_owner && old.domain == OwnerDomain::Engines)
        {
            *new = old.clone();
        }
    }
    if normalized.encode().map_err(|_| rejected())?.as_slice()
        != prior.encode().map_err(|_| rejected())?.as_slice()
    {
        return Err(Response::error(
            501,
            "native authentication cannot change other storage owners",
        ));
    }
    Ok(())
}

impl Service {
    pub(super) fn dispatch_native_raft_observation_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(actor) = principal.as_ref() else {
            return Response::error(403, "missing client token");
        };
        let owner = match native_raft_observation::NativeRaftObservationOwner::prepare(
            self, actor, request,
        ) {
            Ok(owner) => owner,
            Err(error) => return error,
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::RaftObservation(Box::new(owner)),
        )
    }

    pub(super) fn dispatch_native_auth_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        token_fields: Option<&crate::http::token_fields::Carrier<'_>>,
    ) -> Response {
        let Some(source) = self.state.as_ref() else {
            return rejected();
        };
        let owner = if !request.namespace.is_empty() {
            if !source.auth.native_v6_plain_auth_route(
                request.namespace,
                request.method,
                request.path,
                request.body,
            ) {
                return Response::error(
                    501,
                    "native child authentication route has no closed operation owner",
                );
            }
            NativeLocalOwner::Auth
        } else {
            match source.auth.capture_native_v6_userpass_owner(
                principal.as_ref(),
                request.namespace,
                request.method,
                request.path,
                request.body,
            ) {
                Ok(Some(owner)) => NativeLocalOwner::Userpass(Box::new(owner)),
                Ok(None) => NativeLocalOwner::Auth,
                Err(error) => return Response::error(error.status, &error.message),
            }
        };
        self.dispatch_native_owner_request(candidate, principal, request, token_fields, owner)
    }

    pub(super) fn dispatch_native_metadata_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        if !is_native_metadata_read(request.method, request.path) {
            return rejected();
        }
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::Auth,
        )
    }

    pub(super) fn dispatch_native_kv2_mount_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        // A build without native HA must not fall through to a local writer.
        // With native HA, this typed mount owner uses the existing source
        // quorum proof, conditional root publication and final HA delivery proof.
        #[cfg(not(feature = "native-v6-ha"))]
        if self.ha.is_some() {
            return Response::error(
                501,
                "native KV2 mount management requires single-node custody",
            );
        }
        let Some(actor) = principal.as_ref() else {
            return Response::error(403, "missing client token");
        };
        let time = match request.token_time() {
            Ok(time) => time,
            Err(error) => return error,
        };
        let capability = match request.method {
            "GET" => "read",
            "DELETE" => "delete",
            "POST" | "PUT" => "update",
            _ => return Response::error(405, "native KV2 mount method unsupported"),
        };
        // Check original ACLs before inspecting the actual mount/type/revision.
        // Domain dispatch repeats its ordinary operation checks below.
        let authorized = candidate
            .auth
            .authorize_request_parameters_observed(
                actor,
                request.namespace,
                request.method,
                request.path,
                request.body,
                time,
            )
            .and_then(|()| {
                candidate.auth.authorize_request_observed(
                    actor,
                    request.namespace,
                    request.path,
                    capability,
                    time,
                )
            })
            .and_then(|()| {
                if request.method == "GET" {
                    Ok(())
                } else {
                    candidate.auth.authorize_request_observed(
                        actor,
                        request.namespace,
                        request.path,
                        "sudo",
                        time,
                    )
                }
            });
        if let Err(error) = authorized {
            return Response::error(error.status, &error.message);
        }
        let owner = match candidate.engines.capture_native_scoped_kv2_mount_owner(
            request.namespace,
            request.method,
            request.path,
            request.body,
        ) {
            Ok(owner) => owner,
            Err(error) => return Response::from_engine_error(error),
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::Mount(Box::new(owner)),
        )
    }

    pub(super) fn dispatch_native_kv1_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        #[cfg(not(feature = "native-v6-ha"))]
        if self.ha.is_some() {
            return Response::error(501, "native KV1 requires its native HA writer");
        }
        let Some(actor) = principal.as_ref() else {
            return Response::error(403, "missing client token");
        };
        let time = match request.token_time() {
            Ok(time) => time,
            Err(error) => return error,
        };
        let method = request.method;
        // Parameter and capability authorization precede owner capture. The
        // real domain dispatcher repeats its normal operation authorization.
        if let Err(error) = candidate.auth.authorize_request_parameters_observed(
            actor,
            request.namespace,
            method,
            request.path,
            request.body,
            time,
        ) {
            return Response::error(error.status, &error.message);
        }
        let capability = match method {
            "GET" => "read",
            "DELETE" => "delete",
            "POST" | "PUT" => "update",
            _ => return Response::error(405, "native KV1 mount method unsupported"),
        };
        if let Err(error) = candidate.auth.authorize_request_observed(
            actor,
            request.namespace,
            request.path,
            capability,
            time,
        ) {
            return Response::error(error.status, &error.message);
        }
        if method != "GET" {
            if let Err(error) = candidate.auth.authorize_request_observed(
                actor,
                request.namespace,
                request.path,
                "sudo",
                time,
            ) {
                return Response::error(error.status, &error.message);
            }
        }
        let owner = match candidate.engines.capture_native_kv1_owner(
            request.namespace,
            method,
            request.path,
            request.body,
            capability,
        ) {
            Ok(owner) => owner,
            Err(error) => return Response::from_engine_error(error),
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::Kv1(Box::new(owner)),
        )
    }

    pub(super) fn dispatch_native_transit_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(actor) = principal.as_ref() else {
            return Response::error(403, "missing client token");
        };
        let run = (|| -> Result<crate::engines::NativeTransitOwner, Response> {
            let time = request.token_time()?;
            let method = kv_authorization_method(request.method, request.body);
            candidate
                .auth
                .authorize_request_parameters_observed(
                    actor,
                    "",
                    method,
                    request.path,
                    request.body,
                    time,
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
            let registry = request.path.starts_with("sys/mounts/");
            let capability = if registry {
                match request.method {
                    "GET" => "read",
                    "DELETE" => "delete",
                    "POST" | "PUT" => "update",
                    _ => {
                        return Err(Response::error(
                            405,
                            "native Transit mount method unsupported",
                        ));
                    }
                }
            } else {
                candidate
                    .engines
                    .required_capability("", method, request.path)
                    .ok_or_else(rejected)?
            };
            candidate
                .auth
                .authorize_request_observed(actor, "", request.path, capability, time)
                .map_err(|error| Response::error(error.status, &error.message))?;
            if registry && request.method != "GET" {
                candidate
                    .auth
                    .authorize_request_observed(actor, "", request.path, "sudo", time)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
            candidate
                .engines
                .capture_native_transit_owner(
                    request.method,
                    request.path,
                    request.body,
                    self.native_root.as_ref().ok_or_else(rejected)?,
                    &|| deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)
        })();
        let owner = match run {
            Ok(owner) => owner,
            Err(error) => return error,
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::Transit(Box::new(owner)),
        )
    }

    pub(super) fn dispatch_native_totp_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(actor) = principal.as_ref() else {
            return Response::error(403, "missing client token");
        };
        let run = (|| -> Result<crate::engines::NativeTotpOwner, Response> {
            let time = request.token_time()?;
            let method = kv_authorization_method(request.method, request.body);
            candidate
                .auth
                .authorize_request_parameters_observed(
                    actor,
                    "",
                    method,
                    request.path,
                    request.body,
                    time,
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
            let registry = request.path.starts_with("sys/mounts/");
            let capability = if registry {
                match request.method {
                    "GET" => "read",
                    "DELETE" => "delete",
                    "POST" | "PUT" => "update",
                    _ => {
                        return Err(Response::error(405, "native TOTP mount method unsupported"));
                    }
                }
            } else {
                candidate
                    .engines
                    .required_capability("", method, request.path)
                    .ok_or_else(rejected)?
            };
            candidate
                .auth
                .authorize_request_observed(actor, "", request.path, capability, time)
                .map_err(|error| Response::error(error.status, &error.message))?;
            if registry && request.method != "GET" {
                candidate
                    .auth
                    .authorize_request_observed(actor, "", request.path, "sudo", time)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
            candidate
                .engines
                .capture_native_totp_owner(
                    request.method,
                    request.path,
                    request.body,
                    self.native_root.as_ref().ok_or_else(rejected)?,
                    &|| deadline.check().is_ok(),
                )
                .map_err(Response::from_engine_error)
        })();
        let owner = match run {
            Ok(owner) => owner,
            Err(error) => return error,
        };
        self.dispatch_native_owner_request(
            candidate,
            principal,
            request,
            None,
            NativeLocalOwner::Totp(Box::new(owner)),
        )
    }

    pub(super) fn dispatch_native_empty_namespace_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        if namespaces::native_empty::is_catalog_read(request.method, request.path) {
            return self.dispatch_native_metadata_request(candidate, principal, request);
        }
        let Some(actor) = principal else {
            return Response::error(403, "missing client token");
        };
        let Some(root) = self.native_root.as_ref() else {
            return rejected();
        };
        let Some(source) = self.state.as_ref() else {
            return rejected();
        };
        let owner = match namespaces::native_empty::NativeEmptyNamespaceDraft::prepare(
            source, root, actor, request,
        ) {
            Ok(owner) => owner,
            Err(error) => return error,
        };
        // Principal is affine and retained by the distinct namespace owner.
        // It is never copied into the general Auth principal slot.
        self.dispatch_native_owner_request(
            candidate,
            None,
            request,
            None,
            NativeLocalOwner::EmptyNamespace(Box::new(owner)),
        )
    }

    fn dispatch_native_owner_request(
        &mut self,
        candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        token_fields: Option<&crate::http::token_fields::Carrier<'_>>,
        owner: NativeLocalOwner,
    ) -> Response {
        self.dispatch_native_owner_request_with_pki(
            candidate,
            principal,
            request,
            token_fields,
            None,
            owner,
        )
    }

    fn dispatch_native_owner_request_with_pki(
        &mut self,
        mut candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        token_fields: Option<&crate::http::token_fields::Carrier<'_>>,
        pki_role_fields: Option<&crate::http::pki_role_fields::Carrier<'_>>,
        owner: NativeLocalOwner,
    ) -> Response {
        // Only the original closed local Auth selector may acquire this output
        // adapter. Metadata, engine, namespace and ordinary wrapping owners do
        // not inherit it from a public path prefix or positive TTL.
        let compose_response = request.namespace.is_empty()
            && matches!(&owner, NativeLocalOwner::Auth)
            && request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
            && candidate.auth.native_response_wrapping_route(
                request.namespace,
                request.method,
                request.path,
                request.body,
            );
        let select_batch_issuer = request.namespace.is_empty()
            && (matches!(&owner, NativeLocalOwner::Auth)
                || matches!(&owner, NativeLocalOwner::Userpass(owner) if !owner.is_login()))
            && !request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0);
        let (
            mount_owner,
            transit_owner,
            kv1_owner,
            namespace_owner,
            identity_owner,
            raft_observation_owner,
            userpass_owner,
            totp_owner,
            wrapping_owner,
            missing_route_owner,
            pki_owner,
            capabilities_owner,
        ) = match owner {
            NativeLocalOwner::Auth => (
                None, None, None, None, None, None, None, None, None, None, None, None,
            ),
            NativeLocalOwner::Userpass(owner) => (
                None,
                None,
                None,
                None,
                None,
                None,
                Some(*owner),
                None,
                None,
                None,
                None,
                None,
            ),
            NativeLocalOwner::Mount(owner) => (
                Some(*owner),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            NativeLocalOwner::Transit(owner) => (
                None,
                Some(*owner),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            NativeLocalOwner::Kv1(owner) => (
                None,
                None,
                Some(*owner),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            NativeLocalOwner::EmptyNamespace(owner) => (
                None,
                None,
                None,
                Some(*owner),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            NativeLocalOwner::Identity(owner) => (
                None,
                None,
                None,
                None,
                Some(owner),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            NativeLocalOwner::RaftObservation(owner) => (
                None,
                None,
                None,
                None,
                None,
                Some(*owner),
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            NativeLocalOwner::Totp(owner) => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(*owner),
                None,
                None,
                None,
                None,
            ),
            NativeLocalOwner::Wrapping(owner) => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(*owner),
                None,
                None,
                None,
            ),
            NativeLocalOwner::MissingRoute(owner) => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(owner),
                None,
                None,
            ),
            NativeLocalOwner::Pki(owner) => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(owner),
                None,
            ),
            NativeLocalOwner::Capabilities(owner) => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(owner),
            ),
        };
        if self.pending_native_auth_delivery.is_some()
            || pki_role_fields.is_some() && pki_owner.is_none()
            || (request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
                && wrapping_owner.is_none()
                && !compose_response)
            || (!request.namespace.is_empty()
                && (userpass_owner.is_some()
                    || wrapping_owner.is_some()
                    || pki_owner.is_some()
                    || transit_owner.is_some()
                    || totp_owner.is_some()
                    || capabilities_owner.is_some()
                    || raft_observation_owner.is_some()
                    || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)))
            || self.require_native_root_candidate(&candidate).is_err()
            || (mount_owner.is_some() && transit_owner.is_some())
            || (namespace_owner.is_some() && (mount_owner.is_some() || transit_owner.is_some()))
            || (identity_owner.is_some()
                && (mount_owner.is_some() || transit_owner.is_some() || namespace_owner.is_some()))
            || (totp_owner.is_some()
                && (mount_owner.is_some()
                    || transit_owner.is_some()
                    || namespace_owner.is_some()
                    || identity_owner.is_some()
                    || raft_observation_owner.is_some()))
            || (missing_route_owner.is_some()
                && (mount_owner.is_some()
                    || transit_owner.is_some()
                    || namespace_owner.is_some()
                    || identity_owner.is_some()
                    || raft_observation_owner.is_some()))
        {
            return Response::error(
                501,
                "native local authentication requires an admitted unwrapped namespace request",
            );
        }
        let Some(clock) = request.token_clock else {
            return rejected();
        };
        let Ok(deadline) = OriginalDeadline::capture() else {
            return rejected();
        };
        let Some(source) = self.state.as_ref() else {
            return rejected();
        };
        let scope =
            match namespaces::native_plain::PlainNamespaceScope::capture(source, request.namespace)
            {
                Ok(scope) => scope,
                Err(error) => return error,
            };
        if let Err(error) = scope.check(&candidate) {
            return error;
        }
        let source_auth = match owner_store::serialize_owner(&source.auth) {
            Ok(bytes) => bytes,
            Err(_) => return rejected(),
        };
        let public_login =
            source
                .auth
                .is_public_login(request.namespace, request.method, request.path);
        if principal.is_none()
            && !public_login
            && !is_native_openapi_metadata(request.path)
            && namespace_owner.is_none()
            && wrapping_owner.is_none()
            && !pki_owner.as_ref().is_some_and(|owner| owner.public())
        {
            return Response::error(403, "missing client token");
        }
        let batch_issuer_owner = if select_batch_issuer {
            match source.auth.capture_native_batch_issuer(
                principal.as_ref(),
                request.method,
                request.path,
                request.body,
                clock,
            ) {
                Ok(owner) => owner,
                Err(error) => return Response::error(error.status, &error.message),
            }
        } else {
            None
        };
        let batch_lifecycle_owner = if (public_login
            && userpass_owner
                .as_ref()
                .is_some_and(|owner| owner.is_login()))
            || batch_issuer_owner.is_some()
        {
            let Some(root) = self.native_root.as_ref() else {
                return rejected();
            };
            match native_batch::NativeBatchLifecycleOwner::prepare(source, root, deadline) {
                Ok(owner) => Some(owner),
                Err(error) => return error,
            }
        } else {
            None
        };
        let response_wrapping_owner = if compose_response {
            let Some(ttl) = request.wrap_ttl_seconds else {
                return rejected();
            };
            match crate::auth::NativeResponseWrappingOwner::prepare(
                &source.auth,
                request.namespace,
                request.path,
                ttl,
                clock,
            ) {
                Ok(owner) => Some(owner),
                Err(error) => return Response::error(error.status, &error.message),
            }
        } else {
            None
        };
        let openapi_catalog = if is_native_openapi_metadata(request.path) {
            match openapi_catalog_digest(
                &candidate,
                principal.as_ref(),
                request.namespace,
                request.now,
                deadline,
            ) {
                Ok(digest) => Some(digest),
                Err(error) => return error,
            }
        } else {
            None
        };
        let mut response_wrapping_rollback = compose_response.then(|| candidate.clone());
        let mut delivery = NativeAuthDelivery {
            scope,
            principal,
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            body: request.body.clone(),
            clock,
            deadline,
            source_auth_digest: crypto::digest(&source_auth),
            source_auth: source.auth.clone(),
            userpass_owner,
            userpass_reply: None,
            batch_lifecycle_owner,
            batch_issuer_owner,
            batch_issuer_reply: None,
            pki_owner,
            mount_owner,
            transit_owner,
            transit_reply: None,
            kv1_owner,
            kv1_reply: None,
            totp_owner,
            totp_reply: None,
            wrapping_owner,
            response_wrapping_owner,
            cubbyhole_owner: None,
            cubbyhole_reply: None,
            namespace_owner,
            namespace_reply: None,
            identity_owner,
            missing_route_owner,
            capabilities_owner,
            raft_observation_owner,
            raft_observation_reply: None,
            metadata_reply: None,
            openapi_catalog,
            cert_lifetime: None,
            cluster_id: source.cluster_id.clone(),
            activation: self.unseal_nonce.clone(),
            data_dir: self.data_dir.clone(),
            origin_peer: request.origin_peer,
            issued_token: None,
            publication_generation: self
                .durable
                .as_ref()
                .map_or(0, |durable| durable.generation()),
            delivery_checkpoint: None,
            ha: self.ha.clone(),
            proof: None,
        };
        #[cfg(test)]
        if delivery.totp_owner.is_some() || delivery.missing_route_owner.is_some() {
            crate::auth::actor_lifetime_diagnostic::owner_entered();
        }
        #[cfg(test)]
        delivery.record_missing_route_stage("source-before", None);
        if let Err(error) = delivery.check_source(&source.auth) {
            #[cfg(test)]
            delivery.record_missing_route_stage("source-veto", Some(error.status));
            #[cfg(test)]
            delivery.record_token_create_failure("source-veto", error.status);
            return error;
        }
        if let Some(owner) = delivery.mount_owner.as_ref()
            && let Err(error) = owner.check_source(&source.engines, &|| deadline.check().is_ok())
        {
            return Response::from_engine_error(error);
        }
        if let Some(owner) = delivery.kv1_owner.as_ref()
            && let Err(error) = owner.check_source(&source.engines, &|| deadline.check().is_ok())
        {
            return Response::from_engine_error(error);
        }
        if let Some(owner) = delivery.transit_owner.as_ref()
            && let Err(error) = owner.check_source(&source.engines, &|| deadline.check().is_ok())
        {
            return Response::from_engine_error(error);
        }
        if let Some(owner) = delivery.totp_owner.as_ref()
            && let Err(error) = owner.check_source(&source.engines, &|| deadline.check().is_ok())
        {
            return Response::from_engine_error(error);
        }
        if let Some(owner) = delivery.pki_owner.as_ref()
            && let Err(error) = owner.check_source(&source.engines)
        {
            return error;
        }
        if let Some(owner) = delivery.identity_owner.as_ref()
            && let Err(error) = owner.check_source(&source.engines)
        {
            return error;
        }
        if let Some(owner) = delivery.missing_route_owner.as_ref()
            && let Err(error) = owner.check_source(&source.engines)
        {
            return error;
        }
        if let Some(owner) = delivery.capabilities_owner.as_ref()
            && let Err(error) = owner.check_source(&source.engines)
        {
            return error;
        }
        // Protected local operations open private material only after the
        // actual local graph or HA quorum selection is authenticated. The
        // separate post-terminal delivery proof never refreshes this source.
        let cubbyhole_request =
            request.path == "cubbyhole" || request.path.starts_with("cubbyhole/");
        #[cfg(test)]
        delivery.record_missing_route_stage("source-proof-before", None);
        let protected_source = if !delivery.scope.namespace().is_empty()
            || delivery.userpass_owner.is_some()
            || delivery.batch_issuer_owner.is_some()
            || delivery.pki_owner.is_some()
            || delivery.transit_owner.is_some()
            || delivery.kv1_owner.is_some()
            || delivery.totp_owner.is_some()
            || delivery.wrapping_owner.is_some()
            || delivery.response_wrapping_owner.is_some()
            || cubbyhole_request
            || delivery.namespace_owner.is_some()
            || delivery.identity_owner.is_some()
            || delivery.missing_route_owner.is_some()
            || delivery.capabilities_owner.is_some()
            || delivery.raft_observation_owner.is_some()
            || delivery.metadata_read()
            || (delivery.mount_owner.is_some() && delivery.ha.is_some())
        {
            match self
                .capture_native_request_proof(&mut || delivery.check_source(&delivery.source_auth))
            {
                Ok(Some(proof)) => {
                    #[cfg(feature = "native-v6-ha")]
                    if delivery.mount_owner.is_some()
                        && delivery.ha.is_some()
                        && !matches!(&proof, native_v6_reader::NativeProof::Ha(_))
                    {
                        return rejected();
                    }
                    Some(proof)
                }
                Ok(None) => return rejected(),
                Err(error) => return error,
            }
        } else {
            None
        };
        #[cfg(test)]
        delivery.record_missing_route_stage("source-proof-after", None);
        // This is the real domain dispatcher: AppRole/cert authentication,
        // identity bindings, SecretID consumption and ACLs are unchanged.
        let mut consumption = None;
        let mut response = if let Some(owner) = delivery.pki_owner.as_mut() {
            owner.execute(
                &mut candidate,
                delivery.principal.as_ref(),
                request,
                pki_role_fields,
            )
        } else if let Some(owner) = delivery.wrapping_owner.as_mut() {
            match owner.execute(&mut candidate.auth, delivery.principal.as_ref()) {
                Ok(response) => response,
                Err(error) => return Response::error(error.status, &error.message),
            }
        } else if let Some(owner) = delivery.missing_route_owner.as_mut() {
            let Some(actor) = delivery.principal.as_ref() else {
                return Response::error(403, "missing client token");
            };
            owner.execute(&mut candidate, actor, request.now, clock)
        } else if let Some(owner) = delivery.identity_owner.as_mut() {
            let Some(actor) = delivery.principal.as_ref() else {
                return Response::error(403, "missing client token");
            };
            owner.execute(&mut candidate, actor, request.now, clock)
        } else if let Some(owner) = delivery.capabilities_owner.as_mut() {
            let Some(actor) = delivery.principal.as_ref() else {
                return Response::error(403, "missing client token");
            };
            owner.execute(&candidate, actor, request.now, clock)
        } else if let Some(owner) = delivery.raft_observation_owner.as_mut() {
            let Some(proof) = protected_source.as_ref() else {
                return rejected();
            };
            match owner.execute(self, &candidate, proof) {
                Ok(response) => response,
                Err(error) => return error,
            }
        } else if let Some(owner) = delivery.namespace_owner.as_ref() {
            let Some(root) = self.native_root.as_ref() else {
                return rejected();
            };
            let result = owner.candidate(&candidate, root);
            match result {
                Ok(next) => {
                    candidate = next;
                    match owner.response(&candidate) {
                        Ok(response) => response,
                        Err(error) => return error,
                    }
                }
                Err(error) => return error,
            }
        } else if delivery.transit_owner.is_some() {
            let at = match delivery
                .time(&delivery.source_auth)
                .and_then(Self::kv2_request_timestamp)
            {
                Ok(at) if at.seconds() >= request.now => at,
                Ok(_) => return rejected(),
                Err(error) => return error,
            };
            let result = delivery
                .transit_owner
                .as_mut()
                .ok_or_else(rejected)
                .and_then(|owner| {
                    owner
                        .execute(&mut candidate.engines, at, &|| deadline.check().is_ok())
                        .map_err(Response::from_engine_error)
                });
            match result {
                Ok(Some(mut response)) => Response {
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                },
                Ok(None) => Response::error(404, "unsupported path"),
                Err(error) => error,
            }
        } else if delivery.totp_owner.is_some() {
            let at = match delivery
                .time(&delivery.source_auth)
                .and_then(Self::kv2_request_timestamp)
            {
                Ok(at) if at.seconds() >= request.now => at,
                Ok(_) => return rejected(),
                Err(error) => return error,
            };
            let result = delivery
                .totp_owner
                .as_mut()
                .ok_or_else(rejected)
                .and_then(|owner| {
                    owner
                        .execute(&mut candidate.engines, at, &|| deadline.check().is_ok())
                        .map_err(Response::from_engine_error)
                });
            match result {
                Ok(Some(mut response)) => Response {
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                },
                Ok(None) => Response::error(404, "unsupported path"),
                Err(error) => error,
            }
        } else if namespaces::native_empty::is_catalog_read(request.method, request.path) {
            let time = match delivery.time(&delivery.source_auth) {
                Ok(time) => time,
                Err(error) => return error,
            };
            namespaces::native_empty::catalog_read(
                &candidate,
                delivery.principal.as_ref(),
                request,
                time,
            )
        } else {
            Self::dispatch_native_authorized_subrequest(
                &mut candidate,
                delivery.principal.as_ref(),
                request.namespace,
                request.method,
                request.path,
                request.body,
                token_fields,
                None,
                request.now,
                request.token_clock,
                request.client_certificates,
                request.origin_peer,
                &mut consumption,
            )
        };
        #[cfg(test)]
        delivery.record_missing_route_stage("owner-returned", Some(response.status));
        #[cfg(test)]
        if response.status >= 300 {
            delivery.record_token_create_failure("business-response-error", response.status);
        }
        if let Some(proof) = protected_source.as_ref() {
            let checked = proof
                .check_warm(self)
                .and_then(|()| delivery.check_source(&delivery.source_auth));
            if let Err(error) = checked {
                erase_json(&mut response.body);
                return error;
            }
            if delivery.kv1_owner.is_some() {
                let digest = match transit_reply_digest(response.status, &response.body, deadline) {
                    Ok(digest) => digest,
                    Err(_) => {
                        erase_json(&mut response.body);
                        return rejected();
                    }
                };
                delivery.kv1_reply = Some(digest);
            }
            if delivery.transit_owner.is_some() {
                let digest = match transit_reply_digest(response.status, &response.body, deadline) {
                    Ok(digest) => digest,
                    Err(_) => {
                        erase_json(&mut response.body);
                        return rejected();
                    }
                };
                delivery.transit_reply = Some(digest);
            }
            if delivery.totp_owner.is_some() {
                let digest = match transit_reply_digest(response.status, &response.body, deadline) {
                    Ok(digest) => digest,
                    Err(_) => {
                        erase_json(&mut response.body);
                        return rejected();
                    }
                };
                delivery.totp_reply = Some(digest);
            }
            if delivery.metadata_read() {
                delivery.metadata_reply =
                    match transit_reply_digest(response.status, &response.body, deadline) {
                        Ok(digest) => Some(digest),
                        Err(error) => {
                            erase_json(&mut response.body);
                            return error;
                        }
                    };
            }
            if delivery.raft_observation_owner.is_some() {
                delivery.raft_observation_reply =
                    match transit_reply_digest(response.status, &response.body, deadline) {
                        Ok(digest) => Some(digest),
                        Err(error) => {
                            erase_json(&mut response.body);
                            return error;
                        }
                    };
            }
        }
        if response.status < 300 && delivery.namespace_owner.is_some() {
            delivery.namespace_reply =
                match transit_reply_digest(response.status, &response.body, deadline) {
                    Ok(digest) => Some(digest),
                    Err(error) => {
                        erase_json(&mut response.body);
                        return error;
                    }
                };
        }
        if response.status < 300 && cubbyhole_request {
            let captured = (|| -> Result<crate::auth::NativeCubbyholeOwner, Response> {
                let actor = delivery.principal.as_ref().ok_or_else(rejected)?;
                let owner = delivery
                    .source_auth
                    .capture_native_cubbyhole_owner(
                        actor,
                        request.method,
                        request.path,
                        request.body,
                        delivery.time(&delivery.source_auth)?,
                    )
                    .map_err(|error| Response::error(error.status, &error.message))?;
                owner
                    .admit_candidate(
                        &delivery.source_auth,
                        &candidate.auth,
                        request.body,
                        response.status,
                    )
                    .map_err(|error| Response::error(error.status, &error.message))?;
                Ok(owner)
            })();
            match captured {
                Ok(owner) => {
                    delivery.cubbyhole_owner = Some(owner);
                    match transit_reply_digest(response.status, &response.body, deadline) {
                        Ok(digest) => delivery.cubbyhole_reply = Some(digest),
                        Err(error) => {
                            erase_json(&mut response.body);
                            return error;
                        }
                    }
                }
                Err(error) => {
                    erase_json(&mut response.body);
                    return error;
                }
            }
        }
        if public_login && response.status == 200 {
            // Capture only after the real handler has authenticated the actual
            // TLS leaf. Its original validity remains binding through publish
            // and audited response delivery; it grants no additional authority.
            let captured = delivery.time(&delivery.source_auth).and_then(|time| {
                delivery
                    .source_auth
                    .capture_native_v6_cert_login_lifetime(
                        request.namespace,
                        request.method,
                        request.path,
                        request.client_certificates,
                        time,
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            });
            match captured {
                Ok(lifetime) => delivery.cert_lifetime = lifetime,
                Err(error) => {
                    erase_json(&mut response.body);
                    return error;
                }
            }
            #[cfg(test)]
            tests::login_tests::before_native_login_publication(request.path);
        }
        if !public_login
            && response.status == 200
            && let Some(principal) = delivery.principal.as_ref()
        {
            let captured = delivery.time(&delivery.source_auth).and_then(|time| {
                delivery
                    .source_auth
                    .capture_native_v6_cert_renewal_lifetime(
                        principal,
                        request.namespace,
                        request.method,
                        request.path,
                        request.body,
                        request.client_certificates,
                        time,
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            });
            match captured {
                Ok(lifetime) => delivery.cert_lifetime = lifetime,
                Err(error) => {
                    erase_json(&mut response.body);
                    return error;
                }
            }
            #[cfg(test)]
            if delivery.cert_lifetime.is_some() {
                tests::cert_renewal_tests::before_native_cert_renewal_publication(request.path);
            }
        }
        if response.status == 200 {
            let echo = match request.path {
                "auth/token/renew-self" => Some(request.token),
                "auth/token/renew" => request.body.get("token").and_then(Value::as_str),
                _ => None,
            };
            if let (Some(token), Some(auth)) = (
                echo,
                response.body.get_mut("auth").and_then(Value::as_object_mut),
            ) {
                auth.insert("client_token".into(), json!(token));
            }
            let lookup = match request.path {
                "auth/token/lookup-self" => Some(request.token),
                "auth/token/lookup" => Some(
                    request
                        .body
                        .get("token")
                        .and_then(Value::as_str)
                        .filter(|raw| !raw.is_empty())
                        .unwrap_or(request.token),
                ),
                "auth/token/lookup-accessor" => Some(""),
                _ => None,
            };
            if let (Some(token), Some(data)) = (
                lookup,
                response.body.get_mut("data").and_then(Value::as_object_mut),
            ) {
                data.insert("id".into(), json!(token));
            }
            if public_login
                || matches!(
                    request.path,
                    "auth/token/create" | "auth/token/create-orphan"
                )
                || request.path.starts_with("auth/token/create/")
            {
                delivery.issued_token = response
                    .body
                    .get("auth")
                    .and_then(|auth| auth.get("client_token"))
                    .and_then(Value::as_str)
                    .filter(|token| !token.is_empty())
                    .map(|token| Zeroizing::new(token.to_owned()));
            }
        }
        if response.status >= 400
            && let Some(consumption) = consumption.take()
            && let Err(error) = consumption.apply(&mut candidate.auth)
        {
            erase_json(&mut response.body);
            return Response::error(error.status, &error.message);
        }
        let issuing_auth = public_login
            || matches!(
                request.path,
                "auth/token/create" | "auth/token/create-orphan"
            )
            || request.path.starts_with("auth/token/create/");
        let batch_reply = issuing_auth
            && response.status == 200
            && response.body["auth"]["token_type"].as_str() == Some("batch");
        if delivery.batch_issuer_owner.is_some() && response.status == 200 && !batch_reply {
            erase_json(&mut response.body);
            return rejected();
        }
        if batch_reply {
            // The real producer must have its own retained issuer and paired
            // Namespace/Auth owner. Wrapping and other issuers remain closed.
            let bound = (|| -> Result<(), Response> {
                if delivery.batch_lifecycle_owner.is_none() {
                    return Err(Response::error(
                        501,
                        "native batch issuer has no lifecycle owner",
                    ));
                }
                let time = delivery.time(&candidate.auth)?;
                if let Some(owner) = delivery
                    .userpass_owner
                    .as_ref()
                    .filter(|owner| owner.is_login())
                {
                    owner
                        .validate_batch_reply(
                            &candidate.auth,
                            &response.body,
                            time,
                            delivery.origin_peer,
                        )
                        .map_err(|error| Response::error(error.status, &error.message))
                } else if let Some(owner) = delivery.batch_issuer_owner.as_mut() {
                    owner
                        .bind_batch_reply(
                            &delivery.source_auth,
                            &candidate.auth,
                            &response.body,
                            time,
                            delivery.origin_peer,
                        )
                        .map_err(|error| Response::error(error.status, &error.message))
                } else {
                    Err(Response::error(
                        501,
                        "native batch issuer has no lifecycle owner",
                    ))
                }
            })();
            if let Err(error) = bound {
                erase_json(&mut response.body);
                return error;
            }
        }
        if delivery.response_wrapping_owner.is_some() {
            // Admit the real business Engine delta before an output adapter can
            // add Auth wrapping. The adapter receives no mutable State/Engine.
            if !self.state.as_ref().is_some_and(|source| {
                source.engines.native_namespace_identity_only_change(
                    request.namespace,
                    &candidate.engines,
                    &|| delivery.deadline.check().is_ok(),
                )
            }) {
                erase_json(&mut response.body);
                return Response::error(501, "native wrapped authentication changed other engines");
            }
            let Some(owner) = delivery.response_wrapping_owner.as_mut() else {
                return rejected();
            };
            response = match owner.compose(&mut candidate.auth, response) {
                Ok(response) => response,
                Err(error) => return Response::error(error.status, &error.message),
            };
            if owner.construction_failed() {
                let Some(rollback) = response_wrapping_rollback.take() else {
                    erase_json(&mut response.body);
                    return rejected();
                };
                candidate = rollback;
                // The original admitted token was already consumed. Only the
                // actual affine authenticated SecretID transition survives the
                // failed business/wrapper transaction; it is applied once.
                if let Err(error) = owner.bind_failure_rollback(
                    &delivery.source_auth,
                    &mut candidate.auth,
                    consumption.take(),
                ) {
                    erase_json(&mut response.body);
                    return Response::error(error.status, &error.message);
                }
                delivery.issued_token = None;
            }
        }
        // A catalog read cannot acquire a writer merely to normalize schema.
        // Any earlier finite-use consumption already has its own committed owner.
        if !delivery.immutable_local_read() {
            candidate.schema = candidate.writer_schema();
        }
        #[cfg(test)]
        if delivery.wrapping_owner.is_some() {
            wrapping_tests::before_native_wrapping_publication(self);
        }
        #[cfg(test)]
        if delivery.response_wrapping_owner.is_some() {
            self.before_response_composition_publication();
        }
        #[cfg(test)]
        delivery.record_missing_route_stage("publication-before", Some(response.status));
        let result = (|| -> Result<(), Response> {
            delivery.scope.check(&candidate)?;
            if let Some(owner) = delivery.userpass_owner.as_ref() {
                owner
                    .admit_candidate(&delivery.source_auth, &candidate.auth)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            if let Some(owner) = delivery.batch_lifecycle_owner.as_mut() {
                owner.admit_domain_candidate(
                    self.state.as_ref().ok_or_else(rejected)?,
                    self.native_root.as_ref().ok_or_else(rejected)?,
                    &candidate,
                    batch_reply,
                )?;
            }
            if let Some(owner) = delivery.response_wrapping_owner.as_ref() {
                owner
                    .admit_candidate(&candidate.auth)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            if let Some(owner) = delivery.wrapping_owner.as_ref() {
                owner
                    .admit_candidate(&candidate.auth)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            if let Some(owner) = delivery.pki_owner.as_ref() {
                owner.admit_candidate(&candidate)?;
            } else if let Some(owner) = delivery.mount_owner.as_mut() {
                owner
                    .admit_candidate(&candidate.engines, response.status, &|| {
                        deadline.check().is_ok()
                    })
                    .map_err(Response::from_engine_error)?;
            } else if let Some(owner) = delivery.kv1_owner.as_mut() {
                owner
                    .admit_candidate(&candidate.engines, response.status, &|| {
                        deadline.check().is_ok()
                    })
                    .map_err(Response::from_engine_error)?;
            } else if let Some(owner) = delivery.transit_owner.as_ref() {
                owner
                    .admit_candidate(&candidate.engines, &|| deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
            } else if let Some(owner) = delivery.totp_owner.as_ref() {
                owner
                    .admit_candidate(&candidate.engines, &|| deadline.check().is_ok())
                    .map_err(Response::from_engine_error)?;
            } else if let Some(owner) = delivery.identity_owner.as_ref() {
                owner.admit_candidate(&candidate)?;
            } else if let Some(owner) = delivery.missing_route_owner.as_ref() {
                owner.admit_candidate(&candidate)?;
            } else if let Some(owner) = delivery.capabilities_owner.as_ref() {
                owner.admit_candidate(&candidate)?;
            } else if delivery.namespace_owner.is_some() {
                // Exact three-owner delta is checked against the actual staged
                // native plan below, never the Auth identity-only allowance.
            } else if !self
                .state
                .as_ref()
                .ok_or_else(rejected)?
                .engines
                .native_namespace_identity_only_change(
                    request.namespace,
                    &candidate.engines,
                    &|| delivery.deadline.check().is_ok(),
                )
            {
                return Err(Response::error(
                    501,
                    "native authentication cannot change non-identity engine state",
                ));
            }
            // Only the actual engine owner can report a successful disable.
            // Remove its exact quota definitions in this same candidate; the
            // full Auth delta is independently proved against both real roots
            // below before the engine owner consumes that narrow exception.
            let disabled_mount = delivery
                .mount_owner
                .as_ref()
                .and_then(|owner| owner.disabled_mount())
                .or_else(|| {
                    delivery
                        .kv1_owner
                        .as_ref()
                        .and_then(|owner| owner.disabled_mount())
                })
                .or_else(|| {
                    delivery
                        .transit_owner
                        .as_ref()
                        .and_then(|owner| owner.disabled_mount())
                })
                .or_else(|| {
                    delivery
                        .totp_owner
                        .as_ref()
                        .and_then(|owner| owner.disabled_mount())
                })
                .or_else(|| {
                    delivery
                        .pki_owner
                        .as_ref()
                        .and_then(|owner| owner.disabled_mount())
                })
                .map(|(namespace, mount)| (namespace.to_owned(), mount.to_owned()));
            if let Some((namespace, mount)) = &disabled_mount {
                candidate
                    .auth
                    .prune_rate_limit_quotas_mount(namespace, mount);
            }
            let plan = self.prepare_native_live_root_checked(&candidate, &mut |auth| {
                delivery.check_source(auth)
            })?;
            let prior = self.native_root.as_ref().ok_or_else(rejected)?;
            let mut quota_retirement = match disabled_mount.as_ref() {
                Some((namespace, mount)) => {
                    crate::auth::rate_limit_quotas::MountRetirement::capture(
                        &delivery.source_auth,
                        &plan.candidate.auth,
                        namespace,
                        mount,
                        prior,
                        &plan.root,
                        &|| deadline.check().is_ok(),
                    )
                    .map_err(|error| Response::error(error.status, &error.message))?
                }
                None => None,
            };
            if let Some(owner) = delivery.response_wrapping_owner.as_ref() {
                owner
                    .admit_candidate(&plan.candidate.auth)
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            if delivery.immutable_local_read()
                && plan.root.identity().map_err(|_| rejected())?
                    != prior.identity().map_err(|_| rejected())?
            {
                return Err(Response::error(
                    503,
                    "native metadata read changed storage state",
                ));
            }
            if let Some(owner) = delivery.pki_owner.as_mut() {
                match quota_retirement.take() {
                    Some(retirement) => owner.admit_root_with_quota_retirement(
                        prior,
                        &plan.candidate,
                        &plan.root,
                        retirement,
                    )?,
                    None => owner.admit_root(prior, &plan.candidate, &plan.root)?,
                }
            } else if let Some(owner) = delivery.namespace_owner.as_mut() {
                owner.admit_candidate(
                    self.state.as_ref().ok_or_else(rejected)?,
                    prior,
                    &plan.candidate,
                )?;
                owner.check_root_delta(prior, &plan.root)?;
            } else if let Some(owner) = delivery.identity_owner.as_mut() {
                owner.admit_root(prior, &plan.root)?;
            } else if let Some(owner) = delivery.missing_route_owner.as_mut() {
                owner.admit_root(prior, &plan.root)?;
            } else if let Some(owner) = delivery.capabilities_owner.as_mut() {
                owner.admit_root(prior, &plan.root)?;
            } else if let Some(owner) = delivery.raft_observation_owner.as_ref() {
                owner.check_installed(self)?;
                // A real read must retain the exact root, including Auth. Only
                // the subsequent terminal-clock owner may advance its receipt.
                if plan.root.identity().map_err(|_| rejected())?
                    != prior.identity().map_err(|_| rejected())?
                {
                    return Err(rejected());
                }
            } else if let Some(owner) = delivery.mount_owner.as_mut() {
                match quota_retirement.take() {
                    Some(retirement) => owner.admit_root_with_quota_retirement(
                        prior,
                        &plan.root,
                        retirement,
                        &|| deadline.check().is_ok(),
                    ),
                    None => owner.admit_root(prior, &plan.root, &|| deadline.check().is_ok()),
                }
                .map_err(Response::from_engine_error)?;
            } else if let Some(owner) = delivery.kv1_owner.as_mut() {
                match quota_retirement.take() {
                    Some(retirement) => owner.admit_root_with_quota_retirement(
                        prior,
                        &plan.root,
                        retirement,
                        &|| deadline.check().is_ok(),
                    ),
                    None => owner.admit_root(prior, &plan.root, &|| deadline.check().is_ok()),
                }
                .map_err(Response::from_engine_error)?;
            } else if let Some(owner) = delivery.transit_owner.as_mut() {
                match quota_retirement.take() {
                    Some(retirement) => owner.admit_root_with_quota_retirement(
                        prior,
                        &plan.root,
                        retirement,
                        &|| deadline.check().is_ok(),
                    ),
                    None => owner.admit_root(prior, &plan.root, &|| deadline.check().is_ok()),
                }
                .map_err(Response::from_engine_error)?;
            } else if let Some(owner) = delivery.totp_owner.as_mut() {
                match quota_retirement.take() {
                    Some(retirement) => owner.admit_root_with_quota_retirement(
                        prior,
                        &plan.root,
                        retirement,
                        &|| deadline.check().is_ok(),
                    ),
                    None => owner.admit_root(prior, &plan.root, &|| deadline.check().is_ok()),
                }
                .map_err(Response::from_engine_error)?;
            } else if let Some(owner) = delivery.batch_lifecycle_owner.as_mut() {
                owner.admit_plan(
                    self.state.as_ref().ok_or_else(rejected)?,
                    prior,
                    &plan.candidate,
                    &plan.root,
                )?;
            } else {
                auth_only_root_change(
                    prior,
                    &plan.root,
                    delivery.cubbyhole_owner.is_none() && delivery.wrapping_owner.is_none(),
                )?;
            }
            if quota_retirement.is_some() {
                return Err(rejected());
            }
            if plan.root.identity().map_err(|_| rejected())?
                != prior.identity().map_err(|_| rejected())?
            {
                let purpose = if delivery.pki_owner.is_some() {
                    "pki-local"
                } else if delivery.userpass_owner.is_some() {
                    "userpass"
                } else if delivery.wrapping_owner.is_some() {
                    "ordinary-wrapping"
                } else if delivery.mount_owner.is_some() {
                    "kv2-mount"
                } else if delivery.kv1_owner.is_some() {
                    "kv1"
                } else if delivery.transit_owner.is_some() {
                    "transit"
                } else if delivery.totp_owner.is_some() {
                    "totp"
                } else if delivery.identity_owner.is_some() {
                    "identity"
                } else if delivery.namespace_owner.is_some() {
                    "empty-namespace-create"
                } else if delivery.cubbyhole_owner.is_some() {
                    "cubbyhole"
                } else {
                    "auth"
                };
                candidate =
                    self.commit_native_root_plan(&candidate, plan, false, purpose, &mut |auth| {
                        delivery.check_source(auth)
                    })?;
                self.state = Some(candidate);
            }
            delivery.publication_generation =
                self.durable.as_ref().ok_or_else(rejected)?.generation();
            delivery.check_environment(self)
        })();
        if let Err(error) = result {
            #[cfg(test)]
            delivery.record_missing_route_stage("publication-veto", Some(error.status));
            #[cfg(test)]
            delivery.record_token_create_failure("publication-veto", error.status);
            erase_json(&mut response.body);
            return error;
        }
        if let Some(owner) = delivery.userpass_owner.as_mut() {
            let bound = owner
                .bind_response(response.status, &response.body)
                .map_err(|error| Response::error(error.status, &error.message))
                .and_then(|()| {
                    if owner.is_login() && response.status == 200 && delivery.issued_token.is_none()
                    {
                        return Err(rejected());
                    }
                    transit_reply_digest(response.status, &response.body, deadline)
                });
            match bound {
                Ok(digest) => delivery.userpass_reply = Some(digest),
                Err(error) => {
                    erase_json(&mut response.body);
                    response.consistency_index = None;
                    return error;
                }
            }
        }
        if delivery.batch_issuer_owner.is_some() {
            match transit_reply_digest(response.status, &response.body, deadline) {
                Ok(digest) => delivery.batch_issuer_reply = Some(digest),
                Err(error) => {
                    erase_json(&mut response.body);
                    response.consistency_index = None;
                    return error;
                }
            }
        }
        #[cfg(test)]
        delivery.record_missing_route_stage("publication-after", Some(response.status));
        let staged = if delivery.tracks_terminal_checkpoint() {
            // Retain exact post-operation provenance before the terminal
            // observation. A local mount consumes that same affine write
            // receipt; only HA captures an additional ReadIndex proof. Neither
            // path rebinds its checkpoint in the final response handler.
            delivery.stage_publication(self)
        } else {
            delivery.bind_publication(self)
        };
        if let Err(error) = staged {
            #[cfg(test)]
            delivery.record_token_create_failure("publication-binding-veto", error.status);
            erase_json(&mut response.body);
            response.consistency_index = None;
            return error;
        }
        self.pending_native_auth_delivery = Some(delivery);
        response
    }

    pub(super) fn native_auth_terminal_deadline(&self) -> Option<Instant> {
        self.pending_native_auth_delivery
            .as_ref()
            .filter(|delivery| delivery.tracks_terminal_checkpoint())
            .map(|delivery| delivery.deadline.instant())
    }

    #[cfg(test)]
    pub(super) fn before_response_composition_publication(&mut self) {
        wrapping_tests::before_response_composition_publication(self);
    }

    #[cfg(test)]
    pub(super) fn record_pending_missing_route_stage(
        &self,
        stage: &'static str,
        status: Option<u16>,
    ) {
        if let Some(delivery) = self.pending_native_auth_delivery.as_ref() {
            delivery.record_missing_route_stage(stage, status);
        }
    }

    pub(super) fn check_pending_native_auth_before_terminal(&mut self) -> Result<(), Response> {
        let Some(delivery) = self.pending_native_auth_delivery.take() else {
            return Ok(());
        };
        #[cfg(test)]
        delivery.record_missing_route_stage("terminal-check-before", None);
        let result = if delivery.tracks_terminal_checkpoint() {
            if delivery.proof.is_some() || self.pending_forward_delivery.is_some() {
                Err(rejected())
            } else {
                delivery.check_checkpoint(self)
            }
        } else {
            Ok(())
        };
        #[cfg(test)]
        delivery.record_missing_route_stage(
            "terminal-check-after",
            result.as_ref().err().map(|error| error.status),
        );
        self.pending_native_auth_delivery = Some(delivery);
        result
    }

    pub(super) fn bind_pending_native_auth_before_audit(
        &mut self,
        receipt: Option<token_precision::TerminalClockReceipt>,
    ) -> Result<(), Response> {
        let Some(mut delivery) = self.pending_native_auth_delivery.take() else {
            return Err(rejected());
        };
        #[cfg(test)]
        delivery.record_missing_route_stage("terminal-bind-before", None);
        let result = delivery.bind_after_terminal_observation(self, receipt);
        #[cfg(test)]
        delivery.record_missing_route_stage(
            "terminal-bind-after",
            result.as_ref().err().map(|error| error.status),
        );
        // A rejected bind still owns the original capsule. The terminal
        // response path consumes it normally rather than inventing a missing
        // delivery, repeating the operation, or recapturing after audit.
        self.pending_native_auth_delivery = Some(delivery);
        result
    }

    pub(super) fn complete_native_auth_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let mut delivery = match (expected, self.pending_native_auth_delivery.take()) {
            (false, None) => return response,
            (true, Some(delivery)) => delivery,
            _ => {
                erase_json(&mut response.body);
                self.recovery_required = true;
                return rejected();
            }
        };
        #[cfg(test)]
        delivery.record_missing_route_stage("after-audit-entry", Some(response.status));
        #[cfg(test)]
        if delivery.batch_issuer_owner.is_some() && response.status < 300 {
            batch_issuer_test_observer::after_actual_audit(self, &mut response);
        }
        #[cfg(test)]
        if delivery.totp_owner.is_some() && response.status < 300 {
            crate::auth::actor_lifetime_diagnostic::hook_entered();
            totp_tests::after_actual_totp_audit(self, &mut response);
            crate::auth::actor_lifetime_diagnostic::hook_returned();
        }
        #[cfg(test)]
        if delivery.missing_route_owner.is_some() && response.status == 404 {
            crate::auth::actor_lifetime_diagnostic::hook_entered();
            missing_route_tests::after_actual_missing_route_audit(self, &mut response);
            crate::auth::actor_lifetime_diagnostic::hook_returned();
        }
        #[cfg(test)]
        delivery.record_missing_route_stage("after-audit-hook-returned", Some(response.status));
        #[cfg(test)]
        if delivery.raft_observation_owner.is_some() && response.status < 300 {
            native_raft_observation::tests::after_actual_raft_observation_audit(
                self,
                &mut response,
            );
        }
        #[cfg(test)]
        if delivery.capabilities_owner.is_some() {
            capabilities_tests::after_actual_capabilities_audit(self, &mut response);
        }
        if response.status >= 300
            && delivery.pki_owner.is_none()
            && delivery.userpass_owner.is_none()
            && delivery.batch_issuer_owner.is_none()
            && delivery.response_wrapping_owner.is_none()
            && delivery.wrapping_owner.is_none()
            && delivery.transit_owner.is_none()
            && delivery.kv1_owner.is_none()
            && delivery.totp_owner.is_none()
            && delivery.identity_owner.is_none()
            && delivery.missing_route_owner.is_none()
            && delivery.capabilities_owner.is_none()
            && delivery.raft_observation_owner.is_none()
        {
            return response;
        }
        #[cfg(test)]
        if delivery.mount_owner.is_some() {
            mount_tests::after_actual_mount_audit(self);
        }
        #[cfg(test)]
        if delivery.transit_owner.is_some() {
            transit_tests::after_actual_transit_audit(self);
        }
        let checked = (|| -> Result<(), Response> {
            if delivery.batch_issuer_owner.is_some()
                && delivery.batch_issuer_reply
                    != Some(transit_reply_digest(
                        response.status,
                        &response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            if delivery.userpass_owner.is_some()
                && delivery.userpass_reply
                    != Some(transit_reply_digest(
                        response.status,
                        &response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            if let Some(owner) = delivery.response_wrapping_owner.as_ref() {
                owner
                    .check_reply(&response)
                    // A post-audit projection mismatch invalidates delivery,
                    // not the already completed domain request.
                    .map_err(|_| rejected())?;
            }
            let domain_response = delivery
                .response_wrapping_owner
                .as_ref()
                .map_or(&response, |owner| owner.domain_response(&response));
            if let Some(owner) = delivery.wrapping_owner.as_ref() {
                owner
                    .check_reply(&response)
                    // A post-audit projection mismatch invalidates delivery,
                    // not the already completed domain request.
                    .map_err(|_| rejected())?;
            }
            if let Some(owner) = delivery.pki_owner.as_ref() {
                owner.check_reply(&response)?;
            }
            if let Some(owner) = delivery.identity_owner.as_ref() {
                owner.check_reply(&response)?;
            }
            if let Some(owner) = delivery.missing_route_owner.as_ref() {
                #[cfg(test)]
                delivery.record_missing_route_stage("delivery-reply-check", Some(response.status));
                owner.check_reply(&response)?;
            }
            if let Some(owner) = delivery.capabilities_owner.as_ref() {
                owner.check_reply(&response)?;
            }
            if delivery.raft_observation_owner.is_some()
                && delivery.raft_observation_reply
                    != Some(transit_reply_digest(
                        domain_response.status,
                        &domain_response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            if delivery.namespace_owner.is_some()
                && delivery.namespace_reply
                    != Some(transit_reply_digest(
                        domain_response.status,
                        &domain_response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            if delivery.metadata_read()
                && delivery.metadata_reply
                    != Some(transit_reply_digest(
                        domain_response.status,
                        &domain_response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            if delivery.cubbyhole_owner.is_some()
                && delivery.cubbyhole_reply
                    != Some(transit_reply_digest(
                        domain_response.status,
                        &domain_response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            if delivery.kv1_owner.is_some()
                && delivery.kv1_reply
                    != Some(transit_reply_digest(
                        domain_response.status,
                        &domain_response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            if delivery.transit_owner.is_some()
                && delivery.transit_reply
                    != Some(transit_reply_digest(
                        domain_response.status,
                        &domain_response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            if delivery.totp_owner.is_some()
                && delivery.totp_reply
                    != Some(transit_reply_digest(
                        response.status,
                        &response.body,
                        delivery.deadline,
                    )?)
            {
                return Err(rejected());
            }
            #[cfg(test)]
            delivery.record_missing_route_stage("delivery-owner-check", Some(response.status));
            delivery.check_owner(self)?;
            #[cfg(test)]
            delivery.record_missing_route_stage("delivery-actor-check", Some(response.status));
            delivery.check_source(&delivery.source_auth)?;
            if let Some(proof) = delivery.proof.as_ref() {
                // No fresh ReadIndex is acquired here. Inspect the actual local
                // typed closure under the same pre-audit consensus witness,
                // then validate the response against its authenticated Auth.
                proof.check_with(self, |installed, metadata, native, root, deadline| {
                    delivery.check_source(&delivery.source_auth)?;
                    Self::check_native_installed(installed, metadata, native, root, deadline)?;
                    delivery.check_reply_auth(&metadata.auth, response.status)?;
                    delivery.check_source(&delivery.source_auth)
                })?;
                delivery.check_owner(self)?;
                delivery.check_source(&delivery.source_auth)?;
                delivery.check_reply_auth(
                    &self.state.as_ref().ok_or_else(rejected)?.auth,
                    response.status,
                )?;
            } else {
                let state = self.state.as_ref().ok_or_else(rejected)?;
                delivery.check_reply_auth(&state.auth, response.status)?;
            }
            delivery.check_current_identity_actor(self.state.as_ref().ok_or_else(rejected)?)?;
            delivery.deadline.check().map_err(|_| rejected())
        })();
        if let Err(error) = checked {
            // TOTP, missing-route, capabilities and batch issuer owners have
            // already bound their actual operation and reply. Losing the original
            // actor or proof after audit makes that delivery unavailable.
            // Domain errors with valid custody retain their original status.
            let error = if delivery.totp_owner.is_some()
                || delivery.missing_route_owner.is_some()
                || delivery.capabilities_owner.is_some()
                || delivery.batch_issuer_owner.is_some()
            {
                rejected()
            } else {
                error
            };
            #[cfg(test)]
            delivery.record_missing_route_stage("delivery-veto", Some(error.status));
            #[cfg(test)]
            delivery.record_token_create_failure("delivery-veto", error.status);
            erase_json(&mut response.body);
            response.consistency_index = None;
            if self
                .audit_event(
                    "native-auth-delivery-veto",
                    fingerprint,
                    delivery.clock.admitted_at().seconds(),
                    Some(error.status),
                )
                .is_err()
            {
                self.recovery_required = true;
                return rejected();
            }
            return error;
        }
        #[cfg(test)]
        delivery.record_missing_route_stage("delivery-success", Some(response.status));
        response
    }
}

#[cfg(test)]
#[path = "service_native_cubbyhole_tests.rs"]
mod cubbyhole_tests;

#[cfg(test)]
#[path = "service_native_kv2_mount_tests.rs"]
mod mount_tests;
#[cfg(test)]
#[path = "service_native_auth_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_native_transit_tests.rs"]
mod transit_tests;

#[cfg(test)]
#[path = "service_native_identity_tests.rs"]
mod identity_tests;

#[cfg(test)]
#[path = "service_native_userpass_tests.rs"]
mod userpass_tests;

#[cfg(test)]
#[path = "service_native_totp_tests.rs"]
pub(super) mod totp_tests;

#[cfg(test)]
#[path = "service_native_wrapping_tests.rs"]
mod wrapping_tests;

#[cfg(test)]
#[path = "service_native_missing_route_tests.rs"]
pub(super) mod missing_route_tests;

#[cfg(test)]
#[path = "service_native_pki_tests.rs"]
mod pki_tests;

#[cfg(test)]
#[path = "service_native_capabilities_tests.rs"]
pub(super) mod capabilities_tests;
