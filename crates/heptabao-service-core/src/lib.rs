#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Mandatory request composition for the V2 single-process product candidate.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, DomainError, Id, SecretValue, Tick};
use heptabao_identity::{IdentityError, IdentityStore};
use heptabao_kv_engine::{KvError, KvMetadata, KvStore};
use heptabao_mount_router::{Backend, MountError, MountRouter};
use heptabao_namespace::{NamespaceError, NamespaceStore};
use heptabao_operator_api::{OperatorError, OutcomeRecord, ReconciliationStore, Resolution};
use heptabao_policy::{Capability, PolicyStore};
use heptabao_telemetry::{MemoryTelemetry, TelemetryError, TelemetryEvent};
use heptabao_token::{TokenError, TokenId, TokenStore};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceOperation {
    KvRead {
        version: Option<u64>,
    },
    KvWrite {
        value: SecretValue,
        cas: Option<u64>,
    },
    KvDelete,
    KvList,
}

impl ServiceOperation {
    fn capability(&self) -> Capability {
        match self {
            Self::KvRead { .. } => Capability::Read,
            Self::KvWrite { .. } => Capability::Update,
            Self::KvDelete => Capability::Delete,
            Self::KvList => Capability::List,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::KvRead { .. } => "kv_read",
            Self::KvWrite { .. } => "kv_write",
            Self::KvDelete => "kv_delete",
            Self::KvList => "kv_list",
        }
    }

    fn is_commit(&self) -> bool {
        matches!(self, Self::KvWrite { .. } | Self::KvDelete)
    }
}

#[derive(Debug)]
pub struct ServiceRequest {
    pub request_id: Id,
    pub token_id: TokenId,
    pub namespace_id: Id,
    pub path: CanonicalPath,
    pub operation: ServiceOperation,
}

pub const DEFAULT_REQUEST_REGISTRY_CAPACITY: usize = 256;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct RequestKey {
    principal_id: Id,
    namespace_id: Id,
    request_id: Id,
}

impl fmt::Debug for RequestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestKey")
            .field("principal_id", &"[BOUND]")
            .field("namespace_id", &"[BOUND]")
            .field("request_id", &"[BOUND]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RequestBinding {
    path: CanonicalPath,
    operation: ServiceOperation,
}

impl fmt::Debug for RequestBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBinding")
            .field("path", &"[BOUND]")
            .field("operation", &self.operation.label())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestRegistryCounts {
    pub capacity: usize,
    pub pending: usize,
    pub unresolved: usize,
    pub resolved: usize,
}

impl RequestRegistryCounts {
    pub const fn total(self) -> usize {
        self.pending + self.unresolved + self.resolved
    }
}

#[derive(Debug)]
struct RequestRegistry {
    capacity: usize,
    pending: BTreeMap<RequestKey, RequestBinding>,
    unresolved: BTreeMap<RequestKey, RequestBinding>,
    resolved: BTreeSet<RequestKey>,
    resolved_order: VecDeque<RequestKey>,
}

impl RequestRegistry {
    fn new(capacity: usize) -> Result<Self, ServiceError> {
        if capacity == 0 {
            return Err(ServiceError::InvalidRequestRegistryCapacity);
        }
        Ok(Self {
            capacity,
            pending: BTreeMap::new(),
            unresolved: BTreeMap::new(),
            resolved: BTreeSet::new(),
            resolved_order: VecDeque::new(),
        })
    }

    fn counts(&self) -> RequestRegistryCounts {
        RequestRegistryCounts {
            capacity: self.capacity,
            pending: self.pending.len(),
            unresolved: self.unresolved.len(),
            resolved: self.resolved.len(),
        }
    }

    fn existing_binding(&self, key: &RequestKey) -> Option<&RequestBinding> {
        self.pending.get(key).or_else(|| self.unresolved.get(key))
    }

    fn retained_len(&self) -> usize {
        self.unresolved.len() + self.resolved.len()
    }

    fn begin(&mut self, key: RequestKey, binding: RequestBinding) -> Result<(), ServiceError> {
        if self.resolved.contains(&key) {
            return Err(ServiceError::DuplicateRequest);
        }
        if let Some(existing) = self.existing_binding(&key) {
            return if existing == &binding {
                Err(ServiceError::DuplicateRequest)
            } else {
                Err(ServiceError::RequestBindingMismatch)
            };
        }
        if self.retained_len() >= self.capacity && self.resolved.is_empty() {
            return Err(ServiceError::RequestRegistrySaturated);
        }
        let previous = self.pending.insert(key, binding);
        if previous.is_some() {
            return Err(ServiceError::RequestRegistryInvariant);
        }
        Ok(())
    }

    fn make_retained_slot(&mut self) -> Result<(), ServiceError> {
        while self.retained_len() >= self.capacity {
            let evicted = self
                .resolved_order
                .pop_front()
                .ok_or(ServiceError::RequestRegistryInvariant)?;
            if !self.resolved.remove(&evicted) {
                return Err(ServiceError::RequestRegistryInvariant);
            }
        }
        Ok(())
    }

    fn abort(&mut self, key: &RequestKey) -> Result<(), ServiceError> {
        if self.pending.remove(key).is_none() {
            return Err(ServiceError::RequestRegistryInvariant);
        }
        Ok(())
    }

    fn mark_resolved(&mut self, key: &RequestKey) -> Result<(), ServiceError> {
        self.make_retained_slot()?;
        if self.pending.remove(key).is_none() || !self.resolved.insert(key.clone()) {
            return Err(ServiceError::RequestRegistryInvariant);
        }
        self.resolved_order.push_back(key.clone());
        Ok(())
    }

    fn mark_unresolved(&mut self, key: &RequestKey) -> Result<(), ServiceError> {
        self.make_retained_slot()?;
        let binding = self
            .pending
            .remove(key)
            .ok_or(ServiceError::RequestRegistryInvariant)?;
        if self.unresolved.insert(key.clone(), binding).is_some() {
            return Err(ServiceError::RequestRegistryInvariant);
        }
        Ok(())
    }

    fn resolve_unresolved(&mut self, key: &RequestKey) -> Result<(), ServiceError> {
        let binding = self
            .unresolved
            .remove(key)
            .ok_or(ServiceError::RequestRegistryInvariant)?;
        drop(binding);
        if !self.resolved.insert(key.clone()) {
            return Err(ServiceError::RequestRegistryInvariant);
        }
        self.resolved_order.push_back(key.clone());
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceOutput {
    Read {
        metadata: KvMetadata,
        value: SecretValue,
    },
    Written(KvMetadata),
    Deleted(KvMetadata),
    Listed(Vec<CanonicalPath>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceResponse {
    Completed(ServiceOutput),
    OutcomeUnknownAfterEntry { recovery_reference: Id },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostCommitError;

impl fmt::Display for PostCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("post-commit confirmation failed")
    }
}

impl Error for PostCommitError {}

pub trait PostCommitHook: fmt::Debug {
    fn after_commit(&mut self, request_id: &Id) -> Result<(), PostCommitError>;
}

#[derive(Debug, Default)]
pub struct NoopPostCommitHook;

impl PostCommitHook for NoopPostCommitHook {
    fn after_commit(&mut self, _request_id: &Id) -> Result<(), PostCommitError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct FailOncePostCommitHook {
    failed: bool,
}

impl PostCommitHook for FailOncePostCommitHook {
    fn after_commit(&mut self, _request_id: &Id) -> Result<(), PostCommitError> {
        if self.failed {
            return Ok(());
        }
        self.failed = true;
        Err(PostCommitError)
    }
}

#[derive(Debug)]
pub struct ServiceCore<H: PostCommitHook> {
    identities: IdentityStore,
    policies: PolicyStore,
    tokens: TokenStore,
    namespaces: NamespaceStore,
    mounts: MountRouter,
    kv: KvStore,
    telemetry: MemoryTelemetry,
    reconciliation: ReconciliationStore,
    request_registry: RequestRegistry,
    recovery_requests: BTreeMap<Id, RequestKey>,
    next_recovery_sequence: u64,
    post_commit: H,
}

impl<H: PostCommitHook> ServiceCore<H> {
    pub fn new(max_versions: usize, post_commit: H) -> Result<Self, ServiceError> {
        Self::new_with_request_capacity(
            max_versions,
            DEFAULT_REQUEST_REGISTRY_CAPACITY,
            post_commit,
        )
    }

    pub fn new_with_request_capacity(
        max_versions: usize,
        request_registry_capacity: usize,
        post_commit: H,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            identities: IdentityStore::default(),
            policies: PolicyStore::default(),
            tokens: TokenStore::default(),
            namespaces: NamespaceStore::default(),
            mounts: MountRouter::default(),
            kv: KvStore::new(max_versions).map_err(ServiceError::Kv)?,
            telemetry: MemoryTelemetry::default(),
            reconciliation: ReconciliationStore::default(),
            request_registry: RequestRegistry::new(request_registry_capacity)?,
            recovery_requests: BTreeMap::new(),
            next_recovery_sequence: 0,
            post_commit,
        })
    }

    pub fn identities_mut(&mut self) -> &mut IdentityStore {
        &mut self.identities
    }

    pub fn policies_mut(&mut self) -> &mut PolicyStore {
        &mut self.policies
    }

    pub fn tokens_mut(&mut self) -> &mut TokenStore {
        &mut self.tokens
    }

    pub fn namespaces_mut(&mut self) -> &mut NamespaceStore {
        &mut self.namespaces
    }

    pub fn mounts_mut(&mut self) -> &mut MountRouter {
        &mut self.mounts
    }

    pub fn kv(&self) -> &KvStore {
        &self.kv
    }

    pub fn telemetry(&self) -> &MemoryTelemetry {
        &self.telemetry
    }

    pub fn reconciliation(&self) -> &ReconciliationStore {
        &self.reconciliation
    }

    pub fn request_registry_counts(&self) -> RequestRegistryCounts {
        self.request_registry.counts()
    }

    pub fn resolve_unknown(
        &mut self,
        recovery_reference: &Id,
        resolution: Resolution,
    ) -> Result<(), ServiceError> {
        let key = self
            .recovery_requests
            .get(recovery_reference)
            .cloned()
            .ok_or(ServiceError::MissingRecoveryReference)?;
        self.reconciliation
            .resolve(recovery_reference, resolution)
            .map_err(ServiceError::Operator)?;
        self.request_registry.resolve_unresolved(&key)?;
        if self.recovery_requests.remove(recovery_reference).is_none() {
            return Err(ServiceError::RequestRegistryInvariant);
        }
        Ok(())
    }

    fn allocate_recovery_reference(&mut self) -> Result<Id, ServiceError> {
        let sequence = self
            .next_recovery_sequence
            .checked_add(1)
            .ok_or(ServiceError::RecoveryReferenceOverflow)?;
        let reference = Id::parse(format!("recovery_{sequence}")).map_err(ServiceError::Domain)?;
        self.next_recovery_sequence = sequence;
        Ok(reference)
    }

    pub fn handle(
        &mut self,
        request: ServiceRequest,
        now: Tick,
    ) -> Result<ServiceResponse, ServiceError> {
        let token = self
            .tokens
            .validate(&request.token_id, now)
            .map_err(ServiceError::Token)?;
        let principal_id = token.entity_id.clone();
        let mut effective = self
            .identities
            .effective_policy_ids(&principal_id)
            .map_err(ServiceError::Identity)?;
        effective.extend(token.policy_ids);
        if !self
            .policies
            .authorize(&effective, request.operation.capability(), &request.path)
        {
            return Err(ServiceError::Unauthorized);
        }
        let _qualified_path = self
            .namespaces
            .qualify(&request.namespace_id, &request.path)
            .map_err(ServiceError::Namespace)?;
        let route = self
            .mounts
            .route(&request.namespace_id, &request.path)
            .map_err(ServiceError::Mount)?;
        if route.backend != Backend::Kv {
            return Err(ServiceError::UnsupportedBackend);
        }
        let operation_label = request.operation.label();
        let success_event = telemetry_event(operation_label, "completed")?;
        let unknown_event = telemetry_event(operation_label, "outcome_unknown")?;
        let engine_path =
            engine_path(&request.namespace_id, &route.mount_id, &route.relative_path)?;
        let request_key = if request.operation.is_commit() {
            let key = RequestKey {
                principal_id,
                namespace_id: request.namespace_id.clone(),
                request_id: request.request_id.clone(),
            };
            let binding = RequestBinding {
                path: request.path.clone(),
                operation: request.operation.clone(),
            };
            self.request_registry.begin(key.clone(), binding)?;
            Some(key)
        } else {
            None
        };
        let recovery_reference = if let Some(key) = &request_key {
            match self.allocate_recovery_reference() {
                Ok(reference) => Some(reference),
                Err(error) => {
                    self.request_registry.abort(key)?;
                    return Err(error);
                }
            }
        } else {
            None
        };
        let output_result = match request.operation {
            ServiceOperation::KvRead { version } => {
                let read = self
                    .kv
                    .read(&engine_path, version)
                    .map_err(ServiceError::Kv)?;
                let value = SecretValue::new(read.value.to_vec()).map_err(ServiceError::Domain)?;
                Ok(ServiceOutput::Read {
                    metadata: read.metadata,
                    value,
                })
            }
            ServiceOperation::KvWrite { value, cas } => self
                .kv
                .write(engine_path, value, now, cas)
                .map(ServiceOutput::Written)
                .map_err(ServiceError::Kv),
            ServiceOperation::KvDelete => self
                .kv
                .delete_latest(&engine_path)
                .map(ServiceOutput::Deleted)
                .map_err(ServiceError::Kv),
            ServiceOperation::KvList => Ok(ServiceOutput::Listed(self.kv.list(&engine_path))),
        };
        let output = match output_result {
            Ok(output) => output,
            Err(error) => {
                if let Some(key) = &request_key {
                    self.request_registry.abort(key)?;
                }
                return Err(error);
            }
        };
        if let Some(key) = &request_key {
            if self.post_commit.after_commit(&request.request_id).is_err() {
                self.request_registry.mark_unresolved(key)?;
                let recovery_reference =
                    recovery_reference.ok_or(ServiceError::RequestRegistryInvariant)?;
                if self
                    .recovery_requests
                    .insert(recovery_reference.clone(), key.clone())
                    .is_some()
                {
                    return Err(ServiceError::RequestRegistryInvariant);
                }
                let record = OutcomeRecord::unknown_after_entry(
                    request.request_id.clone(),
                    recovery_reference.clone(),
                );
                self.reconciliation
                    .record(record)
                    .map_err(ServiceError::Operator)?;
                self.telemetry.record(unknown_event);
                return Ok(ServiceResponse::OutcomeUnknownAfterEntry { recovery_reference });
            }
            self.request_registry.mark_resolved(key)?;
        }
        self.telemetry.record(success_event);
        Ok(ServiceResponse::Completed(output))
    }
}

fn engine_path(
    namespace_id: &Id,
    mount_id: &Id,
    relative_path: &str,
) -> Result<CanonicalPath, ServiceError> {
    let value = if relative_path.is_empty() {
        format!("/{}/{}", namespace_id.as_str(), mount_id.as_str())
    } else {
        format!(
            "/{}/{}/{}",
            namespace_id.as_str(),
            mount_id.as_str(),
            relative_path
        )
    };
    CanonicalPath::parse(value).map_err(ServiceError::Domain)
}

fn telemetry_event(operation: &str, outcome: &str) -> Result<TelemetryEvent, ServiceError> {
    let mut labels = BTreeMap::new();
    labels.insert(
        Id::parse("operation").map_err(ServiceError::Domain)?,
        Id::parse(operation).map_err(ServiceError::Domain)?,
    );
    labels.insert(
        Id::parse("outcome").map_err(ServiceError::Domain)?,
        Id::parse(outcome).map_err(ServiceError::Domain)?,
    );
    TelemetryEvent::new(
        Id::parse("request_completed").map_err(ServiceError::Domain)?,
        labels,
    )
    .map_err(ServiceError::Telemetry)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    DuplicateRequest,
    RequestBindingMismatch,
    RequestRegistrySaturated,
    RequestRegistryInvariant,
    InvalidRequestRegistryCapacity,
    MissingRecoveryReference,
    RecoveryReferenceOverflow,
    Unauthorized,
    UnsupportedBackend,
    Domain(DomainError),
    Identity(IdentityError),
    Token(TokenError),
    Namespace(NamespaceError),
    Mount(MountError),
    Kv(KvError),
    Telemetry(TelemetryError),
    Operator(OperatorError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateRequest => {
                "request identifier was already used for this principal and namespace"
            }
            Self::RequestBindingMismatch => "request identifier is bound to a different operation",
            Self::RequestRegistrySaturated => {
                "request registry is saturated by admitted operations"
            }
            Self::RequestRegistryInvariant => "request registry invariant failed",
            Self::InvalidRequestRegistryCapacity => "request registry capacity must be positive",
            Self::MissingRecoveryReference => {
                "recovery reference does not identify an unresolved request"
            }
            Self::RecoveryReferenceOverflow => "recovery reference sequence overflowed",
            Self::Unauthorized => "request is not authorized",
            Self::UnsupportedBackend => "selected backend is not supported by this composition",
            Self::Domain(_) => "domain value is invalid",
            Self::Identity(_) => "identity resolution failed",
            Self::Token(_) => "token validation failed",
            Self::Namespace(_) => "namespace resolution failed",
            Self::Mount(_) => "mount routing failed",
            Self::Kv(_) => "KV operation failed",
            Self::Telemetry(_) => "telemetry event construction failed",
            Self::Operator(_) => "operator reconciliation failed",
        })
    }
}

impl Error for ServiceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_policy::{Policy, PolicyRule};

    #[derive(Debug, Default)]
    struct AlwaysFailPostCommitHook;

    impl PostCommitHook for AlwaysFailPostCommitHook {
        fn after_commit(&mut self, _request_id: &Id) -> Result<(), PostCommitError> {
            Err(PostCommitError)
        }
    }

    fn configured<H: PostCommitHook>(hook: H) -> Result<(ServiceCore<H>, TokenId), Box<dyn Error>> {
        configured_with_capacity(hook, DEFAULT_REQUEST_REGISTRY_CAPACITY)
    }

    fn configured_with_capacity<H: PostCommitHook>(
        hook: H,
        request_registry_capacity: usize,
    ) -> Result<(ServiceCore<H>, TokenId), Box<dyn Error>> {
        let mut service =
            ServiceCore::new_with_request_capacity(4, request_registry_capacity, hook)?;
        let root = Id::parse("root")?;
        service.namespaces_mut().bootstrap_root(root.clone())?;
        service.mounts_mut().mount(
            Id::parse("root_secret")?,
            root,
            CanonicalPath::parse("/secret")?,
            Backend::Kv,
        )?;
        let entity = Id::parse("alice")?;
        service.identities_mut().create_entity(entity.clone())?;
        let policy_id = Id::parse("app_rw")?;
        let capabilities = [
            Capability::Read,
            Capability::Update,
            Capability::Delete,
            Capability::List,
        ]
        .into_iter()
        .collect();
        let rule = PolicyRule::new(CanonicalPath::parse("/secret")?, capabilities)?;
        service
            .policies_mut()
            .insert(Policy::new(policy_id.clone(), vec![rule])?)?;
        service.identities_mut().attach_policy(&entity, policy_id)?;
        let token_id = TokenId::parse("token_alice")?;
        service.tokens_mut().issue(
            token_id.clone(),
            entity,
            BTreeSet::new(),
            Tick::new(0),
            1000,
            true,
        )?;
        Ok((service, token_id))
    }

    #[test]
    fn accepted_request_runs_identity_policy_namespace_mount_and_engine()
    -> Result<(), Box<dyn Error>> {
        let (mut service, token) = configured(NoopPostCommitHook)?;
        let write = service.handle(
            ServiceRequest {
                request_id: Id::parse("write_one")?,
                token_id: token.clone(),
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"value-one".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(1),
        )?;
        assert!(matches!(
            write,
            ServiceResponse::Completed(ServiceOutput::Written(_))
        ));
        let read = service.handle(
            ServiceRequest {
                request_id: Id::parse("read_one")?,
                token_id: token,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvRead { version: None },
            },
            Tick::new(2),
        )?;
        match read {
            ServiceResponse::Completed(ServiceOutput::Read { value, .. }) => {
                assert_eq!(b"value-one", value.expose());
            }
            _ => return Err("unexpected service response".into()),
        }
        assert_eq!(2, service.telemetry().events().len());
        Ok(())
    }

    #[test]
    fn default_deny_and_token_revocation_stop_dispatch() -> Result<(), Box<dyn Error>> {
        let (mut service, token) = configured(NoopPostCommitHook)?;
        let bob = Id::parse("bob")?;
        service.identities_mut().create_entity(bob.clone())?;
        let bob_token = TokenId::parse("token_bob")?;
        service.tokens_mut().issue(
            bob_token.clone(),
            bob,
            BTreeSet::new(),
            Tick::new(0),
            100,
            false,
        )?;
        let denied = service.handle(
            ServiceRequest {
                request_id: Id::parse("denied_one")?,
                token_id: bob_token,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvRead { version: None },
            },
            Tick::new(1),
        );
        assert_eq!(Err(ServiceError::Unauthorized), denied);
        service.tokens_mut().revoke(&token, Tick::new(2))?;
        let revoked = service.handle(
            ServiceRequest {
                request_id: Id::parse("revoked_one")?,
                token_id: token,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvRead { version: None },
            },
            Tick::new(3),
        );
        assert_eq!(Err(ServiceError::Token(TokenError::Revoked)), revoked);
        Ok(())
    }

    #[test]
    fn request_registry_rejects_zero_capacity() {
        assert!(matches!(
            ServiceCore::new_with_request_capacity(4, 0, NoopPostCommitHook),
            Err(ServiceError::InvalidRequestRegistryCapacity)
        ));
    }

    #[test]
    fn resolved_request_retention_is_finite_and_fifo() -> Result<(), Box<dyn Error>> {
        let (mut service, token) = configured_with_capacity(NoopPostCommitHook, 2)?;
        for index in 0..3 {
            service.handle(
                ServiceRequest {
                    request_id: Id::parse(format!("resolved_{index}"))?,
                    token_id: token.clone(),
                    namespace_id: Id::parse("root")?,
                    path: CanonicalPath::parse(format!("/secret/resolved_{index}"))?,
                    operation: ServiceOperation::KvWrite {
                        value: SecretValue::new(vec![b'a' + index])?,
                        cas: Some(0),
                    },
                },
                Tick::new(u64::from(index)),
            )?;
        }
        assert_eq!(2, service.request_registry_counts().resolved);
        assert_eq!(2, service.request_registry_counts().total());
        Ok(())
    }

    #[test]
    fn invalid_token_cannot_preempt_a_later_authenticated_request_id() -> Result<(), Box<dyn Error>>
    {
        let (mut service, token) = configured(NoopPostCommitHook)?;
        let request_id = Id::parse("shared_request")?;
        let invalid = service.handle(
            ServiceRequest {
                request_id: request_id.clone(),
                token_id: TokenId::parse("missing_token")?,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"rejected".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(1),
        );
        assert_eq!(Err(ServiceError::Token(TokenError::MissingToken)), invalid);
        assert_eq!(0, service.request_registry_counts().total());

        let accepted = service.handle(
            ServiceRequest {
                request_id,
                token_id: token,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"accepted".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(2),
        )?;
        assert!(matches!(
            accepted,
            ServiceResponse::Completed(ServiceOutput::Written(_))
        ));
        Ok(())
    }

    #[test]
    fn request_ids_are_scoped_to_authenticated_principal_and_namespace()
    -> Result<(), Box<dyn Error>> {
        let (mut service, alice_token) = configured(NoopPostCommitHook)?;
        let bob = Id::parse("bob")?;
        service.identities_mut().create_entity(bob.clone())?;
        service
            .identities_mut()
            .attach_policy(&bob, Id::parse("app_rw")?)?;
        let bob_token = TokenId::parse("token_bob")?;
        service.tokens_mut().issue(
            bob_token.clone(),
            bob,
            BTreeSet::new(),
            Tick::new(0),
            1000,
            true,
        )?;
        let shared = Id::parse("shared_principal_request")?;

        for (token_id, path, value) in [
            (alice_token, "/secret/alice", &b"alice"[..]),
            (bob_token, "/secret/bob", &b"bob"[..]),
        ] {
            service.handle(
                ServiceRequest {
                    request_id: shared.clone(),
                    token_id,
                    namespace_id: Id::parse("root")?,
                    path: CanonicalPath::parse(path)?,
                    operation: ServiceOperation::KvWrite {
                        value: SecretValue::new(value.to_vec())?,
                        cas: Some(0),
                    },
                },
                Tick::new(1),
            )?;
        }
        assert_eq!(2, service.request_registry_counts().resolved);
        Ok(())
    }

    #[test]
    fn rejected_engine_operation_releases_request_identity_for_a_safe_retry()
    -> Result<(), Box<dyn Error>> {
        let (mut service, token) = configured(NoopPostCommitHook)?;
        let request_id = Id::parse("cas_retry")?;
        let rejected = service.handle(
            ServiceRequest {
                request_id: request_id.clone(),
                token_id: token.clone(),
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/cas")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"first".to_vec())?,
                    cas: Some(1),
                },
            },
            Tick::new(1),
        );
        assert_eq!(Err(ServiceError::Kv(KvError::CasMismatch)), rejected);
        assert_eq!(0, service.request_registry_counts().total());

        service.handle(
            ServiceRequest {
                request_id,
                token_id: token,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/cas")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"second".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(2),
        )?;
        assert_eq!(1, service.request_registry_counts().resolved);
        Ok(())
    }

    #[test]
    fn rejected_mutation_does_not_evict_a_resolved_request_id() -> Result<(), Box<dyn Error>> {
        let (mut service, token) = configured_with_capacity(NoopPostCommitHook, 1)?;
        let retained_id = Id::parse("retained_request")?;
        service.handle(
            ServiceRequest {
                request_id: retained_id.clone(),
                token_id: token.clone(),
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/retained")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"retained".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(1),
        )?;

        let rejected = service.handle(
            ServiceRequest {
                request_id: Id::parse("failed_request")?,
                token_id: token.clone(),
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/failed")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"rejected".to_vec())?,
                    cas: Some(1),
                },
            },
            Tick::new(2),
        );
        assert_eq!(Err(ServiceError::Kv(KvError::CasMismatch)), rejected);

        let duplicate = service.handle(
            ServiceRequest {
                request_id: retained_id,
                token_id: token,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/retained")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"retained".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(3),
        );
        assert_eq!(Err(ServiceError::DuplicateRequest), duplicate);
        assert_eq!(1, service.request_registry_counts().resolved);
        Ok(())
    }

    #[test]
    fn invalid_input_does_not_grow_the_bounded_request_registry() -> Result<(), Box<dyn Error>> {
        let (mut service, _token) = configured_with_capacity(NoopPostCommitHook, 2)?;
        for index in 0..64 {
            let result = service.handle(
                ServiceRequest {
                    request_id: Id::parse(format!("invalid_{index}"))?,
                    token_id: TokenId::parse("missing_token")?,
                    namespace_id: Id::parse("root")?,
                    path: CanonicalPath::parse("/secret/app")?,
                    operation: ServiceOperation::KvWrite {
                        value: SecretValue::new(b"rejected".to_vec())?,
                        cas: Some(0),
                    },
                },
                Tick::new(1),
            );
            assert_eq!(Err(ServiceError::Token(TokenError::MissingToken)), result);
        }
        assert_eq!(
            RequestRegistryCounts {
                capacity: 2,
                pending: 0,
                unresolved: 0,
                resolved: 0,
            },
            service.request_registry_counts()
        );
        Ok(())
    }

    #[test]
    fn unresolved_effects_are_exactly_bound_and_never_evicted() -> Result<(), Box<dyn Error>> {
        let (mut service, token) = configured_with_capacity(FailOncePostCommitHook::default(), 1)?;
        let request_id = Id::parse("unresolved_one")?;
        let first = service.handle(
            ServiceRequest {
                request_id: request_id.clone(),
                token_id: token.clone(),
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/one")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"committed".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(1),
        )?;
        assert!(matches!(
            first,
            ServiceResponse::OutcomeUnknownAfterEntry { .. }
        ));
        assert_eq!(1, service.request_registry_counts().unresolved);

        let different_binding = service.handle(
            ServiceRequest {
                request_id: request_id.clone(),
                token_id: token.clone(),
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/one")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"different".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(2),
        );
        assert_eq!(Err(ServiceError::RequestBindingMismatch), different_binding);

        let exact_duplicate = service.handle(
            ServiceRequest {
                request_id,
                token_id: token.clone(),
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/one")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"committed".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(3),
        );
        assert_eq!(Err(ServiceError::DuplicateRequest), exact_duplicate);

        let saturated = service.handle(
            ServiceRequest {
                request_id: Id::parse("second_request")?,
                token_id: token,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/two")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"must-not-dispatch".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(4),
        );
        assert_eq!(Err(ServiceError::RequestRegistrySaturated), saturated);
        assert_eq!(
            0,
            service
                .kv()
                .current_version(&CanonicalPath::parse("/root/root_secret/two")?)
        );
        assert_eq!(1, service.request_registry_counts().unresolved);
        Ok(())
    }

    #[test]
    fn recovery_references_disambiguate_cross_principal_unknown_outcomes()
    -> Result<(), Box<dyn Error>> {
        let (mut service, alice_token) = configured_with_capacity(AlwaysFailPostCommitHook, 2)?;
        let bob = Id::parse("bob_unknown")?;
        service.identities_mut().create_entity(bob.clone())?;
        service
            .identities_mut()
            .attach_policy(&bob, Id::parse("app_rw")?)?;
        let bob_token = TokenId::parse("token_bob_unknown")?;
        service.tokens_mut().issue(
            bob_token.clone(),
            bob,
            BTreeSet::new(),
            Tick::new(0),
            1000,
            true,
        )?;
        let shared = Id::parse("same_external_request")?;
        let mut references = Vec::new();
        for (token_id, path) in [
            (alice_token, "/secret/alice_unknown"),
            (bob_token, "/secret/bob_unknown"),
        ] {
            let response = service.handle(
                ServiceRequest {
                    request_id: shared.clone(),
                    token_id,
                    namespace_id: Id::parse("root")?,
                    path: CanonicalPath::parse(path)?,
                    operation: ServiceOperation::KvWrite {
                        value: SecretValue::new(b"committed".to_vec())?,
                        cas: Some(0),
                    },
                },
                Tick::new(1),
            )?;
            match response {
                ServiceResponse::OutcomeUnknownAfterEntry { recovery_reference } => {
                    references.push(recovery_reference);
                }
                _ => return Err("unexpected service response".into()),
            }
        }
        let first_reference = references
            .first()
            .cloned()
            .ok_or("missing first recovery reference")?;
        let second_reference = references
            .get(1)
            .cloned()
            .ok_or("missing second recovery reference")?;
        assert_ne!(first_reference, second_reference);
        for reference in &references {
            assert_eq!(
                heptabao_operator_api::OperatorAction::AuthoritativeReadback,
                service.reconciliation().get(reference)?.action()
            );
        }
        service.resolve_unknown(
            &first_reference,
            heptabao_operator_api::Resolution::ConfirmedCommitted,
        )?;
        assert_eq!(1, service.request_registry_counts().unresolved);
        assert_eq!(1, service.request_registry_counts().resolved);
        assert_eq!(
            heptabao_operator_api::OperatorAction::DoNotRetry,
            service.reconciliation().get(&first_reference)?.action()
        );
        Ok(())
    }

    #[test]
    fn namespace_storage_keys_are_isolated() -> Result<(), Box<dyn Error>> {
        let (mut service, token) = configured(NoopPostCommitHook)?;
        let root = Id::parse("root")?;
        let team = Id::parse("team")?;
        service.namespaces_mut().create(team.clone(), &root)?;
        service.mounts_mut().mount(
            Id::parse("team_secret")?,
            team.clone(),
            CanonicalPath::parse("/secret")?,
            Backend::Kv,
        )?;
        for (request_id, namespace_id, value) in [
            ("write_root", root, &b"root-value"[..]),
            ("write_team", team.clone(), &b"team-value"[..]),
        ] {
            service.handle(
                ServiceRequest {
                    request_id: Id::parse(request_id)?,
                    token_id: token.clone(),
                    namespace_id,
                    path: CanonicalPath::parse("/secret/app")?,
                    operation: ServiceOperation::KvWrite {
                        value: SecretValue::new(value.to_vec())?,
                        cas: Some(0),
                    },
                },
                Tick::new(1),
            )?;
        }
        let team_read = service.handle(
            ServiceRequest {
                request_id: Id::parse("read_team")?,
                token_id: token,
                namespace_id: team,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvRead { version: None },
            },
            Tick::new(2),
        )?;
        match team_read {
            ServiceResponse::Completed(ServiceOutput::Read { value, .. }) => {
                assert_eq!(b"team-value", value.expose());
            }
            _ => return Err("unexpected service response".into()),
        }
        Ok(())
    }

    #[test]
    fn unknown_after_entry_is_recorded_and_request_is_not_replayed() -> Result<(), Box<dyn Error>> {
        let (mut service, token) = configured(FailOncePostCommitHook::default())?;
        let request_id = Id::parse("ambiguous_write")?;
        let response = service.handle(
            ServiceRequest {
                request_id: request_id.clone(),
                token_id: token.clone(),
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"committed-once".to_vec())?,
                    cas: Some(0),
                },
            },
            Tick::new(1),
        )?;
        let recovery_reference = match response {
            ServiceResponse::OutcomeUnknownAfterEntry { recovery_reference } => recovery_reference,
            _ => return Err("unexpected service response".into()),
        };
        assert_ne!(request_id, recovery_reference);
        let engine_path = CanonicalPath::parse("/root/root_secret/app")?;
        assert_eq!(1, service.kv().current_version(&engine_path));
        let replay = service.handle(
            ServiceRequest {
                request_id: request_id.clone(),
                token_id: token,
                namespace_id: Id::parse("root")?,
                path: CanonicalPath::parse("/secret/app")?,
                operation: ServiceOperation::KvWrite {
                    value: SecretValue::new(b"duplicate".to_vec())?,
                    cas: None,
                },
            },
            Tick::new(2),
        );
        assert_eq!(Err(ServiceError::RequestBindingMismatch), replay);
        assert_eq!(1, service.kv().current_version(&engine_path));
        assert_eq!(
            heptabao_operator_api::OperatorAction::AuthoritativeReadback,
            service.reconciliation().get(&recovery_reference)?.action()
        );
        Ok(())
    }
}
