#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Mandatory request composition for the V2 single-process product candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use heptabao_domain::{CanonicalPath, DomainError, Id, SecretValue, Tick};
use heptabao_identity::{IdentityError, IdentityStore};
use heptabao_kv_engine::{KvError, KvMetadata, KvStore};
use heptabao_mount_router::{Backend, MountError, MountRouter};
use heptabao_namespace::{NamespaceError, NamespaceStore};
use heptabao_operator_api::{OutcomeRecord, ReconciliationStore};
use heptabao_policy::{Capability, PolicyStore};
use heptabao_telemetry::{MemoryTelemetry, TelemetryError, TelemetryEvent};
use heptabao_token::{TokenError, TokenId, TokenStore};

#[derive(Debug)]
pub enum ServiceOperation {
    KvRead { version: Option<u64> },
    KvWrite { value: SecretValue, cas: Option<u64> },
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceOutput {
    Read { metadata: KvMetadata, value: SecretValue },
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
    seen_requests: BTreeSet<Id>,
    post_commit: H,
}

impl<H: PostCommitHook> ServiceCore<H> {
    pub fn new(max_versions: usize, post_commit: H) -> Result<Self, ServiceError> {
        Ok(Self {
            identities: IdentityStore::default(),
            policies: PolicyStore::default(),
            tokens: TokenStore::default(),
            namespaces: NamespaceStore::default(),
            mounts: MountRouter::default(),
            kv: KvStore::new(max_versions).map_err(ServiceError::Kv)?,
            telemetry: MemoryTelemetry::default(),
            reconciliation: ReconciliationStore::default(),
            seen_requests: BTreeSet::new(),
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

    pub fn handle(
        &mut self,
        request: ServiceRequest,
        now: Tick,
    ) -> Result<ServiceResponse, ServiceError> {
        if !self.seen_requests.insert(request.request_id.clone()) {
            return Err(ServiceError::DuplicateRequest);
        }
        let token = self
            .tokens
            .validate(&request.token_id, now)
            .map_err(ServiceError::Token)?;
        let mut effective = self
            .identities
            .effective_policy_ids(&token.entity_id)
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
        let engine_path = engine_path(
            &request.namespace_id,
            &route.mount_id,
            &route.relative_path,
        )?;
        let is_commit = request.operation.is_commit();
        let output = match request.operation {
            ServiceOperation::KvRead { version } => {
                let read = self.kv.read(&engine_path, version).map_err(ServiceError::Kv)?;
                let value = SecretValue::new(read.value.to_vec()).map_err(ServiceError::Domain)?;
                ServiceOutput::Read {
                    metadata: read.metadata,
                    value,
                }
            }
            ServiceOperation::KvWrite { value, cas } => ServiceOutput::Written(
                self.kv
                    .write(engine_path, value, now, cas)
                    .map_err(ServiceError::Kv)?,
            ),
            ServiceOperation::KvDelete => ServiceOutput::Deleted(
                self.kv
                    .delete_latest(&engine_path)
                    .map_err(ServiceError::Kv)?,
            ),
            ServiceOperation::KvList => ServiceOutput::Listed(self.kv.list(&engine_path)),
        };
        if is_commit && self.post_commit.after_commit(&request.request_id).is_err() {
            let recovery_reference = request.request_id.clone();
            let record = OutcomeRecord::unknown_after_entry(
                request.request_id.clone(),
                recovery_reference.clone(),
            );
            let _ = self.reconciliation.record(record);
            self.telemetry.record(unknown_event);
            return Ok(ServiceResponse::OutcomeUnknownAfterEntry { recovery_reference });
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
    Unauthorized,
    UnsupportedBackend,
    Domain(DomainError),
    Identity(IdentityError),
    Token(TokenError),
    Namespace(NamespaceError),
    Mount(MountError),
    Kv(KvError),
    Telemetry(TelemetryError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateRequest => "request identifier was already used",
            Self::Unauthorized => "request is not authorized",
            Self::UnsupportedBackend => "selected backend is not supported by this composition",
            Self::Domain(_) => "domain value is invalid",
            Self::Identity(_) => "identity resolution failed",
            Self::Token(_) => "token validation failed",
            Self::Namespace(_) => "namespace resolution failed",
            Self::Mount(_) => "mount routing failed",
            Self::Kv(_) => "KV operation failed",
            Self::Telemetry(_) => "telemetry event construction failed",
        })
    }
}

impl Error for ServiceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_policy::{Policy, PolicyRule};

    fn configured<H: PostCommitHook>(hook: H) -> Result<(ServiceCore<H>, TokenId), Box<dyn Error>> {
        let mut service = ServiceCore::new(4, hook)?;
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
        service
            .identities_mut()
            .attach_policy(&entity, policy_id)?;
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
    fn accepted_request_runs_identity_policy_namespace_mount_and_engine() -> Result<(), Box<dyn Error>> {
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
        assert!(matches!(write, ServiceResponse::Completed(ServiceOutput::Written(_))));
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
        assert_eq!(
            ServiceResponse::OutcomeUnknownAfterEntry {
                recovery_reference: request_id.clone()
            },
            response
        );
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
        assert_eq!(Err(ServiceError::DuplicateRequest), replay);
        assert_eq!(1, service.kv().current_version(&engine_path));
        assert_eq!(
            heptabao_operator_api::OperatorAction::AuthoritativeReadback,
            service.reconciliation().get(&request_id)?.action()
        );
        Ok(())
    }
}
