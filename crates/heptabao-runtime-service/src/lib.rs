#![forbid(unsafe_code)]

//! Admission-to-durability adapter for the HeptaBao repository candidate.
//!
//! `RuntimeService` owns its durable writer and exposes no mutable bypass. Every
//! mutation must authenticate, authorize, and append a pre-dispatch audit event
//! before it can enter the durable intent journal. Once durable entry may have
//! happened, failure is never translated into an automatic retry signal.

use sha2::{Digest, Sha256};

use std::fmt;

use heptabao_durable_service::{
    Barrier, DeleteRequest, DurableService, Failpoint, MutationOutcome, PutRequest,
    ReconciliationStatus, Secret, ServiceError,
};

const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_FIELD_BYTES: usize = 4 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct Credential(Vec<u8>);

impl Credential {
    pub fn new(bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
            return Err(RuntimeError::InvalidRequest);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credential([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    Put,
    Delete,
}

#[derive(Clone, Eq, PartialEq)]
pub enum InboundOperation {
    Put(Secret),
    Delete,
}

impl InboundOperation {
    #[must_use]
    pub const fn kind(&self) -> OperationKind {
        match self {
            Self::Put(_) => OperationKind::Put,
            Self::Delete => OperationKind::Delete,
        }
    }
}

impl fmt::Debug for InboundOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Put(_) => formatter.write_str("Put([REDACTED])"),
            Self::Delete => formatter.write_str("Delete"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct InboundMutation {
    credential: Credential,
    namespace: String,
    request_id: String,
    resource: String,
    operation: InboundOperation,
}

impl InboundMutation {
    pub fn new(
        credential: Credential,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        resource: impl Into<String>,
        operation: InboundOperation,
    ) -> Result<Self, RuntimeError> {
        let request = Self {
            credential,
            namespace: namespace.into(),
            request_id: request_id.into(),
            resource: resource.into(),
            operation,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        validate_field(&self.namespace)?;
        validate_field(&self.request_id)?;
        validate_field(&self.resource)?;
        Ok(())
    }
}

impl fmt::Debug for InboundMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundMutation")
            .field("credential", &self.credential)
            .field("namespace", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .field("resource", &"[REDACTED]")
            .field("operation", &self.operation)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedPrincipal(String);

impl AuthenticatedPrincipal {
    pub fn new(value: impl Into<String>) -> Result<Self, RuntimeError> {
        let value = value.into();
        validate_principal(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthenticatedPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPrincipal([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthorizationDigest([u8; 32]);

impl AuthorizationDigest {
    pub fn new(value: [u8; 32]) -> Result<Self, RuntimeError> {
        if value == [0; 32] {
            return Err(RuntimeError::AuthorizationDenied);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for AuthorizationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationDigest([REDACTED])")
    }
}

pub trait Authenticator {
    fn authenticate(
        &mut self,
        credential: &Credential,
    ) -> Result<AuthenticatedPrincipal, AuthenticationFailure>;
}

pub trait Authorizer {
    fn authorize(
        &mut self,
        principal: &AuthenticatedPrincipal,
        namespace: &str,
        resource: &str,
        operation: OperationKind,
    ) -> Result<AuthorizationDigest, AuthorizationFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationFailure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationFailure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditFailure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditStage {
    AcceptedBeforeEntry,
    Committed,
    Duplicate,
    OutcomeUnknown,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditEvent {
    stage: AuditStage,
    request_fingerprint: [u8; 32],
    generation: Option<u64>,
}

impl AuditEvent {
    #[must_use]
    pub const fn stage(&self) -> AuditStage {
        self.stage
    }

    #[must_use]
    pub const fn generation(&self) -> Option<u64> {
        self.generation
    }
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditEvent")
            .field("stage", &self.stage)
            .field("request_fingerprint", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

pub trait AuditSink {
    fn append(&mut self, event: &AuditEvent) -> Result<(), AuditFailure>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeOutcome {
    Committed {
        generation: u64,
        recovery_reference: String,
    },
    Duplicate {
        generation: u64,
        recovery_reference: String,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeError {
    InvalidRequest,
    AuthenticationDenied,
    AuthorizationDenied,
    AuditUnavailableBeforeEntry,
    OutcomeUnknown { recovery_reference: String },
    DurableRejected,
    DurableCorrupt,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("invalid inbound mutation"),
            Self::AuthenticationDenied => formatter.write_str("authentication denied"),
            Self::AuthorizationDenied => formatter.write_str("authorization denied"),
            Self::AuditUnavailableBeforeEntry => {
                formatter.write_str("pre-entry audit is unavailable")
            }
            Self::OutcomeUnknown { .. } => formatter.write_str("mutation outcome is unknown"),
            Self::DurableRejected => formatter.write_str("durable mutation rejected"),
            Self::DurableCorrupt => formatter.write_str("durable state failed closed"),
        }
    }
}

impl std::error::Error for RuntimeError {}

/// A mandatory admission-to-durability path.
///
/// The durable writer is private and has no accessor. A mutation can reach it only
/// through `handle`, which authenticates, authorizes and audits before dispatch.
pub struct RuntimeService<A, Z, U, B>
where
    A: Authenticator,
    Z: Authorizer,
    U: AuditSink,
    B: Barrier,
{
    authenticator: A,
    authorizer: Z,
    audit: U,
    durable: DurableService<B>,
}

impl<A, Z, U, B> fmt::Debug for RuntimeService<A, Z, U, B>
where
    A: Authenticator,
    Z: Authorizer,
    U: AuditSink,
    B: Barrier,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeService")
            .field("durable", &self.durable)
            .finish_non_exhaustive()
    }
}

impl<A, Z, U, B> RuntimeService<A, Z, U, B>
where
    A: Authenticator,
    Z: Authorizer,
    U: AuditSink,
    B: Barrier,
{
    #[must_use]
    pub const fn new(
        authenticator: A,
        authorizer: Z,
        audit: U,
        durable: DurableService<B>,
    ) -> Self {
        Self {
            authenticator,
            authorizer,
            audit,
            durable,
        }
    }

    pub fn handle(&mut self, request: InboundMutation) -> Result<RuntimeOutcome, RuntimeError> {
        self.handle_with_failpoint(request, Failpoint::None)
    }

    pub fn handle_with_failpoint(
        &mut self,
        request: InboundMutation,
        failpoint: Failpoint,
    ) -> Result<RuntimeOutcome, RuntimeError> {
        request.validate()?;
        let principal = self
            .authenticator
            .authenticate(&request.credential)
            .map_err(|_| RuntimeError::AuthenticationDenied)?;
        let authorization = self
            .authorizer
            .authorize(
                &principal,
                &request.namespace,
                &request.resource,
                request.operation.kind(),
            )
            .map_err(|_| RuntimeError::AuthorizationDenied)?;
        let fingerprint = request_fingerprint(
            &principal,
            &request.namespace,
            &request.request_id,
            &request.resource,
            request.operation.kind(),
            authorization,
        );
        self.audit
            .append(&AuditEvent {
                stage: AuditStage::AcceptedBeforeEntry,
                request_fingerprint: fingerprint,
                generation: None,
            })
            .map_err(|_| RuntimeError::AuditUnavailableBeforeEntry)?;

        let result = match request.operation {
            InboundOperation::Put(value) => PutRequest::new(
                principal.as_str(),
                request.namespace,
                request.request_id,
                request.resource,
                authorization.into_inner(),
                value,
            )
            .map_err(map_durable_error)
            .and_then(|mutation| {
                self.durable
                    .put_with_failpoint(mutation, failpoint)
                    .map_err(map_durable_error)
            }),
            InboundOperation::Delete => DeleteRequest::new(
                principal.as_str(),
                request.namespace,
                request.request_id,
                request.resource,
                authorization.into_inner(),
            )
            .map_err(map_durable_error)
            .and_then(|mutation| {
                self.durable
                    .delete_with_failpoint(mutation, failpoint)
                    .map_err(map_durable_error)
            }),
        };

        match result {
            Ok(MutationOutcome::Committed {
                generation,
                recovery_reference,
            }) => {
                if self
                    .audit
                    .append(&AuditEvent {
                        stage: AuditStage::Committed,
                        request_fingerprint: fingerprint,
                        generation: Some(generation),
                    })
                    .is_err()
                {
                    return Err(RuntimeError::OutcomeUnknown { recovery_reference });
                }
                Ok(RuntimeOutcome::Committed {
                    generation,
                    recovery_reference,
                })
            }
            Ok(MutationOutcome::Duplicate {
                generation,
                recovery_reference,
            }) => {
                if self
                    .audit
                    .append(&AuditEvent {
                        stage: AuditStage::Duplicate,
                        request_fingerprint: fingerprint,
                        generation: Some(generation),
                    })
                    .is_err()
                {
                    return Err(RuntimeError::OutcomeUnknown { recovery_reference });
                }
                Ok(RuntimeOutcome::Duplicate {
                    generation,
                    recovery_reference,
                })
            }
            Err(RuntimeError::OutcomeUnknown { recovery_reference }) => {
                let _ = self.audit.append(&AuditEvent {
                    stage: AuditStage::OutcomeUnknown,
                    request_fingerprint: fingerprint,
                    generation: None,
                });
                Err(RuntimeError::OutcomeUnknown { recovery_reference })
            }
            Err(other) => Err(other),
        }
    }

    #[must_use]
    pub fn reconcile(&self, recovery_reference: &str) -> ReconciliationStatus {
        self.durable.reconcile(recovery_reference)
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.durable.generation()
    }

    #[must_use]
    pub fn retained_request_count(&self) -> usize {
        self.durable.retained_request_count()
    }
}

fn validate_field(value: &str) -> Result<(), RuntimeError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || !value.is_ascii() {
        return Err(RuntimeError::InvalidRequest);
    }
    Ok(())
}

fn validate_principal(value: &str) -> Result<(), RuntimeError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RuntimeError::AuthenticationDenied);
    }
    Ok(())
}

fn map_durable_error(error: ServiceError) -> RuntimeError {
    match error {
        ServiceError::OutcomeUnknown { recovery_reference } => {
            RuntimeError::OutcomeUnknown { recovery_reference }
        }
        ServiceError::CorruptState | ServiceError::BarrierFailure => RuntimeError::DurableCorrupt,
        ServiceError::InvalidIdentifier
        | ServiceError::InvalidNamespace
        | ServiceError::InvalidResource
        | ServiceError::InvalidSecret
        | ServiceError::InvalidAuthorizationDigest => RuntimeError::InvalidRequest,
        ServiceError::RequestBindingConflict
        | ServiceError::RequestCapacityExhausted
        | ServiceError::GenerationOverflow
        | ServiceError::InvalidRoot
        | ServiceError::RootNotEmpty
        | ServiceError::WriterLocked
        | ServiceError::Io(_) => RuntimeError::DurableRejected,
    }
}

fn request_fingerprint(
    principal: &AuthenticatedPrincipal,
    namespace: &str,
    request_id: &str,
    resource: &str,
    operation: OperationKind,
    authorization: AuthorizationDigest,
) -> [u8; 32] {
    let mut material = Vec::new();
    append_length_prefixed(&mut material, principal.as_str().as_bytes());
    append_length_prefixed(&mut material, namespace.as_bytes());
    append_length_prefixed(&mut material, request_id.as_bytes());
    append_length_prefixed(&mut material, resource.as_bytes());
    material.push(match operation {
        OperationKind::Put => 1,
        OperationKind::Delete => 2,
    });
    material.extend_from_slice(&authorization.into_inner());
    digest32(b"heptabao.runtime-service.request.v1", &material)
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
}

fn digest32(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let domain_len = u64::try_from(domain.len()).unwrap_or(u64::MAX);
    let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut hasher = Sha256::new();
    hasher.update(domain_len.to_le_bytes());
    hasher.update(domain);
    hasher.update(bytes_len.to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_durable_service::BarrierError;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone)]
    struct TestBarrier([u8; 32]);

    impl TestBarrier {
        const fn new() -> Self {
            Self([0xa5; 32])
        }
    }

    impl Barrier for TestBarrier {
        fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
            let ciphertext: Vec<u8> = plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.0[index % self.0.len()])
                .collect();
            let mut material = Vec::new();
            material.extend_from_slice(&self.0);
            material.extend_from_slice(context);
            material.extend_from_slice(&ciphertext);
            let mut protected = Vec::new();
            protected.extend_from_slice(&digest32(b"heptabao.runtime-test-barrier.v1", &material));
            protected.extend_from_slice(&ciphertext);
            Ok(protected)
        }

        fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError> {
            let (tag, ciphertext) = protected.split_at_checked(32).ok_or(BarrierError)?;
            let mut material = Vec::new();
            material.extend_from_slice(&self.0);
            material.extend_from_slice(context);
            material.extend_from_slice(ciphertext);
            if tag != digest32(b"heptabao.runtime-test-barrier.v1", &material) {
                return Err(BarrierError);
            }
            Ok(ciphertext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.0[index % self.0.len()])
                .collect())
        }
    }

    struct Root(PathBuf);

    impl Root {
        fn new(label: &str) -> Result<Self, RuntimeError> {
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "heptabao-runtime-service-{label}-{}-{sequence}",
                std::process::id()
            ));
            if path.exists() {
                fs::remove_dir_all(&path).map_err(|_| RuntimeError::DurableRejected)?;
            }
            Ok(Self(path))
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone)]
    struct TestAuthenticator;

    impl Authenticator for TestAuthenticator {
        fn authenticate(
            &mut self,
            credential: &Credential,
        ) -> Result<AuthenticatedPrincipal, AuthenticationFailure> {
            match credential.expose() {
                b"token-a" => {
                    AuthenticatedPrincipal::new("principal-a").map_err(|_| AuthenticationFailure)
                }
                b"token-b" => {
                    AuthenticatedPrincipal::new("principal-b").map_err(|_| AuthenticationFailure)
                }
                _ => Err(AuthenticationFailure),
            }
        }
    }

    #[derive(Clone)]
    struct TestAuthorizer {
        allow: bool,
    }

    impl Authorizer for TestAuthorizer {
        fn authorize(
            &mut self,
            _principal: &AuthenticatedPrincipal,
            namespace: &str,
            resource: &str,
            _operation: OperationKind,
        ) -> Result<AuthorizationDigest, AuthorizationFailure> {
            if self.allow && namespace.starts_with("root/") && resource.starts_with("secret/") {
                AuthorizationDigest::new([0x33; 32]).map_err(|_| AuthorizationFailure)
            } else {
                Err(AuthorizationFailure)
            }
        }
    }

    #[derive(Clone, Default)]
    struct TestAudit {
        events: Vec<AuditEvent>,
        fail_on_call: Option<usize>,
        calls: usize,
    }

    impl AuditSink for TestAudit {
        fn append(&mut self, event: &AuditEvent) -> Result<(), AuditFailure> {
            self.calls = self.calls.saturating_add(1);
            if self.fail_on_call == Some(self.calls) {
                return Err(AuditFailure);
            }
            self.events.push(event.clone());
            Ok(())
        }
    }

    fn inbound(
        token: &[u8],
        request_id: &str,
        resource: &str,
        value: &[u8],
    ) -> Result<InboundMutation, RuntimeError> {
        InboundMutation::new(
            Credential::new(token.to_vec())?,
            "root/team-a",
            request_id,
            resource,
            InboundOperation::Put(Secret::new(value.to_vec()).map_err(map_durable_error)?),
        )
    }

    fn service(
        root: &Root,
        authorizer: TestAuthorizer,
        audit: TestAudit,
    ) -> Result<
        RuntimeService<TestAuthenticator, TestAuthorizer, TestAudit, TestBarrier>,
        RuntimeError,
    > {
        let durable = DurableService::create_new(&root.0, TestBarrier::new(), 32)
            .map_err(map_durable_error)?;
        Ok(RuntimeService::new(
            TestAuthenticator,
            authorizer,
            audit,
            durable,
        ))
    }

    #[test]
    fn invalid_credential_cannot_allocate_durable_request_identity() -> Result<(), RuntimeError> {
        let root = Root::new("invalid-token")?;
        let mut runtime = service(&root, TestAuthorizer { allow: true }, TestAudit::default())?;
        assert_eq!(
            runtime.handle(inbound(b"invalid", "request-1", "secret/app", b"value")?),
            Err(RuntimeError::AuthenticationDenied)
        );
        assert_eq!(runtime.retained_request_count(), 0);
        assert_eq!(runtime.generation(), 0);
        Ok(())
    }

    #[test]
    fn denied_request_does_not_preempt_later_authorized_identity() -> Result<(), RuntimeError> {
        let root = Root::new("deny-then-allow")?;
        let durable = DurableService::create_new(&root.0, TestBarrier::new(), 32)
            .map_err(map_durable_error)?;
        let mut runtime = RuntimeService::new(
            TestAuthenticator,
            TestAuthorizer { allow: false },
            TestAudit::default(),
            durable,
        );
        let request = inbound(b"token-a", "same-request", "secret/app", b"value")?;
        assert_eq!(
            runtime.handle(request.clone()),
            Err(RuntimeError::AuthorizationDenied)
        );
        assert_eq!(runtime.retained_request_count(), 0);
        runtime.authorizer.allow = true;
        assert!(matches!(
            runtime.handle(request)?,
            RuntimeOutcome::Committed { generation: 1, .. }
        ));
        Ok(())
    }

    #[test]
    fn request_identity_is_scoped_to_authenticated_principal() -> Result<(), RuntimeError> {
        let root = Root::new("principal-scope")?;
        let mut runtime = service(&root, TestAuthorizer { allow: true }, TestAudit::default())?;
        assert!(matches!(
            runtime.handle(inbound(b"token-a", "shared-id", "secret/a", b"a")?)?,
            RuntimeOutcome::Committed { generation: 1, .. }
        ));
        assert!(matches!(
            runtime.handle(inbound(b"token-b", "shared-id", "secret/b", b"b")?)?,
            RuntimeOutcome::Committed { generation: 2, .. }
        ));
        assert_eq!(runtime.retained_request_count(), 2);
        Ok(())
    }

    #[test]
    fn pre_entry_audit_failure_prevents_durable_dispatch() -> Result<(), RuntimeError> {
        let root = Root::new("audit-before")?;
        let audit = TestAudit {
            fail_on_call: Some(1),
            ..TestAudit::default()
        };
        let mut runtime = service(&root, TestAuthorizer { allow: true }, audit)?;
        assert_eq!(
            runtime.handle(inbound(
                b"token-a",
                "request-audit",
                "secret/app",
                b"value"
            )?),
            Err(RuntimeError::AuditUnavailableBeforeEntry)
        );
        assert_eq!(runtime.generation(), 0);
        assert_eq!(runtime.retained_request_count(), 0);
        Ok(())
    }

    #[test]
    fn post_commit_audit_failure_is_reconcile_only() -> Result<(), RuntimeError> {
        let root = Root::new("audit-after")?;
        let audit = TestAudit {
            fail_on_call: Some(2),
            ..TestAudit::default()
        };
        let mut runtime = service(&root, TestAuthorizer { allow: true }, audit)?;
        let request = inbound(b"token-a", "request-post-audit", "secret/app", b"value")?;
        let recovery_reference = match runtime.handle(request.clone()) {
            Err(RuntimeError::OutcomeUnknown { recovery_reference }) => recovery_reference,
            other => return other.map(|_| ()).and(Err(RuntimeError::DurableRejected)),
        };
        assert_eq!(
            runtime.reconcile(&recovery_reference),
            ReconciliationStatus::Committed { generation: 1 }
        );
        assert!(matches!(
            runtime.handle(request)?,
            RuntimeOutcome::Duplicate { generation: 1, .. }
        ));
        Ok(())
    }

    #[test]
    fn durable_unknown_survives_restart_and_reconciles() -> Result<(), RuntimeError> {
        let root = Root::new("restart")?;
        let barrier = TestBarrier::new();
        let durable =
            DurableService::create_new(&root.0, barrier.clone(), 32).map_err(map_durable_error)?;
        let request = inbound(b"token-a", "request-restart", "secret/app", b"value")?;
        let mut runtime = RuntimeService::new(
            TestAuthenticator,
            TestAuthorizer { allow: true },
            TestAudit::default(),
            durable,
        );
        let recovery_reference = match runtime
            .handle_with_failpoint(request.clone(), Failpoint::AfterSnapshotPublication)
        {
            Err(RuntimeError::OutcomeUnknown { recovery_reference }) => recovery_reference,
            other => return other.map(|_| ()).and(Err(RuntimeError::DurableRejected)),
        };
        drop(runtime);

        let reopened = DurableService::reopen(&root.0, barrier, 32).map_err(map_durable_error)?;
        let mut runtime = RuntimeService::new(
            TestAuthenticator,
            TestAuthorizer { allow: true },
            TestAudit::default(),
            reopened,
        );
        assert_eq!(
            runtime.reconcile(&recovery_reference),
            ReconciliationStatus::Committed { generation: 1 }
        );
        assert!(matches!(
            runtime.handle(request)?,
            RuntimeOutcome::Duplicate { generation: 1, .. }
        ));
        Ok(())
    }

    #[test]
    fn debug_output_redacts_credentials_paths_and_secret() -> Result<(), RuntimeError> {
        let request = inbound(
            b"token-a",
            "request-redacted",
            "secret/high-value",
            b"never-print-me",
        )?;
        let rendered = format!("{request:?}");
        for secret in [
            "token-a",
            "request-redacted",
            "secret/high-value",
            "never-print-me",
        ] {
            assert!(!rendered.contains(secret));
        }
        Ok(())
    }
}
