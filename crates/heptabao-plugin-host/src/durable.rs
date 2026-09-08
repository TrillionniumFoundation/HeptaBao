//! Durable plugin invocation and dynamic-lease composition.
//!
//! This module composes the process boundary with the repository's encrypted
//! durable service.  A plugin effect is never entered before a durable intent
//! exists.  Plaintext plugin responses are released only after the lease view
//! is durably published and the intent is durably cleared.  Any ambiguity after
//! process entry leaves the intent present and fences the host across restart.

use super::{
    DynamicLeaseRecord, DynamicLeaseSpec, DynamicLeaseState, DynamicLeaseView, DynamicSecretBroker,
    DynamicSecretIssue, PluginHostError, PluginHostState, PluginOperation, SandboxRunner,
    SecretEnvironment, sha256,
};
use heptabao_domain::{CanonicalPath, Id, SecretValue, Tick};
use heptabao_durable_service::{
    Barrier, DeleteRequest, DurableService, MutationOutcome, PutRequest, Secret, ServiceError,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

const DURABLE_NAMESPACE: &str = "plugin-runtime";
const LEASE_PREFIX: &str = "leases";
const INTENT_PREFIX: &str = "intents";
const LEASE_MAGIC: &[u8; 4] = b"HBDL";
const INTENT_MAGIC: &[u8; 4] = b"HBDI";
const DURABLE_SCHEMA_VERSION: u16 = 1;
const MAX_ENCODED_RECORD_BYTES: usize = 16 * 1024;

/// Already-authorized identity used for each durable plugin transition.
#[derive(Clone, Eq, PartialEq)]
pub struct PluginMutationContext {
    principal: Id,
    request_id: Id,
    authorization_digest: [u8; 32],
}

impl PluginMutationContext {
    pub fn new(
        principal: Id,
        request_id: Id,
        authorization_digest: [u8; 32],
    ) -> Result<Self, PluginHostError> {
        if authorization_digest == [0; 32] {
            return Err(PluginHostError::InvalidAuthorizationDigest);
        }
        Ok(Self {
            principal,
            request_id,
            authorization_digest,
        })
    }

    pub fn principal(&self) -> &Id {
        &self.principal
    }

    pub fn request_id(&self) -> &Id {
        &self.request_id
    }
}

impl fmt::Debug for PluginMutationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginMutationContext")
            .field("principal", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .field("authorization_digest", &"[REDACTED]")
            .finish()
    }
}

/// Safe projection of the one outstanding plugin invocation, if any.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPluginInvocation {
    pub lease_id: Id,
    pub operation: PluginOperation,
    pub generation: u64,
}

/// Operator-supplied result of authoritative provider readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableReconciliationDecision {
    ProvenNoEffect,
    Completed {
        lease: DynamicLeaseView,
        response_digest: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurablePluginIntent {
    lease_id: Id,
    operation: PluginOperation,
    generation: u64,
    owner_entity: Id,
    scope: CanonicalPath,
    issued_at: Tick,
    proposed_expires_at: Tick,
    renewable: bool,
    previous: Option<DynamicLeaseView>,
    request_digest: [u8; 32],
}

/// Restart-safe composition of the plugin broker and encrypted durable service.
#[derive(Debug)]
pub struct DurableDynamicSecretBroker<B: Barrier, R: SandboxRunner> {
    durable: DurableService<B>,
    broker: DynamicSecretBroker<R>,
    pending: Option<DurablePluginIntent>,
}

impl<B: Barrier, R: SandboxRunner> DurableDynamicSecretBroker<B, R> {
    pub fn create_new(
        root: impl AsRef<Path>,
        barrier: B,
        broker: DynamicSecretBroker<R>,
        max_retained_requests: usize,
    ) -> Result<Self, PluginHostError> {
        let durable = DurableService::create_new(root, barrier, max_retained_requests)?;
        Ok(Self {
            durable,
            broker,
            pending: None,
        })
    }

    pub fn reopen(
        root: impl AsRef<Path>,
        barrier: B,
        mut broker: DynamicSecretBroker<R>,
        max_retained_requests: usize,
    ) -> Result<Self, PluginHostError> {
        let durable = DurableService::reopen(root, barrier, max_retained_requests)?;
        let mut leases = BTreeMap::new();
        for child in durable.list(DURABLE_NAMESPACE, LEASE_PREFIX)? {
            if child.ends_with('/') {
                return Err(PluginHostError::CorruptDurablePluginState);
            }
            let lease_id = Id::parse(child)?;
            let resource = lease_resource(&lease_id);
            let value = durable
                .get(DURABLE_NAMESPACE, &resource)?
                .ok_or(PluginHostError::CorruptDurablePluginState)?;
            let view = decode_lease(value.expose())?;
            if view.lease_id != lease_id
                || view.state == DynamicLeaseState::ReconciliationRequired
                || leases
                    .insert(view.lease_id.clone(), DynamicLeaseRecord { view })
                    .is_some()
            {
                return Err(PluginHostError::CorruptDurablePluginState);
            }
        }

        let mut pending = None;
        for child in durable.list(DURABLE_NAMESPACE, INTENT_PREFIX)? {
            if child.ends_with('/') || pending.is_some() {
                return Err(PluginHostError::CorruptDurablePluginState);
            }
            let lease_id = Id::parse(child)?;
            let resource = intent_resource(&lease_id);
            let value = durable
                .get(DURABLE_NAMESPACE, &resource)?
                .ok_or(PluginHostError::CorruptDurablePluginState)?;
            let intent = decode_intent(value.expose())?;
            if intent.lease_id != lease_id {
                return Err(PluginHostError::CorruptDurablePluginState);
            }
            pending = Some(intent);
        }

        broker.leases = leases;
        if let Some(intent) = pending.as_ref() {
            broker.host.state = PluginHostState::ReconciliationRequired;
            if let Some(record) = broker.leases.get_mut(&intent.lease_id) {
                record.view.state = DynamicLeaseState::ReconciliationRequired;
            }
        }
        Ok(Self {
            durable,
            broker,
            pending,
        })
    }

    pub fn host_state(&self) -> PluginHostState {
        self.broker.host_state()
    }

    pub fn pending_invocation(&self) -> Option<PendingPluginInvocation> {
        self.pending.as_ref().map(|intent| PendingPluginInvocation {
            lease_id: intent.lease_id.clone(),
            operation: intent.operation,
            generation: intent.generation,
        })
    }

    pub fn view(&mut self, lease_id: &Id, now: Tick) -> Result<DynamicLeaseView, PluginHostError> {
        self.broker.view(lease_id, now)
    }

    pub fn issue(
        &mut self,
        context: &PluginMutationContext,
        spec: DynamicLeaseSpec,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<DynamicSecretIssue, PluginHostError> {
        self.ensure_ready()?;
        if spec.ttl == 0
            || spec.ttl > super::MAX_LEASE_TTL
            || self.broker.leases.contains_key(&spec.lease_id)
        {
            return self.broker.issue(spec, request, environment);
        }
        let proposed_expires_at = spec
            .issued_at
            .checked_add(spec.ttl)
            .map_err(PluginHostError::Domain)?;
        let intent = DurablePluginIntent {
            lease_id: spec.lease_id.clone(),
            operation: PluginOperation::Issue,
            generation: 1,
            owner_entity: spec.owner_entity.clone(),
            scope: spec.scope.clone(),
            issued_at: spec.issued_at,
            proposed_expires_at,
            renewable: spec.renewable,
            previous: None,
            request_digest: bound_request_digest(PluginOperation::Issue, request),
        };
        self.publish_intent(context, &intent)?;

        match self.broker.issue(spec, request, environment) {
            Ok(issue) => {
                if let Err(error) = self.publish_lease(context, &issue.lease, &intent) {
                    self.fence(&intent.lease_id);
                    return Err(error);
                }
                if let Err(error) = self.clear_intent(context, &intent) {
                    self.fence(&intent.lease_id);
                    return Err(error);
                }
                self.pending = None;
                Ok(issue)
            }
            Err(error @ PluginHostError::ProcessBeforeEntry) => {
                self.clear_after_before_entry(context, &intent, error)
            }
            Err(error) => {
                if self.broker.host_state() == PluginHostState::ReconciliationRequired {
                    self.fence(&intent.lease_id);
                }
                Err(error)
            }
        }
    }

    pub fn renew(
        &mut self,
        context: &PluginMutationContext,
        lease_id: &Id,
        now: Tick,
        ttl: u64,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<DynamicLeaseView, PluginHostError> {
        self.ensure_ready()?;
        let previous = self.broker.view(lease_id, now)?;
        if ttl == 0
            || ttl > super::MAX_LEASE_TTL
            || previous.state != DynamicLeaseState::Active
            || !previous.renewable
        {
            return self.broker.renew(lease_id, now, ttl, request, environment);
        }
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(PluginHostError::GenerationOverflow)?;
        let proposed_expires_at = now.checked_add(ttl).map_err(PluginHostError::Domain)?;
        let intent = DurablePluginIntent {
            lease_id: lease_id.clone(),
            operation: PluginOperation::Renew,
            generation,
            owner_entity: previous.owner_entity.clone(),
            scope: previous.scope.clone(),
            issued_at: previous.issued_at,
            proposed_expires_at,
            renewable: previous.renewable,
            previous: Some(previous),
            request_digest: bound_request_digest(PluginOperation::Renew, request),
        };
        self.publish_intent(context, &intent)?;

        match self.broker.renew(lease_id, now, ttl, request, environment) {
            Ok(view) => {
                if let Err(error) = self.publish_lease(context, &view, &intent) {
                    self.fence(lease_id);
                    return Err(error);
                }
                if let Err(error) = self.clear_intent(context, &intent) {
                    self.fence(lease_id);
                    return Err(error);
                }
                self.pending = None;
                Ok(view)
            }
            Err(error @ PluginHostError::ProcessBeforeEntry) => {
                self.clear_after_before_entry(context, &intent, error)
            }
            Err(error) => {
                if self.broker.host_state() == PluginHostState::ReconciliationRequired {
                    self.fence(lease_id);
                }
                Err(error)
            }
        }
    }

    pub fn revoke(
        &mut self,
        context: &PluginMutationContext,
        lease_id: &Id,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<DynamicLeaseView, PluginHostError> {
        self.ensure_ready()?;
        let previous = self
            .broker
            .leases
            .get(lease_id)
            .map(|record| record.view.clone())
            .ok_or(PluginHostError::MissingLease)?;
        if previous.state != DynamicLeaseState::Active {
            return self.broker.revoke(lease_id, request, environment);
        }
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(PluginHostError::GenerationOverflow)?;
        let intent = DurablePluginIntent {
            lease_id: lease_id.clone(),
            operation: PluginOperation::Revoke,
            generation,
            owner_entity: previous.owner_entity.clone(),
            scope: previous.scope.clone(),
            issued_at: previous.issued_at,
            proposed_expires_at: previous.expires_at,
            renewable: previous.renewable,
            previous: Some(previous),
            request_digest: bound_request_digest(PluginOperation::Revoke, request),
        };
        self.publish_intent(context, &intent)?;

        match self.broker.revoke(lease_id, request, environment) {
            Ok(view) => {
                if let Err(error) = self.publish_lease(context, &view, &intent) {
                    self.fence(lease_id);
                    return Err(error);
                }
                if let Err(error) = self.clear_intent(context, &intent) {
                    self.fence(lease_id);
                    return Err(error);
                }
                self.pending = None;
                Ok(view)
            }
            Err(error @ PluginHostError::ProcessBeforeEntry) => {
                self.clear_after_before_entry(context, &intent, error)
            }
            Err(error) => {
                if self.broker.host_state() == PluginHostState::ReconciliationRequired {
                    self.fence(lease_id);
                }
                Err(error)
            }
        }
    }

    pub fn reconcile(
        &mut self,
        context: &PluginMutationContext,
        decision: DurableReconciliationDecision,
    ) -> Result<Option<DynamicLeaseView>, PluginHostError> {
        let intent = self
            .pending
            .clone()
            .ok_or(PluginHostError::InvalidReconciliation)?;
        self.broker
            .host
            .runner
            .admit(&self.broker.host.manifest)
            .map_err(|_| PluginHostError::SandboxUnavailable)?;

        let resolved = match decision {
            DurableReconciliationDecision::ProvenNoEffect => intent.previous.clone(),
            DurableReconciliationDecision::Completed {
                lease,
                response_digest,
            } => {
                validate_completed_resolution(&intent, &lease, response_digest)?;
                Some(lease)
            }
        };

        match resolved.as_ref() {
            Some(view) => self.publish_lease(context, view, &intent)?,
            None => self.delete_lease(context, &intent)?,
        }
        self.clear_intent(context, &intent)?;

        match resolved.clone() {
            Some(view) => {
                self.broker
                    .leases
                    .insert(view.lease_id.clone(), DynamicLeaseRecord { view });
            }
            None => {
                self.broker.leases.remove(&intent.lease_id);
            }
        }
        self.pending = None;
        // Admission was rechecked above.  Activation occurs only after the
        // resolved lease projection and intent deletion are both durable.
        self.broker.host.state = PluginHostState::Active;
        Ok(resolved)
    }

    fn ensure_ready(&self) -> Result<(), PluginHostError> {
        if self.pending.is_some() {
            return Err(PluginHostError::PendingPluginInvocation);
        }
        match self.broker.host_state() {
            PluginHostState::Active => Ok(()),
            PluginHostState::ReconciliationRequired => Err(PluginHostError::ReconciliationRequired),
            PluginHostState::Revoked => Err(PluginHostError::PluginRevoked),
        }
    }

    fn publish_intent(
        &mut self,
        context: &PluginMutationContext,
        intent: &DurablePluginIntent,
    ) -> Result<(), PluginHostError> {
        let bytes = encode_intent(intent)?;
        let request = PutRequest::new(
            context.principal.as_str(),
            DURABLE_NAMESPACE,
            storage_request_id(context, "intent", intent),
            intent_resource(&intent.lease_id),
            context.authorization_digest,
            Secret::new(bytes)?,
        )?;
        require_committed(self.durable.put(request)?)?;
        self.pending = Some(intent.clone());
        Ok(())
    }

    fn publish_lease(
        &mut self,
        context: &PluginMutationContext,
        view: &DynamicLeaseView,
        intent: &DurablePluginIntent,
    ) -> Result<(), PluginHostError> {
        let request = PutRequest::new(
            context.principal.as_str(),
            DURABLE_NAMESPACE,
            storage_request_id(context, "lease", intent),
            lease_resource(&view.lease_id),
            context.authorization_digest,
            Secret::new(encode_lease(view)?)?,
        )?;
        require_committed(self.durable.put(request)?)
    }

    fn delete_lease(
        &mut self,
        context: &PluginMutationContext,
        intent: &DurablePluginIntent,
    ) -> Result<(), PluginHostError> {
        let request = DeleteRequest::new(
            context.principal.as_str(),
            DURABLE_NAMESPACE,
            storage_request_id(context, "drop-lease", intent),
            lease_resource(&intent.lease_id),
            context.authorization_digest,
        )?;
        require_committed(self.durable.delete(request)?)
    }

    fn clear_intent(
        &mut self,
        context: &PluginMutationContext,
        intent: &DurablePluginIntent,
    ) -> Result<(), PluginHostError> {
        let request = DeleteRequest::new(
            context.principal.as_str(),
            DURABLE_NAMESPACE,
            storage_request_id(context, "clear", intent),
            intent_resource(&intent.lease_id),
            context.authorization_digest,
        )?;
        require_committed(self.durable.delete(request)?)
    }

    fn clear_after_before_entry<T>(
        &mut self,
        context: &PluginMutationContext,
        intent: &DurablePluginIntent,
        original: PluginHostError,
    ) -> Result<T, PluginHostError> {
        if let Err(error) = self.clear_intent(context, intent) {
            self.fence(&intent.lease_id);
            return Err(error);
        }
        self.pending = None;
        Err(original)
    }

    fn fence(&mut self, lease_id: &Id) {
        self.broker.host.state = PluginHostState::ReconciliationRequired;
        if let Some(record) = self.broker.leases.get_mut(lease_id) {
            record.view.state = DynamicLeaseState::ReconciliationRequired;
        }
    }
}

fn validate_completed_resolution(
    intent: &DurablePluginIntent,
    lease: &DynamicLeaseView,
    response_digest: [u8; 32],
) -> Result<(), PluginHostError> {
    if response_digest == [0; 32]
        || lease.lease_id != intent.lease_id
        || lease.owner_entity != intent.owner_entity
        || lease.scope != intent.scope
        || lease.issued_at != intent.issued_at
        || lease.expires_at != intent.proposed_expires_at
        || lease.renewable != intent.renewable
        || lease.generation != intent.generation
    {
        return Err(PluginHostError::InvalidReconciliation);
    }
    match intent.operation {
        PluginOperation::Issue | PluginOperation::Renew => {
            if lease.state != DynamicLeaseState::Active || lease.secret_digest != response_digest {
                return Err(PluginHostError::InvalidReconciliation);
            }
        }
        PluginOperation::Revoke => {
            if lease.state != DynamicLeaseState::Revoked
                || intent
                    .previous
                    .as_ref()
                    .is_none_or(|previous| previous.secret_digest != lease.secret_digest)
            {
                return Err(PluginHostError::InvalidReconciliation);
            }
        }
        PluginOperation::Read | PluginOperation::Write => {
            return Err(PluginHostError::InvalidReconciliation);
        }
    }
    Ok(())
}

fn require_committed(outcome: MutationOutcome) -> Result<(), PluginHostError> {
    match outcome {
        MutationOutcome::Committed { .. } | MutationOutcome::Duplicate { .. } => Ok(()),
    }
}

fn bound_request_digest(operation: PluginOperation, request: &SecretValue) -> [u8; 32] {
    let mut material = Vec::with_capacity(1 + 8 + request.len());
    material.push(operation.tag());
    material.extend_from_slice(&(request.len() as u64).to_be_bytes());
    material.extend_from_slice(request.expose());
    sha256(&material)
}

fn storage_request_id(
    context: &PluginMutationContext,
    phase: &str,
    intent: &DurablePluginIntent,
) -> String {
    format!(
        "{}:{}:{}:{}",
        context.request_id.as_str(),
        phase,
        intent.operation.as_str(),
        intent.generation
    )
}

fn lease_resource(lease_id: &Id) -> String {
    format!("{LEASE_PREFIX}/{}", lease_id.as_str())
}

fn intent_resource(lease_id: &Id) -> String {
    format!("{INTENT_PREFIX}/{}", lease_id.as_str())
}

fn encode_lease(view: &DynamicLeaseView) -> Result<Vec<u8>, PluginHostError> {
    let mut output = Vec::new();
    output.extend_from_slice(LEASE_MAGIC);
    output.extend_from_slice(&DURABLE_SCHEMA_VERSION.to_be_bytes());
    write_text(&mut output, view.lease_id.as_str())?;
    write_text(&mut output, view.owner_entity.as_str())?;
    write_text(&mut output, view.scope.as_str())?;
    output.push(lease_state_tag(view.state));
    output.extend_from_slice(&view.issued_at.as_u64().to_be_bytes());
    output.extend_from_slice(&view.expires_at.as_u64().to_be_bytes());
    output.push(u8::from(view.renewable));
    output.extend_from_slice(&view.generation.to_be_bytes());
    output.extend_from_slice(&view.secret_digest);
    if output.len() > MAX_ENCODED_RECORD_BYTES {
        return Err(PluginHostError::CorruptDurablePluginState);
    }
    Ok(output)
}

fn decode_lease(bytes: &[u8]) -> Result<DynamicLeaseView, PluginHostError> {
    let mut cursor = DurableCursor::new(bytes);
    if cursor.take(4)? != LEASE_MAGIC || cursor.read_u16()? != DURABLE_SCHEMA_VERSION {
        return Err(PluginHostError::CorruptDurablePluginState);
    }
    let lease_id = Id::parse(cursor.read_text(64)?)?;
    let owner_entity = Id::parse(cursor.read_text(64)?)?;
    let scope = CanonicalPath::parse(cursor.read_text(1024)?)?;
    let state = decode_lease_state(cursor.read_u8()?)?;
    let issued_at = Tick::new(cursor.read_u64()?);
    let expires_at = Tick::new(cursor.read_u64()?);
    let renewable = match cursor.read_u8()? {
        0 => false,
        1 => true,
        _ => return Err(PluginHostError::CorruptDurablePluginState),
    };
    let generation = cursor.read_u64()?;
    let secret_digest = cursor.read_array_32()?;
    cursor.finish()?;
    let view = DynamicLeaseView {
        lease_id,
        owner_entity,
        scope,
        state,
        issued_at,
        expires_at,
        renewable,
        generation,
        secret_digest,
    };
    validate_lease_view(&view)?;
    Ok(view)
}

fn encode_intent(intent: &DurablePluginIntent) -> Result<Vec<u8>, PluginHostError> {
    let mut output = Vec::new();
    output.extend_from_slice(INTENT_MAGIC);
    output.extend_from_slice(&DURABLE_SCHEMA_VERSION.to_be_bytes());
    write_text(&mut output, intent.lease_id.as_str())?;
    output.push(intent.operation.tag());
    output.extend_from_slice(&intent.generation.to_be_bytes());
    write_text(&mut output, intent.owner_entity.as_str())?;
    write_text(&mut output, intent.scope.as_str())?;
    output.extend_from_slice(&intent.issued_at.as_u64().to_be_bytes());
    output.extend_from_slice(&intent.proposed_expires_at.as_u64().to_be_bytes());
    output.push(u8::from(intent.renewable));
    output.extend_from_slice(&intent.request_digest);
    match intent.previous.as_ref() {
        None => output.extend_from_slice(&0_u32.to_be_bytes()),
        Some(previous) => {
            let encoded = encode_lease(previous)?;
            let length = u32::try_from(encoded.len())
                .map_err(|_| PluginHostError::CorruptDurablePluginState)?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(&encoded);
        }
    }
    if output.len() > MAX_ENCODED_RECORD_BYTES {
        return Err(PluginHostError::CorruptDurablePluginState);
    }
    Ok(output)
}

fn decode_intent(bytes: &[u8]) -> Result<DurablePluginIntent, PluginHostError> {
    let mut cursor = DurableCursor::new(bytes);
    if cursor.take(4)? != INTENT_MAGIC || cursor.read_u16()? != DURABLE_SCHEMA_VERSION {
        return Err(PluginHostError::CorruptDurablePluginState);
    }
    let lease_id = Id::parse(cursor.read_text(64)?)?;
    let operation = decode_operation(cursor.read_u8()?)?;
    if matches!(operation, PluginOperation::Read | PluginOperation::Write) {
        return Err(PluginHostError::CorruptDurablePluginState);
    }
    let generation = cursor.read_u64()?;
    let owner_entity = Id::parse(cursor.read_text(64)?)?;
    let scope = CanonicalPath::parse(cursor.read_text(1024)?)?;
    let issued_at = Tick::new(cursor.read_u64()?);
    let proposed_expires_at = Tick::new(cursor.read_u64()?);
    let renewable = match cursor.read_u8()? {
        0 => false,
        1 => true,
        _ => return Err(PluginHostError::CorruptDurablePluginState),
    };
    let request_digest = cursor.read_array_32()?;
    let previous_length = usize::try_from(cursor.read_u32()?)
        .map_err(|_| PluginHostError::CorruptDurablePluginState)?;
    let previous = if previous_length == 0 {
        None
    } else {
        Some(decode_lease(cursor.take(previous_length)?)?)
    };
    cursor.finish()?;
    if generation == 0
        || request_digest == [0; 32]
        || proposed_expires_at <= issued_at
        || matches!(operation, PluginOperation::Issue) != previous.is_none()
    {
        return Err(PluginHostError::CorruptDurablePluginState);
    }
    if let Some(view) = previous.as_ref()
        && (view.lease_id != lease_id
            || view.owner_entity != owner_entity
            || view.scope != scope
            || view.issued_at != issued_at
            || view.renewable != renewable
            || view.generation.checked_add(1) != Some(generation))
    {
        return Err(PluginHostError::CorruptDurablePluginState);
    }
    Ok(DurablePluginIntent {
        lease_id,
        operation,
        generation,
        owner_entity,
        scope,
        issued_at,
        proposed_expires_at,
        renewable,
        previous,
        request_digest,
    })
}

fn validate_lease_view(view: &DynamicLeaseView) -> Result<(), PluginHostError> {
    if view.generation == 0 || view.secret_digest == [0; 32] || view.expires_at <= view.issued_at {
        return Err(PluginHostError::CorruptDurablePluginState);
    }
    Ok(())
}

const fn lease_state_tag(state: DynamicLeaseState) -> u8 {
    match state {
        DynamicLeaseState::Active => 1,
        DynamicLeaseState::Revoked => 2,
        DynamicLeaseState::Expired => 3,
        DynamicLeaseState::ReconciliationRequired => 4,
    }
}

fn decode_lease_state(value: u8) -> Result<DynamicLeaseState, PluginHostError> {
    match value {
        1 => Ok(DynamicLeaseState::Active),
        2 => Ok(DynamicLeaseState::Revoked),
        3 => Ok(DynamicLeaseState::Expired),
        4 => Ok(DynamicLeaseState::ReconciliationRequired),
        _ => Err(PluginHostError::CorruptDurablePluginState),
    }
}

fn decode_operation(value: u8) -> Result<PluginOperation, PluginHostError> {
    match value {
        1 => Ok(PluginOperation::Read),
        2 => Ok(PluginOperation::Write),
        3 => Ok(PluginOperation::Issue),
        4 => Ok(PluginOperation::Renew),
        5 => Ok(PluginOperation::Revoke),
        _ => Err(PluginHostError::CorruptDurablePluginState),
    }
}

fn write_text(output: &mut Vec<u8>, value: &str) -> Result<(), PluginHostError> {
    let length =
        u16::try_from(value.len()).map_err(|_| PluginHostError::CorruptDurablePluginState)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct DurableCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DurableCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PluginHostError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PluginHostError::CorruptDurablePluginState)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PluginHostError::CorruptDurablePluginState)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, PluginHostError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(PluginHostError::CorruptDurablePluginState)?)
    }

    fn read_u16(&mut self) -> Result<u16, PluginHostError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| PluginHostError::CorruptDurablePluginState)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, PluginHostError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| PluginHostError::CorruptDurablePluginState)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, PluginHostError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| PluginHostError::CorruptDurablePluginState)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_array_32(&mut self) -> Result<[u8; 32], PluginHostError> {
        self.take(32)?
            .try_into()
            .map_err(|_| PluginHostError::CorruptDurablePluginState)
    }

    fn read_text(&mut self, maximum: usize) -> Result<String, PluginHostError> {
        let length = usize::from(self.read_u16()?);
        if length == 0 || length > maximum {
            return Err(PluginHostError::CorruptDurablePluginState);
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| PluginHostError::CorruptDurablePluginState)?;
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<(), PluginHostError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PluginHostError::CorruptDurablePluginState)
        }
    }
}

impl From<ServiceError> for PluginHostError {
    fn from(value: ServiceError) -> Self {
        Self::Durable(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PluginHost, PluginLimits, PluginManifest, SandboxBinding, SandboxFailure};
    use heptabao_durable_service::BarrierError;
    use heptabao_plugin_contracts::{PluginDescriptor, PluginKind, PluginRegistry};
    use ring::digest::SHA256;
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone, Copy, Debug)]
    enum Behavior {
        Success,
        BeforeEntry,
        OutcomeUnknown,
    }

    #[derive(Debug)]
    struct FakeRunner {
        behavior: Behavior,
    }

    impl SandboxRunner for FakeRunner {
        fn admit(&self, _manifest: &PluginManifest) -> Result<(), SandboxFailure> {
            Ok(())
        }

        fn invoke(
            &self,
            _manifest: &PluginManifest,
            _operation: PluginOperation,
            _request: &SecretValue,
            _environment: &SecretEnvironment,
        ) -> Result<SecretValue, SandboxFailure> {
            match self.behavior {
                Behavior::Success => SecretValue::new(b"synthetic-issued-secret".to_vec())
                    .map_err(|_| SandboxFailure::BeforeEntry),
                Behavior::BeforeEntry => Err(SandboxFailure::BeforeEntry),
                Behavior::OutcomeUnknown => Err(SandboxFailure::OutcomeUnknownAfterEntry),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TestBarrier {
        key: [u8; 32],
    }

    impl TestBarrier {
        const fn new() -> Self {
            Self { key: [0x5a; 32] }
        }

        fn tag(&self, context: &[u8], ciphertext: &[u8]) -> [u8; 32] {
            let mut material = Vec::new();
            material.extend_from_slice(&self.key);
            material.extend_from_slice(context);
            material.extend_from_slice(ciphertext);
            let digest = ring::digest::digest(&SHA256, &material);
            let mut output = [0_u8; 32];
            output.copy_from_slice(digest.as_ref());
            output
        }
    }

    impl Barrier for TestBarrier {
        fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
            let ciphertext: Vec<u8> = plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
                .collect();
            let mut protected = Vec::with_capacity(32 + ciphertext.len());
            protected.extend_from_slice(&self.tag(context, &ciphertext));
            protected.extend_from_slice(&ciphertext);
            Ok(protected)
        }

        fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError> {
            if protected.len() < 32 {
                return Err(BarrierError);
            }
            let (tag, ciphertext) = protected.split_at(32);
            if tag != self.tag(context, ciphertext) {
                return Err(BarrierError);
            }
            Ok(ciphertext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
                .collect())
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Result<Self, Box<dyn Error>> {
            let path = std::env::temp_dir().join(format!(
                "heptabao-plugin-durable-{label}-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            if path.exists() {
                fs::remove_dir_all(&path)?;
            }
            Ok(Self(path))
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn broker(behavior: Behavior) -> Result<DynamicSecretBroker<FakeRunner>, Box<dyn Error>> {
        let plugin_id = Id::parse("durable_plugin")?;
        let descriptor = PluginDescriptor::new(
            plugin_id.clone(),
            PluginKind::Database,
            CanonicalPath::parse("/opt/heptabao/plugins/durable")?,
            [7; 32],
            1,
        )?;
        let mut registry = PluginRegistry::default();
        registry.register(descriptor)?;
        registry.enable(&plugin_id)?;
        let manifest = PluginManifest::new(
            registry.get(&plugin_id)?.clone(),
            SandboxBinding::new(
                Id::parse("sandbox_provider")?,
                CanonicalPath::parse("/usr/bin/heptabao-sandbox")?,
                [8; 32],
                Id::parse("durable_profile")?,
            )?,
            PluginLimits {
                maximum_request_bytes: 4096,
                maximum_response_bytes: 4096,
                timeout_ms: 1000,
            },
            BTreeSet::from([
                PluginOperation::Issue,
                PluginOperation::Renew,
                PluginOperation::Revoke,
            ]),
            BTreeSet::new(),
        )?;
        Ok(DynamicSecretBroker::new(PluginHost::admit(
            manifest,
            FakeRunner { behavior },
        )?)?)
    }

    fn context(label: &str) -> Result<PluginMutationContext, Box<dyn Error>> {
        Ok(PluginMutationContext::new(
            Id::parse("operator")?,
            Id::parse(label)?,
            [9; 32],
        )?)
    }

    fn spec() -> Result<DynamicLeaseSpec, Box<dyn Error>> {
        Ok(DynamicLeaseSpec {
            lease_id: Id::parse("lease_one")?,
            owner_entity: Id::parse("entity_one")?,
            scope: CanonicalPath::parse("/database/role_one")?,
            issued_at: Tick::new(100),
            ttl: 300,
            renewable: true,
        })
    }

    #[test]
    fn issued_secret_is_released_only_after_durable_metadata_and_survives_reopen()
    -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new("issue")?;
        let mut durable = DurableDynamicSecretBroker::create_new(
            &root.0,
            TestBarrier::new(),
            broker(Behavior::Success)?,
            64,
        )?;
        let issue = durable.issue(
            &context("issue_request")?,
            spec()?,
            &SecretValue::new(b"synthetic-input".to_vec())?,
            &SecretEnvironment::new(),
        )?;
        assert_eq!(b"synthetic-issued-secret", issue.secret.expose());
        assert!(durable.pending_invocation().is_none());
        let expected = issue.lease.clone();
        drop(issue);
        drop(durable);

        let mut reopened = DurableDynamicSecretBroker::reopen(
            &root.0,
            TestBarrier::new(),
            broker(Behavior::Success)?,
            64,
        )?;
        assert_eq!(
            expected,
            reopened.view(&Id::parse("lease_one")?, Tick::new(101))?
        );
        assert!(!tree_contains(&root.0, b"synthetic-issued-secret")?);
        Ok(())
    }

    #[test]
    fn unknown_effect_persists_intent_and_fences_restart_until_readback()
    -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new("unknown")?;
        let mut durable = DurableDynamicSecretBroker::create_new(
            &root.0,
            TestBarrier::new(),
            broker(Behavior::OutcomeUnknown)?,
            64,
        )?;
        assert!(matches!(
            durable.issue(
                &context("unknown_request")?,
                spec()?,
                &SecretValue::new(b"synthetic-input".to_vec())?,
                &SecretEnvironment::new(),
            ),
            Err(PluginHostError::ProcessOutcomeUnknown)
        ));
        assert!(durable.pending_invocation().is_some());
        drop(durable);

        let mut reopened = DurableDynamicSecretBroker::reopen(
            &root.0,
            TestBarrier::new(),
            broker(Behavior::Success)?,
            64,
        )?;
        assert_eq!(
            PluginHostState::ReconciliationRequired,
            reopened.host_state()
        );
        assert!(matches!(
            reopened.issue(
                &context("blocked_request")?,
                spec()?,
                &SecretValue::new(b"synthetic-input".to_vec())?,
                &SecretEnvironment::new(),
            ),
            Err(PluginHostError::PendingPluginInvocation)
        ));
        assert!(
            reopened
                .reconcile(
                    &context("reconcile_request")?,
                    DurableReconciliationDecision::ProvenNoEffect,
                )?
                .is_none()
        );
        assert_eq!(PluginHostState::Active, reopened.host_state());
        assert!(reopened.pending_invocation().is_none());
        Ok(())
    }

    #[test]
    fn before_entry_failure_clears_durable_intent_without_poisoning_host()
    -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new("before-entry")?;
        let mut durable = DurableDynamicSecretBroker::create_new(
            &root.0,
            TestBarrier::new(),
            broker(Behavior::BeforeEntry)?,
            64,
        )?;
        assert!(matches!(
            durable.issue(
                &context("before_request")?,
                spec()?,
                &SecretValue::new(b"synthetic-input".to_vec())?,
                &SecretEnvironment::new(),
            ),
            Err(PluginHostError::ProcessBeforeEntry)
        ));
        assert!(durable.pending_invocation().is_none());
        assert_eq!(PluginHostState::Active, durable.host_state());
        drop(durable);
        let reopened = DurableDynamicSecretBroker::reopen(
            &root.0,
            TestBarrier::new(),
            broker(Behavior::Success)?,
            64,
        )?;
        assert!(reopened.pending_invocation().is_none());
        Ok(())
    }

    #[test]
    fn durable_failure_after_plugin_entry_withholds_secret_and_retains_intent()
    -> Result<(), Box<dyn Error>> {
        let root = TestRoot::new("capacity")?;
        let mut durable = DurableDynamicSecretBroker::create_new(
            &root.0,
            TestBarrier::new(),
            broker(Behavior::Success)?,
            1,
        )?;
        assert!(matches!(
            durable.issue(
                &context("capacity_request")?,
                spec()?,
                &SecretValue::new(b"synthetic-input".to_vec())?,
                &SecretEnvironment::new(),
            ),
            Err(PluginHostError::Durable(
                ServiceError::RequestCapacityExhausted
            ))
        ));
        assert_eq!(
            PluginHostState::ReconciliationRequired,
            durable.host_state()
        );
        assert!(durable.pending_invocation().is_some());
        assert!(!tree_contains(&root.0, b"synthetic-issued-secret")?);
        Ok(())
    }

    fn tree_contains(root: &Path, needle: &[u8]) -> Result<bool, Box<dyn Error>> {
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    pending.push(entry.path());
                } else if file_type.is_file()
                    && fs::read(entry.path())?
                        .windows(needle.len())
                        .any(|window| window == needle)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
