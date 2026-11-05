//! Audited, original-Actor inspection of complete retained typed history.
//! This lane never submits retirement metadata or writes a GC ledger, and never removes
//! a shared or local file. It joins the complete historical typed mark with
//! the actual registered local catalog, retaining every current local typed
//! object. The remaining physical-owner / Pending / unlink qualification is
//! deliberately separate from this point-in-time inspection.
use super::*;
use crate::state_record_root_v6::ObjectDomain;
use crate::state_records::{ObjectRef, RecordError};
use crate::v6_read_validation::{ObjectSource, ReadContext, ReadIdentity};
use std::cell::RefCell;
use std::collections::BTreeSet;

struct CurrentLocalSource<'a> {
    inner: native_blob_source::NativeSource<'a>,
    reached: RefCell<BTreeSet<String>>,
}
impl ObjectSource for CurrentLocalSource<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let bytes = self.inner.read(domain, reference)?;
        let resource = v6_records::native_resource(domain, reference);
        let mut reached = self
            .reached
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        if !reached.contains(&resource) && reached.len() >= 1_000_000 {
            return Err(RecordError::TooLarge);
        }
        reached.insert(resource);
        Ok(bytes)
    }
    fn object_count(&self) -> Option<usize> {
        None
    }
}

impl Service {
    pub(super) fn native_ha_current_local_mark(
        &mut self,
        plan: &GcDelivery,
        root: &RecordStateRootV6,
    ) -> Result<BTreeSet<String>, Response> {
        plan.check_source(self)?;
        let context = ReadContext {
            expected_identity: ReadIdentity::RecordsV6(
                root.identity().map_err(|_| rejected())?.digest(),
            ),
            cluster_id: &root.cluster_id,
            replay_epoch: root.replay_epoch,
            minimum_state_schema: root.state_schema,
            maximum_state_schema: root.state_schema,
            reader_format: crate::state_record_root_v6::READER_FORMAT,
        };
        let reached = {
            let durable = self.durable.as_mut().ok_or_else(rejected)?;
            let source = CurrentLocalSource {
                inner: native_blob_source::NativeSource::new_checked(
                    durable,
                    plan.deadline,
                    || {
                        plan.authorize_original()
                            .map_err(|_| ServiceError::BarrierFailure)
                    },
                )
                .map_err(|_| rejected())?,
                reached: RefCell::new(BTreeSet::new()),
            };
            let (metadata, native) = v6_records::materialize_for_service(root, context, &source)
                .map_err(|_| rejected())?;
            Self::check_native_installed(&plan.admitted, &metadata, &native, root, plan.deadline)?;
            let CurrentLocalSource { inner, reached } = source;
            drop(inner);
            reached.into_inner()
        };
        if reached.is_empty() {
            return Err(rejected());
        }
        plan.check_source(self)?;
        Ok(reached)
    }

    fn check_native_ha_local_mark_source(
        &mut self,
        plan: &GcDelivery,
        generation: u64,
        conditions: &[PublicationCondition],
        root: &[u8],
    ) -> Result<(), Response> {
        plan.check_source(self)?;
        self.check_native_ha_local_mark_local_source(plan, generation, conditions, root)
    }

    fn check_native_ha_local_mark_local_source(
        &mut self,
        plan: &GcDelivery,
        generation: u64,
        conditions: &[PublicationCondition],
        root: &[u8],
    ) -> Result<(), Response> {
        plan.check_local_source_while_retained_ha(self)?;
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        if durable.generation() != generation
            || durable
                .get("system", "state")
                .map_err(|_| rejected())?
                .as_ref()
                .map(Secret::expose)
                != Some(root)
            || durable
                .immutable_retirement_status()
                .map_err(|_| rejected())?
                .is_some_and(|status| status.pending)
            || durable
                .native_ha_shared_retirement_status()
                .map_err(|_| rejected())?
                .is_some_and(|status| status.pending)
            || durable
                .native_ha_intent_retirement_status()
                .map_err(|_| rejected())?
                .is_some_and(|status| status.pending)
        {
            return Err(rejected());
        }
        for condition in conditions {
            plan.authorize_original()?;
            if durable
                .get("system", &condition.resource)
                .map_err(|_| rejected())?
                .as_ref()
                .map(Secret::expose)
                != condition.expected.as_ref().map(Secret::expose)
            {
                return Err(rejected());
            }
        }
        plan.authorize_original()
    }

    pub(super) fn execute_native_ha_local_mark(
        &mut self,
        plan: &GcDelivery,
        source_generation: u64,
        conditions: &[PublicationCondition],
        root_bytes: &[u8],
    ) -> Result<Response, Response> {
        self.check_native_ha_local_mark_source(plan, source_generation, conditions, root_bytes)?;
        let root = self.native_root.as_ref().ok_or_else(rejected)?.clone();
        if root.encode().map_err(|_| rejected())?.as_slice() != root_bytes {
            return Err(rejected());
        }
        let current = self.native_ha_current_local_mark(plan, &root)?;
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        let session = native_blob_source::session(durable, root_bytes).map_err(|_| rejected())?;
        if session.generation() != source_generation {
            return Err(rejected());
        }
        let registered = durable
            .inspect_native_ha_local_resources(&session, conditions, &mut || {
                plan.authorize_original()
                    .map_err(|_| ServiceError::BarrierFailure)
            })
            .map_err(|_| rejected())?;
        drop(session);
        if !current.is_subset(&registered) {
            return Err(rejected());
        }
        self.check_native_ha_local_mark_source(plan, source_generation, conditions, root_bytes)?;
        let ha = Arc::clone(&plan.ha);
        let process = ha.lock_for_request().map_err(|_| rejected())?;
        let observed = process
            .inspect_native_v6_local_retained_resources(
                plan.deadline,
                plan.checkpoint.0,
                &mut || {
                    self.check_native_ha_local_mark_local_source(
                        plan,
                        source_generation,
                        conditions,
                        root_bytes,
                    )
                    .map_err(|_| LocalV6BlobError::CorruptOrChanged)
                },
                |marked, original| {
                    original().map_err(|_| "original local mark owner unavailable".to_owned())?;
                    if !current.is_subset(marked.resources()) {
                        return Err(
                            "current typed local source is absent from retained Raft history"
                                .into(),
                        );
                    }
                    let mut retained = 0_u64;
                    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
                    hash.update(b"HeptaBao/native-v6/registered-local-retained-union/v1\0");
                    hash.update(&marked.catalog_sha256());
                    hash.update(&source_generation.to_be_bytes());
                    for resource in registered.intersection(marked.resources()) {
                        original()
                            .map_err(|_| "original local union owner unavailable".to_owned())?;
                        hash.update(&(resource.len() as u64).to_be_bytes());
                        hash.update(resource.as_bytes());
                        retained += 1;
                    }
                    if retained < current.len() as u64 {
                        return Err("incomplete current local retention".into());
                    }
                    original().map_err(|_| "original local union owner unavailable".to_owned())?;
                    let union: [u8; 32] = hash
                        .finish()
                        .as_ref()
                        .try_into()
                        .map_err(|_| "invalid union digest".to_owned())?;
                    Ok((
                        marked.catalog_sha256(),
                        marked.root_count(),
                        marked.resources().len(),
                        retained,
                        union,
                    ))
                },
            )
            .map_err(|_| rejected())?;
        drop(process);
        self.check_native_ha_local_mark_source(plan, source_generation, conditions, root_bytes)?;
        // The complete held mark has ended. A new ordinary proof rechecks the
        // exact installed source before staging the response for the existing
        // mandatory audit / original terminal-clock delivery chain.
        let proof = self
            .capture_native_request_proof(&mut || plan.authorize_original())?
            .ok_or_else(rejected)?;
        if proof.identity() != plan.checkpoint.0 || proof.generation() != source_generation {
            return Err(rejected());
        }
        proof.check_with(self, Self::check_native_installed)?;
        self.check_native_ha_local_mark_source(plan, source_generation, conditions, root_bytes)?;
        Ok(Response::ok(json!({"data":{
            "schema":"heptabao-native-ha-historical-local-mark-v1",
            "source_generation":source_generation,
            "retained_catalog_sha256":hex(&observed.0),
            "retained_roots":observed.1,
            "historical_typed_resources":observed.2,
            "historical_shared_typed_union_complete":true,
            "local_registered_catalog_union_complete":true,
            "local_registered_catalog_union_sha256":hex(&observed.4),
            "current_local_typed_resources":current.len(),
            "registered_local_resources":registered.len(),
            "retained_registered_local_resources":observed.3,
            "unreferenced_registered_resources_observed":registered.len() as u64 - observed.3,
            "physical_deletion_authorized":false,
            "local_barrier_objects_retained":true,
            "local_barriers_gc_qualified":false,
            "historical_request_outcome_reclassified":false
        }})))
    }
}
