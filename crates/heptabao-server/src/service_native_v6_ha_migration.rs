//! Repair a lagging V5 local owner before the existing strict native installer.
//! The historical root never grants a V5 business read, cursor or activation.
use super::*;
use crate::state_records::{ObjectRef, RecordError, RecordReader, StagedObject};

#[cfg(test)]
impl Service {
    pub(in crate::service) fn test_native_v6_predecessor_missing_once(
        observed: std::rc::Rc<Cell<bool>>,
        materialization_refused: std::rc::Rc<Cell<bool>>,
    ) -> impl Drop {
        negative_test_faults::arm(
            negative_test_faults::Kind::MissingObject,
            observed,
            Some(materialization_refused),
        )
    }

    pub(in crate::service) fn test_native_v6_predecessor_wrong_bytes_once(
        observed: std::rc::Rc<Cell<bool>>,
        materialization_refused: std::rc::Rc<Cell<bool>>,
    ) -> impl Drop {
        negative_test_faults::arm(
            negative_test_faults::Kind::WrongObjectBytes,
            observed,
            Some(materialization_refused),
        )
    }

    pub(in crate::service) fn test_native_v6_predecessor_post_cas_once(
        observed: std::rc::Rc<Cell<bool>>,
    ) -> impl Drop {
        negative_test_faults::arm(negative_test_faults::Kind::AfterRootCas, observed, None)
    }
}

struct OriginalV5 {
    bytes: Secret,
    root: RecordStateRoot,
    generation: u64,
    epoch: u64,
}

impl OriginalV5 {
    fn capture(durable: &mut DurableService<AeadBarrier>) -> Result<Self, Response> {
        durable.verify_live_ownership().map_err(storage_rejected)?;
        if durable.recovery_required() {
            return Err(unavailable());
        }
        let bytes = durable
            .get("system", "state")
            .map_err(storage_rejected)?
            .ok_or_else(unavailable)?;
        let root = RecordStateRoot::decode(bytes.expose()).map_err(|_| unavailable())?;
        let selected = Self {
            bytes,
            root,
            generation: durable.generation(),
            epoch: durable.replay_epoch(),
        };
        if selected.root.replay_epoch != selected.epoch {
            return Err(unavailable());
        }
        selected.check(durable, selected.generation)?;
        Ok(selected)
    }

    fn conditions(&self) -> Vec<PublicationCondition> {
        vec![
            PublicationCondition {
                resource: "state".into(),
                expected: Some(self.bytes.clone()),
            },
            PublicationCondition {
                resource: ACTIVE_CURSOR_RESOURCE.into(),
                expected: None,
            },
            PublicationCondition {
                resource: ACTIVE_SOURCE_ROOT_RESOURCE.into(),
                expected: None,
            },
            PublicationCondition {
                resource: HA_CURSOR_RESOURCE.into(),
                expected: None,
            },
        ]
    }

    fn check(
        &self,
        durable: &mut DurableService<AeadBarrier>,
        generation: u64,
    ) -> Result<(), Response> {
        durable.verify_live_ownership().map_err(storage_rejected)?;
        if durable.recovery_required()
            || durable.generation() != generation
            || durable.replay_epoch() != self.epoch
        {
            return Err(unavailable());
        }
        for condition in self.conditions() {
            let actual = durable
                .get("system", &condition.resource)
                .map_err(storage_rejected)?;
            if actual.as_ref().map(Secret::expose)
                != condition.expected.as_ref().map(Secret::expose)
            {
                return Err(unavailable());
            }
        }
        Ok(())
    }
}

struct CheckedRaftRecords<'a, G> {
    process: &'a HaProcess,
    root: &'a RecordStateRoot,
    gate: RefCell<&'a mut G>,
}

impl<G: FnMut() -> Result<(), ServiceError>> RecordReader for CheckedRaftRecords<'_, G> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.gate.borrow_mut())().map_err(|_| RecordError::Invalid)?;
        let bytes = self
            .process
            .read_record_object(self.root, reference)
            .map_err(|_| RecordError::Corrupt)?;
        (self.gate.borrow_mut())().map_err(|_| RecordError::Invalid)?;
        #[cfg(test)]
        let bytes = negative_test_faults::after_real_object_read(self.root, reference, bytes)?;
        Ok(bytes)
    }
}

impl Service {
    pub(super) fn sync_native_v6_migration_source(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        read: &CommittedNativeV6Read,
        original_actor: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<bool, Response> {
        let deadline = read.deadline();
        live(deadline)?;
        if self.native_root.is_some() {
            return Ok(false);
        }
        let old_identity = self.current_state_identity()?;
        let expected = StateIdentity::RecordsV5(read.published().migration_source().0);
        if old_identity == expected {
            return Ok(false);
        }
        if !matches!(old_identity, StateIdentity::RecordsV5(_)) {
            return Err(unavailable());
        }
        let actual = self.state.as_ref().ok_or_else(unavailable)?.clone();
        root_namespace_only(&actual)?;
        let source_auth = actual.auth.clone();
        original_actor(&source_auth)?;
        let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
        let environment = LocalHaEnvironment::capture(self, ha, &key, deadline)?;
        let process = ha.lock_for_request().map_err(|_| unavailable())?;
        let source = process
            .native_v6_retained_migration_source(read)
            .map_err(|_| unavailable())?;
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let root_committed = Cell::new(false);
        let denial = RefCell::new(None);
        let result = (|| -> Result<State, Response> {
            let selected = OriginalV5::capture(&mut durable)?;
            if selected.root.identity().map_err(|_| unavailable())? != old_identity
                || self
                    .record_root
                    .as_ref()
                    .and_then(|root| root.identity().ok())
                    != Some(old_identity)
                || selected.root.cluster_id != actual.cluster_id
                || selected.epoch != actual.replay_epoch
                || source.root().cluster_id != actual.cluster_id
                || source.root().replay_epoch != selected.epoch
                || selected.epoch != read.published().native_origin_epoch()
            {
                return Err(unavailable());
            }
            let mut gate = || -> Result<(), ServiceError> {
                let checked = (|| {
                    environment.check(self)?;
                    if self.current_state_identity()? != old_identity {
                        return Err(unavailable());
                    }
                    original_actor(&source_auth)?;
                    source.check(&process).map_err(|_| unavailable())?;
                    live(deadline)
                })();
                checked.map_err(|error| {
                    if denial.borrow().is_none() {
                        *denial.borrow_mut() = Some(error);
                    }
                    ServiceError::BarrierFailure
                })
            };
            verify_v5_source(&durable, &selected.root, &actual, &mut gate)?;
            let (target, objects) = {
                let reader = CheckedRaftRecords {
                    process: &process,
                    root: source.root(),
                    gate: RefCell::new(&mut gate),
                };
                let target = Self::materialize_record_state(source.root(), &reader);
                #[cfg(test)]
                negative_test_faults::after_target_materialization(&target);
                let target = target?;
                root_namespace_only(&target)?;
                target.validate_publication_schema(Some(&actual))?;
                target
                    .auth
                    .validate_token_api_clock_floor(Some(&actual.auth))
                    .map_err(|_| unavailable())?;
                Self::validate_snapshot_protected_floor(&actual, &target)?;
                self.validate_loaded_capacity(&target, Some(source.root()))?;
                let mut objects = Vec::new();
                target
                    .engines
                    .visit_record_objects(|object| {
                        objects.push(Arc::clone(object));
                        Ok(())
                    })
                    .map_err(Response::from_engine_error)?;
                let address = source.root().address_key();
                for owner in &source.root().owners {
                    for reference in &owner.chunks {
                        let bytes = reader.read_object(reference).map_err(|_| unavailable())?;
                        let payload = reference
                            .owner_chunk_payload(&address, &bytes)
                            .map_err(|_| unavailable())?;
                        let object = StagedObject::owner_chunk(&address, payload)
                            .map_err(|_| unavailable())?;
                        if object.reference() != reference {
                            return Err(unavailable());
                        }
                        objects.push(object);
                    }
                }
                (target, objects)
            };
            gate().map_err(storage_rejected)?;
            let mut unique = BTreeMap::<String, Zeroizing<Vec<u8>>>::new();
            let address = source.root().address_key();
            for object in objects {
                gate().map_err(storage_rejected)?;
                object
                    .reference()
                    .verify(&address, object.bytes())
                    .map_err(|_| unavailable())?;
                let resource = object.reference().resource();
                if let Some(previous) = unique.get(&resource) {
                    if previous.as_slice() != object.bytes() {
                        return Err(unavailable());
                    }
                } else {
                    unique.insert(resource, Zeroizing::new(object.bytes().to_vec()));
                }
            }
            let operation = format!(
                "native6-ha-predecessor-{}",
                hex(&crypto::random::<16>().map_err(|_| unavailable())?)
            );
            let prepared = unique
                .iter()
                .map(|(resource, bytes)| (resource.clone(), bytes.as_slice()))
                .collect::<Vec<_>>();
            durable
                .preflight_immutable_publication_with_separate_root(
                    heptabao_durable_service::ImmutablePublication {
                        replay_epoch: selected.epoch,
                        principal: "heptabao-server",
                        namespace: "system",
                        operation_id: &operation,
                        authorization_digest: expected.digest(),
                        objects: &prepared,
                        root_resource: "state",
                        root_bytes: source.bytes(),
                    },
                )
                .map_err(storage_rejected)?;
            gate().map_err(storage_rejected)?;
            let mut pending = Vec::new();
            for (resource, bytes) in unique {
                gate().map_err(storage_rejected)?;
                match durable.get("system", &resource).map_err(storage_rejected)? {
                    Some(previous) if previous.expose() == bytes.as_slice() => {}
                    Some(_) => return Err(unavailable()),
                    None => pending.push((
                        resource,
                        Some(Secret::new(bytes.to_vec()).map_err(storage_rejected)?),
                    )),
                }
            }
            let mut generation = selected.generation;
            for (index, batch) in pending
                .chunks(heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
                .enumerate()
            {
                selected.check(&mut durable, generation)?;
                gate().map_err(storage_rejected)?;
                durable
                    .apply_batch_conditionally_before_publish(
                        BatchPublication {
                            replay_epoch: selected.epoch,
                            principal: "heptabao-server".into(),
                            namespace: "system".into(),
                            request_id: format!("{operation}-objects-{index}"),
                            authorization_digest: expected.digest(),
                            mutations: batch.to_vec(),
                        },
                        selected.conditions(),
                        &mut gate,
                    )
                    .map_err(storage_rejected)?;
                generation = generation.checked_add(1).ok_or_else(unavailable)?;
                selected.check(&mut durable, generation)?;
                gate().map_err(storage_rejected)?;
            }
            verify_v5_source(&durable, source.root(), &target, &mut gate)?;
            selected.check(&mut durable, generation)?;
            gate().map_err(storage_rejected)?;
            durable
                .apply_batch_conditionally_before_publish(
                    BatchPublication {
                        replay_epoch: selected.epoch,
                        principal: "heptabao-server".into(),
                        namespace: "system".into(),
                        request_id: format!("{operation}-root"),
                        authorization_digest: expected.digest(),
                        mutations: vec![(
                            "state".into(),
                            Some(Secret::new(source.bytes().to_vec()).map_err(storage_rejected)?),
                        )],
                    },
                    selected.conditions(),
                    &mut gate,
                )
                .map_err(storage_rejected)?;
            root_committed.set(true);
            #[cfg(test)]
            negative_test_faults::after_root_cas()?;
            generation = generation.checked_add(1).ok_or_else(unavailable)?;
            gate().map_err(storage_rejected)?;
            durable.verify_live_ownership().map_err(storage_rejected)?;
            if durable.generation() != generation
                || durable.replay_epoch() != selected.epoch
                || durable
                    .get("system", "state")
                    .map_err(storage_rejected)?
                    .as_ref()
                    .map(Secret::expose)
                    != Some(source.bytes())
            {
                return Err(unavailable());
            }
            for resource in [
                ACTIVE_CURSOR_RESOURCE,
                ACTIVE_SOURCE_ROOT_RESOURCE,
                HA_CURSOR_RESOURCE,
            ] {
                if durable
                    .get("system", resource)
                    .map_err(storage_rejected)?
                    .is_some()
                {
                    return Err(unavailable());
                }
            }
            verify_v5_source(&durable, source.root(), &target, &mut gate)?;
            gate().map_err(storage_rejected)?;
            Ok(target)
        })();
        let uncertain = durable.recovery_required() || root_committed.get() && result.is_err();
        self.durable = Some(durable);
        self.ha_activation = None;
        self.ha_read_cache = None;
        let target = match result {
            Ok(target) => target,
            Err(error) => {
                if uncertain {
                    self.recovery_required = true;
                }
                return Err(denial.into_inner().unwrap_or(error));
            }
        };
        self.state = Some(target);
        self.state_digest = Some(expected.digest());
        self.record_root = Some(source.root().clone());
        self.record_writes_since_gc = 0;
        // This is deliberately not cache_verified_ha_records or activation.
        // The caller must complete its same native read before any response.
        Ok(true)
    }
}

// These one-shot faults exist only in tests. They can remove or corrupt one
// genuinely read object, or refuse after a genuine root CAS. They cannot
// supply a root, Actor, witness, deadline, successful read or receipt.
#[cfg(test)]
mod negative_test_faults {
    use super::*;
    use std::marker::PhantomData;
    use std::rc::Rc;

    #[derive(Clone, Copy)]
    pub(super) enum Kind {
        MissingObject,
        WrongObjectBytes,
        AfterRootCas,
    }
    struct Fault {
        kind: Kind,
        observed: Rc<Cell<bool>>,
        materialization_refused: Option<Rc<Cell<bool>>>,
    }
    thread_local! {
        static NEXT: RefCell<Option<Fault>> = const { RefCell::new(None) };
        static MATERIALIZATION_REFUSAL: RefCell<Option<Rc<Cell<bool>>>> = const { RefCell::new(None) };
    }

    // The scope cannot move to a different thread or survive an unused fault.
    pub(super) struct Scope(PhantomData<Rc<()>>);

    pub(super) fn arm(
        kind: Kind,
        observed: Rc<Cell<bool>>,
        materialization_refused: Option<Rc<Cell<bool>>>,
    ) -> Scope {
        assert!(
            !observed.get(),
            "predecessor fault observation is already set"
        );
        assert!(
            materialization_refused
                .as_ref()
                .is_none_or(|seen| !seen.get())
        );
        assert_eq!(
            materialization_refused.is_none(),
            matches!(kind, Kind::AfterRootCas)
        );
        MATERIALIZATION_REFUSAL.with(|next| {
            assert!(
                next.borrow().is_none(),
                "retained refusal observation is pending"
            );
        });
        NEXT.with(|next| {
            let mut next = next.borrow_mut();
            assert!(next.is_none(), "predecessor fault is already armed");
            *next = Some(Fault {
                kind,
                observed,
                materialization_refused,
            });
        });
        Scope(PhantomData)
    }

    fn take_when(matches: impl FnOnce(Kind) -> bool) -> Option<Fault> {
        NEXT.with(|next| {
            let mut next = next.borrow_mut();
            if next.as_ref().is_some_and(|fault| matches(fault.kind)) {
                next.take()
            } else {
                None
            }
        })
    }

    pub(super) fn after_real_object_read(
        root: &RecordStateRoot,
        reference: &ObjectRef,
        mut bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let Some(fault) = take_when(|kind| !matches!(kind, Kind::AfterRootCas)) else {
            return Ok(bytes);
        };
        // read_record_object has already used the real HA AEAD codec and the
        // original selected reference. The first materialized item is a real
        // owner chunk; assert its original address and kind before faulting.
        let address = root.address_key();
        assert!(reference.owner_chunk_payload(&address, &bytes).is_ok());
        assert!(
            !fault.observed.replace(true),
            "one retained-object fault only"
        );
        MATERIALIZATION_REFUSAL.with(|next| {
            let mut next = next.borrow_mut();
            assert!(
                next.is_none(),
                "one retained materialization observation only"
            );
            let refused = fault.materialization_refused;
            assert!(refused.is_some(), "retained fault observer");
            *next = refused;
        });
        match fault.kind {
            Kind::MissingObject => Err(RecordError::Missing),
            Kind::WrongObjectBytes => {
                assert!(!bytes.is_empty(), "actual owner chunk is nonempty");
                if let Some(last) = bytes.last_mut() {
                    *last ^= 1;
                }
                assert_eq!(
                    reference.verify(&address, &bytes),
                    Err(RecordError::Corrupt)
                );
                // Return the altered bytes, not a synthetic validation error.
                // materialize_record_state -> owner_bytes must run its actual
                // owner_chunk_payload/address validation and reject them.
                Ok(bytes)
            }
            Kind::AfterRootCas => unreachable!("root fault is consumed separately"),
        }
    }

    pub(super) fn after_target_materialization(result: &Result<State, Response>) {
        MATERIALIZATION_REFUSAL.with(|next| {
            let Some(observed) = next.borrow_mut().take() else {
                return;
            };
            assert!(
                result.is_err(),
                "the actual retained record materializer accepted a faulted owner"
            );
            if let Err(response) = result {
                assert_eq!(response.status, 503);
                assert_eq!(
                    response.body.get("errors"),
                    Some(&json!(["record state failed authenticated validation"]))
                );
                assert!(response.body.get("data").is_none() && response.body.get("auth").is_none());
                assert!(response.unwrapped_json.is_none() && response.consistency_index.is_none());
                assert!(
                    !observed.replace(true),
                    "one actual materialization refusal only"
                );
            }
        });
    }

    pub(super) fn after_root_cas() -> Result<(), Response> {
        if let Some(fault) = take_when(|kind| matches!(kind, Kind::AfterRootCas)) {
            assert!(!fault.observed.replace(true), "one post-CAS refusal only");
            return Err(unavailable());
        }
        Ok(())
    }

    impl Drop for Scope {
        fn drop(&mut self) {
            NEXT.with(|next| {
                next.borrow_mut().take();
            });
            MATERIALIZATION_REFUSAL.with(|next| {
                next.borrow_mut().take();
            });
        }
    }
}
