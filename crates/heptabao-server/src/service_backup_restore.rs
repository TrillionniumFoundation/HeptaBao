//! Validate one authenticated backup before consuming its durable restore plan.
use super::*;
#[path = "service_ha_restore.rs"]
mod ha_restore;
use heptabao_durable_service::PreparedRestore;

// Live durable reads own Secret; prepared reads borrow the decoded snapshot.
// This shares the exact startup/schema/owner/record validation without a
// second BTreeMap containing copies of every system resource.
pub(super) enum StateResource<'a> {
    Owned(Secret),
    Borrowed(&'a [u8]),
}
impl StateResource<'_> {
    fn expose(&self) -> &[u8] {
        match self {
            Self::Owned(value) => value.expose(),
            Self::Borrowed(value) => value,
        }
    }
}
pub(super) trait StateResources {
    fn get(&self, resource: &str) -> Result<Option<StateResource<'_>>, ServiceError>;
    fn replay_epoch(&self) -> u64;
}
impl StateResources for DurableService<AeadBarrier> {
    fn get(&self, resource: &str) -> Result<Option<StateResource<'_>>, ServiceError> {
        DurableService::get(self, "system", resource).map(|value| value.map(StateResource::Owned))
    }
    fn replay_epoch(&self) -> u64 {
        DurableService::replay_epoch(self)
    }
}
impl StateResources for PreparedRestore {
    fn get(&self, resource: &str) -> Result<Option<StateResource<'_>>, ServiceError> {
        PreparedRestore::get(self, "system", resource)
            .map(|value| value.map(StateResource::Borrowed))
    }
    fn replay_epoch(&self) -> u64 {
        self.metadata().replay_epoch
    }
}
struct ResourceRecordReader<'a, R>(&'a R);
impl<R: StateResources> crate::state_records::RecordReader for ResourceRecordReader<'_, R> {
    fn read_object(
        &self,
        reference: &crate::state_records::ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, crate::state_records::RecordError> {
        let resource = self
            .0
            .get(&reference.resource())
            .map_err(|_| crate::state_records::RecordError::Corrupt)?
            .ok_or(crate::state_records::RecordError::Missing)?;
        // The core reader requires an owned, zeroizing object. Only this
        // selected object is copied; no extra full resource map is built.
        Ok(Zeroizing::new(resource.expose().to_vec()))
    }
}

pub(super) struct PreparedSnapshotRestore {
    durable: PreparedRestore,
    state: State,
    root: Option<crate::state_record_root::RecordStateRoot>,
    digest: [u8; 32],
    activation: String,
    base: crate::state_record_root::StateIdentity,
}

impl PreparedSnapshotRestore {
    pub(super) fn generation(&self) -> u64 {
        self.durable.metadata().generation
    }
}

impl Service {
    fn load_owner_bytes(
        resources: &impl StateResources,
        manifest: &owner_store::OwnerStateManifest,
        owner: &str,
    ) -> Result<Zeroizing<Vec<u8>>, Response> {
        let count = manifest
            .chunk_count(owner)
            .map_err(|_| Response::error(503, "owner-state manifest is invalid"))?;
        let mut values = Vec::with_capacity(count);
        for index in 0..count {
            let resource = manifest
                .chunk_resource(owner, index)
                .map_err(|_| Response::error(503, "owner-state manifest is invalid"))?;
            let chunk = resources
                .get(&resource)
                .map_err(|_| Response::error(503, "owner-state chunk is unavailable"))?
                .ok_or_else(|| Response::error(503, "owner-state chunk is absent"))?;
            values.push(chunk);
        }
        let refs = values.iter().map(StateResource::expose).collect::<Vec<_>>();
        let bytes = manifest
            .assemble_owner(owner, &refs)
            .map_err(|_| Response::error(503, "owner-state chunk set is invalid"))?;
        Ok(bytes)
    }

    pub(super) fn load_state_from_resources(
        resources: &impl StateResources,
    ) -> Result<(State, Zeroizing<Vec<u8>>, bool), Response> {
        let record = resources
            .get("state")
            .map_err(|_| Response::error(503, "server state is unavailable"))?
            .ok_or_else(|| Response::error(503, "server state is absent; recovery required"))?;

        if let Some(mut root) = records::decode_root(record.expose())? {
            let mut state =
                Self::materialize_record_state(&root, &ResourceRecordReader(resources))?;
            if state.replay_epoch > resources.replay_epoch() {
                return Err(Response::error(
                    503,
                    "record replay epoch is ahead of durable authority",
                ));
            }
            let rewrite = state.replay_epoch < resources.replay_epoch();
            if rewrite {
                state.replay_epoch = resources.replay_epoch();
                root.replay_epoch = state.replay_epoch;
                state.schema = CURRENT_STATE_SCHEMA;
                root.state_schema = state.schema;
            }
            let bytes = root
                .encode()
                .map_err(|_| Response::error(503, "record root encoding failed"))?;
            return Ok((state, bytes, rewrite));
        }
        let owner_manifest = owner_store::decode_manifest(record.expose())
            .map_err(|_| Response::error(503, "owner-state manifest is invalid"))?;
        let (mut state, mut bytes, mut needs_rewrite) = if let Some(manifest) = owner_manifest {
            let namespaces = Self::load_owner_bytes(resources, &manifest, "namespaces")?;
            let auth = Self::load_owner_bytes(resources, &manifest, "auth")?;
            let engines = Self::load_owner_bytes(resources, &manifest, "engines")?;
            let database = Self::load_owner_bytes(resources, &manifest, "database")?;
            let raft_admin = Self::load_owner_bytes(resources, &manifest, "raft_admin")?;
            let state = State {
                schema: manifest.state_schema(),
                cluster_id: manifest.cluster_id().to_owned(),
                replay_epoch: manifest.replay_epoch(),
                namespaces: serde_json::from_slice::<namespaces::NamespaceRegistry>(&namespaces)
                    .map(CowOwner::from)
                    .map_err(|_| Response::error(503, "namespace owner state is invalid"))?,
                auth: serde_json::from_slice(&auth)
                    .map_err(|_| Response::error(503, "auth owner state is invalid"))?,
                engines: serde_json::from_slice(&engines)
                    .map_err(|_| Response::error(503, "engine owner state is invalid"))?,
                database: serde_json::from_slice(&database)
                    .map_err(|_| Response::error(503, "database owner state is invalid"))?,
                raft_admin: serde_json::from_slice(&raft_admin)
                    .map_err(|_| Response::error(503, "raft-admin owner state is invalid"))?,
            };
            state.validate_format()?;
            let bytes = owner_store::serialize_owner(&state).map_err(state_serialization_error)?;
            manifest
                .verify_logical(&bytes)
                .map_err(|_| Response::error(503, "owner-state logical digest is invalid"))?;
            (state, bytes, false)
        } else {
            let manifest = state_store::decode_manifest(record.expose())
                .map_err(|_| Response::error(503, "server state manifest is invalid"))?;
            let (bytes, needs_rewrite) = if let Some(manifest) = manifest.as_ref() {
                let mut chunk_values = Vec::with_capacity(manifest.chunk_count());
                for index in 0..manifest.chunk_count() {
                    let resource = manifest
                        .chunk_resource(index)
                        .map_err(|_| Response::error(503, "server state manifest is invalid"))?;
                    let chunk = resources
                        .get(&resource)
                        .map_err(|_| Response::error(503, "server state chunk is unavailable"))?
                        .ok_or_else(|| Response::error(503, "server state chunk is absent"))?;
                    chunk_values.push(chunk);
                }
                let chunk_refs = chunk_values
                    .iter()
                    .map(StateResource::expose)
                    .collect::<Vec<_>>();
                let assembled = state_store::assemble_state(manifest, &chunk_refs)
                    .map_err(|_| Response::error(503, "server state chunk set is invalid"))?;
                (assembled, false)
            } else {
                if record.expose().len() > MAX_STATE_BYTES {
                    return Err(Response::error(
                        507,
                        "legacy server state exceeds migration bound",
                    ));
                }
                (Zeroizing::new(record.expose().to_vec()), true)
            };
            let state: State = serde_json::from_slice(&bytes)
                .map_err(|_| Response::error(503, "server state schema is invalid"))?;
            state.validate_format()?;
            if let Some(manifest) = manifest
                && manifest.state_schema() != state.schema
            {
                return Err(Response::error(
                    503,
                    "server state manifest schema binding is inconsistent",
                ));
            }
            (state, bytes, needs_rewrite)
        };

        let durable_epoch = resources.replay_epoch();
        if state.replay_epoch > durable_epoch {
            return Err(Response::error(
                503,
                "server state replay epoch is ahead of durable replay authority",
            ));
        }
        let mut logical_rewrite = false;
        if state.replay_epoch < durable_epoch {
            state.replay_epoch = durable_epoch;
            logical_rewrite = true;
        }
        if state.adopt_legacy_namespaces()? {
            logical_rewrite = true;
        }
        if logical_rewrite {
            state.schema = CURRENT_STATE_SCHEMA;
            state.validate_format()?;
        }
        if logical_rewrite || needs_rewrite {
            // Raw legacy bytes can use another serializer's field order or
            // omitted defaults. The new owner chunks serialize the typed State;
            // their local logical digest must bind that same representation.
            // Already-published owner manifests are verified above, never
            // repaired by accepting a mismatched digest.
            bytes = owner_store::serialize_owner(&state).map_err(state_serialization_error)?;
            needs_rewrite = true;
        }
        Ok((state, bytes, needs_rewrite))
    }

    pub(super) fn prepare_snapshot_restore(
        &self,
        backup: &[u8],
    ) -> Result<PreparedSnapshotRestore, Response> {
        let durable = self
            .durable
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let prepared = durable
            .prepare_restore(backup)
            .map_err(|error| match error {
                ServiceError::CorruptState | ServiceError::BarrierFailure => {
                    Response::error(400, "snapshot authentication or structure failed")
                }
                _ => Response::error(503, "snapshot preparation is unavailable"),
            })?;
        self.validate_prepared_snapshot_restore(prepared)
    }

    pub(super) fn prepare_snapshot_restore_from_reader(
        &self,
        reader: &mut impl Read,
        length: u64,
    ) -> Result<PreparedSnapshotRestore, Response> {
        let durable = self
            .durable
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let prepared = durable
            .prepare_restore_from_reader(reader, length)
            .map_err(|error| match error {
                ServiceError::CorruptState | ServiceError::BarrierFailure => {
                    Response::error(400, "snapshot authentication or structure failed")
                }
                _ => Response::error(503, "snapshot preparation is unavailable"),
            })?;
        self.validate_prepared_snapshot_restore(prepared)
    }

    fn validate_prepared_snapshot_restore(
        &self,
        prepared: heptabao_durable_service::PreparedRestore,
    ) -> Result<PreparedSnapshotRestore, Response> {
        let (state, bytes, _) = Self::load_state_from_resources(&prepared)
            .map_err(|_| Response::error(400, "snapshot application state is invalid"))?;
        if state.engines.has_openldap_mount() || !state.database.is_empty() {
            return Err(Response::error(
                409,
                "snapshot contains external provider identities; reconcile them before restore",
            ));
        }
        let root = records::decode_root(&bytes)
            .map_err(|_| Response::error(400, "snapshot publication is invalid"))?;
        self.validate_loaded_capacity(&state, root.as_ref())?;
        let digest = match &root {
            Some(root) => root
                .identity()
                .map_err(|_| Response::error(400, "snapshot record identity is invalid"))?
                .digest(),
            None => crypto::digest(&bytes),
        };
        Ok(PreparedSnapshotRestore {
            durable: prepared,
            state,
            root,
            digest,
            activation: self.unseal_nonce.clone(),
            base: self.current_state_identity()?,
        })
    }

    pub(super) fn commit_snapshot_restore(
        &mut self,
        prepared: PreparedSnapshotRestore,
        principal: &Principal,
        request: &RequestView<'_>,
    ) -> Response {
        self.commit_snapshot_restore_with_rollback(
            prepared,
            principal,
            request,
            request.path == "sys/storage/raft/snapshot-force",
        )
    }

    pub(super) fn commit_native_snapshot_restore(
        &mut self,
        verified: snapshot_transfer::VerifiedNativeRestore,
        principal: &Principal,
        request: &RequestView<'_>,
    ) -> Response {
        if self.ha.is_some() {
            let clock = verified.clock();
            return self.commit_ha_native_snapshot_restore(
                verified.into_prepared(),
                principal,
                request,
                clock,
            );
        }
        // Native ordinary restore, like OpenBao, restores older data after
        // proving the archive belongs to the live seal. JSON retains its
        // explicit legacy generation/force policy above.
        self.commit_snapshot_restore_with_rollback(
            verified.into_prepared(),
            principal,
            request,
            true,
        )
    }

    fn commit_snapshot_restore_with_rollback(
        &mut self,
        prepared: PreparedSnapshotRestore,
        principal: &Principal,
        request: &RequestView<'_>,
        allow_rollback: bool,
    ) -> Response {
        // This route is synchronous under the Service writer. Keep the
        // authority checks explicit before consuming the plan; future callers
        // must not turn this into an unfenced split-phase commit.
        if self.ha.is_some() {
            return Response::error(
                409,
                "direct local snapshot restore is forbidden while HA is enabled",
            );
        }
        if self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.unseal_nonce != prepared.activation
            || self.current_state_identity().ok() != Some(prepared.base)
        {
            return Response::error(503, "snapshot restore authority changed; prepare again");
        }
        let Some(current) = self.state.as_ref() else {
            return Response::error(503, "server is sealed");
        };
        if !principal.is_root() {
            return Response::error(403, "permission denied");
        }
        if let Err(error) = current.auth.authorize_request(
            principal,
            request.namespace,
            request.path,
            "update",
            request.now,
        ) {
            return Response::error(error.status, &error.message);
        }
        if !current.database.is_empty() || current.engines.has_openldap_mount() {
            return Response::error(
                409,
                "external provider state cannot be rolled back with a local snapshot",
            );
        }
        if let Err(error) = self.validate_loaded_capacity(&prepared.state, prepared.root.as_ref()) {
            return error;
        }
        let Some(durable) = self.durable.as_mut() else {
            return Response::error(503, "server is sealed");
        };
        // Restoring identical auth configuration is still a new activation:
        // provider observations admitted before rollback must not survive it.
        // Prepare randomness before publication, and change the live nonce
        // only after the durable restore succeeds.
        let next_activation = match crypto::random::<16>() {
            Ok(value) => hex(&value),
            Err(error) => return Response::error(503, error),
        };
        let outcome = match durable.restore_prepared(prepared.durable, allow_rollback) {
            Ok(outcome) => outcome,
            Err(ServiceError::BackupRollbackRejected) => {
                return Response::error(
                    400,
                    "snapshot is older than live state; use snapshot-force only after review",
                );
            }
            Err(ServiceError::RequestBindingConflict) => {
                return Response::error(409, "snapshot restore state changed; prepare again");
            }
            Err(_) => {
                if durable.recovery_required() {
                    self.recovery_required = true;
                }
                return Response::error(
                    503,
                    "snapshot restore failed; authoritative recovery required",
                );
            }
        };
        // All parsing/graph/owner checks happened before publication. Install
        // that exact candidate rather than decrypt or materialize it again.
        self.state = Some(prepared.state);
        self.record_root = prepared.root;
        self.state_digest = Some(prepared.digest);
        self.unseal_nonce = next_activation;
        self.record_writes_since_gc = 64;
        self.ha_read_cache = None;
        self.recovery_required = false;
        Response::ok(json!({"data": {
            "previous_generation": outcome.previous_generation,
            "restored_generation": outcome.restored_generation,
            "retained_requests": outcome.retained_requests,
            "rollback": outcome.restored_generation < outcome.previous_generation,
        }}))
    }
}

#[cfg(test)]
#[path = "service_backup_restore_tests.rs"]
mod tests;
