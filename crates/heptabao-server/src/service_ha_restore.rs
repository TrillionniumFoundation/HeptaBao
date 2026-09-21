//! Native restore is a new cluster publication, never a local Raft rewind.
use super::*;
use crate::state_record_root::{self, OWNER_CHUNK_BYTES, OpaqueOwnerRef, RecordStateRoot};
use crate::state_records::{ObjectId, StagedObject};
use std::collections::BTreeSet;

fn invalid() -> Response {
    Response::error(400, "native HA restore application state is invalid")
}
fn deadline() -> Result<(), Response> {
    if crate::request_deadline::current().is_none_or(|end| std::time::Instant::now() >= end) {
        return Err(Response::error(
            503,
            "native HA restore deadline unavailable or elapsed",
        ));
    }
    Ok(())
}

impl Service {
    // Only called after v2 checksum and same-seal verification by the affine
    // native transfer. No constructor accepting an unverified archive exists.
    pub(super) fn commit_ha_native_snapshot_restore(
        &mut self,
        prepared: PreparedSnapshotRestore,
        actor: &Principal,
        request: &RequestView<'_>,
        clock: (Duration, std::time::Instant),
    ) -> Response {
        match self.publish_ha_native_restore(prepared, actor, request, clock) {
            Ok(response) => response,
            Err(response) => response,
        }
    }

    fn publish_ha_native_restore(
        &mut self,
        prepared: PreparedSnapshotRestore,
        actor: &Principal,
        request: &RequestView<'_>,
        clock: (Duration, std::time::Instant),
    ) -> Result<Response, Response> {
        deadline()?;
        if self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.unseal_nonce != prepared.activation
            || self.current_state_identity().ok() != Some(prepared.base)
        {
            return Err(Response::error(409, "native HA restore authority changed"));
        }
        let process = self
            .ha
            .clone()
            .ok_or_else(|| Response::error(409, "HA restore requires HA"))?;
        {
            let process = process
                .lock_for_request()
                .map_err(|_| Response::error(503, "HA unavailable"))?;
            if !process.is_leader().unwrap_or(false) {
                return Err(Response::error(503, "HA restore requires leader"));
            }
        }
        let live = self.state.as_ref().ok_or_else(invalid)?;
        if !actor.is_root() || !request.namespace.is_empty() {
            return Err(Response::error(403, "permission denied"));
        }
        live.auth
            .authorize_request(
                actor,
                request.namespace,
                request.path,
                "update",
                request.now,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        if !live.database.is_empty()
            || live.engines.has_openldap_mount()
            || !prepared.state.database.is_empty()
            || prepared.state.engines.has_openldap_mount()
        {
            return Err(Response::error(
                409,
                "external provider state cannot be restored by HA snapshot",
            ));
        }
        if self.record_root.is_none() || prepared.root.is_none() {
            return Err(Response::error(
                409,
                "native HA restore requires record-v5 application roots",
            ));
        }
        if prepared.state.cluster_id != live.cluster_id
            || prepared.state.replay_epoch > live.replay_epoch
        {
            return Err(Response::error(
                400,
                "snapshot cluster or replay history differs",
            ));
        }
        if *prepared.state.raft_admin != *live.raft_admin {
            return Err(Response::error(
                409,
                "native HA restore cannot change autopilot or promotion state",
            ));
        }
        let next_epoch = live
            .replay_epoch
            .checked_add(1)
            .ok_or_else(|| Response::error(507, "replay epoch exhausted"))?;
        let previous_generation = self.durable.as_ref().ok_or_else(invalid)?.generation();
        let imported_generation = prepared.generation();
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        let fixture_base = prepared.base;
        let (state, plan) = self.prepare_ha_restore_records(prepared, next_epoch)?;
        deadline()?;
        let now = clock.0.saturating_add(clock.1.elapsed()).as_secs();
        self.state
            .as_ref()
            .ok_or_else(invalid)?
            .auth
            .authorize_request(actor, request.namespace, request.path, "update", now)
            .map_err(|error| Response::error(error.status, &error.message))?;
        // This performs local full-closure admission and HA full replacement
        // admission before staging, then exact CAS. Unknown epoch publication
        // errors and postcommit local failures fence in commit_record_plan.
        #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
        let fixture = self.native_restore_fault.take().map(|gate| {
            crate::fixture_native_restore::NativeRestoreFaultContext::new(
                gate,
                fixture_base,
                plan.identity,
                previous_generation,
            )
        });
        if let Err(mut response) = self.commit_record_plan_with_before_publish(
            &state,
            plan,
            |auth| {
                deadline()?;
                let now = clock.0.saturating_add(clock.1.elapsed()).as_secs();
                auth.authorize_request(actor, request.namespace, request.path, "update", now)
                    .map_err(|error| Response::error(error.status, &error.message))
            },
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            fixture,
        ) {
            if self.recovery_required
                && let Some(body) = response.body.as_object_mut()
            {
                body.insert("recovery_required".into(), json!(true));
                body.insert("retry_allowed".into(), json!(false));
            }
            return Err(response);
        }
        self.state = Some(state);
        let published_generation = self.durable.as_ref().ok_or_else(invalid)?.generation();
        if deadline().is_err() {
            self.recovery_required = true;
            self.ha_read_cache = None;
            return Err(Response {
                status: 503,
                body: json!({
                    "errors":["native HA restore committed after response deadline; reconcile before retry"],
                    "recovery_required":true,"retry_allowed":false
                }),
            });
        }
        Ok(Response::ok(json!({"data":{
            "imported_generation":imported_generation,
            "previous_local_generation":previous_generation,
            "published_local_generation":published_generation,
            "replay_epoch":next_epoch,"cluster_coordinated":true
        }})))
    }

    fn prepare_ha_restore_records(
        &self,
        prepared: PreparedSnapshotRestore,
        next_epoch: u64,
    ) -> Result<(State, records::RecordPlan), Response> {
        let archive_root = prepared.root.as_ref().ok_or_else(invalid)?;
        let key = archive_root.address_key();
        let mut state = prepared.state;
        if state.engines.record_root().as_ref() != Some(&archive_root.kv1)
            || state.cluster_id != archive_root.cluster_id
            || state.replay_epoch != archive_root.replay_epoch
        {
            return Err(invalid());
        }
        state.schema = CURRENT_STATE_SCHEMA;
        state.replay_epoch = next_epoch;
        state.auth.discard_restored_oidc_sessions();
        state.validate_format()?;
        let mut objects = Vec::<Arc<StagedObject>>::new();
        state
            .engines
            .visit_record_objects(|object| {
                objects.push(Arc::clone(object));
                Ok(())
            })
            .map_err(|_| invalid())?;
        let mut owners = archive_root.owners.clone();
        // Every owner comes from the authenticated archive, not the live
        // durable map. Auth is rebuilt after discarding external code sessions.
        for owner in &mut owners {
            if owner.name == "auth" {
                let bytes =
                    owner_store::serialize_owner(&state.auth).map_err(state_serialization_error)?;
                let mut chunks = Vec::new();
                for part in bytes.chunks(OWNER_CHUNK_BYTES) {
                    let object = StagedObject::owner_chunk(&key, part).map_err(|_| invalid())?;
                    chunks.push(object.reference().clone());
                    objects.push(object);
                }
                *owner = OpaqueOwnerRef {
                    name: "auth".into(),
                    total_bytes: bytes.len() as u64,
                    chunks,
                    digest: state_record_root::digest_owner(&key, "auth", &bytes)
                        .map_err(|_| invalid())?,
                };
            } else {
                for reference in &owner.chunks {
                    let bytes = prepared
                        .durable
                        .get("system", &reference.resource())
                        .map_err(|_| invalid())?
                        .ok_or_else(invalid)?;
                    let payload = reference
                        .owner_chunk_payload(&key, bytes)
                        .map_err(|_| invalid())?;
                    let object = StagedObject::owner_chunk(&key, payload).map_err(|_| invalid())?;
                    if object.reference() != reference {
                        return Err(invalid());
                    }
                    objects.push(object);
                }
            }
        }
        let mut seen = BTreeMap::<ObjectId, Arc<StagedObject>>::new();
        let mut unique = Vec::new();
        for object in objects {
            if let Some(prior) = seen.get(&object.reference().id) {
                if prior.reference() != object.reference() || prior.bytes() != object.bytes() {
                    return Err(invalid());
                }
            } else {
                seen.insert(object.reference().id, Arc::clone(&object));
                unique.push(object);
            }
        }
        let root = RecordStateRoot::new(
            state.schema,
            state.cluster_id.clone(),
            next_epoch,
            owners,
            archive_root.kv1.clone(),
            *key.expose(),
        )
        .map_err(|_| invalid())?;
        // Full closure, including shared edges, must be available before any
        // proposal. Imported unrelated staging objects are deliberately omitted.
        let mut visited = BTreeSet::new();
        let mut pending = root.references().cloned().collect::<Vec<_>>();
        while let Some(reference) = pending.pop() {
            if !visited.insert(reference.id) {
                continue;
            }
            let object = seen.get(&reference.id).ok_or_else(invalid)?;
            if object.reference() != &reference {
                return Err(invalid());
            }
            pending.extend(object.children().iter().cloned());
        }
        if visited.len() != seen.len() {
            return Err(invalid());
        }
        let bytes = root.encode().map_err(|_| invalid())?;
        let identity = root.identity().map_err(|_| invalid())?;
        Ok((
            state,
            records::RecordPlan {
                root,
                bytes,
                identity,
                objects: unique,
            },
        ))
    }
}
