//! A local historical KV read during the explicitly configured peer-v1 bridge.
//! This never executes a legacy business RPC or constructs forward completion.
use super::*;
use heptabao_raft_runtime::ApplicationReadWitness;
use std::time::Instant;

pub(super) struct LegacyReplicaRead {
    ha: Arc<Mutex<HaProcess>>,
    witness: ApplicationReadWitness,
    nonce: Zeroizing<String>,
    seal: SealMetadata,
    barrier_digest: [u8; 32],
    deadline: Instant,
}

fn unavailable() -> Response {
    Response::error(503, "legacy local KV read authority is unavailable")
}

impl LegacyReplicaRead {
    fn capture(service: &mut Service, ha: Arc<Mutex<HaProcess>>) -> Result<Self, Response> {
        let deadline = crate::request_deadline::current().ok_or_else(unavailable)?;
        verify_local_graph(service, deadline)?;
        let (identity, witness) = ha
            .lock_for_request()
            .map_err(|_| unavailable())?
            .application_identity_witness()
            .map_err(|_| unavailable())?;
        if service.current_state_identity()? != identity {
            return Err(unavailable());
        }
        let result = Self {
            ha,
            witness,
            nonce: Zeroizing::new(service.unseal_nonce.clone()),
            seal: service.seal.clone().ok_or_else(unavailable)?,
            barrier_digest: crypto::digest(
                service
                    .barrier_key
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .as_slice(),
            ),
            deadline,
        };
        result.check(service)?;
        Ok(result)
    }

    pub(super) fn check(&self, service: &mut Service) -> Result<(), Response> {
        if Instant::now() >= self.deadline
            || crate::request_deadline::current().is_some_and(|deadline| Instant::now() >= deadline)
            || service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.nonce.as_str()
            || service.seal.as_ref() != Some(&self.seal)
            || load_seal_metadata(&service.data_dir)
                .ok()
                .flatten()
                .as_ref()
                != Some(&self.seal)
            || service
                .ha
                .as_ref()
                .is_none_or(|ha| !Arc::ptr_eq(ha, &self.ha))
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
        {
            return Err(unavailable());
        }
        verify_local_graph(service, self.deadline)?;
        // The runtime witness carries the actual store/session and original
        // quorum scope. A digest or an applied-index inequality is insufficient.
        let (identity, current) = self
            .ha
            .lock_for_request()
            .map_err(|_| unavailable())?
            .application_identity_witness()
            .map_err(|_| unavailable())?;
        if service.current_state_identity()? != identity
            || !current.covers_application_witness(&self.witness)
            || Instant::now() >= self.deadline
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

fn verify_local_graph(service: &mut Service, deadline: Instant) -> Result<(), Response> {
    if Instant::now() >= deadline
        || crate::request_deadline::current().is_some_and(|original| Instant::now() >= original)
        || service.recovery_required
        || service.audit_failed
    {
        return Err(unavailable());
    }
    service
        .durable
        .as_mut()
        .ok_or_else(unavailable)?
        .verify_live_ownership()
        .map_err(|_| unavailable())?;
    let durable = service.durable.as_ref().ok_or_else(unavailable)?;
    let generation = durable.generation();
    let (loaded, _, _) = Service::load_state_from_durable(durable)?;
    let actual = service
        .state
        .as_ref()
        .ok_or_else(unavailable)?
        .protected_state()?;
    let logical = owner_store::serialize_owner(&loaded).map_err(state_serialization_error)?;
    if owner_store::serialize_owner(&actual).map_err(state_serialization_error)? != logical
        || durable.replay_epoch() != loaded.replay_epoch
    {
        return Err(unavailable());
    }
    let published = durable
        .get("system", "state")
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    match service.current_state_identity()? {
        crate::state_record_root::StateIdentity::Legacy(digest) => {
            if records::decode_root(published.expose())?.is_some()
                || crypto::digest(&logical) != digest
            {
                return Err(unavailable());
            }
            if let Some(manifest) =
                owner_store::decode_manifest(published.expose()).map_err(|_| unavailable())?
            {
                manifest
                    .verify_logical(&logical)
                    .map_err(|_| unavailable())?;
            }
        }
        crate::state_record_root::StateIdentity::RecordsV5(identity) => {
            let root = RecordStateRoot::decode(published.expose()).map_err(|_| unavailable())?;
            if root.identity().map_err(|_| unavailable())?
                != crate::state_record_root::StateIdentity::RecordsV5(identity)
                || root.state_schema != loaded.schema
                || root.cluster_id != loaded.cluster_id
                || root.replay_epoch != loaded.replay_epoch
            {
                return Err(unavailable());
            }
        }
    }
    service
        .durable
        .as_mut()
        .ok_or_else(unavailable)?
        .verify_live_ownership()
        .map_err(|_| unavailable())?;
    if service
        .durable
        .as_ref()
        .ok_or_else(unavailable)?
        .generation()
        != generation
        || Instant::now() >= deadline
    {
        return Err(unavailable());
    }
    Ok(())
}

impl Service {
    pub(super) fn legacy_immutable_kv_response(
        &mut self,
        request: &RequestView<'_>,
        ha: Arc<Mutex<HaProcess>>,
    ) -> Option<Response> {
        // Restrict this initial bridge to native, root-namespace GETs with no
        // operation carrier, wrapping or provider credential. Other requests
        // retain the original completed-forward requirement.
        if request.method != "GET"
            || !request.namespace.is_empty()
            || request.wrap_ttl_seconds.is_some()
            || request.token_clock.is_none()
            || request.body.as_object().is_none_or(|body| !body.is_empty())
            || crate::request_deadline::current().is_none()
        {
            return None;
        }
        let legacy = match ha.lock_for_request() {
            Ok(process) => process.emits_legacy_peer_v1(),
            Err(_) => return Some(unavailable()),
        };
        if !legacy {
            return None;
        }
        if let Err(error) = self.sync_from_ha_with_anchor(false) {
            return Some(error);
        }
        let state = self.state.as_ref()?;
        if state.has_token_api_precision_state()
            || state.engines.has_kubernetes_opaque_artifact_state()
            || state.engines.has_live_leases()
            || !state
                .auth
                .legacy_immutable_token_is_non_consuming(request.token)
            || !state.engines.is_immutable_kv_read("", "GET", request.path)
            || state
                .engines
                .ordinary_kv_mount_binding("", request.path)
                .is_none()
        {
            return None;
        }
        let replica = match LegacyReplicaRead::capture(self, ha) {
            Ok(replica) => replica,
            Err(error) => return Some(error),
        };
        let Some(response) = self.immutable_kv_response(request) else {
            return Some(unavailable());
        };
        if let Some(authority) = self.pending_ordinary_kv_authority.as_mut() {
            authority.bind_legacy_replica(replica);
        } else if (200..300).contains(&response.status) {
            return Some(unavailable());
        }
        self.kv_read_only_dispatches = self.kv_read_only_dispatches.saturating_add(1);
        Some(response)
    }
}

#[cfg(test)]
#[path = "service_legacy_immutable_kv_tests.rs"]
mod tests;
