//! Narrow, lossless historical whole-state publication during peer-v1 upgrade.
use super::*;
use std::time::Instant;
pub(crate) const OLD_STATE_LIMIT: usize = 768 * 1024;

pub(crate) struct Candidate {
    bytes: Zeroizing<Vec<u8>>,
    base_digest: [u8; 32],
    cluster_id: String,
    deadline: Instant,
}
impl Candidate {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn base_digest(&self) -> [u8; 32] {
        self.base_digest
    }
    pub(crate) fn cluster_id(&self) -> &str {
        &self.cluster_id
    }
    pub(crate) fn live(&self) -> Result<(), Response> {
        if Instant::now() >= self.deadline
            || crate::request_deadline::current() != Some(self.deadline)
        {
            return Err(unavailable());
        }
        Ok(())
    }
}
fn unavailable() -> Response {
    Response::error(
        503,
        "historical whole-state upgrade publication is unavailable",
    )
}
struct CheckedJson(Value);
impl Drop for CheckedJson {
    fn drop(&mut self) {
        erase_json(&mut self.0);
    }
}

fn object(value: &Value) -> Result<&serde_json::Map<String, Value>, Response> {
    value.as_object().ok_or_else(unavailable)
}
fn exact(value: &Value, keys: &[&str]) -> Result<(), Response> {
    let actual = object(value)?;
    if actual.len() != keys.len() || keys.iter().any(|key| !actual.contains_key(*key)) {
        return Err(unavailable());
    }
    Ok(())
}
fn discard(value: &mut Value, key: &str) -> Result<(), Response> {
    if let Some(mut removed) = value.as_object_mut().ok_or_else(unavailable)?.remove(key) {
        erase_json(&mut removed);
    }
    Ok(())
}
fn empty_namespace_maps(value: &Value) -> Result<(), Response> {
    if object(value)?
        .values()
        .any(|map| map.as_object().is_none_or(|map| !map.is_empty()))
    {
        return Err(unavailable());
    }
    Ok(())
}
fn kv_config(value: &Value) -> Result<(), Response> {
    exact(
        value,
        &["max_versions", "cas_required", "delete_version_after"],
    )
}
fn old_kv2(value: &Value) -> Result<(), Response> {
    exact(value, &["config", "entries"])?;
    kv_config(&value["config"])?;
    for entry in object(&value["entries"])?.values() {
        exact(
            entry,
            &[
                "config",
                "current_version",
                "oldest_version",
                "created_at",
                "updated_at",
                "custom_metadata",
                "versions",
            ],
        )?;
        kv_config(&entry["config"])?;
        for version in object(&entry["versions"])?.values() {
            exact(version, &["created_at", "deletion_at", "destroyed", "data"])?;
        }
    }
    Ok(())
}

/// This is a serialization proof, not a credential/ACL admission. Unknown fields
/// are never removed. The few historical-reader-ignored defaults below must
/// round-trip to the exact complete current typed State before bytes can publish.
fn checked_bytes(state: &State) -> Result<Zeroizing<Vec<u8>>, Response> {
    state.validate_format()?;
    if state.schema != 1
        || state.replay_epoch != 0
        || state.engines.record_root().is_some()
        || !state.namespace_leases.is_empty()
        || !state.namespaces.is_empty()
        || !state.database.is_empty()
        || !state.raft_admin.is_default()
    {
        return Err(unavailable());
    }
    let bytes = owner_store::serialize_owner(state).map_err(state_serialization_error)?;
    if bytes.len() > OLD_STATE_LIMIT {
        return Err(Response::error(507, "historical state capacity exhausted"));
    }
    let mut projected = CheckedJson(serde_json::from_slice(&bytes).map_err(|_| unavailable())?);
    exact(&projected.0, &["schema", "cluster_id", "auth", "engines"])?;
    let auth = &mut projected.0["auth"];
    exact(
        auth,
        &[
            "tokens",
            "policies",
            "users",
            "roles",
            "mounted_users",
            "mounted_roles",
            "auth_mounts",
            "jwt_mounts",
        ],
    )?;
    for field in [
        "users",
        "roles",
        "mounted_users",
        "mounted_roles",
        "jwt_mounts",
    ] {
        empty_namespace_maps(&auth[field])?;
    }
    for token in auth["tokens"]
        .as_object_mut()
        .ok_or_else(unavailable)?
        .values_mut()
    {
        discard(token, "cubbyhole")?;
        exact(
            token,
            &[
                "accessor",
                "namespace",
                "policies",
                "root",
                "parent",
                "created_at",
                "expires_at",
                "max_expires_at",
                "period",
                "renewable",
                "uses_remaining",
                "display_name",
                "auth_mount",
                "auth_origin_known",
            ],
        )?;
        if token["root"] != true
            || token["namespace"] != ""
            || !token["parent"].is_null()
            || !token["expires_at"].is_null()
            || !token["max_expires_at"].is_null()
            || !token["uses_remaining"].is_null()
            || !token["auth_mount"].is_null()
            || token["period"] != 0
        {
            return Err(unavailable());
        }
    }
    if object(&auth["tokens"])?.is_empty() {
        return Err(unavailable());
    }
    for namespace in object(&auth["policies"])?.values() {
        for policy in object(namespace)?.values() {
            exact(policy, &["source", "rules"])?;
            for rule in policy["rules"].as_array().ok_or_else(unavailable)? {
                exact(rule, &["path", "capabilities"])?;
            }
        }
    }
    for namespace in auth["auth_mounts"]
        .as_object_mut()
        .ok_or_else(unavailable)?
        .values_mut()
    {
        for mount in namespace
            .as_object_mut()
            .ok_or_else(unavailable)?
            .values_mut()
        {
            for key in ["accessor", "revision", "default_lease_ttl", "max_lease_ttl"] {
                discard(mount, key)?;
            }
            exact(mount, &["kind", "description"])?;
        }
    }
    let engines = &mut projected.0["engines"];
    exact(engines, &["namespaces"])?;
    for (name, namespace) in engines["namespaces"]
        .as_object_mut()
        .ok_or_else(unavailable)?
    {
        if !name.is_empty() {
            return Err(unavailable());
        }
        discard(namespace, "identity")?;
        exact(namespace, &["mounts"])?;
        for mount in namespace["mounts"]
            .as_object_mut()
            .ok_or_else(unavailable)?
            .values_mut()
        {
            discard(mount, "revision")?;
            discard(mount, "incarnation")?;
            exact(mount, &["description", "backend"])?;
            let backend = object(&mount["backend"])?;
            if backend.len() != 1 {
                return Err(unavailable());
            }
            for (kind, value) in backend {
                match kind.as_str() {
                    "Kv1" => {
                        object(value)?;
                    }
                    "Kv2" => old_kv2(value)?,
                    "Transit" | "Totp" => {
                        if kind == "Transit" {
                            exact(value, &["keys", "disable_upsert"])?;
                        } else {
                            exact(value, &["keys"])?;
                        }
                        if !object(&value["keys"])?.is_empty() {
                            return Err(unavailable());
                        }
                    }
                    _ => return Err(unavailable()),
                }
            }
        }
    }
    let projected_bytes =
        owner_store::serialize_owner(&projected.0).map_err(state_serialization_error)?;
    let restored: State = serde_json::from_slice(&projected_bytes).map_err(|_| unavailable())?;
    restored.validate_format()?;
    if owner_store::serialize_owner(&restored).map_err(state_serialization_error)? != bytes {
        return Err(unavailable());
    }
    // Publish the original full bytes, including proven neutral fields, not the
    // temporary projection. Local owners and HA keep the identical digest.
    Ok(bytes)
}

impl Service {
    fn fence_legacy_upgrade_unknown(&mut self) -> Response {
        self.capture_legacy_upgrade_publication_failure(
            ordinary_kv_delivery::LegacyUpgradePublicationFailure::ProposalUncertain,
        );
        crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
        self.recovery_required = true;
        self.ha_activation = None;
        self.ha_read_cache = None;
        Response {
            status: 503,
            body: json!({"errors":["HA publication outcome unknown; reopen and reconcile; do not blindly retry"],
            "recovery_required":true,"retry_allowed":false}),
            response_headers: Default::default(),
            consistency_index: None,
        }
    }

    fn persist_legacy_upgrade_local(
        &mut self,
        state: &State,
        candidate: &Candidate,
        plan: owner_store::OwnerWritePlan,
        operation_id: &str,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
    ) -> Result<(), Response> {
        plan.publication_binding(operation_id, candidate.bytes())
            .map_err(|_| unavailable())?;
        plan.validate_write_set().map_err(|_| unavailable())?;
        let mut mutations = Vec::with_capacity(plan.required_mutations());
        for chunk in plan.chunks {
            owner_store::validate_content_addressed_chunk(&chunk.resource, chunk.bytes.expose())
                .map_err(|_| unavailable())?;
            mutations.push((chunk.resource, Some(chunk.bytes)));
        }
        for resource in plan.deletes {
            mutations.push((resource, None));
        }
        mutations.push((
            "state".to_owned(),
            Some(Secret::new(plan.manifest_bytes).map_err(|_| unavailable())?),
        ));
        let durable = self.durable.as_mut().ok_or_else(unavailable)?;
        if durable.replay_epoch() != state.replay_epoch {
            return Err(unavailable());
        }
        let namespace_nonce = &self.unseal_nonce;
        let seal = &self.seal;
        let data_dir = &self.data_dir;
        let result = durable.apply_batch_before_publish(
            heptabao_durable_service::BatchPublication {
                replay_epoch: state.replay_epoch,
                principal: "heptabao-server".to_owned(),
                namespace: "system".to_owned(),
                request_id: operation_id.to_owned(),
                authorization_digest: crypto::digest(candidate.bytes()),
                mutations,
            },
            || {
                // Actual storage calls this after sealing/capacity/compaction, just
                // before its first candidate journal append. No new admission occurs.
                candidate
                    .live()
                    .map_err(|_| ServiceError::RecoveryRequired)?;
                if load_seal_metadata(data_dir).ok().flatten().as_ref() != seal.as_ref() {
                    return Err(ServiceError::RecoveryRequired);
                }
                authority
                    .check(state, &state.auth, namespace_nonce)
                    .map_err(|_| ServiceError::RecoveryRequired)
            },
        );
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                self.capture_ordinary_kv_outcome_unknown(&error, false);
                let mut body = json!({"errors":["local publication rejected after HA commit"]});
                if let ServiceError::OutcomeUnknown { recovery_reference } = &error {
                    body["recovery_reference"] = json!(recovery_reference);
                }
                Err(Response {
                    status: 503,
                    body,
                    response_headers: Default::default(),
                    consistency_index: None,
                })
            }
        }
    }

    /// A selected legacy bridge never falls through to a new record command.
    pub(super) fn commit_legacy_upgrade_kv(
        &mut self,
        state: &mut State,
        request: &RequestView<'_>,
    ) -> Result<bool, Response> {
        let Some(ha) = self.ha.as_ref().cloned() else {
            return Ok(false);
        };
        if !ha
            .lock_for_request()
            .map_err(|_| unavailable())?
            .emits_legacy_peer_v1()
        {
            return Ok(false);
        }
        if !matches!(request.method, "POST" | "PUT")
            || !request.namespace.is_empty()
            || request.wrap_ttl_seconds.is_some()
            || request.token_clock.is_none()
            || self.record_root.is_some()
            || self.pending_token_api_authority.is_some()
            || self.pending_ordinary_kv_commit_notice.is_some()
        {
            return Err(unavailable());
        }
        let old = self.state.as_ref().ok_or_else(unavailable)?;
        state.validate_publication_schema(Some(old))?;
        checked_bytes(old)?;
        if owner_store::serialize_owner(&old.auth).map_err(state_serialization_error)?
            != owner_store::serialize_owner(&state.auth).map_err(state_serialization_error)?
            || !old
                .auth
                .legacy_immutable_token_is_non_consuming(request.token)
        {
            return Err(unavailable());
        }
        let deadline = crate::request_deadline::current().ok_or_else(unavailable)?;
        let candidate = Candidate {
            bytes: checked_bytes(state)?,
            base_digest: self.current_state_digest()?,
            cluster_id: state.cluster_id.clone(),
            deadline,
        };
        candidate.live()?;
        let authority = self
            .pending_ordinary_kv_authority
            .as_mut()
            .ok_or_else(unavailable)?;
        if !authority.principal().is_root() {
            return Err(unavailable());
        }
        authority.check(state, &state.auth, &self.unseal_nonce)?;
        self.durable
            .as_mut()
            .ok_or_else(unavailable)?
            .verify_live_ownership()
            .map_err(|_| unavailable())?;
        let durable = self.durable.as_ref().ok_or_else(unavailable)?;
        durable
            .preflight_new_identity()
            .map_err(|error| match error {
                ServiceError::RequestCapacityExhausted => {
                    Response::error(507, "retained operation capacity exhausted")
                }
                _ => unavailable(),
            })?;
        let generation = durable.generation();
        let operation_id = hex(&crypto::random::<16>().map_err(|_| unavailable())?);
        let plan = Self::prepare_owner_state_plan(
            durable,
            state,
            candidate.bytes(),
            &operation_id,
            state.schema,
            state.replay_epoch,
            PersistOwnerStateOptions {
                compact_before_entry: true,
                allow_epoch_catchup: false,
                reuse: OwnerReuseHint::between(self.state.as_ref(), state),
            },
        )
        .map_err(|_| unavailable())?;
        let binding = plan
            .publication_binding(&operation_id, candidate.bytes())
            .map_err(|_| unavailable())?;
        let activation = self.prepare_epoch_activation(state.replay_epoch, false)?;
        self.pending_ordinary_kv_authority
            .as_mut()
            .ok_or_else(unavailable)?
            .check(state, &state.auth, &self.unseal_nonce)?;
        candidate.live()?;
        if self.durable.as_ref().ok_or_else(unavailable)?.generation() != generation
            || self
                .ha
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &ha))
        {
            return Err(unavailable());
        }
        match ha
            .lock_for_request()
            .map_err(|_| unavailable())?
            .commit_legacy_upgrade_whole(&operation_id, &candidate, binding)
        {
            Ok(_) => {}
            Err(crate::ha::LegacyCommitError::BeforeProposal) => return Err(unavailable()),
            Err(crate::ha::LegacyCommitError::ProposalUncertain) => {
                return Err(self.fence_legacy_upgrade_unknown());
            }
        }
        #[cfg(test)]
        AFTER_QUORUM_DELAY_MS.with(|delay| {
            let millis = delay.replace(0);
            if millis != 0 {
                std::thread::sleep(Duration::from_millis(millis));
            }
        });
        let Some(mut authority) = self.pending_ordinary_kv_authority.take() else {
            return Err(self.fence_legacy_upgrade_unknown());
        };
        let result = self.persist_legacy_upgrade_local(
            state,
            &candidate,
            plan,
            &operation_id,
            &mut authority,
        );
        self.pending_ordinary_kv_authority = Some(authority);
        // A quorum commit followed by a local failure is not an unused effect.
        if let Err(error) = result {
            self.capture_legacy_upgrade_publication_failure(
                ordinary_kv_delivery::LegacyUpgradePublicationFailure::CommittedLocalIncomplete,
            );
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            self.ha_read_cache = None;
            return Err(Self::ha_committed_local_failure(error));
        }
        self.state_digest = Some(crypto::digest(candidate.bytes()));
        self.install_epoch_activation(activation);
        // Keep the original capsule for the mandatory audit and final current
        // Actor/Clock/namespace/mount gate; there is no second authentication.
        Ok(true)
    }
}
#[cfg(test)]
#[path = "service_legacy_upgrade_wire_tests.rs"]
mod tests;

#[cfg(test)]
thread_local! { static AFTER_QUORUM_DELAY_MS:std::cell::Cell<u64> = const {std::cell::Cell::new(0)}; }
