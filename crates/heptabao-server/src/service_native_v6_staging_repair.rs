//! A newly authorized V5 snapshot may retire only unreachable locator metadata
//! from an interrupted native migration. The original V5 root and its complete
//! graph remain selected; physical immutable ciphertext is never removed.
use super::*;
use crate::state_records::RecordReader;
use heptabao_durable_service::{BatchPublication, MAX_ATOMIC_MUTATIONS, PublicationCondition};

const PREFIX: &str = "state-records/v6";
const RESERVED_ROOTS: [&str; 4] = [
    native_v6_reader::ACTIVE_CURSOR_RESOURCE,
    native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE,
    "state-native-v6/root",
    "state-native-v6/publication-cursor",
];
// The durable journal itself is bounded to one million records. This is an
// independent repair-work ceiling, not an unbounded recursive directory scan.
const MAX_REPAIR_LOCATORS: usize = 1_000_000;
const ROOT_CONDITIONS: usize = 1 + RESERVED_ROOTS.len();
const DELETE_BATCH: usize = MAX_ATOMIC_MUTATIONS - ROOT_CONDITIONS;

struct CheckedV5Reader<'a, F> {
    durable: &'a DurableService<AeadBarrier>,
    gate: F,
}
impl<F: Fn() -> Result<(), ServiceError>> RecordReader for CheckedV5Reader<'_, F> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.gate)().map_err(|_| RecordError::Invalid)?;
        let bytes = records::DurableReader(self.durable).read_object(reference)?;
        (self.gate)().map_err(|_| RecordError::Invalid)?;
        Ok(bytes)
    }
}

// These checks restrict deletion to the exact private locator format emitted
// by this writer. They do not authenticate a V6 graph, create a read capability
// or assume that the referenced physical object is present.
fn check_marker(resource: &str, value: &[u8], store: [u8; 16]) -> Result<(), ServiceError> {
    let invalid = || ServiceError::CorruptState;
    if value.len() != 72 || &value[..16] != b"HBV6BLOBREF0001\0" || value[16..32] != store {
        return Err(invalid());
    }
    let name = resource.rsplit('/').next().ok_or_else(invalid)?;
    if name.len() != 64
        || !name
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(invalid());
    }
    if hex(&value[32..64]) != name || value[32..64] == [0; 32] {
        return Err(invalid());
    }
    let ciphertext = u32::from_be_bytes(value[64..68].try_into().map_err(|_| invalid())?) as usize;
    let plaintext = u32::from_be_bytes(value[68..72].try_into().map_err(|_| invalid())?) as usize;
    if ciphertext == 0
        || plaintext == 0
        || ciphertext > heptabao_durable_service::MAX_IMMUTABLE_CIPHERTEXT_BYTES
        || plaintext > heptabao_durable_service::MAX_IMMUTABLE_CIPHERTEXT_BYTES
    {
        return Err(invalid());
    }
    Ok(())
}

fn collect_markers(
    durable: &DurableService<AeadBarrier>,
    root: &RecordStateRoot,
    gate: &impl Fn() -> Result<(), ServiceError>,
) -> Result<Vec<(String, Secret)>, ServiceError> {
    let mut scope = b"HeptaBao/native-v6/immutable-store/cluster\0".to_vec();
    scope.extend_from_slice(root.cluster_id.as_bytes());
    let digest = crypto::digest(&scope);
    let store: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| ServiceError::CorruptState)?;
    if store == [0; 16] {
        return Err(ServiceError::CorruptState);
    }

    let mut buckets = Vec::new();
    gate()?;
    for child in durable.list("system", PREFIX)? {
        gate()?;
        match child.as_str() {
            "kv1/" | "kv2/" => buckets.push(format!("{PREFIX}/{}", child.trim_end_matches('/'))),
            "owner/" => {
                for owner in durable.list("system", &format!("{PREFIX}/owner"))? {
                    gate()?;
                    if !matches!(
                        owner.as_str(),
                        "namespaces/" | "auth/" | "engines/" | "database/" | "raft_admin/"
                    ) {
                        return Err(ServiceError::CorruptState);
                    }
                    buckets.push(format!("{PREFIX}/owner/{}", owner.trim_end_matches('/')));
                }
            }
            _ => return Err(ServiceError::CorruptState),
        }
    }
    let mut selected = Vec::new();
    let mut observed = 0usize;
    for bucket in buckets {
        gate()?;
        for child in durable.list("system", &bucket)? {
            gate()?;
            observed = observed
                .checked_add(1)
                .ok_or(ServiceError::RequestCapacityExhausted)?;
            if observed > MAX_REPAIR_LOCATORS || child.ends_with('/') {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            let resource = format!("{bucket}/{child}");
            let value = durable
                .get("system", &resource)?
                .ok_or(ServiceError::CorruptState)?;
            gate()?;
            // Earlier inline side experiments have no external backup marker.
            // They remain completely unchanged, including their private data.
            if value.expose().starts_with(b"HBV6BLOB") {
                check_marker(&resource, value.expose(), store)?;
                selected.push((resource, value));
            }
        }
    }
    gate()?;
    Ok(selected)
}

fn source_conditions(
    durable: &DurableService<AeadBarrier>,
    root: &RecordStateRoot,
    source: &Secret,
) -> Result<Vec<PublicationCondition>, ServiceError> {
    if durable.replay_epoch() != root.replay_epoch
        || durable.get("system", "state")?.as_ref().map(Secret::expose) != Some(source.expose())
    {
        return Err(ServiceError::PublicationConditionConflict);
    }
    let mut conditions = vec![PublicationCondition {
        resource: "state".into(),
        expected: Some(source.clone()),
    }];
    for resource in RESERVED_ROOTS {
        if durable.get("system", resource)?.is_some() {
            return Err(ServiceError::PublicationConditionConflict);
        }
        conditions.push(PublicationCondition {
            resource: resource.into(),
            expected: None,
        });
    }
    Ok(conditions)
}

impl Service {
    pub(in crate::service::snapshot_transfer) fn repair_unreachable_native_migration_slots_before_v5_snapshot(
        &mut self,
        plan: &SnapshotTransferPlan,
    ) -> Result<(), Response> {
        // Ordinary configurations retain the existing export behavior. A V5
        // archive must still fail closed if it contains an external locator.
        if self.native_candidate_profile.is_none() {
            return Ok(());
        }
        if self
            .durable
            .as_ref()
            .ok_or_else(unavailable)?
            .list("system", PREFIX)
            .map_err(storage_error)?
            .is_empty()
        {
            return Ok(());
        }
        self.check_v6_snapshot_owner(plan)?;
        if !plan.is_download
            || self.native_root.is_some()
            || !matches!(plan.base, StateIdentity::RecordsV5(_))
        {
            return Err(unavailable());
        }
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        self.require_native_root_candidate(state)?;
        let root = self.record_root.as_ref().ok_or_else(unavailable)?.clone();
        if root.identity().map_err(|_| invalid())? != plan.base {
            return Err(invalid());
        }
        let source =
            Secret::new(root.encode().map_err(|_| invalid())?.to_vec()).map_err(storage_error)?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        if deadline.instant() != plan.deadline {
            return Err(unavailable());
        }
        let operation = format!(
            "native6-snapshot-staging-repair-{}",
            hex(&crypto::random::<16>().map_err(|_| unavailable())?)
        );
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let result = (|| -> Result<(), ServiceError> {
            let gate = || {
                deadline.check().map_err(|_| ServiceError::BarrierFailure)?;
                self.check_v6_snapshot_owner(plan)
                    .map_err(|_| ServiceError::BarrierFailure)
            };
            gate()?;
            durable.verify_live_ownership()?;
            let markers = collect_markers(&durable, &root, &gate)?;
            if markers.is_empty() {
                return Ok(());
            }
            source_conditions(&durable, &root, &source)?;
            // The selected, fully authenticated V5 graph cannot name resources
            // in the separate V6 domain. Neither a side root nor any retained
            // active cursor/source is permitted to claim those V6 resources.
            records::verify_received_record_graph(
                &root,
                &CheckedV5Reader {
                    durable: &durable,
                    gate: &gate,
                },
                self.state.as_ref().ok_or(ServiceError::CorruptState)?,
            )
            .map_err(|_| ServiceError::CorruptState)?;
            gate()?;
            for (index, batch) in markers.chunks(DELETE_BATCH).enumerate() {
                gate()?;
                let mut conditions = source_conditions(&durable, &root, &source)?;
                conditions.extend(batch.iter().map(|(resource, value)| PublicationCondition {
                    resource: resource.clone(),
                    expected: Some(value.clone()),
                }));
                durable.apply_batch_conditionally_before_publish(
                    BatchPublication {
                        replay_epoch: root.replay_epoch,
                        principal: "heptabao-server".into(),
                        namespace: "system".into(),
                        request_id: format!("{operation}-{index}"),
                        authorization_digest: plan.base.digest(),
                        mutations: batch
                            .iter()
                            .map(|(resource, _)| (resource.clone(), None))
                            .collect(),
                    },
                    conditions,
                    &gate,
                )?;
                gate()?;
            }
            source_conditions(&durable, &root, &source)?;
            gate()?;
            durable.verify_live_ownership()?;
            gate()?;
            Ok(())
        })();
        let unknown = durable.recovery_required()
            || matches!(
                &result,
                Err(ServiceError::OutcomeUnknown { .. } | ServiceError::RecoveryRequired)
            );
        self.durable = Some(durable);
        if unknown {
            self.recovery_required = true;
            self.ha_activation = None;
        }
        result.map_err(|error| self.v6_storage_failure(plan, error))?;
        self.check_v6_snapshot_owner(plan)
    }
}
