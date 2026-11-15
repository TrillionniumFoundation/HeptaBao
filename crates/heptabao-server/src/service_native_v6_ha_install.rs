//! Install an already committed V6 graph under this Service's local barrier.
//!
//! Raft authority, local journal generations and HTTP authorization are distinct.
//! Only the actual configured HA process supplies the committed read; all local
//! mutations retain the originally selected state and the same local owner.
//! The feature and existing single-node gates remain independent and closed.
use super::*;
use crate::engines::kv2_native_records::{NativeReadView, PagedPayloadValidationMemo};
use crate::ha::{CommittedNativeV6Read, NativeV6FailureObservation};
use crate::ha_state::ClusterStateCodec;
use crate::service::native_v6_ha_objects::{
    NativeV6ObjectStorage, open_native_v6_ha_objects,
    open_native_v6_ha_objects_with_payload_validation,
};
use crate::service::native_v6_reader::{
    ACTIVE_CURSOR_RESOURCE, ACTIVE_SOURCE_ROOT_RESOURCE, NativeActiveCursor,
};
use crate::state_record_root::{RecordStateRoot, StateIdentity};
use crate::state_record_root_v6::{MountScope, RecordStateRootV6};
use crate::v6_native_custody::OriginalDeadline;
use crate::v6_read_validation::{ReadContext, ReadIdentity};
use heptabao_durable_service::{BatchPublication, ImmutableSourceSession, PublicationCondition};
use heptabao_raft_runtime::{LocalV6BlobStage, NativeV6PublishedRoot};
use std::cell::{Cell, RefCell};
#[path = "service_native_v6_ha_ingress.rs"]
mod ingress_selection;
pub(crate) use ingress_selection::NativeIngressSelectionPermit;

#[path = "service_native_v6_ha_read.rs"]
mod read;
pub(in crate::service) use read::BorrowedArchiveRepairSource;
#[cfg(test)]
use read::ColdNativeHaRead;
pub(crate) use read::{NativeHaArchiveRepairSource, NativeHaReadProof, load_cold_native_ha};

#[path = "service_native_v6_ha_migration.rs"]
mod migration;

#[path = "service_native_v6_ha_seal_syntax.rs"]
mod seal_syntax;

pub(super) const HA_CURSOR_RESOURCE: &str = "state-native-v6/ha-publication-cursor";
const HA_CURSOR_FORMAT: &str = "heptabao-native-v6-ha-local-publication-v1";

pub(in crate::service) fn validate_historical_archive_cursor(
    root: &RecordStateRootV6,
    retained: &RecordStateRoot,
    active: &[u8],
    ha: &[u8],
    archive_generation: u64,
    origin_epoch: u64,
    facts: &crate::ha::native_v6_backup::HistoricalNativeV6ArchiveFacts,
) -> Result<(), Response> {
    NativeActiveCursor::decode(active)?.validate(retained, root, archive_generation)?;
    let cursor = NativeHaCursor::decode(ha)?;
    let exact = |log: [u64; 3]| ExactLog {
        term: log[0],
        node: log[1],
        index: log[2],
    };
    if root.cluster_id != retained.cluster_id
        || root.replay_epoch != facts.replay_epoch()
        || cursor.cluster_digest != facts.cluster_digest()
        || retained.replay_epoch != origin_epoch
        || cursor.replay_epoch != facts.replay_epoch()
        || cursor.enrollment_digest != facts.enrollment_digest()
        || cursor.root_digest != facts.root_digest()
        || cursor.root_digest != root.identity().map_err(|_| unavailable())?.digest()
        || cursor.raft_generation != facts.raft_generation()
        || cursor.migration_digest != facts.migration_digest()
        || cursor.migration_digest != retained.identity().map_err(|_| unavailable())?.digest()
        || cursor.publication_log != exact(facts.publication_log())
        || cursor.intent_log != exact(facts.intent_log())
        || cursor.migration_log != exact(facts.migration_log())
        || cursor.local_publication_generation > archive_generation
        || cursor.local_publication_generation != active_generation(active)?
    {
        return Err(unavailable());
    }
    Ok(())
}

/// Check the internal relationship of an authenticated cold archive's local
/// root and cursors. These are old DATA: no surviving enrollment, new quorum
/// or live source authority is supplied or constructed by this function.
pub(in crate::service) fn validate_cold_archive_cursor(
    root: &RecordStateRootV6,
    retained: &RecordStateRoot,
    active: &[u8],
    ha: &[u8],
    archive_generation: u64,
    facts: &crate::ha::native_v6_backup::ColdNativeV6ArchiveFacts,
) -> Result<(), Response> {
    NativeActiveCursor::decode(active)?.validate(retained, root, archive_generation)?;
    let cursor = NativeHaCursor::decode(ha)?;
    let exact = |log: [u64; 3]| ExactLog {
        term: log[0],
        node: log[1],
        index: log[2],
    };
    if root.cluster_id != retained.cluster_id
        || !facts.matches_cluster_id(&root.cluster_id)
        || root.replay_epoch != facts.replay_epoch()
        || cursor.cluster_digest != facts.cluster_digest()
        || cursor.replay_epoch != facts.replay_epoch()
        || cursor.enrollment_digest != facts.enrollment_digest()
        || cursor.root_digest != facts.root_digest()
        || cursor.root_digest != root.identity().map_err(|_| unavailable())?.digest()
        || cursor.raft_generation != facts.raft_generation()
        || cursor.migration_digest != facts.migration_digest()
        || cursor.migration_digest != retained.identity().map_err(|_| unavailable())?.digest()
        || cursor.publication_log != exact(facts.publication_log())
        || cursor.intent_log != exact(facts.intent_log())
        || cursor.migration_log != exact(facts.migration_log())
        || cursor.local_publication_generation > archive_generation
        || cursor.local_publication_generation != active_generation(active)?
    {
        return Err(unavailable());
    }
    Ok(())
}

// Opt-in phase observations only: no payload, credential, source admission or
// new deadline is created. Drop also records the phase that returned an error.
// Diagnostic I/O failure never changes the original result or its custody.
#[cfg(feature = "private-ha-forward-diagnostic")]
pub(super) struct NativeHaPhaseTimer {
    phase: &'static str,
    started: std::time::Instant,
    original_until: std::time::Instant,
    generation: u64,
    objects: u64,
    bytes: u64,
    completed: bool,
}
#[cfg(feature = "private-ha-forward-diagnostic")]
impl NativeHaPhaseTimer {
    pub(super) fn start(
        phase: &'static str,
        original_until: std::time::Instant,
        generation: u64,
        objects: u64,
        bytes: u64,
    ) -> Self {
        Self {
            phase,
            started: std::time::Instant::now(),
            original_until,
            generation,
            objects,
            bytes,
            completed: false,
        }
    }
    pub(super) fn finish(mut self, completed: bool) {
        self.completed = completed;
    }
}
#[cfg(feature = "private-ha-forward-diagnostic")]
impl Drop for NativeHaPhaseTimer {
    fn drop(&mut self) {
        use std::io::Write as _;
        let observed = std::time::Instant::now();
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-PRIVATE-PERF phase={} elapsed_us={} completed={} original_deadline_expired={} generation={} objects={} bytes={}",
            self.phase,
            observed.duration_since(self.started).as_micros(),
            self.completed,
            observed >= self.original_until,
            self.generation,
            self.objects,
            self.bytes,
        );
    }
}

// Private timing observations retain every existing authority check in order.
// Only elapsed time and call counts leave this scope; no state or payload does.
#[cfg(feature = "private-ha-forward-diagnostic")]
struct NativeHaGateMetrics {
    samples: [Cell<(u64, u128)>; 4],
}
#[cfg(feature = "private-ha-forward-diagnostic")]
impl NativeHaGateMetrics {
    fn new() -> Self {
        Self {
            samples: std::array::from_fn(|_| Cell::new((0, 0))),
        }
    }
    fn observe<T>(&self, slot: usize, operation: impl FnOnce() -> T) -> T {
        let started = std::time::Instant::now();
        let result = operation();
        let (count, elapsed) = self.samples[slot].get();
        self.samples[slot].set((
            count.saturating_add(1),
            elapsed.saturating_add(started.elapsed().as_nanos()),
        ));
        result
    }
}
#[cfg(feature = "private-ha-forward-diagnostic")]
impl Drop for NativeHaGateMetrics {
    fn drop(&mut self) {
        use std::io::Write as _;
        let names = ["environment", "identity", "actor", "raft_witness"];
        for (name, slot) in names.into_iter().zip(&self.samples) {
            let (calls, elapsed) = slot.get();
            let _ = writeln!(
                std::io::stderr().lock(),
                "HBHA-PRIVATE-GATE-COST scope=local_install component={} calls={} elapsed_us={}",
                name,
                calls,
                elapsed / 1000
            );
        }
    }
}

fn unavailable() -> Response {
    Response::error(503, "native V6 HA local publication is unavailable")
}
fn live(deadline: OriginalDeadline) -> Result<(), Response> {
    deadline.check().map_err(|_| unavailable())
}
fn is_native_root(bytes: &[u8]) -> Result<bool, Response> {
    #[derive(Deserialize)]
    struct Probe {
        storage_format: String,
    }
    let probe: Probe = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
    match probe.storage_format.as_str() {
        crate::state_record_root_v6::STORAGE_FORMAT => Ok(true),
        crate::state_record_root::STORAGE_FORMAT => Ok(false),
        _ => Err(unavailable()),
    }
}
fn active_generation(bytes: &[u8]) -> Result<u64, Response> {
    // Read only after the complete canonical NativeActiveCursor was validated.
    // This extracts durable metadata, never constructs a publication permit.
    #[derive(Deserialize)]
    struct Generation {
        publication_generation: u64,
    }
    let value: Generation = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
    Ok(value.publication_generation)
}
fn storage_rejected(error: ServiceError) -> Response {
    match error {
        ServiceError::RequestCapacityExhausted | ServiceError::JournalCapacityExhausted => {
            Response::error(507, "native V6 HA local storage capacity exhausted")
        }
        ServiceError::OutcomeUnknown { recovery_reference } => Response {
            status: 503,
            body: json!({"errors":["native V6 HA local outcome unknown; reopen and reconcile"],"recovery_reference":recovery_reference}),
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
        },
        _ => unavailable(),
    }
}

// Durable metadata, never a caller capability. Full LogIds are recorded rather
// than comparing indices across terms or equating Raft and local generations.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactLog {
    term: u64,
    node: u64,
    index: u64,
}
impl ExactLog {
    fn valid(self) -> bool {
        self.term != 0 && self.node != 0 && self.index != 0
    }
    fn root(root: &NativeV6PublishedRoot) -> Self {
        let log = root.publication_log_id();
        Self {
            term: log.committed_leader_id().term,
            node: log.committed_leader_id().node_id,
            index: log.index,
        }
    }
    fn intent(root: &NativeV6PublishedRoot) -> Self {
        let log = root.intent_log_id();
        Self {
            term: log.committed_leader_id().term,
            node: log.committed_leader_id().node_id,
            index: log.index,
        }
    }
    fn migration(root: &NativeV6PublishedRoot) -> Self {
        let (_, log) = root.migration_source();
        Self {
            term: log.committed_leader_id().term,
            node: log.committed_leader_id().node_id,
            index: log.index,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeHaCursor {
    format: String,
    cluster_digest: [u8; 32],
    enrollment_digest: [u8; 32],
    replay_epoch: u64,
    raft_generation: u64,
    publication_log: ExactLog,
    intent_log: ExactLog,
    migration_log: ExactLog,
    migration_digest: [u8; 32],
    root_digest: [u8; 32],
    local_publication_generation: u64,
}
impl NativeHaCursor {
    fn new(
        read: &CommittedNativeV6Read,
        local_publication_generation: u64,
    ) -> Result<Self, Response> {
        let published = read.published();
        let cursor = Self {
            format: HA_CURSOR_FORMAT.into(),
            cluster_digest: read.enrollment().cluster_digest(),
            enrollment_digest: read.enrollment().digest(),
            replay_epoch: read.enrollment().epoch(),
            raft_generation: published.generation(),
            publication_log: ExactLog::root(published),
            intent_log: ExactLog::intent(published),
            migration_log: ExactLog::migration(published),
            migration_digest: published.migration_source().0,
            root_digest: published.root_digest(),
            local_publication_generation,
        };
        cursor.validate()?;
        Ok(cursor)
    }
    fn validate(&self) -> Result<(), Response> {
        if self.format != HA_CURSOR_FORMAT
            || self.cluster_digest == [0; 32]
            || self.enrollment_digest == [0; 32]
            || self.raft_generation == 0
            || self.local_publication_generation == 0
            || !self.publication_log.valid()
            || !self.intent_log.valid()
            || !self.migration_log.valid()
            || self.migration_log.index >= self.intent_log.index
            || self.intent_log.index >= self.publication_log.index
            || self.migration_digest == [0; 32]
            || self.root_digest == [0; 32]
        {
            return Err(unavailable());
        }
        Ok(())
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Response> {
        self.validate()?;
        crate::secret_serde::to_vec(self, crate::state_record_root::MAX_ROOT_BYTES)
            .map_err(|_| unavailable())
    }
    fn decode(bytes: &[u8]) -> Result<Self, Response> {
        if bytes.len() > crate::state_record_root::MAX_ROOT_BYTES {
            return Err(unavailable());
        }
        let cursor: Self = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
        if cursor.encode()?.as_slice() != bytes {
            return Err(unavailable());
        }
        Ok(cursor)
    }
    fn matches_current(&self, read: &CommittedNativeV6Read) -> Result<(), Response> {
        self.covered_by(read)?;
        if self.raft_generation != read.published().generation()
            || self.publication_log != ExactLog::root(read.published())
            || self.intent_log != ExactLog::intent(read.published())
            || self.root_digest != read.published().root_digest()
        {
            return Err(unavailable());
        }
        Ok(())
    }
    // Only a previously authenticated local journal may use this for cold
    // preloading/catch-up. It is never a current business-read permission.
    fn covered_by(&self, read: &CommittedNativeV6Read) -> Result<(), Response> {
        self.validate()?;
        let published = read.published();
        if self.replay_epoch != read.enrollment().epoch() {
            return self.covered_by_epoch_lineage(read);
        }
        if self.cluster_digest != read.enrollment().cluster_digest()
            || self.enrollment_digest != read.enrollment().digest()
            || self.replay_epoch != read.enrollment().epoch()
            || self.migration_digest != published.migration_source().0
            || self.migration_log != ExactLog::migration(published)
            || self.raft_generation > published.generation()
            || self.publication_log.index > published.publication_log_id().index
            || self.publication_log.term > published.publication_log_id().committed_leader_id().term
            || (self.raft_generation == published.generation()
                && (self.publication_log != ExactLog::root(published)
                    || self.intent_log != ExactLog::intent(published)
                    || self.root_digest != published.root_digest()))
            || (self.raft_generation < published.generation()
                && self.publication_log.index >= published.publication_log_id().index)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    // Only actual committed lineage can cover an older authenticated local
    // cursor. Preserve the ordinary same-epoch predicate above unchanged.
    // Mere epoch ordering or a manifest's numeric index is insufficient.
    fn covered_by_epoch_lineage(&self, read: &CommittedNativeV6Read) -> Result<(), Response> {
        self.validate()?;
        let published = read.published();
        if self.replay_epoch >= read.enrollment().epoch()
            || self.cluster_digest != read.enrollment().cluster_digest()
            || self.migration_digest != published.migration_source().0
            || self.migration_log != ExactLog::migration(published)
        {
            return Err(unavailable());
        }
        let step = published
            .epoch_transitions()
            .find(|step| step.source_enrollment().epoch() == self.replay_epoch)
            .ok_or_else(unavailable)?;
        let enrollment = step.source_enrollment();
        let source_publication = step.source_publication_log_id();
        let source_intent = step.source_intent_log_id();
        let exact_publication = ExactLog {
            term: source_publication.committed_leader_id().term,
            node: source_publication.committed_leader_id().node_id,
            index: source_publication.index,
        };
        let exact_intent = ExactLog {
            term: source_intent.committed_leader_id().term,
            node: source_intent.committed_leader_id().node_id,
            index: source_intent.index,
        };
        if enrollment.digest() != self.enrollment_digest
            || !enrollment.same_peer_configuration(read.enrollment())
            || self.raft_generation > step.source_generation()
            || self.publication_log.term > exact_publication.term
            || (self.publication_log.term == exact_publication.term
                && self.publication_log.node != exact_publication.node)
            || (self.raft_generation == step.source_generation()
                && (self.publication_log != exact_publication
                    || self.intent_log != exact_intent
                    || self.root_digest != step.source_root_digest()))
            || (self.raft_generation < step.source_generation()
                && self.publication_log.index >= exact_publication.index)
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

// Actual local unseal/file owner. Neither the read witness nor a serialized
// cursor can construct or substitute this process/nonce/barrier binding.
struct LocalHaEnvironment {
    ha: Arc<Mutex<HaProcess>>,
    data_dir: PathBuf,
    seal: seal_syntax::SealSyntaxMemo,
    nonce: Zeroizing<String>,
    barrier_digest: [u8; 32],
    deadline: OriginalDeadline,
}
impl LocalHaEnvironment {
    fn capture(
        service: &Service,
        ha: &Arc<Mutex<HaProcess>>,
        key: &[u8; 32],
        deadline: OriginalDeadline,
    ) -> Result<Self, Response> {
        live(deadline)?;
        let seal = service.seal.as_ref().ok_or_else(unavailable)?.clone();
        if service
            .ha
            .as_ref()
            .is_none_or(|actual| !Arc::ptr_eq(actual, ha))
            || service.postgres_durable.is_some()
            || service.durable_profile.is_some()
            || service.openbao_wrapper_owner.is_some()
            || service.recovery_required
            || service.audit_failed
            || seal.is_wrapper()
            || seal.schema != 1
            || key == &[0; 32]
        {
            return Err(unavailable());
        }
        seal.validate().map_err(|_| unavailable())?;
        let seal = seal_syntax::SealSyntaxMemo::capture(&service.data_dir, seal)
            .map_err(|_| unavailable())?;
        let environment = Self {
            ha: Arc::clone(ha),
            data_dir: service.data_dir.clone(),
            seal,
            nonce: Zeroizing::new(service.unseal_nonce.clone()),
            barrier_digest: crypto::digest(key),
            deadline,
        };
        environment.check_seal()?;
        Ok(environment)
    }
    fn check_seal(&self) -> Result<(), Response> {
        let result = (|| {
            live(self.deadline)?;
            self.seal.check(&self.data_dir).map_err(|_| unavailable())?;
            live(self.deadline)
        })();
        if result.is_err() {
            self.seal.refuse();
        }
        result
    }
    fn check(&self, service: &Service) -> Result<(), Response> {
        live(self.deadline)?;
        if service
            .ha
            .as_ref()
            .is_none_or(|actual| !Arc::ptr_eq(actual, &self.ha))
            || service.data_dir != self.data_dir
            || service.seal.as_ref() != Some(self.seal.expected())
            || service.unseal_nonce != *self.nonce
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
            || service.recovery_required
            || service.audit_failed
            || service.postgres_durable.is_some()
            || service.durable_profile.is_some()
            || service.openbao_wrapper_owner.is_some()
        {
            return Err(unavailable());
        }
        self.check_seal()
    }
    fn check_cold(&self, service: &Service, key: &[u8; 32]) -> Result<(), Response> {
        live(self.deadline)?;
        if service
            .ha
            .as_ref()
            .is_none_or(|actual| !Arc::ptr_eq(actual, &self.ha))
            || service.data_dir != self.data_dir
            || service.seal.as_ref() != Some(self.seal.expected())
            || service.unseal_nonce != *self.nonce
            || crypto::digest(key) != self.barrier_digest
            || service.recovery_required
            || service.audit_failed
            || service.postgres_durable.is_some()
            || service.durable_profile.is_some()
            || service.openbao_wrapper_owner.is_some()
        {
            return Err(unavailable());
        }
        self.check_seal()
    }
}

// This borrow validates only the Service's ordinary in-memory fields once.
// It is confined to one local install attempt: its shared Service reference
// prevents mutation of those fields while any gate or installer uses it.
// Filesystem seal state, Actor, Raft authority and the deadline stay live;
// durable ownership, generation, cursors and graph checks remain independent.
struct BorrowedLocalHaService<'a> {
    service: &'a Service,
    environment: &'a LocalHaEnvironment,
}
impl<'a> BorrowedLocalHaService<'a> {
    fn capture(
        service: &'a Service,
        environment: &'a LocalHaEnvironment,
        identity: StateIdentity,
    ) -> Result<Self, Response> {
        environment.check(service)?;
        if service.current_state_identity()? != identity {
            return Err(unavailable());
        }
        Ok(Self {
            service,
            environment,
        })
    }

    fn check_seal(&self) -> Result<(), Response> {
        self.environment.check_seal()
    }

    fn service(&self) -> &Service {
        self.service
    }
}

fn root_namespace_only(state: &State) -> Result<(), Response> {
    if state.auth.has_recovery_state() {
        return Err(unavailable());
    }
    // Plain child catalogs and graphs stay under the same authenticated root
    // barrier and committed Raft read. Independent/inherited custody, deletion
    // history and unpaired batch ledgers remain excluded by this exact profile.
    // V6 materialization separately enforces the new schema 138 reader floor;
    // a retained V5 migration source is still authenticated as original data.
    namespaces::native_empty::require_catalog_profile(state).map_err(|_| unavailable())
}

// One exact selected local A, including absence conditions for a first move.
// Locator-only batches may advance the durable generation; A's bytes remain
// conditions on each append until the single final root/cursor publication.
struct LocalSelection {
    root_bytes: Secret,
    active_bytes: Option<Secret>,
    source_bytes: Option<Secret>,
    ha_bytes: Option<Secret>,
    source: RecordStateRoot,
    active: Option<NativeActiveCursor>,
    native: Option<RecordStateRootV6>,
    initial_generation: u64,
    local_epoch: u64,
}
impl LocalSelection {
    fn read(
        durable: &mut DurableService<AeadBarrier>,
        read: &CommittedNativeV6Read,
    ) -> Result<Self, Response> {
        live(read.deadline())?;
        durable.verify_live_ownership().map_err(storage_rejected)?;
        if durable.recovery_required() || durable.replay_epoch() > read.enrollment().epoch() {
            return Err(unavailable());
        }
        let local_epoch = durable.replay_epoch();
        let initial_generation = durable.generation();
        let root_bytes = durable
            .get("system", "state")
            .map_err(storage_rejected)?
            .ok_or_else(unavailable)?;
        let active_bytes = durable
            .get("system", ACTIVE_CURSOR_RESOURCE)
            .map_err(storage_rejected)?;
        let source_bytes = durable
            .get("system", ACTIVE_SOURCE_ROOT_RESOURCE)
            .map_err(storage_rejected)?;
        let ha_bytes = durable
            .get("system", HA_CURSOR_RESOURCE)
            .map_err(storage_rejected)?;
        let (source, active, native) = if !is_native_root(root_bytes.expose())? {
            let root = RecordStateRoot::decode(root_bytes.expose()).map_err(|_| unavailable())?;
            if active_bytes.is_some()
                || source_bytes.is_some()
                || ha_bytes.is_some()
                || root.identity().map_err(|_| unavailable())?.digest()
                    != read.published().migration_source().0
                || root.replay_epoch != local_epoch
                || root.replay_epoch != read.published().native_origin_epoch()
            {
                return Err(unavailable());
            }
            (root, None, None)
        } else {
            let root = RecordStateRootV6::decode(root_bytes.expose()).map_err(|_| unavailable())?;
            let source =
                RecordStateRoot::decode(source_bytes.as_ref().ok_or_else(unavailable)?.expose())
                    .map_err(|_| unavailable())?;
            let active = NativeActiveCursor::decode(
                active_bytes.as_ref().ok_or_else(unavailable)?.expose(),
            )?;
            active.validate(&source, &root, initial_generation)?;
            let cursor =
                NativeHaCursor::decode(ha_bytes.as_ref().ok_or_else(unavailable)?.expose())?;
            cursor.covered_by(read)?;
            if root.replay_epoch != local_epoch
                || cursor.replay_epoch != local_epoch
                || cursor.root_digest != root.identity().map_err(|_| unavailable())?.digest()
                || cursor.migration_digest != source.identity().map_err(|_| unavailable())?.digest()
                || cursor.local_publication_generation > initial_generation
                || cursor.local_publication_generation
                    != active_generation(active_bytes.as_ref().ok_or_else(unavailable)?.expose())?
            {
                return Err(unavailable());
            }
            (source, Some(active), Some(root))
        };
        if source.replay_epoch != read.published().native_origin_epoch() {
            return Err(unavailable());
        }
        live(read.deadline())?;
        Ok(Self {
            root_bytes,
            active_bytes,
            source_bytes,
            ha_bytes,
            source,
            active,
            native,
            initial_generation,
            local_epoch,
        })
    }
    fn conditions(&self) -> Vec<PublicationCondition> {
        vec![
            PublicationCondition {
                resource: "state".into(),
                expected: Some(self.root_bytes.clone()),
            },
            PublicationCondition {
                resource: ACTIVE_CURSOR_RESOURCE.into(),
                expected: self.active_bytes.clone(),
            },
            PublicationCondition {
                resource: ACTIVE_SOURCE_ROOT_RESOURCE.into(),
                expected: self.source_bytes.clone(),
            },
            PublicationCondition {
                resource: HA_CURSOR_RESOURCE.into(),
                expected: self.ha_bytes.clone(),
            },
        ]
    }
    fn check(
        &self,
        durable: &mut DurableService<AeadBarrier>,
        generation: u64,
    ) -> Result<(), ServiceError> {
        durable.verify_live_ownership()?;
        if durable.generation() != generation || durable.replay_epoch() != self.local_epoch {
            return Err(ServiceError::PublicationConditionConflict);
        }
        for (resource, expected) in [
            ("state", Some(&self.root_bytes)),
            (ACTIVE_CURSOR_RESOURCE, self.active_bytes.as_ref()),
            (ACTIVE_SOURCE_ROOT_RESOURCE, self.source_bytes.as_ref()),
            (HA_CURSOR_RESOURCE, self.ha_bytes.as_ref()),
        ] {
            let actual = durable.get("system", resource)?;
            if actual.as_ref().map(Secret::expose) != expected.map(Secret::expose) {
                return Err(ServiceError::PublicationConditionConflict);
            }
        }
        Ok(())
    }
}

// Constructed only after LocalSelection authenticated the exact four local
// resources and checked their older epoch against the ACTUAL committed Raft
// lineage. This borrowed scope permits staging only; it cannot publish epoch,
// authorise a read, stand in for the Actor or renew the original witness.
pub(in crate::service) struct EpochInstallScope<'a> {
    selected: &'a LocalSelection,
    committed: &'a CommittedNativeV6Read,
}
impl EpochInstallScope<'_> {
    pub(in crate::service) fn check_received(
        &self,
        session: &ImmutableSourceSession,
        object: &crate::service::native_v6_ha_objects::VerifiedNativeV6Object<'_>,
    ) -> Result<(), ServiceError> {
        self.committed
            .deadline()
            .check()
            .map_err(|_| ServiceError::BarrierFailure)?;
        let target = self.committed.enrollment().epoch();
        if self.selected.local_epoch >= target
            || session.replay_epoch() != self.selected.local_epoch
            || object.root().replay_epoch != target
            || object.root().cluster_id != self.selected.source.cluster_id
            || object
                .root()
                .identity()
                .map_err(|_| ServiceError::CorruptState)?
                .digest()
                != self.committed.published().root_digest()
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        // Its typed borrow retains the same original full closure/Actor gate,
        // including the actual consensus witness. No archived object can mint it.
        object
            .check_original()
            .map_err(|_| ServiceError::BarrierFailure)
    }
}

fn context(root: &RecordStateRootV6) -> Result<ReadContext<'_>, Response> {
    Ok(ReadContext {
        expected_identity: ReadIdentity::RecordsV6(
            root.identity().map_err(|_| unavailable())?.digest(),
        ),
        cluster_id: &root.cluster_id,
        replay_epoch: root.replay_epoch,
        minimum_state_schema: root.state_schema,
        maximum_state_schema: root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    })
}

// Reopens actual registered ciphertext under a fresh generation-bound source
// session. All payloads and history are authenticated before selecting B.
fn materialize_local(
    durable: &mut DurableService<AeadBarrier>,
    root: &RecordStateRootV6,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<(State, BTreeMap<MountScope, NativeReadView>), Response> {
    materialize_local_with_payload_validation(durable, root, deadline, gate, None)
}

fn materialize_local_with_payload_validation(
    durable: &mut DurableService<AeadBarrier>,
    root: &RecordStateRootV6,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
    payload_validation: Option<&RefCell<PagedPayloadValidationMemo>>,
) -> Result<(State, BTreeMap<MountScope, NativeReadView>), Response> {
    let source = native_blob_source::NativeSource::new_checked(durable, deadline, gate)
        .map_err(|_| unavailable())?;
    let result = match payload_validation {
        Some(memo) => v6_records::materialize_for_service_with_payload_validation(
            root,
            context(root)?,
            &source,
            memo,
        ),
        None => v6_records::materialize_for_service(root, context(root)?, &source),
    };
    result.map_err(|_| unavailable())
}

fn verify_v5_source(
    durable: &DurableService<AeadBarrier>,
    root: &RecordStateRoot,
    state: &State,
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<(), Response> {
    use crate::state_records::{ObjectRef, RecordError, RecordReader};
    struct Checked<'a, G> {
        durable: &'a DurableService<AeadBarrier>,
        gate: RefCell<&'a mut G>,
    }
    impl<G: FnMut() -> Result<(), ServiceError>> RecordReader for Checked<'_, G> {
        fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
            (self.gate.borrow_mut())().map_err(|_| RecordError::Invalid)?;
            let bytes = records::DurableReader(self.durable).read_object(reference)?;
            (self.gate.borrow_mut())().map_err(|_| RecordError::Invalid)?;
            Ok(bytes)
        }
    }
    gate().map_err(storage_rejected)?;
    records::verify_received_record_graph(
        root,
        &Checked {
            durable,
            gate: RefCell::new(&mut *gate),
        },
        state,
    )?;
    gate().map_err(storage_rejected)
}

// Repair only objects selected by an exact-current authenticated local root.
// The complete received graph is independently authenticated first. Metadata
// absence or alteration is never repaired from a loose manifest; an existing
// bad physical object is rejected by the no-replace local barrier primitive.
fn repair_current_local_objects(
    durable: &mut DurableService<AeadBarrier>,
    selected: &LocalSelection,
    read: &CommittedNativeV6Read,
    codec: &ClusterStateCodec,
    store: &LocalV6BlobStage,
    gate: &mut impl FnMut() -> Result<(), ServiceError>,
) -> Result<(), Response> {
    use crate::ha_state::native_v6::NativeV6CodecError;
    let root = selected.native.as_ref().ok_or_else(unavailable)?;
    if root.identity().map_err(|_| unavailable())?.digest() != read.published().root_digest() {
        return Err(unavailable());
    }
    let shared = RefCell::new(gate);
    let mut original = || (shared.borrow_mut())().map_err(|_| NativeV6CodecError::Gate);
    let received = open_native_v6_ha_objects(
        codec,
        read.enrollment(),
        read.published(),
        store,
        context(root)?,
        read.deadline(),
        &mut original,
    )
    .map_err(|_| unavailable())?;
    if received.root_bytes() != selected.root_bytes.expose() {
        return Err(unavailable());
    }
    let session = native_blob_source::session(durable, selected.root_bytes.expose())
        .map_err(storage_rejected)?;
    received
        .visit_verified_objects(codec, store, &mut original, &mut |object| {
            let resource = v6_records::native_resource(object.domain(), object.reference());
            let previous = durable
                .get("system", &resource)
                .map_err(|_| NativeV6CodecError::Storage)?
                .ok_or(NativeV6CodecError::Storage)?;
            native_blob_source::validate_archive_slot(
                selected.root_bytes.expose(),
                previous.expose(),
                object.reference(),
            )
            .map_err(|_| NativeV6CodecError::Storage)?;
            let marker =
                native_blob_source::stage_verified_received(durable, &session, object, &mut || {
                    (shared.borrow_mut())()
                })
                .map_err(|_| NativeV6CodecError::Storage)?;
            if marker.expose() != previous.expose() {
                return Err(NativeV6CodecError::Storage);
            }
            (shared.borrow_mut())().map_err(|_| NativeV6CodecError::Gate)
        })
        .map_err(|_| unavailable())?;
    drop(session);
    selected
        .check(durable, selected.initial_generation)
        .map_err(storage_rejected)?;
    (shared.borrow_mut())().map_err(storage_rejected)
}

// The immutable source and its pure JSON-semantics memo share one install
// call. No source identity, generation, Actor or consensus proof is memoized.
struct LocalInstallSource<'a> {
    storage: NativeV6ObjectStorage<'a>,
    payload_validation: &'a RefCell<PagedPayloadValidationMemo>,
}

// A same-call borrow of the publisher's actual typed plan. It is DATA, not a
// source witness or Raft capability: the common installer still obtains its
// real process read, local selection, owner and every live gate. Neither a
// follower nor cold recovery constructs this optimization input.
#[derive(Clone, Copy)]
struct PublishedLocalPlan<'a> {
    plan: &'a v6_records::NativeRootMigrationPlan,
    installed: &'a State,
}

struct PublishedLocalInstallSource<'a> {
    prepared: PublishedLocalPlan<'a>,
    storage: NativeV6ObjectStorage<'a>,
}

impl PublishedLocalPlan<'_> {
    fn check_selection(
        &self,
        selected: &LocalSelection,
        read: &CommittedNativeV6Read,
    ) -> Result<(), Response> {
        live(read.deadline())?;
        let plan = self.plan;
        let previous = selected.native.as_ref().ok_or_else(unavailable)?;
        v6_records::validate_frontier(
            &plan.root,
            ReadContext {
                expected_identity: ReadIdentity::RecordsV6(read.published().root_digest()),
                cluster_id: &selected.source.cluster_id,
                replay_epoch: read.enrollment().epoch(),
                minimum_state_schema: selected.source.state_schema,
                maximum_state_schema: MAX_SUPPORTED_STATE_SCHEMA,
                reader_format: crate::state_record_root_v6::READER_FORMAT,
            },
        )
        .map_err(|_| unavailable())?;
        if plan.deadline.instant() != read.deadline().instant()
            || plan.source_generation != selected.initial_generation
            || plan.root.cluster_id != selected.source.cluster_id
            || plan.root.cluster_id != previous.cluster_id
            || plan.root.replay_epoch != selected.local_epoch
            || plan.root.replay_epoch != read.enrollment().epoch()
            || plan.root.identity().map_err(|_| unavailable())?.digest()
                != read.published().root_digest()
            || plan.root.reader_floor.native_kv2_format != 2
            || plan.root.encode().map_err(|_| unavailable())?.as_slice() != plan.bytes.as_slice()
            || plan.conditions.len() != 3
            || self.installed.cluster_id != plan.root.cluster_id
            || self.installed.replay_epoch != plan.root.replay_epoch
        {
            return Err(unavailable());
        }
        let installed_auth =
            owner_store::serialize_owner(&self.installed.auth).map_err(|_| unavailable())?;
        let planned_auth =
            owner_store::serialize_owner(&plan.candidate.auth).map_err(|_| unavailable())?;
        if installed_auth.as_slice() != planned_auth.as_slice() {
            return Err(unavailable());
        }
        // The three original plan predicates must be the exact current local
        // selection. The common installer additionally retains/checks its
        // actual HA cursor as the fourth predicate on every local journal CAS.
        for (condition, (resource, expected)) in plan.conditions.iter().zip([
            ("state", Some(&selected.root_bytes)),
            (ACTIVE_CURSOR_RESOURCE, selected.active_bytes.as_ref()),
            (ACTIVE_SOURCE_ROOT_RESOURCE, selected.source_bytes.as_ref()),
        ]) {
            if condition.resource != resource
                || condition.expected.as_ref().map(Secret::expose) != expected.map(Secret::expose)
            {
                return Err(unavailable());
            }
        }
        live(read.deadline())
    }
}

impl Service {
    /// Receive a committed target during serialized process-owned catch-up.
    /// This local installation grants no business permission or response ACK.
    pub(super) fn sync_native_v6_from_ha(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: CommittedNativeV6Read,
    ) -> Result<ha_received::HaSyncProgress, Response> {
        self.sync_native_v6_from_ha_checked(ha, committed, &mut |_| Ok(()))
    }

    /// Request owners can retain their original principal/clock check through
    /// every effect. The authenticated source Auth is retained even if B changes it.
    pub(super) fn sync_native_v6_from_ha_checked(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: CommittedNativeV6Read,
        original_actor: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<ha_received::HaSyncProgress, Response> {
        let payload_validation = RefCell::new(PagedPayloadValidationMemo::default());
        self.sync_native_v6_from_ha_with_payload_validation(
            ha,
            committed,
            original_actor,
            &payload_validation,
        )
    }

    // A caller may retain only deterministic payload semantics from earlier
    // traversals in this same request. The received and both local graphs still
    // reopen every real object and validate all current authority and digests.
    pub(super) fn sync_native_v6_from_ha_with_payload_validation(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: CommittedNativeV6Read,
        original_actor: &mut impl FnMut(&AuthState) -> Result<(), Response>,
        payload_validation: &RefCell<PagedPayloadValidationMemo>,
    ) -> Result<ha_received::HaSyncProgress, Response> {
        self.sync_native_v6_from_ha_with_local_plan(
            ha,
            committed,
            original_actor,
            payload_validation,
            None,
        )
    }

    /// A successful real publisher may retain its already authenticated typed
    /// plan through its own local installation. This never accepts a serialized
    /// proof and never takes the shortcut for initial migration or cold catch-up.
    pub(super) fn sync_published_native_v6_local_plan_checked(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: CommittedNativeV6Read,
        plan: &v6_records::NativeRootMigrationPlan,
        installed: &State,
        payload_validation: &RefCell<PagedPayloadValidationMemo>,
        original_actor: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<ha_received::HaSyncProgress, Response> {
        if self.native_root.is_none() {
            return Err(unavailable());
        }
        self.sync_native_v6_from_ha_with_local_plan(
            ha,
            committed,
            original_actor,
            payload_validation,
            Some(PublishedLocalPlan { plan, installed }),
        )
    }

    fn sync_native_v6_from_ha_with_local_plan(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: CommittedNativeV6Read,
        original_actor: &mut impl FnMut(&AuthState) -> Result<(), Response>,
        payload_validation: &RefCell<PagedPayloadValidationMemo>,
        published_plan: Option<PublishedLocalPlan<'_>>,
    ) -> Result<ha_received::HaSyncProgress, Response> {
        let failure = NativeV6FailureObservation::start(
            "sync_migration_source",
            committed.deadline().instant(),
        );
        live(committed.deadline())?;
        // This historical installation publishes no application activation.
        // Every failure after its root CAS requires a cold reconciliation;
        // no caller may release the intermediate V5 owner as a current read.
        let predecessor_installed =
            self.sync_native_v6_migration_source(ha, &committed, original_actor)?;
        let result = (|| {
            // A successful retained-V5 installation is a completed phase,
            // not a failed native install to replay. Before beginning the V6
            // phase, obtain a new actual quorum read of that EXACT selection.
            // Keep the original operation deadline and Actor; the old witness
            // must still verify. Every refusal remains inside the existing
            // post-predecessor recovery fence below.
            let committed = if predecessor_installed {
                failure.step("sync_predecessor_read_boundary");
                original_actor(&self.state.as_ref().ok_or_else(unavailable)?.auth)?;
                let process = ha.lock_for_request().map_err(|_| unavailable())?;
                process
                    .recapture_native_v6_same_selection(&committed)
                    .map_err(|_| unavailable())?
            } else {
                committed
            };
            failure.step("sync_after_migration");
            self.sync_native_v6_after_migration_checked(
                ha,
                committed,
                original_actor,
                payload_validation,
                published_plan,
            )
        })();
        if predecessor_installed && result.is_err() {
            self.recovery_required = true;
            self.ha_activation = None;
            self.ha_read_cache = None;
        }
        if result.is_ok() {
            failure.complete();
        }
        result
    }

    // A same-content root can still belong to an older publication. Only an
    // exact-current local cursor may enter the read-only witness continuation;
    // a required local installation must retain the original one-shot result.
    fn native_v6_same_root_continuation_is_current(
        &self,
        committed: &CommittedNativeV6Read,
    ) -> Result<bool, Response> {
        if self.current_state_identity()?
            != StateIdentity::RecordsV6(committed.published().root_digest())
        {
            return Ok(false);
        }
        let bytes = self
            .durable
            .as_ref()
            .ok_or_else(unavailable)?
            .get("system", HA_CURSOR_RESOURCE)
            .map_err(storage_rejected)?
            .ok_or_else(unavailable)?;
        Ok(NativeHaCursor::decode(bytes.expose())?
            .matches_current(committed)
            .is_ok())
    }

    fn sync_native_v6_after_migration_checked(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: CommittedNativeV6Read,
        original_actor: &mut impl FnMut(&AuthState) -> Result<(), Response>,
        payload_validation: &RefCell<PagedPayloadValidationMemo>,
        published_plan: Option<PublishedLocalPlan<'_>>,
    ) -> Result<ha_received::HaSyncProgress, Response> {
        // Only an already-current warm local root may continue one read-only
        // phase after a concurrent apply invalidated its witness. Capture the
        // original local owner and journal generation before the first pass;
        // a repair/publication, changed environment or recovery fence cannot
        // be adopted by this continuation. Publisher and cold paths stay exact.
        let continuation = if published_plan.is_none()
            && self.native_v6_same_root_continuation_is_current(&committed)?
        {
            let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
            Some((
                LocalHaEnvironment::capture(self, ha, &key, committed.deadline())?,
                self.durable.as_ref().ok_or_else(unavailable)?.generation(),
                self.current_state_identity()?,
            ))
        } else {
            None
        };
        let witness_refused = Cell::new(false);
        let result = self.sync_native_v6_after_migration_attempt(
            ha,
            &committed,
            original_actor,
            payload_validation,
            published_plan,
            &witness_refused,
        );
        let Err(original_error) = result else {
            return result;
        };
        let Some((environment, generation, identity)) = continuation else {
            return Err(original_error);
        };
        if !witness_refused.get()
            || environment.check(self).is_err()
            || self.current_state_identity().ok() != Some(identity)
            || self.durable.as_ref().is_none_or(|durable| {
                durable.generation() != generation || durable.recovery_required()
            })
        {
            return Err(original_error);
        }
        let fresh = {
            let process = ha.lock_for_request().map_err(|_| unavailable())?;
            match process.recapture_native_v6_same_root_after_progress(&committed) {
                Ok(fresh) => fresh,
                Err(_) => return Err(original_error),
            }
        };
        environment.check(self)?;
        // A new actual ReadIndex of the exact same published graph, bounded
        // by the FIRST witness, precedes this one final local pass. No HTTP
        // callback, use consumption, business mutation or audit is replayed.
        self.sync_native_v6_after_migration_attempt(
            ha,
            &fresh,
            original_actor,
            payload_validation,
            None,
            &Cell::new(false),
        )
    }

    fn sync_native_v6_after_migration_attempt(
        &mut self,
        ha: &Arc<Mutex<HaProcess>>,
        committed: &CommittedNativeV6Read,
        original_actor: &mut impl FnMut(&AuthState) -> Result<(), Response>,
        payload_validation: &RefCell<PagedPayloadValidationMemo>,
        published_plan: Option<PublishedLocalPlan<'_>>,
        witness_refused: &Cell<bool>,
    ) -> Result<ha_received::HaSyncProgress, Response> {
        let deadline = committed.deadline();
        let failure = NativeV6FailureObservation::start("sync_environment", deadline.instant());
        live(deadline)?;
        let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
        let environment = LocalHaEnvironment::capture(self, ha, &key, deadline)?;
        let actual = self.state.as_ref().ok_or_else(unavailable)?.clone();
        root_namespace_only(&actual)?;
        let source_auth = actual.auth.clone();
        original_actor(&source_auth)?;
        let old_identity = self.current_state_identity()?;
        failure.step("sync_process_witness");
        let process = ha.lock_for_request().map_err(|_| unavailable())?;
        if !process.native_v6_enabled() || process.cluster_id() != actual.cluster_id {
            return Err(unavailable());
        }
        process
            .verify_native_v6_committed_read(committed)
            .map_err(|_| {
                witness_refused.set(true);
                unavailable()
            })?;
        // Raft already committed any higher epoch. Allocate the new activation
        // before local publication; an entropy failure fences that authority.
        let next_activation =
            self.prepare_epoch_activation(committed.enrollment().epoch(), true)?;
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let root_committed = Cell::new(false);
        let denial = RefCell::new(None);
        let result = (|| -> Result<State, Response> {
            failure.step("sync_local_selection");
            let selected = LocalSelection::read(&mut durable, committed)?;
            if selected.source.cluster_id != actual.cluster_id
                || selected.local_epoch != actual.replay_epoch
                || match selected.native.as_ref() {
                    Some(root) => {
                        root.identity().map_err(|_| unavailable())? != old_identity
                            || self
                                .native_root
                                .as_ref()
                                .and_then(|root| root.identity().ok())
                                != Some(old_identity)
                            || self.record_root.is_some()
                    }
                    None => {
                        selected.source.identity().map_err(|_| unavailable())? != old_identity
                            || self
                                .record_root
                                .as_ref()
                                .and_then(|root| root.identity().ok())
                                != Some(old_identity)
                            || self.native_root.is_some()
                    }
                }
            {
                return Err(unavailable());
            }
            if let Some(prepared) = published_plan {
                prepared.check_selection(&selected, committed)?;
            }
            // This scope owns no mutable Service alias. The guard stays borrowed
            // by every gate and by the inner installer until the result returns.
            // A refusal here still follows the outer durable restore/fence path.
            failure.step("sync_local_guard");
            let borrowed = BorrowedLocalHaService::capture(self, &environment, old_identity)?;
            #[cfg(feature = "private-ha-forward-diagnostic")]
            let gate_metrics = NativeHaGateMetrics::new();
            let original = RefCell::new(|| -> Result<(), ServiceError> {
                let check = (|| {
                    // The same real seal-file check remains at every old gate.
                    // The borrowed in-memory fields cannot change in this scope.
                    #[cfg(feature = "private-ha-forward-diagnostic")]
                    let environment_result = gate_metrics.observe(0, || borrowed.check_seal());
                    #[cfg(not(feature = "private-ha-forward-diagnostic"))]
                    let environment_result = borrowed.check_seal();
                    environment_result?;
                    #[cfg(feature = "private-ha-forward-diagnostic")]
                    let actor_result = gate_metrics.observe(2, || original_actor(&source_auth));
                    #[cfg(not(feature = "private-ha-forward-diagnostic"))]
                    let actor_result = original_actor(&source_auth);
                    actor_result?;
                    #[cfg(feature = "private-ha-forward-diagnostic")]
                    let witness_result = gate_metrics
                        .observe(3, || process.verify_native_v6_committed_read(committed));
                    #[cfg(not(feature = "private-ha-forward-diagnostic"))]
                    let witness_result = process.verify_native_v6_committed_read(committed);
                    witness_result.map_err(|_| {
                        witness_refused.set(true);
                        unavailable()
                    })?;
                    live(deadline)
                })();
                check.map_err(|error| {
                    if denial.borrow().is_none() {
                        *denial.borrow_mut() = Some(error);
                    }
                    ServiceError::BarrierFailure
                })
            });
            let mut gate = || (original.borrow_mut())();
            gate().map_err(storage_rejected)?;
            if selected.native.is_none() {
                failure.step("sync_v5_source");
                verify_v5_source(&durable, &selected.source, &actual, &mut gate)?;
                selected
                    .check(&mut durable, selected.initial_generation)
                    .map_err(storage_rejected)?;
            }
            // An exact-current warm root reopens its typed metadata and every
            // real payload locator. Selected point reads retain AEAD/address
            // authentication; cold loads and new-root installs remain full.
            if old_identity == StateIdentity::RecordsV6(committed.published().root_digest())
                && NativeHaCursor::decode(
                    selected.ha_bytes.as_ref().ok_or_else(unavailable)?.expose(),
                )?
                .matches_current(committed)
                .is_ok()
            {
                let root = selected.native.as_ref().ok_or_else(unavailable)?;
                NativeHaCursor::decode(
                    selected.ha_bytes.as_ref().ok_or_else(unavailable)?.expose(),
                )?
                .matches_current(committed)?;
                failure.step("sync_current_local_graph");
                let (metadata, native) = match read::materialize_current_local_request(
                    &mut durable,
                    root,
                    deadline,
                    &mut gate,
                ) {
                    Ok(local) => local,
                    Err(_) => {
                        failure.step("sync_current_local_repair");
                        // Repair remains under the original witness/Actor. Its
                        // actual no-replace readback distinguishes a missing
                        // file from a corrupt existing one; it never masks the latter.
                        process
                            .with_native_v6_source(committed, |codec, store| {
                                repair_current_local_objects(
                                    &mut durable,
                                    &selected,
                                    committed,
                                    codec,
                                    store,
                                    &mut gate,
                                )
                            })
                            .map_err(|_| unavailable())??;
                        failure.step("sync_current_local_graph_after_repair");
                        materialize_local(&mut durable, root, deadline, &mut gate)?
                    }
                };
                failure.step("sync_current_local_finish");
                Self::check_native_installed(&actual, &metadata, &native, root, deadline)?;
                selected
                    .check(&mut durable, selected.initial_generation)
                    .map_err(storage_rejected)?;
                gate().map_err(storage_rejected)?;
                return Ok(actual);
            }
            failure.step("sync_changed_root_install");
            process
                .with_native_v6_source(committed, |codec, store| {
                    borrowed
                        .service()
                        .install_native_v6_replica_inner_with_local_plan(
                            &mut durable,
                            &selected,
                            committed,
                            LocalInstallSource {
                                storage: NativeV6ObjectStorage { codec, store },
                                payload_validation,
                            },
                            published_plan,
                            &mut gate,
                            &root_committed,
                        )
                })
                .map_err(|_| unavailable())?
        })();
        let uncertain = root_committed.get() && result.is_err() || durable.recovery_required();
        self.durable = Some(durable);
        self.ha_read_cache = None;
        let installed = match result {
            Ok(installed) => installed,
            Err(error) => {
                self.ha_activation = None;
                if uncertain {
                    self.recovery_required = true;
                    return Err(Response::error(
                        503,
                        "native V6 HA local publication requires cold reconciliation",
                    ));
                }
                return Err(denial.into_inner().unwrap_or(error));
            }
        };
        failure.step("sync_final_environment");
        let final_check = (|| {
            environment.check(self)?;
            if self.current_state_identity()? != old_identity {
                return Err(unavailable());
            }
            original_actor(&source_auth)?;
            process
                .verify_native_v6_committed_read(committed)
                .map_err(|_| unavailable())?;
            let root_bytes = self
                .durable
                .as_ref()
                .ok_or_else(unavailable)?
                .get("system", "state")
                .map_err(storage_rejected)?
                .ok_or_else(unavailable)?;
            let root = RecordStateRootV6::decode(root_bytes.expose()).map_err(|_| unavailable())?;
            if root.identity().map_err(|_| unavailable())?.digest()
                != committed.published().root_digest()
            {
                return Err(unavailable());
            }
            live(deadline)?;
            Ok(root)
        })();
        let root = final_check.inspect_err(|_| {
            if root_committed.get() {
                self.recovery_required = true;
            }
            self.ha_activation = None;
        })?;
        failure.step("sync_publish_local_state");
        self.state = Some(installed);
        self.state_digest = Some(committed.published().root_digest());
        self.record_root = None;
        self.native_root = Some(root);
        self.record_writes_since_gc = 0;
        self.install_epoch_activation(next_activation);
        live(deadline).inspect_err(|_| {
            self.recovery_required = true;
            self.ha_activation = None;
        })?;
        failure.complete();
        Ok(ha_received::HaSyncProgress::Current)
    }

    // Keep the four validated outputs together at this single install boundary.
    #[allow(clippy::type_complexity)]
    fn stage_published_native_v6_local_plan(
        &self,
        durable: &mut DurableService<AeadBarrier>,
        selected: &LocalSelection,
        read: &CommittedNativeV6Read,
        input: PublishedLocalInstallSource<'_>,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<
        (
            RecordStateRootV6,
            Zeroizing<Vec<u8>>,
            State,
            Vec<(String, Option<Secret>)>,
        ),
        Response,
    > {
        let PublishedLocalInstallSource { prepared, storage } = input;
        let NativeV6ObjectStorage { codec, store } = storage;
        gate().map_err(storage_rejected)?;
        prepared.check_selection(selected, read)?;
        selected
            .check(durable, selected.initial_generation)
            .map_err(storage_rejected)?;
        let plan = prepared.plan;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let cipher_phase = NativeHaPhaseTimer::start(
            "install_published_plan_cipher_graph",
            read.deadline().instant(),
            selected.initial_generation,
            read.published().intent().object_count,
            read.published().intent().ciphertext_bytes,
        );
        // Reopen the ACTUAL committed cipher directory and its authenticated
        // small root under the same process/Actor gate. The original plan is
        // not evidence that current HA files remain present or unchanged.
        let cipher = codec
            .open_native_v6_committed_read(read.enrollment(), read.published(), store, &mut || {
                gate().map_err(|_| crate::ha_state::native_v6::NativeV6CodecError::Gate)
            })
            .map_err(|_| unavailable())?;
        if cipher.root_bytes() != plan.bytes.as_slice()
            || cipher.root().identity().map_err(|_| unavailable())?
                != plan.root.identity().map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        let physical = store
            .reopen_root_closure(read.published(), &mut || {
                gate().map_err(|_| heptabao_raft_runtime::LocalV6BlobError::CorruptOrChanged)
            })
            .map_err(|_| unavailable())?;
        gate().map_err(storage_rejected)?;
        if physical.as_slice() != cipher.references() {
            return Err(unavailable());
        }
        #[cfg(feature = "private-ha-forward-diagnostic")]
        cipher_phase.finish(true);
        let owner_bytes = plan
            .root
            .owners
            .iter()
            .try_fold(0u64, |sum, owner| sum.checked_add(owner.owner.total_bytes))
            .ok_or_else(unavailable)?;
        if owner_bytes > self.opaque_owner_limit() as u64 {
            return Err(Response::error(
                507,
                "native opaque owner capacity exhausted",
            ));
        }
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "install_published_plan_local_objects",
            read.deadline().instant(),
            selected.initial_generation,
            plan.objects.len() as u64,
            plan.root.kv2.iter().fold(0u64, |sum, graph| {
                sum.saturating_add(graph.logical_payload_bytes)
            }),
        );
        // These are the original typed plaintext objects, held immutably from
        // preparation through the real Raft publication. They cannot substitute
        // for either store's physical proof: local HBA1 encryption, actual-fd
        // no-replace/fsync, readback and old-root session are still performed.
        let session = native_blob_source::session(durable, selected.root_bytes.expose())
            .map_err(storage_rejected)?;
        let mut pending = plan.objects.iter().peekable();
        let mut locators = Vec::new();
        while pending.peek().is_some() {
            gate().map_err(storage_rejected)?;
            selected
                .check(durable, selected.initial_generation)
                .map_err(storage_rejected)?;
            let mut batch = Vec::new();
            let mut ciphertext_bytes = 0usize;
            while let Some(&((domain, _), object)) = pending.peek() {
                let next_bytes = ciphertext_bytes
                    .checked_add(object.bytes().len())
                    .and_then(|bytes| bytes.checked_add(32))
                    .ok_or_else(unavailable)?;
                if batch.len() == heptabao_filesystem_guard::MAX_IMMUTABLE_BATCH_OBJECTS
                    || next_bytes > ImmutableSourceSession::MAX_BATCH_CIPHERTEXT_BYTES
                {
                    break;
                }
                ciphertext_bytes = next_bytes;
                batch.push((domain, object.as_ref()));
                pending.next();
            }
            if batch.is_empty() {
                return Err(unavailable());
            }
            let markers = native_blob_source::stage_batch(durable, &session, &batch, gate)
                .map_err(storage_rejected)?;
            if markers.len() != batch.len() {
                return Err(unavailable());
            }
            for ((domain, object), marker) in batch.into_iter().zip(markers) {
                gate().map_err(storage_rejected)?;
                let resource = v6_records::native_resource(domain, object.reference());
                match durable.get("system", &resource).map_err(storage_rejected)? {
                    Some(actual) if actual.expose() == marker.expose() => {}
                    Some(actual) if actual.expose() == object.bytes() => {
                        locators.push((resource, Some(marker)));
                    }
                    Some(_) => return Err(unavailable()),
                    None => locators.push((resource, Some(marker))),
                }
                gate().map_err(storage_rejected)?;
            }
        }
        drop(session);
        // Keep the same cipher reader/store borrowed through all local fsyncs.
        // A full physical closure reopen after them must select exactly the
        // same references; the gate keeps its original process read/deadline.
        let after = store
            .reopen_root_closure(read.published(), &mut || {
                gate().map_err(|_| heptabao_raft_runtime::LocalV6BlobError::CorruptOrChanged)
            })
            .map_err(|_| unavailable())?;
        if after != physical || cipher.root_bytes() != plan.bytes.as_slice() {
            return Err(unavailable());
        }
        selected
            .check(durable, selected.initial_generation)
            .map_err(storage_rejected)?;
        gate().map_err(storage_rejected)?;
        prepared.check_selection(selected, read)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        // The common installer will freshly authenticate the complete local
        // closure BEFORE and AFTER the root CAS and compare it with this exact
        // typed candidate. Unchanged old leaves are not assumed healthy.
        Ok((
            plan.root.clone(),
            Zeroizing::new(plan.bytes.to_vec()),
            prepared.installed.clone(),
            locators,
        ))
    }

    fn install_native_v6_replica_inner_with_payload_validation(
        &self,
        durable: &mut DurableService<AeadBarrier>,
        selected: &LocalSelection,
        read: &CommittedNativeV6Read,
        source: LocalInstallSource<'_>,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
        root_committed: &Cell<bool>,
    ) -> Result<State, Response> {
        self.install_native_v6_replica_inner_with_local_plan(
            durable,
            selected,
            read,
            source,
            None,
            gate,
            root_committed,
        )
    }

    // Keep source, proposal, original gate and root-CAS observation explicit.
    #[allow(clippy::too_many_arguments)]
    fn install_native_v6_replica_inner_with_local_plan(
        &self,
        durable: &mut DurableService<AeadBarrier>,
        selected: &LocalSelection,
        read: &CommittedNativeV6Read,
        source: LocalInstallSource<'_>,
        published_plan: Option<PublishedLocalPlan<'_>>,
        gate: &mut impl FnMut() -> Result<(), ServiceError>,
        root_committed: &Cell<bool>,
    ) -> Result<State, Response> {
        let LocalInstallSource {
            storage,
            payload_validation,
        } = source;
        let NativeV6ObjectStorage { codec, store } = storage;
        let deadline = read.deadline();
        let failure =
            NativeV6FailureObservation::start("install_received_graph", deadline.instant());
        let shared_gate = RefCell::new(gate);
        // Received/pre-CAS/post-CAS readers capture their own real source and
        // generation. Only the exact authenticated bytes' JSON semantics may
        // also have been checked during this same request or cold recovery call.
        let codec_gate = || {
            (shared_gate.borrow_mut())()
                .map_err(|_| crate::ha_state::native_v6::NativeV6CodecError::Storage)
        };
        let (root, root_bytes, installed, locators) = if let Some(prepared) = published_plan {
            failure.step("install_published_local_plan");
            self.stage_published_native_v6_local_plan(
                durable,
                selected,
                read,
                PublishedLocalInstallSource {
                    prepared,
                    storage: NativeV6ObjectStorage { codec, store },
                },
                &mut || (shared_gate.borrow_mut())(),
            )?
        } else {
            #[cfg(feature = "private-ha-forward-diagnostic")]
            let phase = NativeHaPhaseTimer::start(
                "install_received_graph",
                deadline.instant(),
                selected.initial_generation,
                read.published().intent().object_count,
                read.published().intent().ciphertext_bytes,
            );
            // The codec obtains the canonical root from the committed small seal.
            // Its closure/full typed reader rejects missing, extra and wrong-domain data.
            let received = open_native_v6_ha_objects_with_payload_validation(
                NativeV6ObjectStorage { codec, store },
                read.enrollment(),
                read.published(),
                ReadContext {
                    expected_identity: ReadIdentity::RecordsV6(read.published().root_digest()),
                    cluster_id: &selected.source.cluster_id,
                    replay_epoch: read.enrollment().epoch(),
                    minimum_state_schema: selected.source.state_schema,
                    maximum_state_schema: MAX_SUPPORTED_STATE_SCHEMA,
                    reader_format: crate::state_record_root_v6::READER_FORMAT,
                },
                deadline,
                &mut || codec_gate(),
                payload_validation,
            )
            .map_err(|_| unavailable())?;
            #[cfg(feature = "private-ha-forward-diagnostic")]
            phase.finish(true);
            failure.step("install_root_binding");
            let root = received.root().clone();
            let root_bytes = Zeroizing::new(received.root_bytes().to_vec());
            if root.reader_floor.native_kv2_format != 2
                || root.replay_epoch != read.enrollment().epoch()
            {
                return Err(unavailable());
            }
            let owner_bytes = root
                .owners
                .iter()
                .try_fold(0u64, |sum, owner| sum.checked_add(owner.owner.total_bytes))
                .ok_or_else(unavailable)?;
            if owner_bytes > self.opaque_owner_limit() as u64 {
                return Err(Response::error(
                    507,
                    "native opaque owner capacity exhausted",
                ));
            }
            let epoch_scope =
                (selected.local_epoch < root.replay_epoch).then_some(EpochInstallScope {
                    selected,
                    committed: read,
                });
            #[cfg(feature = "private-ha-forward-diagnostic")]
            let phase = NativeHaPhaseTimer::start(
                "install_local_objects",
                deadline.instant(),
                selected.initial_generation,
                read.published().intent().object_count,
                read.published().intent().ciphertext_bytes,
            );
            failure.step("install_local_objects");
            let mut locators = Vec::new();
            let session = native_blob_source::session(durable, selected.root_bytes.expose())
                .map_err(storage_rejected)?;
            received
                .visit_verified_object_batches(codec, store, &mut || codec_gate(), &mut |objects| {
                    let markers =
                        native_blob_source::ha_local_stage::stage_verified_received_batch(
                            durable,
                            &session,
                            objects,
                            epoch_scope.as_ref(),
                            &mut || (shared_gate.borrow_mut())(),
                        )
                        .map_err(|_| crate::ha_state::native_v6::NativeV6CodecError::Storage)?;
                    if markers.len() != objects.len() {
                        return Err(crate::ha_state::native_v6::NativeV6CodecError::Storage);
                    }
                    for (object, marker) in objects.iter().zip(markers) {
                        codec_gate()?;
                        let resource =
                            v6_records::native_resource(object.domain(), object.reference());
                        match durable
                            .get("system", &resource)
                            .map_err(|_| crate::ha_state::native_v6::NativeV6CodecError::Storage)?
                        {
                            Some(actual) if actual.expose() == marker.expose() => {}
                            Some(actual) if actual.expose() == object.plaintext() => {
                                locators.push((resource, Some(marker)))
                            }
                            Some(_) => {
                                return Err(
                                    crate::ha_state::native_v6::NativeV6CodecError::Storage,
                                );
                            }
                            None => locators.push((resource, Some(marker))),
                        }
                        codec_gate()?;
                    }
                    codec_gate()
                })
                .map_err(|_| unavailable())?;
            #[cfg(feature = "private-ha-forward-diagnostic")]
            phase.finish(true);
            drop(session);
            failure.step("install_detached_metadata");
            let (mut installed, native, _) = received
                .into_detached_parts(&mut || codec_gate())
                .map_err(|_| unavailable())?;
            installed
                .engines
                .install_native_views(native)
                .map_err(Response::from_engine_error)?;
            (root, root_bytes, installed, locators)
        };
        let identity = root.identity().map_err(|_| unavailable())?;
        let epoch_scope = (selected.local_epoch < root.replay_epoch).then_some(EpochInstallScope {
            selected,
            committed: read,
        });
        root_namespace_only(&installed)?;
        if epoch_scope.is_some() {
            if let Some(current) = self.state.as_ref() {
                Self::validate_snapshot_protected_floor(current, &installed)?;
            }
            // A cold node has no warm State. Its authenticated old local
            // protected owners still supply the non-regression floor; missing
            // obsolete KV payloads need not be read, and no archived/new Auth
            // substitutes for that original protected source.
            if let Some(previous) = selected.native.as_ref() {
                let source =
                    native_blob_source::NativeSource::new_checked(durable, deadline, || {
                        (shared_gate.borrow_mut())()
                    })
                    .map_err(|_| unavailable())?;
                let (mut metadata, native) = v6_records::materialize_metadata_for_service(
                    previous,
                    context(previous)?,
                    &source,
                )
                .map_err(|_| unavailable())?;
                metadata
                    .engines
                    .install_native_views(native)
                    .map_err(Response::from_engine_error)?;
                root_namespace_only(&metadata)?;
                Self::validate_snapshot_protected_floor(&metadata, &installed)?;
            } else if self.state.is_none() {
                return Err(unavailable());
            }
        }
        root_namespace_only(&installed)?;
        let operation = format!(
            "native6-ha-install-{}",
            hex(&crypto::random::<16>().map_err(|_| unavailable())?)
        );
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "install_locator_batches",
            deadline.instant(),
            selected.initial_generation,
            read.published().intent().object_count,
            read.published().intent().ciphertext_bytes,
        );
        failure.step("install_locator_batches");
        let mut expected_generation = selected.initial_generation;
        for (batch_index, batch) in locators
            .chunks(heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
            .enumerate()
        {
            (shared_gate.borrow_mut())().map_err(storage_rejected)?;
            selected
                .check(durable, expected_generation)
                .map_err(storage_rejected)?;
            durable
                .apply_batch_conditionally_before_publish(
                    BatchPublication {
                        replay_epoch: selected.local_epoch,
                        principal: "heptabao-server".into(),
                        namespace: "system".into(),
                        request_id: format!("{operation}-locators-{batch_index}"),
                        authorization_digest: identity.digest(),
                        mutations: batch.to_vec(),
                    },
                    selected.conditions(),
                    &mut || (shared_gate.borrow_mut())(),
                )
                .map_err(storage_rejected)?;
            expected_generation = expected_generation.checked_add(1).ok_or_else(unavailable)?;
            selected
                .check(durable, expected_generation)
                .map_err(storage_rejected)?;
            (shared_gate.borrow_mut())().map_err(storage_rejected)?;
        }
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "install_pre_cas_local_graph",
            deadline.instant(),
            selected.initial_generation,
            read.published().intent().object_count,
            read.published().intent().ciphertext_bytes,
        );
        failure.step("install_pre_cas_graph");
        let (metadata, native) = materialize_local_with_payload_validation(
            durable,
            &root,
            deadline,
            &mut || (shared_gate.borrow_mut())(),
            Some(payload_validation),
        )?;
        Self::check_native_installed(&installed, &metadata, &native, &root, deadline)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        selected
            .check(durable, expected_generation)
            .map_err(storage_rejected)?;
        failure.step("install_prepare_root_cas");
        let publication_generation = expected_generation.checked_add(1).ok_or_else(unavailable)?;
        let cursor = match &selected.active {
            Some(cursor) => cursor.advance(&root, publication_generation)?,
            None => NativeActiveCursor::for_migration(
                &selected.source,
                selected.initial_generation,
                &root,
                publication_generation,
            )?,
        };
        let cursor_bytes = cursor.encode()?;
        let ha_bytes = NativeHaCursor::new(read, publication_generation)?.encode()?;
        let mut mutations = vec![
            (
                "state".into(),
                Some(Secret::new(root_bytes.to_vec()).map_err(storage_rejected)?),
            ),
            (
                ACTIVE_CURSOR_RESOURCE.into(),
                Some(Secret::new(cursor_bytes.to_vec()).map_err(storage_rejected)?),
            ),
            (
                HA_CURSOR_RESOURCE.into(),
                Some(Secret::new(ha_bytes.to_vec()).map_err(storage_rejected)?),
            ),
        ];
        if selected.active.is_none() {
            mutations.push((
                ACTIVE_SOURCE_ROOT_RESOURCE.into(),
                Some(selected.root_bytes.clone()),
            ));
        }
        (shared_gate.borrow_mut())().map_err(storage_rejected)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "install_local_root_cas",
            deadline.instant(),
            selected.initial_generation,
            read.published().intent().object_count,
            read.published().intent().ciphertext_bytes,
        );
        failure.step("install_local_root_cas");
        let publication = BatchPublication {
            replay_epoch: root.replay_epoch,
            principal: "heptabao-server".into(),
            namespace: "system".into(),
            request_id: format!("{operation}-root"),
            authorization_digest: identity.digest(),
            mutations,
        };
        if epoch_scope.is_some() {
            durable.publish_epoch_batch_conditionally_before_publish(
                expected_generation,
                selected.local_epoch,
                publication,
                selected.conditions(),
                &mut || (shared_gate.borrow_mut())(),
            )
        } else {
            durable.apply_batch_conditionally_before_publish(
                publication,
                selected.conditions(),
                &mut || (shared_gate.borrow_mut())(),
            )
        }
        .map_err(storage_rejected)?;
        failure.step("install_local_root_readback");
        root_committed.set(true);
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        (shared_gate.borrow_mut())().map_err(storage_rejected)?;
        durable.verify_live_ownership().map_err(storage_rejected)?;
        if durable.generation() != publication_generation
            || durable.replay_epoch() != root.replay_epoch
        {
            return Err(unavailable());
        }
        for (resource, expected) in [
            ("state", root_bytes.as_slice()),
            (ACTIVE_CURSOR_RESOURCE, cursor_bytes.as_slice()),
            (HA_CURSOR_RESOURCE, ha_bytes.as_slice()),
        ] {
            if durable
                .get("system", resource)
                .map_err(storage_rejected)?
                .ok_or_else(unavailable)?
                .expose()
                != expected
            {
                return Err(unavailable());
            }
            (shared_gate.borrow_mut())().map_err(storage_rejected)?;
        }
        let source = durable
            .get("system", ACTIVE_SOURCE_ROOT_RESOURCE)
            .map_err(storage_rejected)?
            .ok_or_else(unavailable)?;
        if source.expose()
            != selected
                .source
                .encode()
                .map_err(|_| unavailable())?
                .as_slice()
        {
            return Err(unavailable());
        }
        cursor.validate(&selected.source, &root, durable.generation())?;
        let observed = NativeHaCursor::decode(ha_bytes.as_slice())?;
        observed.matches_current(read)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "install_post_cas_local_graph",
            deadline.instant(),
            selected.initial_generation,
            read.published().intent().object_count,
            read.published().intent().ciphertext_bytes,
        );
        failure.step("install_post_cas_graph");
        let (metadata, native) = materialize_local_with_payload_validation(
            durable,
            &root,
            deadline,
            &mut || (shared_gate.borrow_mut())(),
            Some(payload_validation),
        )?;
        Self::check_native_installed(&installed, &metadata, &native, &root, deadline)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        (shared_gate.borrow_mut())().map_err(storage_rejected)?;
        failure.complete();
        Ok(installed)
    }
}

#[cfg(test)]
#[path = "service_native_v6_ha_install_tests.rs"]
mod tests;
