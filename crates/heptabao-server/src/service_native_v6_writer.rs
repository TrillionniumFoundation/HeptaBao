//! Opt-in, root-namespace single-node candidate writer. No HA or default admission.
use super::native_v6_reader::{
    ACTIVE_CURSOR_RESOURCE, ACTIVE_SOURCE_ROOT_RESOURCE, NativeActiveCursor,
};
use super::*;
use crate::state_records::RecordError;
use crate::v6_native_custody::OriginalDeadline;

// These affine values carry only a typed negative outcome. They never grant
// actor/resource publication, response payload delivery or a new time budget.
pub(super) struct NativeRequestBinding {
    fingerprint: String,
    clock: RequestClock,
    admission_started: std::time::Instant,
    deadline: OriginalDeadline,
    nonce: String,
    data_dir: std::path::PathBuf,
}
pub(super) struct NativeFailureNotice {
    fingerprint: String,
    clock: RequestClock,
    admission_started: std::time::Instant,
    deadline: OriginalDeadline,
    nonce: String,
    data_dir: std::path::PathBuf,
    source_identity: crate::state_record_root::StateIdentity,
    source_generation: u64,
    recovery_reference: String,
}
impl Service {
    pub(super) fn bind_native_request_failure(
        &mut self,
        fingerprint: &str,
        clock: Option<RequestClock>,
        admission_started: std::time::Instant,
        path: &str,
    ) {
        if self.native_root.is_none() && path != "sys/internal/native-v6/activate" {
            return;
        }
        let (Some(clock), Ok(deadline)) = (clock, OriginalDeadline::capture()) else {
            return;
        };
        if clock.started() != admission_started {
            return;
        }
        self.native_request_binding = Some(NativeRequestBinding {
            fingerprint: fingerprint.to_owned(),
            clock,
            admission_started,
            deadline,
            nonce: self.unseal_nonce.clone(),
            data_dir: self.data_dir.clone(),
        });
    }
    pub(super) fn retire_native_external_binding(
        &mut self,
        fingerprint: &str,
        clock: Option<RequestClock>,
    ) {
        let Some(clock) = clock else {
            return;
        };
        let matching = self.native_request_binding.as_ref().is_some_and(|binding| {
            binding.fingerprint == fingerprint
                && binding.clock.started() == clock.started()
                && binding.clock.admitted_at() == clock.admitted_at()
                && binding.admission_started == clock.started()
        });
        if matching {
            self.native_request_binding = None;
        }
    }

    fn capture_native_failure_notice(&mut self, error: &ServiceError) {
        let ServiceError::OutcomeUnknown { recovery_reference } = error else {
            return;
        };
        let Some(binding) = self.native_request_binding.as_ref() else {
            return;
        };
        let Ok(source_identity) = self.current_state_identity() else {
            return;
        };
        let Some(source_generation) = self.durable.as_ref().map(|durable| durable.generation())
        else {
            return;
        };
        self.native_failure_notice = Some(NativeFailureNotice {
            fingerprint: binding.fingerprint.clone(),
            clock: binding.clock,
            admission_started: binding.admission_started,
            deadline: binding.deadline,
            nonce: binding.nonce.clone(),
            data_dir: binding.data_dir.clone(),
            source_identity,
            source_generation,
            recovery_reference: recovery_reference.clone(),
        });
    }
    pub(super) fn take_native_failure_response(
        &mut self,
        fingerprint: &str,
        clock: Option<RequestClock>,
    ) -> Option<Response> {
        let notice = self.native_failure_notice.take()?;
        let binding = self.native_request_binding.as_ref()?;
        let clock = clock?;
        if !self.recovery_required
            || self.barrier_key.is_none()
            || notice.fingerprint != fingerprint
            || notice.fingerprint != binding.fingerprint
            || notice.clock.started() != clock.started()
            || notice.clock.admitted_at() != clock.admitted_at()
            || notice.admission_started != clock.started()
            || binding.admission_started != notice.admission_started
            || binding.deadline.instant() != notice.deadline.instant()
            || crate::request_deadline::current() != Some(notice.deadline.instant())
            || notice.nonce != self.unseal_nonce
            || notice.nonce != binding.nonce
            || notice.data_dir != self.data_dir
            || notice.data_dir != binding.data_dir
            || self.current_state_identity().ok().as_ref() != Some(&notice.source_identity)
            || self.durable.as_ref().map(|durable| durable.generation())
                != Some(notice.source_generation)
        {
            return None;
        }
        Some(Response {
            status: 503,
            body: json!({"errors":["native durable outcome unknown; reopen and reconcile; do not blindly retry"],"recovery_reference":notice.recovery_reference}),
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
        })
    }
}

fn rejected() -> Response {
    Response::error(503, "native V6 Service candidate publication rejected")
}
fn conditions_copy(
    conditions: &[heptabao_durable_service::PublicationCondition],
) -> Vec<heptabao_durable_service::PublicationCondition> {
    conditions
        .iter()
        .map(|condition| heptabao_durable_service::PublicationCondition {
            resource: condition.resource.clone(),
            expected: condition.expected.clone(),
        })
        .collect()
}

impl Service {
    pub fn configure_native_v6_candidate(&mut self) -> Result<(), String> {
        if self.native_candidate_profile.is_some() {
            return Err("native candidate already configured".into());
        }
        self.native_candidate_profile = Some(
            native_v6_reader::NativeCandidateProfile::capture(self)
                .map_err(|_| "native candidate requires sealed single-node file custody")?,
        );
        Ok(())
    }

    pub(super) fn require_native_root_candidate(&self, state: &State) -> Result<(), Response> {
        self.native_candidate_profile
            .as_ref()
            .ok_or_else(rejected)?
            .check_environment(self)?;
        if self.native_candidate_profile.is_none()
            || self.ha.is_some()
            || self.postgres_durable.is_some()
            || self.durable_profile.is_some()
            || self.openbao_wrapper_owner.is_some()
            || self.recovery_required
            || self.audit_failed
            || state.namespace_protected.is_some()
            || state
                .engines
                .v6_namespace_paths()
                .any(|path| !path.is_empty())
            || !state.namespaces.is_empty()
            || !state.namespace_leases.is_empty()
        {
            return Err(rejected());
        }
        Ok(())
    }

    pub(super) fn activate_native_v6_route(
        &mut self,
        admitted: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        if request.token_clock.is_none() {
            return Response::error(503, "trusted token clock is required");
        }
        if request.method != "POST"
            || !request.namespace.is_empty()
            || !request
                .body
                .as_object()
                .is_some_and(|object| object.is_empty())
            || self.native_root.is_some()
        {
            return rejected();
        }
        let Some(principal) = principal.filter(Principal::is_root) else {
            return Response::error(403, "root token required");
        };
        let deadline = match OriginalDeadline::capture() {
            Ok(d) => d,
            Err(_) => return rejected(),
        };
        let state = match self.state.as_ref() {
            Some(state) => state,
            None => return rejected(),
        };
        if let Err(error) = self.require_native_root_candidate(state) {
            return error;
        }
        // consumed_use was durably published by the ordinary authentication
        // prelude before this selector. Never replace that current source with
        // an earlier Auth snapshot or silently drop admitted Auth changes.
        let source_auth = match owner_store::serialize_owner(&state.auth) {
            Ok(bytes) => bytes,
            Err(_) => return rejected(),
        };
        let admitted_auth = match owner_store::serialize_owner(&admitted.auth) {
            Ok(bytes) => bytes,
            Err(_) => return rejected(),
        };
        if source_auth.as_slice() != admitted_auth.as_slice() {
            return rejected();
        }
        if deadline.check().is_err() {
            return rejected();
        }
        let plan = match self.prepare_native_root_migration_paged(&|| {
            deadline.check().map_err(|_| RecordError::Invalid)
        }) {
            Ok(plan) => plan,
            Err(error) => return error,
        };
        let Some(state) = self.state.as_ref().cloned() else {
            return rejected();
        };
        let mut authority = |auth: &AuthState| {
            deadline.check().map_err(|_| rejected())?;
            auth.authorize_request_parameters_observed(
                &principal,
                "",
                "POST",
                request.path,
                request.body,
                request.token_time()?,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
            deadline.check().map_err(|_| rejected())
        };
        match self.commit_native_root_plan(&state, plan, true, "migration", &mut authority) {
            Ok(installed) => {
                self.state = Some(installed);
                Response {
                    status: 204,
                    body: Value::Null,
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                }
            }
            Err(error) => error,
        }
    }

    // Uses the same actual durable conditional append primitive, request Actor
    // and captured deadline for every physical effect. It never recaptures time.
    pub(super) fn commit_native_root_plan(
        &mut self,
        state: &State,
        plan: v6_records::NativeRootMigrationPlan,
        migration: bool,
        purpose: &'static str,
        before_publish: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<State, Response> {
        let deadline = plan.deadline;
        let check = || deadline.check().map_err(|_| RecordError::Invalid);
        check().map_err(|_| rejected())?;
        self.require_native_root_candidate(state)?;
        let owner_bytes = plan
            .root
            .owners
            .iter()
            .try_fold(0u64, |sum, owner| sum.checked_add(owner.owner.total_bytes))
            .ok_or_else(|| Response::error(507, "native opaque owner capacity exhausted"))?;
        if owner_bytes > self.opaque_owner_limit() as u64 {
            return Err(Response::error(
                507,
                "native opaque owner capacity exhausted",
            ));
        }
        let actual_auth = self.state.as_ref().ok_or_else(rejected)?.auth.clone();
        before_publish(&actual_auth)?;
        let installed = self.install_prepared_native_candidate(&plan, before_publish)?;
        self.require_native_root_candidate(&installed)?;
        let identity = plan.root.identity().map_err(|_| rejected())?;
        before_publish(&actual_auth)?;
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        check().map_err(|_| rejected())?;
        if durable.generation() != plan.source_generation {
            return Err(rejected());
        }
        let current = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let (source, old_cursor) = if migration {
            let source = records::decode_root(current.expose())?.ok_or_else(rejected)?;
            if self.native_root.is_some()
                || self
                    .record_root
                    .as_ref()
                    .ok_or_else(rejected)?
                    .encode()
                    .map_err(|_| rejected())?
                    .as_slice()
                    != current.expose()
                || plan.conditions.len() != 2
                || plan.conditions[0]
                    .expected
                    .as_ref()
                    .is_none_or(|bytes| bytes.expose() != current.expose())
                || durable
                    .get("system", ACTIVE_CURSOR_RESOURCE)
                    .map_err(|_| rejected())?
                    .is_some()
                || durable
                    .get("system", ACTIVE_SOURCE_ROOT_RESOURCE)
                    .map_err(|_| rejected())?
                    .is_some()
            {
                return Err(rejected());
            }
            (source, None)
        } else {
            let source_bytes = durable
                .get("system", ACTIVE_SOURCE_ROOT_RESOURCE)
                .map_err(|_| rejected())?
                .ok_or_else(rejected)?;
            let source = records::decode_root(source_bytes.expose())?.ok_or_else(rejected)?;
            let cursor_bytes = durable
                .get("system", ACTIVE_CURSOR_RESOURCE)
                .map_err(|_| rejected())?
                .ok_or_else(rejected)?;
            let cursor = NativeActiveCursor::decode(cursor_bytes.expose())?;
            let old = self.native_root.as_ref().ok_or_else(rejected)?;
            cursor.validate(&source, old, durable.generation())?;
            if old.encode().map_err(|_| rejected())?.as_slice() != current.expose()
                || plan.conditions.len() != 3
            {
                return Err(rejected());
            }
            (source, Some(cursor))
        };
        let conditions = if migration {
            vec![
                heptabao_durable_service::PublicationCondition {
                    resource: "state".into(),
                    expected: Some(current.clone()),
                },
                heptabao_durable_service::PublicationCondition {
                    resource: ACTIVE_CURSOR_RESOURCE.into(),
                    expected: None,
                },
                heptabao_durable_service::PublicationCondition {
                    resource: ACTIVE_SOURCE_ROOT_RESOURCE.into(),
                    expected: None,
                },
            ]
        } else {
            plan.conditions
        };
        // Immutable source objects are retained. No V5 collector is used once active.
        let operation = format!(
            "native6-{purpose}-{}",
            hex(&crypto::random::<16>().map_err(|_| rejected())?)
        );
        let retained_source = source.encode().map_err(|_| rejected())?;
        let mut root_committed = false;
        let result = {
            let mut gate = || {
                check().map_err(|_| ServiceError::BarrierFailure)?;
                before_publish(&actual_auth).map_err(|_| ServiceError::BarrierFailure)?;
                check().map_err(|_| ServiceError::BarrierFailure)
            };
            (|| -> Result<(), ServiceError> {
                let mut missing = Vec::new();
                let blob_session = super::native_blob_source::session(durable, current.expose())?;
                for ((domain, _), object) in &plan.objects {
                    gate()?;
                    let resource = v6_records::native_resource(domain, object.reference());
                    let marker = super::native_blob_source::stage(
                        durable,
                        &blob_session,
                        domain,
                        object,
                        &mut gate,
                    )?;
                    gate()?;
                    match durable.get("system", &resource)? {
                        Some(value) if value.expose() == marker.expose() => {}
                        Some(value) if migration && value.expose() == object.bytes() => {
                            missing.push((resource, marker))
                        }
                        Some(_) => return Err(ServiceError::CorruptState),
                        None => missing.push((resource, marker)),
                    }
                }
                // All ciphertext was read back under the original source session.
                // Do not reuse that generation-bound session after any journal
                // append. A large migration may register unreachable locators
                // in bounded batches while preserving the exact old root,
                // cursor and retained-source conditions on every append.
                drop(blob_session);
                let root_slots = if migration { 3 } else { 2 };
                let mut mutations = missing
                    .into_iter()
                    .map(|(resource, marker)| (resource, Some(marker)))
                    .collect::<Vec<_>>();
                if mutations.len()
                    .checked_add(root_slots)
                    .is_none_or(|count| count > heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
                {
                    let mut staged = std::mem::take(&mut mutations).into_iter();
                    let mut batch_index = 0usize;
                    loop {
                        let batch: Vec<_> = staged
                            .by_ref()
                            .take(heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
                            .collect();
                        if batch.is_empty() {
                            break;
                        }
                        gate()?;
                        durable.apply_batch_conditionally_before_publish(
                            heptabao_durable_service::BatchPublication {
                                replay_epoch: plan.root.replay_epoch,
                                principal: "heptabao-server".into(),
                                namespace: "system".into(),
                                request_id: format!("{operation}-locators-{batch_index}"),
                                authorization_digest: identity.digest(),
                                mutations: batch,
                            },
                            conditions_copy(&conditions),
                            &mut gate,
                        )?;
                        gate()?;
                        batch_index += 1;
                    }
                    // Reopen every candidate object through a fresh source
                    // session at the actual new generation. The typed closure
                    // must authenticate from durable bytes before the old root
                    // can be replaced; staged memory is not recovery evidence.
                    v6_records::verify_durable_native_candidate(
                        &plan.root, durable, deadline, &mut gate,
                    )
                    .map_err(|_| ServiceError::CorruptState)?;
                    gate()?;
                }
                gate()?;
                let publication_generation = durable
                    .generation()
                    .checked_add(1)
                    .ok_or(ServiceError::GenerationOverflow)?;
                let cursor = match old_cursor {
                    Some(cursor) => cursor.advance(&plan.root, publication_generation),
                    None => NativeActiveCursor::for_migration(
                        &source,
                        plan.source_generation,
                        &plan.root,
                        publication_generation,
                    ),
                }
                .map_err(|_| ServiceError::CorruptState)?;
                let cursor_bytes = cursor.encode().map_err(|_| ServiceError::CorruptState)?;
                mutations.extend(vec![
                    ("state".into(), Some(Secret::new(plan.bytes.to_vec())?)),
                    (
                        ACTIVE_CURSOR_RESOURCE.into(),
                        Some(Secret::new(cursor_bytes.to_vec())?),
                    ),
                ]);
                if migration {
                    mutations.push((
                        ACTIVE_SOURCE_ROOT_RESOURCE.into(),
                        Some(Secret::new(current.expose().to_vec())?),
                    ));
                }
                durable.apply_batch_conditionally_before_publish(
                    heptabao_durable_service::BatchPublication {
                        replay_epoch: plan.root.replay_epoch,
                        principal: "heptabao-server".into(),
                        namespace: "system".into(),
                        request_id: format!("{operation}-root"),
                        authorization_digest: identity.digest(),
                        mutations,
                    },
                    conditions_copy(&conditions),
                    &mut gate,
                )?;
                root_committed = true;
                gate()?;
                durable.verify_live_ownership()?;
                gate()?;
                if durable.generation() != publication_generation {
                    return Err(ServiceError::CorruptState);
                }
                let committed_bytes = durable
                    .get("system", "state")?
                    .ok_or(ServiceError::CorruptState)?;
                gate()?;
                if committed_bytes.expose() != plan.bytes.as_slice() {
                    return Err(ServiceError::CorruptState);
                }
                let committed = crate::state_record_root_v6::RecordStateRootV6::decode(
                    committed_bytes.expose(),
                )
                .map_err(|_| ServiceError::CorruptState)?;
                gate()?;
                if committed
                    .identity()
                    .map_err(|_| ServiceError::CorruptState)?
                    != identity
                {
                    return Err(ServiceError::CorruptState);
                }
                let observed_cursor = durable
                    .get("system", ACTIVE_CURSOR_RESOURCE)?
                    .ok_or(ServiceError::CorruptState)?;
                gate()?;
                if observed_cursor.expose() != cursor_bytes.as_slice() {
                    return Err(ServiceError::CorruptState);
                }
                let observed_cursor = NativeActiveCursor::decode(observed_cursor.expose())
                    .map_err(|_| ServiceError::CorruptState)?;
                observed_cursor
                    .validate(&source, &committed, durable.generation())
                    .map_err(|_| ServiceError::CorruptState)?;
                gate()?;
                let observed_source = durable
                    .get("system", ACTIVE_SOURCE_ROOT_RESOURCE)?
                    .ok_or(ServiceError::CorruptState)?;
                gate()?;
                if observed_source.expose() != retained_source.as_slice() {
                    return Err(ServiceError::CorruptState);
                }
                v6_records::verify_durable_native_candidate(
                    &committed, durable, deadline, &mut gate,
                )
                .map_err(|_| ServiceError::CorruptState)?;
                gate()?;
                Ok(())
            })()
        };
        let unknown = (root_committed && result.is_err())
            || durable.capacity_status().recovery_required
            || matches!(
                &result,
                Err(ServiceError::OutcomeUnknown { .. } | ServiceError::RecoveryRequired)
            );
        if unknown {
            self.recovery_required = true;
            self.ha_activation = None;
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
        }
        if let Err(error) = result {
            self.capture_native_failure_notice(&error);
            self.capture_ordinary_kv_outcome_unknown(&error, true);
            return Err(match error {
                ServiceError::OutcomeUnknown { recovery_reference } => Response {
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    status: 503,
                    body: json!({"errors":["native durable outcome unknown; reopen and reconcile; do not blindly retry"],"recovery_reference":recovery_reference}),
                },
                ServiceError::RequestCapacityExhausted | ServiceError::JournalCapacityExhausted => {
                    Response::error(507, "native state capacity exhausted")
                }
                _ => rejected(),
            });
        }
        // The typed root was actually committed. A late caller cannot keep a
        // stale V5/native cache live or turn a late append into a success.
        if check().is_err() || before_publish(&actual_auth).is_err() {
            self.recovery_required = true;
            self.ha_activation = None;
            return Err(rejected());
        }
        self.state_digest = Some(identity.digest());
        self.record_root = None;
        self.native_root = Some(plan.root);
        self.record_writes_since_gc = 0;
        Ok(installed)
    }
}

impl Service {
    /// Authentication consumption only. This borrowed, non-clone Principal was
    /// produced and Clock-bound by the real authentication prelude; it grants
    /// no resource ACL, reply delivery, opaque-owner edit or namespace action.
    pub(super) fn commit_native_consumed_auth_use(
        &mut self,
        candidate: &mut State,
        principal: &Principal,
        request: &RequestView<'_>,
    ) -> Result<(), Response> {
        if !principal.consumed_use() || request.token_clock.is_none() {
            return Err(Response::error(
                503,
                "native token use requires original authentication clock",
            ));
        }
        let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
        let live = || deadline.check().map_err(|_| rejected());
        live()?;
        let source = self.state.as_ref().ok_or_else(rejected)?;
        let root = self.native_root.as_ref().ok_or_else(rejected)?;
        if candidate.cluster_id != source.cluster_id
            || candidate.replay_epoch != source.replay_epoch
            || candidate.global_lossless_json_format != source.global_lossless_json_format
            || candidate.namespace_protected.is_some()
            || !candidate.namespace_leases.is_empty()
        {
            return Err(rejected());
        }
        for (actual, expected) in [
            (
                owner_store::serialize_owner(&candidate.namespaces),
                owner_store::serialize_owner(&source.namespaces),
            ),
            (
                owner_store::serialize_owner(&candidate.database),
                owner_store::serialize_owner(&source.database),
            ),
            (
                owner_store::serialize_owner(&candidate.raft_admin),
                owner_store::serialize_owner(&source.raft_admin),
            ),
        ] {
            live()?;
            if actual.map_err(|_| rejected())?.as_slice()
                != expected.map_err(|_| rejected())?.as_slice()
            {
                return Err(rejected());
            }
            live()?;
        }
        let key = root.kv1_key().map_err(|_| rejected())?;
        if candidate.engines.record_root().as_ref() != Some(&root.kv1)
            || candidate
                .engines
                .record_address_key()
                .is_none_or(|observed| observed.expose() != key.expose())
        {
            return Err(rejected());
        }
        let parent = root.kv2_parent_key().map_err(|_| rejected())?;
        let check = || deadline.check().map_err(|_| RecordError::Invalid);
        candidate
            .engines
            .validate_native_roots(&parent, &root.kv2, &check)
            .map_err(|_| rejected())?;
        let (actual, _) = if root.reader_floor.native_kv2_format == 2 {
            candidate
                .engines
                .project_v6_native_paged(&parent, &check, |_, _| check())
        } else {
            candidate
                .engines
                .project_v6_native(&parent, &check, |_, _| check())
        }
        .map_err(|_| rejected())?;
        let (expected, _) = if root.reader_floor.native_kv2_format == 2 {
            source
                .engines
                .project_v6_native_paged(&parent, &check, |_, _| check())
        } else {
            source
                .engines
                .project_v6_native(&parent, &check, |_, _| check())
        }
        .map_err(|_| rejected())?;
        live()?;
        if owner_store::serialize_owner(&actual)
            .map_err(|_| rejected())?
            .as_slice()
            != owner_store::serialize_owner(&expected)
                .map_err(|_| rejected())?
                .as_slice()
        {
            return Err(rejected());
        }
        source
            .auth
            .validate_native_consumed_auth_candidate(
                principal,
                &candidate.auth,
                request.token_time()?,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        live()?;
        let source_auth = owner_store::serialize_owner(&source.auth).map_err(|_| rejected())?;
        let candidate_auth =
            owner_store::serialize_owner(&candidate.auth).map_err(|_| rejected())?;
        if source_auth.as_slice() == candidate_auth.as_slice() {
            return Err(rejected());
        }
        live()?;
        let candidate_auth_owner = candidate.auth.clone();
        let mut original_gate = |auth: &AuthState| {
            live()?;
            if !principal.consumed_use()
                || request.token_clock.is_none()
                || owner_store::serialize_owner(auth)
                    .map_err(|_| rejected())?
                    .as_slice()
                    != source_auth.as_slice()
            {
                return Err(rejected());
            }
            // Observe the original trusted request clock, without reauthenticating
            // a bearer or granting its requested resource capability.
            auth.validate_native_consumed_auth_candidate(
                principal,
                &candidate_auth_owner,
                request.token_time()?,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
            live()
        };
        let plan = self.prepare_native_live_root_checked(candidate, &mut original_gate)?;
        let installed =
            self.commit_native_root_plan(candidate, plan, false, "auth-use", &mut original_gate)?;
        *candidate = installed;
        Ok(())
    }
}

impl Service {
    /// A private terminal observation write, never resource authorization.
    /// `at` is the first actual observation of the original trusted request
    /// Clock in the terminal writer. Subsequent checks observe that same Clock;
    /// the exact floor delta remains fixed rather than refreshing its budget.
    pub(super) fn commit_native_terminal_clock_floor(
        &mut self,
        candidate: &mut State,
        clock: RequestClock,
        fixed_time: AuthorityTime,
    ) -> Result<(), Response> {
        let AuthorityTime::Precise(at) = fixed_time else {
            return Err(rejected());
        };
        let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
        let live = || {
            deadline.check().map_err(|_| rejected())?;
            let observed = clock.observed_at().map_err(|_| rejected())?;
            if observed < at {
                return Err(rejected());
            }
            deadline.check().map_err(|_| rejected())
        };
        live()?;
        let source = self.state.as_ref().ok_or_else(rejected)?;
        let root = self.native_root.as_ref().ok_or_else(rejected)?;
        let mut expected = source.clone();
        let time = expected
            .engines
            .kubernetes_artifact_time(fixed_time)
            .map_err(|error| Response::error(503, &error.message))?;
        let time = expected.auth.token_api_observed_time(time);
        let mut changed = expected
            .auth
            .observe_token_api_time(time)
            .map_err(|error| Response::error(503, &error.message))?;
        changed |= expected
            .engines
            .observe_kubernetes_artifact_time(time)
            .map_err(|error| Response::error(503, &error.message))?;
        if !changed {
            return Err(rejected());
        }
        expected.schema = expected.writer_schema();
        live()?;
        if candidate.schema != expected.schema
            || candidate.cluster_id != expected.cluster_id
            || candidate.replay_epoch != expected.replay_epoch
            || candidate.global_lossless_json_format != expected.global_lossless_json_format
            || candidate.namespace_protected.is_some()
            || !candidate.namespace_leases.is_empty()
        {
            return Err(rejected());
        }
        for (actual, expected) in [
            (
                owner_store::serialize_owner(&candidate.auth),
                owner_store::serialize_owner(&expected.auth),
            ),
            (
                owner_store::serialize_owner(&candidate.namespaces),
                owner_store::serialize_owner(&expected.namespaces),
            ),
            (
                owner_store::serialize_owner(&candidate.database),
                owner_store::serialize_owner(&expected.database),
            ),
            (
                owner_store::serialize_owner(&candidate.raft_admin),
                owner_store::serialize_owner(&expected.raft_admin),
            ),
        ] {
            live()?;
            if actual.map_err(|_| rejected())?.as_slice()
                != expected.map_err(|_| rejected())?.as_slice()
            {
                return Err(rejected());
            }
            live()?;
        }
        let key = root.kv1_key().map_err(|_| rejected())?;
        if candidate.engines.record_root().as_ref() != Some(&root.kv1)
            || candidate
                .engines
                .record_address_key()
                .is_none_or(|observed| observed.expose() != key.expose())
        {
            return Err(rejected());
        }
        let parent = root.kv2_parent_key().map_err(|_| rejected())?;
        let check = || deadline.check().map_err(|_| RecordError::Invalid);
        candidate
            .engines
            .validate_native_roots(&parent, &root.kv2, &check)
            .map_err(|_| rejected())?;
        let (actual_meta, _) = if root.reader_floor.native_kv2_format == 2 {
            candidate
                .engines
                .project_v6_native_paged(&parent, &check, |_, _| check())
        } else {
            candidate
                .engines
                .project_v6_native(&parent, &check, |_, _| check())
        }
        .map_err(|_| rejected())?;
        let (expected_meta, _) = if root.reader_floor.native_kv2_format == 2 {
            expected
                .engines
                .project_v6_native_paged(&parent, &check, |_, _| check())
        } else {
            expected
                .engines
                .project_v6_native(&parent, &check, |_, _| check())
        }
        .map_err(|_| rejected())?;
        live()?;
        if owner_store::serialize_owner(&actual_meta)
            .map_err(|_| rejected())?
            .as_slice()
            != owner_store::serialize_owner(&expected_meta)
                .map_err(|_| rejected())?
                .as_slice()
        {
            return Err(rejected());
        }
        live()?;
        let source_auth = owner_store::serialize_owner(&source.auth).map_err(|_| rejected())?;
        let expected_auth = owner_store::serialize_owner(&expected.auth).map_err(|_| rejected())?;
        let mut original_gate = |auth: &AuthState| {
            live()?;
            if owner_store::serialize_owner(auth)
                .map_err(|_| rejected())?
                .as_slice()
                != source_auth.as_slice()
            {
                return Err(rejected());
            }
            let mut checked = auth.clone();
            checked
                .observe_token_api_time(time)
                .map_err(|error| Response::error(503, &error.message))?;
            if owner_store::serialize_owner(&checked)
                .map_err(|_| rejected())?
                .as_slice()
                != expected_auth.as_slice()
            {
                return Err(rejected());
            }
            live()
        };
        #[cfg(test)]
        let clock_witness = tests::start_native_clock_witness(self)?;
        let plan = self.prepare_native_live_root_checked(candidate, &mut original_gate)?;
        let installed = self.commit_native_root_plan(
            candidate,
            plan,
            false,
            "clock-observation",
            &mut original_gate,
        )?;
        *candidate = installed;
        #[cfg(test)]
        tests::finish_native_clock_witness(self, candidate, clock_witness)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            std::time::Instant::now() + Duration::from_secs(60),
        );
        service.handle(method, path, "", token, body)
    }

    // These negative fixtures exercise the normal trusted request Clock with
    // the listener's default budget. They never re-anchor an admitted actor.
    fn call_default_budget(
        service: &mut Service,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            std::time::Instant::now() + Duration::from_secs(15),
        );
        service.handle(method, path, "", token, body)
    }

    #[derive(Clone)]
    pub(super) struct NativeDurableFrontier {
        generation: u64,
        root: Zeroizing<Vec<u8>>,
        cursor: Zeroizing<Vec<u8>>,
        retained_source: Zeroizing<Vec<u8>>,
        journal: Zeroizing<Vec<u8>>,
    }

    fn native_frontier(
        service: &mut Service,
    ) -> Result<NativeDurableFrontier, Box<dyn std::error::Error>> {
        let durable = service.durable.as_mut().ok_or("durable")?;
        let generation = durable.generation();
        let root = durable
            .get("system", "state")?
            .ok_or("durable native root")?;
        let cursor = durable
            .get("system", ACTIVE_CURSOR_RESOURCE)?
            .ok_or("durable native cursor")?;
        let retained = durable
            .get("system", ACTIVE_SOURCE_ROOT_RESOURCE)?
            .ok_or("retained migration source")?;
        Ok(NativeDurableFrontier {
            generation,
            root: Zeroizing::new(root.expose().to_vec()),
            cursor: Zeroizing::new(cursor.expose().to_vec()),
            retained_source: Zeroizing::new(retained.expose().to_vec()),
            journal: Zeroizing::new(fs::read(service.data_dir.join("journal.hbj"))?),
        })
    }

    fn assert_native_frontier_unchanged(
        service: &mut Service,
        prior: &NativeDurableFrontier,
    ) -> TestResult {
        let actual = native_frontier(service)?;
        assert_eq!(
            actual.generation, prior.generation,
            "rejected request changed generation"
        );
        assert!(
            actual.root == prior.root,
            "rejected request changed native root"
        );
        assert!(
            actual.cursor == prior.cursor,
            "rejected request changed native cursor"
        );
        assert!(
            actual.retained_source == prior.retained_source,
            "rejected request changed migration source"
        );
        assert!(
            actual.journal == prior.journal,
            "rejected request appended journal bytes"
        );
        Ok(())
    }

    fn same_native_frontier(left: &NativeDurableFrontier, right: &NativeDurableFrontier) -> bool {
        left.generation == right.generation
            && left.root == right.root
            && left.cursor == right.cursor
            && left.retained_source == right.retained_source
            && left.journal == right.journal
    }

    fn same_native_resources_except_auth_clock(
        before: &NativeDurableFrontier,
        after: &NativeDurableFrontier,
    ) -> Result<bool, crate::state_record_root::RootError> {
        use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
        let before_root = RecordStateRootV6::decode(&before.root)?;
        let mut after_root = RecordStateRootV6::decode(&after.root)?;
        for (prior, current) in before_root.owners.iter().zip(after_root.owners.iter_mut()) {
            if current.domain == OwnerDomain::Auth && prior.domain == OwnerDomain::Auth {
                *current = prior.clone();
            }
        }
        Ok(
            before_root.encode()?.as_slice() == after_root.encode()?.as_slice()
                && before.retained_source == after.retained_source,
        )
    }

    pub(super) struct NativeClockStart {
        frontier: NativeDurableFrontier,
        auth: AuthState,
    }
    struct NativeClockSpan {
        before: NativeDurableFrontier,
        after: NativeDurableFrontier,
    }
    std::thread_local! {
        static NATIVE_CLOCK_SPANS: std::cell::RefCell<Option<Vec<NativeClockSpan>>> =
            const { std::cell::RefCell::new(None) };
    }
    struct NativeClockWitness;
    impl NativeClockWitness {
        fn begin() -> Self {
            NATIVE_CLOCK_SPANS.with(|slot| {
                assert!(slot.borrow().is_none(), "nested native clock observer");
                *slot.borrow_mut() = Some(Vec::new());
            });
            Self
        }
        fn assert_only_observed_clock_spans(
            self,
            service: &mut Service,
            original: &NativeDurableFrontier,
        ) -> TestResult {
            let spans = NATIVE_CLOCK_SPANS
                .with(|slot| slot.borrow_mut().take())
                .ok_or("missing native clock witness")?;
            assert!(
                !spans.is_empty(),
                "real precise-token observation write was not witnessed"
            );
            let mut prior = original;
            for span in &spans {
                assert!(
                    same_native_frontier(prior, &span.before),
                    "durable write occurred outside the exact observation-only span"
                );
                assert!(
                    same_native_resources_except_auth_clock(&span.before, &span.after)
                        .map_err(|_| "malformed native clock frontier")?,
                    "clock span changed a resource, layout, non-Auth owner or retained source"
                );
                assert!(span.after.generation > span.before.generation);
                assert!(span.after.journal.starts_with(&span.before.journal));
                prior = &span.after;
            }
            assert!(
                same_native_frontier(prior, &native_frontier(service)?),
                "rejected resource appended outside the witnessed clock spans"
            );
            eprintln!(
                "native-expiry-proof clock_only_spans={} no_resource_publication=true",
                spans.len()
            );
            Ok(())
        }
    }
    impl Drop for NativeClockWitness {
        fn drop(&mut self) {
            NATIVE_CLOCK_SPANS.with(|slot| *slot.borrow_mut() = None);
        }
    }
    pub(super) fn start_native_clock_witness(
        service: &mut Service,
    ) -> Result<Option<NativeClockStart>, Response> {
        if !NATIVE_CLOCK_SPANS.with(|slot| slot.borrow().is_some()) {
            return Ok(None);
        }
        let frontier = native_frontier(service)
            .map_err(|_| Response::error(503, "test native frontier observation failed"))?;
        let auth = service
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "test native source missing"))?
            .auth
            .clone();
        Ok(Some(NativeClockStart {
            frontier,
            auth: (*auth).clone(),
        }))
    }
    pub(super) fn finish_native_clock_witness(
        service: &mut Service,
        installed: &State,
        start: Option<NativeClockStart>,
    ) -> Result<(), Response> {
        let Some(start) = start else {
            return Ok(());
        };
        let bad = || Response::error(503, "test native clock-only proof rejected");
        let after = native_frontier(service).map_err(|_| bad())?;
        let before_time = start.auth.terminal_token_clock_floor().ok_or_else(bad)?;
        let after_time = installed
            .auth
            .terminal_token_clock_floor()
            .ok_or_else(bad)?;
        if after_time <= before_time
            || !same_native_resources_except_auth_clock(&start.frontier, &after)
                .map_err(|_| bad())?
        {
            return Err(bad());
        }
        // Reconstruct ONLY the exact monotonic clock delta. Token issuance,
        // renew/revoke, policy changes and resource mutations cannot match.
        let mut expected = start.auth;
        expected
            .observe_token_api_time(AuthorityTime::Precise(after_time))
            .map_err(|_| bad())?;
        if owner_store::serialize_owner(&expected)
            .map_err(|_| bad())?
            .as_slice()
            != owner_store::serialize_owner(&installed.auth)
                .map_err(|_| bad())?
                .as_slice()
        {
            return Err(bad());
        }
        NATIVE_CLOCK_SPANS.with(|slot| {
            let mut slot = slot.borrow_mut();
            let spans = slot.as_mut().ok_or_else(bad)?;
            spans.push(NativeClockSpan {
                before: start.frontier,
                after,
            });
            Ok(())
        })
    }

    #[test]
    fn genuine_native_capacity_alias_binds_components_to_one_durable_generation() -> TestResult {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (_, token) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(15),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "secret/data/capacity-components",
                &token,
                json!({"data":{"value":"same-native-root"}})
            )
            .status,
            200
        );
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &token,
                json!({})
            )
            .status,
            204
        );
        let before = native_frontier(&mut service)?;
        // Direct observation methods deliberately sample the same frozen state,
        // unlike two audited HTTP requests with terminal clock publications.
        let detailed = service.capacity_response("GET", &json!({}));
        let alias = service.capacity_route("GET", &json!({}));
        assert_eq!(detailed.status, 200);
        assert_eq!(alias.status, 200);
        let d = &detailed.body["data"];
        let a = &alias.body["data"];
        assert_eq!(d["generation"], a["generation"]);
        assert_eq!(d["state_bytes"], a["stored_value_bytes"]);
        assert_eq!(
            d["opaque_owner_aggregate_bytes"],
            a["opaque_owner_aggregate_bytes"]
        );
        assert_eq!(
            d["native_kv2_metadata_bytes"],
            a["native_kv2_metadata_bytes"]
        );
        assert_eq!(
            d["native_kv2_logical_payload_bytes"],
            a["native_kv2_logical_payload_bytes"]
        );
        let sum = [
            "opaque_owner_aggregate_bytes",
            "native_kv1_metadata_bytes",
            "native_kv2_metadata_bytes",
            "native_kv2_logical_payload_bytes",
        ]
        .iter()
        .try_fold(0_u64, |sum, name| {
            a[*name].as_u64().and_then(|v| sum.checked_add(v))
        })
        .ok_or("missing checked native capacity components")?;
        assert_eq!(a["stored_value_bytes"].as_u64(), Some(sum));
        assert_native_frontier_unchanged(&mut service, &before)?;
        Ok(())
    }

    #[test]
    fn genuine_native_unchanged_metadata_reauthenticates_without_restage() -> TestResult {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (_, root) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(15),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "secret/data/reused-stage",
                &root,
                json!({"data":{"kept":"one-resource"}})
            )
            .status,
            200
        );
        // Root-backed issuance establishes precise token clock semantics.
        let created = call_default_budget(
            &mut service,
            "POST",
            "auth/token/create",
            &root,
            json!({"policies":["root"],"num_uses":0,"ttl":"30s","no_default_policy":true,"no_parent":true}),
        );
        assert_eq!(created.status, 200, "precise token setup failed");
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &root,
                json!({})
            )
            .status,
            204
        );
        let source_before = native_frontier(&mut service)?;
        let counts_before = super::super::native_blob_source::staging_outcomes();
        let observation = call_default_budget(
            &mut service,
            "GET",
            "sys/internal/capacity",
            &root,
            json!({}),
        );
        assert_eq!(observation.status, 200);
        let counts_after = super::super::native_blob_source::staging_outcomes();
        assert!(
            counts_after.0 > counts_before.0,
            "no actual committed ciphertext was reauthenticated"
        );
        let source_after = native_frontier(&mut service)?;
        assert!(
            same_native_resources_except_auth_clock(&source_before, &source_after)
                .map_err(|_| "invalid metadata reuse frontier")?
        );
        assert!(source_after.generation > source_before.generation);
        // Only changed clock-owner material is staged; the existing native
        // resource must still pass a real selected-payload authentication.
        let response = call_default_budget(
            &mut service,
            "GET",
            "secret/data/reused-stage",
            &root,
            json!({}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["data"]["kept"], "one-resource");
        eprintln!(
            "native-reuse-proof reauthenticated={} newly_staged={} unchanged_resource=true",
            counts_after.0 - counts_before.0,
            counts_after.1 - counts_before.1
        );
        Ok(())
    }

    #[test]
    fn native_clock_witness_rejects_every_unwitnessed_durable_dimension() {
        let original = NativeDurableFrontier {
            generation: 7,
            root: Zeroizing::new(vec![1]),
            cursor: Zeroizing::new(vec![2]),
            retained_source: Zeroizing::new(vec![3]),
            journal: Zeroizing::new(vec![4]),
        };
        assert!(same_native_frontier(&original, &original));
        for dimension in 0..5 {
            let mut changed = original.clone();
            match dimension {
                0 => changed.generation += 1,
                1 => changed.root.push(5),
                2 => changed.cursor.push(5),
                3 => changed.retained_source.push(5),
                _ => changed.journal.push(5),
            }
            assert!(!same_native_frontier(&original, &changed));
        }
    }

    fn actor_expiry_after_actual_payload_open(method: &str) -> TestResult {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (key, primary) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(15),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        let _key = Zeroizing::new(key);
        let primary = Zeroizing::new(primary);
        let payload = "actual-barrier-floor2-actor".repeat(3_000);
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "secret/data/actor-expiry",
                &primary,
                json!({"data":{"payload":payload,"stable":1}}),
            )
            .status,
            200
        );
        // The real token is unlimited-use so rejection cannot be confused with
        // the separate consumed-auth publication. Required clock-only writes
        // remain explicit witnessed transitions, never resource authority.
        // Its real TTL expires only
        // after the actual FileBackend read and AeadBarrier open below.
        let created = call_default_budget(
            &mut service,
            "POST",
            "auth/token/create",
            &primary,
            json!({"policies":["root"],"num_uses":0,"ttl":"5s","no_default_policy":true,"no_parent":true}),
        );
        assert_eq!(
            created.status, 200,
            "actor creation rejected: {}",
            created.body
        );
        assert_eq!(created.body["auth"]["lease_duration"], 5);
        let actor = Zeroizing::new(
            created.body["auth"]["client_token"]
                .as_str()
                .ok_or("expiring actor")?
                .to_owned(),
        );
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &primary,
                json!({}),
            )
            .status,
            204
        );
        assert_eq!(
            service
                .native_root
                .as_ref()
                .ok_or("native root")?
                .reader_floor
                .native_kv2_format,
            2
        );
        let before = native_frontier(&mut service)?;
        let clock_witness = NativeClockWitness::begin();
        let observations = Arc::clone(&service.native_payload_observations);
        let opened = observations
            .blocks_opened
            .load(std::sync::atomic::Ordering::Relaxed);
        let ciphertext_bytes = observations
            .ciphertext_bytes_read
            .load(std::sync::atomic::Ordering::Relaxed);
        let plaintext_bytes = observations
            .plaintext_bytes_opened
            .load(std::sync::atomic::Ordering::Relaxed);
        let pause = native_blob_source::pause_after_payload_open_once(Duration::from_secs(6))?;
        let started = std::time::Instant::now();
        let body = if method == "PATCH" {
            json!({"options":{"cas":1},"data":{"stable":2}})
        } else {
            json!({"version":1})
        };
        let response = call_default_budget(
            &mut service,
            method,
            "secret/data/actor-expiry",
            &actor,
            body,
        );
        assert!(
            pause.fired(),
            "expiry must occur after an actual typed payload AEAD open"
        );
        drop(pause);
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "request budget, rather than Actor expiry, elapsed"
        );
        assert_eq!(
            observations
                .blocks_opened
                .load(std::sync::atomic::Ordering::Relaxed),
            opened + 1
        );
        assert!(
            observations
                .ciphertext_bytes_read
                .load(std::sync::atomic::Ordering::Relaxed)
                > ciphertext_bytes
        );
        assert!(
            observations
                .plaintext_bytes_opened
                .load(std::sync::atomic::Ordering::Relaxed)
                > plaintext_bytes
        );
        assert_eq!(
            response.status, 403,
            "expired Actor delivery: {}",
            response.body
        );
        assert!(response.body.get("data").is_none());
        assert!(response.body.get("auth").is_none());
        assert!(response.body.get("wrap_info").is_none());
        assert!(response.unwrapped_json.is_none());
        assert!(!service.recovery_required);
        clock_witness.assert_only_observed_clock_spans(&mut service, &before)?;
        let metadata = call_default_budget(
            &mut service,
            "GET",
            "secret/metadata/actor-expiry",
            &primary,
            json!({}),
        );
        assert_eq!(metadata.status, 200);
        assert_eq!(metadata.body["data"]["current_version"], 1);
        let stored = call_default_budget(
            &mut service,
            "GET",
            "secret/data/actor-expiry",
            &primary,
            json!({"version":1}),
        );
        assert_eq!(stored.status, 200);
        assert_eq!(stored.body["data"]["data"]["stable"], 1);
        assert_eq!(stored.body["data"]["data"]["payload"], payload);
        Ok(())
    }

    #[test]
    fn genuine_native_floor2_actor_expiry_after_actual_aead_get_has_no_delivery_or_resource_publication()
    -> TestResult {
        actor_expiry_after_actual_payload_open("GET")
    }

    #[test]
    fn genuine_native_floor2_actor_expiry_after_actual_aead_patch_has_no_delivery_or_resource_publication()
    -> TestResult {
        actor_expiry_after_actual_payload_open("PATCH")
    }

    #[test]
    fn genuine_native_quota_floor_and_runtime_survive_publish_but_cold_owner_resets() -> TestResult
    {
        fn quota_request(service: &mut Service) -> Response {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(60),
            );
            service.handle_request(
                ServiceRequest::new(
                    "POST",
                    "auth/approle/login",
                    "",
                    "",
                    json!({"role_id":"unknown-role-id","secret_id":"wrong-secret"}),
                )
                .with_origin_peer(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            )
        }
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (key, token) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(60),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        let key = Zeroizing::new(key);
        let token = Zeroizing::new(token);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/auth/approle",
                &token,
                json!({"type":"approle"})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/quotas/rate-limit/native",
                &token,
                json!({"path":"auth/approle/","rate":1,"interval":"1h"})
            )
            .status,
            204
        );
        assert_eq!(quota_request(&mut service).status, 400);
        let original = std::sync::Arc::clone(
            &service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .rate_limit_quota_registry()
                .ok_or("quota")?
                .runtime_owner,
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &token,
                json!({})
            )
            .status,
            204
        );
        assert!(
            service
                .native_root
                .as_ref()
                .ok_or("native root")?
                .state_schema
                >= RATE_LIMIT_QUOTA_STATE_SCHEMA
        );
        assert!(std::sync::Arc::ptr_eq(
            &original,
            &service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .rate_limit_quota_registry()
                .ok_or("quota")?
                .runtime_owner
        ));
        assert_eq!(quota_request(&mut service).status, 429);
        let written = call(
            &mut service,
            "POST",
            "secret/data/quota-lineage",
            &token,
            json!({"data":{"value":"retained"}}),
        );
        // Diagnostic only: expose no bearer, Auth owner or successful payload.
        let errors = written.body.get("errors").cloned().unwrap_or(Value::Null);
        assert_eq!(
            written.status, 200,
            "native quota hot POST status={}, errors={}",
            written.status, errors,
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/internal/storage/capacity",
                &token,
                json!({})
            )
            .status,
            200
        );
        assert!(std::sync::Arc::ptr_eq(
            &original,
            &service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .rate_limit_quota_registry()
                .ok_or("quota")?
                .runtime_owner
        ));
        assert_eq!(quota_request(&mut service).status, 429);
        drop(service);
        let mut reopened = directory.service()?;
        reopened.configure_native_v6_candidate()?;
        assert_eq!(
            call(
                &mut reopened,
                "POST",
                "sys/unseal",
                "",
                json!({"key":key.as_str()})
            )
            .status,
            200
        );
        let recovered = reopened.state.as_ref().ok_or("reopened state")?;
        assert!(recovered.schema >= RATE_LIMIT_QUOTA_STATE_SCHEMA);
        assert!(
            recovered
                .auth
                .rate_limit_quota_registry()
                .ok_or("reopened quota")?
                .definitions
                .contains_key("native")
        );
        assert!(!std::sync::Arc::ptr_eq(
            &original,
            &recovered
                .auth
                .rate_limit_quota_registry()
                .ok_or("reopened quota")?
                .runtime_owner
        ));
        // The cold RAM bucket is fresh; current native auth dispatch remains
        // intentionally closed, after consuming this one fallback allowance.
        assert_eq!(quota_request(&mut reopened).status, 501);
        assert_eq!(quota_request(&mut reopened).status, 429);
        Ok(())
    }

    #[test]
    fn genuine_native_service_large_history_cold_reopen_and_point_write() -> TestResult {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (key, token) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(60),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        let key = Zeroizing::new(key);
        let token = Zeroizing::new(token);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/bootstrap",
                &token,
                json!({"data":{"value":"source"}})
            )
            .status,
            200
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/config",
                &token,
                json!({"max_versions":32})
            )
            .status,
            204
        );
        assert!(service.record_root.is_some());
        let migration = call(
            &mut service,
            "POST",
            "sys/internal/native-v6/activate",
            &token,
            json!({}),
        );
        assert_eq!(
            migration.status, 204,
            "migration rejected: {}",
            migration.body
        );
        assert!(service.record_root.is_none());
        assert!(service.native_root.is_some());
        assert!(matches!(
            service.current_state_identity().map_err(|_| "identity")?,
            crate::state_record_root::StateIdentity::RecordsV6(_)
        ));
        for path in ["sys/internal/storage/capacity", "sys/internal/capacity"] {
            let capacity = call(&mut service, "GET", path, &token, json!({}));
            assert_eq!(capacity.status, 200, "native capacity: {}", capacity.body);
            assert!(
                capacity.body["data"]["state_storage_format"]
                    .as_str()
                    .is_some_and(|format| format.contains("v6"))
            );
        }
        for version in 1..=16 {
            let payload = char::from(b'A' + version as u8)
                .to_string()
                .repeat(2560 * 1024);
            let response = call(
                &mut service,
                "POST",
                "secret/data/capacity",
                &token,
                json!({"options":{"cas":version-1},"data":{"payload":payload}}),
            );
            assert_eq!(response.status, 200, "version {version}: {}", response.body);
            assert_eq!(response.body["data"]["version"], version);
        }
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let denied = call(
            &mut service,
            "POST",
            "secret/data/capacity",
            &token,
            json!({"options":{"cas":15},"data":{"payload":"stale"}}),
        );
        assert_eq!(denied.status, 400);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/data/capacity",
                &token,
                json!({"version":1})
            )
            .body["data"]["data"]["payload"]
                .as_str()
                .ok_or("history")?
                .len(),
            2560 * 1024
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/delete/capacity",
                &token,
                json!({"versions":[3]})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/data/capacity",
                &token,
                json!({"version":3})
            )
            .status,
            404
        );
        let digest = service
            .current_state_identity()
            .map_err(|_| "identity")?
            .digest();
        drop(service);
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let unsealed = call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()}),
        );
        assert_eq!(unsealed.status, 200, "cold unseal: {}", unsealed.body);
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "reopened identity")?
                .digest(),
            digest
        );
        let metadata = call(
            &mut service,
            "GET",
            "secret/metadata/capacity",
            &token,
            json!({}),
        );
        assert_eq!(metadata.status, 200, "metadata: {}", metadata.body);
        assert_eq!(metadata.body["data"]["current_version"], 16);
        assert!(
            !metadata.body["data"]["versions"]["3"]["deletion_time"]
                .as_str()
                .ok_or("deleted metadata")?
                .is_empty()
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/data/capacity",
                &token,
                json!({"version":1})
            )
            .body["data"]["data"]["payload"]
                .as_str()
                .ok_or("cold history")?
                .len(),
            2560 * 1024
        );
        let response = call(
            &mut service,
            "POST",
            "secret/data/capacity",
            &token,
            json!({"options":{"cas":16},"data":{"payload":"after-cold"}}),
        );
        assert_eq!(response.status, 200, "cold point writer: {}", response.body);
        assert_eq!(response.body["data"]["version"], 17);
        drop(service);
        let mut default_reader = directory.service()?;
        let refused = call(
            &mut default_reader,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()}),
        );
        assert_eq!(refused.status, 503);
        assert!(default_reader.state.is_none());
        drop(default_reader);
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":key.as_str()})
            )
            .status,
            200
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/data/capacity",
                &token,
                json!({})
            )
            .body["data"]["data"]["payload"],
            "after-cold"
        );
        Ok(())
    }

    #[test]
    fn genuine_native_service_activation_rejects_missing_profile_and_unsealed_configuration()
    -> TestResult {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        let (_, token) = super::super::tests::bootstrap(&mut service)?;
        let token = Zeroizing::new(token);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/seed",
                &token,
                json!({"data":{"x":1}})
            )
            .status,
            200
        );
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &token,
                json!({})
            )
            .status,
            503
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert!(service.native_root.is_none());
        assert!(service.configure_native_v6_candidate().is_err());
        Ok(())
    }
    #[test]
    fn genuine_native_service_failed_audit_and_original_plan_deadline_have_no_effect() -> TestResult
    {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (_, token) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(30),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        let token = Zeroizing::new(token);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/seed",
                &token,
                json!({"data":{"x":1}})
            )
            .status,
            200
        );
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let plan = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(2),
            );
            service
                .prepare_native_root_migration(&|| Ok(()))
                .map_err(|_| "source plan")?
        };
        std::thread::sleep(Duration::from_millis(2100));
        let state = service.state.as_ref().ok_or("state")?.clone();
        let _new_ambient = crate::request_deadline::RequestDeadlineScope::enter(
            std::time::Instant::now() + Duration::from_secs(30),
        );
        assert!(
            service
                .commit_native_root_plan(&state, plan, true, "migration", &mut |_| Ok(()))
                .is_err()
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert!(service.native_root.is_none());
        service.audit_failed = true;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &token,
                json!({})
            )
            .status,
            503
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert!(service.native_root.is_none());
        Ok(())
    }
    #[test]
    fn genuine_native_consumed_actor_publishes_auth_only_for_permitted_and_denied_resource()
    -> TestResult {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (key, primary) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(30),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        let key = Zeroizing::new(key);
        let primary = Zeroizing::new(primary);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/seed",
                &primary,
                json!({"data":{"x":1}})
            )
            .status,
            200
        );
        let mut tokens = Vec::new();
        for (policy, status) in [("root", 200), ("default", 403)] {
            let created = call(
                &mut service,
                "POST",
                "auth/token/create",
                &primary,
                json!({"policies":[policy],"num_uses":1,"ttl":"1h","no_default_policy":true}),
            );
            assert_eq!(created.status, 200, "token create: {}", created.body);
            tokens.push((
                Zeroizing::new(
                    created.body["auth"]["client_token"]
                        .as_str()
                        .ok_or("finite token")?
                        .to_owned(),
                ),
                status,
            ));
        }
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &primary,
                json!({})
            )
            .status,
            204
        );
        let source_graph = service
            .native_root
            .as_ref()
            .ok_or("native root")?
            .kv1
            .clone();
        for (token, status) in &tokens {
            let response = call(&mut service, "GET", "secret/data/seed", token, json!({}));
            assert_eq!(
                response.status, *status,
                "first limited use: {}",
                response.body
            );
            assert_eq!(
                call(&mut service, "GET", "secret/data/seed", token, json!({})).status,
                403
            );
            assert_eq!(
                service.native_root.as_ref().ok_or("native root")?.kv1,
                source_graph
            );
        }
        drop(service);
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":key.as_str()})
            )
            .status,
            200
        );
        for (token, _) in &tokens {
            assert_eq!(
                call(&mut service, "GET", "secret/data/seed", token, json!({})).status,
                403
            );
        }
        assert_eq!(
            call(&mut service, "GET", "secret/data/seed", &primary, json!({})).status,
            200
        );
        Ok(())
    }

    #[test]
    fn genuine_native_activation_keeps_existing_preconsumption_on_success_and_rejection()
    -> TestResult {
        for configured in [false, true] {
            let directory = super::super::tests::Root::new();
            let mut service = directory.service()?;
            if configured {
                service.configure_native_v6_candidate()?;
            }
            let (key, primary) = {
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                    std::time::Instant::now() + Duration::from_secs(30),
                );
                super::super::tests::bootstrap(&mut service)?
            };
            let key = Zeroizing::new(key);
            let primary = Zeroizing::new(primary);
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "secret/data/seed",
                    &primary,
                    json!({"data":{"x":1}})
                )
                .status,
                200
            );
            let created = call(
                &mut service,
                "POST",
                "auth/token/create",
                &primary,
                json!({"policies":["root"],"num_uses":1,"ttl":"1h","no_default_policy":true}),
            );
            assert_eq!(created.status, 200);
            let finite = Zeroizing::new(
                created.body["auth"]["client_token"]
                    .as_str()
                    .ok_or("finite root")?
                    .to_owned(),
            );
            let response = call(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &finite,
                json!({}),
            );
            assert_eq!(
                response.status,
                if configured { 204 } else { 503 },
                "activation finite: {}",
                response.body
            );
            assert_eq!(
                call(&mut service, "GET", "secret/data/seed", &finite, json!({})).status,
                403
            );
            drop(service);
            let mut service = directory.service()?;
            if configured {
                service.configure_native_v6_candidate()?;
            }
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/unseal",
                    "",
                    json!({"key":key.as_str()})
                )
                .status,
                200
            );
            assert_eq!(
                call(&mut service, "GET", "secret/data/seed", &finite, json!({})).status,
                403
            );
        }
        Ok(())
    }
    struct LostApplyAck {
        inner: heptabao_durable_service::FileBackend,
        barrier: AeadBarrier,
        lost: Arc<std::sync::atomic::AtomicBool>,
        purpose: &'static str,
    }
    impl LostApplyAck {
        // Inspect only this owned fixture's real barrier-authenticated journal.
        // Selection uses the actual Apply kind and request_id. It is independent
        // of prelude/terminal writes, batching or append-frame counts.
        fn is_selected_native_root_apply(
            &self,
            frame: &[u8],
        ) -> Result<bool, heptabao_durable_service::BackendError> {
            use heptabao_durable_service::BackendError;
            let invalid = || BackendError::OutcomeUnknown;
            let u32_at = |offset: usize| -> Result<usize, BackendError> {
                let end = offset.checked_add(4).ok_or_else(invalid)?;
                let bytes: [u8; 4] = frame
                    .get(offset..end)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?;
                Ok(u32::from_le_bytes(bytes) as usize)
            };
            let encoded_length = u32_at(0)?;
            if frame.len().checked_sub(4) != Some(encoded_length) {
                return Err(invalid());
            }
            let sequence = frame.get(4..12).ok_or_else(invalid)?;
            let protected_end = 16usize.checked_add(u32_at(12)?).ok_or_else(invalid)?;
            if protected_end.checked_add(32) != Some(frame.len()) {
                return Err(invalid());
            }
            let protected = frame.get(16..protected_end).ok_or_else(invalid)?;
            let mut context = b"heptabao.durable-service.journal.v2".to_vec();
            context.extend_from_slice(sequence);
            let plain = Zeroizing::new(
                heptabao_durable_service::Barrier::open(&self.barrier, &context, protected)
                    .map_err(|_| invalid())?,
            );
            if plain.first() != Some(&5) {
                return Ok(false);
            }
            let mut offset = 1usize;
            let mut selected = false;
            for number in 0..3 {
                let length_end = offset.checked_add(4).ok_or_else(invalid)?;
                let length: [u8; 4] = plain
                    .get(offset..length_end)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?;
                let end = length_end
                    .checked_add(u32::from_le_bytes(length) as usize)
                    .ok_or_else(invalid)?;
                let field = std::str::from_utf8(plain.get(length_end..end).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                if number == 2 {
                    selected = field.starts_with(&format!("native6-{}-", self.purpose))
                        && field.ends_with("-root");
                }
                offset = end;
            }
            Ok(selected)
        }
    }
    impl heptabao_durable_service::DurableBackend for LostApplyAck {
        fn verify(&self) -> Result<(), heptabao_durable_service::BackendError> {
            self.inner.verify()
        }
        fn immutable_blob_profile(
            &self,
        ) -> Result<
            heptabao_durable_service::ImmutableBlobProfile,
            heptabao_durable_service::BackendError,
        > {
            self.inner.immutable_blob_profile()
        }
        fn stage_immutable_ciphertext(
            &mut self,
            locator: heptabao_durable_service::BlobLocator,
            ciphertext: &[u8],
        ) -> Result<
            heptabao_durable_service::ImmutableBlobStage,
            heptabao_durable_service::BackendError,
        > {
            self.inner.stage_immutable_ciphertext(locator, ciphertext)
        }
        fn stage_immutable_ciphertext_checked(
            &mut self,
            locator: heptabao_durable_service::BlobLocator,
            ciphertext: &[u8],
            gate: &mut dyn FnMut() -> Result<(), heptabao_durable_service::BackendError>,
        ) -> Result<
            heptabao_durable_service::ImmutableBlobStage,
            heptabao_durable_service::BackendError,
        > {
            self.inner
                .stage_immutable_ciphertext_checked(locator, ciphertext, gate)
        }
        fn pin_immutable_ciphertext(
            &self,
            locator: heptabao_durable_service::BlobLocator,
            exact_len: usize,
        ) -> Result<
            heptabao_durable_service::ImmutableBlobReadPin,
            heptabao_durable_service::BackendError,
        > {
            self.inner.pin_immutable_ciphertext(locator, exact_len)
        }
        fn verify_live_ownership(&mut self) -> Result<(), heptabao_durable_service::BackendError> {
            self.inner.verify_live_ownership()
        }
        fn load(
            &mut self,
        ) -> Result<heptabao_durable_service::BackendBundle, heptabao_durable_service::BackendError>
        {
            self.inner.load()
        }
        fn initialize_empty(
            &mut self,
            initial: &heptabao_durable_service::BackendBundle,
        ) -> Result<(), heptabao_durable_service::BackendError> {
            self.inner.initialize_empty(initial)
        }
        fn append_journal(
            &mut self,
            expected_len: usize,
            frame: &[u8],
        ) -> Result<usize, heptabao_durable_service::BackendError> {
            let written = self.inner.append_journal(expected_len, frame)?;
            if self.is_selected_native_root_apply(frame)? {
                self.lost.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(heptabao_durable_service::BackendError::OutcomeUnknown);
            }
            Ok(written)
        }
        fn truncate_journal(
            &mut self,
            expected_len: usize,
            new_len: usize,
        ) -> Result<(), heptabao_durable_service::BackendError> {
            self.inner.truncate_journal(expected_len, new_len)
        }
        fn publish_checkpoint(
            &mut self,
            expected: &heptabao_durable_service::BackendBundle,
            replacement: &heptabao_durable_service::BackendBundle,
        ) -> Result<(), heptabao_durable_service::BackendError> {
            self.inner.publish_checkpoint(expected, replacement)
        }
        fn restore_profile(
            &self,
        ) -> Result<heptabao_durable_service::RestoreProfile, heptabao_durable_service::BackendError>
        {
            self.inner.restore_profile()
        }
        fn publish_restore(
            &mut self,
            expected: &heptabao_durable_service::BackendBundle,
            replacement: &heptabao_durable_service::BackendBundle,
            intent: Option<&[u8]>,
        ) -> Result<(), heptabao_durable_service::BackendError> {
            self.inner.publish_restore(expected, replacement, intent)
        }
        fn staged_restore_commitments(
            &self,
        ) -> Result<
            heptabao_durable_service::StagedRestoreCommitments,
            heptabao_durable_service::BackendError,
        > {
            self.inner.staged_restore_commitments()
        }
        fn staged_restore_replacement(
            &self,
        ) -> Result<heptabao_durable_service::BackendBundle, heptabao_durable_service::BackendError>
        {
            self.inner.staged_restore_replacement()
        }
        fn finish_restore(
            &mut self,
            intent: &[u8],
            replacement: &heptabao_durable_service::BackendBundle,
        ) -> Result<(), heptabao_durable_service::BackendError> {
            self.inner.finish_restore(intent, replacement)
        }
        fn close(self) -> Result<(), heptabao_durable_service::BackendError> {
            self.inner.close()
        }
    }

    #[test]
    fn genuine_native_auth_use_lost_filesystem_apply_ack_fences_and_cold_recovers_once()
    -> TestResult {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (key, primary) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(30),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        let key = Zeroizing::new(key);
        let primary = Zeroizing::new(primary);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/seed",
                &primary,
                json!({"data":{"x":1}})
            )
            .status,
            200
        );
        let created = call(
            &mut service,
            "POST",
            "auth/token/create",
            &primary,
            json!({"policies":["root"],"num_uses":1,"ttl":"1h","no_default_policy":true}),
        );
        assert_eq!(created.status, 200);
        let finite = Zeroizing::new(
            created.body["auth"]["client_token"]
                .as_str()
                .ok_or("finite root")?
                .to_owned(),
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &primary,
                json!({})
            )
            .status,
            204
        );
        let before = service.current_state_identity().map_err(|_| "identity")?;
        let barrier = Zeroizing::new(**service.barrier_key.as_ref().ok_or("barrier key")?);
        drop(service.durable.take().ok_or("durable")?);
        let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Authenticate the real journal frame using this fixture's actual
        // barrier. Lose only the consumed-auth root/cursor Apply acknowledgement
        // after the actual FilesystemBackend append+fsync has completed.
        let backend = LostApplyAck {
            inner: heptabao_durable_service::FileBackend::open(&service.data_dir)?,
            barrier: AeadBarrier::new(*barrier)?,
            lost: Arc::clone(&lost),
            purpose: "auth-use",
        };
        service.durable = Some(DurableService::reopen_with_backend(
            Box::new(backend) as Box<dyn heptabao_durable_service::DurableBackend>,
            AeadBarrier::new(*barrier)?,
            MAX_OPERATIONS,
        )?);
        let response = call(&mut service, "GET", "secret/data/seed", &finite, json!({}));
        assert_eq!(response.status, 503);
        assert!(lost.load(std::sync::atomic::Ordering::SeqCst));
        assert!(service.recovery_required);
        assert!(response.body.get("data").is_none());
        assert!(response.body["recovery_reference"].as_str().is_some());
        assert_eq!(
            call(&mut service, "GET", "secret/data/seed", &primary, json!({})).status,
            503
        );
        drop(service);
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":key.as_str()})
            )
            .status,
            200
        );
        assert_ne!(
            service
                .current_state_identity()
                .map_err(|_| "reconciled identity")?,
            before
        );
        assert_eq!(
            call(&mut service, "GET", "secret/data/seed", &finite, json!({})).status,
            403
        );
        let before_tokens: Value = serde_json::from_slice(
            owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.auth)?.as_slice(),
        )?;
        let before_graph = service
            .native_root
            .as_ref()
            .ok_or("native root")?
            .kv1
            .clone();
        assert!(before_tokens["tokens"].as_object().is_some_and(|tokens| {
            tokens
                .values()
                .any(|token| token["uses_remaining"].as_u64() == Some(0))
        }));
        assert_eq!(
            call(&mut service, "GET", "secret/data/seed", &finite, json!({})).status,
            403
        );
        let after_tokens: Value = serde_json::from_slice(
            owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.auth)?.as_slice(),
        )?;
        assert_eq!(
            before_tokens["tokens"], after_tokens["tokens"],
            "rejected use must not restore or reconsume any token"
        );
        assert_eq!(
            service.native_root.as_ref().ok_or("native root")?.kv1,
            before_graph
        );
        assert_eq!(
            call(&mut service, "GET", "secret/data/seed", &primary, json!({})).status,
            200
        );
        Ok(())
    }

    fn native_ciphertext_files(
        service: &Service,
    ) -> Result<BTreeSet<PathBuf>, Box<dyn std::error::Error>> {
        let mut paths = BTreeSet::new();
        for entry in fs::read_dir(&service.data_dir)? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "hbo")
            {
                assert!(
                    entry.file_type()?.is_file(),
                    "fixture ciphertext must be a regular file"
                );
                paths.insert(entry.path());
            }
        }
        Ok(paths)
    }

    #[test]
    fn genuine_native_floor2_resource_lost_apply_ack_cold_follows_committed_root_not_valid_orphan()
    -> TestResult {
        use crate::state_record_root_v6::ObjectDomain;
        use crate::state_records::ObjectKind;

        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (key, primary) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(15),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        let key = Zeroizing::new(key);
        let primary = Zeroizing::new(primary);
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "secret/data/seed",
                &primary,
                json!({"data":{"seed":"already-rooted"}}),
            )
            .status,
            200
        );
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &primary,
                json!({}),
            )
            .status,
            204
        );
        assert_eq!(
            service
                .native_root
                .as_ref()
                .ok_or("native root")?
                .reader_floor
                .native_kv2_format,
            2
        );
        let before = native_frontier(&mut service)?;
        let files_before = native_ciphertext_files(&service)?;

        // Construct a detached typed floor2 candidate with this live root's
        // actual graph keys, and validate it through the real private planner.
        // Publish exactly its valid payload ciphertext, discarding the Slot:
        // neither a locator nor a graph/root/cursor mutation is committed.
        let orphan_resource = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(15),
            );
            let mut detached = service.state.as_ref().ok_or("state")?.clone();
            let at = Service::kv2_request_timestamp(AuthorityTime::Coarse(1))
                .map_err(|_| "fixture timestamp")?;
            let response = detached.engines.dispatch_native_paged(
                "", "POST", "secret/data/unreferenced-orphan",
                &json!({"options":{"cas":0},"data":{"payload":"valid-but-unreferenced-ciphertext".repeat(3_000)}}),
                at,
                |_scope, _reference| Err(RecordError::Missing),
            ).map_err(|_| "detached floor2 mutation")?;
            assert_eq!(response.status, 200);
            let plan = service
                .prepare_native_live_root_checked(&detached, &mut |_| Ok(()))
                .map_err(|_| "detached orphan preparation")?;
            let mut payloads = plan.objects.iter().filter(|((domain, _), object)| {
                matches!(domain, ObjectDomain::Kv2(_))
                    && object.reference().kind == ObjectKind::Block
                    && object.bytes().len() > 32 * 1024
            });
            let ((domain, _), object) = payloads.next().ok_or("valid orphan payload")?;
            assert!(
                payloads.next().is_none(),
                "fixture must select exactly one new large payload object"
            );
            let resource = v6_records::native_resource(domain, object.reference());
            let durable = service.durable.as_mut().ok_or("durable")?;
            assert!(durable.get("system", &resource)?.is_none());
            let session = native_blob_source::session(durable, &before.root)?;
            let unpublished_slot =
                native_blob_source::stage(durable, &session, domain, object, &mut || Ok(()))?;
            assert!(!unpublished_slot.expose().is_empty());
            drop(unpublished_slot);
            assert!(
                durable.get("system", &resource)?.is_none(),
                "ciphertext stage must not publish its locator"
            );
            resource
        };
        assert_native_frontier_unchanged(&mut service, &before)?;
        let files_after = native_ciphertext_files(&service)?;
        let new_files = files_after.difference(&files_before).collect::<Vec<_>>();
        assert_eq!(
            new_files.len(),
            1,
            "actual orphan must be independently staged"
        );
        let orphan_path = (*new_files[0]).clone();
        let orphan_ciphertext = fs::read(&orphan_path)?;
        assert!(orphan_ciphertext.len() > 32 * 1024);
        let orphan_digest = crypto::digest(&orphan_ciphertext);

        let barrier = Zeroizing::new(**service.barrier_key.as_ref().ok_or("barrier key")?);
        drop(service.durable.take().ok_or("durable")?);
        let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let backend = LostApplyAck {
            inner: heptabao_durable_service::FileBackend::open(&service.data_dir)?,
            barrier: AeadBarrier::new(*barrier)?,
            lost: Arc::clone(&lost),
            purpose: "resource",
        };
        service.durable = Some(DurableService::reopen_with_backend(
            Box::new(backend) as Box<dyn heptabao_durable_service::DurableBackend>,
            AeadBarrier::new(*barrier)?,
            MAX_OPERATIONS,
        )?);
        // This uses the actual admitted unlimited primary Actor. Lose only
        // this resource root/cursor Apply ACK, after the real append+fsync.
        let response = call_default_budget(
            &mut service,
            "POST",
            "secret/data/committed-after-lost-ack",
            &primary,
            json!({"options":{"cas":0},"data":{"value":"committed-exactly-once"}}),
        );
        assert_eq!(response.status, 503);
        assert!(lost.load(std::sync::atomic::Ordering::SeqCst));
        assert!(service.recovery_required);
        assert!(response.body.get("data").is_none());
        assert!(response.body.get("auth").is_none());
        assert!(response.body.get("wrap_info").is_none());
        assert!(response.body["recovery_reference"].as_str().is_some());
        assert_eq!(
            call_default_budget(&mut service, "GET", "secret/data/seed", &primary, json!({}))
                .status,
            503
        );
        drop(service);

        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":key.as_str()})
            )
            .status,
            200
        );
        let reopened = native_frontier(&mut service)?;
        assert_eq!(
            reopened.generation,
            before.generation + 1,
            "exactly the lost resource Apply was committed"
        );
        assert!(reopened.root != before.root);
        assert!(reopened.cursor != before.cursor);
        assert!(reopened.retained_source == before.retained_source);
        let root = service.native_root.as_ref().ok_or("cold native root")?;
        assert_eq!(root.reader_floor.native_kv2_format, 2);
        assert!(root.encode().map_err(|_| "root encoding")?.as_slice() == reopened.root.as_slice());
        let source = records::decode_root(&reopened.retained_source)
            .map_err(|_| "retained source decoding")?
            .ok_or("retained source root")?;
        NativeActiveCursor::decode(&reopened.cursor)
            .map_err(|_| "cold cursor")?
            .validate(&source, root, reopened.generation)
            .map_err(|_| "cold root/cursor match")?;
        assert!(
            service
                .durable
                .as_mut()
                .ok_or("durable")?
                .get("system", &orphan_resource)?
                .is_none()
        );
        assert_eq!(crypto::digest(&fs::read(&orphan_path)?), orphan_digest);

        let committed = call_default_budget(
            &mut service,
            "GET",
            "secret/data/committed-after-lost-ack",
            &primary,
            json!({"version":1}),
        );
        assert_eq!(committed.status, 200);
        assert_eq!(
            committed.body["data"]["data"],
            json!({"value":"committed-exactly-once"})
        );
        assert_eq!(committed.body["data"]["metadata"]["version"], 1);
        let metadata = call_default_budget(
            &mut service,
            "GET",
            "secret/metadata/committed-after-lost-ack",
            &primary,
            json!({}),
        );
        assert_eq!(metadata.status, 200);
        assert_eq!(metadata.body["data"]["current_version"], 1);
        assert_eq!(
            metadata.body["data"]["versions"]
                .as_object()
                .ok_or("committed versions")?
                .len(),
            1
        );
        let before_unknown = native_frontier(&mut service)?;
        let payload_opens = service
            .native_payload_observations
            .blocks_opened
            .load(std::sync::atomic::Ordering::Relaxed);
        for path in [
            "secret/data/unreferenced-orphan",
            "secret/metadata/unreferenced-orphan",
        ] {
            let unknown = call_default_budget(&mut service, "GET", path, &primary, json!({}));
            assert_eq!(
                unknown.status, 404,
                "unrooted ciphertext acquired a logical grant"
            );
            assert!(unknown.body.get("auth").is_none());
            assert!(unknown.body.get("wrap_info").is_none());
            assert!(unknown.unwrapped_json.is_none());
        }
        assert_eq!(
            service
                .native_payload_observations
                .blocks_opened
                .load(std::sync::atomic::Ordering::Relaxed),
            payload_opens
        );
        assert_native_frontier_unchanged(&mut service, &before_unknown)?;
        assert!(
            service
                .durable
                .as_mut()
                .ok_or("durable")?
                .get("system", &orphan_resource)?
                .is_none()
        );
        assert_eq!(crypto::digest(&fs::read(orphan_path)?), orphan_digest);
        Ok(())
    }
    #[test]
    fn genuine_native_anonymous_kv_preserves_denial_without_publication() -> TestResult {
        let directory = super::super::tests::Root::new();
        let mut service = directory.service()?;
        service.configure_native_v6_candidate()?;
        let (key, root) = {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() + Duration::from_secs(15),
            );
            super::super::tests::bootstrap(&mut service)?
        };
        let key = Zeroizing::new(key);
        let root = Zeroizing::new(root);
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "secret/data/anonymous-probe",
                &root,
                json!({"data":{"kept":"original"}})
            )
            .status,
            200
        );
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "auth/token/create",
                &root,
                json!({"policies":["root"],"ttl":"1h","no_parent":true})
            )
            .status,
            200
        );
        assert_eq!(
            call_default_budget(
                &mut service,
                "POST",
                "sys/internal/native-v6/activate",
                &root,
                json!({})
            )
            .status,
            204
        );
        let operations = [
            ("GET", "secret/data/anonymous-probe", json!({})),
            (
                "POST",
                "secret/data/anonymous-probe",
                json!({"data":{"rejected":true}}),
            ),
            ("DELETE", "secret/data/anonymous-probe", json!({})),
            (
                "PATCH",
                "secret/data/anonymous-probe",
                json!({"data":{"rejected":true}}),
            ),
            ("GET", "secret/metadata/anonymous-probe", json!({})),
            ("GET", "secret/data/absent", json!({})),
        ];
        for cycle in 0..2 {
            let before = native_frontier(&mut service)?;
            let opens = service
                .native_payload_observations
                .blocks_opened
                .load(std::sync::atomic::Ordering::Relaxed);
            let mut statuses = Vec::new();
            for (method, path, body) in &operations {
                let response = call_default_budget(&mut service, method, path, "", body.clone());
                statuses.push(response.status);
                assert!(response.body.get("data").is_none());
                assert!(response.body.get("auth").is_none());
                assert!(response.body.get("wrap_info").is_none());
                if response.status == 403 {
                    assert_eq!(response.body, json!({"errors":["permission denied"]}));
                }
                assert!(service.pending_ordinary_kv_authority.is_none());
            }
            assert_eq!(
                service
                    .native_payload_observations
                    .blocks_opened
                    .load(std::sync::atomic::Ordering::Relaxed),
                opens
            );
            let after = native_frontier(&mut service)?;
            assert!(
                same_native_resources_except_auth_clock(&before, &after)
                    .map_err(|_| "invalid anonymous request frontier")?
            );
            assert_eq!(
                statuses,
                vec![403; operations.len()],
                "anonymous KV status matrix, cycle {cycle}"
            );
            let response = call_default_budget(
                &mut service,
                "GET",
                "secret/data/anonymous-probe",
                &root,
                json!({}),
            );
            assert_eq!(response.status, 200);
            assert_eq!(response.body["data"]["data"], json!({"kept":"original"}));
            assert_eq!(response.body["data"]["metadata"]["version"], 1);
            if cycle == 0 {
                drop(service);
                service = directory.service()?;
                service.configure_native_v6_candidate()?;
                assert_eq!(
                    call_default_budget(
                        &mut service,
                        "POST",
                        "sys/unseal",
                        "",
                        json!({"key":key.as_str()})
                    )
                    .status,
                    200
                );
            }
        }
        service.audit_failed = true;
        assert_eq!(
            call_default_budget(
                &mut service,
                "GET",
                "secret/data/anonymous-probe",
                "",
                json!({})
            )
            .status,
            503
        );
        Ok(())
    }
}
