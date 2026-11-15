//! Publish only the lazy policy deletions observed by this admitted request.
//! This commit precedes resource authorization and immutable backend owners.
use super::*;
use crate::auth::policy_retirement::PolicyRetirement;

fn rejected() -> Response {
    Response::error(503, "original policy retirement publication is unavailable")
}

impl Service {
    /// Ordinary CheckToken constructs its ACL before rejecting a disabled or
    /// missing entity. This helper only retires the observed policy batch and
    /// returns the same denial; it never authorizes either actor. The original
    /// finite use has committed already.
    pub(super) fn disabled_identity_policy_response(
        &mut self,
        admitted: &mut State,
        actor: &mut Principal,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        let entity = actor.entity_id()?;
        let policies = match admitted
            .engines
            .identity_projection_if_present(request.namespace, entity)
        {
            Ok(Some(projection)) if !projection.disabled => return None,
            Ok(Some(projection)) => projection.policies,
            // The loaded namespace resolved both direct and merged records.
            // A deleted entity contributes no former Identity policies.
            Ok(None) => std::collections::BTreeSet::new(),
            Err(error) => return Some(Response::error(error.status, &error.message)),
        };
        // Only this actual actor's stored Identity observation supplies names.
        // No templates, foreign target, new Principal or grant escape this
        // terminal path. The existing fixed retirement validator still owns
        // the complete Auth delta, original clock and publication gates.
        actor.bind_identity_policies(policies);
        Some(match self.retire_actor_policies(admitted, actor, request) {
            Ok(()) => Response::error(403, "permission denied"),
            Err(response) => response,
        })
    }

    pub(super) fn retire_actor_policies(
        &mut self,
        admitted: &mut State,
        actor: &Principal,
        request: &RequestView<'_>,
    ) -> Result<(), Response> {
        let batch = admitted
            .auth
            .actor_policy_retirement(actor, request.namespace, request.token_time()?)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.publish_policy_retirement(admitted, &batch, request, None)
    }

    pub(super) fn retire_capabilities_target_policies(
        &mut self,
        admitted: &mut State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
        token_fields: Option<&crate::http::token_fields::Carrier<'_>>,
    ) -> Result<(), Response> {
        if !matches!(
            request.path,
            "sys/capabilities" | "sys/capabilities-self" | "sys/capabilities-accessor"
        ) {
            return Ok(());
        }
        let actor = principal.ok_or_else(|| Response::error(403, "missing client token"))?;
        let time = actor
            .request_authority_time(request.token_time()?)
            .map_err(|error| Response::error(error.status, &error.message))?;
        admitted
            .auth
            .authorize_request_observed(actor, request.namespace, request.path, "update", time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if !matches!(request.method, "POST" | "PUT") {
            return Err(Response::error(405, "method not allowed"));
        }
        // Parameter authorization keeps the original numeric Values. The
        // backend and all retirement gates share this original carrier's weak
        // string conversion, including the exact HTTP number spelling.
        let backend_body = match token_fields {
            Some(carrier) => {
                if carrier.original != request.body {
                    return Err(rejected());
                }
                carrier.backend_body()
            }
            None => crate::http::ocsp::CarrierBody(request.body.clone()),
        };
        let object = backend_body
            .0
            .as_object()
            .ok_or_else(|| Response::error(400, "request must be an object"))?;
        // Reuse the route's exact field decoder, plural precedence and original
        // read-only target selector. No target is authenticated for execution.
        let plural = capabilities::capabilities_paths(object.get("paths"), "paths")?;
        let singular = capabilities::capabilities_paths(object.get("path"), "path")?;
        if plural.is_empty() && singular.is_empty() {
            return Err(Response::error(400, "paths must be supplied"));
        }
        let target = Self::capabilities_inspection_target_observed(
            &admitted.auth,
            actor,
            request.namespace,
            request.path,
            &backend_body.0,
            time,
        )?;
        let policies = match target.entity_id.as_deref() {
            Some(id) => match admitted.engines.identity_projection(request.namespace, id) {
                Ok(projection) if !projection.disabled => {
                    let selectors = admitted
                        .auth
                        .inspection_template_selectors_observed(
                            request.namespace,
                            &target,
                            &projection.policies,
                            time,
                        )
                        .map_err(|error| Response::error(error.status, &error.message))?;
                    // Match actual Identity admission, including all template
                    // errors, before a foreign policy can be selected.
                    admitted
                        .engines
                        .identity_template_values(
                            request.namespace,
                            &projection,
                            &selectors,
                            |accessor| {
                                admitted
                                    .auth
                                    .has_mount_accessor(request.namespace, accessor)
                            },
                        )
                        .map_err(|error| Response::error(error.status, &error.message))?;
                    projection.policies
                }
                Ok(_) => return Ok(()),
                Err(error) if error.status == 403 || error.status == 404 => return Ok(()),
                Err(error) => return Err(Response::error(error.status, &error.message)),
            },
            None => std::collections::BTreeSet::new(),
        };
        let batch = admitted
            .auth
            .inspection_policy_retirement(actor, request.namespace, target, &policies, time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.publish_policy_retirement(admitted, &batch, request, Some(&backend_body.0))
    }

    fn check_policy_retirement_target(
        auth: &AuthState,
        batch: &PolicyRetirement<'_>,
        request: &RequestView<'_>,
        inspection_body: Option<&Value>,
    ) -> Result<(), Response> {
        if batch.namespace() != request.namespace
            || batch.target().is_some() != inspection_body.is_some()
        {
            return Err(rejected());
        }
        let time = request.token_time()?;
        batch
            .check_actor(auth, time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if let Some(original) = batch.target() {
            // Keep the actual original target identity. Equal policy sets are
            // insufficient, and this read never charges a second target use.
            auth.authorize_request_observed(
                batch.actor(),
                request.namespace,
                request.path,
                "update",
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
            let current = Self::capabilities_inspection_target_observed(
                auth,
                batch.actor(),
                request.namespace,
                request.path,
                inspection_body.ok_or_else(rejected)?,
                time,
            )?;
            if &current != original {
                return Err(rejected());
            }
        }
        Ok(())
    }

    fn publish_policy_retirement(
        &mut self,
        admitted: &mut State,
        batch: &PolicyRetirement<'_>,
        request: &RequestView<'_>,
        inspection_body: Option<&Value>,
    ) -> Result<(), Response> {
        if batch.is_empty() {
            // No write, generation bump, or new native transaction for an
            // empty observation. This does not alter other empty-delta rules.
            return Ok(());
        }
        let mut candidate = admitted.clone();
        batch
            .apply(&mut candidate.auth)
            .map_err(|error| Response::error(error.status, &error.message))?;
        candidate.schema = candidate.writer_schema();
        let source = self.state.as_ref().ok_or_else(rejected)?;
        Self::check_policy_retirement_target(&source.auth, batch, request, inspection_body)?;
        batch
            .validate_candidate(&source.auth, &candidate.auth, request.token_time()?)
            .map_err(|error| Response::error(error.status, &error.message))?;
        #[cfg(feature = "native-v6-storage")]
        if self.native_root.is_some() {
            self.commit_native_policy_retirement(&mut candidate, batch, request, inspection_body)?;
        } else {
            self.commit_state(&mut candidate)?;
        }
        #[cfg(not(feature = "native-v6-storage"))]
        self.commit_state(&mut candidate)?;
        *admitted = self.install_committed_namespace_view(candidate);
        Ok(())
    }
}

#[cfg(feature = "native-v6-storage")]
impl Service {
    fn commit_native_policy_retirement(
        &mut self,
        candidate: &mut State,
        batch: &PolicyRetirement<'_>,
        request: &RequestView<'_>,
        inspection_body: Option<&Value>,
    ) -> Result<(), Response> {
        use crate::state_records::RecordError;
        use crate::v6_native_custody::OriginalDeadline;

        let (Some(clock), Some(actor_clock)) =
            (request.token_clock, batch.actor().original_request_clock())
        else {
            return Err(rejected());
        };
        if clock.started() != actor_clock.started()
            || clock.admitted_at() != actor_clock.admitted_at()
        {
            return Err(rejected());
        }
        let AuthorityTime::Precise(observed_at) = batch.observed_at() else {
            return Err(rejected());
        };
        let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
        let live = || {
            deadline.check().map_err(|_| rejected())?;
            if clock.observed_at().map_err(|_| rejected())? < observed_at {
                return Err(rejected());
            }
            deadline.check().map_err(|_| rejected())
        };
        live()?;
        let source = self.state.as_ref().ok_or_else(rejected)?;
        let root = self.native_root.as_ref().ok_or_else(rejected)?;
        if candidate.schema != candidate.writer_schema()
            || candidate.cluster_id != source.cluster_id
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
        batch
            .validate_candidate(&source.auth, &candidate.auth, request.token_time()?)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let source_auth = owner_store::serialize_owner(&source.auth).map_err(|_| rejected())?;
        let candidate_auth = candidate.auth.clone();
        let mut original_gate = |auth: &AuthState| {
            live()?;
            if owner_store::serialize_owner(auth)
                .map_err(|_| rejected())?
                .as_slice()
                != source_auth.as_slice()
            {
                return Err(rejected());
            }
            Self::check_policy_retirement_target(auth, batch, request, inspection_body)?;
            batch
                .validate_candidate(auth, &candidate_auth, request.token_time()?)
                .map_err(|error| Response::error(error.status, &error.message))?;
            live()
        };
        let plan = self.prepare_native_live_root_checked(candidate, &mut original_gate)?;
        let installed = self.commit_native_root_plan(
            candidate,
            plan,
            false,
            "policy-expiration",
            &mut original_gate,
        )?;
        *candidate = installed;
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_policy_retirement_tests.rs"]
mod tests;
