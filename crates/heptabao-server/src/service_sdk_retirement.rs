//! Original HTTP mount authority owns a serial, bounded retirement operation.
//! Every SDK Revoke is committed through the existing writer before relocation.
use super::*;
use crate::engines::sdk_lease::{Lease, Phase};
use std::collections::VecDeque;

pub(super) enum Action {
    Remount {
        to: String,
        cas: Option<u64>,
        id: String,
    },
    Unmount,
}
pub(super) struct Retirement {
    leases: VecDeque<Lease>,
    action: Action,
    completed: Option<Completed>,
}
struct Completed {
    target: Option<(String, MountOwner)>,
    retired: Vec<(String, [u8; 32])>,
}
fn digest(lease: &Lease) -> Result<[u8; 32], Response> {
    Ok(crypto::digest(
        &crate::secret_serde::to_vec(lease, 512 * 1024)
            .map_err(|_| Response::error(503, "SDK retirement typed owner serialization failed"))?,
    ))
}
impl Plan {
    pub(super) fn execute_retirement(
        &self,
        service: &Arc<Mutex<Service>>,
        deadline: Instant,
    ) -> Result<Option<Value>, Response> {
        loop {
            let record = {
                let state = self
                    .retirement
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK retirement authority absent"))?
                    .lock()
                    .map_err(|_| Response::error(503, "SDK retirement owner unavailable"))?;
                state.leases.front().cloned()
            };
            let Some(record) = record else {
                return Ok(None);
            };
            *self
                .lease
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement callback unavailable"))? =
                Some(Box::new(secret_lease::LeaseCall {
                    record: record.clone(),
                    action: "revoke",
                    increment_ns: 0,
                }));
            // The previous actual completion precedes the worker's busy release.
            // Observe that same completion under the unchanged deadline.
            while self.control.busy.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    return Err(Response::error(
                        503,
                        "SDK retirement original deadline expired",
                    ));
                }
                std::thread::park_timeout(Duration::from_millis(1));
            }
            let result = self.execute_once(service, deadline);
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
            let mut writer = writer_before(service, deadline)
                .map_err(|_| Response::error(503, "SDK retirement writer unavailable"))?;
            let mut response = match result {
                Ok(value) => writer.finalize_sdk_transaction(self, value),
                Err(error) => error,
            };
            let now = self
                .authority
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement affine authority unavailable"))?
                .now();
            let fingerprint = writer.request_fingerprint(
                "INTERNAL",
                "sdk-mount-retirement/revoke",
                &self.namespace,
                "",
            );
            if writer
                .audit_event(
                    "sdk-retirement-revoke-response",
                    &fingerprint,
                    now,
                    Some(response.status),
                )
                .is_err()
            {
                erase_json(&mut response.body);
                response.response_headers.clear();
                response.consistency_index = None;
                writer.recovery_required = true;
                writer.ha_activation = None;
                writer.retire_sdk_hosts();
                return Err(Response::error(
                    503,
                    "SDK retirement revoke audit failed; recovery required",
                ));
            }
            let gate = (|| {
                let mut authority = self.authority.lock().map_err(|_| {
                    Response::error(503, "SDK retirement affine authority unavailable")
                })?;
                writer.validate_sdk_authority(&mut authority)?;
                writer.sdk_binding_gate(self).map_err(bridge_failure)
            })();
            if let Err(error) = gate {
                let response = writer.sdk_delivery_veto(response, error, &fingerprint, now);
                return Err(response);
            }
            let success = response.status == 204;
            erase_json(&mut response.body);
            response.response_headers.clear();
            response.consistency_index = None;
            if !success {
                return Err(Response::error(
                    503,
                    "SDK retirement Revoke remains pending",
                ));
            }
            let current = writer
                .state
                .as_ref()
                .and_then(|s| s.engines.sdk_lease(&self.namespace, &record.id))
                .ok_or_else(|| Response::error(503, "SDK retirement terminal lease missing"))?;
            let mut expected = record.clone();
            expected.revoke();
            if digest(&current)? != digest(&expected)? {
                return Err(Response::error(
                    503,
                    "SDK retirement terminal lease owner changed",
                ));
            }
            self.retirement
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement authority absent"))?
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement owner unavailable"))?
                .leases
                .pop_front();
        }
    }
}
impl Service {
    pub(super) fn stage_sdk_retirement(
        &mut self,
        mut state: State,
        mut authority: plugin::PluginResponseAuthority,
        request: &RequestView<'_>,
        mount: String,
        owner: MountOwner,
        action: Action,
    ) -> Response {
        let records = match state
            .engines
            .sdk_mount_leases(request.namespace, &mount, &owner)
        {
            Ok(records) => records,
            Err(error) => return Response::from_engine_error(error),
        };
        if records.is_empty() {
            return Response::error(503, "SDK retirement requires registered leases");
        }
        // Validate relocation, including CAS/destination, before any Revoke.
        let mut preview = state.clone();
        for record in &records {
            let mut retired = record.clone();
            retired.revoke();
            if let Err(error) = preview.engines.store_sdk_lease(retired) {
                return Response::from_engine_error(error);
            }
        }
        let preflight = match &action {
            Action::Remount { to, cas, .. } => preview
                .engines
                .remount(request.namespace, &mount, to, *cas)
                .map(|_| ()),
            Action::Unmount => preview
                .engines
                .handle(
                    request.namespace,
                    "DELETE",
                    request.path,
                    request.body,
                    request.now,
                )
                .map(|_| ()),
        };
        if let Err(error) = preflight {
            return Response::from_engine_error(error);
        }
        let expected = match self.current_state_identity() {
            Ok(value) => value,
            Err(error) => return error,
        };
        if let Err(error) = self.validate_plugin_response(&mut authority) {
            return error;
        }
        let at = match secret_lease::precise(&authority, &state) {
            Ok(value) => value,
            Err(error) => return error,
        };
        state.engines.observe_sdk_lease_clock(at);
        let mut pending = VecDeque::new();
        for mut record in records {
            record.phase = Phase::PendingRevoke;
            if let Err(error) = state.engines.store_sdk_lease(record.clone()) {
                return Response::from_engine_error(error);
            };
            pending.push_back(record)
        }
        let first = match pending.front() {
            Some(record) => record.clone(),
            None => return Response::error(503, "SDK retirement lease list unavailable"),
        };
        let path = first.path.strip_prefix(&mount).unwrap_or("").to_owned();
        // Stage the original controller before publication; claim it exclusively.
        let actual = self.state.clone().unwrap_or_else(|| state.clone());
        let response = self.stage_sdk_plan(
            &actual,
            authority.into(),
            request,
            StageTarget {
                mount,
                owner,
                operation: "revoke",
                path: &path,
                lease: Some(secret_lease::LeaseCall {
                    record: first,
                    action: "revoke",
                    increment_ns: 0,
                }),
            },
        );
        let Some(mut plan) = self.pending_sdk_request.take() else {
            return response;
        };
        if plan
            .control
            .retiring
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Response::error(409, "SDK mount retirement already in progress");
        }
        plan.retirement = Some(Mutex::new(Retirement {
            leases: pending,
            action,
            completed: None,
        }));
        if plan.control.busy.load(Ordering::Acquire) {
            return Response::error(409, "SDK mount is busy before retirement");
        }
        let result = (|| {
            let mut authority = plan.authority.lock().map_err(|_| {
                Response::error(503, "SDK retirement original authority unavailable")
            })?;
            self.validate_sdk_authority(&mut authority)?;
            let expiry::Authority::Client(client) = &mut *authority else {
                return Err(Response::error(
                    503,
                    "SDK retirement requires original HTTP authority",
                ));
            };
            self.commit_sdk_control(&mut state, client, &expected)?;
            let mut transaction = plan
                .transaction
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement transaction unavailable"))?;
            transaction.engines = state.engines.clone();
            transaction.identity = self.current_state_identity()?;
            transaction.changed = false;
            Ok(())
        })();
        if let Err(error) = result {
            return error;
        }
        self.pending_sdk_request = Some(plan);
        Response {
            status: 202,
            body: json!({}),
            response_headers: Default::default(),
            consistency_index: None,
        }
    }
    pub(super) fn finalize_sdk_retirement(&mut self, plan: &Plan) -> Response {
        let result = (|| {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
            let mut authority = plan
                .authority
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement affine authority unavailable"))?;
            self.validate_sdk_authority(&mut authority)?;
            self.sdk_binding_gate(plan).map_err(bridge_failure)?;
            let mut retirement = plan
                .retirement
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement authority absent"))?
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement owner unavailable"))?;
            if !retirement.leases.is_empty() || retirement.completed.is_some() {
                return Err(Response::error(503, "SDK retirement callbacks incomplete"));
            }
            let mut state = self
                .state
                .clone()
                .ok_or_else(|| Response::error(503, "SDK retirement server sealed"))?;
            if !state
                .engines
                .sdk_mount_leases(&plan.namespace, &plan.mount, &plan.owner)
                .map_err(Response::from_engine_error)?
                .is_empty()
            {
                return Err(Response::error(
                    503,
                    "SDK retirement acquired a new live lease",
                ));
            }
            let retired = state
                .engines
                .sdk_retired_mount_leases(&plan.namespace, &plan.mount, &plan.owner)
                .map_err(Response::from_engine_error)?
                .into_iter()
                .map(|record| Ok((record.id.clone(), digest(&record)?)))
                .collect::<Result<Vec<_>, Response>>()?;
            let expected = self.current_state_identity()?;
            let response = match &retirement.action {
                Action::Remount { to, cas, id } => {
                    if self.sdk_migrations.len() >= 128 || self.sdk_migrations.contains_key(id) {
                        return Err(Response::error(
                            507,
                            "SDK migration status capacity changed",
                        ));
                    }
                    state
                        .engines
                        .remount(&plan.namespace, &plan.mount, to, *cas)
                        .map_err(Response::from_engine_error)?;
                    Response::ok(json!({"migration_id":id,"data":{"migration_id":id}}))
                }
                Action::Unmount => {
                    state
                        .engines
                        .handle(
                            &plan.namespace,
                            "DELETE",
                            &format!("sys/mounts/{}", plan.mount.trim_end_matches('/')),
                            &json!({}),
                            authority.now(),
                        )
                        .map_err(Response::from_engine_error)?;
                    Response {
                        status: 204,
                        body: json!({}),
                        response_headers: Default::default(),
                        consistency_index: None,
                    }
                }
            };
            let target = match &retirement.action {
                Action::Remount { to, .. } => Some(
                    state
                        .engines
                        .sdk_mount_binding(&plan.namespace, to)
                        .ok_or_else(|| {
                            Response::error(503, "SDK retirement target owner unavailable")
                        })?,
                ),
                Action::Unmount => None,
            };
            let expiry::Authority::Client(client) = &mut *authority else {
                return Err(Response::error(
                    503,
                    "SDK retirement original HTTP authority missing",
                ));
            };
            self.commit_sdk_control(&mut state, client, &expected)?;
            if let Action::Remount { to, id, .. } = &retirement.action {
                self.sdk_migrations.insert(
                    id.clone(),
                    MigrationStatus {
                        namespace: plan.namespace.clone(),
                        namespace_incarnation: state.namespaces.incarnation(&plan.namespace),
                        namespace_binding: namespace_runtime::DeliveryBinding::capture(
                            &state,
                            &plan.namespace,
                        ),
                        cluster: state.cluster_id.clone(),
                        from: plan.mount.clone(),
                        to: to.clone(),
                    },
                );
            }
            retirement.completed = Some(Completed { target, retired });
            if let Some(control) =
                self.sdk_hosts
                    .remove(&self.sdk_host_key(&plan.namespace, &plan.mount, &plan.owner))
            {
                control.retire();
            }
            Ok(response)
        })();
        result.unwrap_or_else(|error| {
            plan.control.retire();
            error
        })
    }
    pub(super) fn sdk_retirement_delivery_gate(&self, plan: &Plan) -> Result<(), Response> {
        let scope = plan
            .retirement
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement scope unavailable"))?
            .lock()
            .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?;
        let complete = scope
            .completed
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement terminal publication missing"))?;
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement server sealed"))?;
        if Instant::now() >= plan.deadline
            || self.recovery_required
            || state
                .engines
                .sdk_mount_binding(&plan.namespace, &plan.mount)
                .is_some()
            || state
                .engines
                .sdk_descriptor(&plan.owner.plugin, &plan.owner.version)
                != Some(plan.descriptor.clone())
        {
            return Err(Response::error(
                503,
                "SDK retirement original terminal owner changed",
            ));
        }
        if let Some((mount, owner)) = &complete.target
            && state.engines.sdk_mount_binding(&plan.namespace, mount)
                != Some((mount.clone(), owner.clone()))
        {
            return Err(Response::error(
                503,
                "SDK retirement target incarnation changed",
            ));
        }
        for (id, expected) in &complete.retired {
            let lease = state
                .engines
                .sdk_lease(&plan.namespace, id)
                .ok_or_else(|| Response::error(503, "SDK retirement retained owner missing"))?;
            if lease.phase != Phase::Revoked || digest(&lease)? != *expected {
                return Err(Response::error(
                    503,
                    "SDK retirement retained lease owner changed",
                ));
            }
        }
        Ok(())
    }
}
