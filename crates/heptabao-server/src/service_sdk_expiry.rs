//! Native cleanup is confined to an already authenticated typed lease. It has
//! no Principal and may only run that original backend's Revoke callback.
use super::*;
use crate::auth::Timestamp;
use crate::engines::sdk_lease::{Lease, Phase};

pub(super) enum Authority {
    Client(Box<plugin::PluginResponseAuthority>),
    Admitted(Box<AdmittedAuthority>),
    Cleanup(Box<CleanupAuthority>),
}
impl From<plugin::PluginResponseAuthority> for Authority {
    fn from(value: plugin::PluginResponseAuthority) -> Self {
        Self::Client(Box::new(value))
    }
}
impl Authority {
    pub(super) fn principal(&self) -> Result<&Principal, Response> {
        match self {
            Self::Client(value) => Ok(value.principal()),
            Self::Admitted(value) if value.strict_secret => Ok(value.client.principal()),
            Self::Admitted(_) => Err(Response::error(
                502,
                "SDK Data admission cannot issue a Secret",
            )),
            Self::Cleanup(_) => Err(Response::error(502, "SDK cleanup cannot register a Secret")),
        }
    }
    pub(super) fn now(&self) -> u64 {
        match self {
            Self::Client(value) => value.now(),
            Self::Admitted(value) => value.client.now(),
            Self::Cleanup(value) => value
                .clock
                .observed_at()
                .map_or(value.admitted_at, Timestamp::seconds),
        }
    }
    pub(super) fn token_time(&self) -> Result<AuthorityTime, Response> {
        match self {
            Self::Client(value) => value.token_time(),
            Self::Admitted(value) => value.client.token_time(),
            Self::Cleanup(value) => value
                .clock
                .observed_at()
                .map(AuthorityTime::Precise)
                .map_err(|_| Response::error(503, "SDK cleanup original clock unavailable")),
        }
    }
    pub(super) fn observe_candidate_time_changed(
        &self,
        state: &mut State,
    ) -> Result<bool, Response> {
        match self {
            Self::Client(value) => value.observe_candidate_time_changed(state),
            Self::Admitted(value) => value.client.observe_candidate_time_changed(state),
            Self::Cleanup(_) => Ok(false),
        }
    }
    pub(super) fn validate_live_auth(&self, auth: &AuthState) -> Result<(), Response> {
        match self {
            Self::Client(value) => value.validate_live_auth(auth),
            Self::Admitted(value) if value.strict_secret => value.client.validate_live_auth(auth),
            Self::Admitted(value) => value.check_deadline(),
            Self::Cleanup(value) => value.check_deadline(),
        }
    }
    pub(super) fn admitted_data(&self) -> bool {
        matches!(self, Self::Admitted(value) if !value.strict_secret)
    }
    pub(super) fn require_secret_authority(&mut self) {
        if let Self::Admitted(value) = self {
            // The Data continuation never creates lease authority. Retain the
            // same original client object for the existing Secret path.
            value.strict_secret = true;
        }
    }
    pub(super) fn after_lease_commit(&mut self, state: &State) -> Result<(), Response> {
        let Self::Cleanup(value) = self else {
            return Ok(());
        };
        let current = state
            .engines
            .sdk_lease(&value.record.namespace, &value.record.id)
            .ok_or_else(|| Response::error(503, "SDK cleanup terminal record missing"))?;
        let mut expected = value.record.clone();
        expected.revoke();
        if digest(&current)? != digest(&expected)? {
            return Err(Response::error(503, "SDK cleanup terminal owner changed"));
        }
        value.record = current;
        value.terminal = true;
        Ok(())
    }
}
/// Affine entrance receipt for ordinary standard SDK Data requests. The
/// original client was authenticated, authorized and consumed before moving
/// here. Later Auth graph changes are retained; no Principal is reconstructed.
pub(super) struct AdmittedAuthority {
    client: Box<plugin::PluginResponseAuthority>,
    namespace: String,
    namespace_catalog_required: bool,
    namespace_incarnation: Option<u64>,
    binding: namespace_runtime::DeliveryBinding,
    cluster: String,
    activation: String,
    ha: Option<Arc<Mutex<HaProcess>>>,
    deadline: Instant,
    strict_secret: bool,
}
impl AdmittedAuthority {
    pub(super) fn capture(
        client: Box<plugin::PluginResponseAuthority>,
        state: &State,
        request: &RequestView<'_>,
        activation: &str,
        ha: Option<Arc<Mutex<HaProcess>>>,
        deadline: Instant,
    ) -> Result<Self, Response> {
        if request.token_clock.is_none()
            || !matches!(client.token_time()?, AuthorityTime::Precise(_))
        {
            return Err(Response::error(
                503,
                "SDK entrance precise clock unavailable",
            ));
        }
        let value = Self {
            client,
            namespace: request.namespace.into(),
            namespace_catalog_required: request.enforce_namespace,
            namespace_incarnation: state.namespaces.incarnation(request.namespace),
            binding: namespace_runtime::DeliveryBinding::capture(state, request.namespace),
            cluster: state.cluster_id.clone(),
            activation: activation.into(),
            ha,
            deadline,
            strict_secret: false,
        };
        value.check_deadline()?;
        Ok(value)
    }
    fn check_deadline(&self) -> Result<(), Response> {
        self.client.token_time()?;
        if Instant::now() >= self.deadline {
            return Err(Response::error(
                503,
                "SDK admitted original deadline expired",
            ));
        }
        Ok(())
    }
}
fn digest(record: &Lease) -> Result<[u8; 32], Response> {
    let bytes = crate::secret_serde::to_vec(record, 512 * 1024)
        .map_err(|_| Response::error(503, "SDK cleanup owner serialization failed"))?;
    Ok(crypto::digest(&bytes))
}
pub(super) fn precise(authority: &Authority, state: &State) -> Result<Timestamp, Response> {
    let at = state
        .auth
        .token_api_observed_time(authority.token_time()?)
        .exact()
        .ok_or_else(|| Response::error(503, "SDK original precise clock unavailable"))?;
    Ok(state
        .engines
        .sdk_lease_clock_floor()
        .map_or(at, |floor| at.max(floor)))
}
pub(super) struct CleanupAuthority {
    record: Lease,
    namespace_incarnation: Option<u64>,
    binding: namespace_runtime::DeliveryBinding,
    cluster: String,
    activation: String,
    ha: Option<Arc<Mutex<HaProcess>>>,
    clock: RequestClock,
    admitted_at: u64,
    deadline: Instant,
    terminal: bool,
}
impl CleanupAuthority {
    fn check_deadline(&self) -> Result<(), Response> {
        self.clock
            .observed_at()
            .map_err(|_| Response::error(503, "SDK cleanup original clock unavailable"))?;
        if Instant::now() >= self.deadline {
            return Err(Response::error(
                503,
                "SDK cleanup original deadline expired",
            ));
        }
        Ok(())
    }
}
impl Service {
    pub(super) fn validate_sdk_authority(
        &mut self,
        authority: &mut Authority,
    ) -> Result<(), Response> {
        match authority {
            Authority::Client(value) => self.validate_plugin_response(value),
            Authority::Admitted(value) => {
                if value.strict_secret {
                    return self.validate_plugin_response(&mut value.client);
                }
                value.check_deadline()?;
                if self.recovery_required
                    || self.audit_failed
                    || self.unseal_nonce != value.activation
                {
                    return Err(Response::error(503, "SDK admitted activation unavailable"));
                }
                match (&self.ha, &value.ha) {
                    (Some(current), Some(original)) if Arc::ptr_eq(current, original) => {
                        let node = current.lock_for_request().map_err(|_| {
                            Response::error(503, "SDK admitted HA owner unavailable")
                        })?;
                        if node
                            .leader()
                            .map_err(|_| Response::error(503, "SDK admitted leader unavailable"))?
                            != Some(node.local_id().map_err(|_| {
                                Response::error(503, "SDK admitted node unavailable")
                            })?)
                        {
                            return Err(Response::error(
                                503,
                                "SDK admitted requires current leader",
                            ));
                        }
                        drop(node);
                        self.sync_from_ha_with_anchor(false)?;
                    }
                    (None, None) => {}
                    _ => return Err(Response::error(503, "SDK admitted HA owner changed")),
                }
                let state = self
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK admitted server sealed"))?;
                if state.cluster_id != value.cluster
                    || (value.namespace_catalog_required
                        && !state.namespace_exists(&value.namespace))
                    || state.namespace_is_sealed(&value.namespace)
                    || (state.namespaces.inherited_owner(&value.namespace).is_some()
                        && !self.namespace_runtime.is_loaded(&value.namespace))
                    || state.namespaces.incarnation(&value.namespace) != value.namespace_incarnation
                    || namespace_runtime::DeliveryBinding::capture(state, &value.namespace)
                        != value.binding
                {
                    return Err(Response::error(503, "SDK admitted namespace owner changed"));
                }
                value.check_deadline()
            }
            Authority::Cleanup(value) => {
                value.check_deadline()?;
                if self.recovery_required
                    || self.audit_failed
                    || self.unseal_nonce != value.activation
                {
                    return Err(Response::error(503, "SDK cleanup activation unavailable"));
                }
                match (&self.ha, &value.ha) {
                    (Some(current), Some(original)) if Arc::ptr_eq(current, original) => {
                        let node = current.lock_for_request().map_err(|_| {
                            Response::error(503, "SDK cleanup HA owner unavailable")
                        })?;
                        if node
                            .leader()
                            .map_err(|_| Response::error(503, "SDK cleanup leader unavailable"))?
                            != Some(node.local_id().map_err(|_| {
                                Response::error(503, "SDK cleanup node unavailable")
                            })?)
                        {
                            return Err(Response::error(
                                503,
                                "SDK cleanup requires current leader",
                            ));
                        }
                        drop(node);
                        self.sync_from_ha_with_anchor(false)?;
                    }
                    (None, None) => {}
                    _ => return Err(Response::error(503, "SDK cleanup HA owner changed")),
                }
                let state = self
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK cleanup server sealed"))?;
                let namespace = &value.record.namespace;
                if state.cluster_id != value.cluster
                    || !state.namespace_exists(namespace)
                    || state.namespace_is_sealed(namespace)
                    || (state.namespaces.inherited_owner(namespace).is_some()
                        && !self.namespace_runtime.is_loaded(namespace))
                    || state.namespaces.incarnation(namespace) != value.namespace_incarnation
                    || namespace_runtime::DeliveryBinding::capture(state, namespace)
                        != value.binding
                {
                    return Err(Response::error(503, "SDK cleanup namespace owner changed"));
                }
                let current = state
                    .engines
                    .sdk_lease(namespace, &value.record.id)
                    .ok_or_else(|| Response::error(503, "SDK cleanup lease owner missing"))?;
                if digest(&current)? != digest(&value.record)?
                    || (value.terminal && current.phase != Phase::Revoked)
                    || (!value.terminal && current.phase != Phase::PendingRevoke)
                {
                    return Err(Response::error(503, "SDK cleanup typed lease changed"));
                }
                current
                    .validate(namespace)
                    .map_err(Response::from_engine_error)?;
                if let Some(floor) = state.engines.sdk_lease_clock_floor() {
                    value.clock = value.clock.with_timestamp_floor(floor);
                }
                value.check_deadline()
            }
        }
    }
    pub(in crate::service) fn prepare_sdk_expiry(
        &mut self,
        clock: RequestClock,
    ) -> Result<Option<Plan>, Response> {
        if self.sdk_configuration.is_none() || self.state.is_none() {
            return Ok(None);
        }
        if self.pending_sdk_request.is_some() || self.recovery_required || self.audit_failed {
            return Ok(None);
        }
        if let Some(ha) = &self.ha {
            let node = ha
                .lock_for_request()
                .map_err(|_| Response::error(503, "SDK expiry HA owner unavailable"))?;
            if node
                .leader()
                .map_err(|_| Response::error(503, "SDK expiry leader unavailable"))?
                != Some(
                    node.local_id()
                        .map_err(|_| Response::error(503, "SDK expiry node unavailable"))?,
                )
            {
                return Ok(None);
            }
            drop(node);
            self.sync_from_ha_with_anchor(false)?;
        }
        let mut state = self
            .state
            .clone()
            .ok_or_else(|| Response::error(503, "SDK expiry state unavailable"))?;
        let at = clock
            .observed_at()
            .map_err(|_| Response::error(503, "SDK expiry original clock unavailable"))?;
        let at = state
            .engines
            .sdk_lease_clock_floor()
            .map_or(at, |floor| at.max(floor));
        let after = self
            .sdk_cleanup_cursor
            .as_ref()
            .map(|(namespace, id)| (namespace.as_str(), id.as_str()));
        let Some(mut record) = state.engines.sdk_cleanup_candidate(&state.auth, at, after) else {
            return Ok(None);
        };
        self.sdk_cleanup_cursor = Some((record.namespace.clone(), record.id.clone()));
        let namespace = record.namespace.clone();
        if !state.namespace_exists(&namespace)
            || state.namespace_is_sealed(&namespace)
            || (state.namespaces.inherited_owner(&namespace).is_some()
                && !self.namespace_runtime.is_loaded(&namespace))
        {
            return Ok(None);
        }
        let Some((mount, owner)) = state
            .engines
            .sdk_mount_binding(&namespace, &record.mount)
            .filter(|(m, o)| m == &record.mount && record.same_backend(o))
        else {
            return Ok(None);
        };
        let key = self.sdk_host_key(&namespace, &mount, &owner);
        if self.sdk_hosts.get(&key).is_some_and(|control| {
            control.busy.load(Ordering::Acquire) || control.retiring.load(Ordering::Acquire)
        }) {
            return Ok(None);
        }
        if self
            .sdk_hosts
            .get(&key)
            .is_some_and(|control| control.fenced.load(Ordering::Acquire))
            && let Some(control) = self.sdk_hosts.remove(&key)
        {
            control.retire();
        }
        let config = self
            .sdk_configuration
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK expiry configuration unavailable"))?;
        let deadline = (clock.started() + Duration::from_millis(config.timeout_ms)).min(
            crate::request_deadline::current()
                .unwrap_or(clock.started() + Duration::from_millis(config.timeout_ms)),
        );
        if Instant::now() >= deadline {
            return Err(Response::error(503, "SDK expiry original deadline expired"));
        }
        let fingerprint =
            self.request_fingerprint("INTERNAL", "sdk-lifecycle/revoke", &namespace, "");
        self.audit_event("sdk-lifecycle-request", &fingerprint, at.seconds(), None)
            .map_err(|_| Response::error(503, "SDK cleanup request audit failed"))?;
        record.phase = Phase::PendingRevoke;
        state.engines.observe_sdk_lease_clock(at);
        state
            .engines
            .store_sdk_lease(record.clone())
            .map_err(Response::from_engine_error)?;
        state.schema = state.writer_schema();
        let identity = self.current_state_identity()?;
        let publication = self.prepare_record_plan(&mut state)?;
        if self.current_state_identity()? != identity || Instant::now() >= deadline {
            return Err(Response::error(503, "SDK expiry candidate changed"));
        }
        self.commit_record_plan_with_before_publish(
            &state,
            publication,
            |_| {
                clock
                    .observed_at()
                    .map_err(|_| Response::error(503, "SDK expiry original clock unavailable"))?;
                if Instant::now() >= deadline {
                    return Err(Response::error(
                        503,
                        "SDK expiry publication deadline expired",
                    ));
                }
                Ok(())
            },
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )?;
        self.state = Some(state.clone());
        let cleanup = CleanupAuthority {
            record: record.clone(),
            namespace_incarnation: state.namespaces.incarnation(&namespace),
            binding: namespace_runtime::DeliveryBinding::capture(&state, &namespace),
            cluster: state.cluster_id.clone(),
            activation: self.unseal_nonce.clone(),
            ha: self.ha.clone(),
            clock: clock.with_timestamp_floor(at),
            admitted_at: at.seconds(),
            deadline,
            terminal: false,
        };
        let body = json!({});
        let path = record.path.strip_prefix(&mount).unwrap_or("").to_owned();
        let request_path = record.path.clone();
        let request = RequestView {
            method: "INTERNAL",
            path: &request_path,
            namespace: &namespace,
            token: "",
            body: &body,
            now: at.seconds(),
            admission_started: clock.started(),
            token_clock: Some(clock),
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        };
        let response = self.stage_sdk_plan(
            &state,
            Authority::Cleanup(Box::new(cleanup)),
            &request,
            StageTarget {
                mount,
                owner,
                operation: "revoke",
                path: &path,
                lease: Some(secret_lease::LeaseCall {
                    record,
                    action: "revoke",
                    increment_ns: 0,
                }),
            },
        );
        let Some(mut plan) = self.pending_sdk_request.take() else {
            return Err(response);
        };
        plan.deadline = plan.deadline.min(deadline);
        Ok(Some(plan))
    }
    pub(in crate::service) fn finish_sdk_expiry(
        &mut self,
        mut plan: Plan,
        result: Result<Option<Value>, Response>,
    ) -> Result<(), Response> {
        let response = self.finalize_sdk_request(&mut plan, result);
        let now = plan
            .authority
            .lock()
            .map_err(|_| Response::error(503, "SDK expiry authority unavailable"))?
            .now();
        let fingerprint =
            self.request_fingerprint("INTERNAL", "sdk-lifecycle/revoke", &plan.namespace, "");
        if self
            .audit_event(
                "sdk-lifecycle-response",
                &fingerprint,
                now,
                Some(response.status),
            )
            .is_err()
        {
            self.recovery_required = true;
            self.ha_activation = None;
            self.retire_sdk_hosts();
            return Err(Response::error(
                503,
                "SDK expiry response audit failed; recovery required",
            ));
        }
        let mut response = self.complete_sdk_delivery(&mut plan, response, &fingerprint);
        let success = response.status == 204;
        erase_json(&mut response.body);
        response.response_headers.clear();
        response.consistency_index = None;
        if success {
            Ok(())
        } else {
            Err(Response::error(503, "SDK expiry revoke remains pending"))
        }
    }
}
