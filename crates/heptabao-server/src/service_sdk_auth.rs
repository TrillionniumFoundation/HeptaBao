//! The real SDK credential family uses the original Service admission and
//! encrypted auth owner. Plugin JSON never becomes a Principal or bearer.
use super::*;
use crate::auth::Timestamp;
use crate::auth::sdk::{Binding, Entry, Paths, RenewalTarget, StorageWitness};
use heptabao_plugin_host::sdk_backend::SdkBackendType;
#[path = "service_sdk_credential.rs"]
mod credential;
#[path = "service_sdk_auth_retirement.rs"]
mod retirement;
pub(in crate::service) use retirement::RecoveryWork;

struct Context {
    namespace: String,
    incarnation: Option<u64>,
    delivery: namespace_runtime::DeliveryBinding,
    cluster: String,
    activation: String,
    ha: Option<Arc<Mutex<HaProcess>>>,
    clock: RequestClock,
    namespace_required: bool,
}
struct StageTarget<'a> {
    binding: Binding,
    caller: Option<plugin::PluginResponseAuthority>,
    context: Context,
    operation: &'a str,
    path: &'a str,
    deadline: Instant,
    renewal: Option<RenewalTarget>,
    retirement: Option<retirement::Retirement>,
}
/// Minted only by stage_sdk_auth after the actual entrance authentication,
/// consumed use, parameter ACL and SpecialPaths authorization. The moved
/// authority is retained, never cloned or reconstructed from plugin JSON.
struct Admission {
    authority: Mutex<plugin::PluginResponseAuthority>,
    backend: Arc<Control>,
    storage: Mutex<StorageWitness>,
    entry: Option<crate::auth::AcceptedSdkLeaseIssuer>,
    accepted: Timestamp,
    final_use: bool,
}
impl Admission {
    fn clock_and_deadline(&self, auth: &AuthState) -> Result<(), Response> {
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| Response::error(503, "SDK admitted authority unavailable"))?;
        if authority.deadline_expired() {
            return Err(Response::error(503, "SDK admitted HTTP deadline expired"));
        }
        authority.apply_sdk_auth_clock_floor(auth)?;
        authority.token_time()?;
        if authority.deadline_expired() {
            return Err(Response::error(503, "SDK admitted HTTP deadline expired"));
        }
        Ok(())
    }
    fn owned_storage(&self, auth: &AuthState, binding: &Binding) -> Result<(), Response> {
        self.storage
            .lock()
            .map_err(|_| Response::error(503, "SDK admitted Storage observation unavailable"))?
            .check(auth, binding)
            .map_err(auth_error)
    }
    fn published(&self, auth: &AuthState, binding: &Binding) -> Result<(), Response> {
        let current = auth.sdk_auth_storage_witness(binding).map_err(auth_error)?;
        *self
            .storage
            .lock()
            .map_err(|_| Response::error(503, "SDK admitted Storage observation unavailable"))? =
            current;
        Ok(())
    }
}
/// This terminal classification is used only after the original admitted
/// credential operation has passed its current owned Storage gates. It carries
/// no authentication authority and can never issue a token.
enum AdmittedTerminal {
    Data,
    UnexpectedAuth,
}
// Paired with the same moved control authority through mandatory audit. This
// projection never contains a Secret or a new Principal.
pub(in crate::service) struct CredentialList {
    binding: Binding,
    prefix: String,
    keys: BTreeSet<String>,
}
impl CredentialList {
    fn check(&self, auth: &AuthState) -> Result<(), Response> {
        let actual = auth
            .sdk_credential_lease_keys(&self.binding, &self.prefix)
            .map_err(auth_error)?;
        if actual != self.keys {
            return Err(Response::error(
                503,
                "SDK credential lease list owner changed",
            ));
        }
        Ok(())
    }
}
struct Transaction {
    auth: CowOwner<AuthState>,
    namespace_original: Option<namespace_sdk_cleanup::CredentialStorageCut>,
    identity: crate::state_record_root::StateIdentity,
}
pub(in crate::service) struct Plan {
    context: Context,
    wrapping: Option<sdk_wrapping::Owner>,
    binding: Binding,
    paths: Option<Paths>,
    caller: Mutex<Option<plugin::PluginResponseAuthority>>,
    admission: Option<Admission>,
    control: Arc<Control>,
    transaction: Mutex<Transaction>,
    operation: String,
    path: String,
    data: Value,
    logical_data: Option<crate::request_metadata::DataFrame>,
    pub(in crate::service) deadline: Instant,
    renewal: Mutex<Option<Box<RenewalTarget>>>,
    lease: Mutex<Option<credential::Call>>,
    cleanup: Mutex<Option<credential::Cleanup>>,
    retirement: Option<Mutex<retirement::Retirement>>,
    namespace_cleanup: bool,
    private_retirement: Mutex<Option<namespace_runtime::RetirementPermit>>,
    private_cleanup: Mutex<Option<namespace_runtime::CleanupPermit>>,
}
impl Drop for Plan {
    fn drop(&mut self) {
        erase_json(&mut self.data)
    }
}
impl Plan {
    fn namespace_native_role(
        &self,
        service: &Service,
    ) -> Result<Option<namespace_sdk_cleanup::NativeRole>, Response> {
        let cleanup = self
            .cleanup
            .lock()
            .map_err(|_| Response::error(503, "SDK credential cleanup unavailable"))?;
        let role = cleanup
            .as_ref()
            .and_then(credential::Cleanup::namespace_work)
            .map(|work| work.credential_native_role(service, &self.binding))
            .transpose()?;
        if self.namespace_cleanup != role.is_some() {
            return Err(Response::error(
                503,
                "namespace SDK credential authority scope changed",
            ));
        }
        // The guard is released before any live_auth/sdk_auth_gate publication closure.
        Ok(role)
    }
    fn namespace_storage_cut(
        &self,
        service: &Service,
    ) -> Result<Option<namespace_sdk_cleanup::CredentialStorageCut>, Response> {
        let cleanup = self
            .cleanup
            .lock()
            .map_err(|_| Response::error(503, "SDK credential cleanup unavailable"))?;
        cleanup
            .as_ref()
            .and_then(credential::Cleanup::namespace_work)
            .map(|work| work.credential_storage_cut(service, &self.binding))
            .transpose()
    }
    pub(in crate::service) fn execute(
        &self,
        service: &Arc<Mutex<Service>>,
        deadline: Instant,
    ) -> Result<Option<Value>, Response> {
        let deadline = deadline.min(self.deadline);
        if self.retirement.is_some() {
            return self.execute_retirement(service, deadline);
        }
        self.execute_once(service, deadline)
    }
    fn execute_once(
        &self,
        service: &Arc<Mutex<Service>>,
        deadline: Instant,
    ) -> Result<Option<Value>, Response> {
        let deadline = deadline.min(self.deadline);
        if self.control.fenced.load(Ordering::Acquire)
            || Instant::now() >= deadline
            || (self.control.retiring.load(Ordering::Acquire)
                && self.retirement.is_none()
                && !self.namespace_cleanup)
        {
            return Err(Response::error(
                503,
                "SDK Auth original owner or deadline unavailable",
            ));
        }
        let native_retirement = self.has_native_retirement()?;
        if self.namespace_cleanup || native_retirement {
            let mut writer = writer_before(service, deadline)?;
            writer.sdk_auth_gate(self)?;
        }
        let auth = self
            .renewal
            .lock()
            .map_err(|_| Response::error(503, "SDK renewal target unavailable"))?
            .as_ref()
            .map(|target| {
                let transaction = self
                    .transaction
                    .lock()
                    .map_err(|_| Response::error(503, "SDK renewal transaction unavailable"))?;
                let (auth, issue_time_ns, increment_ns) = target
                    .input(&transaction.auth, self.context.clock)
                    .map_err(auth_error)?;
                Ok(Box::new(SdkAuthCallback {
                    auth,
                    issue_time_ns,
                    increment_ns,
                }))
            })
            .transpose()?;
        if self
            .control
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Response::error(503, "SDK Auth mount is busy before entry"));
        }
        if self.control.retiring.load(Ordering::Acquire)
            && self.retirement.is_none()
            && !self.namespace_cleanup
        {
            self.control.busy.store(false, Ordering::Release);
            return Err(Response::error(
                409,
                "SDK Auth retirement blocks an old invocation",
            ));
        }
        if native_retirement {
            let result =
                writer_before(service, deadline).and_then(|mut writer| writer.sdk_auth_gate(self));
            if let Err(error) = result {
                self.control.busy.store(false, Ordering::Release);
                return Err(error);
            }
        }
        let (events, received) = mpsc::channel();
        let path = if self.retirement.is_some() {
            let lease = self
                .lease
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement callback unavailable"))?;
            let call = lease
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement callback absent"))?;
            call.record
                .path
                .strip_prefix(&call.record.mount)
                .ok_or_else(|| Response::error(503, "SDK retirement callback path owner changed"))?
                .to_owned()
        } else {
            self.path.clone()
        };
        let job = WorkerJob {
            operation: self.operation.clone(),
            path,
            data: self.data.clone(),
            logical_data: self.logical_data.clone(),
            lease: self
                .lease
                .lock()
                .map_err(|_| Response::error(503, "SDK credential callback unavailable"))?
                .as_ref()
                .map(credential::Call::callback)
                .transpose()?,
            auth,
            expected_auth_paths: if self.operation == "_mount" {
                None
            } else {
                Some(self.paths.clone().unwrap_or_else(Paths::legacy).wire())
            },
            deadline,
            events,
        };
        let private = (|| {
            let retirement = self
                .private_retirement
                .lock()
                .map_err(|_| Response::error(503, "SDK private original permit unavailable"))?
                .is_some();
            let cleanup = self
                .private_cleanup
                .lock()
                .map_err(|_| Response::error(503, "SDK private cleanup permit unavailable"))?
                .is_some();
            if retirement && cleanup {
                return Err(Response::error(503, "SDK private scopes overlap"));
            }
            Ok(retirement || cleanup)
        })();
        let original_private = match private {
            Ok(value) => value,
            Err(error) => {
                self.control.busy.store(false, Ordering::Release);
                self.control.retire();
                return Err(error);
            }
        };
        if original_private {
            let dispatch = (|| {
                let mut writer = writer_before(service, deadline)?;
                writer.sdk_auth_gate(self)?;
                let retirement = self
                    .private_retirement
                    .lock()
                    .map_err(|_| Response::error(503, "SDK original permit unavailable"))?;
                let cleanup = self
                    .private_cleanup
                    .lock()
                    .map_err(|_| Response::error(503, "SDK original cleanup unavailable"))?;
                if retirement
                    .as_ref()
                    .map(|permit| permit.handed_off())
                    .transpose()?
                    .unwrap_or(false)
                    || cleanup
                        .as_ref()
                        .map(|permit| permit.handed_off())
                        .transpose()?
                        .unwrap_or(false)
                {
                    return Err(Response::error(
                        503,
                        "sealed SDK callback cannot be redispatched",
                    ));
                }
                if self
                    .control
                    .sender
                    .try_send(WorkerCommand::Invoke(Box::new(job)))
                    .is_err()
                {
                    return Err(Response::error(503, "SDK Auth owner queue unavailable"));
                }
                if let Some(permit) = retirement.as_ref() {
                    permit.dispatched();
                }
                if let Some(permit) = cleanup.as_ref() {
                    permit.dispatched();
                }
                Ok(())
            })();
            if let Err(error) = dispatch {
                self.control.busy.store(false, Ordering::Release);
                self.control.retire();
                return Err(error);
            }
        } else if self
            .control
            .sender
            .try_send(WorkerCommand::Invoke(Box::new(job)))
            .is_err()
        {
            self.control.busy.store(false, Ordering::Release);
            return Err(Response::error(503, "SDK Auth owner queue unavailable"));
        }
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                self.control.retire();
                return Err(Response::error(503, "SDK Auth original deadline expired"));
            };
            match received.recv_timeout(remaining) {
                Ok(Event::Complete(value)) => return value.map_err(bridge_failure),
                Ok(Event::Storage(op, reply)) => {
                    let result = writer_before(service, deadline)
                        .and_then(|mut writer| writer.sdk_auth_storage(self, op))
                        .map_err(|_| SdkBridgeError::Fenced);
                    if matches!(
                        result,
                        Err(SdkBridgeError::OutcomeUnknown | SdkBridgeError::Fenced)
                    ) {
                        self.control.retire()
                    }
                    if reply.send(result).is_err() {
                        self.control.retire();
                        return Err(Response::error(
                            503,
                            "SDK Auth Storage acknowledgement outcome unknown",
                        ));
                    }
                }
                Err(_) => {
                    self.control.retire();
                    return Err(Response::error(
                        503,
                        "SDK Auth owned execution outcome unavailable",
                    ));
                }
            }
        }
    }
    fn time(&self, auth: &AuthState) -> Result<Timestamp, Response> {
        let clock = auth
            .sdk_auth_clock_floor()
            .map_or(self.context.clock, |floor| {
                self.context.clock.with_timestamp_floor(floor)
            });
        auth.token_api_observed_time(AuthorityTime::Precise(
            clock
                .observed_at()
                .map_err(|_| Response::error(503, "SDK Auth original clock unavailable"))?,
        ))
        .exact()
        .ok_or_else(|| Response::error(503, "SDK Auth original precise observation unavailable"))
    }
    fn live_auth(&self, auth: &AuthState) -> Result<(), Response> {
        if Instant::now() >= self.deadline {
            return Err(Response::error(
                503,
                "SDK Auth original deadline expired before publication",
            ));
        }
        auth.sdk_auth_owner_gate(&self.binding)
            .map_err(auth_error)?;
        if let Some(admission) = &self.admission {
            admission.clock_and_deadline(auth)?;
        } else if let Some(caller) = self
            .caller
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth original capsule unavailable"))?
            .as_mut()
        {
            caller.apply_sdk_auth_clock_floor(auth)?;
            caller.validate_live_auth(auth)?;
        }
        if self.retirement.is_none() && auth.sdk_auth_retirement_tainted(&self.binding) {
            return Err(Response::error(
                409,
                "SDK Auth durable retirement blocks delivery",
            ));
        }
        self.check_retirement_control(auth)?;
        self.time(auth)?;
        self.credential_owner_gate(auth)?;
        self.live_target(auth)?;
        Ok(())
    }
    fn credential_owner_gate(&self, auth: &AuthState) -> Result<(), Response> {
        let lease = self
            .lease
            .lock()
            .map_err(|_| Response::error(503, "SDK credential callback unavailable"))?;
        if let Some(call) = lease.as_ref() {
            call.check(auth, self.time(auth)?)?;
            if let Some(cleanup) = self
                .cleanup
                .lock()
                .map_err(|_| Response::error(503, "SDK credential cleanup unavailable"))?
                .as_ref()
            {
                cleanup.check(call)?;
                cleanup.check_auth(auth)?;
            }
        }
        Ok(())
    }
    fn live_target(&self, auth: &AuthState) -> Result<(), Response> {
        if let Some(target) = self
            .renewal
            .lock()
            .map_err(|_| Response::error(503, "SDK renewal target unavailable"))?
            .as_ref()
        {
            auth.sdk_renewal_gate(target, self.context.clock)
                .map_err(auth_error)?;
        }
        Ok(())
    }
}
fn auth_error(error: crate::auth::AuthError) -> Response {
    Response::error(error.status, &error.message)
}
pub(in crate::service) fn sdk_auth_key(
    cluster: &str,
    binding: &Binding,
) -> Result<String, Response> {
    let data = serde_json::to_vec(&(cluster, binding))
        .map_err(|_| Response::error(503, "SDK Auth host identity encoding failed"))?;
    Ok(format!("AUTH:{}", hex(&crypto::digest(&data))))
}
fn empty_response() -> Response {
    Response {
        status: 204,
        body: json!({}),
        unwrapped_json: None,
        response_headers: Default::default(),
        consistency_index: None,
    }
}
fn has_sdk_owner(auth: &AuthState, namespace: &str, mount: &str) -> bool {
    // Candidate discovery is deliberately separate from the owner proof.
    // A malformed retained owner is still routed here and fails closed.
    auth.sdk_auth_owned_mount(namespace, mount)
}
impl Service {
    pub(in crate::service) fn sdk_auth_handles(
        &self,
        state: &State,
        request: &RequestView<'_>,
    ) -> bool {
        if request.path == "sys/plugins/catalog/auth"
            || request.path.starts_with("sys/plugins/catalog/auth/")
        {
            return self.sdk_configuration.is_some() || state.auth.has_sdk_auth_state();
        }
        if let Some(mount) = request.path.strip_prefix("sys/auth/") {
            if has_sdk_owner(
                &state.auth,
                request.namespace,
                mount.trim_end_matches('/').trim_end_matches("/tune"),
            ) {
                return true;
            }
            if matches!(request.method, "POST" | "PUT") {
                let name = request
                    .body
                    .get("plugin_name")
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty())
                    .or_else(|| request.body.get("type").and_then(Value::as_str))
                    .unwrap_or("");
                let version = request
                    .body
                    .get("config")
                    .and_then(|c| c.get("plugin_version"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                return state.auth.sdk_auth_descriptor(name, version).is_some();
            }
        }
        if state
            .auth
            .sdk_renewal_binding(request.namespace, request.path, request.body, request.token)
            .is_some()
        {
            return true;
        }
        matches!(
            state.auth.sdk_auth_binding(request.namespace, request.path),
            Ok(Some(_)) | Err(_)
        )
    }
    pub(in crate::service) fn sdk_auth_route(
        &mut self,
        mut state: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(clock) = request.token_clock else {
            return Response::error(503, "SDK Auth requires the original trusted request clock");
        };
        let Some(config) = self.sdk_configuration.clone() else {
            return Response::error(503, "SDK Auth runtime is not configured");
        };
        let deadline = crate::request_deadline::current()
            .unwrap_or(request.admission_started + Duration::from_millis(config.timeout_ms));
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        let clock = match clock.with_seconds_floor(request.now) {
            Ok(c) => c,
            Err(_) => return Response::error(503, "SDK Auth original clock rejected"),
        };
        let catalog = request.path == "sys/plugins/catalog/auth"
            || request.path.starts_with("sys/plugins/catalog/auth/");
        let control = catalog || request.path.starts_with("sys/auth/");
        let renewing = matches!(
            request.path,
            "auth/token/renew-self" | "auth/token/renew" | "auth/token/renew-accessor"
        );
        if renewing && !matches!(request.method, "POST" | "PUT") {
            return Response::error(405, "SDK token renewal requires POST or PUT");
        }
        let relative = if renewing {
            match state.auth.sdk_renewal_binding(
                request.namespace,
                request.path,
                request.body,
                request.token,
            ) {
                Some(binding) => Some(binding),
                None => return Response::error(403, "SDK renewal target unavailable"),
            }
        } else if control {
            None
        } else {
            match state.auth.sdk_auth_binding(request.namespace, request.path) {
                Ok(Some(b)) => Some(b),
                Ok(None) => return Response::error(404, "SDK Auth mount not found"),
                Err(e) => return auth_error(e),
            }
        };
        let path_policy = match relative.as_ref().filter(|_| !renewing) {
            Some(binding) => match state.auth.sdk_auth_paths(binding) {
                Ok(paths) => Some(paths.unwrap_or_else(Paths::legacy)),
                Err(error) => return auth_error(error),
            },
            None => None,
        };
        let relative_path = relative.as_ref().filter(|_| !renewing).and_then(|binding| {
            request
                .path
                .strip_prefix(&format!("auth/{}/", binding.mount))
        });
        let effective_path = relative_path
            .map(|path| heptabao_plugin_contracts::sdk_paths::request_path(path, request.method));
        let relative_path = effective_path.as_deref();
        let root_path = path_policy
            .as_ref()
            .zip(relative_path)
            .is_some_and(|(policy, path)| policy.is_root(path));
        let login = path_policy
            .as_ref()
            .zip(relative_path)
            .is_some_and(|(policy, path)| policy.is_public(path));
        if login && root_path {
            return Response::error(400, "cannot access root path in unauthenticated request");
        }
        let capability = match request.method {
            "GET" | "HEAD" => "read",
            "LIST" | "SCAN" => "list",
            "DELETE" => "delete",
            _ => "update",
        };
        let expected = match self.current_state_identity() {
            Ok(id) => id,
            Err(error) => return error,
        };
        let mut caller = if login {
            None
        } else {
            let Some(principal) = principal else {
                return Response::error(403, "missing client token");
            };
            let mut authority = plugin::PluginResponseAuthority::new(
                principal,
                &state,
                request,
                capability,
                control || root_path,
                &self.unseal_nonce,
            )
            .with_sdk_clock();
            if let Err(error) = self.validate_plugin_response(&mut authority) {
                return error;
            }
            Some(authority)
        };
        if self.current_state_identity().as_ref().ok() != Some(&expected) {
            return Response::error(503, "SDK Auth original root changed during admission sync");
        }
        let renewal = if renewing {
            let Some(authority) = caller.as_ref() else {
                return Response::error(403, "SDK renewal original caller absent");
            };
            match state.auth.prepare_sdk_renewal(
                authority.principal(),
                request.namespace,
                request.path,
                request.body,
                request.token,
                clock,
            ) {
                Ok(target) => Some(target),
                Err(error) => return auth_error(error),
            }
        } else {
            None
        };
        // The captured route snapshot must be current after original ACL sync.
        // No candidate may overwrite a newer root after unlocked admission.
        let context = Context {
            namespace: request.namespace.into(),
            incarnation: state.namespaces.incarnation(request.namespace),
            delivery: namespace_runtime::DeliveryBinding::capture(&state, request.namespace),
            cluster: state.cluster_id.clone(),
            activation: self.unseal_nonce.clone(),
            ha: self.ha.clone(),
            clock,
            namespace_required: request.enforce_namespace,
        };
        if catalog {
            if !request.namespace.is_empty() {
                return Response::error(403, "SDK Auth catalog is root-namespace only");
            }
            let suffix = request.path.trim_start_matches("sys/plugins/catalog/auth");
            if suffix.is_empty() {
                if !matches!(request.method, "GET" | "HEAD" | "LIST" | "SCAN") {
                    return Response::error(405, "SDK Auth catalog listing requires GET or LIST");
                }
                self.pending_sdk_control_authority = caller;
                return Response::ok(
                    json!({"data":{"keys":state.auth.sdk_auth_descriptors().into_iter().map(|d|d.name).collect::<BTreeSet<_>>()}}),
                );
            }
            let Some(name) = suffix
                .strip_prefix('/')
                .filter(|n| !n.is_empty() && !n.contains('/'))
            else {
                return Response::error(404, "SDK Auth catalog entry not found");
            };
            let version = request
                .body
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("");
            let response = match request.method {
                "GET" | "HEAD" => {
                    let Some(d) = state.auth.sdk_auth_descriptor(name, version) else {
                        return Response::error(404, "SDK Auth catalog entry not found");
                    };
                    Response::ok(
                        json!({"data":{"name":d.name,"command":d.command,"args":d.args,"sha256":d.sha256,"version":d.version,"builtin":false}}),
                    )
                }
                "POST" | "PUT" => {
                    let Some(object) = request.body.as_object() else {
                        return Response::error(400, "SDK Auth descriptor requires object");
                    };
                    if object.keys().any(|k| {
                        !matches!(
                            k.as_str(),
                            "type" | "command" | "sha256" | "args" | "version"
                        )
                    }) || object
                        .get("type")
                        .is_some_and(|v| v.as_str() != Some("auth") && v.as_u64() != Some(1))
                    {
                        return Response::error(400, "SDK Auth descriptor fields rejected");
                    }
                    if state.namespaces.has_custody_state()
                        && state.auth.sdk_auth_descriptor(name, version).is_some()
                    {
                        return Response::error(
                            409,
                            "SDK Auth replacement requires complete namespace custody proof",
                        );
                    }
                    let args = match object.get("args") {
                        None | Some(Value::Null) => Vec::new(),
                        Some(value) => match serde_json::from_value::<Vec<String>>(value.clone()) {
                            Ok(a) => a,
                            Err(_) => return Response::error(400, "SDK Auth arguments rejected"),
                        },
                    };
                    let descriptor = Descriptor {
                        name: name.into(),
                        version: version.into(),
                        command: object
                            .get("command")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .into(),
                        args,
                        sha256: object
                            .get("sha256")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .into(),
                        generation: 1,
                    };
                    if let Err(e) = state.auth.register_sdk_auth_descriptor(descriptor) {
                        return auth_error(e);
                    }
                    if let Err(e) = self.sdk_auth_commit_control(
                        &mut state,
                        match caller.as_mut() {
                            Some(authority) => authority,
                            None => {
                                return Response::error(
                                    503,
                                    "SDK Auth original control capsule absent",
                                );
                            }
                        },
                        &expected,
                        clock,
                    ) {
                        return e;
                    }
                    self.state = Some(state);
                    empty_response()
                }
                "DELETE" => {
                    if state.namespaces.has_custody_state() {
                        return Response::error(
                            409,
                            "SDK Auth removal requires complete namespace custody proof",
                        );
                    }
                    if let Err(e) = state.auth.deregister_sdk_auth_descriptor(name, version) {
                        return auth_error(e);
                    }
                    if let Err(e) = self.sdk_auth_commit_control(
                        &mut state,
                        match caller.as_mut() {
                            Some(authority) => authority,
                            None => {
                                return Response::error(
                                    503,
                                    "SDK Auth original control capsule absent",
                                );
                            }
                        },
                        &expected,
                        clock,
                    ) {
                        return e;
                    }
                    self.state = Some(state);
                    empty_response()
                }
                _ => Response::error(405, "SDK Auth catalog method unsupported"),
            };
            self.pending_sdk_control_authority = caller;
            return response;
        }
        if let Some(rawmount) = request.path.strip_prefix("sys/auth/") {
            let mount = rawmount.trim_end_matches('/');
            if mount.ends_with("/tune") {
                return Response::error(501, "SDK Auth tune is not implemented");
            }
            if request.method == "DELETE" {
                let binding = match state
                    .auth
                    .sdk_auth_binding(request.namespace, &format!("auth/{mount}/config"))
                {
                    Ok(Some(b)) => b,
                    Ok(None) => return Response::error(404, "SDK Auth mount not found"),
                    Err(e) => return auth_error(e),
                };
                {
                    let Some(authority) = caller.take() else {
                        return Response::error(503, "SDK retirement original caller absent");
                    };
                    return self.stage_sdk_auth_retirement(
                        state, authority, request, binding, context, deadline,
                    );
                }
            }
            if !matches!(request.method, "POST" | "PUT") {
                return Response::error(405, "SDK Auth mount requires POST, PUT or DELETE");
            }
            let name = request
                .body
                .get("plugin_name")
                .and_then(Value::as_str)
                .filter(|n| !n.is_empty())
                .or_else(|| request.body.get("type").and_then(Value::as_str))
                .unwrap_or("");
            let version = request
                .body
                .get("config")
                .and_then(|c| c.get("plugin_version"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let Some(descriptor) = state.auth.sdk_auth_descriptor(name, version) else {
                return Response::error(400, "SDK Auth descriptor not found");
            };
            let mut body = request.body.clone();
            let Some(object) = body.as_object_mut() else {
                return Response::error(400, "SDK Auth mount requires object");
            };
            object.remove("plugin_name");
            if let Some(configuration) = object.remove("config").filter(|v| !v.is_null()) {
                let Some(c) = configuration.as_object() else {
                    return Response::error(400, "SDK Auth config requires object");
                };
                if c.iter().any(|(k, v)| match k.as_str() {
                    "plugin_version" => v.as_str() != Some(version),
                    "plugin_name" => v.as_str().is_none_or(|n| !n.is_empty() && n != name),
                    "default_lease_ttl" | "max_lease_ttl" => v.as_str() != Some(""),
                    "force_no_cache" => v.as_bool() != Some(false),
                    "options" => !v.is_null() && v.as_object().is_none_or(|o| !o.is_empty()),
                    "allowed_response_headers"
                    | "audit_non_hmac_request_keys"
                    | "audit_non_hmac_response_keys" => {
                        !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty())
                    }
                    _ => true,
                }) {
                    return Response::error(
                        501,
                        "SDK Auth nondefault mount config is not implemented",
                    );
                }
            }
            for flag in ["local", "seal_wrap", "external_entropy_access"] {
                if let Some(value) = object.remove(flag)
                    && value.as_bool() != Some(false)
                {
                    return Response::error(
                        501,
                        "SDK Auth nondefault mount flags are not implemented",
                    );
                }
            }
            if let Some(value) = object.remove("options")
                && !value.is_null()
                && value.as_object().is_none_or(|options| !options.is_empty())
            {
                return Response::error(
                    501,
                    "SDK Auth nondefault mount options are not implemented",
                );
            }
            object.insert("type".into(), json!("plugin"));
            match state.auth.handle_with_connection_clock(
                caller.as_ref().map(|a| a.principal()),
                request.namespace,
                request.method,
                request.path,
                &body,
                request
                    .token_time()
                    .unwrap_or(AuthorityTime::Coarse(request.now)),
                Some(clock),
                request.client_certificates,
                request.origin_peer,
            ) {
                Ok(Some(r)) if r.status == 204 => {}
                Ok(_) => return Response::error(503, "SDK Auth mount returned no ownership"),
                Err(e) => return auth_error(e),
            }
            let binding =
                match state
                    .auth
                    .bind_sdk_auth_mount(request.namespace, mount, &descriptor)
                {
                    Ok(b) => b,
                    Err(e) => return auth_error(e),
                };
            if let Err(e) = self.sdk_auth_commit_control(
                &mut state,
                match caller.as_mut() {
                    Some(authority) => authority,
                    None => {
                        return Response::error(503, "SDK Auth original control capsule absent");
                    }
                },
                &expected,
                clock,
            ) {
                return e;
            }
            self.install_committed_namespace_view_copy(&state);
            return self.stage_sdk_auth(
                &state,
                request,
                StageTarget {
                    binding,
                    caller,
                    context,
                    operation: "_mount",
                    path: "",
                    deadline,
                    renewal: None,
                    retirement: None,
                },
            );
        }
        let Some(binding) = relative else {
            return Response::error(503, "SDK Auth actual mount binding absent");
        };
        if let Some(renewal) = renewal {
            let path = renewal.path().to_owned();
            if renewal.binding() != &binding {
                return Response::error(503, "SDK renewal issuer changed during admission");
            }
            return self.stage_sdk_auth(
                &state,
                request,
                StageTarget {
                    binding,
                    caller,
                    context,
                    operation: "renew",
                    path: &path,
                    deadline,
                    renewal: Some(renewal),
                    retirement: None,
                },
            );
        }
        let operation = match request.method {
            "GET" | "HEAD" => "read",
            "LIST" | "SCAN" => "list",
            "DELETE" => "delete",
            "POST" | "PUT" => "update",
            "PATCH" => "patch",
            _ => return Response::error(405, "SDK Auth method unsupported"),
        };
        let path = relative_path.unwrap_or("");
        self.stage_sdk_auth(
            &state,
            request,
            StageTarget {
                binding,
                caller,
                context,
                operation,
                path,
                deadline,
                renewal: None,
                retirement: None,
            },
        )
    }
    fn sdk_auth_commit_control(
        &mut self,
        state: &mut State,
        authority: &mut plugin::PluginResponseAuthority,
        expected: &crate::state_record_root::StateIdentity,
        clock: RequestClock,
    ) -> Result<(), Response> {
        let at = clock
            .observed_at()
            .map_err(|_| Response::error(503, "SDK Auth original clock unavailable"))?;
        state.auth.observe_sdk_auth_clock(at);
        self.commit_sdk_control(state, authority, expected)
    }
    fn stage_sdk_auth(
        &mut self,
        state: &State,
        request: &RequestView<'_>,
        target: StageTarget<'_>,
    ) -> Response {
        self.stage_owned_sdk_auth(state, request, target, None)
    }
    fn stage_owned_sdk_auth(
        &mut self,
        state: &State,
        request: &RequestView<'_>,
        target: StageTarget<'_>,
        namespace_work: Option<&namespace_sdk_cleanup::Authority>,
    ) -> Response {
        if target.retirement.is_some() && namespace_work.is_some() {
            return Response::error(503, "SDK cleanup authority scopes are mutually exclusive");
        }
        if let Some(work) = namespace_work
            && let Err(error) = work.sync_before_setup(self)
        {
            return error;
        }
        // Cleanup's Setup transaction starts from the actual graph admitted
        // by that original task, never the pre-sync Auth snapshot.
        if let Some(native) = target
            .retirement
            .as_ref()
            .and_then(|value| value.native.as_ref())
            && let Err(error) = native.sync_before_setup(self)
        {
            return error;
        }
        let current_state = if namespace_work.is_some()
            || target
                .retirement
                .as_ref()
                .is_some_and(|value| value.native.is_some())
        {
            self.state.clone()
        } else {
            None
        };
        let state = current_state.as_ref().unwrap_or(state);
        let StageTarget {
            binding,
            mut caller,
            context,
            operation,
            path,
            deadline,
            renewal,
            retirement,
        } = target;
        if let Some(retirement) = &retirement {
            if let Err(error) = retirement.check_attempt(&state.auth, &binding) {
                return error;
            }
        } else if state.auth.sdk_auth_retirement_tainted(&binding) {
            return Response::error(409, "SDK Auth durable retirement is in progress");
        }
        let wrapping = match sdk_wrapping::Owner::capture(request) {
            Ok(wrapping) => wrapping,
            Err(error) => return error,
        };
        let Some(config) = self.sdk_configuration.clone() else {
            return Response::error(503, "SDK Auth runtime absent");
        };
        let key = match sdk_auth_key(&state.cluster_id, &binding) {
            Ok(k) => k,
            Err(e) => return e,
        };
        if self
            .sdk_hosts
            .get(&key)
            .is_some_and(|c| c.fenced.load(Ordering::Acquire))
        {
            if self
                .sdk_hosts
                .get(&key)
                .is_some_and(|c| c.busy.load(Ordering::Acquire))
            {
                return Response::error(503, "SDK Auth retired invocation is still owned");
            }
            if let Some(host) = self.sdk_hosts.remove(&key) {
                host.retire()
            }
        }
        let control = if let Some(control) = self.sdk_hosts.get(&key) {
            Arc::clone(control)
        } else {
            let suffix = match crypto::random::<16>() {
                Ok(b) => hex(&b),
                Err(_) => return Response::error(503, "SDK Auth runtime entropy unavailable"),
            };
            let socket = config.runtime_directory.join(suffix);
            if private_directory(&socket).is_err() {
                return Response::error(503, "SDK Auth private runtime unavailable");
            }
            let launch = SdkLaunch {
                companion: config.companion,
                companion_sha256: match checksum(&config.companion_sha256) {
                    Ok(v) => v,
                    Err(e) => return e,
                },
                plugin: config.plugin_directory.join(&binding.descriptor().command),
                plugin_sha256: match checksum(&binding.descriptor().sha256) {
                    Ok(v) => v,
                    Err(e) => return e,
                },
                plugin_args: binding.descriptor().args.clone(),
                socket_directory: socket.clone(),
                private_log: socket.join("companion.private"),
                timeout: Duration::from_millis(config.timeout_ms),
                default_ttl_seconds: 2_764_800,
                max_ttl_seconds: 2_764_800,
            };
            if let Some(work) = namespace_work
                && let Err(error) = work.check(self)
            {
                return error;
            }
            if let Some(native) = retirement.as_ref().and_then(|value| value.native.as_ref())
                && let Err(error) = native.check(self)
            {
                return error;
            }
            let control = match start_worker_typed(launch, SdkBackendType::Auth) {
                Ok(c) => c,
                Err(e) => return e,
            };
            self.sdk_hosts.insert(key, Arc::clone(&control));
            control
        };
        if control.retiring.load(Ordering::Acquire)
            && retirement.is_none()
            && namespace_work.is_none()
        {
            return Response::error(409, "SDK Auth mount retirement is in progress");
        }
        let identity = match self.current_state_identity() {
            Ok(id) => id,
            Err(e) => return e,
        };
        let paths = match state.auth.sdk_auth_paths(&binding) {
            Ok(paths) => paths,
            Err(error) => return auth_error(error),
        };
        let admission =
            if renewal.is_none() && caller.is_some() && matches!(operation, "read" | "update") {
                let Some(authority) = caller.take() else {
                    return Response::error(503, "SDK admitted actual caller unavailable");
                };
                let storage = match state.auth.sdk_auth_storage_witness(&binding) {
                    Ok(storage) => storage,
                    Err(error) => return auth_error(error),
                };
                let entry_time = match authority.token_time() {
                    Ok(time) => time,
                    Err(error) => return error,
                };
                let Some(accepted) = entry_time.exact() else {
                    return Response::error(503, "SDK credential entrance precise clock absent");
                };
                let entry = match state.auth.admitted_standard_sdk_lease_issuer_observed(
                    authority.principal(),
                    &binding.namespace,
                    entry_time,
                ) {
                    Ok(entry) => entry,
                    Err(error) => return auth_error(error),
                };
                let final_use = authority.principal().consumed_last_use();
                Some(Admission {
                    entry,
                    accepted,
                    final_use,
                    authority: Mutex::new(authority),
                    backend: Arc::clone(&control),
                    storage: Mutex::new(storage),
                })
            } else {
                None
            };
        let namespace_original = match namespace_work
            .map(|work| work.credential_storage_cut(self, &binding))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => return error,
        };
        let private_retirement = if let Some(value) = retirement.as_ref()
            && !binding.namespace.is_empty()
            && (caller.is_some() || value.native.is_some())
        {
            let Some(first) = value.remaining.front() else {
                return Response::error(503, "SDK namespace original attempted resource absent");
            };
            match self.capture_namespace_sdk_retirement(
                state,
                &binding,
                &value.job,
                &first.id,
                namespace_runtime::RetirementCallbackParts {
                    clock: context.clock,
                    deadline,
                    control: Arc::clone(&control),
                },
            ) {
                Ok(permit) => {
                    if value
                        .native
                        .as_ref()
                        .is_some_and(|native| native.role_for_custody() != permit.role())
                    {
                        return Response::error(
                            503,
                            "SDK native original role differs from handoff",
                        );
                    }
                    Some(permit)
                }
                Err(error) => return error,
            }
        } else {
            None
        };
        let private_cleanup = match namespace_work
            .map(|work| work.capture_credential_custody(self, &binding, Arc::clone(&control)))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => return error,
        };
        let logical_data = match crate::request_metadata::current(
            request.method,
            request.path,
            request.namespace,
            request.body,
        ) {
            Ok(value) => value,
            Err(_) => {
                return Response::error(503, "SDK Auth logical data lost its original request");
            }
        };
        self.pending_sdk_auth_request = Some(Plan {
            wrapping,
            context,
            binding,
            paths,
            caller: Mutex::new(caller),
            admission,
            control,
            transaction: Mutex::new(Transaction {
                auth: state.auth.clone(),
                namespace_original,
                identity,
            }),
            operation: operation.into(),
            path: path.into(),
            data: request.body.clone(),
            logical_data,
            deadline,
            renewal: Mutex::new(renewal.map(Box::new)),
            lease: Mutex::new(None),
            cleanup: Mutex::new(None),
            retirement: retirement.map(Mutex::new),
            namespace_cleanup: namespace_work.is_some(),
            private_retirement: Mutex::new(private_retirement),
            private_cleanup: Mutex::new(private_cleanup),
        });
        Response::error(500, "SDK Auth invocation was not dispatched")
    }
    fn sdk_auth_gate(&mut self, plan: &Plan) -> Result<(), Response> {
        if self.sdk_auth_cleanup_private_view(plan)?.is_some() {
            return Ok(());
        }
        if self.sdk_auth_private_view(plan)?.is_some() {
            return Ok(());
        }
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        plan.sync_native_retirement(self)?;
        let completed_retirement = plan.retirement_completed()?;
        if plan.operation != "_mount" && !completed_retirement {
            let Some(state) = self.state.as_ref() else {
                return Err(Response::error(503, "SDK metadata owner unavailable"));
            };
            if state
                .auth
                .sdk_auth_paths(&plan.binding)
                .map_err(auth_error)?
                != plan.paths
            {
                return Err(Response::error(
                    503,
                    "SDK path policy changed after admission",
                ));
            }
        }
        if Instant::now() >= plan.deadline
            || (!completed_retirement && plan.control.fenced.load(Ordering::Acquire))
        {
            return Err(Response::error(
                503,
                "SDK Auth original owner or deadline fenced",
            ));
        }
        let mut caller = plan
            .caller
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth original capsule unavailable"))?;
        if let Some(admission) = &plan.admission {
            if !Arc::ptr_eq(&admission.backend, &plan.control) {
                return Err(Response::error(503, "SDK admitted backend owner changed"));
            }
            // Synchronize current owners, without a second authentication/use.
            // In-flight SDK authorization is the actual entrance snapshot.
            self.revalidate_online_authority_with_sync(
                &plan.context.namespace,
                &plan.context.activation,
                Self::sync_from_ha,
            )?;
            let state = self
                .state
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK admitted owner unavailable"))?;
            admission.clock_and_deadline(&state.auth)?;
            admission.owned_storage(&state.auth, &plan.binding)?;
        } else if let Some(caller) = caller.as_mut() {
            if let Some(state) = self.state.as_ref() {
                caller.apply_sdk_auth_clock_floor(&state.auth)?;
            }
            self.validate_plugin_response(caller)?;
            if let Some(state) = self.state.as_ref() {
                caller.apply_sdk_auth_clock_floor(&state.auth)?;
                caller.validate_live_auth(&state.auth)?;
            }
        } else if !plan.has_native_retirement()? {
            self.revalidate_online_authority_with_sync(
                &plan.context.namespace,
                &plan.context.activation,
                Self::sync_from_ha,
            )?;
        }
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK Auth current owner unavailable"))?;
        let same_ha = match (&self.ha, &plan.context.ha) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        if self.recovery_required
            || self.unseal_nonce != plan.context.activation
            || !same_ha
            || state.cluster_id != plan.context.cluster
            || plan.context.namespace_required && !state.namespace_exists(&plan.context.namespace)
            || state.namespace_is_sealed(&plan.context.namespace)
            || state.namespaces.incarnation(&plan.context.namespace) != plan.context.incarnation
            || namespace_runtime::DeliveryBinding::capture(state, &plan.context.namespace)
                != plan.context.delivery
            || state
                .namespaces
                .inherited_owner(&plan.context.namespace)
                .is_some()
                && !self.namespace_runtime.is_loaded(&plan.context.namespace)
        {
            return Err(Response::error(
                503,
                "SDK Auth original namespace or host owner changed",
            ));
        }
        if completed_retirement {
            plan.retirement_delivery_gate(&state.auth)?;
        } else {
            state
                .auth
                .sdk_auth_owner_gate(&plan.binding)
                .map_err(auth_error)?;
        }
        if plan.retirement.is_none() && state.auth.sdk_auth_retirement_tainted(&plan.binding) {
            return Err(Response::error(
                409,
                "SDK Auth durable retirement blocks delivery",
            ));
        }
        plan.check_retirement_control(&state.auth)?;
        if let Some(cleanup) = plan
            .cleanup
            .lock()
            .map_err(|_| Response::error(503, "SDK credential cleanup unavailable"))?
            .as_ref()
        {
            cleanup.check_service(self)?;
        }
        plan.time(&state.auth)?;
        plan.credential_owner_gate(&state.auth)?;
        plan.live_target(&state.auth)?;
        if Instant::now() >= plan.deadline {
            return Err(Response::error(503, "SDK Auth original deadline expired"));
        }
        Ok(())
    }
    fn sdk_auth_storage(
        &mut self,
        plan: &Plan,
        operation: StorageOp,
    ) -> Result<StorageReply, Response> {
        if let Some(view) = self.sdk_auth_cleanup_private_view(plan)? {
            return self.sdk_auth_cleanup_private_storage(plan, view, operation);
        }
        if let Some(view) = self.sdk_auth_private_view(plan)? {
            return self.sdk_auth_private_storage(plan, view, operation);
        }
        self.sdk_auth_gate(plan).inspect_err(|_cause| {
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            if plan.namespace_cleanup {
                namespace_storage_diagnostic("credential_authority_gate", _cause);
            }
        })?;
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth transaction unavailable"))?;
        let namespace_role = plan.namespace_native_role(self)?;
        match (&transaction.namespace_original, &namespace_role) {
            (Some(cut), Some(_)) => cut.check(
                &self
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK Auth current owner unavailable"))?
                    .auth,
                &plan.binding,
            )?,
            (None, None) => {}
            _ => {
                return Err(Response::error(
                    503,
                    "namespace SDK credential Storage cut scope changed",
                ));
            }
        }
        if plan.admission.is_none()
            && self.current_state_identity()? != transaction.identity
            && namespace_role.is_none()
        {
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            if plan.namespace_cleanup {
                eprintln!(
                    "heptabao-ns-storage-diag: phase=credential_whole_identity status=503 identity_equal=false private_namespace_cleanup=true precise_token={} schema={}",
                    self.state
                        .as_ref()
                        .is_some_and(State::has_token_api_precision_state),
                    self.state.as_ref().map_or(0, |state| state.schema)
                );
            }
            return Err(Response::error(
                503,
                "SDK Auth Storage root changed since admission",
            ));
        }
        let mut current = self
            .state
            .clone()
            .ok_or_else(|| Response::error(503, "SDK Auth current owner unavailable"))?;
        transaction.identity = self.current_state_identity()?;
        let at = plan.time(&current.auth)?;
        let changed = current.auth.observe_sdk_auth_clock(at);
        if changed {
            current.schema = current.writer_schema();
            let publication = self
                .prepare_record_plan(&mut current)
                .inspect_err(|_cause| {
                    #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                    if plan.namespace_cleanup {
                        namespace_storage_diagnostic("credential_record_plan", _cause);
                    }
                })?;
            self.sdk_auth_gate(plan)?;
            self.commit_record_plan_with_native_role(
                &current,
                publication,
                namespace_role
                    .as_ref()
                    .and_then(namespace_sdk_cleanup::NativeRole::captured),
                |auth| plan.live_auth(auth),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )?;
            self.state = Some(current);
            transaction.identity = self.current_state_identity()?;
        }
        transaction.auth.observe_sdk_auth_clock(at);
        transaction
            .auth
            .sdk_auth_owner_gate(&plan.binding)
            .map_err(auth_error)?;
        let reply = sdk_auth_storage_operation(&mut transaction.auth, &plan.binding, operation)?;
        self.sdk_auth_gate(plan)?;
        Ok(reply)
    }
    pub(in crate::service) fn finalize_sdk_auth(
        &mut self,
        plan: &mut Plan,
        result: Result<Option<Value>, Response>,
    ) -> Response {
        let mut value = match result {
            Ok(v) => v,
            Err(e) => return e,
        };
        let result = if plan.retirement.is_some() {
            self.finalize_sdk_auth_retirement(plan)
        } else {
            self.finish_sdk_auth_candidate(plan, value.as_ref())
        };
        if let Some(value) = value.as_mut() {
            erase_json(value)
        }
        match result {
            Ok(response) => response,
            Err(error) => {
                plan.control.retire();
                error
            }
        }
    }
    fn finish_sdk_auth_candidate(
        &mut self,
        plan: &Plan,
        value: Option<&Value>,
    ) -> Result<Response, Response> {
        if let Some(view) = self.sdk_auth_cleanup_private_view(plan)? {
            return self.finish_sdk_auth_cleanup_private_callback(plan, view, value);
        }
        if let Some(view) = self.sdk_auth_private_view(plan)? {
            return self.finish_sdk_auth_private_callback(plan, view, value);
        }
        self.sdk_auth_gate(plan)?;
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth transaction unavailable"))?;
        let namespace_role = plan.namespace_native_role(self)?;
        match (&transaction.namespace_original, &namespace_role) {
            (Some(cut), Some(_)) => cut.check(
                &self
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK Auth current owner unavailable"))?
                    .auth,
                &plan.binding,
            )?,
            (None, None) => {}
            _ => {
                return Err(Response::error(
                    503,
                    "namespace SDK credential Storage cut scope changed",
                ));
            }
        }
        if plan.admission.is_none()
            && self.current_state_identity()? != transaction.identity
            && namespace_role.is_none()
        {
            return Err(Response::error(
                503,
                "SDK Auth original root changed before publication",
            ));
        }
        let mut candidate = self
            .state
            .clone()
            .ok_or_else(|| Response::error(503, "SDK Auth current state unavailable"))?;
        transaction.identity = self.current_state_identity()?;
        let mut admitted_terminal = AdmittedTerminal::Data;
        if let Some(admission) = &plan.admission {
            let original = admission.storage.lock().map_err(|_| {
                Response::error(503, "SDK admitted Storage observation unavailable")
            })?;
            candidate
                .auth
                .merge_sdk_auth_storage(&plan.binding, &original, &transaction.auth)
                .map_err(auth_error)?;
            if value.is_some_and(|value| value.get("auth").is_some_and(|v| !v.is_null())) {
                admitted_terminal = AdmittedTerminal::UnexpectedAuth;
            }
        } else if namespace_role.is_some() {
            transaction
                .namespace_original
                .as_ref()
                .ok_or_else(|| {
                    Response::error(503, "namespace SDK credential Storage cut missing")
                })?
                .merge(&mut candidate.auth, &transaction.auth, &plan.binding)?;
        } else {
            candidate.auth = transaction.auth.clone();
        }
        let at = plan.time(&candidate.auth)?;
        candidate.auth.observe_sdk_auth_clock(at);
        let has_secret =
            value.is_some_and(|value| value.get("secret").is_some_and(|v| !v.is_null()));
        let has_auth = value.is_some_and(|value| value.get("auth").is_some_and(|v| !v.is_null()));
        let is_callback = plan
            .lease
            .lock()
            .map_err(|_| Response::error(503, "SDK credential callback unavailable"))?
            .is_some();
        // This successor covers ordinary admitted operations and public login.
        // Dedicated renewal, Setup, and lease callbacks keep their prior rules.
        if has_secret
            && has_auth
            && (is_callback || matches!(plan.operation.as_str(), "renew" | "_mount"))
        {
            return Err(Response::error(
                501,
                "SDK combined Auth and Secret response unsupported",
            ));
        }
        let mut response = if is_callback {
            credential::finish_callback(plan, &mut candidate, value, at)?
        } else if has_secret && plan.admission.is_some() {
            let issued = credential::issue(
                plan,
                &mut candidate,
                value.ok_or_else(|| Response::error(502, "SDK Secret missing"))?,
                at,
            )?;
            if has_auth && issued.status != 400 {
                // OpenBao registers the ordinary Secret before rejecting Auth.
                // Keep the real lease and Storage; disclose neither authority.
                Response::error(500, "1 error occurred:\n\t* internal error\n\n")
            } else {
                issued
            }
        } else if has_secret {
            // Login rejects Secret before token issuance or lease registration,
            // while preserving the backend's already executed Storage writes.
            Response::error(500, "internal error")
        } else if plan.operation == "renew" {
            let renewal = plan
                .renewal
                .lock()
                .map_err(|_| Response::error(503, "SDK renewal target unavailable"))?;
            let target = renewal
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK renewal typed issuer absent"))?;
            let auth = value
                .and_then(|v| v.get("auth"))
                .filter(|v| v.is_object())
                .ok_or_else(|| Response::error(400, "SDK Auth renewal did not return Auth"))?;
            if value
                .and_then(|v| v.get("secret"))
                .is_some_and(|v| !v.is_null())
            {
                return Err(Response::error(501, "SDK Auth renewal Secret rejected"));
            }
            let mut renewed = candidate
                .auth
                .finish_sdk_renewal(target, auth, plan.context.clock)
                .map_err(auth_error)?;
            Self::finish_identity_response_observed(
                &mut candidate.auth,
                &mut candidate.engines,
                &mut renewed,
                &candidate.namespaces,
                &plan.context.namespace,
                at.seconds(),
                AuthorityTime::Precise(at),
            )?;
            Response {
                status: renewed.status,
                body: std::mem::take(&mut renewed.body),
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
            }
        } else if plan.operation == "_mount" {
            let metadata = value
                .and_then(|value| value.get("auth_paths"))
                .ok_or_else(|| Response::error(503, "SDK owned Setup metadata missing"))?;
            let paths = Paths::from_actual(metadata).map_err(auth_error)?;
            candidate
                .auth
                .capture_sdk_auth_paths(&plan.binding, paths)
                .map_err(auth_error)?;
            empty_response()
        } else if matches!(admitted_terminal, AdmittedTerminal::UnexpectedAuth) {
            // OpenBao v2.7.0 request_handling.go:1592..1603 rejects Auth from a
            // non-token authenticated request after the actual backend callback.
            // Keep its already admitted Storage effect under the same publication
            // gates, while rejecting the Auth without invoking the native issuer.
            Response::error(500, "1 error occurred:\n\t* internal error\n\n")
        } else if let Some(auth) = value
            .and_then(|value| value.get("auth"))
            .filter(|value| !value.is_null())
        {
            if value
                .and_then(|v| v.get("secret"))
                .is_some_and(|v| !v.is_null())
            {
                return Err(Response::error(
                    501,
                    "SDK Auth Secret response is not implemented",
                ));
            }
            let mut issued = candidate
                .auth
                .finish_sdk_auth_login(&plan.binding, &plan.path, auth, plan.context.clock)
                .map_err(auth_error)?;
            Self::finish_identity_response_observed(
                &mut candidate.auth,
                &mut candidate.engines,
                &mut issued,
                &candidate.namespaces,
                &plan.context.namespace,
                at.seconds(),
                AuthorityTime::Precise(at),
            )?;
            Response {
                status: issued.status,
                body: std::mem::take(&mut issued.body),
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
            }
        } else if let Some(value) = value {
            if value.get("secret").is_some_and(|v| !v.is_null())
                || value
                    .get("redirect")
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
            {
                return Err(Response::error(
                    501,
                    "SDK Auth Secret or redirect response is not implemented",
                ));
            }
            let data = value.get("data").cloned().unwrap_or(Value::Null);
            if let Some(error) = logical_sdk_error(&data) {
                Response {
                    status: 400,
                    body: json!({"errors":[error]}),
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                }
            } else {
                Response::ok(json!({"data":data}))
            }
        } else if plan.operation == "read" {
            // A real SDK nil Read is not found. Nil Update remains 204.
            Response {
                status: 404,
                body: json!({"errors": []}),
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
            }
        } else {
            empty_response()
        };
        if let Some(wrapping) = &plan.wrapping
            && response.status == 200
        {
            let wrapped = wrapping.apply(
                &mut candidate.auth,
                &plan.context.namespace,
                &response.body,
                at,
            )?;
            erase_json(&mut response.body);
            response.body = wrapped;
            response.response_headers.clear();
        }
        let publication = (|| {
            candidate.schema = candidate.writer_schema();
            let publication = self.prepare_record_plan(&mut candidate)?;
            self.sdk_auth_gate(plan)?;
            if self.current_state_identity()? != transaction.identity {
                return Err(Response::error(
                    503,
                    "SDK Auth root changed before final publish",
                ));
            }
            self.commit_record_plan_with_native_role(
                &candidate,
                publication,
                namespace_role
                    .as_ref()
                    .and_then(namespace_sdk_cleanup::NativeRole::captured),
                |auth| plan.live_auth(auth),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )?;
            self.state = Some(candidate);
            if let Some(target) = plan
                .renewal
                .lock()
                .map_err(|_| Response::error(503, "SDK renewal target unavailable"))?
                .as_mut()
            {
                self.state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK published renewal owner absent"))?
                    .auth
                    .sdk_renewal_published(target)
                    .map_err(auth_error)?;
            }
            transaction.identity = self.current_state_identity()?;
            credential::after_publication(
                plan,
                &self
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK credential publication absent"))?
                    .auth,
            )?;
            plan.retirement_native_after_callback(
                &self
                    .state
                    .as_ref()
                    .ok_or_else(|| {
                        Response::error(503, "SDK retirement actual publication absent")
                    })?
                    .auth,
                at,
            )?;
            if let Some(admission) = &plan.admission {
                let auth = &self
                    .state
                    .as_ref()
                    .ok_or_else(|| {
                        Response::error(503, "SDK admitted published owner unavailable")
                    })?
                    .auth;
                admission.published(auth, &plan.binding)?;
            }
            if namespace_role.is_some() {
                transaction.namespace_original = plan.namespace_storage_cut(self)?;
            }
            self.sdk_auth_gate(plan)?;
            Ok(())
        })();
        if let Err(error) = publication {
            erase_json(&mut response.body);
            response.response_headers.clear();
            return Err(error);
        }
        Ok(response)
    }
    pub(in crate::service) fn check_sdk_credential_list(
        &self,
        listing: &CredentialList,
    ) -> Result<(), Response> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK credential list state absent"))?;
        listing.check(&state.auth)
    }
    pub(in crate::service) fn complete_sdk_auth_delivery(
        &mut self,
        plan: &Plan,
        response: Response,
        fingerprint: &str,
    ) -> Response {
        let gate = self.sdk_auth_gate(plan).and_then(|()| {
            let auth = &self
                .state
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK Auth delivery state unavailable"))?
                .auth;
            let wrapped_raw = match &plan.wrapping {
                Some(wrapping) => wrapping.check_delivery(
                    auth,
                    &plan.context.namespace,
                    &response,
                    AuthorityTime::Precise(plan.context.clock.observed_at().map_err(|_| {
                        Response::error(503, "SDK original wrapping clock unavailable")
                    })?),
                )?,
                None => None,
            };
            if let Some(raw) = response
                .body
                .get("auth")
                .and_then(|auth| auth.get("client_token"))
                .and_then(Value::as_str)
                .or(wrapped_raw)
            {
                let auth = &self
                    .state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK Auth issued owner unavailable"))?
                    .auth;
                let renewal = plan
                    .renewal
                    .lock()
                    .map_err(|_| Response::error(503, "SDK renewal target unavailable"))?;
                if let Some(target) = renewal.as_ref() {
                    target
                        .response_gate(auth, raw, plan.context.clock)
                        .map_err(auth_error)?;
                } else {
                    auth.sdk_auth_issued_live(raw, plan.context.clock)
                        .map_err(auth_error)?;
                }
            }
            if Instant::now() >= plan.deadline {
                return Err(Response::error(
                    503,
                    "SDK Auth original delivery deadline expired",
                ));
            }
            Ok(())
        });
        if let Err(error) = gate {
            plan.control.retire();
            let now = plan
                .context
                .clock
                .observed_at()
                .map_or(0, |at| at.seconds());
            return self.sdk_delivery_veto(response, error, fingerprint, now);
        }
        response
    }
}

// Exact SDK v2.7.0 logical.Response.IsError shape. A business field named
// error alongside arbitrary other data remains ordinary data.
fn logical_sdk_error(data: &Value) -> Option<&str> {
    let data = data.as_object()?;
    if data.len() == 1 || data.len() == 2 && data.get("data").is_some_and(|value| !value.is_null())
    {
        data.get("error").and_then(Value::as_str)
    } else {
        None
    }
}
#[cfg(test)]
mod error_tests {
    use super::*;
    #[test]
    fn sdk_auth100_literal_characters_preserve_namespace_and_traversal_boundaries() {
        assert!(super::super::valid_path("auth/sdk/root*literal"));
        assert!(super::super::valid_path("auth/sdk/root/用户"));
        assert!(!super::super::valid_namespace("用户"));
        for path in [
            "/auth/sdk",
            "auth//sdk",
            "auth/sdk/../private",
            "auth/sdk/用户\n",
            "auth/sdk/%2e",
            "auth/sdk/\\private",
        ] {
            assert!(!super::super::valid_path(path));
        }
    }
    #[test]
    fn sdk_auth100_logical_error_matches_actual_sdk_shape_without_flattening_business_data() {
        assert_eq!(
            logical_sdk_error(&json!({"error":"invalid credentials"})),
            Some("invalid credentials")
        );
        assert_eq!(
            logical_sdk_error(&json!({"error":"rejected","data":{}})),
            Some("rejected")
        );
        assert!(logical_sdk_error(&json!({"error":"business","other":1})).is_none());
        assert!(logical_sdk_error(&json!({"error":"business","data":null})).is_none());
        assert!(logical_sdk_error(&json!({"error":null})).is_none());
        assert!(logical_sdk_error(&json!({"errors":["business"]})).is_none());
    }
}

#[cfg(test)]
mod durable_tests {
    use super::*;
    use crate::service::tests::{Root, bootstrap, call};
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    pub(super) fn mount(
        state: &mut State,
        root: &str,
    ) -> Result<Binding, Box<dyn std::error::Error>> {
        let principal = state.auth.authenticate(root, 100)?;
        let mounted = state
            .auth
            .handle(
                Some(&principal),
                "",
                "POST",
                "sys/auth/sdk",
                &json!({"type":"plugin"}),
                100,
            )?
            .ok_or("native auth mount")?;
        assert_eq!(mounted.status, 204);
        state.auth.register_sdk_auth_descriptor(Descriptor {
            name: "auth_probe".into(),
            version: "v0.0.1".into(),
            command: "probe".into(),
            args: vec![],
            sha256: "a".repeat(64),
            generation: 1,
        })?;
        let descriptor = state
            .auth
            .sdk_auth_descriptor("auth_probe", "v0.0.1")
            .ok_or("descriptor")?;
        let binding = state.auth.bind_sdk_auth_mount("", "sdk", &descriptor)?;
        state
            .auth
            .observe_sdk_auth_clock(Timestamp::checked(100, 1)?);
        Ok(binding)
    }
    pub(super) fn publish(
        service: &mut Service,
        mut candidate: State,
    ) -> Result<(), Box<dyn std::error::Error>> {
        candidate.schema = candidate.writer_schema();
        service
            .commit_state(&mut candidate)
            .map_err(|e| format!("actual record commit: {} {}", e.status, e.body))?;
        service.state = Some(candidate);
        Ok(())
    }
    #[test]
    fn sdk_auth100_encrypted_cells_clock_only_commit_protected_backup_and_reopen() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (key, root) = bootstrap(&mut service)?;
        let old_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
        let mut candidate = service.state.clone().ok_or("state")?;
        let binding = mount(&mut candidate, &root)?;
        candidate.auth.sdk_auth_storage_put(
            &binding,
            Entry {
                key: "config".into(),
                value: Zeroizing::new(b"durable-Auth-owned-config".to_vec()),
                seal_wrap: true,
            },
        )?;
        publish(&mut service, candidate)?;
        let original = service.state.clone().ok_or("state")?;
        assert_eq!(original.schema, SDK_AUTH_STATE_SCHEMA);
        assert!(service.prepare_snapshot_restore(&old_backup).is_err());
        for lower in [92, 95, 96, 97, 98, 99] {
            let mut wrong = original.clone();
            wrong.schema = lower;
            assert!(wrong.validate_format().is_err());
            assert!(service.commit_state(&mut wrong).is_err());
        }
        let first_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
        let identity = service
            .current_state_identity()
            .map_err(|_| "first identity")?;
        let mut later = original.clone();
        let floor = Timestamp::checked(101, 999)?;
        assert!(later.auth.observe_sdk_auth_clock(floor));
        publish(&mut service, later)?;
        assert!(
            service
                .current_state_identity()
                .map_err(|_| "second identity")?
                != identity
        );
        assert!(service.prepare_snapshot_restore(&first_backup).is_err());
        assert!(
            Service::validate_snapshot_protected_floor(
                service.state.as_ref().ok_or("state")?,
                &original
            )
            .is_err()
        );
        let fresh = service.durable.as_ref().ok_or("durable")?.export_backup()?;
        service
            .prepare_snapshot_restore(&fresh)
            .map_err(|_| "fresh protected backup")?;
        assert_eq!(
            call(&mut service, "PUT", "sys/seal", &root, json!({})).status,
            204
        );
        drop(service);
        let mut reopened = directory.service()?;
        assert_eq!(
            call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let actual = reopened.state.as_ref().ok_or("reopened")?;
        assert_eq!(actual.auth.sdk_auth_clock_floor(), Some(floor));
        assert_eq!(actual.schema, SDK_AUTH_STATE_SCHEMA);
        assert_eq!(
            actual
                .auth
                .sdk_auth_storage_get(&binding, "config")?
                .ok_or("encrypted cell")?
                .value
                .as_slice(),
            b"durable-Auth-owned-config"
        );
        Ok(())
    }
    #[test]
    fn sdk_admission_storage_merge_preserves_current_revocation_policy_and_reopen() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (key, root) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/policies/acl/admitted",
                &root,
                json!({"policy":"path \"auth/sdk/config\" { capabilities = [\"update\"] }"})
            )
            .status,
            204
        );
        let issued = call(
            &mut service,
            "POST",
            "auth/token/create",
            &root,
            json!({"policies":["admitted"],"ttl":60}),
        );
        assert_eq!(issued.status, 200);
        let token = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("issued token")?
            .to_owned();
        let mut initial = service.state.clone().ok_or("state")?;
        let binding = mount(&mut initial, &root)?;
        publish(&mut service, initial)?;
        let original = service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .sdk_auth_storage_witness(&binding)?;
        let mut working = service.state.as_ref().ok_or("state")?.auth.clone();
        working.sdk_auth_storage_put(
            &binding,
            Entry {
                key: "config".into(),
                value: Zeroizing::new(b"admitted-inflight-write".to_vec()),
                seal_wrap: false,
            },
        )?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/token/revoke",
                &root,
                json!({"token":token})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/policies/acl/admitted",
                &root,
                json!({"policy":"path \"auth/sdk/config\" { capabilities = [\"deny\"] }"})
            )
            .status,
            204
        );
        let mut current = service.state.clone().ok_or("current")?;
        assert!(current.auth.authenticate(&token, 100).is_err());
        current
            .auth
            .merge_sdk_auth_storage(&binding, &original, &working)?;
        assert!(current.auth.authenticate(&token, 100).is_err());
        publish(&mut service, current)?;
        let policy = call(
            &mut service,
            "GET",
            "sys/policies/acl/admitted",
            &root,
            json!({}),
        );
        assert_eq!(policy.status, 200);
        assert!(
            policy.body["data"]["policy"]
                .as_str()
                .ok_or("current policy")?
                .contains("deny")
        );
        assert_eq!(
            call(&mut service, "PUT", "sys/seal", &root, json!({})).status,
            204
        );
        drop(service);
        let mut reopened = directory.service()?;
        assert_eq!(
            call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let auth = &mut reopened.state.as_mut().ok_or("reopened")?.auth;
        assert!(auth.authenticate(&token, 100).is_err());
        assert_eq!(
            auth.sdk_auth_storage_get(&binding, "config")?
                .ok_or("durable admitted config")?
                .value
                .as_slice(),
            b"admitted-inflight-write"
        );
        let policy = call(
            &mut reopened,
            "GET",
            "sys/policies/acl/admitted",
            &root,
            json!({}),
        );
        assert!(
            policy.body["data"]["policy"]
                .as_str()
                .ok_or("reopened policy")?
                .contains("deny")
        );
        Ok(())
    }
    #[test]
    fn sdk_admission_storage_merge_rejects_changed_cells_and_retired_mount() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, root) = bootstrap(&mut service)?;
        let mut initial = service.state.clone().ok_or("state")?;
        let binding = mount(&mut initial, &root)?;
        publish(&mut service, initial)?;
        let original = service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .sdk_auth_storage_witness(&binding)?;
        let mut working = service.state.as_ref().ok_or("state")?.auth.clone();
        working.sdk_auth_storage_put(
            &binding,
            Entry {
                key: "config".into(),
                value: Zeroizing::new(b"held-write".to_vec()),
                seal_wrap: false,
            },
        )?;
        let mut changed = service.state.clone().ok_or("state")?;
        changed.auth.sdk_auth_storage_put(
            &binding,
            Entry {
                key: "new-member".into(),
                value: Zeroizing::new(b"current-writer".to_vec()),
                seal_wrap: false,
            },
        )?;
        publish(&mut service, changed)?;
        let mut current = service.state.clone().ok_or("state")?;
        assert!(original.check(&current.auth, &binding).is_err());
        assert!(
            current
                .auth
                .merge_sdk_auth_storage(&binding, &original, &working)
                .is_err()
        );
        assert!(
            current
                .auth
                .sdk_auth_storage_get(&binding, "config")?
                .is_none()
        );
        assert_eq!(
            current
                .auth
                .sdk_auth_storage_get(&binding, "new-member")?
                .ok_or("current member")?
                .value
                .as_slice(),
            b"current-writer"
        );
        let principal = current.auth.authenticate(&root, 100)?;
        assert_eq!(
            current
                .auth
                .handle(
                    Some(&principal),
                    "",
                    "DELETE",
                    "sys/auth/sdk",
                    &json!({}),
                    100
                )?
                .ok_or("retirement")?
                .status,
            204
        );
        assert!(
            current
                .auth
                .merge_sdk_auth_storage(&binding, &original, &working)
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn sdk_admission_original_http_deadline_rejects_even_with_live_owner() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, root) = bootstrap(&mut service)?;
        let mut state = service.state.clone().ok_or("state")?;
        let binding = mount(&mut state, &root)?;
        publish(&mut service, state)?;
        let mut state = service.state.clone().ok_or("state")?;
        let principal = state.auth.authenticate(&root, 100)?;
        let clock =
            RequestClock::anchored(Duration::new(100, 0), Instant::now()).map_err(|_| "clock")?;
        let body = json!({"username":"value"});
        let request = RequestView {
            namespace: "",
            method: "POST",
            path: "auth/sdk/config",
            token: &root,
            body: &body,
            now: 100,
            wrap_ttl_seconds: None,
            enforce_namespace: true,
            token_clock: Some(clock),
            admission_started: clock.started(),
            allow_forward: false,
            origin_peer: None,
            client_certificates: None,
        };
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_millis(20),
        );
        let accepted = clock.observed_at().map_err(|_| "clock")?;
        let entry = state.auth.admitted_standard_sdk_lease_issuer_observed(
            &principal,
            "",
            AuthorityTime::Precise(accepted),
        )?;
        let final_use = principal.consumed_last_use();
        let authority = plugin::PluginResponseAuthority::new(
            principal,
            &state,
            &request,
            "update",
            false,
            &service.unseal_nonce,
        )
        .with_sdk_clock();
        let (sender, _receiver) = mpsc::sync_channel(1);
        let admission = Admission {
            entry,
            accepted,
            final_use,
            authority: Mutex::new(authority),
            backend: Arc::new(Control {
                sender,
                busy: Arc::new(AtomicBool::new(false)),
                fenced: Arc::new(AtomicBool::new(false)),
                retiring: AtomicBool::new(false),
            }),
            storage: Mutex::new(state.auth.sdk_auth_storage_witness(&binding)?),
        };
        admission
            .clock_and_deadline(&state.auth)
            .map_err(|_| "initial deadline")?;
        std::thread::sleep(Duration::from_millis(25));
        assert!(admission.clock_and_deadline(&state.auth).is_err());
        assert!(admission.owned_storage(&state.auth, &binding).is_ok());
        Ok(())
    }
    #[test]
    fn sdk_auth100_catalog_retirement_has_independent_epoch_cut_and_sticky_reader() -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (_, root) = bootstrap(&mut service)?;
        let mut candidate = service.state.clone().ok_or("state")?;
        let binding = mount(&mut candidate, &root)?;
        publish(&mut service, candidate)?;
        let mounted = service.state.clone().ok_or("mounted")?;
        let before_epoch = mounted.auth.sdk_auth_epoch_floor().ok_or("epoch")?;
        let mut retired = mounted.clone();
        let principal = retired.auth.authenticate(&root, 100)?;
        let removed = retired
            .auth
            .handle(
                Some(&principal),
                "",
                "DELETE",
                "sys/auth/sdk",
                &json!({}),
                100,
            )?
            .ok_or("native retirement")?;
        assert_eq!(removed.status, 204);
        assert!(
            retired
                .auth
                .deregister_sdk_auth_descriptor("auth_probe", "v0.0.1")?
        );
        let after_epoch = retired.auth.sdk_auth_epoch_floor().ok_or("retired epoch")?;
        assert!(after_epoch["auth_probe@v0.0.1"] > before_epoch["auth_probe@v0.0.1"]);
        // This cut is independent from the observation timestamp: even an equal
        // clock cannot resurrect the retired descriptor from a prior snapshot.
        assert!(
            mounted
                .auth
                .validate_sdk_auth_epoch_floor(Some(&after_epoch))
                .is_err()
        );
        assert!(retired.auth.sdk_auth_owner_gate(&binding).is_err());
        publish(&mut service, retired)?;
        let retired = service.state.as_ref().ok_or("retired")?;
        assert_eq!(retired.schema, SDK_AUTH_STATE_SCHEMA);
        assert!(retired.auth.has_sdk_auth_state());
        assert!(retired.auth.sdk_auth_descriptors().is_empty());
        assert!(Service::validate_snapshot_protected_floor(retired, &mounted).is_err());
        let mut lower = retired.clone();
        lower.schema = 98;
        assert!(lower.validate_format().is_err());
        Ok(())
    }
    #[test]
    fn sdk_auth100_actual_path_policy_cannot_roll_back_same_clock_and_reopens_encrypted()
    -> TestResult {
        let directory = Root::new();
        let mut service = directory.service()?;
        let (key, root) = bootstrap(&mut service)?;
        let mut initial = service.state.clone().ok_or("state")?;
        let binding = mount(&mut initial, &root)?;
        publish(&mut service, initial)?;
        let before = service.state.clone().ok_or("before policy")?;
        let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
        let paths = Paths::from_actual(
            &json!({"Root":["root/+/write","privileged*","privileged-exact"],"Unauthenticated":["public/+/read"]}),
        )?;
        let mut captured = before.clone();
        captured
            .auth
            .capture_sdk_auth_paths(&binding, paths.clone())?;
        captured.auth.sdk_auth_storage_put(
            &binding,
            Entry {
                key: "config".into(),
                value: Zeroizing::new(b"policy-bound-real-cell".to_vec()),
                seal_wrap: false,
            },
        )?;
        // Policy capture is a separate cut even when the original observation
        // floor has not moved. Restore may never recover the old guessed login.
        assert_eq!(
            before.auth.sdk_auth_clock_floor(),
            captured.auth.sdk_auth_clock_floor()
        );
        publish(&mut service, captured)?;
        assert!(service.prepare_snapshot_restore(&backup).is_err());
        let current = service.state.as_ref().ok_or("current")?;
        assert!(
            before
                .auth
                .validate_sdk_auth_clock(Some(&current.auth))
                .is_err()
        );
        assert!(!current.auth.is_public_login("", "GET", "auth/sdk/login"));
        assert!(
            current
                .auth
                .is_public_login("", "GET", "auth/sdk/public/alice/read")
        );
        assert!(
            !current
                .auth
                .is_public_login("", "LIST", "auth/sdk/public/alice/read")
        );
        assert!(!paths.is_root("root/alice/write"));
        assert!(paths.is_root("root/+/write"));
        assert!(!paths.is_root("privileged-exact-more"));
        assert_eq!(
            call(&mut service, "PUT", "sys/seal", &root, json!({})).status,
            204
        );
        drop(service);
        let mut reopened = directory.service()?;
        assert_eq!(
            call(&mut reopened, "PUT", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let actual = reopened.state.as_ref().ok_or("reopened")?;
        assert!(actual.auth.sdk_auth_paths(&binding)? == Some(paths));
        assert_eq!(
            actual
                .auth
                .sdk_auth_storage_get(&binding, "config")?
                .ok_or("cell")?
                .value
                .as_slice(),
            b"policy-bound-real-cell"
        );
        assert!(
            before
                .auth
                .validate_sdk_auth_clock(Some(&actual.auth))
                .is_err()
        );
        assert!(reopened.prepare_snapshot_restore(&backup).is_err());
        Ok(())
    }
}

fn sdk_auth_storage_operation(
    auth: &mut AuthState,
    binding: &Binding,
    operation: StorageOp,
) -> Result<StorageReply, Response> {
    let reply = match operation {
        StorageOp::Get(key) => StorageReply::Entry(
            auth.sdk_auth_storage_get(binding, &key)
                .map_err(auth_error)?
                .map(|entry| SdkStorageEntry {
                    key: entry.key,
                    value: entry.value,
                    seal_wrap: entry.seal_wrap,
                }),
        ),
        StorageOp::Put(entry) => {
            auth.sdk_auth_storage_put(
                binding,
                Entry {
                    key: entry.key,
                    value: entry.value,
                    seal_wrap: entry.seal_wrap,
                },
            )
            .map_err(auth_error)?;
            StorageReply::Empty
        }
        StorageOp::Delete(key) => {
            auth.sdk_auth_storage_delete(binding, &key)
                .map_err(auth_error)?;
            StorageReply::Empty
        }
        StorageOp::List(prefix, after, limit) => StorageReply::Keys(
            auth.sdk_auth_storage_list(binding, &prefix, &after, limit)
                .map_err(auth_error)?,
        ),
    };
    Ok(reply)
}

impl Service {
    fn refresh_namespace_sdk_retirement(&mut self, plan: &Plan, id: &str) -> Result<(), Response> {
        if plan.binding.namespace.is_empty() {
            return Ok(());
        }
        let mut permit = plan
            .private_retirement
            .lock()
            .map_err(|_| Response::error(503, "SDK original private permit unavailable"))?;
        let Some(previous) = permit.as_ref() else {
            return Ok(());
        };
        if previous.handed_off()? {
            return Err(Response::error(
                503,
                "closed SDK original permit cannot be replaced",
            ));
        }
        if previous.original_resource() == id {
            return Ok(());
        }
        previous.check_service(self)?;
        let role = previous.role();
        let job = plan
            .retirement
            .as_ref()
            .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
            .lock()
            .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?
            .job
            .clone();
        let state = self
            .state
            .clone()
            .ok_or_else(|| Response::error(503, "SDK retirement actual owner absent"))?;
        let next = self.capture_namespace_sdk_retirement(
            &state,
            &plan.binding,
            &job,
            id,
            namespace_runtime::RetirementCallbackParts {
                clock: plan.context.clock,
                deadline: plan.deadline,
                control: Arc::clone(&plan.control),
            },
        )?;
        if next.role() != role {
            return Err(Response::error(
                503,
                "SDK original retirement role cannot be rearmed",
            ));
        }
        *permit = Some(next);
        Ok(())
    }

    fn sdk_auth_private_view(
        &mut self,
        plan: &Plan,
    ) -> Result<Option<namespace_runtime::RetirementView>, Response> {
        let permit = plan
            .private_retirement
            .lock()
            .map_err(|_| Response::error(503, "SDK private original permit unavailable"))?;
        let Some(permit) = permit.as_ref() else {
            return Ok(None);
        };
        if !permit.handed_off()? {
            return Ok(None);
        }
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        permit.check_service(self)?;
        self.sync_from_ha()?;
        permit.check_service(self)?;
        let view = permit.open(self)?;
        let state = view.state();
        let same_ha = match (&self.ha, &plan.context.ha) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        if !same_ha
            || plan.context.namespace_required && !state.namespace_exists(&plan.context.namespace)
            || state.namespaces.incarnation(&plan.context.namespace) != plan.context.incarnation
        {
            return Err(Response::error(
                503,
                "SDK original private namespace or HA owner changed",
            ));
        }
        let completed = plan.retirement_completed()?;
        if plan.admission.is_some()
            || plan.namespace_cleanup
            || plan.retirement.is_none()
            || plan
                .renewal
                .lock()
                .map_err(|_| Response::error(503, "SDK renewal target unavailable"))?
                .is_some()
            || Instant::now() >= plan.deadline
            || (!completed && plan.control.fenced.load(Ordering::Acquire))
        {
            return Err(Response::error(
                503,
                "SDK original private retirement fenced",
            ));
        }
        view.matches_original(
            &plan.context.activation,
            &plan.context.cluster,
            &plan.context.namespace,
            plan.context.incarnation,
            &plan.context.delivery,
        )?;
        if plan.operation != "_mount"
            && !completed
            && state
                .auth
                .sdk_auth_paths(&plan.binding)
                .map_err(auth_error)?
                != plan.paths
        {
            return Err(Response::error(
                503,
                "SDK path policy changed after admission",
            ));
        }
        {
            let mut caller = plan
                .caller
                .lock()
                .map_err(|_| Response::error(503, "SDK Auth original capsule unavailable"))?;
            if let Some(caller) = caller.as_mut() {
                caller.apply_sdk_auth_clock_floor(&state.auth)?;
                self.validate_plugin_response_custody(caller, &view)?;
                caller.apply_sdk_auth_clock_floor(&state.auth)?;
                caller.validate_live_auth(&state.auth)?;
            } else if !plan.has_native_retirement()? {
                return Err(Response::error(
                    503,
                    "SDK private retirement original caller absent",
                ));
            }
        }
        if completed {
            plan.retirement_delivery_gate(&state.auth)?;
        } else {
            state
                .auth
                .sdk_auth_owner_gate(&plan.binding)
                .map_err(auth_error)?;
            view.check_storage()?;
        }
        plan.check_retirement_control(&state.auth)?;
        plan.time(&state.auth)?;
        plan.credential_owner_gate(&state.auth)?;
        plan.live_target(&state.auth)?;
        view.check_current(self)?;
        Ok(Some(view))
    }

    fn sdk_auth_private_storage(
        &mut self,
        plan: &Plan,
        view: namespace_runtime::RetirementView,
        operation: StorageOp,
    ) -> Result<StorageReply, Response> {
        view.check_current(self)?;
        view.check_storage()?;
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth transaction unavailable"))?;
        let at = plan.time(&view.state().auth)?;
        let mut candidate = view.state().clone();
        if candidate.auth.observe_sdk_auth_clock(at) {
            let proof = view.clock_publication(self, candidate, at)?;
            let closed = self
                .commit_namespace_sdk_retirement_publication(proof, |auth| plan.live_auth(auth))?;
            self.state = Some(closed);
        }
        transaction.identity = self.current_state_identity()?;
        transaction.auth.observe_sdk_auth_clock(at);
        transaction
            .auth
            .sdk_auth_owner_gate(&plan.binding)
            .map_err(auth_error)?;
        let reply = sdk_auth_storage_operation(&mut transaction.auth, &plan.binding, operation)?;
        self.sdk_auth_gate(plan)?;
        Ok(reply)
    }

    fn finish_sdk_auth_private_callback(
        &mut self,
        plan: &Plan,
        view: namespace_runtime::RetirementView,
        value: Option<&Value>,
    ) -> Result<Response, Response> {
        view.check_current(self)?;
        view.check_storage()?;
        {
            let lease = plan
                .lease
                .lock()
                .map_err(|_| Response::error(503, "SDK credential callback unavailable"))?;
            let call = lease
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK original attempted callback absent"))?;
            if call.action != "revoke" || call.record.id != view.resource() {
                return Err(Response::error(
                    503,
                    "SDK private callback differs from original Attempted",
                ));
            }
        }
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth transaction unavailable"))?;
        let mut candidate = view.state().clone();
        view.merge_storage(&mut candidate.auth, &transaction.auth)?;
        let at = plan.time(&candidate.auth)?;
        let mut response = credential::finish_callback(plan, &mut candidate, value, at)?;
        let published_auth = candidate.auth.clone();
        let mut published = false;
        let result = (|| {
            let proof = namespace_diagnostic!(
                "auth.retirement.callback.factory",
                view.callback_publication(self, candidate, &transaction.auth, at)
            )?;
            let closed = namespace_diagnostic!(
                "auth.retirement.callback.commit",
                self.commit_namespace_sdk_retirement_publication(proof, |auth| plan
                    .live_auth(auth))
            )?;
            published = true;
            self.state = Some(closed);
            transaction.identity = self.current_state_identity()?;
            // These original post-Publish receipts consume only the complete
            // logical Auth whose exact ciphertext was just physically committed.
            namespace_diagnostic!(
                "auth.retirement.callback.after_publish",
                credential::after_publication(plan, &published_auth)
            )?;
            namespace_diagnostic!(
                "auth.retirement.callback.native_after",
                plan.retirement_native_after_callback(&published_auth, at)
            )?;
            transaction.auth = published_auth;
            namespace_diagnostic!(
                "auth.retirement.callback.final_gate",
                self.sdk_auth_gate(plan)
            )
        })();
        if let Err(error) = result {
            erase_json(&mut response.body);
            response.response_headers.clear();
            if published {
                self.recovery_required = true;
                self.ha_activation = None;
                self.namespace_runtime.clear();
                self.retire_sdk_hosts();
            }
            return Err(error);
        }
        Ok(response)
    }
}

impl Service {
    fn finalize_sdk_auth_private_retirement(
        &mut self,
        plan: &Plan,
        view: namespace_runtime::RetirementView,
    ) -> Result<Response, Response> {
        view.check_current(self)?;
        let (mut body, job, retired) = {
            let retirement = plan
                .retirement
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?;
            if !retirement.remaining.is_empty() || retirement.completed.is_some() {
                return Err(Response::error(503, "SDK retirement callbacks incomplete"));
            }
            let retired = view
                .state()
                .auth
                .sdk_credential_retired_mount_records(&plan.binding)
                .map_err(auth_error)?
                .into_iter()
                .map(|r| Ok((r.id.clone(), retirement::digest(&r)?)))
                .collect::<Result<Vec<_>, Response>>()?;
            (retirement.body.clone(), retirement.job.clone(), retired)
        };
        let mut published = false;
        let result = (|| {
            let mut caller = plan
                .caller
                .lock()
                .map_err(|_| Response::error(503, "SDK retirement actual caller unavailable"))?;
            let proof = if let Some(caller) = caller.as_mut() {
                self.validate_plugin_response_custody(caller, &view)?;
                view.removal_publication(self, caller, &body)?
            } else {
                let retirement = plan
                    .retirement
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
                    .lock()
                    .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?;
                let native = retirement
                    .native
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK retirement native owner absent"))?;
                view.native_removal_publication(self, native.selected_for_custody())?
            };
            drop(caller);
            let closed = self
                .commit_namespace_sdk_retirement_publication(proof, |auth| plan.live_auth(auth))?;
            published = true;
            self.state = Some(closed);
            let permit = plan
                .private_retirement
                .lock()
                .map_err(|_| Response::error(503, "SDK original private permit unavailable"))?;
            let current = permit
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK original private permit absent"))?
                .open(self)?;
            let at = plan.time(&current.state().auth)?;
            {
                let mut retirement = plan
                    .retirement
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK retirement scope absent"))?
                    .lock()
                    .map_err(|_| Response::error(503, "SDK retirement scope unavailable"))?;
                if retirement.job != job
                    || !retirement.remaining.is_empty()
                    || retirement.completed.is_some()
                {
                    return Err(Response::error(
                        503,
                        "SDK original retirement control changed",
                    ));
                }
                if let Some(native) = retirement.native.as_mut() {
                    native.published_private_removal(&current.state().auth, at)?;
                }
                retirement.completed = Some(retired);
            }
            drop(permit);
            let key = sdk_auth_key(&plan.context.cluster, &plan.binding)?;
            let host = self
                .sdk_hosts
                .get(&key)
                .ok_or_else(|| Response::error(503, "SDK retirement actual Control absent"))?;
            if !Arc::ptr_eq(host, &plan.control) {
                return Err(Response::error(
                    503,
                    "SDK retirement actual Control changed",
                ));
            }
            if let Some(host) = self.sdk_hosts.remove(&key) {
                host.retire();
            }
            self.sdk_auth_gate(plan)?;
            Ok(empty_response())
        })();
        erase_json(&mut body);
        if result.is_err() && published {
            // A post-Publish error must never resurrect the old maintenance owner.
            self.recovery_required = true;
            self.ha_activation = None;
            self.namespace_runtime.clear();
            self.retire_sdk_hosts();
        }
        result
    }
}

impl Service {
    fn sdk_auth_cleanup_private_view(
        &mut self,
        plan: &Plan,
    ) -> Result<Option<namespace_runtime::CleanupView>, Response> {
        let permit = plan
            .private_cleanup
            .lock()
            .map_err(|_| Response::error(503, "SDK namespace cleanup permit unavailable"))?;
        let Some(permit) = permit.as_ref() else {
            return Ok(None);
        };
        if !permit.handed_off()? {
            return Ok(None);
        }
        if !plan.namespace_cleanup
            || plan.retirement.is_some()
            || plan.admission.is_some()
            || plan
                .caller
                .lock()
                .map_err(|_| Response::error(503, "SDK original caller unavailable"))?
                .is_some()
            || plan
                .renewal
                .lock()
                .map_err(|_| Response::error(503, "SDK original renewal unavailable"))?
                .is_some()
            || plan.operation != "revoke"
            || Instant::now() >= plan.deadline
            || plan.control.fenced.load(Ordering::Acquire)
        {
            return Err(Response::error(
                503,
                "SDK namespace cleanup original scope changed",
            ));
        }
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        let view = permit.open(self)?;
        view.matches_origin(namespace_sdk_cleanup::CapturedOrigin {
            namespace: &plan.context.namespace,
            incarnation: plan.context.incarnation,
            cluster: &plan.context.cluster,
            activation: &plan.context.activation,
            ha: &plan.context.ha,
            delivery: &plan.context.delivery,
            clock: plan.context.clock,
            deadline: plan.deadline,
        })?;
        if view
            .state()
            .auth
            .sdk_auth_paths(&plan.binding)
            .map_err(auth_error)?
            != plan.paths
        {
            return Err(Response::error(
                503,
                "SDK namespace cleanup original policy changed",
            ));
        }
        {
            let cleanup = plan
                .cleanup
                .lock()
                .map_err(|_| Response::error(503, "SDK cleanup unavailable"))?;
            let cleanup = cleanup
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK cleanup absent"))?;
            let lease = plan
                .lease
                .lock()
                .map_err(|_| Response::error(503, "SDK cleanup lease unavailable"))?;
            let call = lease
                .as_ref()
                .ok_or_else(|| Response::error(503, "SDK cleanup lease absent"))?;
            cleanup.check(call)?;
            cleanup
                .namespace_work()
                .ok_or_else(|| Response::error(503, "SDK original task absent"))?
                .check_private_graph(self, &view)?;
            call.check(&view.state().auth, plan.time(&view.state().auth)?)?;
        }
        view.state()
            .auth
            .sdk_auth_owner_gate(&plan.binding)
            .map_err(auth_error)?;
        view.check_current(self)?;
        Ok(Some(view))
    }
    fn sdk_auth_cleanup_private_storage(
        &mut self,
        plan: &Plan,
        view: namespace_runtime::CleanupView,
        operation: StorageOp,
    ) -> Result<StorageReply, Response> {
        view.check_current(self)?;
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth transaction unavailable"))?;
        let at = plan.time(&view.state().auth)?;
        let mut candidate = view.state().clone();
        if candidate.auth.observe_sdk_auth_clock(at) {
            let proof = view.clock_publication(self, at)?;
            let cleanup = plan
                .cleanup
                .lock()
                .map_err(|_| Response::error(503, "SDK cleanup unavailable"))?;
            let work = cleanup
                .as_ref()
                .and_then(credential::Cleanup::namespace_work)
                .ok_or_else(|| Response::error(503, "SDK cleanup task absent"))?;
            let closed = self.commit_namespace_sdk_cleanup_publication(proof, |state| {
                work.check_auth(&state.auth)
            })?;
            self.state = Some(closed);
        }
        transaction.identity = self.current_state_identity()?;
        transaction.auth.observe_sdk_auth_clock(at);
        transaction
            .auth
            .sdk_auth_owner_gate(&plan.binding)
            .map_err(auth_error)?;
        let reply = sdk_auth_storage_operation(&mut transaction.auth, &plan.binding, operation)?;
        // This gate uses the actual unchanged captured task and private MAC graph;
        // it does not reacquire a loaded slot or reconstruct a Principal.
        self.sdk_auth_gate(plan)?;
        Ok(reply)
    }
    fn finish_sdk_auth_cleanup_private_callback(
        &mut self,
        plan: &Plan,
        view: namespace_runtime::CleanupView,
        value: Option<&Value>,
    ) -> Result<Response, Response> {
        view.check_current(self)?;
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth transaction unavailable"))?;
        let mut incoming = view.state().clone();
        incoming.auth = transaction.auth.clone();
        let mut candidate = view.state().clone();
        view.merge_storage(&mut candidate, &incoming)?;
        let at = plan.time(&candidate.auth)?;
        let mut response = credential::finish_callback(plan, &mut candidate, value, at)?;
        let published = candidate.clone();
        let mut committed = false;
        let result = (|| {
            let proof = namespace_diagnostic!(
                "auth.cleanup.callback.factory",
                view.callback_publication(self, candidate, &incoming, at)
            )?;
            let closed = {
                let cleanup = plan
                    .cleanup
                    .lock()
                    .map_err(|_| Response::error(503, "SDK cleanup unavailable"))?;
                let work = cleanup
                    .as_ref()
                    .and_then(credential::Cleanup::namespace_work)
                    .ok_or_else(|| Response::error(503, "SDK original task absent"))?;
                namespace_diagnostic!(
                    "auth.cleanup.callback.commit",
                    self.commit_namespace_sdk_cleanup_publication(proof, |state| {
                        work.check_auth(&state.auth)
                    })
                )?
            };
            committed = true;
            self.state = Some(closed);
            transaction.identity = self.current_state_identity()?;
            namespace_diagnostic!(
                "auth.cleanup.callback.after_publish",
                credential::after_publication(plan, &published.auth)
            )?;
            transaction.auth = published.auth;
            namespace_diagnostic!("auth.cleanup.callback.final_gate", self.sdk_auth_gate(plan))
        })();
        if let Err(error) = result {
            erase_json(&mut response.body);
            response.response_headers.clear();
            if committed {
                self.recovery_required = true;
                self.ha_activation = None;
                self.namespace_runtime.clear();
                self.retire_sdk_hosts();
            }
            return Err(error);
        }
        Ok(response)
    }
}

#[cfg(test)]
#[path = "service_sdk_advanced_tests.rs"]
mod advanced_tests;
