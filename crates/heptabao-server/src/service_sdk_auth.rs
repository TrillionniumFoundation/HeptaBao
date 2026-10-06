//! The real SDK credential family uses the original Service admission and
//! encrypted auth owner. Plugin JSON never becomes a Principal or bearer.
use super::*;
use crate::auth::Timestamp;
use crate::auth::sdk::{Binding, Entry, Paths};
use heptabao_plugin_host::sdk_backend::SdkBackendType;

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
}
struct Transaction {
    auth: CowOwner<AuthState>,
    identity: crate::state_record_root::StateIdentity,
}
pub(in crate::service) struct Plan {
    context: Context,
    binding: Binding,
    paths: Option<Paths>,
    caller: Mutex<Option<plugin::PluginResponseAuthority>>,
    control: Arc<Control>,
    transaction: Mutex<Transaction>,
    operation: String,
    path: String,
    data: Value,
    deadline: Instant,
}
impl Drop for Plan {
    fn drop(&mut self) {
        erase_json(&mut self.data)
    }
}
impl Plan {
    pub(in crate::service) fn execute(
        &self,
        service: &Arc<Mutex<Service>>,
        deadline: Instant,
    ) -> Result<Option<Value>, Response> {
        let deadline = deadline.min(self.deadline);
        if self.control.fenced.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(Response::error(
                503,
                "SDK Auth original owner or deadline unavailable",
            ));
        }
        if self
            .control
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Response::error(503, "SDK Auth mount is busy before entry"));
        }
        let (events, received) = mpsc::channel();
        let job = WorkerJob {
            operation: self.operation.clone(),
            path: self.path.clone(),
            data: self.data.clone(),
            lease: None,
            expected_auth_paths: if self.operation == "_mount" {
                None
            } else {
                Some(self.paths.clone().unwrap_or_else(Paths::legacy).wire())
            },
            deadline,
            events,
        };
        if self
            .control
            .sender
            .try_send(WorkerCommand::Invoke(job))
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
        if let Some(caller) = self
            .caller
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth original capsule unavailable"))?
            .as_mut()
        {
            caller.apply_sdk_auth_clock_floor(auth)?;
            caller.validate_live_auth(auth)?;
        }
        self.time(auth)?;
        Ok(())
    }
}
fn auth_error(error: crate::auth::AuthError) -> Response {
    Response::error(error.status, &error.message)
}
fn sdk_auth_key(cluster: &str, binding: &Binding) -> Result<String, Response> {
    let data = serde_json::to_vec(&(cluster, binding))
        .map_err(|_| Response::error(503, "SDK Auth host identity encoding failed"))?;
    Ok(format!("AUTH:{}", hex(&crypto::digest(&data))))
}
fn empty_response() -> Response {
    Response {
        status: 204,
        body: json!({}),
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
        let relative = if control {
            None
        } else {
            match state.auth.sdk_auth_binding(request.namespace, request.path) {
                Ok(Some(b)) => Some(b),
                Ok(None) => return Response::error(404, "SDK Auth mount not found"),
                Err(e) => return auth_error(e),
            }
        };
        let path_policy = match relative.as_ref() {
            Some(binding) => match state.auth.sdk_auth_paths(binding) {
                Ok(paths) => Some(paths.unwrap_or_else(Paths::legacy)),
                Err(error) => return auth_error(error),
            },
            None => None,
        };
        let relative_path = relative.as_ref().and_then(|binding| {
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
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Response::error(501, "SDK Auth response wrapping is not implemented");
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
                let key = match sdk_auth_key(&state.cluster_id, &binding) {
                    Ok(k) => k,
                    Err(e) => return e,
                };
                if self
                    .sdk_hosts
                    .get(&key)
                    .is_some_and(|c| c.busy.load(Ordering::Acquire))
                {
                    return Response::error(503, "SDK Auth mount is busy before retirement");
                }
                let response = state.auth.handle_with_connection_clock(
                    caller.as_ref().map(|a| a.principal()),
                    request.namespace,
                    request.method,
                    request.path,
                    request.body,
                    request
                        .token_time()
                        .unwrap_or(AuthorityTime::Coarse(request.now)),
                    Some(clock),
                    request.client_certificates,
                    request.origin_peer,
                );
                match response {
                    Ok(Some(r)) if r.status == 204 => {}
                    Ok(_) => return Response::error(503, "SDK Auth retirement returned no owner"),
                    Err(e) => return auth_error(e),
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
                if let Some(host) = self.sdk_hosts.remove(&key) {
                    host.retire()
                }
                self.pending_sdk_control_authority = caller;
                return empty_response();
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
            self.state = Some(state.clone());
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
                },
            );
        }
        let Some(binding) = relative else {
            return Response::error(503, "SDK Auth actual mount binding absent");
        };
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
        let StageTarget {
            binding,
            caller,
            context,
            operation,
            path,
            deadline,
        } = target;
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
            let control = match start_worker_typed(launch, SdkBackendType::Auth) {
                Ok(c) => c,
                Err(e) => return e,
            };
            self.sdk_hosts.insert(key, Arc::clone(&control));
            control
        };
        let identity = match self.current_state_identity() {
            Ok(id) => id,
            Err(e) => return e,
        };
        let paths = match state.auth.sdk_auth_paths(&binding) {
            Ok(paths) => paths,
            Err(error) => return auth_error(error),
        };
        self.pending_sdk_auth_request = Some(Plan {
            context,
            binding,
            paths,
            caller: Mutex::new(caller),
            control,
            transaction: Mutex::new(Transaction {
                auth: state.auth.clone(),
                identity,
            }),
            operation: operation.into(),
            path: path.into(),
            data: request.body.clone(),
            deadline,
        });
        Response::error(500, "SDK Auth invocation was not dispatched")
    }
    fn sdk_auth_gate(&mut self, plan: &Plan) -> Result<(), Response> {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        if plan.operation != "_mount" {
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
        if Instant::now() >= plan.deadline || plan.control.fenced.load(Ordering::Acquire) {
            return Err(Response::error(
                503,
                "SDK Auth original owner or deadline fenced",
            ));
        }
        let mut caller = plan
            .caller
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth original capsule unavailable"))?;
        if let Some(caller) = caller.as_mut() {
            if let Some(state) = self.state.as_ref() {
                caller.apply_sdk_auth_clock_floor(&state.auth)?;
            }
            self.validate_plugin_response(caller)?;
            if let Some(state) = self.state.as_ref() {
                caller.apply_sdk_auth_clock_floor(&state.auth)?;
                caller.validate_live_auth(&state.auth)?;
            }
        } else {
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
        state
            .auth
            .sdk_auth_owner_gate(&plan.binding)
            .map_err(auth_error)?;
        plan.time(&state.auth)?;
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
        self.sdk_auth_gate(plan)?;
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth transaction unavailable"))?;
        if self.current_state_identity()? != transaction.identity {
            return Err(Response::error(
                503,
                "SDK Auth Storage root changed since admission",
            ));
        }
        let mut current = self
            .state
            .clone()
            .ok_or_else(|| Response::error(503, "SDK Auth current owner unavailable"))?;
        let at = plan.time(&current.auth)?;
        let changed = current.auth.observe_sdk_auth_clock(at);
        if changed {
            current.schema = current.writer_schema();
            let publication = self.prepare_record_plan(&mut current)?;
            self.sdk_auth_gate(plan)?;
            self.commit_record_plan_with_before_publish(
                &current,
                publication,
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
        let reply = match operation {
            StorageOp::Get(key) => StorageReply::Entry(
                transaction
                    .auth
                    .sdk_auth_storage_get(&plan.binding, &key)
                    .map_err(auth_error)?
                    .map(|entry| SdkStorageEntry {
                        key: entry.key,
                        value: entry.value,
                        seal_wrap: entry.seal_wrap,
                    }),
            ),
            StorageOp::Put(entry) => {
                transaction
                    .auth
                    .sdk_auth_storage_put(
                        &plan.binding,
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
                transaction
                    .auth
                    .sdk_auth_storage_delete(&plan.binding, &key)
                    .map_err(auth_error)?;
                StorageReply::Empty
            }
            StorageOp::List(prefix, after, limit) => StorageReply::Keys(
                transaction
                    .auth
                    .sdk_auth_storage_list(&plan.binding, &prefix, &after, limit)
                    .map_err(auth_error)?,
            ),
        };
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
        let result = self.finish_sdk_auth_candidate(plan, value.as_ref());
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
        self.sdk_auth_gate(plan)?;
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| Response::error(503, "SDK Auth transaction unavailable"))?;
        if self.current_state_identity()? != transaction.identity {
            return Err(Response::error(
                503,
                "SDK Auth original root changed before publication",
            ));
        }
        let mut candidate = self
            .state
            .clone()
            .ok_or_else(|| Response::error(503, "SDK Auth current state unavailable"))?;
        candidate.auth = transaction.auth.clone();
        let at = plan.time(&candidate.auth)?;
        candidate.auth.observe_sdk_auth_clock(at);
        let mut response = if plan.operation == "_mount" {
            let metadata = value
                .and_then(|value| value.get("auth_paths"))
                .ok_or_else(|| Response::error(503, "SDK owned Setup metadata missing"))?;
            let paths = Paths::from_actual(metadata).map_err(auth_error)?;
            candidate
                .auth
                .capture_sdk_auth_paths(&plan.binding, paths)
                .map_err(auth_error)?;
            empty_response()
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
                .finish_sdk_auth_login(&plan.binding, auth, plan.context.clock)
                .map_err(auth_error)?;
            Self::finish_identity_response_observed(
                &mut candidate.auth,
                &mut candidate.engines,
                &mut issued,
                &plan.context.namespace,
                at.seconds(),
                AuthorityTime::Precise(at),
            )?;
            Response {
                status: issued.status,
                body: std::mem::take(&mut issued.body),
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
                    response_headers: Default::default(),
                    consistency_index: None,
                }
            } else {
                Response::ok(json!({"data":data}))
            }
        } else {
            empty_response()
        };
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
            self.commit_record_plan_with_before_publish(
                &candidate,
                publication,
                |auth| plan.live_auth(auth),
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )?;
            self.state = Some(candidate);
            transaction.identity = self.current_state_identity()?;
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
    pub(in crate::service) fn complete_sdk_auth_delivery(
        &mut self,
        plan: &Plan,
        response: Response,
        fingerprint: &str,
    ) -> Response {
        let gate = self.sdk_auth_gate(plan).and_then(|()| {
            if let Some(raw) = response
                .body
                .get("auth")
                .and_then(|auth| auth.get("client_token"))
                .and_then(Value::as_str)
            {
                self.state
                    .as_ref()
                    .ok_or_else(|| Response::error(503, "SDK Auth issued owner unavailable"))?
                    .auth
                    .sdk_auth_issued_live(raw, plan.context.clock)
                    .map_err(auth_error)?;
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
    fn mount(state: &mut State, root: &str) -> Result<Binding, Box<dyn std::error::Error>> {
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
    fn publish(
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
            &json!({"Root":["root/+/write","root*","root-exact"],"Unauthenticated":["public/+/read"]}),
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
        assert!(!paths.is_root("root-exact-more"));
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
