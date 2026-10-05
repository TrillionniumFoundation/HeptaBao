//! Service-owned SDK secret lease callbacks and atomic Storage/registry publication.
//! No plugin reply can mint an Auth Principal. Callback authority is the same
//! admitted HTTP actor and original precise clock, held by Plan.
use super::*;
use crate::auth::Timestamp;
use crate::engines::sdk_lease::{Binding, Grant, Lease, Phase};

struct Payload(Value);
impl std::ops::Deref for Payload {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl std::ops::DerefMut for Payload {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}
impl Drop for Payload {
    fn drop(&mut self) {
        erase_json(&mut self.0);
    }
}
pub(super) struct LeaseCall {
    record: Lease,
    action: &'static str,
    increment_ns: u64,
}
impl LeaseCall {
    pub(super) fn request_data(&self) -> Value {
        self.record.response_data()
    }
    pub(super) fn callback(&self) -> Result<SdkLeaseCallback, Response> {
        Ok(SdkLeaseCallback {
            secret: self.record.callback(),
            issue_time_ns: self
                .record
                .issue_ns()
                .map_err(Response::from_engine_error)?,
            increment_ns: self.increment_ns,
        })
    }
}
pub(super) fn precise(
    authority: &plugin::PluginResponseAuthority,
    state: &State,
) -> Result<Timestamp, Response> {
    let at = state
        .auth
        .token_api_observed_time(authority.token_time()?)
        .exact()
        .ok_or_else(|| Response::error(503, "SDK secret lease requires original precise clock"))?;
    Ok(state
        .engines
        .sdk_lease_clock_floor()
        .map_or(at, |floor| at.max(floor)))
}
fn body_action<'a>(request: &'a RequestView<'_>) -> Option<(&'static str, &'a str)> {
    let (action, path_id) = if request.path == "sys/leases/lookup" {
        ("lookup", None)
    } else if request.path == "sys/leases/renew" {
        ("renew", None)
    } else if request.path == "sys/leases/revoke" {
        ("revoke", None)
    } else if let Some(id) = request.path.strip_prefix("sys/leases/renew/") {
        ("renew", Some(id))
    } else {
        let id = request.path.strip_prefix("sys/leases/revoke/")?;
        ("revoke", Some(id))
    };
    request
        .body
        .get("lease_id")
        .and_then(Value::as_str)
        .or(path_id)
        .map(|id| (action, id))
}
fn grant(mut secret: Value, data: Value, at: Timestamp) -> Result<Grant, Response> {
    let parsed = (|| {
        let object = secret
            .as_object_mut()
            .ok_or_else(|| Response::error(502, "SDK Secret must be an object"))?;
        if object.keys().any(|k| {
            !matches!(
                k.as_str(),
                "internal_data" | "LeaseID" | "lease" | "max_ttl" | "renewable"
            )
        }) || object.get("internal_data").is_none_or(|v| !v.is_object())
            || !data.is_object()
        {
            return Err(Response::error(502, "SDK Secret metadata rejected"));
        }
        let duration = |key: &str, default: u64| -> Result<u64, Response> {
            object
                .get(key)
                .map_or(Ok(default), |v| {
                    v.as_u64()
                        .filter(|n| *n <= i64::MAX as u64)
                        .ok_or_else(|| Response::error(502, "SDK lease duration rejected"))
                })
                .map(|n| if n == 0 { default } else { n })
        };
        let max = duration("max_ttl", 2_764_800_000_000_000)?;
        let ttl = duration("lease", 2_764_800_000_000_000)?.min(max);
        let renewable = object
            .get("renewable")
            .and_then(Value::as_bool)
            .ok_or_else(|| Response::error(502, "SDK lease renewable type rejected"))?;
        object.insert("LeaseID".into(), Value::String(String::new()));
        Ok((ttl, max, renewable))
    })();
    match parsed {
        Ok((ttl_ns, max_ttl_ns, renewable)) => Ok(Grant {
            issued: at,
            ttl_ns,
            max_ttl_ns,
            renewable,
            secret,
            data,
        }),
        Err(error) => {
            erase_json(&mut secret);
            let mut data = data;
            erase_json(&mut data);
            Err(error)
        }
    }
}
impl Service {
    pub(in crate::service) fn sdk_lease_handles(
        &self,
        state: &State,
        request: &RequestView<'_>,
    ) -> bool {
        body_action(request)
            .is_some_and(|(_, id)| state.engines.sdk_lease(request.namespace, id).is_some())
    }
    pub(in crate::service) fn sdk_lease_route(
        &mut self,
        state: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let Some((action, id)) = body_action(request) else {
            return Response::error(400, "lease_id is required");
        };
        if !matches!(request.method, "PUT" | "POST") {
            return Response::error(405, "SDK lease administration requires POST or PUT");
        }
        let fields = if action == "renew" {
            &["lease_id", "increment"][..]
        } else if action == "revoke" {
            &["lease_id", "sync"][..]
        } else {
            &["lease_id"][..]
        };
        if request
            .body
            .as_object()
            .is_none_or(|o| o.keys().any(|k| !fields.contains(&k.as_str())))
            || request.body.get("sync").is_some_and(|v| !v.is_boolean())
        {
            return Response::error(400, "invalid SDK lease request fields");
        }
        if request
            .path
            .rsplit_once('/')
            .filter(|_| {
                request.path.starts_with("sys/leases/renew/")
                    || request.path.starts_with("sys/leases/revoke/")
            })
            .is_some()
            && request
                .body
                .get("lease_id")
                .and_then(Value::as_str)
                .is_some_and(|body| !request.path.ends_with(&format!("/{body}")))
        {
            return Response::error(400, "lease_id conflicts with authorized path");
        }
        let mut authority = plugin::PluginResponseAuthority::new(
            principal,
            &state,
            request,
            "update",
            false,
            &self.unseal_nonce,
        )
        .with_sdk_clock();
        if let Err(error) = self.validate_plugin_response(&mut authority) {
            return error;
        }
        let at = match precise(&authority, &state) {
            Ok(at) => at,
            Err(e) => return e,
        };
        let Some(record) = state.engines.sdk_lease(request.namespace, id) else {
            return Response::error(400, "lease not found");
        };
        if record.cluster != state.cluster_id {
            return Response::error(503, "SDK lease cluster owner rejected");
        }
        if action == "lookup" {
            let mut candidate = self.state.clone().unwrap_or(state.clone());
            if candidate.engines.observe_sdk_lease_clock(at) {
                candidate.schema = candidate.writer_schema();
                let publication = match self.prepare_record_plan(&mut candidate) {
                    Ok(plan) => plan,
                    Err(error) => return error,
                };
                if let Err(error) = self.validate_plugin_response(&mut authority) {
                    return error;
                }
                if let Err(error) = self.commit_record_plan_with_before_publish(
                    &candidate,
                    publication,
                    |auth| authority.validate_live_auth(auth),
                    #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                    None,
                ) {
                    return error;
                }
                self.state = Some(candidate);
            }
            let body = match record.lookup(at) {
                Ok(value) => value,
                Err(error) => return Response::from_engine_error(error),
            };
            self.pending_sdk_control_authority = Some(authority);
            return Response::ok(json!({"data":body}));
        }
        if record.phase == Phase::Revoked {
            if action == "revoke" {
                self.pending_sdk_control_authority = Some(authority);
                return Response {
                    status: 204,
                    body: json!({}),
                    response_headers: Default::default(),
                    consistency_index: None,
                };
            }
            return Response::error(400, "lease not found");
        }
        if action == "renew"
            && (at >= record.expires
                || !record.renewable
                || state
                    .auth
                    .resolve_lease_owner_observed(
                        &record.issuer,
                        request.namespace,
                        AuthorityTime::Precise(at),
                    )
                    .is_none())
        {
            return Response::error(400, "lease is expired, revoked or not renewable");
        }
        let increment = request.body.get("increment").map_or(Ok(0), |v| {
            v.as_u64()
                .and_then(|n| n.checked_mul(1_000_000_000))
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or_else(|| Response::error(400, "invalid lease increment"))
        });
        let increment = match increment {
            Ok(n) => n,
            Err(e) => return e,
        };
        let Some((mount, owner)) = state
            .engines
            .sdk_mount_binding(request.namespace, &record.mount)
            .filter(|(m, o)| m == &record.mount && record.same_backend(o))
        else {
            return Response::error(503, "SDK lease backend owner unavailable");
        };
        let path = record.path.strip_prefix(&mount).unwrap_or("").to_owned();
        self.stage_sdk_plan(
            &state,
            authority,
            request,
            StageTarget {
                mount,
                owner,
                operation: action,
                path: &path,
                lease: Some(LeaseCall {
                    record,
                    action,
                    increment_ns: increment,
                }),
            },
        )
    }
    pub(super) fn finalize_sdk_transaction(
        &mut self,
        plan: &Plan,
        mut response: Option<Value>,
    ) -> Response {
        let result = (|| {
            let mut authority = plan
                .authority
                .lock()
                .map_err(|_| Response::error(503, "SDK affine authority unavailable"))?;
            self.validate_plugin_response(&mut authority)?;
            self.sdk_binding_gate(plan).map_err(bridge_failure)?;
            let mut transaction = plan
                .transaction
                .lock()
                .map_err(|_| Response::error(503, "SDK transaction unavailable"))?;
            if self.current_state_identity()? != transaction.identity {
                return Err(Response::error(
                    503,
                    "SDK transaction snapshot changed before publication",
                ));
            }
            let mut state = self
                .state
                .clone()
                .ok_or_else(|| Response::error(503, "SDK server sealed"))?;
            state.engines = transaction.engines.clone();
            let changed_clock = authority.observe_candidate_time_changed(&mut state)?;
            let at = precise(&authority, &state)?;
            let sdk_clock_changed = state.engines.observe_sdk_lease_clock(at);
            let mut changed = transaction.changed || changed_clock || sdk_clock_changed;
            let mut status = if plan.operation == "read" { 404 } else { 204 };
            let mut body = Payload(json!({}));
            let mut headers = ResponseHeaders::default();
            let mut secret = Payload(Value::Null);
            let mut data = Payload(Value::Null);
            let mut warnings = Payload(Value::Null);
            if let Some(value) = response.as_mut() {
                if ["auth", "wrap_info"]
                    .iter()
                    .any(|key| value.get(*key).is_none_or(|v| !v.is_null()))
                    || value.get("redirect").is_none_or(|v| v.as_str() != Some(""))
                {
                    return Err(Response::error(
                        501,
                        "SDK auth, redirect and wrapping are not implemented",
                    ));
                }
                headers = ResponseHeaders::from_sdk(
                    value.get("headers"),
                    &plan.owner.allowed_response_headers,
                )
                .map_err(|_| Response::error(501, "SDK response header value rejected"))?;
                secret.0 = value
                    .get_mut("secret")
                    .map(std::mem::take)
                    .unwrap_or(Value::Null);
                data.0 = value
                    .get_mut("data")
                    .map(std::mem::take)
                    .unwrap_or(Value::Null);
                warnings.0 = value
                    .get_mut("warnings")
                    .map(std::mem::take)
                    .unwrap_or(Value::Null);
                if data.get("errors").is_some() {
                    let errors = data["errors"].clone();
                    erase_json(&mut data);
                    erase_json(&mut secret);
                    return Ok(Response {
                        status: 400,
                        body: json!({"errors":errors}),
                        response_headers: Default::default(),
                        consistency_index: None,
                    });
                }
                status = 200;
                body.0 = json!({"data":data.clone()});
            }
            let at = if !secret.is_null() || plan.lease.is_some() {
                let grant_at = precise(&authority, &state)?;
                // The actual affine clock continues while SDK I/O runs. Bind the
                // durable floor to the very sample used by this published grant.
                changed |= state.engines.observe_sdk_lease_clock(grant_at);
                Some(grant_at)
            } else {
                None
            };
            if let Some(call) = &plan.lease {
                let current = state
                    .engines
                    .sdk_lease(&plan.namespace, &call.record.id)
                    .ok_or_else(|| {
                        Response::error(503, "SDK lease changed before callback publication")
                    })?;
                if current.phase != call.record.phase
                    || current.expires != call.record.expires
                    || current.renewed != call.record.renewed
                    || current.issuer != call.record.issuer
                    || current.cluster != state.cluster_id
                    || !current.same_backend(&plan.owner)
                {
                    return Err(Response::error(503, "SDK lease callback owner changed"));
                }
                let mut lease = current;
                if call.action == "renew" {
                    let at = at.ok_or_else(|| {
                        Response::error(503, "SDK original lease clock unavailable")
                    })?;
                    if at >= lease.expires
                        || state
                            .auth
                            .resolve_lease_owner_observed(
                                &lease.issuer,
                                &plan.namespace,
                                AuthorityTime::Precise(at),
                            )
                            .is_none()
                    {
                        return Err(Response::error(
                            400,
                            "SDK lease owner expired during callback",
                        ));
                    }
                    let grant = grant(
                        std::mem::take(&mut secret.0),
                        std::mem::take(&mut data.0),
                        at,
                    )?;
                    lease.renew(grant).map_err(Response::from_engine_error)?;
                    body.0 = json!({"lease_id":lease.id,"lease_duration":lease.ttl_ns/1_000_000_000,"renewable":lease.renewable,"data":lease.response_data()});
                    status = 200;
                } else {
                    if !secret.is_null() {
                        return Err(Response::error(
                            502,
                            "SDK revoke returned an unexpected Secret",
                        ));
                    }
                    lease.revoke();
                    status = 204;
                    body.0 = json!({});
                }
                state
                    .engines
                    .store_sdk_lease(lease)
                    .map_err(Response::from_engine_error)?;
                changed = true;
            } else if !secret.is_null() {
                let at =
                    at.ok_or_else(|| Response::error(503, "SDK original lease clock unavailable"))?;
                let issuer = state
                    .auth
                    .typed_lease_issuer_observed(
                        authority.principal(),
                        &plan.namespace,
                        AuthorityTime::Precise(at),
                    )
                    .map_err(|e| Response::error(e.status, &e.message))?;
                let path = format!("{}{}", plan.mount, plan.path);
                let id = format!(
                    "{path}/{}",
                    hex(&crypto::random::<24>().map_err(|_| Response::error(
                        503,
                        "SDK lease identity entropy unavailable"
                    ))?)
                );
                let lease = Lease::new(
                    Binding {
                        id,
                        namespace: plan.namespace.clone(),
                        cluster: state.cluster_id.clone(),
                        mount: plan.mount.clone(),
                        path,
                        backend: plan.owner.clone(),
                        issuer: issuer.owner,
                    },
                    grant(
                        std::mem::take(&mut secret.0),
                        std::mem::take(&mut data.0),
                        at,
                    )?,
                )
                .map_err(Response::from_engine_error)?;
                body.0 = json!({"lease_id":lease.id,"lease_duration":lease.ttl_ns/1_000_000_000,"renewable":lease.renewable,"data":lease.response_data()});
                state
                    .engines
                    .store_sdk_lease(lease)
                    .map_err(Response::from_engine_error)?;
                changed = true;
            }
            erase_json(&mut data);
            erase_json(&mut secret);
            if !warnings.is_null() {
                body["warnings"] = std::mem::take(&mut warnings.0);
            }
            if changed {
                state.schema = state.writer_schema();
                let publication = self.prepare_record_plan(&mut state)?;
                self.validate_plugin_response(&mut authority)?;
                self.sdk_binding_gate(plan).map_err(bridge_failure)?;
                if self.current_state_identity()? != transaction.identity {
                    return Err(Response::error(
                        503,
                        "SDK transaction changed before publication",
                    ));
                }
                self.commit_record_plan_with_before_publish(
                    &state,
                    publication,
                    |auth| authority.validate_live_auth(auth),
                    #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                    None,
                )?;
                self.state = Some(state);
                transaction.identity = self.current_state_identity()?;
                transaction.changed = false;
            }
            self.validate_plugin_response(&mut authority)?;
            self.sdk_binding_gate(plan).map_err(bridge_failure)?;
            Ok(Response {
                status,
                body: std::mem::take(&mut body.0),
                response_headers: headers,
                consistency_index: None,
            })
        })();
        if let Some(value) = response.as_mut() {
            erase_json(value);
        }
        result.unwrap_or_else(|error| {
            plan.control.retire();
            error
        })
    }
}
