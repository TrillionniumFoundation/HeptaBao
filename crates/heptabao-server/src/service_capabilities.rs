//! Introspection reads the same current Identity snapshot used by authorization.
use super::*;
use std::collections::BTreeSet;

impl Service {
    pub(super) fn capabilities_route(
        state: &State,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        let (mut response, observation) = Self::capabilities_route_observed(
            state,
            principal,
            namespace,
            method,
            path,
            body,
            AuthorityTime::Coarse(now),
        );
        if let Some(observation) = observation {
            let checked = principal
                .ok_or_else(|| Response::error(403, "missing client token"))
                .and_then(|actor| {
                    actor
                        .request_authority_time(AuthorityTime::Coarse(now))
                        .map_err(|error| Response::error(error.status, &error.message))
                })
                .and_then(|time| {
                    observation
                        .check_at(time)
                        .map_err(|error| Response::error(error.status, &error.message))
                });
            if let Err(error) = checked {
                erase_json(&mut response.body);
                return error;
            }
        }
        response
    }

    pub(super) fn capabilities_route_observed(
        state: &State,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> (Response, Option<crate::auth::InspectionObservation>) {
        let result = (|| {
            let actor = principal.ok_or_else(|| Response::error(403, "missing client token"))?;
            let time = actor
                .request_authority_time(time)
                .map_err(|error| Response::error(error.status, &error.message))?;
            state
                .auth
                .authorize_request_observed(actor, namespace, path, "update", time)
                .map_err(|e| Response::error(e.status, &e.message))?;
            if !matches!(method, "POST" | "PUT") {
                return Err(Response::error(405, "method not allowed"));
            }
            let object = body
                .as_object()
                .ok_or_else(|| Response::error(400, "request must be an object"))?;
            // Match v2.7.0 framework.TypeCommaStringSlice. Both declared fields
            // are validated, then the nonempty plural value takes precedence.
            // Unknown fields remain metadata and never select a Principal.
            let plural = capabilities_paths(object.get("paths"), "paths")?;
            let singular = capabilities_paths(object.get("path"), "path")?;
            let paths = if plural.is_empty() { singular } else { plural };
            if paths.is_empty() {
                return Err(Response::error(400, "paths must be supplied"));
            }
            let selector = if path == "sys/capabilities-accessor" {
                "accessor"
            } else {
                "token"
            };
            let target = Self::capabilities_inspection_target_observed(
                &state.auth,
                actor,
                namespace,
                path,
                body,
                time,
            )?;
            let (policies, disabled, templates) = match target.entity_id.as_deref() {
                Some(id) => match state.engines.identity_projection(namespace, id) {
                    Ok(projection) if !projection.disabled => {
                        let selectors = state
                            .auth
                            .inspection_template_selectors_observed(
                                namespace,
                                &target,
                                &projection.policies,
                                time,
                            )
                            .map_err(|e| Response::error(e.status, &e.message))?;
                        let templates = state
                            .engines
                            .identity_template_values(
                                namespace,
                                &projection,
                                &selectors,
                                |accessor| state.auth.has_mount_accessor(namespace, accessor),
                            )
                            .map_err(|e| Response::error(e.status, &e.message))?;
                        (projection.policies, false, templates)
                    }
                    // OpenBao 2.7.1 Core.Capabilities rejects disabled or
                    // missing target entities before constructing their ACL.
                    // The public non-self backend masks that denial as an
                    // invalid token; it is not a successful ["deny"] reply.
                    Ok(_) => return Err(capabilities_identity_denied(path)),
                    Err(e) if e.status == 404 || e.status == 403 => {
                        return Err(capabilities_identity_denied(path));
                    }
                    Err(e) => return Err(Response::error(e.status, &e.message)),
                },
                None => (
                    BTreeSet::new(),
                    false,
                    crate::auth::IdentityTemplateValues::default(),
                ),
            };
            let mut data = serde_json::Map::new();
            for requested in &paths {
                if crate::request_deadline::current()
                    .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                {
                    return Err(Response::error(503, "request deadline exceeded"));
                }
                let capabilities = state
                    .auth
                    .inspect_capabilities_observed(
                        namespace, requested, &target, &policies, disabled, &templates, time,
                    )
                    .map_err(|e| Response::error(e.status, &e.message))?;
                data.insert(requested.clone(), json!(capabilities));
            }
            if paths.len() == 1 {
                data.insert("capabilities".into(), data[&paths[0]].clone());
            }
            // OpenBao projects capability entries both at the top level and
            // under data. Envelope keys never overwrite the authoritative map.
            let mut envelope = data.clone();
            envelope.insert("data".into(), Value::Object(data));
            let ignored: Vec<_> = object
                .keys()
                .filter(|key| !matches!(key.as_str(), "path" | "paths") && key.as_str() != selector)
                .map(String::as_str)
                .collect();
            if !ignored.is_empty() {
                envelope.insert(
                    "warnings".into(),
                    json!([format!(
                        "Endpoint ignored these unrecognized parameters: [{}]",
                        ignored.join(" ")
                    )]),
                );
            }
            let observation = state
                .auth
                .retain_inspection_observation(namespace, target, &policies, time)
                .map_err(|error| Response::error(error.status, &error.message))?;
            Ok((Response::ok(Value::Object(envelope)), observation))
        })();
        match result {
            Ok((response, observation)) => (response, Some(observation)),
            Err(error) => (error, None),
        }
    }

    /// The original field conversion and read-only target selection. This
    /// never authenticates a target for execution or consumes a target use.
    pub(super) fn capabilities_inspection_target_observed(
        auth: &AuthState,
        actor: &Principal,
        namespace: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<crate::auth::InspectionTarget, Response> {
        let object = body
            .as_object()
            .ok_or_else(|| Response::error(400, "request must be an object"))?;
        let selector = if path == "sys/capabilities-accessor" {
            "accessor"
        } else {
            "token"
        };
        // Only the declared target field is needed by Auth. Retain the public
        // request separately and erase this temporary credential spelling.
        let mut target_body = json!({});
        let result = (|| {
            if let Some(value) = object.get(selector) {
                let spelling = capabilities_scalar(value).ok_or_else(|| {
                    let kind = if value.is_object() {
                        "map[string]interface {}"
                    } else {
                        "[]interface {}"
                    };
                    Response::error(400, &format!(
                        "Field validation failed: error converting input for field \"{selector}\": '' expected type 'string', got unconvertible type '{kind}'"
                    ))
                })?;
                target_body[selector] = Value::String(spelling);
            }
            let inspected = match time {
                AuthorityTime::Coarse(now) => {
                    auth.inspection_target(actor, namespace, path, &target_body, now)
                }
                AuthorityTime::Precise(_) => {
                    auth.inspection_target_observed(actor, namespace, path, &target_body, time)
                }
            };
            inspected.map_err(|error| Response::error(error.status, &error.message))
        })();
        erase_json(&mut target_body);
        result
    }
}

fn capabilities_identity_denied(path: &str) -> Response {
    if path == "sys/capabilities-self" {
        Response::error(403, "permission denied")
    } else {
        Response::error(400, "invalid token")
    }
}

// The original HTTP body limit bounds allocations. These values describe ACL
// queries only; ordinary route validation and namespace admission stay separate.
fn capabilities_scalar(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some(String::new()),
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(if *value { "1" } else { "0" }.into()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn capabilities_go_value(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".into(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(capabilities_go_value)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::Object(values) => format!(
            "map[{}]",
            values
                .iter()
                .map(|(key, value)| format!("{key}:{}", capabilities_go_value(value)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

pub(super) fn capabilities_paths(
    value: Option<&Value>,
    field: &str,
) -> Result<Vec<String>, Response> {
    let values: Vec<&Value> = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Object(map)) if map.is_empty() => return Ok(Vec::new()),
        Some(Value::String(value)) if value.is_empty() => return Ok(Vec::new()),
        Some(Value::String(value)) => {
            return Ok(value
                .split(',')
                .map(|part| part.trim().to_owned())
                .collect());
        }
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
    };
    let mut decoded = Vec::with_capacity(values.len());
    let mut errors = Vec::new();
    for (index, value) in values.into_iter().enumerate() {
        if let Some(value) = capabilities_scalar(value) {
            decoded.push(value.trim().to_owned());
        } else {
            let kind = if value.is_object() {
                "map[string]interface {}"
            } else {
                "[]interface {}"
            };
            errors.push(format!(
                "'[{index}]' expected type 'string', got unconvertible type '{kind}', value: '{}'",
                capabilities_go_value(value)
            ));
        }
    }
    if errors.is_empty() {
        return Ok(decoded);
    }
    errors.sort_unstable();
    Err(Response::error(
        400,
        &format!(
            "Field validation failed: error converting input for field \"{field}\": {} error(s) decoding:\n\n* {}",
            errors.len(),
            errors.join("\n* ")
        ),
    ))
}

#[cfg(test)]
#[path = "service_capabilities_identity_expiration_tests.rs"]
mod identity_expiration_tests;
