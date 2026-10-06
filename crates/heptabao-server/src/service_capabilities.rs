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
        let result = (|| {
            let actor = principal.ok_or_else(|| Response::error(403, "missing client token"))?;
            state
                .auth
                .authorize_request(actor, namespace, path, "update", now)
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
            let mut target_body = body.clone();
            if let Some(value) = object.get(selector) {
                let spelling = capabilities_scalar(value).ok_or_else(|| {
                    Response::error(
                        400,
                        &format!(
                            "error converting input for field \"{selector}\": expected string"
                        ),
                    )
                })?;
                target_body[selector] = Value::String(spelling);
            }
            let target: crate::auth::InspectionTarget = state
                .auth
                .inspection_target(actor, namespace, path, &target_body, now)
                .map_err(|e| Response::error(e.status, &e.message))?;
            let (policies, disabled, templates) = match target.entity_id.as_deref() {
                Some(id) => match state.engines.identity_projection(namespace, id) {
                    Ok(projection) if !projection.disabled => {
                        let selectors = state
                            .auth
                            .inspection_template_selectors(namespace, &target, &projection.policies)
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
                    Ok(_) => (
                        BTreeSet::new(),
                        true,
                        crate::auth::IdentityTemplateValues::default(),
                    ),
                    Err(e) if e.status == 404 || e.status == 403 => (
                        BTreeSet::new(),
                        true,
                        crate::auth::IdentityTemplateValues::default(),
                    ),
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
                    .inspect_capabilities(
                        namespace, requested, &target, &policies, disabled, &templates,
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
            Ok(Response::ok(Value::Object(envelope)))
        })();
        result.unwrap_or_else(|error| error)
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

fn capabilities_paths(value: Option<&Value>, field: &str) -> Result<Vec<String>, Response> {
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
