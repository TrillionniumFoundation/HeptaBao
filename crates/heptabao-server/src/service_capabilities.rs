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
            if method != "POST" {
                return Err(Response::error(405, "method not allowed"));
            }
            let object = body
                .as_object()
                .ok_or_else(|| Response::error(400, "request must be an object"))?;
            let selector = match path {
                "sys/capabilities" => Some("token"),
                "sys/capabilities-accessor" => Some("accessor"),
                _ => None,
            };
            if object
                .keys()
                .any(|key| key != "paths" && key != "path" && Some(key.as_str()) != selector)
            {
                return Err(Response::error(400, "unsupported capabilities parameter"));
            }
            let paths: Vec<&str> = match (body.get("paths"), body.get("path")) {
                (Some(Value::Array(paths)), None) if !paths.is_empty() && paths.len() <= 64 => {
                    paths
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .ok_or_else(|| Response::error(400, "paths must contain strings"))
                        })
                        .collect::<Result<_, _>>()?
                }
                (None, Some(Value::String(path))) => vec![path.as_str()],
                _ => return Err(Response::error(400, "supply one path or 1-64 paths")),
            };
            let unique: BTreeSet<_> = paths.iter().copied().collect();
            if unique.len() != paths.len() {
                return Err(Response::error(
                    400,
                    "duplicate capability paths are unsupported",
                ));
            }
            let target: crate::auth::InspectionTarget = state
                .auth
                .inspection_target(actor, namespace, path, body, now)
                .map_err(|e| Response::error(e.status, &e.message))?;
            let (policies, disabled) = match target.entity_id.as_deref() {
                Some(id) => match state.engines.identity_projection(namespace, id) {
                    Ok(projection) => (projection.policies, projection.disabled),
                    Err(e) if e.status == 404 => (BTreeSet::new(), true),
                    Err(e) => return Err(Response::error(e.status, &e.message)),
                },
                None => (BTreeSet::new(), false),
            };
            let mut data = serde_json::Map::new();
            for requested in &paths {
                let capabilities = state
                    .auth
                    .inspect_capabilities(namespace, requested, &target, &policies, disabled)
                    .map_err(|e| Response::error(e.status, &e.message))?;
                data.insert((*requested).into(), json!(capabilities));
            }
            if paths.len() == 1 {
                data.insert("capabilities".into(), data[paths[0]].clone());
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
