//! A real local Transit runtime reload. Admission owns the original principal,
//! request and exact mount/configuration basis until terminal audit completes.
use super::*;

pub(in crate::service) struct AcceptedReload {
    actor: plugin::PluginResponseAuthority,
    namespace: String,
    namespace_incarnation: u64,
    targets: Vec<crate::engines::TransitCacheReloadMount>,
    deadline: std::time::Instant,
}

fn mount_path(input: &str) -> Result<String, Response> {
    let path = input.trim().trim_end_matches('/');
    if path.is_empty() || path.len() > 256 || path.starts_with('/')
        || path.split('/').any(|part| part.is_empty() || matches!(part, "." | ".."))
        || path.chars().any(|c| c.is_control() || matches!(c, '?' | '#' | '\\')) {
        return Err(Response::error(400, "reload mount must be a canonical relative path"));
    }
    Ok(format!("{path}/"))
}

fn selection(body: &Value) -> Result<(Option<Vec<String>>, bool), Response> {
    let object = body.as_object().ok_or_else(|| Response::error(400, "reload requires an object"))?;
    if object.keys().any(|key| !matches!(key.as_str(), "plugin" | "mounts" | "scope")) {
        return Err(Response::error(400, "unsupported reload field"));
    }
    if object.contains_key("plugin") && object.contains_key("mounts") {
        return Err(Response::error(400, "plugin and mounts are mutually exclusive"));
    }
    let scope = match object.get("scope") {
        None => "",
        Some(Value::String(value)) => value.as_str(),
        _ => return Err(Response::error(400, "reload scope must be a string")),
    };
    let paths = if let Some(plugin) = object.get("plugin") {
        let plugin = plugin.as_str().ok_or_else(|| Response::error(400, "reload plugin must be a string"))?;
        if plugin.is_empty() { return Err(Response::error(400, "reload selector is required")); }
        if plugin != "transit" { return Err(Response::error(501, "reload consumer is not implemented for this plugin")); }
        None
    } else if let Some(mounts) = object.get("mounts") {
        let names = match mounts {
            Value::String(value) => value.split(',').map(str::to_owned).collect::<Vec<_>>(),
            Value::Array(values) => values.iter().map(|value| value.as_str()
                .map(str::to_owned).ok_or_else(|| Response::error(400, "reload mounts must contain strings")))
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(Response::error(400, "reload mounts must be an array or comma-separated string")),
        };
        if names.is_empty() || names.len() > 64 {
            return Err(Response::error(400, "reload selector count is outside the supported bound"));
        }
        Some(names.iter().map(|name| mount_path(name)).collect::<Result<Vec<_>, _>>()?)
    } else { return Err(Response::error(400, "reload selector is required")); };
    // The real OpenBao probe accepts unknown string scopes as local.
    Ok((paths, scope == "global"))
}

fn reload_id() -> Result<String, Response> {
    let mut bytes = crypto::random::<16>().map_err(|error| Response::error(503, error))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let text = hex(&bytes);
    Ok(format!("{}-{}-{}-{}-{}", &text[..8], &text[8..12], &text[12..16], &text[16..20], &text[20..]))
}

impl Service {
    pub(in crate::service) fn transit_cache_reload_route(&mut self, state: State,
        actor: Option<Principal>, request: &RequestView<'_>) -> Response {
        let run = (|| {
            if !matches!(request.method, "POST" | "PUT") {
                return Err(Response::error(405, "reload requires POST or PUT"));
            }
            if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
                return Err(Response::error(501, "reload response wrapping is not implemented"));
            }
            let deadline = crate::request_deadline::current()
                .ok_or_else(|| Response::error(503, "reload original request deadline is required"))?;
            let actor = actor.ok_or_else(|| Response::error(403, "permission denied"))?;
            let mut authority = plugin::PluginResponseAuthority::new(
                actor, &state, request, "update", true, &self.unseal_nonce);
            self.validate_plugin_response(&mut authority)?;
            let (paths, global) = selection(request.body)?;
            if global && self.ha.is_some() {
                return Err(Response::error(501, "global reload requires an implemented HA fanout consumer"));
            }
            let current = self.state.as_ref()
                .ok_or_else(|| Response::error(503, "reload accepted state is unavailable"))?;
            let incarnation = current.namespaces.incarnation(request.namespace)
                .ok_or_else(|| Response::error(503, "reload namespace owner is unavailable"))?;
            let targets = current.engines.transit_cache_reload_targets(request.namespace, paths.as_deref())
                .map_err(Response::from_engine_error)?;
            let response = Response::ok(json!({"data":{"reload_id":reload_id()?}}));
            self.pending_transit_cache_reload = Some(AcceptedReload {
                actor: authority, namespace: request.namespace.to_owned(),
                namespace_incarnation: incarnation, targets, deadline,
            });
            Ok(response)
        })();
        run.unwrap_or_else(|response| response)
    }

    pub(in crate::service) fn complete_transit_cache_reload_delivery(&mut self,
        expected: bool, mut response: Response, fingerprint: &str) -> Response {
        let mut accepted = match (expected, self.pending_transit_cache_reload.take()) {
            (false, None) => return response,
            (true, Some(owner)) => owner,
            _ => {
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "transit reload delivery capsule was lost");
            }
        };
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(accepted.deadline);
        let gate = if response.status >= 300 {
            Err(Response::error(response.status, "transit reload terminal delivery failed"))
        } else {
            self.validate_plugin_response(&mut accepted.actor).and_then(|()| {
                let state = self.state.as_ref().ok_or_else(|| Response::error(503, "reload state unavailable"))?;
                if state.namespaces.incarnation(&accepted.namespace) != Some(accepted.namespace_incarnation) {
                    return Err(Response::error(503, "reload namespace incarnation changed"));
                }
                let generation = self.durable.as_ref().ok_or_else(|| Response::error(503, "reload durable owner unavailable"))?.generation();
                state.engines.reload_accepted_transit_policy_caches(
                    &accepted.namespace, accepted.namespace_incarnation, generation, &accepted.targets)
                    .map_err(Response::from_engine_error)
            })
        };
        if let Err(error) = gate {
            erase_json(&mut response.body);
            response.response_headers.clear();
            response.consistency_index = None;
            if self.audit_event("transit-reload-delivery-veto", fingerprint,
                accepted.actor.now(), Some(error.status)).is_err() {
                self.recovery_required = true;
                self.ha_activation = None;
            }
            return error;
        }
        response
    }
}
