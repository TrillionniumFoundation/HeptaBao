//! Service-only compatibility entrypoint; ordinary internal Identity contracts
//! remain strict. The same namespace graph is staged and published exactly once.
use super::*;

fn api_request<'a>(path: &'a str, body: &Value) -> Result<(&'a str, SecretJson)> {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let path = path.trim_start_matches('/');
    let mut params = SecretJson(body.clone());
    if params.is_null() {
        *params = json!({});
    }
    let map = params
        .as_object_mut()
        .ok_or_else(|| bad("request body must be an object"))?;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| bad("invalid query parameter"))?;
        if map.contains_key(key) {
            return Err(bad("duplicate request parameter"));
        }
        map.insert(key.into(), Value::String(value.into()));
    }
    Ok((path, params))
}

impl EngineState {
    pub(crate) fn identity_api_alias_accessor(
        &self,
        namespace: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<String>> {
        let (base, _) = path.split_once('?').unwrap_or((path, ""));
        if !identity::api::owns(base) {
            return Ok(None);
        }
        let (path, params) = api_request(path, body)?;
        let fallback = identity::IdentityState::default();
        let identity = self
            .namespaces
            .get(namespace)
            .map(|state| &state.identity)
            .unwrap_or(&fallback);
        identity::api::alias_write_accessor(identity, path, &params)
    }

    pub(crate) fn handle_identity_api(
        &mut self,
        scope: &IdentityNamespace<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<EngineResponse>> {
        let (base, _) = path.split_once('?').unwrap_or((path, ""));
        if !identity::api::owns(base) {
            return Ok(None);
        }
        let (path, params) = api_request(path, body)?;
        let method = kv_request_method(method, &params);
        let mut candidate = self
            .namespaces
            .get(scope.path)
            .map(|state| state.identity.clone())
            .unwrap_or_default();
        candidate.set_uuid_namespace(scope.id)?;
        let response = identity::api::handle(
            &mut candidate,
            method,
            path,
            &params,
            now,
            scope.id.unwrap_or("root"),
        )?;
        candidate.set_uuid_namespace(None)?;
        if response.mutated {
            self.namespaces
                .entry(scope.path.into())
                .or_default()
                .identity = candidate;
        }
        Ok(Some(response))
    }
}
