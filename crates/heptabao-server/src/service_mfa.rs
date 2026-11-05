//! MFA routes execute only inside the original Service candidate and commit.
use super::*;
use crate::auth::mfa::NativeMfaBinding;

impl Service {
    pub(in crate::service) fn mfa_native_binding(
        namespaces: &namespaces::NamespaceRegistry,
        cluster: &str,
        namespace: &str,
    ) -> Result<NativeMfaBinding, Response> {
        let scope = namespaces.identity_namespace(namespace)?;
        let namespace_id = if namespace.is_empty() {
            "root"
        } else {
            scope
                .id
                .ok_or_else(|| Response::error(503, "MFA native namespace ID unavailable"))?
        };
        let incarnation = namespaces
            .incarnation(namespace)
            .ok_or_else(|| Response::error(503, "MFA native namespace incarnation unavailable"))?;
        let custody = if namespace.is_empty() {
            None
        } else {
            Some(namespaces.custody_binding(cluster, namespace)?)
        };
        NativeMfaBinding::from_native(cluster, namespace, namespace_id, incarnation, custody)
            .map_err(|error| Response::error(error.status, &error.message))
    }
    fn mfa_native_owner(state: &State, namespace: &str) -> Result<(String, u64), Response> {
        let scope = state.namespaces.identity_namespace(namespace)?;
        let id = if namespace.is_empty() {
            "root"
        } else {
            scope
                .id
                .ok_or_else(|| Response::error(503, "MFA native namespace ID unavailable"))?
        };
        let incarnation = state
            .namespaces
            .incarnation(namespace)
            .ok_or_else(|| Response::error(503, "MFA native namespace incarnation unavailable"))?;
        Ok((id.to_owned(), incarnation))
    }
    fn mfa_reply(response: crate::auth::AuthResponse) -> Response {
        Response {
            unwrapped_json: response.unwrapped_json,
            response_headers: Default::default(),
            consistency_index: None,
            status: response.status,
            body: response.body,
        }
    }
    pub(super) fn mfa_identity_route(
        state: &mut State,
        principal: &Principal,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Option<Response> {
        if !path.starts_with("identity/mfa/") {
            return None;
        }
        let execute = (|| -> Result<Response, Response> {
            let (id, incarnation) = Self::mfa_native_owner(state, namespace)?;
            let mut auth = state.auth.clone();
            let response =
                if path == "identity/mfa/method" || path.starts_with("identity/mfa/method/") {
                    auth.mfa_method_route(namespace, &id, incarnation, method, path, body)
                } else if path == "identity/mfa/login-enforcement"
                    || path.starts_with("identity/mfa/login-enforcement/")
                {
                    auth.mfa_enforcement_route(namespace, &id, incarnation, method, path, body)
                } else {
                    return Err(Response::error(404, "unsupported Identity MFA path"));
                };
            let response =
                response.map_err(|error| Response::error(error.status, &error.message))?;
            if response.mutated {
                state.auth = auth;
            }
            let _ = time;
            let _ = principal;
            Ok(Self::mfa_reply(response))
        })();
        Some(match execute {
            Ok(reply) => reply,
            Err(error) => error,
        })
    }
    pub(super) fn mfa_enrollment_route(
        state: &mut State,
        principal: &Principal,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Option<Response> {
        if !matches!(
            path,
            "identity/mfa/method/totp/generate"
                | "identity/mfa/method/totp/admin-generate"
                | "identity/mfa/method/totp/admin-destroy"
        ) {
            return None;
        }
        let execute = (|| -> Result<Response, Response> {
            if !matches!(method, "POST" | "PUT") {
                return Err(Response::error(405, "MFA enrollment requires POST or PUT"));
            }
            let admin = path != "identity/mfa/method/totp/generate";
            if admin {
                state
                    .auth
                    .authorize_sudo_request(principal, namespace, path, "update", time.seconds())
                    .map_err(|error| Response::error(error.status, &error.message))?;
            }
            let object = body
                .as_object()
                .ok_or_else(|| Response::error(400, "MFA enrollment must be an object"))?;
            if object
                .keys()
                .any(|key| key != "method_id" && (key != "entity_id" || !admin))
            {
                return Err(Response::error(400, "unknown MFA enrollment field"));
            }
            let entity = if admin {
                body.get("entity_id").and_then(Value::as_str)
            } else {
                principal.entity_id()
            }
            .filter(|entity| !entity.is_empty())
            .ok_or_else(|| Response::error(400, "missing entity ID"))?;
            let method_id = body
                .get("method_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| Response::error(400, "missing method ID"))?;
            let projection = state
                .engines
                .identity_projection(namespace, entity)
                .map_err(|_| Response::error(400, "invalid entity ID"))?;
            if projection.disabled {
                return Err(Response::error(403, "permission denied"));
            }
            let (id, incarnation) = Self::mfa_native_owner(state, namespace)?;
            let mut auth = state.auth.clone();
            let response = auth
                .mfa_generate(
                    namespace,
                    &id,
                    incarnation,
                    entity,
                    method_id,
                    path.ends_with("/admin-destroy"),
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
            if response.mutated {
                state.auth = auth;
            }
            Ok(Self::mfa_reply(response))
        })();
        Some(match execute {
            Ok(reply) => reply,
            Err(error) => error,
        })
    }
    pub(super) fn mfa_validation_route(
        state: &mut State,
        namespace: &str,
        method: &str,
        body: &Value,
        time: AuthorityTime,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Response {
        if !matches!(method, "POST" | "PUT") {
            return Response::error(405, "MFA validate requires POST or PUT");
        }
        let binding =
            match Self::mfa_native_binding(&state.namespaces, &state.cluster_id, namespace) {
                Ok(binding) => binding,
                Err(error) => return error,
            };
        let mut auth = state.auth.clone();
        let mut response =
            match auth.mfa_validate(namespace, binding.clone(), body, time, origin_peer) {
                Ok(response) => response,
                Err(error) => return Response::error(error.status, &error.message),
            };
        // Invalid numeric attempts still publish their method/entity-owned
        // counter. No credential exists before the final native projection.
        if response.status == 200 {
            let Some(pending) = response.pending_service.as_ref() else {
                return Response::error(503, "MFA validated grant unavailable");
            };
            if let Err(error) = pending.bind_native(binding) {
                return Response::error(error.status, &error.message);
            }
            let mut engines = state.engines.clone();
            if let Err(error) = Self::finish_identity_response_observed(
                &mut auth,
                &mut engines,
                &mut response,
                &state.namespaces,
                namespace,
                time.seconds(),
                time,
            ) {
                erase_json(&mut response.body);
                return error;
            }
            state.engines = engines;
        }
        if response.mutated {
            state.auth = auth;
        }
        Self::mfa_reply(response)
    }
}

#[cfg(test)]
#[path = "service_mfa_tests.rs"]
mod tests;
