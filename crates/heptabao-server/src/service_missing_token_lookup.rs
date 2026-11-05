//! A missing lookup target's Identity does not invalidate its stored token.
//! This response adapter never authenticates a target or authorizes an actor.
use super::*;
use crate::auth::AuthResponse;

fn rejected() -> Response {
    Response::error(503, "original token lookup response is unavailable")
}

impl Service {
    /// Called only on the actual successful Auth backend response, before the
    /// existing generic Identity finalizer. Every other response retains that
    /// finalizer, including issuance, renewal, self lookup and enabled targets.
    pub(super) fn finish_missing_token_lookup_identity(
        auth: &AuthState,
        engines: &EngineState,
        response: &mut AuthResponse,
        namespace: &str,
        method: &str,
        path: &str,
    ) -> Result<bool, Response> {
        if !matches!(
            (method, path),
            ("GET" | "POST", "auth/token/lookup") | ("POST" | "PUT", "auth/token/lookup-accessor")
        ) {
            return Ok(false);
        }
        if !auth.online_mount_enabled(namespace, "token", "token") {
            return Ok(false);
        }
        // Those exact builtin routes have already run the backend's original
        // method/parameter/ACL/target checks. Do not infer a lookup merely from
        // a data envelope, and never finish a grant or provider effect here.
        if response.status != 200
            || response.mutated
            || response.body.get("auth").is_some()
            || response.unwrapped_json.is_some()
            || response.approle_secret_consumption.is_some()
            || response.pending_batch.is_some()
            || response.pending_service.is_some()
            || response.login_identity.is_some()
            || response.external_groups.is_some()
        {
            return Err(rejected());
        }
        let data = response
            .body
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(rejected)?;
        let Some(id) = data
            .get("entity_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            return Ok(false);
        };
        if engines
            .identity_projection_if_present(namespace, id)
            .map_err(|error| Response::error(error.status, &error.message))?
            .is_some()
        {
            return Ok(false);
        }
        // The selected namespace completed its direct and merged lookups.
        // Keep the token's original entity_id, policies, uses and other data.
        // OpenBao adds no Identity-policy fields when that lookup is empty.
        let data = response
            .body
            .get_mut("data")
            .and_then(Value::as_object_mut)
            .ok_or_else(rejected)?;
        data.remove("identity_policies");
        data.remove("external_namespace_policies");
        Ok(true)
    }
}

#[cfg(test)]
#[path = "service_missing_token_lookup_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_token_accessor_method_tests.rs"]
mod accessor_method_tests;
