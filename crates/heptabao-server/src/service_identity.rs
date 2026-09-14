//! Service is the serialization/commit owner for both auth and engine state.
//! Every request sees one post-ReadIndex identity snapshot; successful login
//! publishes the token and its alias/entity association in the same transaction.
use super::*;
use crate::auth::{AuthError, AuthResponse};

impl Service {
    pub(super) fn bind_identity_principal(
        state: &State,
        principal: &mut Principal,
        namespace: &str,
    ) -> Result<(), Response> {
        let Some(id) = principal.entity_id() else {
            return Ok(());
        };
        let projection = state
            .engines
            .identity_projection(namespace, id)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if projection.disabled {
            return Err(Response::error(403, "permission denied"));
        }
        principal.bind_identity_policies(projection.policies);
        Ok(())
    }

    pub(super) fn finish_identity_response(
        auth: &mut AuthState,
        engines: &mut EngineState,
        response: &mut AuthResponse,
        namespace: &str,
        now: u64,
    ) -> Result<(), Response> {
        let auth_error = |error: AuthError| Response::error(error.status, &error.message);
        if let Some(login) = response.login_identity.take() {
            let accessor = auth
                .mount_accessor(namespace, &login.mount)
                .map_err(auth_error)?;
            let projection = engines
                .bind_login_identity(namespace, &accessor, &login.alias, now)
                .map_err(|error| Response::error(error.status, &error.message))?;
            if projection.disabled {
                return Err(Response::error(403, "permission denied"));
            }
            auth.bind_issued_entity(response, namespace, &login.mount, &projection.entity_id)
                .map_err(auth_error)?;
        }
        let is_auth = response.body.get("auth").is_some();
        let envelope = if is_auth { "auth" } else { "data" };
        let Some(id) = response.body[envelope]["entity_id"]
            .as_str()
            .filter(|id| !id.is_empty())
        else {
            return Ok(());
        };
        let projection = engines
            .identity_projection(namespace, id)
            .map_err(|error| Response::error(error.status, &error.message))?;
        // Administrative token lookup can describe a disabled identity. Its
        // token is still unusable: admission checks disabled before dispatch.
        if is_auth && projection.disabled {
            return Err(Response::error(403, "permission denied"));
        }
        response.body[envelope]["entity_id"] = Value::String(projection.entity_id);
        response.body[envelope]["identity_policies"] = json!(projection.policies);
        if is_auth {
            let mut all = projection.policies;
            if let Some(token_policies) = response.body["auth"]["token_policies"].as_array() {
                for policy in token_policies {
                    let name = policy
                        .as_str()
                        .ok_or_else(|| Response::error(500, "invalid token policy"))?;
                    all.insert(name.to_owned());
                }
            }
            response.body["auth"]["policies"] = json!(all);
        }
        Ok(())
    }

    pub(super) fn validate_identity_alias_mount(
        auth: &AuthState,
        namespace: &str,
        path: &str,
        body: &Value,
    ) -> Result<(), Response> {
        let alias_route = path == "identity/entity-alias"
            || path.starts_with("identity/entity-alias/id/")
            || path == "identity/group-alias"
            || path.starts_with("identity/group-alias/id/");
        if alias_route && let Some(accessor) = body.get("mount_accessor") {
            let accessor = accessor
                .as_str()
                .ok_or_else(|| Response::error(400, "invalid mount accessor"))?;
            if !auth.has_mount_accessor(namespace, accessor) {
                return Err(Response::error(400, "unknown auth mount accessor"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "identity_service_tests.rs"]
mod tests;
