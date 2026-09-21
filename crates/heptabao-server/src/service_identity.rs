//! Service is the serialization/commit owner for both auth and engine state.
//! Every request sees one post-ReadIndex identity snapshot; successful login
//! publishes the token and its alias/entity association in the same transaction.
use super::*;
use crate::auth::{AuthError, AuthResponse};

impl State {
    pub(super) fn validate_format(&self) -> Result<(), Response> {
        self.engines
            .validate_record_mode()
            .map_err(|e| Response::error(503, &e.message))?;
        if self.schema < 36 && self.engines.record_root().is_some() {
            return Err(Response::error(503, "record KV1 requires schema 36"));
        }

        if self.schema < 37 && self.engines.has_packed_kv1_records() {
            return Err(Response::error(503, "packed KV1 records require schema 37"));
        }

        self.auth
            .validate_system_lease_defaults()
            .map_err(|_| Response::error(503, "invalid system or Token API lease state"))?;
        self.auth
            .validate_approle_native_defaults()
            .map_err(|_| Response::error(503, "invalid native AppRole state"))?;
        self.auth
            .validate_userpass_native_tokens()
            .map_err(|_| Response::error(503, "invalid native userpass state"))?;
        self.engines
            .validate_identity_alias_state()
            .map_err(|e| Response::error(503, &e.message))?;
        self.engines
            .validate_lease_state()
            .map_err(|e| Response::error(503, &e.message))?;
        self.auth
            .validate_wrapping_state()
            .map_err(|_| Response::error(503, "invalid wrapping state"))?;
        self.database.validate_scope(&self.cluster_id)?;
        self.raft_admin.validate()?;
        self.auth
            .validate_online_auth()
            .map_err(|_| Response::error(503, "invalid online authentication state"))?;
        self.auth
            .validate_plugin_auth_state()
            .map_err(|_| Response::error(503, "invalid authentication plugin state"))?;
        self.auth
            .validate_radius_renewal_state()
            .map_err(|_| Response::error(503, "invalid RADIUS renewal state"))?;
        self.auth
            .validate_ldap_renewal_state()
            .map_err(|_| Response::error(503, "invalid LDAP renewal state"))?;
        self.auth
            .validate_jwt_renewal_state()
            .map_err(|_| Response::error(503, "invalid JWT renewal state"))?;
        self.auth
            .validate_native_jwt_state()
            .map_err(|_| Response::error(503, "invalid native JWT state"))?;
        self.auth
            .validate_kubernetes_renewal_state()
            .map_err(|_| Response::error(503, "invalid Kubernetes renewal state"))?;
        self.auth
            .validate_oidc_renewal_state()
            .map_err(|_| Response::error(503, "invalid OIDC renewal state"))?;
        if self.schema < 5 && self.auth.has_online_auth_state() {
            return Err(Response::error(
                503,
                "online authentication requires schema 5",
            ));
        }
        if self.schema < 5 && self.replay_epoch != 0 {
            return Err(Response::error(503, "replay epoch state requires schema 5"));
        }
        if self.schema < 6 && self.database.has_provider_fence() {
            return Err(Response::error(
                503,
                "database provider fencing requires schema 6",
            ));
        }
        if self.schema < 7 && self.auth.has_ldap_group_state() {
            return Err(Response::error(
                503,
                "LDAP group synchronization requires schema 7",
            ));
        }
        if self.schema < 8 && self.engines.has_kubernetes_mount() {
            return Err(Response::error(
                503,
                "Kubernetes TokenRequest secrets state requires schema 8",
            ));
        }
        self.engines
            .validate_kubernetes_state()
            .map_err(|error| Response::error(503, &error.message))?;
        self.engines
            .validate_openldap_state()
            .map_err(|error| Response::error(503, &error.message))?;
        if self.schema < 9 && !self.namespaces.is_empty() {
            return Err(Response::error(
                503,
                "explicit namespace catalog requires schema 9",
            ));
        }
        self.namespaces.validate(&self.cluster_id)?;
        if self.schema < 10 && self.auth.has_plugin_auth_state() {
            return Err(Response::error(
                503,
                "authentication plugin state requires schema 10",
            ));
        }
        if self.schema < 11 && self.auth.has_approle_token_provenance() {
            return Err(Response::error(
                503,
                "AppRole renewal provenance requires schema 11",
            ));
        }
        if self.schema < 12 && self.auth.has_radius_state() {
            return Err(Response::error(
                503,
                "RADIUS authentication state requires schema 12",
            ));
        }
        if self.schema < 13 && self.namespaces.has_sealed_state() {
            return Err(Response::error(
                503,
                "namespace seal state requires schema 13",
            ));
        }
        if self.schema < 14 && self.engines.has_openldap_mount() {
            return Err(Response::error(
                503,
                "OpenLDAP dynamic credential state requires schema 14",
            ));
        }
        if self.schema < 15 && self.engines.has_metadata_cas_state() {
            return Err(Response::error(
                503,
                "KV metadata CAS state requires schema 15",
            ));
        }
        if self.schema < 16 && self.auth.has_v16_token_provenance() {
            return Err(Response::error(
                503,
                "RADIUS renewal and token API provenance require schema 16",
            ));
        }
        if self.schema < 17
            && (self.auth.has_ldap_renewal_provenance()
                || self.engines.has_external_group_membership())
        {
            return Err(Response::error(
                503,
                "LDAP renewal and external group evidence require schema 17",
            ));
        }
        if self.schema < 18 && self.auth.has_jwt_renewal_state() {
            return Err(Response::error(
                503,
                "JWT renewal provenance and role limits require schema 18",
            ));
        }
        if self.schema < 19 && self.auth.has_native_jwt_state() {
            return Err(Response::error(
                503,
                "native JWT claim semantics require schema 19",
            ));
        }
        if self.schema < 20 && self.auth.has_kubernetes_renewal_state() {
            return Err(Response::error(
                503,
                "Kubernetes renewal provenance and role limits require schema 20",
            ));
        }
        if self.schema < 21 && self.auth.has_oidc_renewal_state() {
            return Err(Response::error(
                503,
                "OIDC renewal provenance and role limits require schema 21",
            ));
        }
        if self.schema < 22 && self.auth.has_radius_native_parameters() {
            return Err(Response::error(
                503,
                "RADIUS native token parameters require schema 22",
            ));
        }
        if self.schema < 23
            && (self.auth.has_native_ldap_state() || self.engines.has_opaque_identity_aliases())
        {
            return Err(Response::error(
                503,
                "native LDAP authority and opaque identity aliases require schema 23",
            ));
        }
        if self.schema < 24 && self.auth.has_native_radius_state() {
            return Err(Response::error(
                503,
                "native RADIUS configuration and provenance require schema 24",
            ));
        }
        if self.schema < 25
            && (self.auth.has_native_ldap_transport() || self.auth.has_radius_no_default_policy())
        {
            return Err(Response::error(
                503,
                "native LDAP transport or RADIUS default-policy semantics require schema 25",
            ));
        }
        if self.schema < 26 && self.auth.has_radius_api_transport() {
            return Err(Response::error(
                503,
                "RADIUS API transport authority requires schema 26",
            ));
        }
        if self.schema < 27 && self.auth.has_token_bound_cidrs() {
            return Err(Response::error(
                503,
                "token source address constraints require schema 27",
            ));
        }
        if self.schema < 28
            && (self.auth.has_jwt_api_https_state() || self.auth.has_oidc_api_https_state())
        {
            return Err(Response::error(
                503,
                "JWT/OIDC API HTTPS authority requires schema 28",
            ));
        }
        if self.schema < 29
            && (self.auth.has_ldap_token_bound_cidrs()
                || self.auth.has_kubernetes_api_https_state())
        {
            return Err(Response::error(
                503,
                "LDAP source constraints or Kubernetes API HTTPS authority require schema 29",
            ));
        }
        if self.schema < 30
            && (self.auth.has_jwt_bound_claims_state() || self.auth.has_ldap_no_default_policy())
        {
            return Err(Response::error(
                503,
                "JWT claim predicates or native LDAP default-policy semantics require schema 30",
            ));
        }
        if self.schema < 31 && self.auth.has_kube_role_bound_cidrs() {
            return Err(Response::error(
                503,
                "Kubernetes role and issued-token source constraints require schema 31",
            ));
        }
        if self.schema < 32 && self.auth.has_jwt_native_ttl_defaults() {
            return Err(Response::error(
                503,
                "JWT role TTL inheritance requires schema 32",
            ));
        }
        if self.schema < 33 && self.auth.has_system_lease_defaults() {
            return Err(Response::error(
                503,
                "system lease defaults and Token API grant metadata require schema 33",
            ));
        }
        if self.schema < 34 && self.auth.has_approle_native_defaults() {
            return Err(Response::error(
                503,
                "AppRole TTL inheritance or SecretID issuance metadata requires schema 34",
            ));
        }
        if self.schema < 35 && self.auth.has_userpass_native_tokens() {
            return Err(Response::error(
                503,
                "userpass native token limits, configured policies or issuer provenance require schema 35",
            ));
        }
        self.auth
            .validate_jwt_api_https_state()
            .map_err(|_| Response::error(503, "invalid JWT HTTPS authority"))?;
        let pre_database = self.database.is_empty()
            && !self.engines.has_database_mount()
            && self.raft_admin.is_default();
        match self.schema {
            1 if pre_database
                && !self.auth.has_remote_jwt_state()
                && !self.auth.has_live_identity_state()
                && !self.auth.has_wrapping_state()
                && !self.engines.has_lease_state() =>
            {
                Ok(())
            }
            2 if pre_database
                && !self.auth.has_remote_jwt_state()
                && !self.auth.has_wrapping_state()
                && !self.engines.has_lease_state() =>
            {
                Ok(())
            }
            3 if pre_database && !self.auth.has_remote_jwt_state() => Ok(()),
            4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21
            | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 30 | 31 | 32 | 33 | 34 | 35 | 36
            | CURRENT_STATE_SCHEMA => Ok(()),
            _ => Err(Response::error(
                503,
                "unsupported or downgraded identity state schema",
            )),
        }
    }
}

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
            if response.external_groups.is_some() {
                return Err(Response::error(
                    503,
                    "provider identity binding is unavailable",
                ));
            }
            return Ok(());
        };
        if let Some(groups) = response.external_groups.take() {
            let accessor = auth
                .mount_accessor(namespace, &groups.mount)
                .map_err(auth_error)?;
            engines
                .verify_external_group_identity(namespace, id, &accessor, &groups.alias)
                .map_err(|error| Response::error(error.status, &error.message))?;
            engines
                .refresh_external_group_membership(namespace, id, &accessor, &groups.names, now)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
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
