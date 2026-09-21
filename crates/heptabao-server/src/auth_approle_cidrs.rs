//! AppRole token CIDRs constrain issued credentials, not RoleID/SecretID login.
//! Role SecretID login-source constraints are validated independently.
use super::*;

pub(super) fn validate_constraints(role: &Role) -> Result<(), AuthError> {
    if !role.bind_secret_id
        && role.token_bound_cidrs.as_ref().is_none_or(Vec::is_empty)
        && role
            .secret_id_bound_cidrs
            .as_ref()
            .is_none_or(Vec::is_empty)
    {
        return Err(err(
            500,
            "at least one constraint should be enabled on the role",
        ));
    }
    Ok(())
}

pub(super) fn update(role: &mut Role, body: &Value) -> Result<(), AuthError> {
    if body.get("token_bound_cidrs").is_some() {
        role.token_bound_cidrs = Some(token_cidrs::field(body)?);
    }
    validate_constraints(role)
}

impl AuthState {
    pub(super) fn approle_token_cidrs_route(
        &mut self,
        scope: AuthScope<'_>,
        name: &str,
        capability: &str,
        body: &Value,
        existing: Option<Role>,
    ) -> Result<AuthResponse, AuthError> {
        // Caller has already authorized the original dedicated-field path.
        let Some(mut role) = existing else {
            return match capability {
                "read" => Ok(AuthResponse {
                    status: 404,
                    body: json!({"errors":[]}),
                    ..empty(false)
                }),
                "delete" => Ok(empty(false)),
                "update" => Err(err(404, "role not found")),
                _ => Err(err(405, "method not allowed")),
            };
        };
        match capability {
            "read" => Ok(response(
                json!({"token_bound_cidrs":role.token_bound_cidrs}),
                false,
            )),
            "update" => {
                // The upstream dedicated endpoint ignores unrelated fields;
                // they must never become an alternate whole-role write.
                if !body.is_object() {
                    return Err(bad("request body must be an object"));
                }
                update(&mut role, body)?;
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(empty(true))
            }
            "delete" => {
                role.token_bound_cidrs = None;
                validate_constraints(&role)?;
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(empty(true))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    pub(crate) fn has_approle_token_bound_cidrs(&self) -> bool {
        self.roles
            .values()
            .flat_map(|roles| roles.values())
            .chain(
                self.mounted_roles
                    .values()
                    .flat_map(|mounts| mounts.values())
                    .flat_map(|roles| roles.values()),
            )
            .any(|role| role.token_bound_cidrs.is_some())
            || self.tokens.values().any(|token| {
                !token.bound_cidrs.is_empty()
                    && matches!(
                        token.auth_provenance,
                        Some(TokenAuthProvenance::AppRole { .. })
                    )
            })
    }

    pub(crate) fn validate_approle_token_bound_cidrs(&self) -> Result<(), AuthError> {
        self.validate_approle_secret_bound_cidrs()?;
        for (namespace, roles) in &self.roles {
            self.validate_approle_role_cidrs(namespace, "approle", roles)?;
        }
        for (namespace, mounts) in &self.mounted_roles {
            for (mount, roles) in mounts {
                self.validate_approle_role_cidrs(namespace, mount, roles)?;
            }
        }
        Ok(())
    }

    fn validate_approle_role_cidrs(
        &self,
        namespace: &str,
        mount: &str,
        roles: &BTreeMap<String, Role>,
    ) -> Result<(), AuthError> {
        for role in roles.values() {
            if let Some(cidrs) = &role.token_bound_cidrs {
                token_cidrs::validate(cidrs)?;
                if !self.online_mount_enabled(namespace, mount, "approle") {
                    return Err(bad(
                        "AppRole token source constraints have no AppRole mount",
                    ));
                }
            }
        }
        // Legacy unconstrained RoleID-only records remain readable. This does
        // not infer an absent SecretID-source constraint or rewrite old roles.
        Ok(())
    }
}
