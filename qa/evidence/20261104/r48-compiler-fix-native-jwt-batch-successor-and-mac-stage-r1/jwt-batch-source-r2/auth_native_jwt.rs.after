//! Root, local-key JWT operation custody for the native V6 transaction.
//! The existing JWT handler alone verifies the assertion and issues the token.
//! This owner retains its signed lifetime, original mount and audited response;
//! it neither verifies a second assertion nor grants an external provider owner.
use super::*;
use crate::federated_auth::NativeJwtLifetime;

enum JwtRoute {
    Mount {
        mount: String,
        tune: bool,
        route: String,
    },
    Config {
        mount: String,
    },
    Role {
        mount: String,
        collection: bool,
    },
    Login {
        mount: String,
    },
}

pub(crate) struct NativeJwtOwner {
    source_mount: Option<(String, Option<AuthMount>)>,
    route: String,
    capability: Option<&'static str>,
    sudo: bool,
    login: bool,
    batch_login: bool,
    may_retire_actor: bool,
    empty_retirement_reply: bool,
    // Private output of the one real verifier invocation. Never serialized,
    // reconstructed from response JSON, or refreshed during renewal/delivery.
    login_lifetime: Option<NativeJwtLifetime>,
}

impl NativeJwtOwner {
    pub(crate) fn is_login(&self) -> bool {
        self.login
    }

    // Selection only: the ordinary dispatcher must still authenticate the JWT,
    // bind Identity and seal the actual batch before this owner accepts it.
    pub(crate) fn is_batch_login(&self) -> bool {
        self.login && self.batch_login
    }

    pub(crate) fn check_bound_batch_login(&self, time: AuthorityTime) -> Result<(), AuthError> {
        if !self.is_batch_login() || self.login_lifetime.is_none() {
            return Err(err(503, "native JWT batch has no original verifier witness"));
        }
        self.check_login_lifetime(time)
    }

    pub(crate) fn permits_empty_actor_retirement(&self) -> bool {
        self.empty_retirement_reply
    }

    pub(crate) fn check_source(&self, source: &AuthState) -> Result<(), AuthError> {
        if let Some((mount, expected)) = &self.source_mount
            && source.effective_auth_mounts("").get(mount) != expected.as_ref()
        {
            return Err(err(503, "native JWT source mount changed"));
        }
        if !source.native_v6_jwt_state_supported() {
            return Err(err(503, "native JWT source state is unsupported"));
        }
        Ok(())
    }

    pub(crate) fn check_login_lifetime(&self, time: AuthorityTime) -> Result<(), AuthError> {
        if let Some(lifetime) = self.login_lifetime.as_ref() {
            lifetime
                .check_at(time.seconds())
                .map_err(|_| err(503, "native JWT original assertion lifetime expired"))?;
        }
        Ok(())
    }

    /// Called only after the original dispatcher has completed its real JWT
    /// login and Identity binding. The lifetime comes through a private output
    /// slot from that same signature verification, not a second authentication.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind_successful_login(
        &mut self,
        source: &AuthState,
        candidate: &AuthState,
        request: &Value,
        reply: &Value,
        lifetime: NativeJwtLifetime,
        time: AuthorityTime,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<(), AuthError> {
        self.check_source(source)?;
        let Some((mount, Some(binding))) = self.source_mount.as_ref() else {
            return Err(err(503, "native JWT login mount is unavailable"));
        };
        let role_name = string_field(request, "role")?;
        let scope = AuthScope {
            namespace: "",
            mount,
        };
        let state = source.jwt_at(scope).ok_or_else(denied)?;
        let role = state.roles.get(role_name).ok_or_else(denied)?;
        if !self.login
            || self.login_lifetime.is_some()
            || binding.kind != "jwt"
            || state
                .config
                .as_ref()
                .is_none_or(|config| config.remote.is_some())
            || self.batch_login != source.jwt_uses_batch(scope, role)
            || reply["auth"]["token_type"].as_str()
                != Some(if self.batch_login { "batch" } else { "service" })
        {
            return Err(err(503, "native JWT login owner changed"));
        }
        let raw = reply["auth"]["client_token"].as_str().ok_or_else(denied)?;
        let digest = hash(raw);
        if raw.is_empty() || source.tokens.contains_key(&digest) {
            return Err(err(503, "native JWT issued credential is not fresh"));
        }
        if self.batch_login {
            // Opening the real sealed credential does not verify the assertion
            // again or create a service-token backing row. The original JWT
            // lifetime below remains authoritative through audited delivery.
            let principal = candidate.batch_principal_observed(raw, time, origin_peer)?;
            let batch_principal::VerifiedCredential::Batch(claims) = &principal.credential else {
                return Err(err(503, "native JWT batch credential changed"));
            };
            let metadata = BTreeMap::from([("role".to_owned(), role_name.to_owned())]);
            let explicit = (role.token_explicit_max_ttl > 0)
                .then(|| checked_expiry(claims.issued_at(), role.token_explicit_max_ttl))
                .transpose()?;
            let expires = source.jwt_token_expiry(
                scope, role, claims.issued_at(), explicit, 0, claims.issued_at(),
            )?;
            if !claims.namespace().is_empty()
                || claims.namespace_binding().is_none()
                || claims.parent().is_some()
                || claims.public_origin().is_some()
                || claims.token_role().is_some()
                || claims.precision().is_some()
                || claims.entity_id().is_none_or(str::is_empty)
                || claims.entity_id() != reply["auth"]["entity_id"].as_str()
                || claims.path() != format!("auth/{mount}/login")
                || claims.metadata() != &metadata
                || claims.policies() != &jwt_policies::issued_policies(role)
                || claims.policies().contains("root")
                || !claims.bound_cidrs().is_empty()
                || claims.expires_at() != expires
                || candidate.tokens.contains_key(&digest)
                || reply["auth"]["accessor"].as_str() != Some("")
                || reply["auth"]["renewable"].as_bool() != Some(false)
            {
                return Err(err(503, "native JWT issued batch or identity changed"));
            }
        } else {
            let token = candidate.tokens.get(&digest).ok_or_else(denied)?;
            if !token.namespace.is_empty()
                || token.auth_mount.as_deref() != Some(mount.as_str())
                || !matches!(&token.auth_provenance,
                    Some(TokenAuthProvenance::Jwt { role_name: issued }) if issued == role_name)
                || token.root
                || token.parent.is_some()
                || token.entity_id.as_deref().is_none_or(str::is_empty)
                || token.entity_id.as_deref() != reply["auth"]["entity_id"].as_str()
                || Some(token.accessor.as_str()) != reply["auth"]["accessor"].as_str()
            {
                return Err(err(503, "native JWT issued token or identity changed"));
            }
        }
        lifetime
            .check_at(time.seconds())
            .map_err(|_| err(503, "native JWT original assertion lifetime expired"))?;
        self.login_lifetime = Some(lifetime);
        Ok(())
    }

    pub(crate) fn admit_candidate(
        &self,
        source: &AuthState,
        candidate: &AuthState,
    ) -> Result<(), AuthError> {
        self.check_source(source)?;
        if !candidate.native_v6_jwt_state_supported() {
            return Err(err(
                501,
                "native JWT requires a root local-key token owner",
            ));
        }
        Ok(())
    }

    pub(crate) fn bind_response(&mut self, status: u16, body: &Value) -> Result<(), AuthError> {
        if status == 204 && !body.is_null()
            || self.login && status == 200 && self.login_lifetime.is_none()
        {
            return Err(err(503, "native JWT response custody changed"));
        }
        self.empty_retirement_reply = self.may_retire_actor && status == 204 && body.is_null();
        Ok(())
    }

    pub(crate) fn authorize_reply(
        &self,
        auth: &AuthState,
        actor: Option<&Principal>,
        status: u16,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        self.check_login_lifetime(time)?;
        if status >= 300 || self.empty_retirement_reply || self.login {
            return Ok(());
        }
        let actor = actor.ok_or_else(denied)?;
        let capability = self.capability.ok_or_else(denied)?;
        auth.authorize_request_observed(actor, "", &self.route, capability, time)?;
        if self.sudo {
            auth.authorize_request_observed(actor, "", &self.route, "sudo", time)?;
        }
        Ok(())
    }
}

impl AuthState {
    /// Native JWT keeps a root/local owner for service and batch issuance.
    /// Stored metadata is checked here; the ordinary JWT parser/verifier and
    /// renewal handler still own every request's semantic authorization.
    pub(crate) fn native_v6_jwt_state_supported(&self) -> bool {
        self.validate_native_jwt_state().is_ok()
            && self.validate_jwt_user_claim_state().is_ok()
            && self.validate_jwt_renewal_state().is_ok()
            && self.validate_jwt_batch_state().is_ok()
            && self.validate_batch_issuance_state().is_ok()
            && self.validate_token_api_creation_ttl().is_ok()
            && self.validate_public_origin_state().is_ok()
            && self.auth_mounts.iter().all(|(namespace, mounts)| {
                mounts.values().all(|mount| {
                    mount.kind != "jwt" || namespace.is_empty()
                })
            })
            && self.jwt_mounts.iter().all(|(namespace, mounts)| {
                mounts.is_empty()
                    || (namespace.is_empty()
                        && mounts.iter().all(|(mount, state)| {
                            self.online_mount_enabled(namespace, mount, "jwt")
                                && state.config.as_ref().is_none_or(|config| {
                                    config.remote.is_none()
                                        && config
                                            .required_namespace
                                            .as_deref()
                                            .is_none_or(str::is_empty)
                                })
                        }))
            })
            && self.native_v6_jwt_token_edges_supported()
    }

    // Token API descendants retain their revocation mount, but have their own
    // issuer and renewal contract. A mount label alone is not that contract:
    // require the real TokenApi marker, initial grant and public path owner.
    fn native_v6_jwt_token_origin(&self, token: &Token) -> bool {
        if !token.namespace.is_empty()
            || !token.auth_origin_known
            || token.root
            || token.policies.contains("root")
            || token.wrapping.is_some()
            || token.raw_wrapped_reply_custody.is_some()
            || token.auth_cert_role.is_some()
            || token.auth_cert_sha256.is_some()
            || !token
                .auth_mount
                .as_ref()
                .is_some_and(|mount| self.online_mount_enabled("", mount, "jwt"))
        {
            return false;
        }
        match token.auth_provenance {
            Some(TokenAuthProvenance::Jwt { .. }) => token.parent.is_none(),
            Some(TokenAuthProvenance::TokenApi {
                issued_creation_ttl: Some(_),
            }) => token.public_origin.is_some() && token.validate_public_origin().is_ok(),
            _ => false,
        }
    }

    fn native_v6_jwt_token_edges_supported(&self) -> bool {
        let mut supported = BTreeSet::new();
        for (digest, token) in &self.tokens {
            let relevant = matches!(token.auth_provenance, Some(TokenAuthProvenance::Jwt { .. }))
                || token
                    .auth_mount
                    .as_ref()
                    .is_some_and(|mount| self.online_mount_enabled(&token.namespace, mount, "jwt"));
            if !relevant || supported.contains(digest.as_str()) {
                continue;
            }
            let mut path = BTreeSet::new();
            let mut current = digest.as_str();
            loop {
                if supported.contains(current) {
                    break;
                }
                if !path.insert(current) {
                    return false;
                }
                let Some(member) = self.tokens.get(current) else {
                    return false;
                };
                if !self.native_v6_jwt_token_origin(member) {
                    return false;
                }
                let Some(parent_digest) = member.parent.as_deref() else {
                    // A direct JWT is parentless. A TokenApi may also become
                    // parentless through the real revoke-orphan transition;
                    // its own validated issuance/path owner remains mandatory.
                    break;
                };
                let Some(parent) = self.tokens.get(parent_digest) else {
                    return false;
                };
                if parent.namespace != member.namespace
                    || parent.auth_mount != member.auth_mount
                    || parent.created_at > member.created_at
                {
                    return false;
                }
                current = parent_digest;
            }
            // Memoize the actual parent graph, so each retained edge is visited
            // once rather than rescanning every ancestor for every child.
            supported.extend(path);
        }
        true
    }

    fn selected_native_jwt_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Option<JwtRoute> {
        if !namespace.is_empty() {
            return None;
        }
        let mounts = self.effective_auth_mounts(namespace);
        if path.starts_with("sys/auth/") {
            let (mount, tune, route) = control_groups::auth_mount_route(path).ok()?;
            if mounts.get(mount).is_some_and(|entry| entry.kind == "jwt")
                || (!tune
                    && matches!(method, "POST" | "PUT")
                    && body.get("type").and_then(Value::as_str) == Some("jwt"))
            {
                return Some(JwtRoute::Mount {
                    mount: mount.to_owned(),
                    tune,
                    route,
                });
            }
            return None;
        }
        let auth_path = path.strip_prefix("auth/")?;
        let (mount, entry, suffix) = mounts.iter().find_map(|(mount, entry)| {
            auth_path
                .strip_prefix(&format!("{mount}/"))
                .map(|suffix| (mount, entry, suffix))
        })?;
        if entry.kind != "jwt" {
            return None;
        }
        match suffix {
            "login" => Some(JwtRoute::Login {
                mount: mount.to_owned(),
            }),
            "config" => Some(JwtRoute::Config {
                mount: mount.to_owned(),
            }),
            "role" => Some(JwtRoute::Role {
                mount: mount.to_owned(),
                collection: true,
            }),
            _ if suffix.starts_with("role/") => Some(JwtRoute::Role {
                mount: mount.to_owned(),
                collection: false,
            }),
            _ => None,
        }
    }

    pub(crate) fn native_v6_jwt_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        self.selected_native_jwt_route(namespace, method, path, body)
            .is_some()
    }

    pub(crate) fn capture_native_v6_jwt_owner(
        &self,
        actor: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<NativeJwtOwner>, AuthError> {
        if !namespace.is_empty() {
            return Ok(None);
        }
        let mut owner = NativeJwtOwner {
            source_mount: None,
            route: path.to_owned(),
            capability: None,
            sudo: false,
            login: false,
            batch_login: false,
            may_retire_actor: false,
            empty_retirement_reply: false,
            login_lifetime: None,
        };
        let mount = match self.selected_native_jwt_route(namespace, method, path, body) {
            Some(JwtRoute::Mount { mount, tune, route }) => {
                owner.route = route;
                owner.capability = Some(match method {
                    "GET" => "read",
                    "POST" | "PUT" => "update",
                    "DELETE" if !tune => "update",
                    _ => return Err(err(405, "method not allowed")),
                });
                owner.sudo = tune || method != "GET";
                owner.may_retire_actor = !tune && method == "DELETE";
                Some(mount)
            }
            Some(JwtRoute::Config { mount }) => {
                owner.capability = Some(match method {
                    "GET" => "read",
                    "POST" | "PUT" => "update",
                    _ => return Err(err(405, "method not allowed")),
                });
                Some(mount)
            }
            Some(JwtRoute::Role { mount, collection }) => {
                owner.capability = Some(match (collection, method) {
                    (true, "GET") | (false, "GET") => "read",
                    (true, "LIST") => "list",
                    (false, "POST" | "PUT") => {
                        let name = path
                            .strip_prefix(&format!("auth/{mount}/role/"))
                            .ok_or_else(|| err(503, "native JWT role route changed"))?;
                        // Retain the original source's decision. A newly
                        // published role must still deliver under Create.
                        self.jwt_role_write_capability(
                            AuthScope { namespace, mount: &mount },
                            name,
                        )
                    }
                    (false, "DELETE") => "delete",
                    _ => return Err(err(405, "method not allowed")),
                });
                Some(mount)
            }
            Some(JwtRoute::Login { mount }) => {
                owner.login = true;
                let scope = AuthScope { namespace, mount: &mount };
                owner.batch_login = string_field(body, "role")
                    .ok()
                    .and_then(|name| self.jwt_at(scope)?.roles.get(name))
                    .is_some_and(|role| self.jwt_uses_batch(scope, role));
                Some(mount)
            }
            None => {
                let Some(operation) = path.strip_prefix("auth/token/") else {
                    return Ok(None);
                };
                if !matches!(
                    operation,
                    "lookup-self"
                        | "lookup"
                        | "lookup-accessor"
                        | "renew-self"
                        | "renew"
                        | "renew-accessor"
                        | "revoke-self"
                        | "revoke"
                        | "revoke-accessor"
                        | "revoke-orphan"
                        | "create"
                        | "create-orphan"
                ) && !operation.starts_with("create/")
                {
                    return Ok(None);
                }
                let from_jwt = |token: &Token| self.native_v6_jwt_token_origin(token);
                let actor_origin = actor
                    .and_then(Principal::service_token)
                    .is_some_and(from_jwt);
                let target_origin = match operation {
                    "lookup" | "renew" | "revoke" | "revoke-orphan" => body
                        .get("token")
                        .and_then(Value::as_str)
                        .and_then(|raw| self.tokens.get(&hash(raw)))
                        .is_some_and(from_jwt),
                    "lookup-accessor" | "renew-accessor" | "revoke-accessor" => body
                        .get("accessor")
                        .and_then(Value::as_str)
                        .is_some_and(|accessor| {
                            self.tokens
                                .values()
                                .any(|token| token.accessor == accessor && from_jwt(token))
                        }),
                    _ => false,
                };
                if !actor_origin && !target_origin {
                    return Ok(None);
                }
                owner.capability = Some(if matches!(operation, "lookup-self" | "lookup") {
                    "read"
                } else {
                    "update"
                });
                owner.sudo = operation == "revoke-orphan";
                owner.may_retire_actor = matches!(
                    operation,
                    "revoke-self" | "revoke" | "revoke-accessor" | "revoke-orphan"
                );
                None
            }
        };
        if let Some(mount) = mount {
            let binding = self.effective_auth_mounts("").get(&mount).cloned();
            owner.source_mount = Some((mount, binding));
        }
        owner.check_source(self)?;
        Ok(Some(owner))
    }
}
