//! Retained root Userpass operation metadata for the native V6 transaction.
//! The ordinary Auth dispatcher remains the sole password, MFA, lockout,
//! issuance and renewal implementation. This owner never authenticates again.
use super::*;

enum UserpassRoute {
    Mount {
        mount: String,
        tune: bool,
        route: String,
    },
    Users {
        mount: String,
        suffix: String,
    },
    Login {
        mount: String,
    },
}

/// The Service separately retains the exact source Auth image, real local/HA
/// proof, original request clock, installed checkpoint and response digest.
/// This type binds the operation's existing mount and original ACL semantics.
pub(crate) struct NativeUserpassOwner {
    source_mount: Option<(String, Option<AuthMount>)>,
    route: String,
    capability: Option<&'static str>,
    sudo: bool,
    login: bool,
    may_retire_actor: bool,
    empty_retirement_reply: bool,
}

impl NativeUserpassOwner {
    pub(crate) fn is_login(&self) -> bool {
        self.login
    }

    /// Inspect the real, freshly sealed batch credential without inventing a
    /// service-token backing record or rechecking a password. The Service owns
    /// the exact Auth/Namespace publication and final audited response proof.
    pub(crate) fn validate_batch_reply(
        &self,
        candidate: &AuthState,
        body: &Value,
        time: AuthorityTime,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<(), AuthError> {
        let Some((mount, Some(binding))) = self.source_mount.as_ref() else {
            return Err(err(503, "native Userpass batch mount is unavailable"));
        };
        if !self.login
            || binding.kind != "userpass"
            || body["auth"]["token_type"].as_str() != Some("batch")
        {
            return Err(err(503, "native Userpass batch route changed"));
        }
        let raw = body["auth"]["client_token"].as_str().ok_or_else(denied)?;
        let username = body["auth"]["metadata"]["username"]
            .as_str()
            .ok_or_else(denied)?;
        let scope = AuthScope {
            namespace: "",
            mount,
        };
        if !valid_name(username)
            || candidate
                .users_at(scope)
                .is_none_or(|users| !users.contains_key(username))
        {
            return Err(denied());
        }
        let principal = candidate.batch_principal_observed(raw, time, origin_peer)?;
        let batch_principal::VerifiedCredential::Batch(claims) = &principal.credential else {
            return Err(denied());
        };
        let metadata = BTreeMap::from([("username".to_owned(), username.to_owned())]);
        if !claims.namespace().is_empty()
            || claims.parent().is_some()
            || claims.public_origin().is_some()
            || claims.token_role().is_some()
            || claims.precision().is_some()
            || claims.entity_id().is_none()
            || claims.namespace_binding().is_none()
            || claims.path() != format!("auth/{mount}/login/{username}")
            || claims.metadata() != &metadata
            || claims.policies().contains("root")
            || candidate.tokens.contains_key(&hash(raw))
        {
            return Err(err(503, "native Userpass batch credential changed"));
        }
        Ok(())
    }

    pub(crate) fn permits_empty_actor_retirement(&self) -> bool {
        self.empty_retirement_reply
    }

    pub(crate) fn check_source(&self, source: &AuthState) -> Result<(), AuthError> {
        if let Some((mount, expected)) = &self.source_mount
            && source.effective_auth_mounts("").get(mount) != expected.as_ref()
        {
            return Err(err(503, "native Userpass source mount changed"));
        }
        if !source.native_v6_userpass_state_supported() {
            return Err(err(503, "native Userpass source state is unsupported"));
        }
        Ok(())
    }

    pub(crate) fn admit_candidate(
        &self,
        source: &AuthState,
        candidate: &AuthState,
    ) -> Result<(), AuthError> {
        self.check_source(source)?;
        candidate.validate_userpass_issuance_state(Some(source))?;
        if !candidate.native_v6_userpass_state_supported() {
            return Err(err(503, "native Userpass candidate state is unsupported"));
        }
        Ok(())
    }

    /// Called only after the actual Auth dispatch and its final token echo.
    /// A successful removal may retire its own actor, but only the domain's
    /// exact empty 204 acknowledgement gets that exception.
    pub(crate) fn bind_response(&mut self, status: u16, body: &Value) -> Result<(), AuthError> {
        if status == 204 && !body.is_null() {
            return Err(err(503, "native Userpass empty acknowledgement changed"));
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
        // The original error, including a durable failed-login counter, is
        // retained through the exact response digest and native publication.
        // Do not replace an actual backend error with a new authentication.
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
    /// Closed metadata eligibility, not a login grant. Historical issuance
    /// facts are validated as stored; none are reconstructed from a renewal.
    pub(crate) fn native_v6_userpass_state_supported(&self) -> bool {
        self.validate_userpass_native_tokens().is_ok()
            && self.validate_batch_issuance_state().is_ok()
            && self.validate_userpass_lockout_state().is_ok()
            && self.users.iter().all(|(namespace, users)| {
                users.is_empty()
                    || (namespace.is_empty()
                        && self.online_mount_enabled(namespace, "userpass", "userpass"))
            })
            && self.mounted_users.iter().all(|(namespace, mounts)| {
                mounts.iter().all(|(mount, users)| {
                    users.is_empty()
                        || (namespace.is_empty()
                            && self.online_mount_enabled(namespace, mount, "userpass"))
                })
            })
    }

    fn selected_native_userpass_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Option<UserpassRoute> {
        if !namespace.is_empty() {
            return None;
        }
        let mounts = self.effective_auth_mounts(namespace);
        if path.starts_with("sys/auth/") {
            let (mount, tune, route) = control_groups::auth_mount_route(path).ok()?;
            if mounts
                .get(mount)
                .is_some_and(|entry| entry.kind == "userpass")
                || (!tune
                    && matches!(method, "POST" | "PUT")
                    && body.get("type").and_then(Value::as_str) == Some("userpass"))
            {
                return Some(UserpassRoute::Mount {
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
        if entry.kind != "userpass" {
            return None;
        }
        if suffix.starts_with("login/") {
            return Some(UserpassRoute::Login {
                mount: mount.to_owned(),
            });
        }
        if suffix == "users" || suffix.starts_with("users/") {
            return Some(UserpassRoute::Users {
                mount: mount.to_owned(),
                suffix: suffix
                    .strip_prefix("users")
                    .unwrap_or(suffix)
                    .trim_start_matches('/')
                    .to_owned(),
            });
        }
        None
    }

    pub(crate) fn native_v6_userpass_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        self.selected_native_userpass_route(namespace, method, path, body)
            .is_some()
    }

    fn userpass_token_origin(&self, token: &Token) -> bool {
        matches!(
            token.auth_provenance,
            Some(TokenAuthProvenance::Userpass { .. })
        ) || (token.auth_origin_known
            && token.auth_mount.as_ref().is_some_and(|mount| {
                self.online_mount_enabled(&token.namespace, mount, "userpass")
            }))
    }

    /// Selection uses existing mounted ownership or stored token provenance.
    /// It grants no capability and never verifies a password or consumes a use.
    pub(crate) fn capture_native_v6_userpass_owner(
        &self,
        actor: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<NativeUserpassOwner>, AuthError> {
        if !namespace.is_empty() {
            return Ok(None);
        }
        let selected = self.selected_native_userpass_route(namespace, method, path, body);
        let mut owner = NativeUserpassOwner {
            source_mount: None,
            route: path.to_owned(),
            capability: None,
            sudo: false,
            login: false,
            may_retire_actor: false,
            empty_retirement_reply: false,
        };
        let mount = match selected {
            Some(UserpassRoute::Mount { mount, tune, route }) => {
                owner.route = route;
                owner.capability = Some(match method {
                    "GET" => "read",
                    "POST" | "PUT" => "update",
                    // The existing auth-mount API authorizes DELETE as update.
                    "DELETE" if !tune => "update",
                    _ => return Err(err(405, "method not allowed")),
                });
                owner.sudo = tune || method != "GET";
                owner.may_retire_actor = !tune && method == "DELETE";
                Some(mount)
            }
            Some(UserpassRoute::Users { mount, suffix }) => {
                owner.capability = Some(route_capability(method, suffix.is_empty())?);
                let (_, subpath) = suffix.split_once('/').unwrap_or((&suffix, ""));
                owner.sudo = subpath == "mfa" && matches!(method, "POST" | "PUT" | "DELETE");
                Some(mount)
            }
            Some(UserpassRoute::Login { mount }) => {
                owner.login = true;
                Some(mount)
            }
            None => {
                let Some(operation) = path.strip_prefix("auth/token/") else {
                    return Ok(None);
                };
                let selected_operation = matches!(
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
                ) || operation.starts_with("create/");
                if !selected_operation {
                    return Ok(None);
                }
                let actor_origin = actor
                    .and_then(Principal::service_token)
                    .is_some_and(|token| self.userpass_token_origin(token));
                let target_origin = match operation {
                    "lookup" | "renew" | "revoke" | "revoke-orphan" => body
                        .get("token")
                        .and_then(Value::as_str)
                        .and_then(|raw| self.tokens.get(&hash(raw)))
                        .is_some_and(|token| self.userpass_token_origin(token)),
                    "lookup-accessor" | "renew-accessor" | "revoke-accessor" => body
                        .get("accessor")
                        .and_then(Value::as_str)
                        .is_some_and(|accessor| {
                            self.tokens.values().any(|token| {
                                token.accessor == accessor && self.userpass_token_origin(token)
                            })
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
            let binding = self.effective_auth_mounts(namespace).get(&mount).cloned();
            owner.source_mount = Some((mount, binding));
        }
        owner.check_source(self)?;
        Ok(Some(owner))
    }
}
