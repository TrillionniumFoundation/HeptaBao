//! Select only in-process Auth owners for the native V6 writer.
//! Selection is not authentication; the existing domain dispatcher still owns ACLs.
use super::*;

/// Original verified leaf validity only. This is neither certificate login
/// authorization nor a token grant; the real cert handler still owns both.
/// The private bounds are captured once from the request's actual TLS leaf.
pub(crate) struct NativeV6CertLifetime {
    not_before_nanos: i128,
    not_after_nanos: i128,
}

impl NativeV6CertLifetime {
    pub(crate) fn check_at(&self, time: AuthorityTime) -> Result<(), AuthError> {
        const NANOS_PER_SECOND: i128 = 1_000_000_000;
        let observed = match time {
            AuthorityTime::Coarse(seconds) => i128::from(seconds) * NANOS_PER_SECOND,
            AuthorityTime::Precise(at) => {
                i128::from(at.seconds()) * NANOS_PER_SECOND
                    + i128::from(at.duration_since_epoch().subsec_nanos())
            }
        };
        // Match the existing cert_validity validator's inclusive X.509 bounds,
        // including the original subsecond request observation.
        if self.not_before_nanos > self.not_after_nanos
            || observed < self.not_before_nanos
            || observed > self.not_after_nanos
        {
            return Err(denied());
        }
        Ok(())
    }
}

fn presented_leaf_lifetime(
    chain: &[Vec<u8>],
    time: AuthorityTime,
) -> Result<NativeV6CertLifetime, AuthError> {
    // Keep the domain's exact chain bounds and strict leaf parser. This only
    // retains time bounds; the real handler owns TLS/role/token admission.
    parse_presented_certificate(chain, time)?;
    let leaf = chain.first().ok_or_else(denied)?;
    let (remaining, certificate) = parse_x509_certificate(leaf).map_err(|_| denied())?;
    if !remaining.is_empty() {
        return Err(denied());
    }
    let validity = certificate.validity();
    let lifetime = NativeV6CertLifetime {
        not_before_nanos: i128::from(validity.not_before.timestamp()) * 1_000_000_000,
        not_after_nanos: i128::from(validity.not_after.timestamp()) * 1_000_000_000,
    };
    lifetime.check_at(time)?;
    Ok(lifetime)
}

impl AuthState {
    /// A configuration-selected native root may retain only owners that its
    /// local dispatcher can continue to service. No credential is exported,
    /// deleted, reissued or considered authenticated by this metadata check.
    pub(crate) fn supports_native_v6_root_storage(&self) -> bool {
        self.native_v6_storage_profile(None)
    }

    pub(crate) fn native_plain_namespace_auth_profile(&self, paths: &BTreeSet<String>) -> bool {
        self.known_namespaces().is_subset(paths)
            && paths
                .iter()
                .all(|path| !path.is_empty() && self.auth_mounts.contains_key(path))
            && self.native_v6_storage_profile(Some(paths))
            && self.roles.iter().all(|(namespace, roles)| {
                namespace.is_empty()
                    || roles.is_empty()
                    || (self.online_mount_enabled(namespace, "approle", "approle")
                        && roles.values().all(|role| {
                            !self.approle_uses_batch(
                                AuthScope {
                                    namespace,
                                    mount: "approle",
                                },
                                role,
                            )
                        }))
            })
            && self.mounted_roles.iter().all(|(namespace, mounts)| {
                namespace.is_empty()
                    || mounts.iter().all(|(mount, roles)| {
                        roles.is_empty()
                            || (self.online_mount_enabled(namespace, mount, "approle")
                                && roles.values().all(|role| {
                                    !self.approle_uses_batch(AuthScope { namespace, mount }, role)
                                }))
                    })
            })
            && self.cert_roles.iter().all(|(namespace, mounts)| {
                namespace.is_empty()
                    || mounts.iter().all(|(mount, roles)| {
                        roles.is_empty()
                            || (self.online_mount_enabled(namespace, mount, "cert")
                                && roles.values().all(|role| {
                                    !self.cert_uses_batch(AuthScope { namespace, mount }, role)
                                }))
                    })
            })
            && self.token_roles.iter().all(|(namespace, roles)| {
                namespace.is_empty()
                    || roles
                        .values()
                        .all(|role| role.batch(&json!({})).is_ok_and(|batch| !batch))
            })
    }

    fn native_v6_storage_profile(&self, paths: Option<&BTreeSet<String>>) -> bool {
        let admitted = |namespace: &String| {
            namespace.is_empty() || paths.is_some_and(|paths| paths.contains(namespace))
        };
        self.identity_mfa.is_none()
            && self.native_wrapping_storage_supported()
            && self.native_v6_control_groups_supported(paths)
            && self.sdk_auth_catalog.is_none()
            && self.sdk_auth_clock.is_none()
            && self.sdk_advanced_format.is_none()
            && self.sdk_credential_leases.is_none()
            && self.sdk_auth_retirements.is_none()
            && self.sdk_namespace_custody.is_none()
            && self
                .namespace_batch_registry
                .as_ref()
                .is_none_or(|registry| match paths {
                    None => registry.native_v6_flat_incarnation_profile(),
                    Some(paths) => registry.native_v6_plain_incarnation_profile(paths),
                })
            && self.namespace_deletions.is_none()
            && self.native_v6_userpass_state_supported()
            && self.recovery_attempt.is_none()
            && self.recovery_intent.is_none()
            && self.recovery_delivery.is_none()
            && self.password_policies.values().all(BTreeMap::is_empty)
            && self.jwt_mounts.values().all(BTreeMap::is_empty)
            && self.kubernetes_mounts.values().all(BTreeMap::is_empty)
            && self.oidc_mounts.values().all(BTreeMap::is_empty)
            && self.ldap_mounts.values().all(BTreeMap::is_empty)
            && self.ldap_groups.values().all(BTreeMap::is_empty)
            && self.ldap_native_users.values().all(BTreeMap::is_empty)
            && self.radius_mounts.values().all(BTreeMap::is_empty)
            && self.radius_native_users.values().all(BTreeMap::is_empty)
            && self.kerberos_mounts.values().all(BTreeMap::is_empty)
            && self.plugin_auth_mounts.values().all(BTreeMap::is_empty)
            && self.auth_mounts.iter().all(|(namespace, mounts)| {
                if namespace.is_empty() {
                    mounts.values().all(|mount| {
                        matches!(
                            mount.kind.as_str(),
                            "token" | "approle" | "cert" | "userpass"
                        )
                    })
                } else if paths.is_some_and(|paths| paths.contains(namespace)) {
                    mounts.values().all(|mount| {
                        matches!(mount.kind.as_str(), "token" | "approle" | "cert")
                            && matches!(
                                mount.token_type.unwrap_or_default(),
                                batch_issuance::MountTokenType::DefaultService
                                    | batch_issuance::MountTokenType::Service
                            )
                    })
                } else {
                    // Only exact fresh, flat metadata is locally serviceable.
                    // Service still binds every child to its visible catalog,
                    // incarnation and paired batch ledger before publication.
                    !namespace.contains('/')
                        && self.namespace_is_empty(namespace)
                        && mounts == &userpass_names::fresh_default_auth_mounts()
                }
            })
            && self.policies.keys().all(admitted)
            && self.roles.keys().all(admitted)
            && self.mounted_roles.keys().all(admitted)
            && self.cert_roles.keys().all(admitted)
            && self.token_roles.keys().all(admitted)
            && self.tokens.values().all(|token| {
                admitted(&token.namespace)
                    && (token.namespace.is_empty()
                        || (token.cubbyhole.native_is_empty() && token.wrapping.is_none()))
                    && token.cubbyhole.supports_native_root()
                    && (token.namespace.is_empty()
                        || !matches!(
                            token.auth_provenance,
                            Some(TokenAuthProvenance::Userpass { .. })
                        ))
                    && matches!(
                        token.auth_provenance,
                        None | Some(TokenAuthProvenance::TokenApi { .. })
                            | Some(TokenAuthProvenance::AppRole { .. })
                            | Some(TokenAuthProvenance::Cert { .. })
                            | Some(TokenAuthProvenance::Userpass { .. })
                    )
            })
    }

    // This is only the Auth half of the closed profile. Service additionally
    // binds every controlled policy/request to its actual namespace KV2 data mount.
    // Unsupported controlled Auth/workflow/wrapped/batch owners stay blocked.
    fn native_v6_control_groups_supported(&self, paths: Option<&BTreeSet<String>>) -> bool {
        self.validate_control_group_state().is_ok()
            && self.policies.values().flat_map(BTreeMap::values)
                .flat_map(|p| p.control_groups.values()).flatten()
                .all(|stanza| stanza.control.factors.iter().all(|factor| {
                    factor.controlled_capabilities.as_ref().is_some_and(|caps| {
                        !caps.is_empty() && caps.iter().all(|cap| matches!(cap.as_str(), "create" | "update" | "read"))
                    })
                }))
            && self.control_groups.requests.values().all(|owner| {
                (if owner.namespace.is_empty() {
                    owner.namespace_id == "root" && owner.namespace_incarnation == 0
                } else {
                    paths.is_some_and(|paths| paths.contains(&owner.namespace))
                        && owner.namespace_id != "root" && owner.namespace_incarnation > 0
                }) && owner.credential.is_none()
                    && owner.logical_data.is_none() && owner.wrap_ttl_seconds.is_none_or(|v| v == 0)
                    && matches!(
                        (owner.method.as_str(), owner.capability.as_str()),
                        ("POST" | "PUT", "create" | "update") | ("GET", "read")
                    )
                    && !owner.requires_sudo
                    && owner.transport_namespace == owner.namespace
                    && owner.transport_method == owner.method
                    && owner.transport_path == owner.path && owner.transport_body == owner.body
                    && matches!(&owner.resource_binding, control_groups::ResourceBinding::Secret { owner: mount } if mount.is_kv(&owner.path))
                    && owner.authorizations.values().all(|approval| approval.credential.is_none())
            })
    }

    pub(crate) fn native_v6_control_group_scoped_policy_paths(
        &self,
    ) -> impl Iterator<Item = (&str, &str)> {
        self.policies.iter().flat_map(|(namespace, policies)| {
            policies.values().flat_map(move |policy| {
                policy
                    .control_groups
                    .keys()
                    .map(move |path| (namespace.as_str(), path.as_str()))
            })
        })
    }

    /// Recheck only the original AppRole login credential's lifetime against
    /// the caller's current observation of its original request clock. Call
    /// this on the retained source Auth owner, never the already consumed
    /// candidate. This does not authenticate, decrement uses or issue a token.
    pub(crate) fn validate_native_v6_approle_login_lifetime_observed(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(());
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return Ok(());
        };
        let mounts = self.effective_auth_mounts(namespace);
        let Some((mount, _)) = mounts.iter().find(|(mount, entry)| {
            entry.kind == "approle" && auth_path.strip_prefix(&format!("{mount}/")) == Some("login")
        }) else {
            return Ok(());
        };
        let role_id = string_field(body, "role_id")?.trim();
        let secret_id = body.get("secret_id").and_then(Value::as_str).map(str::trim);
        if role_id.len() > 256 || secret_id.is_some_and(|value| value.len() > 256) {
            return Err(bad("invalid role or secret ID"));
        }
        let scope = AuthScope { namespace, mount };
        let role = self
            .roles_at(scope)
            .and_then(|roles| roles.values().find(|role| role.role_id == role_id))
            .ok_or_else(|| bad("invalid role or secret ID"))?;
        if role.bind_secret_id {
            let secret_id = secret_id.ok_or_else(|| bad("invalid role or secret ID"))?;
            let secret = role
                .approle_secrets()?
                .get(&hash(secret_id))
                .ok_or_else(|| bad("invalid role or secret ID"))?;
            let now = self.token_api_observed_time(time).seconds();
            if secret.expires_at.is_some_and(|expiry| now >= expiry)
                || secret.uses_remaining == Some(0)
            {
                return Err(bad("invalid role or secret ID"));
            }
        }
        Ok(())
    }

    /// Capture the presented leaf's original validity for an actual mounted
    /// cert-login route. The caller supplies the existing RequestView's verified
    /// TLS chain; raw HTTP fields are never accepted as a certificate source.
    /// The real cert dispatcher separately verifies role/fingerprint/identity.
    pub(crate) fn capture_native_v6_cert_login_lifetime(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        peer_certificates: Option<&[Vec<u8>]>,
        time: AuthorityTime,
    ) -> Result<Option<NativeV6CertLifetime>, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(None);
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return Ok(None);
        };
        if !self
            .effective_auth_mounts(namespace)
            .iter()
            .any(|(mount, entry)| {
                entry.kind == "cert"
                    && auth_path.strip_prefix(&format!("{mount}/")) == Some("login")
            })
        {
            return Ok(None);
        }
        let chain = peer_certificates.ok_or_else(denied)?;
        let time = self.token_api_observed_time(time);
        presented_leaf_lifetime(chain, time).map(Some)
    }

    /// Retain the original verified leaf lifetime only when the actual renewal
    /// target has a direct certificate-login binding. Token-API children keep
    /// their independent renewal authority and require no unrelated TLS leaf.
    /// This must be called on the pre-renewal Auth owner after real dispatch;
    /// it neither renews the target nor consumes another credential use.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture_native_v6_cert_renewal_lifetime(
        &self,
        actor: &Principal,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        peer_certificates: Option<&[Vec<u8>]>,
        time: AuthorityTime,
    ) -> Result<Option<NativeV6CertLifetime>, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(None);
        }
        let Some(operation) = path.strip_prefix("auth/token/") else {
            return Ok(None);
        };
        if !matches!(operation, "renew-self" | "renew" | "renew-accessor") {
            return Ok(None);
        }
        let time = self.principal_token_api_time(actor, time)?;
        let id = if operation == "renew-self" {
            actor.require_service("batch tokens cannot be renewed")?;
            actor.digest.clone()
        } else {
            self.target_token_observed(namespace, body, operation == "renew-accessor", time)?
        };
        // Reuse the real renewal contract, including legacy child provenance,
        // live role, exact leaf fingerprint and the no-certificate error class.
        // None is significant: that target has no certificate renewal binding.
        if self
            .cert_renewal_limits(&id, time, peer_certificates)?
            .is_none()
        {
            return Ok(None);
        }
        let chain = peer_certificates.ok_or_else(denied)?;
        presented_leaf_lifetime(chain, time).map(Some)
    }

    pub(crate) fn native_v6_local_auth_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if !namespace.is_empty() {
            return self.native_v6_plain_auth_route(namespace, method, path, body);
        }
        if self.native_v6_userpass_route(namespace, method, path, body) {
            return true;
        }
        if path == "sys/policy"
            || path == "cubbyhole"
            || path.starts_with("cubbyhole/")
            || path.starts_with("sys/policy/")
            || path == "sys/policies/acl"
            || path.starts_with("sys/policies/acl/")
            || path == "sys/quotas/config"
            || path == "sys/quotas/rate-limit"
            || path.starts_with("sys/quotas/rate-limit/")
            || path.starts_with("auth/token/")
        {
            return true;
        }
        let mounts = self.effective_auth_mounts(namespace);
        if let Some(suffix) = path.strip_prefix("sys/auth/") {
            let mount = suffix.strip_suffix("/tune").unwrap_or(suffix);
            return mounts
                .get(mount)
                .is_some_and(|entry| matches!(entry.kind.as_str(), "approle" | "cert"))
                || (matches!(method, "POST" | "PUT")
                    && !suffix.ends_with("/tune")
                    && body
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| matches!(kind, "approle" | "cert")));
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return false;
        };
        mounts.iter().any(|(mount, entry)| {
            let Some(suffix) = auth_path.strip_prefix(&format!("{mount}/")) else {
                return false;
            };
            match entry.kind.as_str() {
                "approle" => suffix == "login" || suffix == "role" || suffix.starts_with("role/"),
                "cert" => {
                    suffix == "login"
                        || suffix == "config"
                        || suffix == "certs"
                        || suffix.starts_with("certs/")
                }
                _ => false,
            }
        })
    }
    pub(crate) fn native_v6_plain_auth_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if namespace.is_empty() {
            return false;
        }
        // Admit delivery of the root-only 400 rejection through the same
        // authenticated flat-namespace scope; this grants no child quota write.
        if path == "sys/quotas/config"
            || path == "sys/quotas/rate-limit"
            || path.starts_with("sys/quotas/rate-limit/")
        {
            return true;
        }
        if path == "sys/policy"
            || path.starts_with("sys/policy/")
            || path == "sys/policies/acl"
            || path.starts_with("sys/policies/acl/")
            || path.starts_with("auth/token/")
        {
            return true;
        }
        let mounts = self.effective_auth_mounts(namespace);
        if let Some(suffix) = path.strip_prefix("sys/auth/") {
            let mount = suffix.strip_suffix("/tune").unwrap_or(suffix);
            return mounts
                .get(mount)
                .is_some_and(|entry| matches!(entry.kind.as_str(), "approle" | "cert"))
                || (matches!(method, "POST" | "PUT")
                    && !suffix.ends_with("/tune")
                    && body
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| matches!(kind, "approle" | "cert")));
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return false;
        };
        mounts.iter().any(|(mount, entry)| {
            let Some(suffix) = auth_path.strip_prefix(&format!("{mount}/")) else {
                return false;
            };
            match entry.kind.as_str() {
                "approle" => suffix == "login" || suffix == "role" || suffix.starts_with("role/"),
                "cert" => {
                    matches!(suffix, "login" | "config" | "certs") || suffix.starts_with("certs/")
                }
                _ => false,
            }
        })
    }
}
