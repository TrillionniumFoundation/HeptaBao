//! Direct RADIUS tokens require a fresh provider decision for each renewal.
//! Plans contain only an enrolled route and bounded, zeroized PAP credentials;
//! a provider observation is not permission to bypass current local authority.
use super::*;

use super::provider_renewal::{same_policies, state_revision};

pub(crate) struct RadiusRenewalPlan {
    namespace: String,
    mount: String,
    mount_revision: AuthMount,
    config: RadiusMount,
    target: Zeroizing<String>,
    target_revision: [u8; 32],
    native_revision: Option<[u8; 32]>,
    username: String,
    credential: ProviderCredential,
    path: String,
    increment: u64,
    now: u64,
    started: std::time::Instant,
}

pub(crate) struct RadiusRenewalObservation;

impl RadiusRenewalPlan {
    pub(crate) fn execute(
        &self,
        outbound: &crate::outbound::Outbound,
    ) -> Result<RadiusRenewalObservation, AuthError> {
        if let Some(config) = &self.config.native {
            return match outbound.radius_authenticate_native(
                &self.config.url,
                &config.options(),
                &self.username,
                &self.credential.0,
            ) {
                Ok(true) => Ok(RadiusRenewalObservation),
                Ok(false) | Err(_) => Err(bad("RADIUS login failed during renewal")),
            };
        }
        match outbound.radius_authenticate(&self.config.url, &self.username, &self.credential.0) {
            Ok(true) => Ok(RadiusRenewalObservation),
            Ok(false) => Err(bad("access denied by the authentication server")),
            Err(_) => Err(err(503, "RADIUS provider unavailable or response invalid")),
        }
    }

    pub(crate) fn observed_now(&self) -> u64 {
        let elapsed = self.started.elapsed();
        self.now.saturating_add(
            elapsed
                .as_secs()
                .saturating_add(u64::from(elapsed.subsec_nanos() > 0)),
        )
    }
}

impl AuthState {
    pub(crate) fn has_radius_native_parameters(&self) -> bool {
        self.radius_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|config| {
                config.token_period > 0
                    || config.token_explicit_max_ttl > 0
                    || config.policies.is_empty()
            })
            || self.tokens.values().any(|token| {
                token.period > 0
                    && matches!(
                        token.auth_provenance,
                        Some(TokenAuthProvenance::Radius { .. })
                    )
            })
    }

    pub(crate) fn has_v16_token_provenance(&self) -> bool {
        self.tokens.values().any(|token| {
            matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::Radius { .. } | TokenAuthProvenance::TokenApi)
            )
        })
    }

    pub(crate) fn validate_radius_renewal_state(&self) -> Result<(), AuthError> {
        for token in self.tokens.values() {
            match &token.auth_provenance {
                Some(TokenAuthProvenance::Radius {
                    username,
                    credential,
                }) => {
                    if token.root
                        || token.parent.is_some()
                        || !token.auth_origin_known
                        || token.wrapping.is_some()
                        || token.period > MAX_TTL
                        || username.is_empty()
                        || username.len() > 253
                        || username.bytes().any(|byte| byte == 0 || byte < 0x20)
                        || credential.0.is_empty()
                        || credential.0.len() > 128
                        || credential.0.bytes().any(|byte| byte == 0)
                        || token.policies.contains("root")
                        || !token.auth_mount.as_ref().is_some_and(|mount| {
                            self.online_mount_enabled(&token.namespace, mount, "radius")
                                && self
                                    .radius_native_at(AuthScope {
                                        namespace: &token.namespace,
                                        mount,
                                    })
                                    .is_none()
                        })
                    {
                        return Err(bad("invalid RADIUS renewal provenance"));
                    }
                }
                Some(TokenAuthProvenance::TokenApi) if token.wrapping.is_some() => {
                    return Err(bad("invalid token API provenance"));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn legacy_provider_renewal_is_ambiguous(&self, token: &Token) -> bool {
        // Old children with a real parent were issued by the token API. Old
        // orphans and direct logins cannot be distinguished by display_name,
        // which callers were free to choose. Only that ambiguous population
        // must log in again; ordinary existing permissions remain intact.
        token.auth_provenance.is_none()
            && token.parent.is_none()
            && token.auth_mount.as_ref().is_some_and(|mount| {
                self.online_mount_enabled(&token.namespace, mount, "radius")
                    || self.online_mount_enabled(&token.namespace, mount, "ldap")
            })
    }

    pub(super) fn require_offline_renewal_origin(&self, id: &str) -> Result<(), AuthError> {
        let token = self.tokens.get(id).ok_or_else(denied)?;
        if matches!(
            token.auth_provenance,
            Some(
                TokenAuthProvenance::Radius { .. }
                    | TokenAuthProvenance::RadiusNative { .. }
                    | TokenAuthProvenance::Ldap { .. }
                    | TokenAuthProvenance::LdapNative { .. }
            )
        ) {
            return Err(err(
                503,
                "provider renewal requires the Service online-auth dispatcher",
            ));
        }
        if self.legacy_provider_renewal_is_ambiguous(token) {
            return Err(bad(
                "legacy provider token has no renewable credential; log in again",
            ));
        }
        Ok(())
    }

    pub(super) fn prepare_radius_renewal_target(
        &self,
        namespace: &str,
        path: &str,
        target: Zeroizing<String>,
        increment: u64,
        now: u64,
    ) -> Result<RadiusRenewalPlan, AuthError> {
        let token = self.active_token(&target, now, false)?;
        let (username, credential, native) = match &token.auth_provenance {
            Some(TokenAuthProvenance::Radius {
                username,
                credential,
            }) => (username, credential, false),
            Some(TokenAuthProvenance::RadiusNative {
                username,
                credential,
                ..
            }) => (username, credential, true),
            _ => return Err(denied()),
        };
        if !token.renewable {
            return Err(bad("token is not renewable"));
        }
        let mount = token.auth_mount.as_ref().ok_or_else(denied)?;
        let mount_revision = self
            .effective_auth_mounts(namespace)
            .get(mount)
            .cloned()
            .filter(|entry| entry.kind == "radius")
            .ok_or_else(denied)?;
        let config = self
            .radius_mounts
            .get(namespace)
            .and_then(|mounts| mounts.get(mount))
            .cloned()
            .ok_or_else(|| bad("radius backend not configured"))?;
        if config.native.is_some() != native {
            return Err(denied());
        }
        let native_revision = if native {
            Some(self.radius_native_local_revision(AuthScope { namespace, mount }, username)?)
        } else {
            None
        };
        Ok(RadiusRenewalPlan {
            namespace: namespace.to_owned(),
            mount: mount.clone(),
            mount_revision,
            config,
            target_revision: state_revision(token)?,
            native_revision,
            target,
            username: username.clone(),
            credential: credential.clone(),
            path: path.to_owned(),
            increment,
            now,
            started: std::time::Instant::now(),
        })
    }

    pub(crate) fn finish_radius_renewal(
        &mut self,
        plan: RadiusRenewalPlan,
        actor: &Principal,
        _observation: RadiusRenewalObservation,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        self.authorize_request(actor, &plan.namespace, &plan.path, "update", now)?;
        let token = self.active_token(&plan.target, now, false)?;
        if token.namespace != plan.namespace
            || !token.renewable
            || state_revision(token)? != plan.target_revision
            || self.effective_auth_mounts(&plan.namespace).get(&plan.mount)
                != Some(&plan.mount_revision)
            || self
                .radius_mounts
                .get(&plan.namespace)
                .and_then(|mounts| mounts.get(&plan.mount))
                != Some(&plan.config)
        {
            return Err(err(
                409,
                "RADIUS renewal authority changed during provider request",
            ));
        }
        if plan.config.native.is_some() {
            let scope = AuthScope {
                namespace: &plan.namespace,
                mount: &plan.mount,
            };
            if Some(self.radius_native_local_revision(scope, &plan.username)?)
                != plan.native_revision
            {
                return Err(err(409, "RADIUS mapping changed during provider request"));
            }
            return self.finish_native_radius_renewal(
                scope,
                &plan.target,
                &plan.username,
                plan.increment,
                now,
            );
        }
        if !same_policies(&plan.config.policies, &token.policies) {
            return Err(err(500, "policies have changed, not renewing"));
        }
        let expires_at = self.native_token_expiry(
            AuthScope {
                namespace: &plan.namespace,
                mount: &plan.mount,
            },
            NativeTokenLimits {
                ttl: plan.config.token_ttl,
                max_ttl: plan.config.token_max_ttl,
                period: plan.config.token_period,
            },
            token.created_at,
            token.max_expires_at,
            plan.increment,
            now,
        )?;
        let token = self
            .tokens
            .get_mut(plan.target.as_str())
            .ok_or_else(denied)?;
        token.expires_at = Some(expires_at);
        Ok(AuthResponse {
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"auth": {
                "accessor": token.accessor, "policies": token.policies, "token_policies": token.policies,
                "entity_id": token.entity_id.as_deref().unwrap_or(""),
                "lease_duration": expires_at - now, "renewable": true, "token_type": "service"
            }}),
        })
    }
}

#[cfg(test)]
#[path = "auth_radius_tests.rs"]
mod tests;
