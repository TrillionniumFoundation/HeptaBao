//! The LDAPS profiles rebind the original credential and search live
//! groups on every renewal. Local policy, identity and commit authority are
//! checked only after that observation returns to the Service writer.
use super::provider_renewal::{same_policies, state_revision};
use super::*;

pub(crate) struct LdapRenewalPlan {
    namespace: String,
    mount: String,
    mount_revision: AuthMount,
    config: LdapMount,
    local_revision: [u8; 32],
    target: Zeroizing<String>,
    target_revision: [u8; 32],
    username: String,
    dn: String,
    credential: ProviderCredential,
    path: String,
    increment: u64,
    now: u64,
    started: std::time::Instant,
}

pub(crate) struct LdapRenewalObservation {
    pub(super) groups: BTreeSet<String>,
}

#[cfg(test)]
impl LdapRenewalObservation {
    pub(crate) fn observed(groups: BTreeSet<String>) -> Self {
        Self { groups }
    }
}

impl LdapRenewalPlan {
    pub(crate) fn execute(
        &self,
        outbound: &crate::outbound::Outbound,
    ) -> Result<LdapRenewalObservation, AuthError> {
        if let Some(config) = &self.config.native {
            return match outbound.ldap_authenticate_native(
                &self.config.url,
                &config.options(),
                config.transport.as_ref(),
                &self.username,
                &self.credential.0,
            ) {
                Ok(Some(observation)) => Ok(LdapRenewalObservation {
                    groups: observation.groups,
                }),
                Ok(None) | Err(_) => Err(bad("LDAP login failed during renewal")),
            };
        }
        match outbound.ldap_bind_and_search_groups(
            &self.config.url,
            &self.dn,
            &self.credential.0,
            &self.config.group_dn,
            self.config.group_attr(),
            self.config.group_name_attr(),
        ) {
            Ok(Some(groups)) => Ok(LdapRenewalObservation { groups }),
            // OpenBao's LDAP renewal reports bind, search and transport errors
            // as a failed login (400), without extending the token lease.
            Ok(None) | Err(_) => Err(bad("LDAP login failed during renewal")),
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
    pub(crate) fn has_ldap_renewal_provenance(&self) -> bool {
        self.tokens.values().any(|token| {
            matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::Ldap { .. })
            )
        })
    }

    pub(crate) fn validate_ldap_renewal_state(&self) -> Result<(), AuthError> {
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::Ldap {
                username,
                credential,
            }) = &token.auth_provenance
                && (token.root
                    || token.parent.is_some()
                    || !token.auth_origin_known
                    || token.wrapping.is_some()
                    || token.period != 0
                    || !valid_name(username)
                    || credential.0.is_empty()
                    || credential.0.len() > 1024
                    || credential.0.contains('\0')
                    || token.policies.contains("root")
                    || !token.auth_mount.as_ref().is_some_and(|mount| {
                        self.online_mount_enabled(&token.namespace, mount, "ldap")
                            && self
                                .ldap_native_at(AuthScope {
                                    namespace: &token.namespace,
                                    mount,
                                })
                                .is_none()
                    }))
            {
                return Err(bad("invalid LDAP renewal provenance"));
            }
        }
        Ok(())
    }

    fn ldap_renewal_local_revision(
        &self,
        scope: AuthScope<'_>,
        username: &str,
    ) -> Result<[u8; 32], AuthError> {
        if self.ldap_native_at(scope).is_some() {
            return self.ldap_native_local_revision(scope, username);
        }
        let user = self
            .users_at(scope)
            .and_then(|users| users.get(username))
            .ok_or_else(denied)?;
        state_revision(&(user, self.ldap_groups_at(scope)))
    }

    pub(super) fn prepare_ldap_renewal_target(
        &self,
        namespace: &str,
        path: &str,
        target: Zeroizing<String>,
        increment: u64,
        now: u64,
    ) -> Result<LdapRenewalPlan, AuthError> {
        let token = self.active_token(&target, now, false)?;
        let (username, credential, native) = match &token.auth_provenance {
            Some(TokenAuthProvenance::Ldap {
                username,
                credential,
            }) => (username, credential, false),
            Some(TokenAuthProvenance::LdapNative {
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
            .filter(|entry| entry.kind == "ldap")
            .ok_or_else(denied)?;
        let config = self
            .ldap_mounts
            .get(namespace)
            .and_then(|mounts| mounts.get(mount))
            .cloned()
            .ok_or_else(|| bad("LDAP backend not configured"))?;
        if !config.url.starts_with("ldaps://") || config.starttls {
            return Err(bad("LDAP renewal requires a host-enrolled LDAPS endpoint"));
        }
        if config.native.is_some() != native {
            return Err(denied());
        }
        let dn = config.user_dn_template.replace("{{username}}", username);
        if !native
            && (dn.is_empty() || dn.len() > 1024 || dn.bytes().any(|byte| byte == 0 || byte < 0x20))
        {
            return Err(bad("LDAP user DN is outside bounds"));
        }
        Ok(LdapRenewalPlan {
            namespace: namespace.to_owned(),
            mount: mount.clone(),
            mount_revision,
            config,
            local_revision: self
                .ldap_renewal_local_revision(AuthScope { namespace, mount }, username)?,
            target_revision: state_revision(token)?,
            username: username.clone(),
            dn,
            credential: credential.clone(),
            target,
            path: path.to_owned(),
            increment,
            now,
            started: std::time::Instant::now(),
        })
    }

    pub(super) fn finish_ldap_renewal(
        &mut self,
        plan: LdapRenewalPlan,
        actor: &Principal,
        observation: LdapRenewalObservation,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        self.authorize_request(actor, &plan.namespace, &plan.path, "update", now)?;
        let token = self.active_token(&plan.target, now, false)?;
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        if token.namespace != plan.namespace
            || !token.renewable
            || state_revision(token)? != plan.target_revision
            || self.effective_auth_mounts(&plan.namespace).get(&plan.mount)
                != Some(&plan.mount_revision)
            || self
                .ldap_mounts
                .get(&plan.namespace)
                .and_then(|mounts| mounts.get(&plan.mount))
                != Some(&plan.config)
            || self.ldap_renewal_local_revision(scope, &plan.username)? != plan.local_revision
        {
            return Err(err(
                409,
                "LDAP renewal authority changed during provider request",
            ));
        }
        if plan.config.native.is_some() {
            return self.finish_native_ldap_renewal(
                scope,
                &plan.target,
                &plan.username,
                observation.groups,
                plan.increment,
                now,
            );
        }
        let user = self
            .users_at(scope)
            .and_then(|users| users.get(&plan.username))
            .ok_or_else(denied)?;
        let mut effective_policies = user.policies.clone();
        if let Some(mappings) = self.ldap_groups_at(scope) {
            for group in &observation.groups {
                if let Some(policies) = mappings.get(group) {
                    effective_policies.extend(policies.iter().cloned());
                }
            }
        }
        if !same_policies(&effective_policies, &token.policies) {
            return Err(err(500, "policies have changed, not renewing"));
        }
        let expires_at = self.native_token_expiry(
            scope,
            NativeTokenLimits {
                ttl: user.token_ttl,
                max_ttl: user.token_max_ttl,
                period: 0,
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
            pending_batch: None,
            login_identity: None,
            external_groups: Some(identity::ExternalGroups {
                mount: plan.mount,
                alias: plan.username,
                names: observation.groups,
            }),
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
#[path = "auth_ldap_renewal_tests.rs"]
mod tests;
