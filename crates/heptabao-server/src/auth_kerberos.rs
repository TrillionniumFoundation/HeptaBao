//! A deliberately bounded Kerberos auth mount.
//!
//! The process accepts one complete HTTP Negotiate token through the system
//! GSS-API. Durable state contains only the enrolled service binding, local
//! token limits, and a bounded replay fence. Keytab bytes, tickets, passwords,
//! credential caches, and provider diagnostics never enter AuthState.

use super::*;
use crate::outbound::{
    KerberosObservation, MAX_KERBEROS_PRINCIPAL, MAX_KERBEROS_TICKET_LIFETIME, MAX_KERBEROS_TOKEN,
};
use std::path::{Component, Path};

pub(super) const MAX_KERBEROS_REPLAY_ENTRIES: usize = 4096;
const MAX_KERBEROS_KEYTAB_PATH: usize = 2048;
const MAX_KERBEROS_SERVICE: usize = 128;
const MAX_KERBEROS_TICKET_USES: u64 = 1_000_000;
const MAX_KERBEROS_CLOCK_SKEW: u64 = 300;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
pub(super) struct KerberosMount {
    /// The exact keytab principal used by the acceptor. The keytab itself is
    /// process-enrolled through KRB5_KTNAME and is never persisted here.
    service_account: String,
    realm: String,
    /// The Kerberos service component, normally `HTTP`.
    service: String,
    /// An absolute, process-local keytab path. Readback intentionally omits it.
    keytab_path: String,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    token_explicit_max_ttl: u64,
    token_num_uses: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    clock_skew_seconds: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    replay: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    last_admission_time: u64,
}

impl Drop for KerberosMount {
    fn drop(&mut self) {
        for (mut digest, _) in std::mem::take(&mut self.replay) {
            digest.zeroize();
        }
        self.keytab_path.zeroize();
        self.service_account.zeroize();
        self.realm.zeroize();
        self.service.zeroize();
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct KerberosLoginObservation {
    principal: String,
    realm: String,
    service: String,
    expires_at: u64,
}

impl KerberosLoginObservation {
    #[cfg(test)]
    pub(crate) fn for_test(principal: &str, realm: &str, service: &str, expires_at: u64) -> Self {
        Self {
            principal: principal.into(),
            realm: realm.into(),
            service: service.into(),
            expires_at,
        }
    }
}

pub(crate) struct KerberosLoginPlan {
    namespace: String,
    mount: String,
    mount_revision: AuthMount,
    config: KerberosMount,
    authorization: Zeroizing<String>,
    replay_digest: String,
    now: u64,
    started: std::time::Instant,
}

fn valid_realm(realm: &str) -> bool {
    !realm.is_empty()
        && realm.len() <= 255
        && realm.is_ascii()
        && realm
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_service_component(service: &str) -> bool {
    !service.is_empty()
        && service.len() <= MAX_KERBEROS_SERVICE
        && service.is_ascii()
        && service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_keytab_path(path: &str) -> bool {
    let path = path.strip_prefix("FILE:").unwrap_or(path);
    !path.is_empty()
        && path.len() <= MAX_KERBEROS_KEYTAB_PATH
        && path.starts_with('/')
        && !path.chars().any(char::is_control)
        && !Path::new(path)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn parse_service_account(
    service_account: &str,
    service: &str,
    realm: &str,
) -> Result<(), AuthError> {
    if service_account.len() > MAX_KERBEROS_PRINCIPAL
        || !service_account.is_ascii()
        || service_account
            .bytes()
            .any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(bad("invalid Kerberos service account"));
    }
    let (service_part, host_realm) = service_account
        .split_once('/')
        .ok_or_else(|| bad("Kerberos service_account must be service/host@realm"))?;
    let (host, account_realm) = host_realm
        .rsplit_once('@')
        .ok_or_else(|| bad("Kerberos service_account must be service/host@realm"))?;
    if service_account.matches('/').count() != 1
        || host.is_empty()
        || host.contains('@')
        || !valid_service_component(service_part)
        || !valid_service_component(host)
        || account_realm != realm
        || service_part != service
    {
        return Err(bad("Kerberos service account does not match realm/service"));
    }
    Ok(())
}

fn valid_client_principal(principal: &str, realm: &str) -> bool {
    if principal.is_empty()
        || principal.len() > MAX_KERBEROS_PRINCIPAL
        || !principal.is_ascii()
        || principal.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return false;
    }
    let Some((name, principal_realm)) = principal.rsplit_once('@') else {
        return false;
    };
    !name.is_empty()
        && !name.contains('@')
        && !principal_realm.is_empty()
        && principal_realm == realm
}

impl KerberosMount {
    // Replay and admission-clock progress are mutable observations, not a
    // policy revision. Exhaustive destructuring forces future fields to be
    // classified rather than accidentally dropping them from this comparison.
    fn same_authority(&self, other: &Self) -> bool {
        let Self {
            service_account,
            realm,
            service,
            keytab_path,
            policies,
            token_ttl,
            token_max_ttl,
            token_explicit_max_ttl,
            token_num_uses,
            clock_skew_seconds,
            replay: _,
            last_admission_time: _,
        } = self;
        service_account == &other.service_account
            && realm == &other.realm
            && service == &other.service
            && keytab_path == &other.keytab_path
            && policies == &other.policies
            && token_ttl == &other.token_ttl
            && token_max_ttl == &other.token_max_ttl
            && token_explicit_max_ttl == &other.token_explicit_max_ttl
            && token_num_uses == &other.token_num_uses
            && clock_skew_seconds == &other.clock_skew_seconds
    }

    pub(super) fn validate(&self) -> Result<(), AuthError> {
        if !valid_realm(&self.realm)
            || !valid_service_component(&self.service)
            || !valid_keytab_path(&self.keytab_path)
            || self.policies.len() > 128
            || self
                .policies
                .iter()
                .any(|policy| !valid_name(policy) || policy == "root")
            || self.token_ttl > MAX_TTL
            || self.token_max_ttl > MAX_TTL
            || self.token_explicit_max_ttl > MAX_TTL
            || self.token_ttl > 0 && self.token_max_ttl > 0 && self.token_ttl > self.token_max_ttl
            || self.token_num_uses > MAX_KERBEROS_TICKET_USES
            || self.clock_skew_seconds > MAX_KERBEROS_CLOCK_SKEW
            || self.replay.len() > MAX_KERBEROS_REPLAY_ENTRIES
            || self.replay.keys().any(|digest| {
                digest.len() != 43
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        {
            return Err(denied());
        }
        parse_service_account(&self.service_account, &self.service, &self.realm)?;
        if self.replay.values().any(|expiry| *expiry == 0) {
            return Err(denied());
        }
        Ok(())
    }

    pub(super) fn readback(&self) -> Value {
        json!({
            "service_account": self.service_account,
            "realm": self.realm,
            "service": self.service,
            "keytab_configured": true,
            "policies": self.policies,
            "token_policies": self.policies,
            "token_ttl": self.token_ttl,
            "token_max_ttl": self.token_max_ttl,
            "token_explicit_max_ttl": self.token_explicit_max_ttl,
            "token_num_uses": self.token_num_uses,
            "clock_skew_seconds": self.clock_skew_seconds,
        })
    }

    fn keytab_is_enrolled(&self) -> bool {
        let configured = self.keytab_path.as_str();
        let env = std::env::var("KRB5_KTNAME").ok();
        let Some(env) = env else {
            return false;
        };
        env == configured
            || env
                .strip_prefix("FILE:")
                .is_some_and(|path| path == configured.strip_prefix("FILE:").unwrap_or(configured))
            || format!("FILE:{configured}") == env
    }

    fn service_principal(&self) -> &str {
        &self.service_account
    }
}

impl AuthState {
    // A captured AP-REQ must not become reusable on another namespace/mount
    // after HA failover to a different process-local GSS replay cache. The
    // existing durable maps remain the sole owner; no second replay store.
    fn kerberos_replayed(&self, digest: &str, now: u64) -> bool {
        self.kerberos_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| {
                mount
                    .replay
                    .get(digest)
                    .is_some_and(|expires| *expires > now)
            })
    }

    /// Mount-only enrollment and retained configuration/replay state each need
    /// the Kerberos reader, independently of successful login or live tickets.
    pub(crate) fn has_kerberos_state(&self) -> bool {
        self.kerberos_mounts
            .values()
            .any(|mounts| !mounts.is_empty())
            || self
                .auth_mounts
                .values()
                .any(|mounts| mounts.values().any(|mount| mount.kind == "kerberos"))
    }

    pub(super) fn kerberos_at(&self, scope: AuthScope<'_>) -> Option<&KerberosMount> {
        self.kerberos_mounts.get(scope.namespace)?.get(scope.mount)
    }

    fn kerberos_at_mut(&mut self, scope: AuthScope<'_>) -> &mut KerberosMount {
        self.kerberos_mounts
            .entry(scope.namespace.into())
            .or_default()
            .entry(scope.mount.into())
            .or_insert_with(|| KerberosMount {
                service_account: String::new(),
                realm: String::new(),
                service: String::new(),
                keytab_path: String::new(),
                policies: BTreeSet::new(),
                token_ttl: 0,
                token_max_ttl: 0,
                token_explicit_max_ttl: 0,
                token_num_uses: 0,
                clock_skew_seconds: 0,
                replay: BTreeMap::new(),
                last_admission_time: 0,
            })
    }

    pub(super) fn validate_kerberos_state(&self) -> Result<(), AuthError> {
        for (namespace, mounts) in &self.kerberos_mounts {
            validate_namespace(namespace)?;
            for (mount, config) in mounts {
                if mount.is_empty()
                    || mount.len() > 256
                    || !mount.split('/').all(valid_name)
                    || !self
                        .effective_auth_mounts(namespace)
                        .get(mount)
                        .is_some_and(|entry| entry.kind == "kerberos")
                {
                    return Err(denied());
                }
                config.validate()?;
            }
        }
        Ok(())
    }

    pub(super) fn kerberos_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let path = format!("auth/{}/config", scope.mount);
        let actor = self.permission(
            principal,
            scope.namespace,
            &path,
            route_capability(method, false)?,
            now,
        )?;
        match method {
            "GET" => {
                reject_unknown(body, &[])?;
                let config = self
                    .kerberos_at(scope)
                    .ok_or_else(|| err(404, "Kerberos authentication is not configured"))?;
                Ok(response(config.readback(), false))
            }
            "POST" | "PUT" => {
                self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
                reject_unknown(
                    body,
                    &[
                        "service_account",
                        "realm",
                        "service",
                        "keytab_path",
                        "policies",
                        "token_policies",
                        "token_ttl",
                        "token_max_ttl",
                        "token_explicit_max_ttl",
                        "token_num_uses",
                        "clock_skew_seconds",
                    ],
                )?;
                reject_alias_pair(body, "policies", "token_policies")?;
                let previous = self.kerberos_at(scope).cloned();
                let service_account = body
                    .get("service_account")
                    .map(|_| string_field(body, "service_account").map(str::to_owned))
                    .transpose()?
                    .or_else(|| {
                        previous
                            .as_ref()
                            .map(|config| config.service_account.clone())
                    })
                    .ok_or_else(|| bad("service_account is required"))?;
                let realm = body
                    .get("realm")
                    .map(|_| string_field(body, "realm").map(str::to_owned))
                    .transpose()?
                    .or_else(|| previous.as_ref().map(|config| config.realm.clone()))
                    .ok_or_else(|| bad("realm is required"))?;
                let service = body
                    .get("service")
                    .map(|_| string_field(body, "service").map(str::to_owned))
                    .transpose()?
                    .or_else(|| previous.as_ref().map(|config| config.service.clone()))
                    .ok_or_else(|| bad("service is required"))?;
                let keytab_path = body
                    .get("keytab_path")
                    .map(|_| string_field(body, "keytab_path").map(str::to_owned))
                    .transpose()?
                    .or_else(|| previous.as_ref().map(|config| config.keytab_path.clone()))
                    .ok_or_else(|| bad("keytab_path is required"))?;
                if !valid_realm(&realm)
                    || !valid_service_component(&service)
                    || !valid_keytab_path(&keytab_path)
                {
                    return Err(bad("invalid Kerberos configuration bounds"));
                }
                parse_service_account(&service_account, &service, &realm)?;
                let policy_field = if body.get("token_policies").is_some() {
                    "token_policies"
                } else {
                    "policies"
                };
                let next = KerberosMount {
                    service_account,
                    realm,
                    service,
                    keytab_path,
                    policies: policies(
                        body,
                        policy_field,
                        &previous
                            .as_ref()
                            .map(|config| config.policies.clone())
                            .unwrap_or_default(),
                        false,
                    )?,
                    token_ttl: duration(
                        body,
                        "token_ttl",
                        previous.as_ref().map_or(0, |config| config.token_ttl),
                    )?,
                    token_max_ttl: duration(
                        body,
                        "token_max_ttl",
                        previous.as_ref().map_or(0, |config| config.token_max_ttl),
                    )?,
                    token_explicit_max_ttl: duration(
                        body,
                        "token_explicit_max_ttl",
                        previous
                            .as_ref()
                            .map_or(0, |config| config.token_explicit_max_ttl),
                    )?,
                    token_num_uses: number(
                        body,
                        "token_num_uses",
                        previous.as_ref().map_or(0, |config| config.token_num_uses),
                    )?,
                    clock_skew_seconds: number(
                        body,
                        "clock_skew_seconds",
                        previous
                            .as_ref()
                            .map_or(0, |config| config.clock_skew_seconds),
                    )?,
                    replay: previous
                        .as_ref()
                        .map_or_else(BTreeMap::new, |config| config.replay.clone()),
                    last_admission_time: previous
                        .as_ref()
                        .map_or(0, |config| config.last_admission_time),
                };
                next.validate()?;
                let changed = self.kerberos_at(scope) != Some(&next);
                self.kerberos_at_mut(scope).clone_from(&next);
                Ok(empty(changed))
            }
            "DELETE" => {
                self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
                reject_unknown(body, &[])?;
                let removed = self
                    .kerberos_mounts
                    .entry(scope.namespace.into())
                    .or_default()
                    .remove(scope.mount);
                if removed.is_some() {
                    Ok(empty(true))
                } else {
                    Err(err(404, "Kerberos authentication is not configured"))
                }
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    pub(crate) fn prepare_kerberos_login(
        &self,
        namespace: &str,
        mount: &str,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<KerberosLoginPlan, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        validate_namespace(namespace)?;
        let mount_revision = self
            .effective_auth_mounts(namespace)
            .get(mount)
            .filter(|entry| entry.kind == "kerberos")
            .cloned()
            .ok_or_else(denied)?;
        let config = self
            .kerberos_at(AuthScope { namespace, mount })
            .cloned()
            .ok_or_else(|| err(503, "Kerberos authentication is not configured"))?;
        config.validate()?;
        reject_unknown(body, &["kerberos_authorization"])?;
        let authorization = string_field(body, "kerberos_authorization")?;
        if authorization.len() > MAX_KERBEROS_TOKEN * 2 + 16
            || !authorization.is_ascii()
            || !authorization.starts_with("Negotiate ")
        {
            return Err(bad("invalid Kerberos authorization"));
        }
        let replay_digest = hash(authorization);
        if now < config.last_admission_time {
            return Err(err(400, "Kerberos clock moved backwards"));
        }
        // Check committed replay evidence before invoking GSS. Otherwise a
        // previously accepted ticket is classified by the local native cache,
        // which may be missing after restart or live on a different HA host.
        if self.kerberos_replayed(&replay_digest, now) {
            return Err(denied());
        }
        if config
            .replay
            .values()
            .filter(|expires| **expires > now)
            .count()
            >= MAX_KERBEROS_REPLAY_ENTRIES
        {
            return Err(err(503, "Kerberos replay fence is at capacity"));
        }
        Ok(KerberosLoginPlan {
            namespace: namespace.into(),
            mount: mount.into(),
            mount_revision,
            config,
            replay_digest,
            authorization: Zeroizing::new(authorization.to_owned()),
            now,
            started: std::time::Instant::now(),
        })
    }

    pub(crate) fn finish_kerberos_login(
        &mut self,
        plan: KerberosLoginPlan,
        observation: KerberosLoginObservation,
    ) -> Result<AuthResponse, AuthError> {
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        if self.effective_auth_mounts(&plan.namespace).get(&plan.mount)
            != Some(&plan.mount_revision)
        {
            return Err(err(409, "Kerberos configuration changed during login"));
        }
        let mut config = self
            .kerberos_at(scope)
            .filter(|current| current.same_authority(&plan.config))
            .cloned()
            .ok_or_else(|| err(409, "Kerberos configuration changed during login"))?;
        let now = plan.observed_now();
        if now < config.last_admission_time {
            return Err(err(400, "Kerberos clock moved backwards"));
        }
        if observation.service != plan.config.service_principal()
            || observation.realm != plan.config.realm
            || !valid_client_principal(&observation.principal, &plan.config.realm)
            || observation.expires_at <= now
            || observation.expires_at
                > now
                    .saturating_add(MAX_KERBEROS_TICKET_LIFETIME)
                    .saturating_add(plan.config.clock_skew_seconds)
        {
            return Err(denied());
        }
        config.replay.retain(|_, expiry| *expiry > now);
        if self.kerberos_replayed(&plan.replay_digest, now) {
            return Err(denied());
        }
        if config.replay.len() >= MAX_KERBEROS_REPLAY_ENTRIES {
            return Err(err(503, "Kerberos replay fence is at capacity"));
        }
        let ticket_ttl = observation.expires_at.saturating_sub(now);
        let (mount_ttl, mount_max_ttl) =
            self.auth_mount_token_limits(scope, config.token_ttl, config.token_max_ttl)?;
        let explicit_max_ttl = if config.token_explicit_max_ttl == 0 {
            ticket_ttl
        } else {
            checked_expiry(now, config.token_explicit_max_ttl)?
                .min(observation.expires_at)
                .saturating_sub(now)
        };
        let token_max_ttl = mount_max_ttl.min(ticket_ttl).min(explicit_max_ttl);
        let token_ttl = mount_ttl.min(ticket_ttl).min(token_max_ttl);
        if token_ttl == 0 || token_max_ttl == 0 || token_ttl > token_max_ttl {
            return Err(denied());
        }
        let explicit_max_expires_at = (config.token_explicit_max_ttl > 0)
            .then(|| checked_expiry(now, config.token_explicit_max_ttl))
            .transpose()?
            .map(|expiry| expiry.min(observation.expires_at));
        let mut token = login_token(
            &plan.namespace,
            {
                let mut policies = config.policies.clone();
                policies.insert("default".into());
                policies
            },
            token_ttl,
            token_max_ttl,
            config.token_num_uses,
            format!("kerberos-{}", observation.principal),
            now,
        )?;
        token.auth_mount = Some(plan.mount.clone());
        token.expires_at = Some(observation.expires_at.min(checked_expiry(now, token_ttl)?));
        token.max_expires_at = Some(
            explicit_max_expires_at
                .unwrap_or(checked_expiry(now, token_max_ttl)?)
                .min(observation.expires_at),
        );
        let (token_id, token, mut response) = Self::prepare_issue(token, now)?;
        config
            .replay
            .insert(plan.replay_digest, observation.expires_at);
        config.last_admission_time = now;
        self.kerberos_at_mut(scope).clone_from(&config);
        response.login_identity = Some(LoginIdentity {
            metadata: Some(BTreeMap::from([
                ("principal".into(), observation.principal),
                ("realm".into(), observation.realm),
            ])),
            mount: plan.mount,
            alias: token.display_name.clone(),
        });
        self.tokens.insert(token_id, token);
        Ok(response)
    }
}

impl KerberosLoginPlan {
    pub(crate) fn observed_now(&self) -> u64 {
        observed_admission_second(self.now, self.started.elapsed())
    }

    pub(crate) fn execute(
        &self,
        outbound: &crate::outbound::Outbound,
    ) -> Result<KerberosLoginObservation, AuthError> {
        if !self.config.keytab_is_enrolled() {
            return Err(err(503, "Kerberos keytab is not process-enrolled"));
        }
        let observation = outbound
            .kerberos_authenticate(
                self.authorization.as_str(),
                self.config.service_principal(),
                self.now,
            )
            .map_err(|_| bad("Kerberos login failed"))?;
        Ok(KerberosLoginObservation {
            principal: observation.principal,
            realm: observation.realm,
            service: observation.service,
            expires_at: observation.expires_at,
        })
    }
}

impl From<KerberosObservation> for KerberosLoginObservation {
    fn from(observation: KerberosObservation) -> Self {
        Self {
            principal: observation.principal,
            realm: observation.realm,
            service: observation.service,
            expires_at: observation.expires_at,
        }
    }
}

// Admission clocks have whole-second resolution. Rounding every subsecond
// exchange upward manufactures a future watermark and rejects the next
// legitimate login in the same second. Native ticket expiry is independently
// checked by GSS and remains an upper bound on every issued token.
fn observed_admission_second(now: u64, elapsed: std::time::Duration) -> u64 {
    now.saturating_add(elapsed.as_secs())
}

#[cfg(test)]
mod kerberos_clock_tests {
    use super::observed_admission_second;
    use std::time::Duration;

    #[test]
    fn kerberos_admission_clock_does_not_invent_a_future_second() {
        assert_eq!(observed_admission_second(100, Duration::from_nanos(1)), 100);
        assert_eq!(
            observed_admission_second(100, Duration::from_millis(999)),
            100
        );
        assert_eq!(
            observed_admission_second(100, Duration::from_millis(2900)),
            102
        );
        assert_eq!(
            observed_admission_second(u64::MAX, Duration::from_secs(1)),
            u64::MAX
        );
    }
}
