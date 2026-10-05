//! Ordinary Token API issuance preserves the actual original trusted clock.
//! Historical callers with no clock retain their original whole-second graph.
use super::token_precision::{BatchPrecision, DurationNanos, ServicePrecision};
use super::*;

pub(super) const ENABLED: bool = true;
pub(super) struct PreparedCreation<'a> {
    pub(super) actor: &'a Principal,
    pub(super) namespace: &'a str,
    pub(super) request_path: &'a str,
    pub(super) creation_seconds: u64,
    pub(super) parent: Token,
    pub(super) policies: BTreeSet<String>,
    pub(super) role: Option<token_roles::Role>,
    pub(super) issued_role: Option<token_roles::IssuedRole>,
    pub(super) root: bool,
    pub(super) batch: bool,
    pub(super) no_parent: bool,
    pub(super) entity_alias: Option<String>,
    pub(super) creation_path: String,
    pub(super) metadata: public_origin::MetadataInput,
    pub(super) requested_renewable: bool,
    pub(super) is_sudo: bool,
    pub(super) requested_no_parent: bool,
}
fn seconds(value: u64) -> Result<DurationNanos, AuthError> {
    DurationNanos::from_seconds(value).map_err(|_| err(503, "checked token duration unavailable"))
}
fn precise(clock: RequestClock) -> Result<Timestamp, AuthError> {
    clock
        .observed_at()
        .map_err(|_| err(503, "trusted precise token clock is unavailable"))
}
fn lesser(left: DurationNanos, right: DurationNanos) -> DurationNanos {
    if left.is_zero() {
        right
    } else if right.is_zero() {
        left
    } else {
        left.min(right)
    }
}
fn expiry(at: Timestamp, ttl: DurationNanos) -> Result<Timestamp, AuthError> {
    at.checked_add(ttl)
        .map_err(|_| err(503, "checked token deadline unavailable"))
}
fn ceil(at: Timestamp) -> Result<u64, AuthError> {
    at.ceil_seconds()
        .map_err(|_| err(503, "checked token deadline projection unavailable"))
}
impl AuthState {
    pub(super) fn finish_precise_token_creation(
        &mut self,
        prepared: PreparedCreation<'_>,
        body: &Value,
        clock: RequestClock,
    ) -> Result<AuthResponse, AuthError> {
        let clock = self.token_api_request_clock(clock);
        let PreparedCreation {
            actor,
            namespace,
            request_path,
            creation_seconds,
            parent,
            policies,
            role,
            issued_role,
            root,
            batch,
            no_parent,
            entity_alias,
            creation_path,
            metadata,
            requested_renewable,
            is_sudo,
            requested_no_parent,
        } = prepared;
        let role = role.as_ref();
        // These values are private trusted clocks, never body or carrier metadata.
        if Timestamp::whole(creation_seconds).map_err(|_| denied())?
            < clock.admitted_at().truncate_seconds()
        {
            return Err(err(503, "trusted token creation clock moved backwards"));
        }
        let requested = token_precise_ttl::RequestedDurations::parse(body)?;
        let requested_uses = token_precise_ttl::uses(body)?;
        if requested_no_parent && role.is_none() && !is_sudo {
            return Err(bad(
                "root or sudo privileges required to create orphan token",
            ));
        }
        if !requested.period.is_zero() && !is_sudo {
            return Err(bad(
                "root or sudo privileges required to create periodic token",
            ));
        }
        let mut period = requested.period;
        let mut maximum = requested.explicit_max;
        let mut warnings = Vec::new();
        if !batch && let Some(role) = role {
            let role_period = seconds(role.effective_period())?;
            let role_maximum = seconds(role.explicit_max())?;
            period = lesser(period, role_period);
            maximum = lesser(maximum, role_maximum);
            if !requested.explicit_max.is_zero() && !role_maximum.is_zero() {
                warnings.push(format!("Explicit max TTL specified both during creation call and in role; using the lesser value of {} seconds", maximum.public_seconds()));
            }
            if !requested.period.is_zero() && !role_period.is_zero() {
                warnings.push(format!("Period specified both during creation call and in role; using the lesser value of {} seconds", period.public_seconds()));
            }
        }
        if batch {
            let problem = if !requested.explicit_max.is_zero() {
                Some("explicit_max_ttl")
            } else if requested_uses != 0 {
                Some("num_uses")
            } else if !requested.period.is_zero() {
                Some("period")
            } else {
                None
            };
            if let Some(problem) = problem {
                return Err(bad(&format!("batch tokens cannot have {problem:?} set")));
            }
            if root {
                return Err(bad("batch tokens cannot have root policy"));
            }
        }
        let (default_ttl, mount_max) = self.auth_mount_lease_defaults(AuthScope {
            namespace,
            mount: "token",
        })?;
        let granted = if root && period.is_zero() && requested.ttl.is_zero() {
            maximum
        } else {
            let grant = token_precise_ttl::calculate(
                token_precise_ttl::TTLInputs {
                    default_ttl: seconds(default_ttl)?,
                    mount_max: seconds(mount_max)?,
                    increment: seconds(0)?,
                    backend_ttl: requested.ttl,
                    period,
                    backend_max: seconds(0)?,
                    explicit_max: maximum,
                    start: Some(Timestamp::whole(creation_seconds).map_err(|_| denied())?),
                },
                precise(clock)?,
            )
            .map_err(|error| bad(&error.to_string()))?;
            warnings.extend(grant.warnings);
            grant.ttl
        };
        if granted.is_zero() && (!root || parent.expires_at.is_some()) {
            return Err(bad(
                "expiring root tokens cannot create non-expiring root tokens",
            ));
        }
        let display_name = body
            .get("display_name")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("display name must be a string"))
            })
            .transpose()?
            .unwrap_or("token");
        if display_name.len() > 128 {
            return Err(bad("display name too long"));
        }
        warnings.extend(
            policies
                .iter()
                .filter(|name| {
                    name.as_str() != "root"
                        && name.as_str() != "default"
                        && !self
                            .policies
                            .get(namespace)
                            .is_some_and(|entries| entries.contains_key(*name))
                })
                .map(|name| {
                    format!(
                        "Policy {} does not exist",
                        token_policies::quote_policy(name)
                    )
                }),
        );
        let num_uses = role.map_or(requested_uses, |role| role.uses(requested_uses));
        let system_defaults = self.system_lease_defaults()?;
        let cidrs = if granted.is_zero() {
            Vec::new()
        } else if let Some(role) = role {
            role.bound_cidrs()
        } else if no_parent {
            Vec::new()
        } else {
            parent.bound_cidrs.clone()
        };
        let child_parent = (!no_parent).then(|| actor.digest.clone());
        let entity_id = if no_parent || entity_alias.is_some() {
            None
        } else {
            parent.entity_id.clone()
        };
        let issuance_time = precise(clock)?;
        self.authorize_request_observed(
            actor,
            namespace,
            request_path,
            "update",
            AuthorityTime::Precise(issuance_time),
        )?;
        self.check_principal_observed(actor, namespace, AuthorityTime::Precise(issuance_time))?
            .service()?;
        let mut response = if batch {
            // Stateless expiry keeps the whole CreationTime anchor, even when
            // the endpoint's execution and publication have later fractions.
            if granted.is_zero() {
                return Err(bad("batch token requires TTL"));
            }
            let deadline = expiry(
                Timestamp::whole(creation_seconds).map_err(|_| denied())?,
                granted,
            )?;
            // Every precise stateless grant originates in Token API issuance.
            // Bind that private provenance in the authenticated claim even
            // when every policy happens to fit historical ASCII grammar.
            let policy_marker = true;
            self.token_api_batch_policy_state = true;
            let claims = batch::BatchClaims {
                token_role: issued_role,
                token_api_precision: Some(BatchPrecision {
                    granted_ttl: granted,
                    expires_at: deadline,
                }),
                token_api_policy_names: policy_marker,
                public_origin: Some(metadata.batch_origin()),
                namespace: namespace.into(),
                policies,
                metadata: metadata.map(),
                display_name: display_name.into(),
                path: creation_path,
                bound_cidrs: cidrs,
                issued_at: creation_seconds,
                expires_at: ceil(deadline)?,
                parent: child_parent,
                entity_id,
            };
            let mut result = batch_issuance::PendingBatchGrant::response(
                claims,
                entity_alias.as_ref().map(|_| "token".into()),
            );
            result
                .pending_batch
                .as_mut()
                .ok_or_else(|| err(503, "precise batch grant is unavailable"))?
                .bind_token_api_publication(
                    self,
                    actor,
                    namespace,
                    request_path,
                    AuthorityTime::Precise(issuance_time),
                )?;
            result.body["auth"]["lease_duration"] = json!(granted.public_seconds());
            result.body["auth"]["num_uses"] = json!(num_uses);
            result
        } else {
            let accessor = random_id("a.")?;
            let grant_started_at = precise(clock)?;
            let deadline = (!granted.is_zero())
                .then(|| expiry(grant_started_at, granted))
                .transpose()?;
            let issued_at = if granted.is_zero() {
                grant_started_at
            } else {
                precise(clock)?
            };
            let lease = ServicePrecision {
                issued_at,
                grant_started_at,
                expires_at: deadline,
                last_renewed_at: None,
                previous_grant: granted,
                creation_grant: granted,
                requested_period: requested.period,
                requested_explicit_max: requested.explicit_max,
            };
            let max_expires_at = (!requested.explicit_max.is_zero())
                .then(|| {
                    expiry(
                        Timestamp::whole(creation_seconds).map_err(|_| denied())?,
                        requested.explicit_max,
                    )
                    .and_then(ceil)
                })
                .transpose()?;
            let expires_at = deadline.map(ceil).transpose()?;
            let token = Token {
                token_api_precision: Some(lease),
                public_origin: Some(public_origin::TokenApiOrigin::new(
                    metadata,
                    &creation_path,
                )?),
                issue_stamp: None,
                token_api_lease_ttl: deadline.map(|_| granted.ceil_seconds()),
                token_role: issued_role,
                bound_cidrs: cidrs,
                wrapping: None,
                entity_id,
                cubbyhole: cubbyhole::TokenCubbyhole::default(),
                accessor,
                namespace: namespace.into(),
                policies,
                root,
                parent: child_parent,
                created_at: creation_seconds,
                expires_at,
                max_expires_at,
                period: requested.period.ceil_seconds(),
                renewable: requested_renewable
                    && role.is_none_or(|role| role.renewable())
                    && deadline.is_some(),
                uses_remaining: unlimited_zero(num_uses),
                display_name: display_name.into(),
                auth_mount: if entity_alias.is_some() {
                    Some("token".into())
                } else if no_parent {
                    None
                } else {
                    parent.auth_mount.clone()
                },
                auth_origin_known: no_parent || parent.root || parent.auth_origin_known,
                auth_cert_role: None,
                auth_cert_sha256: None,
                auth_provenance: Some(TokenAuthProvenance::TokenApi {
                    issued_creation_ttl: Some(granted.public_seconds()),
                }),
            };
            let mut result = self.issue(token, creation_seconds)?;
            result.body["auth"]["lease_duration"] = json!(granted.public_seconds());
            result
        };
        self.token_api_precision_state = true;
        self.observe_token_api_time(AuthorityTime::Precise(precise(clock)?))?;
        self.system_lease_defaults.get_or_insert(system_defaults);
        if !warnings.is_empty() {
            response.body["warnings"] = json!(warnings);
        }
        if let Some(alias) = entity_alias {
            response.login_identity = Some(LoginIdentity {
                token_api_alias: true,
                mount: "token".into(),
                alias,
                metadata: None,
            });
        }
        Ok(response)
    }
}

impl AuthState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn renew_precise_token_api_token(
        &mut self,
        actor: &Principal,
        namespace: &str,
        path: &str,
        target: &str,
        body: &Value,
        clock: RequestClock,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let clock = self.token_api_request_clock(clock);
        let token = self.tokens.get(target).ok_or_else(denied)?;
        let Some(lease) = token.token_api_precision.as_ref() else {
            return Ok(None);
        };
        if token.namespace != namespace
            || !matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::TokenApi { .. })
            )
        {
            return Err(denied());
        }
        let increment = token_precise_ttl::renew_increment(body)?;
        let now = precise(clock)?;
        self.authorize_request_observed(
            actor,
            namespace,
            path,
            "update",
            AuthorityTime::Precise(now),
        )?;
        if lease.expires_at.is_some_and(|end| end < now) {
            return Err(bad("token not found"));
        }
        self.active_token_observed(target, AuthorityTime::Precise(now), false)?;
        if !token.renewable {
            return Err(bad("lease is not renewable"));
        }
        let role=token.token_role.as_ref().map(|issued|self.token_roles.get(namespace)
            .and_then(|roles|roles.get(&issued.name)).ok_or_else(||err(500,&format!("1 error occurred:\n\t* failed to renew entry: original token role {} could not be found, not renewing\n\n",token_policies::quote_policy(&issued.name))))).transpose()?;
        let period = role
            .map(|role| seconds(role.effective_period()))
            .transpose()?
            .unwrap_or(lease.requested_period);
        let explicit_max = role
            .map(|role| seconds(role.explicit_max()))
            .transpose()?
            .unwrap_or(lease.requested_explicit_max);
        let (default_ttl, mount_max) = self.auth_mount_lease_defaults(AuthScope {
            namespace,
            mount: "token",
        })?;
        let grant = token_precise_ttl::calculate(
            token_precise_ttl::TTLInputs {
                default_ttl: seconds(default_ttl)?,
                mount_max: seconds(mount_max)?,
                increment,
                backend_ttl: lease.previous_grant,
                period,
                backend_max: seconds(0)?,
                explicit_max,
                // The immutable actual lease IssueTime (not Token CreationTime) is
                // truncated by CalculateTTL. Requested original values stay public;
                // a role's current period/max are the renewal backend contract.
                start: Some(lease.issued_at),
            },
            precise(clock)?,
        )
        .map_err(|error| bad(&error.to_string()))?;
        let mut renewed = lease.clone();
        renewed.grant_started_at = precise(clock)?;
        self.authorize_request_observed(
            actor,
            namespace,
            path,
            "update",
            AuthorityTime::Precise(renewed.grant_started_at),
        )?;
        if lease
            .expires_at
            .is_some_and(|end| end < renewed.grant_started_at)
        {
            return Err(bad("token not found"));
        }
        self.active_token_observed(
            target,
            AuthorityTime::Precise(renewed.grant_started_at),
            false,
        )?;
        renewed.expires_at = Some(expiry(renewed.grant_started_at, grant.ttl)?);
        renewed.previous_grant = grant.ttl;
        renewed.last_renewed_at = Some(precise(clock)?);
        let coarse_expiry = renewed.expires_at.map(ceil).transpose()?;
        let system_defaults = self.system_lease_defaults()?;
        let token = self.tokens.get_mut(target).ok_or_else(denied)?;
        token.expires_at = coarse_expiry;
        token.token_api_lease_ttl = Some(grant.ttl.ceil_seconds());
        token.token_api_precision = Some(renewed);
        let mut response = AuthResponse {
            approle_secret_consumption: None,
            pending_batch: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"auth":{"accessor":token.accessor,"policies":token.policies,"token_policies":token.policies,
                "entity_id":token.entity_id.as_deref().unwrap_or(""),"lease_duration":grant.ttl.public_seconds(),
                "renewable":true,"token_type":"service","orphan":token.parent.is_none(),"num_uses":token.uses_remaining.unwrap_or(0)}}),
        };
        self.observe_token_api_time(AuthorityTime::Precise(precise(clock)?))?;
        self.system_lease_defaults.get_or_insert(system_defaults);
        if !grant.warnings.is_empty() {
            response.body["warnings"] = json!(grant.warnings);
        }
        Ok(Some(response))
    }
}
