//! Native service-token lifetimes follow OpenBao's CalculateTTL. Issuer-specific
//! role lookup and authentication stay outside this arithmetic; only the
//! explicit maximum captured at issue is a fixed absolute deadline.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct NativeTokenLimits {
    pub(super) ttl: u64,
    pub(super) max_ttl: u64,
    pub(super) period: u64,
}

pub(super) struct NativeOnlineToken {
    pub(super) bound_cidrs: Vec<String>,
    pub(super) policies: BTreeSet<String>,
    pub(super) limits: NativeTokenLimits,
    pub(super) explicit_max_ttl: u64,
    pub(super) uses: u64,
    pub(super) provenance: TokenAuthProvenance,
}

impl AuthState {
    pub(super) fn native_token_expiry(
        &self,
        scope: AuthScope<'_>,
        limits: NativeTokenLimits,
        issued_at: u64,
        explicit_max_expires_at: Option<u64>,
        increment: u64,
        now: u64,
    ) -> Result<u64, AuthError> {
        let (default_ttl, mut maximum_ttl) =
            self.auth_mount_token_limits(scope, limits.ttl, limits.max_ttl)?;
        if let Some(limit) = explicit_max_expires_at {
            maximum_ttl = maximum_ttl.min(limit.saturating_sub(issued_at));
        }
        if maximum_ttl == 0 {
            return Err(err(500, "past the max TTL, cannot renew"));
        }
        let ttl = if limits.period > 0 {
            limits.period.min(maximum_ttl)
        } else if increment > 0 {
            increment
        } else {
            default_ttl
        }
        .min(maximum_ttl);
        // Remote authorization rounds elapsed time up. Its issue timestamp can
        // therefore be ahead of the next request's integer clock by one second;
        // bound the lease duration as well as the absolute issue-time deadline.
        let mut expires_at = checked_expiry(now, ttl)?;
        if limits.period == 0 {
            expires_at = expires_at.min(checked_expiry(issued_at, maximum_ttl)?);
        }
        if let Some(limit) = explicit_max_expires_at {
            expires_at = expires_at.min(limit);
        }
        if expires_at <= now {
            return Err(err(500, "past the max TTL, cannot renew"));
        }
        Ok(expires_at)
    }

    pub(super) fn issue_native_online_token(
        &mut self,
        scope: AuthScope<'_>,
        alias: &str,
        authority: NativeOnlineToken,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        if authority.policies.contains("root") {
            return Err(denied());
        }
        let explicit_max_expires_at = if authority.explicit_max_ttl == 0 {
            None
        } else {
            Some(checked_expiry(now, authority.explicit_max_ttl)?)
        };
        let expires_at = self.native_token_expiry(
            scope,
            authority.limits,
            now,
            explicit_max_expires_at,
            0,
            now,
        )?;
        let token = Token {
            bound_cidrs: authority.bound_cidrs,
            wrapping: None,
            entity_id: None,
            cubbyhole: cubbyhole::TokenCubbyhole::default(),
            accessor: random_id("a.")?,
            namespace: scope.namespace.into(),
            policies: authority.policies,
            root: false,
            parent: None,
            created_at: now,
            expires_at: Some(expires_at),
            max_expires_at: explicit_max_expires_at,
            period: authority.limits.period,
            renewable: true,
            uses_remaining: unlimited_zero(authority.uses),
            display_name: format!("online-{}", &hash(alias)[..16]),
            auth_mount: Some(scope.mount.into()),
            auth_origin_known: true,
            auth_cert_role: None,
            auth_cert_sha256: None,
            auth_provenance: Some(authority.provenance),
        };
        let (id, token, mut issued) = Self::prepare_issue(token, now)?;
        issued.login_identity = Some(LoginIdentity {
            mount: scope.mount.into(),
            alias: alias.into(),
        });
        self.tokens.insert(id, token);
        Ok(issued)
    }
}
