//! Typed request and inspection capabilities. No batch issuance route is exposed
//! here, and no batch authentication creates a service token backing record.
use super::batch::VerifiedBatchClaims;
use super::*;

pub(super) enum VerifiedCredential {
    Service(Box<Token>),
    Batch(Box<VerifiedBatchClaims>),
}
impl VerifiedCredential {
    pub(super) fn policies(&self) -> &BTreeSet<String> {
        match self {
            Self::Service(token) => &token.policies,
            Self::Batch(claims) => claims.policies(),
        }
    }
    pub(super) fn entity_id(&self) -> Option<&str> {
        match self {
            Self::Service(token) => token.entity_id.as_deref(),
            Self::Batch(claims) => claims.entity_id(),
        }
    }
    pub(super) fn display_name(&self) -> &str {
        match self {
            Self::Service(token) => &token.display_name,
            Self::Batch(claims) => claims.display_name(),
        }
    }
}

pub(super) enum CheckedCredential<'a> {
    Service(&'a Token),
    Batch(&'a VerifiedBatchClaims),
}
impl<'a> CheckedCredential<'a> {
    pub(super) fn service(self) -> Result<&'a Token, AuthError> {
        match self {
            Self::Service(token) => Ok(token),
            Self::Batch(_) => Err(bad("batch tokens cannot create tokens")),
        }
    }
    pub(super) fn namespace(&self) -> &str {
        match self {
            Self::Service(token) => &token.namespace,
            Self::Batch(claims) => claims.namespace(),
        }
    }
    pub(super) fn policies(&self) -> &BTreeSet<String> {
        match self {
            Self::Service(token) => &token.policies,
            Self::Batch(claims) => claims.policies(),
        }
    }
    pub(super) fn entity_id(&self) -> Option<&str> {
        match self {
            Self::Service(token) => token.entity_id.as_deref(),
            Self::Batch(claims) => claims.entity_id(),
        }
    }
    pub(super) fn is_root(&self) -> bool {
        matches!(self, Self::Service(token) if token.root)
    }
    pub(super) fn is_wrapping(&self) -> bool {
        matches!(self, Self::Service(token) if token.wrapping.is_some())
    }
    pub(super) fn info_observed(&self, time: AuthorityTime) -> Result<Value, AuthError> {
        let now = time.seconds();
        match self {
            Self::Service(token) => token_info_observed(token, time),
            Self::Batch(claims) => {
                let mut info = json!({
                    "accessor":"", "policies":claims.policies(),
                    "display_name":claims.display_name(), "path":claims.path(),
                    "creation_time":claims.issued_at(),
                    "ttl":claims.expires_at().saturating_sub(now),
                    "expire_time":crate::engines::timestamp(claims.expires_at()),
                    "expire_time_unix":claims.expires_at(), "explicit_max_ttl":0,
                    "num_uses":0, "renewable":false, "orphan":claims.parent().is_none(),
                    "type":"batch", "namespace":claims.namespace(),
                    "entity_id":claims.entity_id().unwrap_or(""), "meta":claims.metadata()
                });
                if let Some(role) = claims.token_role() {
                    info["role"] = json!(role.name);
                    info["creation_ttl"] = json!(claims.expires_at() - claims.issued_at());
                }
                if !claims.bound_cidrs().is_empty() {
                    info["bound_cidrs"] = json!(claims.bound_cidrs());
                }
                if let Some(lease) = claims.precision() {
                    let now = time.exact().ok_or_else(denied)?;
                    info["ttl"] = json!(
                        lease
                            .expires_at
                            .lookup_remaining_seconds(now)
                            .map_err(|_| denied())?
                    );
                    info["expire_time"] = json!(lease.expires_at.rfc3339());
                    info["issue_time"] = json!(
                        Timestamp::whole(claims.issued_at())
                            .map_err(|_| denied())?
                            .rfc3339()
                    );
                    info["creation_ttl"] = json!(lease.granted_ttl.public_seconds());
                }
                Ok(info)
            }
        }
    }
}

pub(super) enum InspectionCredential {
    Service(String),
    Batch(Box<VerifiedBatchClaims>),
}
impl Drop for InspectionCredential {
    fn drop(&mut self) {
        if let Self::Service(digest) = self {
            digest.zeroize();
        }
    }
}
impl InspectionCredential {
    pub(super) fn view<'a>(
        &'a self,
        auth: &'a AuthState,
        now: u64,
    ) -> Result<CheckedCredential<'a>, AuthError> {
        self.view_observed(auth, AuthorityTime::Coarse(now))
    }

    pub(super) fn view_observed<'a>(
        &'a self,
        auth: &'a AuthState,
        time: AuthorityTime,
    ) -> Result<CheckedCredential<'a>, AuthError> {
        match self {
            Self::Service(digest) => auth
                .active_token_observed(digest, time, true)
                .map(CheckedCredential::Service),
            Self::Batch(claims) => {
                auth.check_batch_claims_observed(claims, claims.namespace(), time)?;
                Ok(CheckedCredential::Batch(claims))
            }
        }
    }
}

impl Principal {
    pub(super) fn service_token(&self) -> Option<&Token> {
        match &self.credential {
            VerifiedCredential::Service(token) => Some(token),
            VerifiedCredential::Batch(_) => None,
        }
    }
    pub(super) fn require_service(&self, message: &str) -> Result<&Token, AuthError> {
        self.service_token().ok_or_else(|| bad(message))
    }
    pub(crate) fn consumed_last_use(&self) -> bool {
        self.service_token()
            .is_some_and(|token| token.uses_remaining == Some(0))
    }
    pub(crate) fn display_name(&self) -> &str {
        self.credential.display_name()
    }
}

pub(crate) struct ResolvedLeaseOwner {
    pub(crate) owner: LeaseOwner,
    pub(crate) expires_at: Option<u64>,
    pub(crate) precise_expires_at: Option<Timestamp>,
    pub(crate) entity_id: Option<String>,
}

impl AuthState {
    pub(crate) fn has_batch_authority(&self) -> bool {
        self.batch_authority.is_some()
    }
    pub(crate) fn validate_batch_authority(&self) -> Result<(), AuthError> {
        if let Some(authority) = &self.batch_authority {
            authority
                .validate()
                .map_err(|_| err(503, "invalid batch authority"))?;
        }
        Ok(())
    }
    pub(crate) fn validate_batch_lease_owner(
        &self,
        claims: &BatchLeaseClaims,
        namespace: &str,
    ) -> Result<(), AuthError> {
        self.batch_authority
            .as_ref()
            .ok_or_else(|| err(503, "missing batch lease key authority"))?
            .validate_lease_authority(claims, namespace)
            .map_err(|_| err(503, "invalid batch lease key authority"))
    }
    fn batch_parent_expiry(
        &self,
        parent: Option<&str>,
        namespace: &str,
        now: u64,
    ) -> Result<Option<u64>, AuthError> {
        self.batch_parent_expiry_observed(parent, namespace, AuthorityTime::Coarse(now))
    }

    fn batch_parent_expiry_observed(
        &self,
        parent: Option<&str>,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<Option<u64>, AuthError> {
        match parent {
            None => Ok(None),
            Some(digest) => self
                .lease_issuer_by_digest_observed(digest, namespace, time)
                .map(|issuer| issuer.expires_at)
                .ok_or_else(denied),
        }
    }
    pub(super) fn check_batch_claims(
        &self,
        claims: &VerifiedBatchClaims,
        namespace: &str,
        now: u64,
    ) -> Result<(), AuthError> {
        self.check_batch_claims_observed(claims, namespace, AuthorityTime::Coarse(now))
    }

    pub(super) fn check_batch_claims_observed(
        &self,
        claims: &VerifiedBatchClaims,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let time = self.token_api_observed_time(time);
        self.batch_authority
            .as_ref()
            .ok_or_else(denied)?
            .check_verified_observed(claims, namespace, time)
            .map_err(|_| denied())?;
        self.batch_parent_expiry_observed(claims.parent(), namespace, time)?;
        Ok(())
    }
    pub(super) fn batch_principal(
        &self,
        raw: &str,
        now: u64,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<Principal, AuthError> {
        self.batch_principal_observed(raw, AuthorityTime::Coarse(now), origin_peer)
    }

    pub(super) fn batch_principal_observed(
        &self,
        raw: &str,
        time: AuthorityTime,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<Principal, AuthError> {
        if raw.len() > batch::MAX_BATCH_TOKEN_BYTES {
            return Err(denied());
        }
        let claims = self
            .batch_authority
            .as_ref()
            .ok_or_else(denied)?
            .open_authenticated_observed(raw, time)
            .map_err(|_| denied())?;
        self.check_batch_claims_observed(&claims, claims.namespace(), time)?;
        token_cidrs::check(claims.bound_cidrs(), origin_peer)?;
        Ok(Principal {
            admission: PrincipalAdmission::Operation {
                finite_use_consumed: false,
            },
            digest: claims.token_digest().to_owned(),
            credential: VerifiedCredential::Batch(Box::new(claims)),
            origin_peer,
            identity_policies: BTreeSet::new(),
            identity_templates: IdentityTemplateValues::default(),
            wrap_ttl_seconds: None,
            identity_checked: false,
            #[cfg(test)]
            request_time: time.seconds(),
        })
    }
    pub(super) fn inspect_raw_target(
        &self,
        raw: &str,
        namespace: &str,
        now: u64,
    ) -> Result<InspectionCredential, AuthError> {
        self.inspect_raw_target_observed(raw, namespace, AuthorityTime::Coarse(now))
    }

    pub(super) fn inspect_raw_target_observed(
        &self,
        raw: &str,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<InspectionCredential, AuthError> {
        validate_namespace(namespace)?;
        if raw.starts_with("hvb.") {
            if raw.len() > batch::MAX_BATCH_TOKEN_BYTES {
                return Err(denied());
            }
            let authority = self.batch_authority.as_ref().ok_or_else(denied)?;
            let claims = match time {
                AuthorityTime::Coarse(now) => authority.open(raw, namespace, now),
                AuthorityTime::Precise(_) => authority.open_authenticated_observed(raw, time),
            }
            .map_err(|_| denied())?;
            self.check_batch_claims_observed(&claims, namespace, time)?;
            // An administrator inspecting a target is not using its bearer as
            // the request actor. Target CIDRs must not be tested against their IP.
            return Ok(InspectionCredential::Batch(Box::new(claims)));
        }
        if raw.len() > 256 || !raw.starts_with("hvs.") {
            return Err(denied());
        }
        let digest = hash(raw);
        let token = self.active_token_observed(&digest, time, true)?;
        if token.namespace != namespace {
            return Err(denied());
        }
        Ok(InspectionCredential::Service(digest))
    }
    pub(crate) fn typed_lease_issuer(
        &self,
        actor: &Principal,
        namespace: &str,
        now: u64,
    ) -> Result<ResolvedLeaseOwner, AuthError> {
        self.typed_lease_issuer_observed(actor, namespace, AuthorityTime::Coarse(now))
    }
    pub(crate) fn typed_lease_issuer_observed(
        &self,
        actor: &Principal,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<ResolvedLeaseOwner, AuthError> {
        self.check_principal_observed(actor, namespace, time)?;
        let owner = match &actor.credential {
            VerifiedCredential::Service(_) => {
                LeaseOwner::service(&actor.digest).map_err(|_| denied())?
            }
            VerifiedCredential::Batch(claims) => LeaseOwner::from_batch(claims),
        };
        self.resolve_lease_owner_observed(&owner, namespace, time)
            .ok_or_else(denied)
    }
    /// The admitted final use may execute Kubernetes TokenRequest, but cannot
    /// release its leased credential. Persistent owner resolution stays strict;
    /// completion retires the observation after that one authorized execution.
    pub(crate) fn admitted_kubernetes_lease_issuer(
        &self,
        actor: &Principal,
        namespace: &str,
        now: u64,
    ) -> Result<ResolvedLeaseOwner, AuthError> {
        self.admitted_kubernetes_lease_issuer_observed(actor, namespace, AuthorityTime::Coarse(now))
    }
    pub(crate) fn admitted_kubernetes_lease_issuer_observed(
        &self,
        actor: &Principal,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<ResolvedLeaseOwner, AuthError> {
        match self.check_principal_observed(actor, namespace, time)? {
            CheckedCredential::Service(token) => Ok(ResolvedLeaseOwner {
                owner: LeaseOwner::service(&actor.digest).map_err(|_| denied())?,
                expires_at: token.expires_at,
                precise_expires_at: token
                    .token_api_precision
                    .as_ref()
                    .and_then(|lease| lease.expires_at),
                entity_id: token.entity_id.clone(),
            }),
            CheckedCredential::Batch(_) => self.typed_lease_issuer_observed(actor, namespace, time),
        }
    }
    pub(crate) fn resolve_lease_owner(
        &self,
        owner: &LeaseOwner,
        namespace: &str,
        now: u64,
    ) -> Option<ResolvedLeaseOwner> {
        self.resolve_lease_owner_observed(owner, namespace, AuthorityTime::Coarse(now))
    }

    pub(crate) fn resolve_lease_owner_observed(
        &self,
        owner: &LeaseOwner,
        namespace: &str,
        time: AuthorityTime,
    ) -> Option<ResolvedLeaseOwner> {
        let time = self.token_api_observed_time(time);
        if let Some(digest) = owner.service_digest() {
            let issuer = self.lease_issuer_by_digest_observed(digest, namespace, time)?;
            return Some(ResolvedLeaseOwner {
                owner: owner.clone(),
                expires_at: issuer.expires_at,
                precise_expires_at: issuer.precise_expires_at,
                entity_id: issuer.entity_id,
            });
        }
        let claims = owner.batch_claims()?;
        self.batch_authority
            .as_ref()?
            .check_lease_observed(claims, namespace, time)
            .ok()?;
        // Parent authority is a live dependency, not the batch lease's TTL cap.
        // Upstream indexes non-orphan batch leases under the service parent for
        // revocation, while the immutable batch claims define maximum expiry.
        self.batch_parent_expiry_observed(claims.parent(), namespace, time)
            .ok()?;
        Some(ResolvedLeaseOwner {
            owner: owner.clone(),
            expires_at: Some(claims.expires_at()),
            precise_expires_at: claims.precision().map(|lease| lease.expires_at),
            entity_id: claims.entity_id().map(str::to_owned),
        })
    }
}
