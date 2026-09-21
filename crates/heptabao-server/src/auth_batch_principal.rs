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
    pub(super) fn info(&self, now: u64) -> Value {
        match self {
            Self::Service(token) => token_info(token, now),
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
                if !claims.bound_cidrs().is_empty() {
                    info["bound_cidrs"] = json!(claims.bound_cidrs());
                }
                info
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
        match self {
            Self::Service(digest) => auth
                .active_token(digest, now, true)
                .map(CheckedCredential::Service),
            Self::Batch(claims) => {
                auth.check_batch_claims(claims, claims.namespace(), now)?;
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
}

pub(crate) struct ResolvedLeaseOwner {
    pub(crate) owner: LeaseOwner,
    pub(crate) expires_at: Option<u64>,
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
        match parent {
            None => Ok(None),
            Some(digest) => self
                .lease_issuer_by_digest(digest, namespace, now)
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
        self.batch_authority
            .as_ref()
            .ok_or_else(denied)?
            .check_verified(claims, namespace, now)
            .map_err(|_| denied())?;
        self.batch_parent_expiry(claims.parent(), namespace, now)?;
        Ok(())
    }
    pub(super) fn batch_principal(
        &self,
        raw: &str,
        now: u64,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<Principal, AuthError> {
        if raw.len() > batch::MAX_BATCH_TOKEN_BYTES {
            return Err(denied());
        }
        let claims = self
            .batch_authority
            .as_ref()
            .ok_or_else(denied)?
            .open_authenticated(raw, now)
            .map_err(|_| denied())?;
        self.check_batch_claims(&claims, claims.namespace(), now)?;
        token_cidrs::check(claims.bound_cidrs(), origin_peer)?;
        Ok(Principal {
            digest: claims.token_digest().to_owned(),
            credential: VerifiedCredential::Batch(Box::new(claims)),
            origin_peer,
            identity_policies: BTreeSet::new(),
            identity_checked: false,
            #[cfg(test)]
            request_time: now,
        })
    }
    pub(super) fn inspect_raw_target(
        &self,
        raw: &str,
        namespace: &str,
        now: u64,
    ) -> Result<InspectionCredential, AuthError> {
        validate_namespace(namespace)?;
        if raw.starts_with("hvb.") {
            if raw.len() > batch::MAX_BATCH_TOKEN_BYTES {
                return Err(denied());
            }
            let claims = self
                .batch_authority
                .as_ref()
                .ok_or_else(denied)?
                .open(raw, namespace, now)
                .map_err(|_| denied())?;
            self.check_batch_claims(&claims, namespace, now)?;
            // An administrator inspecting a target is not using its bearer as
            // the request actor. Target CIDRs must not be tested against their IP.
            return Ok(InspectionCredential::Batch(Box::new(claims)));
        }
        if raw.len() > 256 || !raw.starts_with("hvs.") {
            return Err(denied());
        }
        let digest = hash(raw);
        let token = self.active_token(&digest, now, true)?;
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
        self.check_principal(actor, namespace, now)?;
        let owner = match &actor.credential {
            VerifiedCredential::Service(_) => {
                LeaseOwner::service(&actor.digest).map_err(|_| denied())?
            }
            VerifiedCredential::Batch(claims) => LeaseOwner::from_batch(claims),
        };
        self.resolve_lease_owner(&owner, namespace, now)
            .ok_or_else(denied)
    }
    pub(crate) fn resolve_lease_owner(
        &self,
        owner: &LeaseOwner,
        namespace: &str,
        now: u64,
    ) -> Option<ResolvedLeaseOwner> {
        if let Some(digest) = owner.service_digest() {
            let issuer = self.lease_issuer_by_digest(digest, namespace, now)?;
            return Some(ResolvedLeaseOwner {
                owner: owner.clone(),
                expires_at: issuer.expires_at,
                entity_id: issuer.entity_id,
            });
        }
        let claims = owner.batch_claims()?;
        self.batch_authority
            .as_ref()?
            .check_lease(claims, namespace, now)
            .ok()?;
        // Parent authority is a live dependency, not the batch lease's TTL cap.
        // Upstream indexes non-orphan batch leases under the service parent for
        // revocation, while the immutable batch claims define maximum expiry.
        self.batch_parent_expiry(claims.parent(), namespace, now)
            .ok()?;
        Some(ResolvedLeaseOwner {
            owner: owner.clone(),
            expires_at: Some(claims.expires_at()),
            entity_id: claims.entity_id().map(str::to_owned),
        })
    }
}
