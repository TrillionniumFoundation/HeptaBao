//! Native token renewal retains the actual issuer and original target expiry.
//! Callback input is metadata, never an authentication admission or Principal.
use super::*;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RenewalOwner {
    path: String,
}
impl RenewalOwner {
    pub(super) fn new(path: &str) -> Result<Self, AuthError> {
        let owner = Self { path: path.into() };
        if !owner.valid() {
            return Err(bad("SDK renewal issuer path rejected"));
        }
        Ok(owner)
    }
    pub(super) fn valid(&self) -> bool {
        !self.path.is_empty()
            && self.path.len() <= 4096
            && !self.path.starts_with('/')
            && !self.path.ends_with('/')
            && self.path.split('/').all(|p| !matches!(p, "" | "." | ".."))
            && !self.path.chars().any(char::is_control)
    }
}
pub(crate) struct RenewalTarget {
    id: Zeroizing<String>,
    raw: Zeroizing<String>,
    binding: Binding,
    path: String,
    expected: [u8; 32],
    original_expiry: Timestamp,
    increment: token_precision::DurationNanos,
}
impl std::fmt::Debug for RenewalTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDK renewal target([REDACTED])")
    }
}
impl RenewalTarget {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
    pub(crate) fn binding(&self) -> &Binding {
        &self.binding
    }
    /// The accessor API deliberately masks the bearer. Its actual native
    /// target remains owned by this same renewal admission and final gate.
    pub(crate) fn response_gate(
        &self,
        auth: &AuthState,
        raw: &str,
        clock: RequestClock,
    ) -> Result<(), AuthError> {
        auth.sdk_renewal_gate(self, clock)?;
        if raw != self.raw.as_str() {
            return Err(denied());
        }
        if !raw.is_empty() {
            auth.sdk_auth_issued_live(raw, clock)?;
        }
        Ok(())
    }
    pub(crate) fn input(
        &self,
        auth: &AuthState,
        clock: RequestClock,
    ) -> Result<(Value, u64, u64), AuthError> {
        auth.sdk_renewal_gate(self, clock)?;
        let token = auth.tokens.get(self.id.as_str()).ok_or_else(denied)?;
        let Some(TokenAuthProvenance::Sdk { origin }) = &token.auth_provenance else {
            return Err(denied());
        };
        let issue = u64::try_from(origin.lease.issued_at.duration_since_epoch().as_nanos())
            .map_err(|_| bad("SDK issue time overflow"))?;
        let maximum = origin
            .maximum
            .elapsed(origin.lease.issued_at)
            .map_err(|_| bad("SDK maximum elapsed"))?;
        let value = json!({"lease":origin.lease.previous_grant.nanoseconds(),"max_ttl":maximum.nanoseconds(),
            "renewable":token.renewable,"internal_data":origin.internal_data,"metadata":origin.metadata,
            "policies":token.policies,"token_policies":token.policies,"accessor":token.accessor,
            "client_token":"","display_name":token.display_name,"entity_id":token.entity_id.as_deref().unwrap_or(""),
            "num_uses":token.uses_remaining.unwrap_or(0),"token_type":1,"orphan":token.parent.is_none()});
        Ok((value, issue, self.increment.nanoseconds()))
    }
}
fn fingerprint(token: &Token) -> Result<[u8; 32], AuthError> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(token).map_err(|_| err(503, "SDK renewal target encoding failed"))?,
    );
    Ok(crate::crypto::digest(&bytes))
}
fn precise(auth: &AuthState, clock: RequestClock) -> Result<Timestamp, AuthError> {
    let at = clock
        .observed_at()
        .map_err(|_| err(503, "SDK renewal original clock unavailable"))?;
    let at = auth.sdk_auth_clock.map_or(at, |floor| floor.max(at));
    auth.token_api_observed_time(AuthorityTime::Precise(at))
        .exact()
        .ok_or_else(denied)
}
fn operation(path: &str) -> Option<&str> {
    match path.strip_prefix("auth/token/")? {
        "renew-self" => Some("renew-self"),
        "renew" => Some("renew"),
        "renew-accessor" => Some("renew-accessor"),
        _ => None,
    }
}
impl AuthState {
    // Route discovery does not authorize a target or construct a Principal.
    pub(crate) fn sdk_renewal_binding(
        &self,
        namespace: &str,
        path: &str,
        body: &Value,
        raw: &str,
    ) -> Option<Binding> {
        let op = operation(path)?;
        let id = if op == "renew-self" {
            hash(raw)
        } else if op == "renew" {
            hash(body.get("token")?.as_str()?)
        } else {
            let accessor = body.get("accessor")?.as_str()?;
            self.tokens
                .iter()
                .find(|(_, t)| t.namespace == namespace && t.accessor == accessor)?
                .0
                .clone()
        };
        let token = self.tokens.get(&id)?;
        if token.namespace != namespace {
            return None;
        }
        match &token.auth_provenance {
            Some(TokenAuthProvenance::Sdk { origin }) => Some(origin.binding.clone()),
            _ => None,
        }
    }
    pub(crate) fn prepare_sdk_renewal(
        &self,
        actor: &Principal,
        namespace: &str,
        path: &str,
        body: &Value,
        raw: &str,
        clock: RequestClock,
    ) -> Result<RenewalTarget, AuthError> {
        let op = operation(path).ok_or_else(denied)?;
        if op == "renew-self" {
            reject_unknown(body, &["increment"])?;
            actor.require_service("batch tokens cannot be renewed")?;
        } else {
            reject_unknown(
                body,
                if op == "renew" {
                    &["token", "increment"]
                } else {
                    &["accessor", "increment"]
                },
            )?;
        }
        let at = precise(self, clock)?;
        self.authorize_request_observed(
            actor,
            namespace,
            path,
            "update",
            AuthorityTime::Precise(at),
        )?;
        let id = if op == "renew-self" {
            if hash(raw) != actor.digest {
                return Err(denied());
            }
            actor.digest.clone()
        } else {
            self.target_token_observed(
                namespace,
                body,
                op == "renew-accessor",
                AuthorityTime::Precise(at),
            )?
        };
        let token = self.active_token_observed(&id, AuthorityTime::Precise(at), false)?;
        // The original caller admission may consume the target's final use.
        // OpenBao removes that target before SDK AuthRenew; it cannot receive
        // another lease or callback authority from this admitted request.
        if token.uses_remaining == Some(0) {
            return Err(bad("token not found"));
        }
        let Some(TokenAuthProvenance::Sdk { origin }) = &token.auth_provenance else {
            return Err(denied());
        };
        let owner = origin
            .renewal
            .as_ref()
            .filter(|r| r.valid())
            .ok_or_else(|| bad("SDK token has no renewal issuer"))?;
        if !token.renewable || token.namespace != namespace {
            return Err(bad("lease is not renewable"));
        }
        self.sdk_auth_owner_gate(&origin.binding)?;
        let increment =
            token_precision::DurationNanos::from_seconds(duration(body, "increment", 0)?)
                .map_err(|_| bad("SDK renewal increment rejected"))?;
        let target = RenewalTarget {
            id: Zeroizing::new(id),
            raw: Zeroizing::new(if op == "renew-self" {
                raw.to_owned()
            } else if op == "renew" {
                string_field(body, "token")?.to_owned()
            } else {
                String::new()
            }),
            binding: origin.binding.clone(),
            path: owner.path.clone(),
            expected: fingerprint(token)?,
            original_expiry: origin.lease.expires_at.ok_or_else(denied)?,
            increment,
        };
        self.sdk_renewal_gate(&target, clock)?;
        Ok(target)
    }
    pub(crate) fn sdk_renewal_gate(
        &self,
        target: &RenewalTarget,
        clock: RequestClock,
    ) -> Result<(), AuthError> {
        let at = precise(self, clock)?;
        if at >= target.original_expiry {
            return Err(denied());
        }
        self.sdk_auth_owner_gate(&target.binding)?;
        let token =
            self.active_token_observed(target.id.as_str(), AuthorityTime::Precise(at), false)?;
        if fingerprint(token)? != target.expected {
            return Err(denied());
        }
        Ok(())
    }
    pub(crate) fn sdk_renewal_published(
        &self,
        target: &mut RenewalTarget,
    ) -> Result<(), AuthError> {
        let token = self.tokens.get(target.id.as_str()).ok_or_else(denied)?;
        // Called only after the actual candidate root was durably published.
        target.expected = fingerprint(token)?;
        Ok(())
    }
    pub(crate) fn finish_sdk_renewal(
        &mut self,
        target: &RenewalTarget,
        value: &Value,
        clock: RequestClock,
    ) -> Result<AuthResponse, AuthError> {
        self.sdk_renewal_gate(target, clock)?;
        let object = value
            .as_object()
            .ok_or_else(|| bad("SDK renewal requires Auth response"))?;
        for key in ["period", "explicit_max_ttl"] {
            if sdk_natural(object, key)? != 0 {
                return Err(err(501, "SDK periodic renewal is not implemented"));
            }
        }
        if object
            .get("bound_cidrs")
            .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
            || object
                .get("group_aliases")
                .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
        {
            return Err(err(501, "SDK renewal CIDR and groups are not implemented"));
        }
        let renewable = object
            .get("renewable")
            .and_then(Value::as_bool)
            .ok_or_else(|| bad("SDK renewal requires renewable bool"))?;
        let metadata =
            object
                .get("metadata")
                .filter(|v| !v.is_null())
                .map_or(Ok(BTreeMap::new()), |v| {
                    serde_json::from_value::<BTreeMap<String, String>>(v.clone())
                        .map_err(|_| bad("SDK renewal metadata rejected"))
                })?;
        let internal = object.get("internal_data").cloned().unwrap_or(Value::Null);
        if !crate::login_metadata::within_limit(&metadata)
            || serde_json::to_vec(&internal)
                .map_err(|_| bad("SDK renewal internal data rejected"))?
                .len()
                > 256 * 1024
        {
            return Err(err(413, "SDK renewal metadata exceeds bound"));
        }
        let at = precise(self, clock)?;
        let token = self.tokens.get(target.id.as_str()).ok_or_else(denied)?;
        let Some(TokenAuthProvenance::Sdk { origin }) = &token.auth_provenance else {
            return Err(denied());
        };
        let (_, mount_max) = self.auth_mount_lease_defaults(AuthScope {
            namespace: &target.binding.namespace,
            mount: &target.binding.mount,
        })?;
        let system_max = token_precision::DurationNanos::from_seconds(mount_max)
            .map_err(|_| bad("SDK maximum rejected"))?;
        let requested_max = sdk_natural(object, "max_ttl")?;
        let max = if requested_max == 0 {
            system_max
        } else {
            system_max.min(
                token_precision::DurationNanos::checked(requested_max)
                    .map_err(|_| bad("SDK maximum rejected"))?,
            )
        };
        let maximum = origin
            .lease
            .issued_at
            .checked_add(max)
            .map_err(|_| bad("SDK maximum overflow"))?
            .min(origin.maximum);
        let backend = token_precision::DurationNanos::checked(sdk_natural(object, "lease")?)
            .map_err(|_| bad("SDK renewal lease rejected"))?;
        let requested = if target.increment.is_zero() {
            backend
        } else {
            target.increment
        };
        let ttl = requested.min(
            maximum
                .elapsed(at)
                .map_err(|_| bad("lease expired maximum TTL"))?,
        );
        if ttl.is_zero() {
            return Err(bad("lease expired maximum TTL"));
        }
        let end = at
            .checked_add(ttl)
            .map_err(|_| bad("SDK renewal expiry overflow"))?;
        let mut token = token.clone();
        let Some(TokenAuthProvenance::Sdk { origin }) = &mut token.auth_provenance else {
            return Err(denied());
        };
        origin.lease.grant_started_at = at;
        origin.lease.expires_at = Some(end);
        origin.lease.last_renewed_at = Some(at);
        origin.lease.previous_grant = ttl;
        origin.maximum = maximum;
        origin.metadata = metadata.clone();
        erase_value(&mut origin.internal_data);
        origin.internal_data = internal;
        token.renewable = renewable;
        token.expires_at = Some(
            end.ceil_seconds()
                .map_err(|_| bad("SDK renewal projection rejected"))?,
        );
        token.max_expires_at = Some(
            maximum
                .ceil_seconds()
                .map_err(|_| bad("SDK maximum projection rejected"))?,
        );
        let body = json!({"auth":{"client_token":target.raw.as_str(),"accessor":token.accessor,"policies":token.policies,"token_policies":token.policies,
            "identity_policies":[],"entity_id":token.entity_id.as_deref().unwrap_or(""),"metadata":metadata,"lease_duration":ttl.public_seconds(),
            "renewable":renewable,"token_type":"service","orphan":token.parent.is_none(),"num_uses":token.uses_remaining.unwrap_or(0)}});
        self.observe_sdk_auth_clock(at);
        self.store_token(target.id.to_string(), token);
        Ok(AuthResponse {
            approle_secret_consumption: None,
            pending_batch: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body,
        })
    }
}
