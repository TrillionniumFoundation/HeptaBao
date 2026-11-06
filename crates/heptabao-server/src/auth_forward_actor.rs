use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForwardActorWitness {
    owner: LeaseOwner,
    namespace: String,
    accessor: Option<String>,
    entity_id: Option<String>,
    origin_peer: Option<std::net::IpAddr>,
}
impl Drop for ForwardActorWitness {
    fn drop(&mut self) {
        self.namespace.zeroize();
        self.accessor.zeroize();
        self.entity_id.zeroize();
    }
}
impl AuthState {
    // This projection is never a State, candidate, clock, or credential.
    // Only the monotonic observation field is omitted from the owner hash.
    pub(crate) fn forward_owner_projection_digest(&self) -> Result<[u8; 32], AuthError> {
        let mut view = self.clone();
        view.token_api_observed_at = None;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&view)
                .map_err(|_| err(500, "forwarding owner projection is unavailable"))?,
        );
        Ok(crate::ha_forward_completion::digest(&bytes))
    }

    pub(super) fn capture_forward_actor(&self, actor: &Principal, namespace: &str) {
        if !crate::ha_forward_completion::CompletionScope::active() {
            return;
        }
        let (owner, accessor, entity_id) = match &actor.credential {
            batch_principal::VerifiedCredential::Service(snapshot) => {
                let Ok(owner) = LeaseOwner::service(&actor.digest) else {
                    return;
                };
                (
                    owner,
                    Some(snapshot.accessor.clone()),
                    snapshot.entity_id.clone(),
                )
            }
            batch_principal::VerifiedCredential::Batch(claims) => (
                LeaseOwner::from_batch(claims),
                None,
                claims.entity_id().map(str::to_owned),
            ),
        };
        crate::ha_forward_completion::actor(ForwardActorWitness {
            owner,
            namespace: namespace.to_owned(),
            accessor,
            entity_id,
            origin_peer: actor.origin_peer,
        });
    }
    pub(crate) fn validate_forward_actor(
        &self,
        actor: &ForwardActorWitness,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let time = self.token_api_observed_time(time);
        if let Some(digest) = actor.owner.service_digest() {
            // Peer proof attests the original admitted view. A spent final use
            // remains usable by this delivery only; no new Principal is issued.
            let token = self.active_token_observed(digest, time, false)?;
            if actor.accessor.as_deref() != Some(token.accessor.as_str())
                || actor.entity_id != token.entity_id
                || !token.root && token.namespace != actor.namespace
            {
                return Err(denied());
            }
            token_cidrs::check(&token.bound_cidrs, actor.origin_peer)?;
        } else {
            if self
                .resolve_lease_owner_observed(&actor.owner, &actor.namespace, time)
                .is_none()
            {
                return Err(denied());
            }
        }
        Ok(())
    }
}

#[cfg(feature = "native-v6-ha")]
impl AuthState {
    /// Bind the already admitted root Principal. This does not authenticate,
    /// issue a Principal, consume a use, or read restored credentials.
    pub(crate) fn snapshot_forward_actor(
        &self,
        actor: &Principal,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<ForwardActorWitness, AuthError> {
        if !namespace.is_empty() || !actor.is_root() {
            return Err(denied());
        }
        let batch_principal::VerifiedCredential::Service(snapshot) = &actor.credential else {
            return Err(denied());
        };
        let witness = ForwardActorWitness {
            owner: LeaseOwner::service(&actor.digest).map_err(|_| denied())?,
            namespace: namespace.to_owned(),
            accessor: Some(snapshot.accessor.clone()),
            entity_id: snapshot.entity_id.clone(),
            origin_peer: actor.origin_peer,
        };
        self.validate_snapshot_forward_actor(&witness, time)?;
        Ok(witness)
    }

    /// Delivery-only validation against the actual retained original Auth view.
    /// A finite final use remains a delivery witness, never a new admission.
    pub(crate) fn validate_snapshot_forward_actor(
        &self,
        actor: &ForwardActorWitness,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        if !actor.namespace.is_empty() {
            return Err(denied());
        }
        let digest = actor.owner.service_digest().ok_or_else(denied)?;
        let token =
            self.active_token_observed(digest, self.token_api_observed_time(time), false)?;
        if !token.root {
            return Err(denied());
        }
        self.validate_forward_actor(actor, time)
    }
}

#[cfg(all(test, feature = "native-v6-ha"))]
#[path = "auth_snapshot_forward_actor_tests.rs"]
mod snapshot_tests;
