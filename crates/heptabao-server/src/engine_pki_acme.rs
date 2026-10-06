//! Public protocol dispatch uses the actual built-in PKI mount. These public
//! account proofs never become a Vault Principal or an SDK catalog authority.
use super::*;
use crate::auth::Timestamp;
pub(crate) use pki::acme_jws::{Jwk as AcmeJwk, ParsedJws as AcmeParsedJws};
pub(crate) use pki::acme_state::Binding as AcmeBinding;
use pki::acme_state::{Account, AccountStatus, Protocol};

pub(crate) struct AcmeView {
    pub owner: AcmeBinding,
    pub directory: String,
    pub endpoint: String,
    pub base: String,
    pub enabled: bool,
    pub eab_required: bool,
    pub eab_policy: String,
    pub revision: u64,
    pub headers: Vec<String>,
    pub fingerprint: [u8; 32],
}

fn acme_parts(relative: &str) -> Option<(&str, &str)> {
    let split = relative.find("acme/")?;
    let prefix = &relative[..split];
    let parts: Vec<_> = prefix.trim_end_matches('/').split('/').collect();
    if !prefix.is_empty()
        && !matches!(
            parts.as_slice(),
            ["roles", _] | ["issuer", _] | ["issuer", _, "roles", _]
        )
    {
        return None;
    }
    let index = split + "acme/".len();
    Some((&relative[..index], &relative[index..]))
}

impl EngineState {
    pub(crate) fn has_pki_acme_state(&self) -> bool {
        self.acme_clock.is_some()
    }

    pub(crate) fn acme_view(
        &self,
        namespace: &str,
        path: &str,
        cluster: &str,
        namespace_incarnation: Option<u64>,
    ) -> Result<Option<AcmeView>> {
        let Some(state) = self.namespaces.get(namespace) else {
            return Ok(None);
        };
        let Some((mount_path, mount)) = state
            .mounts
            .iter()
            .filter(|(p, _)| path.starts_with(p.as_str()))
            .max_by_key(|(p, _)| p.len())
        else {
            return Ok(None);
        };
        let Backend::Pki(engine) = &mount.backend else {
            return Ok(None);
        };
        let relative = &path[mount_path.len()..];
        let parts = if relative == "eab" || relative.starts_with("eab/") {
            Some(("acme/", relative))
        } else {
            acme_parts(relative)
        };
        let Some((directory, endpoint)) = parts else {
            return Ok(None);
        };
        let owner = AcmeBinding {
            cluster_id: cluster.to_owned(),
            namespace: namespace.to_owned(),
            namespace_incarnation,
            mount: mount_path.clone(),
            mount_incarnation: mount.incarnation,
        };
        owner.validate()?;
        // Configuration is copied as public routing metadata, never an actor.
        let encoded =
            crate::secret_serde::to_vec(engine.as_ref(), crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| error(503, "ACME routing state exceeds bounds"))?;
        Ok(Some(AcmeView {
            owner,
            directory: directory.to_owned(),
            endpoint: endpoint.to_owned(),
            base: format!("{}/{directory}", engine.cluster_path.trim_end_matches('/')),
            enabled: engine.acme.enabled,
            eab_required: engine.acme.eab_policy != "not-required",
            eab_policy: engine.acme.eab_policy.clone(),
            revision: mount.revision,
            headers: engine
                .acme_protocol
                .as_ref()
                .map_or_else(Vec::new, |p| p.allowed_response_headers.clone()),
            fingerprint: crate::crypto::digest(&encoded),
        }))
    }

    fn acme_pki(&self, owner: &AcmeBinding) -> Result<&pki::Pki> {
        let mount = self
            .namespaces
            .get(&owner.namespace)
            .and_then(|n| n.mounts.get(&owner.mount))
            .ok_or_else(|| error(503, "ACME mount owner is unavailable"))?;
        match &mount.backend {
            Backend::Pki(pki) if mount.incarnation == owner.mount_incarnation => Ok(pki),
            _ => Err(error(503, "ACME mount incarnation changed")),
        }
    }
    fn acme_pki_mut(&mut self, owner: &AcmeBinding) -> Result<&mut pki::Pki> {
        let mount = self
            .namespaces
            .get_mut(&owner.namespace)
            .and_then(|n| n.mounts.get_mut(&owner.mount))
            .ok_or_else(|| error(503, "ACME mount owner is unavailable"))?;
        let incarnation = mount.incarnation;
        match &mut mount.backend {
            Backend::Pki(pki) if incarnation == owner.mount_incarnation => Ok(pki),
            _ => Err(error(503, "ACME mount incarnation changed")),
        }
    }
    pub(crate) fn acme_directory_gate(&self, view: &AcmeView) -> Result<()> {
        let pki = self.acme_pki(&view.owner)?;
        if !pki.acme.enabled {
            return Err(error(404, "ACME is disabled"));
        }
        if pki.cluster_path.is_empty() {
            return Err(error(500, "ACME cluster path is unavailable"));
        }
        let prefix = view
            .directory
            .trim_end_matches("acme/")
            .trim_end_matches('/');
        pki.acme_directory_issuer(prefix)?;
        Ok(())
    }
    pub(crate) fn acme_observe_publication(&mut self, at: Timestamp) -> Result<()> {
        if self.has_pki_acme_state() {
            self.observe_acme(at)?;
        }
        Ok(())
    }
    pub(crate) fn acme_observed_time(&self, at: Timestamp) -> Timestamp {
        self.acme_clock.map_or(at, |floor| at.max(floor))
    }
    fn observe_acme(&mut self, at: Timestamp) -> Result<Timestamp> {
        let at = self.acme_clock.map_or(at, |floor| at.max(floor));
        self.acme_clock = Some(at);
        self.acme_revision = self
            .acme_revision
            .checked_add(1)
            .ok_or_else(|| error(507, "ACME durable frontier exhausted"))?;
        Ok(at)
    }
    pub(crate) fn acme_activate_nonce_owner(
        &mut self,
        owner: &AcmeBinding,
        at: Timestamp,
    ) -> Result<Timestamp> {
        let at = self.observe_acme(at)?;
        let pki = self.acme_pki_mut(owner)?;
        if pki.acme_protocol.is_none() {
            pki.acme_protocol = Some(Box::new(Protocol::new(owner.clone(), at)?));
        }
        let protocol = pki
            .acme_protocol
            .as_mut()
            .ok_or_else(|| error(503, "ACME nonce owner unavailable"))?;
        if protocol.owner != *owner {
            return Err(error(503, "ACME durable owner changed"));
        }
        protocol.observe_time(at);
        protocol.nonce_issue_count = protocol
            .nonce_issue_count
            .checked_add(1)
            .ok_or_else(|| error(507, "ACME nonce issuance exhausted"))?;
        Ok(at)
    }
    pub(crate) fn acme_activate_config(
        &mut self,
        namespace: &str,
        path: &str,
        cluster: &str,
        incarnation: Option<u64>,
        at: Timestamp,
    ) -> Result<()> {
        let Some(prefix) = path.strip_suffix("config/acme") else {
            return Ok(());
        };
        let Some(view) = self.acme_view(
            namespace,
            &format!("{prefix}acme/new-nonce"),
            cluster,
            incarnation,
        )?
        else {
            return Ok(());
        };
        if !view.enabled {
            return Ok(());
        }
        let at = self.observe_acme(at)?;
        let pki = self.acme_pki_mut(&view.owner)?;
        if pki.acme_protocol.is_none() {
            pki.acme_protocol = Some(Box::new(Protocol::new(view.owner.clone(), at)?));
        }
        let protocol = pki
            .acme_protocol
            .as_mut()
            .ok_or_else(|| error(503, "ACME account owner unavailable"))?;
        if protocol.owner != view.owner {
            return Err(error(503, "ACME durable owner changed"));
        }
        protocol.observe_time(at);
        Ok(())
    }
    pub(crate) fn acme_account_key(&self, view: &AcmeView, kid: &str) -> Result<AcmeJwk> {
        // The official loader extracts the final public UUID from kid. A
        // different URL prefix grants no capability: the same directory-owned
        // stored JWK must still verify the complete request and its exact URL.
        let id = kid
            .rsplit('/')
            .next()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| error(400, "an account with this key does not exist: the request specified an account that does not exist"))?;
        let account = self
            .acme_pki(&view.owner)?
            .acme_protocol
            .as_ref()
            .and_then(|p| p.by_id(id, &view.directory))
            .ok_or_else(|| error(400, "an account with this key does not exist: the request specified an account that does not exist"))?;
        if account.status != AccountStatus::Valid {
            return Err(error(401, "the client lacks sufficient authorization"));
        }
        if view.eab_policy == "always-required" && account.eab.is_none() {
            return Err(error(401, pki::acme_eab::REQUIRED));
        }
        Ok(account.jwk.clone())
    }
    pub(crate) fn acme_account_request(
        &mut self,
        view: &AcmeView,
        key: AcmeJwk,
        proof: &pki::acme_jws::VerifiedJws,
        kid: Option<&str>,
        at: Timestamp,
    ) -> Result<(u16, Value, String)> {
        let thumbprint = proof.key_thumbprint();
        if key.thumbprint()? != thumbprint {
            return Err(error(401, "ACME verified account key changed"));
        }
        let payload = proof.payload();
        let at = self.observe_acme(at)?;
        let pki = self.acme_pki_mut(&view.owner)?;
        let protocol = pki
            .acme_protocol
            .as_mut()
            .ok_or_else(|| error(503, "ACME nonce owner unavailable"))?;
        protocol.observe_time(at);
        let empty = json!({});
        let payload = payload.unwrap_or(&empty);
        let flag = |name: &str| -> Result<bool> {
            payload
                .get(name)
                .map(|v| {
                    v.as_bool()
                        .ok_or_else(|| bad("invalid ACME account boolean field"))
                })
                .transpose()
                .map(|v| v.unwrap_or(false))
        };
        let submitted_eab = match payload.get("externalAccountBinding") {
            None => None,
            Some(Value::Object(map)) if map.is_empty() => None,
            Some(value @ Value::Object(_)) => Some(value),
            Some(_) => {
                return Err(bad(
                    "the request message was malformed: externalAccountBinding field was unparseable",
                ));
            }
        };
        let only_existing = flag("onlyReturnExisting")?;
        let terms = flag("termsOfServiceAgreed")?;
        let contact = match payload.get("contact") {
            None => Vec::new(),
            Some(Value::Array(values)) if values.len() <= 64 => values
                .iter()
                .map(|v| {
                    v.as_str()
                        .filter(|s| s.len() <= 2048 && !s.chars().any(char::is_control))
                        .map(str::to_owned)
                        .ok_or_else(|| bad("invalid ACME account contact"))
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(bad("invalid ACME account contact")),
        };
        let new = view.endpoint == "new-account";
        if new && kid.is_some() {
            return Err(bad("cannot submit to newAccount with kid"));
        }
        if !new && kid.is_none() {
            return Err(bad("ACME account update requires kid"));
        }
        if only_existing || new {
            if let Some(account) = protocol.by_thumbprint(thumbprint, &view.directory) {
                if view.eab_policy == "always-required" && account.eab.is_none() {
                    return Err(error(401, pki::acme_eab::REQUIRED));
                }
                return Ok((
                    200,
                    account.descriptor(&view.base),
                    format!("{}account/{}", view.base, account.id),
                ));
            }
            if only_existing {
                return Err(error(
                    400,
                    "an account with this key does not exist: the request specified an account that does not exist",
                ));
            }
            let eab = match submitted_eab {
                Some(binding) => Some(
                    protocol.verify_eab(
                        &view.directory,
                        &format!("{}new-account", view.base),
                        proof
                            .raw_embedded_jwk()
                            .ok_or_else(|| bad("missing signed account jwk"))?,
                        binding,
                    )?,
                ),
                None if view.eab_required => return Err(error(401, pki::acme_eab::REQUIRED)),
                None => None,
            };
            let bytes = crate::crypto::random::<16>()
                .map_err(|_| error(503, "ACME account identifier generation unavailable"))?;
            let id = crate::crypto::uuid_from_bytes(&bytes);
            let account = Account {
                id: id.clone(),
                directory: view.directory.clone(),
                status: AccountStatus::Valid,
                jwk: key,
                thumbprint: thumbprint.to_owned(),
                contact,
                terms_of_service_agreed: terms,
                created: at,
                deactivated: None,
                eab,
            };
            let mut descriptor = account.descriptor(&view.base);
            if let Some(eab) = &account.eab {
                descriptor["externalAccountBinding"] = eab.proof.0.clone();
            }
            let binding_id = account.eab.as_ref().map(|eab| eab.id.clone());
            protocol.insert_account(account)?;
            if let Some(binding_id) = binding_id {
                protocol
                    .eab_keys
                    .get_mut(&binding_id)
                    .ok_or_else(|| error(503, "EAB consumed key history unavailable"))?
                    .retire(at, Some(&id));
                protocol.validate_eab()?;
            }
            return Ok((201, descriptor, format!("{}account/{id}", view.base)));
        }
        if submitted_eab.is_some() {
            return Err(bad(
                "the request message was malformed: not allowed to update EAB data in accounts",
            ));
        }
        let id = kid
            .and_then(|kid| kid.rsplit('/').next())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| bad("invalid ACME account key identifier"))?;
        // Account update follows the verified kid, including public route aliases,
        // exactly as the 2.7 handler. This never selects an unverified account.
        let account = protocol
            .accounts
            .get_mut(id)
            .filter(|a| {
                a.directory == view.directory
                    && a.thumbprint == thumbprint
                    && a.status == AccountStatus::Valid
            })
            .ok_or_else(|| error(401, "the client lacks sufficient authorization"))?;
        let status = payload
            .get("status")
            .map(|v| v.as_str().ok_or_else(|| bad("invalid ACME account status")))
            .transpose()?;
        if status == Some("deactivated") {
            account.status = AccountStatus::Deactivated;
            account.deactivated = Some(at);
        } else {
            account.contact = contact;
        }
        Ok((
            200,
            account.descriptor(&view.base),
            format!("{}account/{id}", view.base),
        ))
    }
    pub(crate) fn acme_order_request(
        &mut self,
        view: &AcmeView,
        proof: &pki::acme_jws::VerifiedJws,
        kid: Option<&str>,
        at: Timestamp,
        clock: Option<crate::auth::RequestClock>,
    ) -> Result<(u16, Value, Option<String>)> {
        let id = kid
            .and_then(|kid| kid.rsplit('/').next())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| bad("ACME order operation requires kid"))?;
        let key = self.acme_account_key(
            view,
            kid.ok_or_else(|| bad("ACME order operation requires kid"))?,
        )?;
        if key.thumbprint()? != proof.key_thumbprint() {
            return Err(error(401, "the client lacks sufficient authorization"));
        }
        let empty = json!({});
        let payload = proof.payload().unwrap_or(&empty);
        let identifiers = if view.endpoint == "new-order" {
            let identifiers = pki::acme_orders::parse_identifiers(payload)?;
            self.acme_pki(&view.owner)?
                .acme_validate_order_names(&view.directory, &identifiers)?;
            Some(identifiers)
        } else {
            None
        };
        if let Some((order_id, action)) = view
            .endpoint
            .strip_prefix("order/")
            .and_then(|rest| rest.split_once('/'))
        {
            let raw = if action == "finalize" {
                Some(pki::acme_certificate::parse_payload(payload)?)
            } else {
                None
            };
            let mounted = self.acme_pki(&view.owner)?;
            let protocol = mounted
                .acme_protocol
                .as_ref()
                .ok_or_else(|| error(503, "ACME order owner unavailable"))?;
            let order = protocol
                .orders
                .get(order_id)
                .filter(|o| o.account == id && o.directory == view.directory)
                .ok_or_else(|| bad("order does not exist: the request message was malformed"))?
                .clone();
            let status = order.status(protocol, at);
            if action == "cert" {
                if status != "valid" {
                    return Err(pki::acme_certificate::order_not_ready(status, "valid"));
                }
                let cert = order
                    .certificate
                    .as_ref()
                    .ok_or_else(|| error(503, "ACME completed certificate unavailable"))?;
                return Ok((
                    200,
                    Value::String(mounted.acme_certificate_chain(cert)?),
                    None,
                ));
            }
            if action != "finalize" {
                return Err(bad("invalid ACME order route"));
            }
            if status != "ready" {
                return Err(pki::acme_certificate::order_not_ready(status, "ready"));
            }
            let certificate = mounted.acme_finalize_local(
                &order,
                raw.as_ref().ok_or_else(|| bad("missing csr in payload"))?,
                at,
                clock,
            )?;
            // Observe the same accepted ingress clock after the actual signature;
            // a long signing operation cannot revive an expired authorization.
            let end = clock
                .map(|c| c.with_timestamp_floor(at).observed_at())
                .transpose()
                .map_err(|_| error(503, "ACME original signing clock unavailable"))?
                .unwrap_or(at);
            let end = self.observe_acme(end)?;
            let mounted = self.acme_pki_mut(&view.owner)?;
            let protocol = mounted
                .acme_protocol
                .as_mut()
                .ok_or_else(|| error(503, "ACME order owner unavailable"))?;
            protocol.observe_time(end);
            if order.status(protocol, end) != "ready"
                || !protocol.accounts.get(id).is_some_and(|a| {
                    a.status == AccountStatus::Valid && a.thumbprint == order.account_thumbprint
                })
            {
                return Err(error(403, "the client lacks sufficient authorization"));
            }
            let current = protocol
                .orders
                .get_mut(order_id)
                .filter(|o| **o == order)
                .ok_or_else(|| {
                    error(
                        503,
                        "ACME order owner changed before certificate publication",
                    )
                })?;
            current.certificate = Some(certificate);
            protocol.validate()?;
            let order = protocol
                .orders
                .get(order_id)
                .ok_or_else(|| error(503, "ACME completed order unavailable"))?;
            return Ok((
                200,
                order.descriptor(protocol, &view.base, end),
                Some(format!("{}order/{order_id}", view.base)),
            ));
        }
        let at = self.observe_acme(at)?;
        let protocol = self
            .acme_pki_mut(&view.owner)?
            .acme_protocol
            .as_mut()
            .ok_or_else(|| error(503, "ACME order owner unavailable"))?;
        protocol.observe_time(at);
        if let Some(identifiers) = identifiers {
            let order_id = protocol.insert_order(id, &view.directory, identifiers, at)?;
            let order = protocol
                .orders
                .get(&order_id)
                .ok_or_else(|| error(503, "ACME inserted order unavailable"))?;
            return Ok((
                201,
                order.descriptor(protocol, &view.base, at),
                Some(format!("{}order/{order_id}", view.base)),
            ));
        }
        if view.endpoint == "orders" {
            // Native list uses stored state; a computed invalid GET is not saved.
            let orders: Vec<_> = protocol
                .orders
                .values()
                .filter(|order| order.account == id && order.directory == view.directory)
                .map(|order| format!("{}order/{}", view.base, order.id))
                .collect();
            return Ok((200, json!({"orders":orders}), None));
        }
        if let Some(order_id) = view.endpoint.strip_prefix("order/") {
            let order = protocol
                .orders
                .get(order_id)
                .filter(|order| order.account == id && order.directory == view.directory)
                .ok_or_else(|| bad("order does not exist: the request message was malformed"))?;
            return Ok((
                200,
                order.descriptor(protocol, &view.base, at),
                Some(format!("{}order/{order_id}", view.base)),
            ));
        }
        if let Some(auth_id) = view.endpoint.strip_prefix("authorization/") {
            let auth = protocol
                .authorizations
                .get_mut(auth_id)
                .filter(|auth| auth.account == id && auth.directory == view.directory)
                .ok_or_else(|| {
                    error(
                        500,
                        "failed to load authorization: authorization does not exist",
                    )
                })?;
            if !payload.as_object().is_some_and(|object| object.is_empty()) {
                let status = payload.get("status");
                if let Some(status) = status
                    && !status.is_string()
                {
                    return Err(bad(&format!(
                        "bad type ({}) for value 'status': the request message was malformed",
                        pki::acme_orders::go_type(status)
                    )));
                }
                if status.and_then(Value::as_str) != Some("deactivated") {
                    return Err(bad("the request message was malformed"));
                }
                if !matches!(
                    auth.status,
                    pki::acme_orders::AuthorizationStatus::Pending
                        | pki::acme_orders::AuthorizationStatus::Valid
                ) {
                    return Err(bad(
                        "unable to deactivate authorization in 'deactivated' status: the request message was malformed",
                    ));
                }
                auth.status = pki::acme_orders::AuthorizationStatus::Deactivated;
                auth.deactivated = Some(at);
                for challenge in &mut auth.challenges {
                    challenge.status = pki::acme_orders::ChallengeStatus::Invalid;
                }
            }
            return Ok((200, auth.descriptor(&view.base), None));
        }
        if let Some(rest) = view.endpoint.strip_prefix("challenge/") {
            let (auth_id, kind) = rest
                .split_once('/')
                .ok_or_else(|| bad("invalid ACME challenge route"))?;
            let auth = protocol
                .authorizations
                .get_mut(auth_id)
                .filter(|a| a.account == id && a.directory == view.directory)
                .ok_or_else(|| {
                    error(
                        500,
                        "failed to load authorization: authorization does not exist",
                    )
                })?;
            let index = auth.challenges.iter().position(|c|c.kind==kind).ok_or_else(||bad(&format!("unknown challenge of type '{kind}' in authorization: the request message was malformed")))?;
            if let Some(payload) = proof.payload() {
                if !payload.as_object().is_some_and(|o| o.is_empty()) {
                    return Err(bad(
                        "unexpected request parameters: the request message was malformed",
                    ));
                }
                let challenge = &auth.challenges[index];
                if challenge.status != pki::acme_orders::ChallengeStatus::Processing {
                    if auth.status != pki::acme_orders::AuthorizationStatus::Pending {
                        let status = match auth.status {
                            pki::acme_orders::AuthorizationStatus::Valid => "valid",
                            pki::acme_orders::AuthorizationStatus::Deactivated => "deactivated",
                            _ => "invalid",
                        };
                        return Err(bad(&format!(
                            "error submitting challenge for validation: the request message was malformed: cannot accept already validated authorization {auth_id} ({status})"
                        )));
                    }
                    if auth.challenges.iter().enumerate().any(|(i, c)| {
                        i != index && c.status != pki::acme_orders::ChallengeStatus::Pending
                    }) {
                        return Err(bad(
                            "error submitting challenge for validation: only a single challenge within an authorization can be accepted: the request message was malformed",
                        ));
                    }
                    if !matches!(kind, "http-01" | "dns-01" | "tls-alpn-01") {
                        return Err(error(
                            501,
                            "ACME TLSALPN01 network verification is not implemented",
                        ));
                    }
                    let challenge = &mut auth.challenges[index];
                    challenge.status = pki::acme_orders::ChallengeStatus::Processing;
                    challenge.validation = Some(pki::acme_orders::Validation {
                        initiated: at,
                        retry_after: at,
                        retry_count: 0,
                        error: None,
                    });
                }
            }
            return Ok((
                200,
                auth.challenges[index].descriptor(&view.base, auth_id),
                None,
            ));
        }
        Err(error(
            501,
            "ACME challenge and certificate operation is not implemented",
        ))
    }
    pub(crate) fn has_pending_acme_challenges(&self) -> bool {
        self.namespaces.values().any(|n|n.mounts.values().any(|m|matches!(&m.backend,Backend::Pki(p) if p.acme_protocol.as_ref().is_some_and(|s|s.authorizations.values().any(|a|a.challenges.iter().any(|c|c.status==pki::acme_orders::ChallengeStatus::Processing))))))
    }
    pub(crate) fn next_acme_challenge(
        &self,
        at: Timestamp,
    ) -> Option<crate::service::QueuedChallenge> {
        for n in self.namespaces.values() {
            for m in n.mounts.values() {
                let Backend::Pki(p) = &m.backend else {
                    continue;
                };
                let Some(protocol) = &p.acme_protocol else {
                    continue;
                };
                if !p.acme.enabled {
                    continue;
                }
                for a in protocol.authorizations.values() {
                    if a.status != pki::acme_orders::AuthorizationStatus::Pending
                        || !protocol
                            .accounts
                            .get(&a.account)
                            .is_some_and(|v| v.status == AccountStatus::Valid)
                    {
                        continue;
                    }
                    for c in &a.challenges {
                        if c.status == pki::acme_orders::ChallengeStatus::Processing
                            && c.validation.as_ref().is_some_and(|v| v.retry_after <= at)
                        {
                            return Some(crate::service::QueuedChallenge {
                                owner: a.owner.clone(),
                                account: a.account.clone(),
                                thumbprint: a.account_thumbprint.clone(),
                                directory: a.directory.clone(),
                                authorization: a.id.clone(),
                                host: a.identifier.value.clone(),
                                challenge: c.clone(),
                                mount_revision: m.revision,
                                dns_resolver: p.acme.dns_resolver.clone(),
                            });
                        }
                    }
                }
            }
        }
        None
    }
    pub(crate) fn check_acme_challenge_state(
        &self,
        queued: &crate::service::QueuedChallenge,
        original: bool,
    ) -> Result<()> {
        let p = self.acme_pki(&queued.owner)?;
        let protocol = p
            .acme_protocol
            .as_ref()
            .ok_or_else(|| error(503, "ACME queued protocol owner unavailable"))?;
        let a = protocol
            .authorizations
            .get(&queued.authorization)
            .ok_or_else(|| error(503, "ACME queued authorization unavailable"))?;
        if !p.acme.enabled
            || p.acme.dns_resolver != queued.dns_resolver
            || a.owner != queued.owner
            || a.account != queued.account
            || a.account_thumbprint != queued.thumbprint
            || a.directory != queued.directory
            || a.identifier.value != queued.host
            || (original && a.status != pki::acme_orders::AuthorizationStatus::Pending)
            || !a.challenges.iter().any(|c| {
                c.kind == queued.challenge.kind
                    && c.token == queued.challenge.token
                    && if original {
                        c == &queued.challenge
                    } else {
                        c.validation
                            .as_ref()
                            .zip(queued.challenge.validation.as_ref())
                            .is_some_and(|(next, old)| next.initiated == old.initiated)
                    }
            })
            || !protocol.accounts.get(&a.account).is_some_and(|account| {
                account.status == AccountStatus::Valid
                    && account.thumbprint == queued.thumbprint
                    && account.directory == queued.directory
            })
        {
            return Err(error(503, "ACME queued account or challenge owner changed"));
        }
        Ok(())
    }
    pub(crate) fn finish_acme_challenge(
        &mut self,
        queued: &crate::service::QueuedChallenge,
        result: std::result::Result<(), String>,
        at: Timestamp,
        validation_started: Timestamp,
    ) -> Result<()> {
        self.check_acme_challenge_state(queued, true)?;
        let at = self.observe_acme(at)?;
        let protocol = self
            .acme_pki_mut(&queued.owner)?
            .acme_protocol
            .as_mut()
            .ok_or_else(|| error(503, "ACME queued protocol unavailable"))?;
        protocol.observe_time(at);
        let a = protocol
            .authorizations
            .get_mut(&queued.authorization)
            .ok_or_else(|| error(503, "ACME queued authorization unavailable"))?;
        let c = a
            .challenges
            .iter_mut()
            .find(|c| c.kind == queued.challenge.kind)
            .ok_or_else(|| error(503, "ACME queued challenge unavailable"))?;
        if let Err(detail) = result {
            let v = c
                .validation
                .as_mut()
                .ok_or_else(|| error(503, "ACME validation owner unavailable"))?;
            v.error = Some(detail);
            if v.retry_count > 5 {
                c.status = pki::acme_orders::ChallengeStatus::Invalid;
                a.status = pki::acme_orders::AuthorizationStatus::Invalid;
                for c in &mut a.challenges {
                    c.status = pki::acme_orders::ChallengeStatus::Invalid;
                }
            } else {
                v.retry_count += 1;
                v.retry_after = Timestamp::checked(
                    at.seconds()
                        .checked_add(u64::from(v.retry_count) * 5)
                        .ok_or_else(|| error(503, "ACME retry expiry overflow"))?,
                    at.duration_since_epoch().subsec_nanos(),
                )
                .map_err(|_| error(503, "ACME retry expiry overflow"))?;
            }
        } else {
            let at = validation_started;
            let expires = Timestamp::checked(
                at.seconds()
                    .checked_add(15 * 86400)
                    .ok_or_else(|| error(503, "ACME validated expiry overflow"))?,
                at.duration_since_epoch().subsec_nanos(),
            )
            .map_err(|_| error(503, "ACME validated expiry overflow"))?;
            c.validated = Some(pki::acme_orders::Validated {
                at,
                expires,
                public_at: at
                    .truncate_seconds()
                    .local_rfc3339()
                    .map_err(|_| error(503, "ACME validated time unavailable"))?,
                public_expires: expires
                    .truncate_seconds()
                    .local_rfc3339()
                    .map_err(|_| error(503, "ACME validated expiry unavailable"))?,
            });
            if let Some(v) = c.validation.as_mut() {
                v.error = None;
            }
            c.status = pki::acme_orders::ChallengeStatus::Valid;
            a.status = pki::acme_orders::AuthorizationStatus::Valid;
        }
        Ok(())
    }
    pub(crate) fn validate_acme_state(
        &self,
        cluster: &str,
        namespace_incarnation: impl Fn(&str) -> Option<u64>,
    ) -> Result<()> {
        if self.acme_clock.is_some() != (self.acme_revision != 0) {
            return Err(error(503, "ACME durable frontier is invalid"));
        }
        for (namespace, state) in &self.namespaces {
            for (path, mount) in &state.mounts {
                if let Backend::Pki(pki) = &mount.backend
                    && let Some(protocol) = &pki.acme_protocol
                {
                    protocol.validate()?;
                    if protocol.owner.cluster_id != cluster
                        || protocol.owner.namespace != *namespace
                        || protocol.owner.namespace_incarnation != namespace_incarnation(namespace)
                        || protocol.owner.mount != *path
                        || protocol.owner.mount_incarnation != mount.incarnation
                        || self.acme_clock.is_none_or(|floor| floor < protocol.clock)
                    {
                        return Err(error(503, "ACME actual namespace and mount owner rejected"));
                    }
                }
            }
        }
        Ok(())
    }
    pub(crate) fn validate_acme_successor(
        &self,
        previous: Option<&Self>,
        namespace_retired: impl Fn(&str) -> bool,
    ) -> Result<()> {
        if let Some(old) = previous {
            if old
                .acme_clock
                .is_some_and(|floor| self.acme_clock.is_none_or(|at| at < floor))
                || self.acme_revision < old.acme_revision
            {
                return Err(error(503, "ACME durable frontier cannot regress"));
            }
            if old.has_pki_acme_state() {
                for (namespace, before) in &old.namespaces {
                    // Only the typed namespace catalog can retire an old path
                    // incarnation. Absence in EngineState alone is insufficient.
                    if namespace_retired(namespace) {
                        continue;
                    }
                    let after = self
                        .namespaces
                        .get(namespace)
                        .ok_or_else(|| error(503, "ACME namespace lifecycle cannot regress"))?;
                    for (mount, epoch) in &before.mount_epochs {
                        if after.mount_epochs.get(mount).is_none_or(|v| v < epoch) {
                            return Err(error(
                                503,
                                "ACME mount retirement frontier cannot regress",
                            ));
                        }
                    }
                    for (path, mounted) in &before.mounts {
                        let Backend::Pki(pki) = &mounted.backend else {
                            continue;
                        };
                        let Some(protocol) = &pki.acme_protocol else {
                            continue;
                        };
                        let incoming = after
                            .mounts
                            .get(path)
                            .filter(|m| m.incarnation == mounted.incarnation);
                        if let Some(mounted) = incoming {
                            let Backend::Pki(pki) = &mounted.backend else {
                                return Err(error(503, "ACME mount backend changed"));
                            };
                            let p = pki
                                .acme_protocol
                                .as_ref()
                                .ok_or_else(|| error(503, "ACME durable owner was lost"))?;
                            if p.owner != protocol.owner
                                || p.nonce_issue_count < protocol.nonce_issue_count
                                || p.clock < protocol.clock
                                || p.response_config_revision < protocol.response_config_revision
                            {
                                return Err(error(503, "ACME mount protocol frontier regressed"));
                            }
                            p.validate_order_successor(protocol)?;
                            p.validate_eab_successor(protocol)?;
                            for (id, account) in &protocol.accounts {
                                let next = p.accounts.get(id).ok_or_else(|| {
                                    error(503, "ACME account retirement cannot disappear")
                                })?;
                                if next.jwk != account.jwk
                                    || next.created != account.created
                                    || next.directory != account.directory
                                    || account.status != AccountStatus::Valid
                                        && next.status != account.status
                                {
                                    return Err(error(
                                        503,
                                        "ACME account owner or deactivation regressed",
                                    ));
                                }
                            }
                        } else if after
                            .mount_epochs
                            .get(path)
                            .is_none_or(|epoch| *epoch <= mounted.incarnation)
                        {
                            return Err(error(503, "ACME mount retirement is unproven"));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl pki::Pki {
    fn acme_validate_order_names(
        &self,
        directory: &str,
        identifiers: &[pki::acme_orders::Identifier],
    ) -> Result<()> {
        let prefix = directory.trim_end_matches("acme/").trim_end_matches('/');
        let parts: Vec<_> = prefix.split('/').collect();
        let explicit_role = match parts.as_slice() {
            ["roles", role] | ["issuer", _, "roles", role] => Some(*role),
            _ => None,
        };
        let name =
            explicit_role.or_else(|| self.acme.default_directory_policy.strip_prefix("role:"));
        let Some(name) = name else {
            return Ok(());
        };
        let role = self
            .roles
            .get(name)
            .ok_or_else(|| bad("the request message was malformed: role does not exist"))?;
        for identifier in identifiers {
            let allowed = match identifier.kind {
                pki::acme_orders::IdentifierType::Dns => {
                    role.role_name_policy.as_ref().map_or_else(
                        || role.allows(&identifier.original),
                        |policy| policy.allows_name(role, &identifier.original),
                    )
                }
                pki::acme_orders::IdentifierType::Ip => role.allow_ip_sans,
            };
            if !allowed {
                let detail = match identifier.kind {
                    pki::acme_orders::IdentifierType::Dns => format!(
                        "server will not issue certificates for the identifier: role ({name}) will not issue certificate for name {}",
                        identifier.original
                    ),
                    pki::acme_orders::IdentifierType::Ip => format!(
                        "server will not issue certificates for the identifier: role ({name}) does not allow IP sans, so cannot issue certificate for {}",
                        identifier.original
                    ),
                };
                return Err(bad(&detail));
            }
        }
        Ok(())
    }
    // Directory eligibility uses the actual selected issuer. This performs no
    // signature effects and never upgrades a public JWS to Vault authority.
    pub(super) fn acme_directory_issuer(&self, prefix: &str) -> Result<&pki::RootCa> {
        let parts: Vec<_> = prefix.split('/').collect();
        let (explicit_issuer, explicit_role) = match parts.as_slice() {
            ["issuer", issuer, "roles", role] => (Some(*issuer), Some(*role)),
            ["issuer", issuer] => (Some(*issuer), None),
            ["roles", role] => (None, Some(*role)),
            _ => (None, None),
        };
        let role_name = match explicit_role {
            Some(role) => Some(role),
            None if self.acme.default_directory_policy == "forbid" => {
                return Err(error(
                    500,
                    "the server experienced an internal error: default directory not allowed by ACME policy",
                ));
            }
            None => self.acme.default_directory_policy.strip_prefix("role:"),
        };
        let role = role_name.map(|name| {
            let role = self.roles.get(name).ok_or_else(|| error(400,
                "the request message was malformed: role does not exist"))?;
            if role.role_name_policy.as_ref().is_some_and(|names| names.no_store) {
                return Err(error(500,
                    "the server experienced an internal error: role can not be used as NoStore is set to true"));
            }
            if explicit_role.is_some()
                && !self.acme.allowed_roles.iter().any(|allowed| allowed == "*" || allowed == name)
            {
                return Err(error(500,
                    "the server experienced an internal error: specified role not allowed by ACME policy"));
            }
            Ok(role)
        }).transpose()?;
        let reference = explicit_issuer.unwrap_or_else(|| {
            role.filter(|role| !role.issuer_ref.is_empty())
                .map_or("default", |role| role.issuer_ref.as_str())
        });
        let issuer = self.selected_issuer(reference).map_err(|_| {
            error(
                400,
                "the request message was malformed: issuer does not exist",
            )
        })?;
        if issuer.key_id.is_empty() {
            return Err(error(
                500,
                "the server experienced an internal error: issuer missing proper issuance usage or key",
            ));
        }
        if self.acme.allowed_issuers.as_slice() != ["*"] {
            let mut allowed = false;
            for (index, reference) in self.acme.allowed_issuers.iter().enumerate() {
                let candidate = self.selected_issuer(reference).map_err(|_| error(500,
                    &format!("failed to resolve reference for allowed_issuer entry {index}: unable to find PKI issuer for reference: {reference}")))?;
                if candidate.issuer_id == issuer.issuer_id {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return Err(error(
                    500,
                    "the server experienced an internal error: specified issuer not allowed by ACME policy",
                ));
            }
        }
        Ok(issuer)
    }
}

impl EngineState {
    pub(crate) fn acme_eab_request(
        &mut self,
        view: &AcmeView,
        method: &str,
        body: &Value,
        at: Timestamp,
    ) -> Result<Value> {
        let at = self.observe_acme(at)?;
        let pki = self.acme_pki_mut(&view.owner)?;
        if pki.acme_protocol.is_none() {
            pki.acme_protocol = Some(Box::new(Protocol::new(view.owner.clone(), at)?));
        }
        let protocol = pki
            .acme_protocol
            .as_mut()
            .ok_or_else(|| error(503, "EAB protocol owner unavailable"))?;
        if protocol.owner != view.owner {
            return Err(error(503, "EAB protocol owner changed"));
        }
        protocol.observe_time(at);
        if view.endpoint == "new-eab" && matches!(method, "POST" | "PUT") {
            let key = pki::acme_eab::Key::new(&view.owner, &view.directory, at)?;
            let data = SecretJson(key.descriptor()?);
            protocol.insert_eab(key)?;
            return Ok(json!({"data":&data.0}));
        }
        if view.endpoint == "eab" && method == "LIST" {
            let after = match body.get("after") {
                None => "",
                Some(v) => v.as_str().ok_or_else(|| bad("invalid EAB list after"))?,
            };
            let limit = match body.get("limit") {
                None => 0,
                Some(v) => v.as_i64().ok_or_else(|| bad("invalid EAB list limit"))?,
            };
            let mut keys = Vec::new();
            let mut info = serde_json::Map::new();
            for (id, key) in &protocol.eab_keys {
                if key.private.is_none() || id.as_str() <= after {
                    continue;
                }
                keys.push(id.clone());
                info.insert(id.clone(), key.info());
                if limit > 0 && keys.len() >= limit as usize {
                    break;
                }
            }
            if keys.is_empty() {
                return Err(error(404, "no value found"));
            }
            return Ok(json!({"data":{"keys":keys,"key_info":info}}));
        }
        if let Some(id) = view.endpoint.strip_prefix("eab/")
            && method == "DELETE"
        {
            if !pki::acme_state::valid_identifier(id) {
                return Err(error(404, "no handler for route"));
            }
            if let Some(key) = protocol
                .eab_keys
                .get_mut(id)
                .filter(|key| key.private.is_some())
            {
                key.retire(at, None);
                return Ok(json!({"data":null}));
            }
            return Ok(json!({"warnings":[format!("No key id found with id: {id}")]}));
        }
        Err(error(405, "unsupported operation"))
    }
}
