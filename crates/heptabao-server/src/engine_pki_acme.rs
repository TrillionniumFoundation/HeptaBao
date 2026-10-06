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
        let Some((directory, endpoint)) = acme_parts(relative) else {
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
        let parts: Vec<_> = prefix.split('/').collect();
        let role = match parts.as_slice() {
            ["roles", name] | ["issuer", _, "roles", name] => Some(*name),
            _ => pki.acme.default_directory_policy.strip_prefix("role:"),
        };
        if role.is_none() && pki.acme.default_directory_policy == "forbid" {
            return Err(error(500, "ACME default directory is forbidden"));
        }
        if let Some(name) = role {
            let role = pki
                .roles
                .get(name)
                .ok_or_else(|| bad("ACME role does not exist"))?;
            if role
                .role_name_policy
                .as_ref()
                .is_some_and(|names| names.no_store)
            {
                return Err(error(500, "ACME role cannot disable certificate storage"));
            }
            if !pki.acme.allowed_roles.iter().any(|r| r == "*" || r == name) {
                return Err(bad("ACME role is not allowed"));
            }
        }
        // Explicit issuer directories stay closed until their complete native
        // selection policy is integrated. No fallback to another issuer.
        if prefix.starts_with("issuer/") {
            return Err(error(
                501,
                "ACME explicit issuer directory is not implemented",
            ));
        }
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
        if payload.get("externalAccountBinding").is_some() {
            return Err(error(
                501,
                "ACME external account binding is not implemented",
            ));
        }
        if view.eab_required {
            return Err(error(400, "ACME external account binding is required"));
        }
        let new = view.endpoint == "new-account";
        if new && kid.is_some() {
            return Err(bad("cannot submit to newAccount with kid"));
        }
        if !new && kid.is_none() {
            return Err(bad("ACME account update requires kid"));
        }
        if only_existing || new {
            if let Some(account) = protocol.by_thumbprint(thumbprint, &view.directory) {
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
            let mut bytes = crate::crypto::random::<16>()
                .map_err(|_| error(503, "ACME account identifier generation unavailable"))?;
            bytes[6] = (bytes[6] & 15) | 64;
            bytes[8] = (bytes[8] & 63) | 128;
            let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let id = format!(
                "{}-{}-{}-{}-{}",
                &hex[..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..]
            );
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
            };
            let descriptor = account.descriptor(&view.base);
            protocol.insert_account(account)?;
            return Ok((201, descriptor, format!("{}account/{id}", view.base)));
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
