//! Owned local issuers. The root slot is the selected default; the remaining
//! roots retain their actual private key and certificate in encrypted state.
use super::*;
use x509_parser::prelude::FromDer;

const MAX_LOCAL_ISSUERS: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LocalIssuers {
    pub(super) other: BTreeMap<String, RootCa>,
    pub(super) default_follows_latest_issuer: bool,
    // Key selection is independent of the selected issuer. Removing an issuer
    // retains its key and therefore retains this default until root deletion.
    pub(super) default_key_id: String,
    #[serde(default)]
    pub(super) orphan_keys: BTreeMap<String, RootCa>,
    #[serde(default)]
    certificates: BTreeMap<String, Vec<u8>>,
    #[serde(default)]
    retired_issuers: BTreeMap<String, PublicIssuer>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PublicIssuer {
    serial: String,
    public: LocalPublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain: Option<Box<LocalCaChain>>,
}

fn archive_issuer(state: &mut LocalIssuers, root: &RootCa) -> Result<()> {
    let public = root.local_key()?.public()?;
    root.validate_local_certificate()?;
    state
        .certificates
        .insert(root.serial.clone(), root.certificate_der.clone());
    state.retired_issuers.insert(
        root.issuer_id.clone(),
        PublicIssuer {
            serial: root.serial.clone(),
            public,
            chain: root.local_chain.clone(),
        },
    );
    Ok(())
}

impl Pki {
    pub(super) fn local_pki_identifiers_in_use(&self, issuer: &str, key: &str) -> bool {
        self.local_key_instances()
            .any(|root| root.issuer_id == issuer || root.key_id == key)
            || self.owned_key(key).is_ok()
            || self
                .local_issuers
                .as_ref()
                .is_some_and(|state| state.retired_issuers.contains_key(issuer))
    }
    pub(super) fn legacy_leaf_is_signed_by(root: &RootCa, issued: &IssuedCertificate) -> bool {
        let Ok(public) = root.local_key().and_then(|key| key.public()) else {
            return false;
        };
        x509_parser::certificate::X509Certificate::from_der(&issued.certificate_der)
            .ok()
            .is_some_and(|(rest, cert)| {
                rest.is_empty()
                    && cert.signature_value.unused_bits == 0
                    && cert.signature_algorithm == cert.tbs_certificate.signature
                    && public
                        .verify(cert.tbs_certificate.as_ref(), &cert.signature_value.data)
                        .is_ok_and(|valid| valid)
            })
    }
    pub(super) fn profile_route_needs_identity(&self, route: &IssuanceRoute<'_>) -> Result<bool> {
        let role = self
            .roles
            .get(route.role)
            .ok_or_else(|| bad(&format!("unknown role: {}", route.role)))?;
        let reference = route
            .explicit_issuer
            .unwrap_or(if role.issuer_ref.is_empty() {
                "default"
            } else {
                &role.issuer_ref
            });
        let selected = self.selected_issuer(reference)?;
        Ok(!selected.is_external() && selected.issuer_id.is_empty())
    }

    pub(super) fn promote_profile_root_identity(
        &mut self,
        route: &IssuanceRoute<'_>,
    ) -> Result<()> {
        if !self.profile_route_needs_identity(route)? {
            return Err(error(503, "PKI profile identity changed"));
        }
        let role = self
            .roles
            .get(route.role)
            .ok_or_else(|| bad(&format!("unknown role: {}", route.role)))?;
        let reference = route
            .explicit_issuer
            .unwrap_or(if role.issuer_ref.is_empty() {
                "default"
            } else {
                &role.issuer_ref
            });
        let selected = self.selected_issuer(reference)?;
        let current = self.root.as_ref().ok_or_else(not_found)?;
        if reference != "default"
            || current.is_external()
            || !current.issuer_id.is_empty()
            || !current.key_id.is_empty()
            || selected.certificate_der != current.certificate_der
        {
            return Err(error(503, "PKI profile identity owner changed"));
        }
        current.validate_local_certificate()?;
        let historical_local = self.verified_unbound_local_leaves(current)?;
        let issuer_id = random_pki_id()?;
        let key_id = random_pki_id()?;
        if issuer_id == key_id
            || self.external_pki_identifiers_in_use(&issuer_id, &key_id)
            || self.owned_key(&key_id).is_ok()
            || self
                .local_key_instances()
                .any(|root| root.issuer_id == issuer_id || root.key_id == key_id)
            || self
                .local_issuers
                .as_ref()
                .is_some_and(|s| s.retired_issuers.contains_key(&issuer_id))
        {
            return Err(error(503, "PKI identifier collision"));
        }
        let mut promoted = current.clone();
        promoted.issuer_id = issuer_id.clone();
        promoted.key_id = key_id.clone();
        let mut state = self
            .local_issuers
            .as_deref()
            .cloned()
            .unwrap_or(LocalIssuers {
                other: BTreeMap::new(),
                default_follows_latest_issuer: false,
                default_key_id: key_id,
                orphan_keys: BTreeMap::new(),
                certificates: BTreeMap::new(),
                retired_issuers: BTreeMap::new(),
            });
        archive_issuer(&mut state, &promoted)?;
        for serial in historical_local {
            if let Some(issued) = self.issued.get_mut(&serial) {
                issued.local_issuer_id = issuer_id.clone();
            }
        }
        self.root = Some(promoted);
        self.local_issuers = Some(Box::new(state));
        self.validate_local_issuers()?;
        Ok(())
    }

    pub(super) fn profile_leaf_issuer_evidence(&self, id: &str) -> Result<(&[u8], LocalPublicKey)> {
        if id.is_empty() {
            return Err(bad("PKI profile issuer identity missing"));
        }
        if let Some(state) = &self.local_issuers
            && let Some(issuer) = state.retired_issuers.get(id)
        {
            return Ok((
                state
                    .certificates
                    .get(&issuer.serial)
                    .ok_or_else(|| bad("PKI profile archived issuer certificate missing"))?
                    .as_slice(),
                issuer.public.clone(),
            ));
        }
        let root = self.local_issuer(id)?;
        Ok((root.certificate_der.as_slice(), root.local_key()?.public()?))
    }

    pub(super) fn has_archived_local_ca_chain(&self) -> bool {
        self.local_keys().any(|root| root.local_chain.is_some())
            || self.local_issuers.iter().any(|state| {
                state
                    .retired_issuers
                    .values()
                    .any(|issuer| issuer.chain.is_some())
            })
    }
    pub(in crate::engines) fn has_local_multi_issuer_state(&self) -> bool {
        self.local_issuers.is_some()
            || self.roles.values().any(|role| !role.issuer_ref.is_empty())
            || self
                .issued
                .values()
                .any(|cert| !cert.local_issuer_id.is_empty())
    }

    pub(super) fn local_roots(&self) -> impl Iterator<Item = &RootCa> {
        self.root.iter().filter(|root| !root.is_external()).chain(
            self.local_issuers
                .iter()
                .flat_map(|state| state.other.values()),
        )
    }

    pub(super) fn local_issuer(&self, reference: &str) -> Result<&RootCa> {
        if reference == "default" {
            if self.has_public_default_override() {
                return Err(error(500, "default issuer has no owned signing key"));
            }
            return self
                .root
                .as_ref()
                .ok_or_else(|| error(500, "issuer reference is unavailable"));
        }
        // IDs resolve before names. An unrelated or unknown name can never
        // fall back to the default issuer.
        self.local_roots()
            .find(|root| root.issuer_id == reference)
            .or_else(|| {
                self.local_roots().find(|root| {
                    root.local_fields.as_ref().is_some_and(|fields| {
                        !fields.issuer_name.is_empty() && fields.issuer_name == reference
                    })
                })
            })
            .ok_or_else(|| error(500, "issuer reference is unavailable"))
    }

    pub(super) fn selected_issuer(&self, reference: &str) -> Result<&RootCa> {
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            self.require_public_issuer(reference)?;
            return self.root.as_ref().ok_or_else(not_found);
        }
        self.local_issuer(reference)
    }

    pub(super) fn admit_local_root_names(&self, fields: &RootFields) -> Result<()> {
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Err(error(
                501,
                "local root generation cannot replace an external issuer",
            ));
        }
        if self.local_roots().count() >= MAX_LOCAL_ISSUERS {
            return Err(error(507, "PKI issuer capacity exhausted"));
        }
        if self.local_keys().count() >= MAX_ISSUED
            || self
                .local_issuers
                .as_ref()
                .is_some_and(|state| state.certificates.len() >= MAX_ISSUED)
        {
            return Err(error(507, "PKI key or certificate capacity exhausted"));
        }
        if let Some(fields) = &fields.metadata {
            if !fields.issuer_name.is_empty()
                && self.local_roots().any(|root| {
                    root.local_fields
                        .as_ref()
                        .is_some_and(|existing| existing.issuer_name == fields.issuer_name)
                })
            {
                return Err(bad("PKI issuer name already exists"));
            }
            if !fields.key_name.is_empty()
                && self.local_keys().any(|root| {
                    root.local_fields
                        .as_ref()
                        .is_some_and(|existing| existing.key_name == fields.key_name)
                })
            {
                return Err(bad("key name already in use"));
            }
        }
        Ok(())
    }

    pub(super) fn publish_local_root(&mut self, next: RootCa) -> Result<()> {
        if self.external_pki_identifiers_in_use(&next.issuer_id, &next.key_id)
            || self
                .local_key_instances()
                .any(|root| root.issuer_id == next.issuer_id)
            || self
                .local_issuers
                .as_ref()
                .is_some_and(|state| state.retired_issuers.contains_key(&next.issuer_id))
        {
            return Err(error(503, "PKI identifier collision"));
        }
        let public = next.local_key()?.public()?.spki()?;
        for existing in self
            .local_key_instances()
            .filter(|key| key.key_id == next.key_id)
        {
            if existing.local_key()?.public()?.spki()? != public
                || existing
                    .local_fields
                    .as_ref()
                    .map_or("", |m| m.key_name.as_str())
                    != next
                        .local_fields
                        .as_ref()
                        .map_or("", |m| m.key_name.as_str())
            {
                return Err(error(503, "PKI shared key ownership changed"));
            }
        }
        let restore_empty_issuer_default =
            self.has_public_default_override() && self.public_default_issuer_id().is_empty();
        let follow_public_default = self.has_public_default_override()
            && self
                .local_issuers
                .as_ref()
                .is_some_and(|state| state.default_follows_latest_issuer);
        let restore_default_key =
            self.local_default_key_unset() && self.owned_key(&next.key_id).is_err();
        let new_key = next.key_id.clone();
        let historical_local = self
            .root
            .as_ref()
            .map(|root| self.verified_unbound_local_leaves(root))
            .transpose()?
            .unwrap_or_default();
        let historical_ids = if self
            .root
            .as_ref()
            .is_some_and(|root| root.issuer_id.is_empty())
        {
            let issuer = random_pki_id()?;
            let key = random_pki_id()?;
            if issuer == key
                || issuer == next.issuer_id
                || key == next.key_id
                || self.external_pki_identifiers_in_use(&issuer, &key)
                || self.local_pki_identifiers_in_use(&issuer, &key)
            {
                return Err(error(503, "PKI identifier collision"));
            }
            Some((issuer, key))
        } else {
            None
        };
        let Some(current) = self.root.as_mut() else {
            if let Some(state) = &mut self.local_issuers {
                archive_issuer(state, &next)?;
                if state.default_key_id.is_empty() {
                    state.default_key_id = next.key_id.clone();
                }
            }
            self.root = Some(next);
            if restore_empty_issuer_default || follow_public_default {
                self.clear_public_default_override();
            }
            if restore_default_key {
                self.set_local_key_default(&new_key);
            }
            return Ok(());
        };
        // Historical roots predate issuer IDs. Generate both before changing
        // either field; their original private key and certificate stay owned.
        if let Some((issuer, key)) = historical_ids {
            current.issuer_id = issuer;
            current.key_id = key;
        }
        let state = self.local_issuers.get_or_insert_with(|| {
            Box::new(LocalIssuers {
                other: BTreeMap::new(),
                default_follows_latest_issuer: false,
                default_key_id: current.key_id.clone(),
                orphan_keys: BTreeMap::new(),
                certificates: BTreeMap::new(),
                retired_issuers: BTreeMap::new(),
            })
        });
        for serial in historical_local {
            if let Some(issued) = self.issued.get_mut(&serial) {
                issued.local_issuer_id = current.issuer_id.clone();
            }
        }
        archive_issuer(state, current)?;
        archive_issuer(state, &next)?;
        let select_default = state.default_follows_latest_issuer || restore_empty_issuer_default;
        if select_default {
            let previous = self
                .root
                .replace(next)
                .ok_or_else(|| error(503, "PKI default changed"))?;
            state.other.insert(previous.issuer_id.clone(), previous);
        } else {
            state.other.insert(next.issuer_id.clone(), next);
        }
        if select_default {
            self.clear_public_default_override();
        }
        if restore_default_key {
            self.set_local_key_default(&new_key);
        }
        Ok(())
    }

    pub(super) fn validate_local_issuers(&self) -> Result<()> {
        let Some(state) = &self.local_issuers else {
            return self.validate_local_leaf_associations();
        };
        // An external default may coexist with retired local public evidence,
        // never with live local issuer/private-key selection authority.
        if self.root.as_ref().is_some_and(RootCa::is_external)
            && (!state.other.is_empty()
                || !state.orphan_keys.is_empty()
                || !state.default_key_id.is_empty()
                || self.has_unbound_owned_keys())
            || self.local_roots().count() > MAX_LOCAL_ISSUERS
            || self.local_keys().count() > MAX_ISSUED
            || state.certificates.len() > MAX_ISSUED
            || state.retired_issuers.len() > MAX_ISSUED
        {
            return Err(bad("invalid local PKI issuer state"));
        }
        if !state.default_key_id.is_empty() && self.owned_key(&state.default_key_id).is_err()
            || self.local_default_key_unset() && !state.default_key_id.is_empty()
            || !self.local_default_key_unset()
                && self.default_local_key_id().is_empty()
                && (self.local_keys().next().is_some() || self.has_unbound_owned_keys())
            || !self.local_default_key_unset()
                && !self.default_local_key_id().is_empty()
                && self.owned_key(self.default_local_key_id()).is_err()
        {
            return Err(bad("invalid local PKI default key ownership"));
        }
        let mut issuer_ids = BTreeSet::new();
        let mut key_ids = BTreeMap::new();
        let mut public_key_owners = BTreeMap::new();
        let mut issuer_names = BTreeSet::new();
        let mut key_names = BTreeMap::new();
        for root in self.local_key_instances() {
            if root.is_external()
                || root.issuer_id.is_empty()
                || root.key_id.is_empty()
                || !valid_pki_id(&root.issuer_id)
                || !valid_pki_id(&root.key_id)
                || !issuer_ids.insert(&root.issuer_id)
                || !external::common_name_valid(&root.common_name)
                || root.not_before >= root.not_after
                || root.local_chain.is_none() && root.not_after - root.not_before > MAX_TTL * 2
                || serial_bytes(&root.serial).is_err()
                || root.certificate_der.len() > 64 * 1024
                || root.pkcs8.len() > 4096
            {
                return Err(bad("invalid local PKI issuer ownership"));
            }
            let identity = (
                root.local_key()?.public()?.spki()?,
                root.local_fields
                    .as_ref()
                    .map_or("", |m| m.key_name.as_str()),
            );
            if public_key_owners
                .insert(identity.0.clone(), &root.key_id)
                .is_some_and(|id| id != &root.key_id)
            {
                return Err(bad("local PKI public key has conflicting identities"));
            }
            if key_ids
                .insert(&root.key_id, identity.clone())
                .is_some_and(|old| old != identity)
            {
                return Err(bad("shared PKI key identity changed"));
            }
            if let Some(fields) = &root.local_fields {
                fields.validate()?;
                if self
                    .local_roots()
                    .any(|issuer| issuer.issuer_id == root.issuer_id)
                    && !fields.issuer_name.is_empty()
                    && !issuer_names.insert(&fields.issuer_name)
                    || !fields.key_name.is_empty()
                        && key_names
                            .insert(&fields.key_name, &root.key_id)
                            .is_some_and(|id| id != &root.key_id)
                {
                    return Err(bad("duplicate local PKI issuer aliases"));
                }
            }
            root.validate_local_certificate()?;
        }
        if state.other.iter().any(|(id, root)| {
            id != &root.issuer_id
                || self
                    .root
                    .as_ref()
                    .is_some_and(|default| id == &default.issuer_id)
        }) || state
            .orphan_keys
            .iter()
            .any(|(id, root)| id != &root.key_id)
            || state.certificates.iter().any(|(serial, der)| {
                serial_bytes(serial).is_err()
                    || der.is_empty()
                    || der.len() > 64 * 1024
                    || root_fields::certificate_subject(der).is_err()
            })
        {
            return Err(bad("invalid local PKI issuer index"));
        }
        for (id, issuer) in &state.retired_issuers {
            if !valid_pki_id(id) {
                return Err(bad("invalid archived PKI issuer identity"));
            }
            let der = state
                .certificates
                .get(&issuer.serial)
                .ok_or_else(|| bad("archived PKI issuer certificate missing"))?;
            if let Some(chain) = &issuer.chain {
                chain.validate(der, &issuer.public)?;
            } else {
                issuer.public.validate_certificate(der)?;
            }
        }
        self.validate_local_leaf_associations()
    }

    fn validate_local_leaf_associations(&self) -> Result<()> {
        for certificate in self
            .issued
            .values()
            .filter(|cert| !cert.local_issuer_id.is_empty())
        {
            let public = if let Some(issuer) = self
                .local_issuers
                .as_ref()
                .and_then(|state| state.retired_issuers.get(&certificate.local_issuer_id))
            {
                issuer.public.clone()
            } else {
                self.local_issuer(&certificate.local_issuer_id)?
                    .local_key()?
                    .public()?
            };
            let (rest, cert) =
                x509_parser::certificate::X509Certificate::from_der(&certificate.certificate_der)
                    .map_err(|_| bad("invalid local PKI leaf certificate"))?;
            if !rest.is_empty()
                || cert.signature_value.unused_bits != 0
                || cert.signature_algorithm != cert.tbs_certificate.signature
                || !public.verify(cert.tbs_certificate.as_ref(), &cert.signature_value.data)?
            {
                return Err(bad("local PKI leaf signing authority changed"));
            }
        }
        Ok(())
    }

    pub(super) fn select_local_owned_default(&mut self, id: &str) -> Result<()> {
        self.local_issuer(id)?;
        if self.root.as_ref().is_none_or(|root| root.issuer_id != id) {
            let state = self
                .local_issuers
                .as_mut()
                .ok_or_else(|| bad("owned issuer selection is unavailable"))?;
            let selected = state
                .other
                .remove(id)
                .ok_or_else(|| bad("owned issuer selection is unavailable"))?;
            if let Some(previous) = self.root.replace(selected) {
                state.other.insert(previous.issuer_id.clone(), previous);
            }
        }
        self.clear_public_default_override();
        Ok(())
    }

    pub(super) fn local_issuer_config(
        &mut self,
        method: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        if method == "GET" {
            reject_unknown(body, &[])?;
            return Ok(ok(
                json!({"default":self.selected_local_issuer_id(),
                "default_follows_latest_issuer":self.local_issuers.as_ref().is_some_and(|s| s.default_follows_latest_issuer)}),
                false,
            ));
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(body, &["default", "default_follows_latest_issuer"])?;
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Err(bad("local PKI issuer configuration is unavailable"));
        }
        if body
            .get("default")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value == "default")
        {
            return Err(bad("default issuer must be specified"));
        }
        let selected = body
            .get("default")
            .map(|value| {
                let reference = value
                    .as_str()
                    .ok_or_else(|| bad("PKI default issuer must be a string"))?;
                if reference.is_empty() || reference == "default" {
                    return Err(bad("default issuer must be specified"));
                }
                if let Some(id) = self.imported_ca_id(reference) {
                    return Ok((id.to_owned(), true));
                }
                self.local_issuer(reference)
                    .map(|root| (root.issuer_id.clone(), false))
                    .map_err(|_| bad("default issuer reference is unavailable"))
            })
            .transpose()?;
        let follows = optional_bool(body, "default_follows_latest_issuer")?;
        let change_default = selected
            .as_ref()
            .is_some_and(|(id, _)| id != self.selected_local_issuer_id());
        let before_follows = self
            .local_issuers
            .as_ref()
            .is_some_and(|s| s.default_follows_latest_issuer);
        let change_follows = follows.is_some_and(|value| value != before_follows);
        if change_default {
            let (id, public) =
                selected.ok_or_else(|| bad("default issuer selection is unavailable"))?;
            if public {
                self.set_public_default_issuer(&id);
            } else {
                self.select_local_owned_default(&id)?;
            }
        }
        if change_follows {
            let default_key_id = self.default_local_key_id().to_owned();
            let state = self.local_issuers.get_or_insert_with(|| {
                Box::new(LocalIssuers {
                    other: BTreeMap::new(),
                    default_follows_latest_issuer: false,
                    default_key_id,
                    orphan_keys: BTreeMap::new(),
                    certificates: BTreeMap::new(),
                    retired_issuers: BTreeMap::new(),
                })
            });
            state.default_follows_latest_issuer =
                follows.ok_or_else(|| bad("issuer follow policy missing"))?;
        }
        let mut response = self.local_issuer_config("GET", &json!({}))?;
        response.mutated = change_default || change_follows;
        if self.public_imported_ca("default").is_some() {
            response.body["warnings"] = json!([
                "This selected default issuer has no key associated with it. Some operations like issuing certificates and signing CRLs will be unavailable with the requested default issuer until a key is imported or the default issuer is changed."
            ]);
        }
        Ok(response)
    }
    fn local_key_instances(&self) -> impl Iterator<Item = &RootCa> {
        self.local_roots().chain(
            self.local_issuers
                .iter()
                .flat_map(|state| state.orphan_keys.values()),
        )
    }

    pub(super) fn local_keys(&self) -> impl Iterator<Item = &RootCa> {
        let mut seen = BTreeSet::new();
        self.local_key_instances()
            .filter(move |root| seen.insert(&root.key_id))
    }

    pub(super) fn local_key_list(&self, body: &Value) -> Result<EngineResponse> {
        reject_unknown(body, &[])?;
        let mut info = serde_json::Map::new();
        let default_key_id = self.default_local_key_id();
        for root in self.local_keys() {
            let name = root
                .local_fields
                .as_ref()
                .map_or("", |fields| fields.key_name.as_str());
            info.insert(
                root.key_id.clone(),
                json!({"key_name":name,"is_default":root.key_id==default_key_id}),
            );
        }
        self.append_pending_keys(&mut info, default_key_id);
        if info.is_empty() {
            return Ok(EngineResponse {
                status: 404,
                body: json!({"errors":[]}),
                mutated: false,
            });
        }
        Ok(ok(
            json!({"keys":info.keys().collect::<Vec<_>>(),"key_info":info}),
            false,
        ))
    }

    pub(super) fn default_local_key_id(&self) -> &str {
        if self.local_default_key_unset() {
            return "";
        }
        let pending = self.pending_key_default();
        if !pending.is_empty() {
            return pending;
        }
        self.local_issuers.as_ref().map_or_else(
            || self.root.as_ref().map_or("", |root| root.key_id.as_str()),
            |state| state.default_key_id.as_str(),
        )
    }

    pub(super) fn local_issuer_delete(
        &mut self,
        reference: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &[])?;
        self.local_issuer(reference)?;
        self.promote_default_associations()?;
        let default_key_id = self
            .root
            .as_ref()
            .map_or_else(String::new, |root| root.key_id.clone());
        let id = self.local_issuer(reference)?.issuer_id.clone();
        let removed = if self.root.as_ref().is_some_and(|root| root.issuer_id == id) {
            self.root.take().ok_or_else(not_found)?
        } else {
            self.local_issuers
                .as_mut()
                .and_then(|state| state.other.remove(&id))
                .ok_or_else(not_found)?
        };
        let state = self.local_issuers.get_or_insert_with(|| {
            Box::new(LocalIssuers {
                other: BTreeMap::new(),
                orphan_keys: BTreeMap::new(),
                certificates: BTreeMap::new(),
                retired_issuers: BTreeMap::new(),
                default_follows_latest_issuer: false,
                default_key_id,
            })
        });
        archive_issuer(state, &removed)?;
        state.orphan_keys.insert(removed.key_id.clone(), removed);
        Ok(ok(Value::Null, true))
    }

    fn verified_unbound_local_leaves(&self, root: &RootCa) -> Result<BTreeSet<String>> {
        if root.is_external() {
            return Err(bad("historical local leaf has no local signer"));
        }
        root.validate_local_certificate()?;
        // This is a timeless cryptographic ownership check, not a request-clock
        // or lease grant. It validates every external projection/archive before
        // excluding it from local identity promotion.
        self.validate_external_consumption(u64::MAX)?;
        let mut serials = BTreeSet::new();
        for (serial, issued) in &self.issued {
            if !issued.local_issuer_id.is_empty() || self.profile_leaf_is_external(serial) {
                continue;
            }
            let verified = Self::legacy_leaf_is_signed_by(root, issued);
            if verified {
                serials.insert(serial.clone());
            } else if issued.role_leaf_profile.is_some() || issued.external_issuer_owner.is_some() {
                return Err(bad("historical PKI leaf signing authority changed"));
            }
            // A pre-profile None leaf with no surviving issuer proof remains
            // unchanged and unassigned. Its legacy gap never grants this root
            // ownership, and does not turn root/delete into a false failure.
        }
        Ok(serials)
    }

    pub(super) fn promote_default_associations(&mut self) -> Result<()> {
        let Some(root) = self.root.as_ref().filter(|root| !root.is_external()) else {
            return Ok(());
        };
        let historical_local = self.verified_unbound_local_leaves(root)?;
        let next_ids = if root.issuer_id.is_empty() {
            let issuer = random_pki_id()?;
            let key = random_pki_id()?;
            if issuer == key
                || self.external_pki_identifiers_in_use(&issuer, &key)
                || self.local_issuers.as_ref().is_some_and(|state| {
                    state
                        .other
                        .values()
                        .chain(state.orphan_keys.values())
                        .any(|root| root.issuer_id == issuer || root.key_id == key)
                        || state.retired_issuers.contains_key(&issuer)
                })
            {
                return Err(error(503, "PKI identifier collision"));
            }
            Some((issuer, key))
        } else {
            None
        };
        let root = self
            .root
            .as_mut()
            .ok_or_else(|| bad("local PKI root changed"))?;
        if let Some((issuer, key)) = next_ids {
            root.issuer_id = issuer;
            root.key_id = key;
        }
        for serial in historical_local {
            if let Some(issued) = self.issued.get_mut(&serial) {
                issued.local_issuer_id = root.issuer_id.clone();
            }
        }
        Ok(())
    }

    pub(super) fn delete_local_roots(&mut self) -> Result<bool> {
        self.promote_default_associations()?;
        let pending_changed = self.delete_intermediate_material();
        let changed = pending_changed
            || self.root.is_some()
            || self
                .local_issuers
                .as_ref()
                .is_some_and(|state| !state.other.is_empty() || !state.orphan_keys.is_empty());
        // Root deletion retires issuer/key ownership, while certificate history
        // and the caller's issuer configuration remain durable.
        if let Some(root) = self.root.take() {
            let state = self.local_issuers.get_or_insert_with(|| {
                Box::new(LocalIssuers {
                    other: BTreeMap::new(),
                    orphan_keys: BTreeMap::new(),
                    certificates: BTreeMap::new(),
                    retired_issuers: BTreeMap::new(),
                    default_follows_latest_issuer: false,
                    default_key_id: root.key_id.clone(),
                })
            });
            archive_issuer(state, &root)?;
        }
        if let Some(state) = &mut self.local_issuers {
            let other = std::mem::take(&mut state.other);
            for root in other.values() {
                archive_issuer(state, root)?;
            }
            state.orphan_keys.clear();
            state.default_key_id.clear();
        }
        Ok(changed)
    }

    pub(super) fn local_issuer_certificate_by_id(&self, id: &str) -> Option<&[u8]> {
        self.local_roots()
            .find(|root| root.issuer_id == id)
            .map(|root| root.certificate_der.as_slice())
            .or_else(|| {
                let state = self.local_issuers.as_ref()?;
                let issuer = state.retired_issuers.get(id)?;
                state.certificates.get(&issuer.serial).map(Vec::as_slice)
            })
    }

    pub(super) fn local_certificate(&self, serial: &str) -> Option<&[u8]> {
        self.local_roots()
            .find(|root| root.serial == serial)
            .map(|root| root.certificate_der.as_slice())
            .or_else(|| self.intermediate_certificate(serial))
            .or_else(|| {
                self.local_issuers
                    .as_ref()?
                    .certificates
                    .get(serial)
                    .map(Vec::as_slice)
            })
    }

    pub(super) fn certificate_list(&self, body: &Value) -> Result<EngineResponse> {
        reject_unknown(body, &[])?;
        let mut serials = self.issued.keys().cloned().collect::<BTreeSet<_>>();
        serials.extend(self.local_roots().map(|root| root.serial.clone()));
        serials.extend(self.signed_ca_serials().cloned());
        if let Some(state) = &self.local_issuers {
            serials.extend(state.certificates.keys().cloned());
        }
        if serials.is_empty() {
            return Err(not_found());
        }
        Ok(ok(
            json!({"keys":serials.iter().map(|serial|external::formatted_serial(serial)).collect::<Vec<_>>()}),
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::{
        certificate::X509Certificate, prelude::FromDer, revocation_list::CertificateRevocationList,
    };
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn generate(pki: &mut Pki, name: &str, now: u64) -> Result<EngineResponse> {
        pki.handle_admin("POST","root/generate/internal",&json!({
            "common_name":format!("{name}.example.test"),"key_type":"ec","ttl":"24h",
            "issuer_name":name,"key_name":format!("key-{name}"),"organization":[format!("Organization {name}")]
        }),now)
    }

    #[test]
    fn real_issuers_select_sign_revoke_reopen_and_preserve_deleted_history() -> TestResult {
        let now = 1_700_000_000;
        let mut pki = Pki::default();
        generate(&mut pki, "root-a", now)?;
        let id_a = pki.root.as_ref().ok_or("root a")?.issuer_id.clone();
        let key_a = pki.root.as_ref().ok_or("key a")?.key_id.clone();
        generate(&mut pki, "root-b", now)?;
        let id_b = pki.local_issuer("root-b")?.issuer_id.clone();
        assert!(
            pki.root.as_ref().ok_or("default")?.issuer_id == id_a,
            "first issuer remains default"
        );
        let before = Zeroizing::new(serde_json::to_vec(&pki)?);
        assert!(
            generate(&mut pki, "root-b", now).is_err(),
            "duplicate alias rejected"
        );
        assert!(
            pki.local_issuer_config("POST", &json!({"default_follows_latest_issuer":true}))
                .is_err(),
            "default required"
        );
        for body in [
            json!({"default":"default"}),
            json!({"default":"unknown-issuer"}),
        ] {
            assert!(
                matches!(pki.local_issuer_config("POST",&body),Err(error) if error.status==400),
                "invalid configuration reference is400"
            );
        }
        assert!(
            serde_json::to_vec(&pki)? == *before,
            "rejected management preserves state"
        );
        pki.local_issuer_config(
            "POST",
            &json!({"default":"root-b","default_follows_latest_issuer":true}),
        )?;
        assert!(
            pki.local_key_list(&json!({}))?.body["data"]["key_info"][&key_a]["is_default"] == true,
            "issuer default changes preserve the independent first key default"
        );
        pki.handle_admin("POST","roles/web",&json!({"allowed_domains":["example.test"],"allow_subdomains":true,"issuer_ref":"root-a","max_ttl":"10m","key_type":"ec"}),now)?;
        let owner = serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?;
        let a = pki.issue_route(
            "pki/",
            "issue/web",
            &json!({"common_name":"a.example.test"}),
            &owner,
            None,
            now,
        )?;
        let b = pki.issue_route(
            "pki/",
            "issuer/root-b/issue/web",
            &json!({"common_name":"b.example.test"}),
            &owner,
            None,
            now,
        )?;
        for leaf in [&a, &b] {
            assert!(
                leaf.body["data"]["private_key"]
                    .as_str()
                    .ok_or("leaf key")?
                    .starts_with("-----BEGIN EC PRIVATE KEY-----\n"),
                "local EC leaves use SEC1"
            );
        }
        let sa = a.body["data"]["serial_number"]
            .as_str()
            .ok_or("serial a")?
            .to_owned();
        let sb = b.body["data"]["serial_number"]
            .as_str()
            .ok_or("serial b")?
            .to_owned();
        for (serial, id) in [(&sa, &id_a), (&sb, &id_b)] {
            let stored = pki
                .issued
                .get(&normalize_serial(serial)?)
                .ok_or("stored leaf")?;
            let root = pki.local_issuer(id)?;
            let (_, cert) = X509Certificate::from_der(&stored.certificate_der)?;
            assert!(
                stored.local_issuer_id == *id
                    && cert.issuer().as_raw()
                        == root_fields::certificate_subject(&root.certificate_der)?,
                "leaf issuer ownership"
            );
            assert!(
                root.local_key()?
                    .public()?
                    .verify(cert.tbs_certificate.as_ref(), &cert.signature_value.data)?,
                "selected issuer really signed leaf"
            );
        }
        pki.handle_admin("POST", "revoke", &json!({"serial_number":sa}), now + 1)?;
        let encoded = Zeroizing::new(serde_json::to_vec(&pki)?);
        let mut pki: Pki = serde_json::from_slice(&encoded)?;
        pki.validate("", "pki/", now + 1)?;
        for (id, count) in [(&id_a, 1), (&id_b, 0)] {
            let root = pki.local_issuer(id)?;
            let der = pki.crl_der(root, now + 2)?;
            let (_, crl) = CertificateRevocationList::from_der(&der)?;
            assert!(
                crl.iter_revoked_certificates().count() == count,
                "CRL includes only this issuer revocations"
            );
            assert!(
                root.local_key()?
                    .public()?
                    .verify(crl.tbs_cert_list.as_ref(), &crl.signature_value.data)?,
                "actual CRL signature"
            );
        }
        generate(&mut pki, "root-c", now + 2)?;
        assert!(
            pki.root
                .as_ref()
                .ok_or("latest")?
                .local_fields
                .as_ref()
                .ok_or("name")?
                .issuer_name
                == "root-c",
            "default follows latest"
        );
        pki.local_issuer_delete("default", &json!({}))?;
        assert!(
            pki.root.is_none()
                && pki.local_roots().count() == 2
                && pki.local_key_list(&json!({}))?.body["data"]["keys"]
                    .as_array()
                    .ok_or("keys")?
                    .len()
                    == 3,
            "delete issuer preserves other issuers and all keys"
        );
        assert!(
            pki.local_issuer("root-c").is_err(),
            "deleted alias never falls back"
        );
        assert!(
            pki.local_key_list(&json!({}))?.body["data"]["key_info"][&key_a]["is_default"] == true,
            "deleted issuer and follows-latest preserve the original default key"
        );
        assert!(
            pki.local_issuer_config("GET", &json!({}))?.body["data"]["default_follows_latest_issuer"]
                == true,
            "delete retains configuration"
        );
        let certs = pki.certificate_list(&json!({}))?.body.clone();
        let deleted = pki.handle_admin("DELETE", "root", &json!({}), now + 2)?;
        assert!(
            deleted.status == 200,
            "root deletion returns the official status"
        );
        assert!(
            pki.certificate_list(&json!({}))?.body == certs
                && pki.roles.len() == 1
                && pki.issued.len() == 2
                && pki.local_key_list(&json!({}))?.status == 404,
            "root deletion preserves certs and roles while deleting keys"
        );
        let encoded = Zeroizing::new(serde_json::to_vec(&pki)?);
        let pki: Pki = serde_json::from_slice(&encoded)?;
        pki.validate("", "pki/", now + 2)?;
        assert!(
            pki.has_local_multi_issuer_state(),
            "retired history retains reader requirement"
        );
        Ok(())
    }
    #[test]
    fn old_default_leaf_keeps_its_real_signer_after_delete_and_recreation() -> TestResult {
        for delete_issuer in [false, true] {
            let now = 1_700_000_000;
            let mut pki = Pki::default();
            generate(&mut pki, "old-root", now)?;
            let old_id = pki.root.as_ref().ok_or("old root")?.issuer_id.clone();
            pki.handle_admin("POST","roles/web",&json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"10m"}),now)?;
            let owner = serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?;
            let leaf = pki.issue_route(
                "pki/",
                "issue/web",
                &json!({"common_name":"old.example.test"}),
                &owner,
                None,
                now,
            )?;
            let serial = normalize_serial(
                leaf.body["data"]["serial_number"]
                    .as_str()
                    .ok_or("serial")?,
            )?;
            if delete_issuer {
                pki.local_issuer_delete("default", &json!({}))?;
            } else {
                pki.delete_local_roots()?;
            }
            generate(&mut pki, "new-root", now + 1)?;
            generate(&mut pki, "other-root", now + 1)?;
            pki.handle_admin("POST", "revoke", &json!({"serial_number":serial}), now + 2)?;
            let encoded = Zeroizing::new(serde_json::to_vec(&pki)?);
            let pki: Pki = serde_json::from_slice(&encoded)?;
            pki.validate("", "pki/", now + 2)?;
            assert!(
                pki.issued.get(&serial).ok_or("old leaf")?.local_issuer_id == old_id,
                "old leaf ownership survives replacement"
            );
            for name in ["new-root", "other-root"] {
                let der = pki.crl_der(pki.local_issuer(name)?, now + 3)?;
                let (_, crl) = CertificateRevocationList::from_der(&der)?;
                assert!(
                    crl.iter_revoked_certificates().next().is_none(),
                    "replacement CRL never adopts old leaf revocation"
                );
            }
            let mut corrupt = pki.clone();
            corrupt
                .issued
                .get_mut(&serial)
                .ok_or("old leaf")?
                .local_issuer_id = pki.local_issuer("new-root")?.issuer_id.clone();
            assert!(
                corrupt.validate("", "pki/", now + 2).is_err(),
                "persisted leaf cannot substitute a different signer"
            );
        }
        Ok(())
    }
}
