//! Private signer history is published only from an actual verified root effect.
//! Public leaf archives never create signing authority. Each request still binds
//! the selected original KMS reference to current namespace grants and enrollment.
use super::*;
const MAX_EXTERNAL_ISSUERS: usize = 256;

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct ExternalSignerHistory {
    other: BTreeMap<String, ExternalSigner>,
    default_follows_latest_issuer: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalSigner {
    key: ExternalKey,
    root: RootCa,
    crls: CrlSet,
    owner: [u8; 32],
}

impl ExternalSigner {
    fn owner_for(key: &ExternalKey, root: &RootCa) -> Result<[u8; 32]> {
        let encoded = serde_json::to_vec(&(key, root))
            .map_err(|_| bad("external signer owner encoding failed"))?;
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        digest.update(b"heptabao/external-pki/private-signer-history/v1\0");
        digest.update(&encoded);
        digest
            .finish()
            .as_ref()
            .try_into()
            .map_err(|_| bad("external signer owner digest failed"))
    }
    fn new(key: ExternalKey, root: RootCa, crls: CrlSet) -> Result<Self> {
        let owner = Self::owner_for(&key, &root)?;
        Ok(Self {
            key,
            root,
            crls,
            owner,
        })
    }
}

impl ExternalSignerHistory {
    pub(super) fn clear_private_signers(&mut self) {
        self.other.clear();
    }
    pub(super) fn identifiers_in_use(&self, issuer: &str, key: &str) -> bool {
        self.other
            .values()
            .any(|s| s.key.issuer_id == issuer || s.key.key_id == key)
    }
}

impl Pki {
    pub(in crate::engines) fn has_external_signer_history(&self) -> bool {
        // Some(empty) retains the owner after all private signing keys retire.
        self.external.signer_history.is_some()
    }

    pub(super) fn external_signers(&self) -> impl Iterator<Item = (&ExternalKey, &RootCa)> {
        self.external.root.iter().zip(self.root.iter()).chain(
            self.external.signer_history.iter().flat_map(|history| {
                history
                    .other
                    .values()
                    .map(|signer| (&signer.key, &signer.root))
            }),
        )
    }

    pub(in crate::engines) fn prepare_related_external_crls(
        &self,
        main: &ExternalPkiTemplate,
        mount: &str,
        context: PkiRequestContext<'_>,
    ) -> Result<Vec<ExternalPkiTemplate>> {
        if !matches!(main.operation, "root" | "import")
            && !matches!(main.consumption, Some(ConsumptionTemplate::Crl { .. }))
        {
            return Ok(Vec::new());
        }
        // Only actual private signers can refresh a CRL. A public archive never
        // creates a provider reference, and every reference is granted anew by
        // Engines before any of this request's provider calls can enter.
        self.external_signers()
            .filter(|(key, _)| key.issuer_id != main.issuer_id)
            .map(|(key, _)| {
                let mut selected = self.clone();
                selected.select_external_default(&key.issuer_id)?;
                selected
                    .prepare_external_consumption(
                        "GET",
                        "crl/rotate",
                        &json!({}),
                        mount,
                        PkiRequestContext {
                            owner: context.owner,
                            time: context.time,
                            clock: context.clock,
                            identity_templates: context.identity_templates,
                        },
                    )?
                    .ok_or_else(|| bad("related external CRL plan missing"))
            })
            .collect()
    }

    pub(in crate::engines::pki) fn external_issuer_key(
        &self,
        reference: &str,
    ) -> Result<&ExternalKey> {
        if reference == "default" {
            return self
                .external
                .root
                .as_ref()
                .ok_or_else(|| error(500, "issuer reference is unavailable"));
        }
        self.external_signers()
            .map(|(key, _)| key)
            .find(|key| key.issuer_id == reference)
            .or_else(|| {
                self.external_signers()
                    .map(|(key, _)| key)
                    .find(|key| !key.issuer_name.is_empty() && key.issuer_name == reference)
            })
            .ok_or_else(|| error(500, "issuer reference is unavailable"))
    }

    pub(in crate::engines::pki) fn external_issuer_root(&self, reference: &str) -> Result<&RootCa> {
        let key = self.external_issuer_key(reference)?;
        self.external_signers()
            .find(|(candidate, _)| candidate.issuer_id == key.issuer_id)
            .map(|(_, root)| root)
            .ok_or_else(|| error(500, "issuer reference is unavailable"))
    }

    pub(super) fn select_external_default(&mut self, reference: &str) -> Result<()> {
        let id = self.external_issuer_key(reference)?.issuer_id.clone();
        if self
            .external
            .root
            .as_ref()
            .is_some_and(|key| key.issuer_id == id)
        {
            return Ok(());
        }
        let history = self
            .external
            .signer_history
            .as_mut()
            .ok_or_else(|| bad("external signing history missing"))?;
        let next = history
            .other
            .get(&id)
            .cloned()
            .ok_or_else(|| bad("external signing issuer missing"))?;
        let current = ExternalSigner::new(
            self.external
                .root
                .clone()
                .ok_or_else(|| bad("external default key missing"))?,
            self.root
                .clone()
                .ok_or_else(|| bad("external default root missing"))?,
            self.external
                .crls
                .clone()
                .ok_or_else(|| bad("external default CRL missing"))?,
        )?;
        history.other.remove(&id);
        history.other.insert(current.key.issuer_id.clone(), current);
        self.root = Some(next.root);
        self.external.root = Some(next.key);
        self.external.crls = Some(next.crls);
        Ok(())
    }

    pub(super) fn admit_external_root_generation(&self, body: &Value) -> Result<()> {
        if self.root.as_ref().is_some_and(|root| !root.is_external()) {
            return Err(error(501, "external root cannot replace a local issuer"));
        }
        if self.external_signers().count() >= MAX_EXTERNAL_ISSUERS {
            return Err(error(507, "external PKI issuer capacity exhausted"));
        }
        for (field, issuer) in [("issuer_name", true), ("key_name", false)] {
            let name = optional_name(body, field)?;
            if !name.is_empty()
                && self.external_signers().any(|(key, _)| {
                    if issuer {
                        key.issuer_name == name
                    } else {
                        key.key_name == name
                    }
                })
            {
                return Err(bad("PKI issuer or key name is already in use"));
            }
        }
        Ok(())
    }

    pub(super) fn install_external_root(
        &mut self,
        root: RootCa,
        key: ExternalKey,
        crls: CrlSet,
        now: u64,
    ) -> Result<()> {
        if self.external.root.is_some() {
            self.retire_external_leaf_issuer(now)?;
            let history = self
                .external
                .signer_history
                .get_or_insert_with(Default::default);
            let current = ExternalSigner::new(
                self.external
                    .root
                    .clone()
                    .ok_or_else(|| bad("external key missing"))?,
                self.root
                    .clone()
                    .ok_or_else(|| bad("external root missing"))?,
                self.external
                    .crls
                    .clone()
                    .ok_or_else(|| bad("external CRL missing"))?,
            )?;
            if history.default_follows_latest_issuer {
                history.other.insert(current.key.issuer_id.clone(), current);
            } else {
                history
                    .other
                    .insert(key.issuer_id.clone(), ExternalSigner::new(key, root, crls)?);
                return Ok(());
            }
        }
        self.root = Some(root);
        self.external.root = Some(key);
        self.external.crls = Some(crls);
        Ok(())
    }

    pub(in crate::engines::pki) fn external_issuer_config(
        &mut self,
        method: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        if method == "GET" {
            reject_unknown(body, &[])?;
            return Ok(ok(
                json!({"default":self.external.root.as_ref().map_or("", |key| key.issuer_id.as_str()),
                "default_follows_latest_issuer":self.external.signer_history.as_ref().is_some_and(|h| h.default_follows_latest_issuer)}),
                false,
            ));
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(body, &["default", "default_follows_latest_issuer"])?;
        let selected = body
            .get("default")
            .map(|value| {
                let reference = value
                    .as_str()
                    .ok_or_else(|| bad("PKI default issuer must be a string"))?;
                if reference.is_empty() || reference == "default" {
                    return Err(bad("default issuer must be specified"));
                }
                self.external_issuer_key(reference)
                    .map(|key| key.issuer_id.clone())
                    .map_err(|_| bad("default issuer reference is unavailable"))
            })
            .transpose()?;
        let follows = optional_bool(body, "default_follows_latest_issuer")?;
        let change_default = selected.as_ref().is_some_and(|id| {
            self.external
                .root
                .as_ref()
                .is_none_or(|key| key.issuer_id != *id)
        });
        let change_follows = follows.is_some_and(|value| {
            value
                != self
                    .external
                    .signer_history
                    .as_ref()
                    .is_some_and(|h| h.default_follows_latest_issuer)
        });
        if change_default {
            self.select_external_default(
                selected.as_deref().ok_or_else(|| bad("default missing"))?,
            )?;
        }
        if change_follows {
            self.external
                .signer_history
                .get_or_insert_with(Default::default)
                .default_follows_latest_issuer =
                follows.ok_or_else(|| bad("follow policy missing"))?;
        }
        let mut response = self.external_issuer_config("GET", &json!({}))?;
        response.mutated = change_default || change_follows;
        Ok(response)
    }

    pub(super) fn external_route_issuer(&self, path: &str, body: &Value) -> Result<Option<String>> {
        let route = path
            .strip_prefix("issue/")
            .or_else(|| path.strip_prefix("sign/"))
            .map(|role| (None, role))
            .or_else(|| {
                Self::issuer_issue_route(path).map(|(reference, role)| (Some(reference), role))
            })
            .or_else(|| {
                Self::issuer_sign_route(path).map(|(reference, role)| (Some(reference), role))
            });
        let reference = if let Some((explicit, role)) = route {
            let role = self
                .roles
                .get(role)
                .ok_or_else(|| bad("unknown PKI role"))?;
            explicit
                .unwrap_or(if role.issuer_ref.is_empty() {
                    "default"
                } else {
                    &role.issuer_ref
                })
                .to_owned()
        } else if path == "revoke" {
            let serial = normalize_serial(string(body, "serial_number")?)?;
            self.external_leaf_issuer_reference(&serial)?.to_owned()
        } else if path == "crl/rotate" {
            "default".to_owned()
        } else {
            return Ok(None);
        };
        Ok(Some(
            self.external_issuer_key(&reference)?.issuer_id.clone(),
        ))
    }

    pub(in crate::engines::pki) fn external_issuers_descriptor(&self) -> EngineResponse {
        let mut info = serde_json::Map::new();
        for (key, root) in self.external_signers() {
            info.insert(key.issuer_id.clone(), json!({"is_default":self.external.root.as_ref().is_some_and(|active| active.issuer_id == key.issuer_id),
                "issuer_name":key.issuer_name,"key_id":key.key_id,"serial_number":formatted_serial(&root.serial)}));
        }
        ok(
            json!({"keys":info.keys().collect::<Vec<_>>(),"key_info":info}),
            false,
        )
    }

    pub(in crate::engines::pki) fn external_issuer_crl_der(
        &self,
        reference: &str,
        delta: bool,
        now: u64,
    ) -> Result<&[u8]> {
        let key = self.external_issuer_key(reference)?;
        if self
            .external
            .root
            .as_ref()
            .is_some_and(|active| active.issuer_id == key.issuer_id)
        {
            return self.external_crl_der(delta, now)?.ok_or_else(not_found);
        }
        let signer = self
            .external
            .signer_history
            .as_ref()
            .and_then(|h| h.other.get(&key.issuer_id))
            .ok_or_else(not_found)?;
        let crls = &signer.crls;
        if crls.full.expires <= now
            || crls.delta.expires <= now
            || self.issued.iter().any(|(serial, issued)| {
                issued.expires > now
                    && self
                        .external_leaf_issuer_reference(serial)
                        .is_ok_and(|id| id == key.issuer_id)
                    && issued
                        .revoked_at
                        .is_some_and(|at| crls.full.revoked.get(serial).copied() != Some(at))
            })
        {
            return Err(error(503, "external CRL rebuild is required"));
        }
        Ok(&crls.selected(delta).der)
    }

    pub(super) fn validate_external_signer_history(&self, clock: u64) -> Result<()> {
        let Some(history) = &self.external.signer_history else {
            return Ok(());
        };
        if history.other.len() >= MAX_EXTERNAL_ISSUERS
            || !history.other.is_empty() && self.external.root.is_none()
        {
            return Err(bad(
                "external signing history has no default or exceeds bounds",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        let mut issuer_names = BTreeSet::new();
        let mut key_names = BTreeSet::new();
        for (key, _) in self.external_signers() {
            if !ids.insert(&key.issuer_id)
                || !key_ids.insert(&key.key_id)
                || !key.issuer_name.is_empty() && !issuer_names.insert(&key.issuer_name)
                || !key.key_name.is_empty() && !key_names.insert(&key.key_name)
                || self.local_pki_identifiers_in_use(&key.issuer_id, &key.key_id)
            {
                return Err(bad("external signer history identifier or name collision"));
            }
        }
        for (id, signer) in &history.other {
            if signer.owner != ExternalSigner::owner_for(&signer.key, &signer.root)? {
                return Err(bad("external signer private owner differs"));
            }
            if id != &signer.key.issuer_id {
                return Err(bad("external signer history identity differs"));
            }
            // Validate private reference, exact public key, original signed CA
            // and issuer-specific CRL through the existing cryptographic lane.
            let mut selected = self.clone();
            // Keep the existing format94 owner marker while validating this
            // single signer. The validator below does not recurse into history.
            selected.external.signer_history = Some(Box::default());
            selected.root = Some(signer.root.clone());
            selected.external.root = Some(signer.key.clone());
            selected.external.crls = Some(signer.crls.clone());
            selected.validate_external_state()?;
            let issuer = selected.captured_external_issuer()?;
            signer
                .crls
                .validate(&issuer.common_name, &issuer.public_key, clock)?;
            if signer.crls.full.revoked.iter().any(|(serial, at)| {
                self.issued.get(serial).is_some_and(|issued| {
                    !self
                        .external_leaf_issuer_reference(serial)
                        .is_ok_and(|owner| owner == id)
                        || issued.revoked_at != Some(*at)
                })
            }) {
                return Err(bad("external historical CRL owner differs"));
            }
        }
        Ok(())
    }
}
