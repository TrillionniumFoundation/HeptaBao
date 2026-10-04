//! Owned local issuers. The root slot is the selected default; the remaining
//! roots retain their actual private key and certificate in encrypted state.
use super::*;

const MAX_LOCAL_ISSUERS: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LocalIssuers {
    pub(super) other: BTreeMap<String, RootCa>,
    pub(super) default_follows_latest_issuer: bool,
    #[serde(default)]
    orphan_keys: BTreeMap<String, RootCa>,
    #[serde(default)]
    certificates: BTreeMap<String, Vec<u8>>,
}

impl Pki {
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
                return Err(bad("PKI key name already exists"));
            }
        }
        Ok(())
    }

    pub(super) fn publish_local_root(&mut self, next: RootCa) -> Result<()> {
        if self
            .local_keys()
            .any(|root| root.issuer_id == next.issuer_id || root.key_id == next.key_id)
        {
            return Err(error(503, "PKI identifier collision"));
        }
        let Some(current) = self.root.as_mut() else {
            if let Some(state) = &mut self.local_issuers {
                state
                    .certificates
                    .insert(next.serial.clone(), next.certificate_der.clone());
            }
            self.root = Some(next);
            return Ok(());
        };
        // Historical roots predate issuer IDs. Generate both before changing
        // either field; their original private key and certificate stay owned.
        if current.issuer_id.is_empty() {
            let issuer = random_pki_id()?;
            let key = random_pki_id()?;
            if issuer == next.issuer_id || key == next.key_id {
                return Err(error(503, "PKI identifier collision"));
            }
            current.issuer_id = issuer;
            current.key_id = key;
        }
        let state = self.local_issuers.get_or_insert_with(|| {
            Box::new(LocalIssuers {
                other: BTreeMap::new(),
                default_follows_latest_issuer: false,
                orphan_keys: BTreeMap::new(),
                certificates: BTreeMap::new(),
            })
        });
        for issued in self.issued.values_mut() {
            if issued.local_issuer_id.is_empty() {
                issued.local_issuer_id = current.issuer_id.clone();
            }
        }
        state
            .certificates
            .insert(current.serial.clone(), current.certificate_der.clone());
        state
            .certificates
            .insert(next.serial.clone(), next.certificate_der.clone());
        if state.default_follows_latest_issuer {
            let previous = self
                .root
                .replace(next)
                .ok_or_else(|| error(503, "PKI default changed"))?;
            state.other.insert(previous.issuer_id.clone(), previous);
        } else {
            state.other.insert(next.issuer_id.clone(), next);
        }
        Ok(())
    }

    pub(super) fn validate_local_issuers(&self) -> Result<()> {
        let Some(state) = &self.local_issuers else {
            return Ok(());
        };
        if self.root.as_ref().is_some_and(RootCa::is_external)
            || self.local_roots().count() > MAX_LOCAL_ISSUERS
            || self.local_keys().count() > MAX_ISSUED
            || state.certificates.len() > MAX_ISSUED
        {
            return Err(bad("invalid local PKI issuer state"));
        }
        let mut issuer_ids = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        let mut issuer_names = BTreeSet::new();
        let mut key_names = BTreeSet::new();
        for root in self.local_keys() {
            if root.is_external()
                || root.issuer_id.is_empty()
                || root.key_id.is_empty()
                || !valid_pki_id(&root.issuer_id)
                || !valid_pki_id(&root.key_id)
                || !issuer_ids.insert(&root.issuer_id)
                || !key_ids.insert(&root.key_id)
                || !external::common_name_valid(&root.common_name)
                || root.not_before >= root.not_after
                || root.not_after - root.not_before > MAX_TTL * 2
                || serial_bytes(&root.serial).is_err()
                || root.certificate_der.len() > 64 * 1024
                || root.pkcs8.len() > 4096
            {
                return Err(bad("invalid local PKI issuer ownership"));
            }
            if let Some(fields) = &root.local_fields {
                fields.validate()?;
                if self
                    .local_roots()
                    .any(|issuer| issuer.issuer_id == root.issuer_id)
                    && !fields.issuer_name.is_empty()
                    && !issuer_names.insert(&fields.issuer_name)
                    || !fields.key_name.is_empty() && !key_names.insert(&fields.key_name)
                {
                    return Err(bad("duplicate local PKI issuer aliases"));
                }
            }
            root.local_key()?
                .public()?
                .validate_certificate(&root.certificate_der)?;
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
                json!({
                    "default":self.root.as_ref().map_or("",|root|root.issuer_id.as_str()),
                    "default_follows_latest_issuer":self.local_issuers.as_ref()
                        .is_some_and(|state|state.default_follows_latest_issuer)
                }),
                false,
            ));
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(body, &["default", "default_follows_latest_issuer"])?;
        if self.local_roots().next().is_none()
            || self.root.as_ref().is_some_and(RootCa::is_external)
        {
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
                value
                    .as_str()
                    .ok_or_else(|| bad("PKI default issuer must be a string"))
            })
            .transpose()?
            .map(|reference| {
                self.local_issuer(reference)
                    .map(|root| root.issuer_id.clone())
            })
            .transpose()?;
        let follows = optional_bool(body, "default_follows_latest_issuer")?;
        let change_default = selected.as_ref().is_some_and(|id| {
            self.root
                .as_ref()
                .is_none_or(|current| id != &current.issuer_id)
        });
        let before_follows = self
            .local_issuers
            .as_ref()
            .is_some_and(|state| state.default_follows_latest_issuer);
        let change_follows = follows.is_some_and(|value| value != before_follows);
        if change_default || change_follows {
            let state = self.local_issuers.get_or_insert_with(|| {
                Box::new(LocalIssuers {
                    other: BTreeMap::new(),
                    default_follows_latest_issuer: false,
                    orphan_keys: BTreeMap::new(),
                    certificates: BTreeMap::new(),
                })
            });
            if change_default {
                let id = selected.ok_or_else(|| bad("PKI default issuer is unavailable"))?;
                let next = state
                    .other
                    .remove(&id)
                    .ok_or_else(|| bad("PKI default issuer is unavailable"))?;
                if let Some(previous) = self.root.replace(next) {
                    state.other.insert(previous.issuer_id.clone(), previous);
                }
            }
            if let Some(value) = follows {
                state.default_follows_latest_issuer = value;
            }
        }
        let mut response = self.local_issuer_config("GET", &json!({}))?;
        response.mutated = change_default || change_follows;
        Ok(response)
    }
    fn local_keys(&self) -> impl Iterator<Item = &RootCa> {
        self.local_roots().chain(
            self.local_issuers
                .iter()
                .flat_map(|state| state.orphan_keys.values()),
        )
    }

    pub(super) fn local_key_list(&self, body: &Value) -> Result<EngineResponse> {
        reject_unknown(body, &[])?;
        let mut info = serde_json::Map::new();
        for root in self.local_keys() {
            let name = root
                .local_fields
                .as_ref()
                .map_or("", |fields| fields.key_name.as_str());
            info.insert(root.key_id.clone(), json!({"key_name":name}));
        }
        if info.is_empty() {
            return Err(not_found());
        }
        Ok(ok(
            json!({"keys":info.keys().collect::<Vec<_>>(),"key_info":info}),
            false,
        ))
    }

    pub(super) fn local_issuer_delete(
        &mut self,
        reference: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &[])?;
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
                default_follows_latest_issuer: false,
            })
        });
        state
            .certificates
            .insert(removed.serial.clone(), removed.certificate_der.clone());
        state.orphan_keys.insert(removed.key_id.clone(), removed);
        Ok(ok(Value::Null, true))
    }

    pub(super) fn delete_local_roots(&mut self) -> bool {
        let changed = self.root.is_some()
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
                    default_follows_latest_issuer: false,
                })
            });
            state
                .certificates
                .insert(root.serial.clone(), root.certificate_der.clone());
        }
        if let Some(state) = &mut self.local_issuers {
            for root in state.other.values() {
                state
                    .certificates
                    .insert(root.serial.clone(), root.certificate_der.clone());
            }
            state.other.clear();
            state.orphan_keys.clear();
        }
        changed
    }

    pub(super) fn local_certificate(&self, serial: &str) -> Option<&[u8]> {
        self.local_roots()
            .find(|root| root.serial == serial)
            .map(|root| root.certificate_der.as_slice())
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
        assert!(
            serde_json::to_vec(&pki)? == *before,
            "rejected management preserves state"
        );
        pki.local_issuer_config(
            "POST",
            &json!({"default":"root-b","default_follows_latest_issuer":true}),
        )?;
        pki.handle_admin("POST","roles/web",&json!({"allowed_domains":["example.test"],"allow_subdomains":true,"issuer_ref":"root-a","max_ttl":"10m"}),now)?;
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
            pki.local_issuer_config("GET", &json!({}))?.body["data"]["default_follows_latest_issuer"]
                == true,
            "delete retains configuration"
        );
        let certs = pki.certificate_list(&json!({}))?.body.clone();
        pki.delete_local_roots();
        assert!(
            pki.certificate_list(&json!({}))?.body == certs
                && pki.roles.len() == 1
                && pki.issued.len() == 2
                && pki.local_key_list(&json!({})).is_err(),
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
}
