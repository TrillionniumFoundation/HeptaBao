//! A signed CA is owned only by the exact pending, remotely verified CSR key.
//! Public parent certificates cannot introduce a provider reference or grant.
use super::super::local_intermediate as local;
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::engines::pki) struct ExternalIntermediateOwner {
    csr_der: Vec<u8>,
    pub(super) parents: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub(super) struct PreparedExternalImport {
    pub(super) pending: ExternalCsr,
    root: RootCa,
    key: ExternalKey,
    public_parents: local::ExternalPublicCaPlans,
    existing_parents: Vec<String>,
}

pub(super) struct ExternalCaIdentity<'a> {
    pub(super) common_name: &'a str,
    pub(super) serial: &'a str,
    pub(super) not_before: u64,
    pub(super) not_after: u64,
}

pub(super) fn validate_public_ca(
    der: &[u8],
    public: &ExternalPkiPublicKey,
    identity: ExternalCaIdentity<'_>,
    parents: &[Vec<u8>],
) -> Result<()> {
    let ExternalCaIdentity {
        common_name,
        serial,
        not_before,
        not_after,
    } = identity;
    let cert = local::certificate(der)?;
    if cert.public_key().raw != public.spki()?
        || local::common_name(cert.subject())? != common_name
        || normalize_serial(&cert.raw_serial_as_string())? != serial
        || u64::try_from(cert.validity().not_before.timestamp()).ok() != Some(not_before)
        || u64::try_from(cert.validity().not_after.timestamp()).ok() != Some(not_after)
        || not_before >= not_after
        || parents.is_empty()
    {
        return Err(bad("external intermediate signed CA ownership changed"));
    }
    local::validate_chain(der, parents)?;
    let terminal = parents
        .last()
        .ok_or_else(|| bad("external CA parent missing"))?;
    // This first finite route requires an actual verified terminal root. A
    // missing parent is not replaced with an invented self-signature.
    local::certificate_signed_by(terminal, terminal)
}

impl ExternalIntermediateOwner {
    pub(super) fn validate(&self, root: &RootCa, key: &ExternalKey) -> Result<()> {
        let csr = local::parse_csr(&self.csr_der)?;
        if csr.certification_request_info.subject_pki.raw != key.public_key.spki()? {
            return Err(bad("external intermediate CSR key changed"));
        }
        validate_public_ca(
            &root.certificate_der,
            &key.public_key,
            ExternalCaIdentity {
                common_name: &root.common_name,
                serial: &root.serial,
                not_before: root.not_before,
                not_after: root.not_after,
            },
            &self.parents,
        )
    }
}

impl Pki {
    pub(in crate::engines::pki) fn external_ca_chain_pem(
        &self,
        root: &RootCa,
    ) -> Result<Vec<String>> {
        if !root.is_external() {
            return Ok(root.local_ca_chain_pem());
        }
        let mut chain = vec![public::stored_pem("CERTIFICATE", &root.certificate_der)];
        if let Some((key, _)) = self
            .external_signers()
            .find(|(_, ca)| ca.certificate_der == root.certificate_der)
            && let Some(owner) = &key.intermediate_owner
        {
            owner.validate(root, key)?;
            chain.extend(
                owner
                    .parents
                    .iter()
                    .map(|der| public::stored_pem("CERTIFICATE", der)),
            );
        }
        Ok(chain)
    }

    pub(super) fn prepare_external_import(
        &self,
        body: &Value,
        now: u64,
    ) -> Result<ExternalPkiTemplate> {
        reject_unknown(body, &["certificate"])?;
        let pending = self
            .external
            .intermediate
            .as_ref()
            .ok_or_else(|| bad("external intermediate CSR key missing"))?
            .clone();
        let objects = local::pem_blocks(string(body, "certificate")?, "CERTIFICATE")?;
        let matching = objects
            .iter()
            .filter(|der| {
                local::certificate(der).is_ok_and(|cert| {
                    pending
                        .key
                        .public_key
                        .spki()
                        .is_ok_and(|spki| cert.public_key().raw == spki)
                })
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(bad("one signed CA must match the pending external CSR key"));
        }
        let der = matching[0];
        let cert = local::certificate(der)?;
        let parents = local::available_ca_chain(der, &objects)?;
        let mut key = pending.key.clone();
        key.issuer_id = identifier()?;
        key.issuer_name.clear();
        key.intermediate_owner = Some(Box::new(ExternalIntermediateOwner {
            csr_der: pending.csr_der.clone(),
            parents,
        }));
        let root = RootCa {
            leaf_not_after_behavior: None,
            common_name: local::common_name(cert.subject())?,
            issuer_id: String::new(),
            key_id: String::new(),
            local_fields: None,
            pkcs8: Vec::new(),
            local_material: None,
            local_chain: None,
            certificate_der: der.clone(),
            serial: normalize_serial(&cert.raw_serial_as_string())?,
            not_before: u64::try_from(cert.validity().not_before.timestamp())
                .map_err(|_| bad("external CA pre-epoch validity is unsupported"))?,
            not_after: u64::try_from(cert.validity().not_after.timestamp())
                .map_err(|_| bad("external CA validity is invalid"))?,
        };
        key.intermediate_owner
            .as_ref()
            .ok_or_else(|| bad("external CA owner missing"))?
            .validate(&root, &key)?;
        if root.not_after <= now {
            return Err(bad("external intermediate has expired"));
        }
        self.admit_external_root_generation(&json!({"key_name":key.key_name}))?;
        let (public_parents, existing_parents) =
            self.prepare_external_public_parents(&objects, der)?;
        Ok(ExternalPkiTemplate {
            reference: key.reference.clone(),
            operation: "import",
            output_format: RootOutputFormat::Pem,
            common_name: root.common_name.clone(),
            serial: root.serial.clone(),
            not_before: root.not_before,
            not_after: root.not_after,
            key_id: key.key_id.clone(),
            issuer_id: key.issuer_id.clone(),
            key_name: key.key_name.clone(),
            issuer_name: String::new(),
            dns_san: key.dns_san,
            generated_at: now,
            consumption: None,
            bound_public: Some(key.public_key.clone()),
            bound_issuer: None,
            signed_ca: None,
            imported: Some(Box::new(PreparedExternalImport {
                pending,
                root,
                key,
                public_parents,
                existing_parents,
            })),
        })
    }

    pub(super) fn publish_external_import(
        &mut self,
        mut material: ExternalPkiMaterial,
        signatures: &[Zeroizing<Vec<u8>>],
        now: u64,
    ) -> Result<EngineResponse> {
        let imported = material
            .template
            .imported
            .take()
            .ok_or_else(|| bad("external CA import missing"))?;
        let current = self
            .external
            .intermediate
            .as_ref()
            .ok_or_else(|| error(503, "external CSR changed before publication"))?;
        let original =
            serde_json::to_vec(&imported.pending).map_err(|_| bad("CSR owner encoding failed"))?;
        let actual = serde_json::to_vec(current).map_err(|_| bad("CSR owner encoding failed"))?;
        if original != actual
            || material.public_key != imported.key.public_key
            || imported.root.not_after <= now
        {
            return Err(error(503, "external CSR changed before publication"));
        }
        imported
            .key
            .intermediate_owner
            .as_ref()
            .ok_or_else(|| bad("external CA owner missing"))?
            .validate(&imported.root, &imported.key)?;
        let mut crls = material
            .root_crls
            .take()
            .ok_or_else(|| bad("external CA CRL effects missing"))?;
        crls.sign(&imported.root.common_name, &material.public_key, signatures)?;
        let mut mapping = serde_json::Map::new();
        mapping.insert(imported.key.issuer_id.clone(), json!(imported.key.key_id));
        let mut ids = vec![imported.key.issuer_id.clone()];
        for (id, _, _) in &imported.public_parents {
            mapping.insert(id.clone(), json!(""));
            ids.push(id.clone());
        }
        for id in &imported.existing_parents {
            mapping.insert(id.clone(), json!(""));
        }
        self.publish_external_public_parents(&imported.public_parents)?;
        self.external.intermediate = None;
        self.external
            .signer_history
            .get_or_insert_with(Default::default);
        self.install_external_root(imported.root, imported.key, crls, now)?;
        let mut response = ok(
            json!({"mapping":mapping,"imported_keys":Value::Null,"existing_keys":Value::Null,
            "imported_issuers":ids,"existing_issuers":if imported.existing_parents.is_empty(){Value::Null}else{json!(imported.existing_parents)}}),
            true,
        );
        response.body["warnings"] = json!([
            "This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information."
        ]);
        Ok(response)
    }
}
