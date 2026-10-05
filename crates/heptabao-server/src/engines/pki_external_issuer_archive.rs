//! Strict public signer history. This never contains a KMS reference, grant,
//! private key, alias or issuer-selection capability. The private leaf owner
//! independently commits to the entire captured issuer, including actual IDs
//! and original signed CA bytes, so same-key certificate renewal is distinct.
use super::*;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct ExternalPublicIssuer {
    pub(super) issuer_id: String,
    pub(super) key_id: String,
    pub(super) public_key: ExternalPkiPublicKey,
    pub(super) common_name: String,
    serial: String,
    pub(super) not_before: u64,
    pub(super) not_after: u64,
    pub(super) certificate_der: Vec<u8>,
    dns_san: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parents: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(in crate::engines::pki) struct ExternalLeafIssuerOwner {
    issuer_id: String,
    issuer_sha256: [u8; 32],
}

impl ExternalPublicIssuer {
    pub(super) fn ca_chain_der(&self) -> Vec<Vec<u8>> {
        std::iter::once(self.certificate_der.clone())
            .chain(self.parents.iter().flatten().cloned())
            .collect()
    }
    pub(super) fn has_intermediate_chain(&self) -> bool {
        self.parents.is_some()
    }
    pub(super) fn capture(root: &RootCa, key: &ExternalKey) -> Result<Self> {
        if !root.is_external()
            || !root.issuer_id.is_empty()
            || !root.key_id.is_empty()
            || root.local_fields.is_some()
            || root.local_chain.is_some()
        {
            return Err(bad(
                "external PKI public issuer has private or local ownership",
            ));
        }
        let captured = Self {
            issuer_id: key.issuer_id.clone(),
            key_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
            common_name: root.common_name.clone(),
            serial: root.serial.clone(),
            not_before: root.not_before,
            not_after: root.not_after,
            certificate_der: root.certificate_der.clone(),
            dns_san: key.dns_san,
            parents: key
                .intermediate_owner
                .as_ref()
                .map(|owner| owner.parents.clone()),
        };
        captured.validate()?;
        Ok(captured)
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.public_key.validate()?;
        if !valid_identifier(&self.issuer_id)
            || !valid_identifier(&self.key_id)
            || self.issuer_id == self.key_id
            || !common_name_valid(&self.common_name)
            || self.parents.is_none() && self.dns_san && !valid_domain(&self.common_name)
            || self.not_before >= self.not_after
            || self.parents.is_none() && self.not_after - self.not_before > MAX_TTL + 120
            || serial_bytes(&self.serial).is_err()
            || self.certificate_der.is_empty()
            || self.certificate_der.len() > 64 * 1024
        {
            return Err(bad("invalid archived external PKI public issuer"));
        }
        if let Some(parents) = &self.parents {
            return intermediate::validate_public_ca(
                &self.certificate_der,
                &self.public_key,
                intermediate::ExternalCaIdentity {
                    common_name: &self.common_name,
                    serial: &self.serial,
                    not_before: self.not_before,
                    not_after: self.not_after,
                },
                parents,
            );
        }
        let tbs = external_root_tbs(
            ExternalRootSpec {
                serial: &self.serial,
                issuer_cn: &self.common_name,
                subject_cn: &self.common_name,
                public_key: &self.public_key,
                not_before: self.not_before,
                not_after: self.not_after,
            },
            self.dns_san,
        )?;
        validate_signed_der(&self.public_key, &tbs, &self.certificate_der)
    }
    pub(super) fn owner(&self) -> Result<ExternalLeafIssuerOwner> {
        let encoded = serde_json::to_vec(self)
            .map_err(|_| bad("external PKI issuer owner encoding failed"))?;
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        digest.update(b"heptabao/external-pki/public-issuer-owner/v1\0");
        digest.update(&encoded);
        let issuer_sha256 = digest
            .finish()
            .as_ref()
            .try_into()
            .map_err(|_| bad("external PKI issuer owner digest failed"))?;
        Ok(ExternalLeafIssuerOwner {
            issuer_id: self.issuer_id.clone(),
            issuer_sha256,
        })
    }
}

impl Pki {
    pub(in crate::engines::pki) fn external_pki_identifiers_in_use(
        &self,
        issuer: &str,
        key: &str,
    ) -> bool {
        self.external
            .root
            .iter()
            .chain(self.external.intermediate.iter().map(|csr| &csr.key))
            .any(|existing| existing.issuer_id == issuer || existing.key_id == key)
            || self
                .external
                .signer_history
                .as_ref()
                .is_some_and(|history| history.identifiers_in_use(issuer, key))
            || self
                .external
                .archived_issuers
                .values()
                .any(|existing| existing.issuer_id == issuer || existing.key_id == key)
    }
    pub(super) fn captured_external_issuer(&self) -> Result<ExternalPublicIssuer> {
        self.validate_external_state()?;
        ExternalPublicIssuer::capture(
            self.root
                .as_ref()
                .ok_or_else(|| bad("external PKI issuer missing"))?,
            self.external
                .root
                .as_ref()
                .ok_or_else(|| bad("external PKI key missing"))?,
        )
    }
    pub(super) fn admit_external_issuer_archive(
        &self,
        issuer: &ExternalPublicIssuer,
    ) -> Result<()> {
        issuer.validate()?;
        if let Some(original) = self.external.archived_issuers.get(&issuer.issuer_id) {
            if original != issuer {
                return Err(bad("archived external PKI issuer identity changed"));
            }
        } else if self.external.archived_issuers.len() >= MAX_ISSUED {
            return Err(error(
                507,
                "external PKI public issuer archive capacity exhausted",
            ));
        }
        Ok(())
    }
}
