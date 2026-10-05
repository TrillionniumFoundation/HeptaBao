//! Remote CA signing shares the original provider and actor capsule with issue.
//! Only the verified CSR public key and admitted root fields control the TBS.
use super::super::local_intermediate as local;
use super::*;
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::FromDer,
};

const FIELDS: &[&str] = &[
    "csr",
    "common_name",
    "ttl",
    "format",
    "use_csr_values",
    "alt_names",
    "ip_sans",
    "uri_sans",
    "exclude_cn_from_sans",
    "ou",
    "organization",
    "country",
    "locality",
    "province",
    "street_address",
    "postal_code",
    "serial_number",
    "not_before_duration",
    "not_after",
    "max_path_length",
    "permitted_dns_domains",
];

#[derive(Clone)]
pub(super) struct PreparedExternalCaSign {
    public: LocalPublicKey,
    fields: RootFields,
    permitted: Vec<String>,
    common_name: String,
    serial: String,
    not_before: i64,
    expires: u64,
    issued: u64,
    issuer: ExternalPublicIssuer,
    format: RootOutputFormat,
}

impl PreparedExternalCaSign {
    pub(super) fn tbs(&self, public: &ExternalPkiPublicKey) -> Result<Vec<u8>> {
        self.issuer.validate()?;
        if self.issuer.public_key != *public {
            return Err(bad("signed CA original issuer public key changed"));
        }
        let issuer_name = root_fields::certificate_subject(&self.issuer.certificate_der)?;
        let ski = root_fields::certificate_key_identifier(&self.issuer.certificate_der)?;
        certificate_tbs_with(
            CertificateSpec {
                serial: &self.serial,
                issuer_cn: &self.issuer.common_name,
                subject_cn: &self.common_name,
                issuer_name_der: Some(&issuer_name),
                subject_name_der: Some(&self.fields.subject_der),
                public_key: &[],
                authority_key_id: ski.as_deref(),
                not_before: self.not_before,
                not_after: self.expires,
                is_ca: true,
                alt_names: &self.fields.dns_sans,
                email_sans: &self.fields.email_sans,
                ip_sans: &self.fields.ip_sans,
                uri_sans: &self.fields.uri_sans,
                exclude_cn_from_sans: self.fields.exclude_cn,
                max_path_length: self.fields.max_path_length,
                permitted_dns_domains: &self.permitted,
                role_leaf_profile: None,
            },
            &self.public.spki()?,
            &public.signature_algorithm(),
        )
    }
}

impl Pki {
    pub(in crate::engines::pki) fn external_ca_owner_certificate(&self, id: &str) -> Option<&[u8]> {
        self.external_signers()
            .find(|(key, _)| key.issuer_id == id)
            .map(|(_, root)| root.certificate_der.as_slice())
            .or_else(|| {
                self.external
                    .archived_issuers
                    .get(id)
                    .map(|issuer| issuer.certificate_der.as_slice())
            })
    }
    pub(super) fn external_sign_intermediate_route(path: &str) -> Option<&str> {
        let reference = path
            .strip_prefix("issuer/")?
            .strip_suffix("/sign-intermediate")?;
        (!reference.is_empty() && reference.len() <= 128 && !reference.contains('/'))
            .then_some(reference)
    }
    pub(super) fn prepare_external_ca_sign(
        &self,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<ExternalPkiTemplate> {
        let reference = if path == "root/sign-intermediate" {
            "default"
        } else {
            Self::external_sign_intermediate_route(path).ok_or_else(not_found)?
        };
        let key = self.external_issuer_key(reference)?;
        if self
            .external
            .root
            .as_ref()
            .is_some_and(|active| active.issuer_id != key.issuer_id)
        {
            let mut candidate = self.clone();
            candidate.select_external_default(&key.issuer_id)?;
            return candidate.prepare_external_ca_sign("root/sign-intermediate", body, now);
        }
        reject_unknown(body, FIELDS)?;
        let bytes = local::csr_from_body(body)?;
        let csr = local::parse_csr(&bytes)?;
        let issuer = self.captured_external_issuer()?;
        if now >= issuer.not_after {
            return Err(error(503, "PKI issuer has expired"));
        }
        let common_name = body
            .get("common_name")
            .map(|value| value.as_str().ok_or_else(|| bad("invalid CA common name")))
            .transpose()?
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or(local::common_name(&csr.certification_request_info.subject)?);
        let mut fields = RootFields::from_body(body, &common_name)?;
        if optional_bool(body, "use_csr_values")?.unwrap_or(false) {
            fields.subject_der = csr.certification_request_info.subject.as_raw().to_vec();
            fields.dns_sans.clear();
            fields.email_sans.clear();
            fields.ip_sans.clear();
            fields.uri_sans.clear();
            fields.exclude_cn = true;
            if let Some(extensions) = csr.requested_extensions() {
                for extension in extensions {
                    if let ParsedExtension::SubjectAlternativeName(names) = extension {
                        for name in &names.general_names {
                            match name {
                                GeneralName::DNSName(v) => fields.dns_sans.push((*v).to_owned()),
                                GeneralName::RFC822Name(v) => {
                                    fields.email_sans.push((*v).to_owned())
                                }
                                GeneralName::URI(v) => fields.uri_sans.push((*v).to_owned()),
                                GeneralName::IPAddress(v) => {
                                    let ip = if v.len() == 4 {
                                        IpAddr::V4(std::net::Ipv4Addr::from(
                                            <[u8; 4]>::try_from(*v)
                                                .map_err(|_| bad("invalid CSR IP SAN"))?,
                                        ))
                                    } else {
                                        IpAddr::V6(std::net::Ipv6Addr::from(
                                            <[u8; 16]>::try_from(*v)
                                                .map_err(|_| bad("invalid CSR IP SAN"))?,
                                        ))
                                    };
                                    fields.ip_sans.push(ip);
                                }
                                _ => return Err(bad("unsupported CSR SAN kind")),
                            }
                        }
                    }
                }
            }
        }
        let (_, parent) = x509_parser::prelude::X509Certificate::from_der(&issuer.certificate_der)
            .map_err(|_| bad("invalid CA issuer"))?;
        let constraints = parent
            .basic_constraints()
            .map_err(|_| bad("invalid CA constraints"))?;
        if constraints
            .as_ref()
            .is_some_and(|c| c.value.path_len_constraint == Some(0))
        {
            return Err(bad("issuer max path length is zero"));
        }
        if !body
            .as_object()
            .is_some_and(|o| o.contains_key("max_path_length"))
        {
            fields.max_path_length =
                constraints.and_then(|c| c.value.path_len_constraint.map(|n| n.saturating_sub(1)));
        }
        let permitted = string_list(body.get("permitted_dns_domains"))?;
        if permitted.len() > 64
            || permitted
                .iter()
                .any(|d| !valid_domain(d.strip_prefix('.').unwrap_or(d)))
        {
            return Err(bad("invalid permitted DNS domains"));
        }
        let public = LocalPublicKey::from_spki(csr.certification_request_info.subject_pki.raw)?;
        let expires = root_fields::root_expiration(body, now, self.max_ttl, self.default_ttl)?;
        let serial = external_serial()?;
        let not_before = role_time::signed_epoch(now.saturating_sub(fields.backdate))?;
        let prepared = PreparedExternalCaSign {
            public,
            fields,
            permitted,
            common_name,
            serial: serial.clone(),
            not_before,
            expires,
            issued: now,
            issuer: issuer.clone(),
            format: RootOutputFormat::from_body(body)?,
        };
        Ok(ExternalPkiTemplate {
            reference: key.reference.clone(),
            operation: "sign-intermediate",
            output_format: RootOutputFormat::Pem,
            common_name: issuer.common_name.clone(),
            serial,
            not_before: now,
            not_after: expires,
            key_id: key.key_id.clone(),
            issuer_id: key.issuer_id.clone(),
            key_name: key.key_name.clone(),
            issuer_name: key.issuer_name.clone(),
            dns_san: key.dns_san,
            generated_at: now,
            consumption: None,
            bound_public: Some(key.public_key.clone()),
            bound_issuer: Some(issuer),
            imported: None,
            signed_ca: Some(Box::new(prepared)),
            native_csr_body: None,
        })
    }
    pub(super) fn publish_external_ca_sign(
        &mut self,
        mut material: ExternalPkiMaterial,
        signatures: &[Zeroizing<Vec<u8>>],
        now: u64,
    ) -> Result<EngineResponse> {
        if self
            .external
            .root
            .as_ref()
            .is_some_and(|key| key.issuer_id != material.template.issuer_id)
        {
            let original = self
                .external
                .root
                .as_ref()
                .ok_or_else(|| bad("default missing"))?
                .issuer_id
                .clone();
            let mut candidate = self.clone();
            candidate.select_external_default(&material.template.issuer_id)?;
            let response = candidate.publish_external_ca_sign(material, signatures, now)?;
            candidate.select_external_default(&original)?;
            *self = candidate;
            return Ok(response);
        }
        let issuer = self.captured_external_issuer()?;
        let key = self
            .external
            .root
            .as_ref()
            .ok_or_else(|| bad("external key missing"))?;
        let prepared = material
            .template
            .signed_ca
            .take()
            .ok_or_else(|| bad("external signed CA plan missing"))?;
        if prepared.issuer != issuer
            || material.template.bound_issuer.as_ref() != Some(&issuer)
            || material.template.reference != key.reference
            || material.public_key != key.public_key
            || prepared.expires <= now
            || material.tbs != prepared.tbs(&material.public_key)?
            || signatures.len() != 1
        {
            return Err(error(
                503,
                "external signed CA owner changed before publication",
            ));
        }
        let der = signed_der(&material.tbs, &signatures[0], &material.public_key);
        local::certificate_signed_by(&der, &issuer.certificate_der)?;
        self.admit_external_issuer_archive(&issuer)?;
        let parents = issuer.ca_chain_der();
        self.publish_external_signed_ca(
            der.clone(),
            parents,
            issuer.issuer_id.clone(),
            prepared.serial.clone(),
            prepared.issued,
            prepared.expires,
        )?;
        self.external
            .archived_issuers
            .insert(issuer.issuer_id.clone(), issuer.clone());
        self.external
            .signer_history
            .get_or_insert_with(Default::default);
        let mut chain = vec![public::stored_pem("CERTIFICATE", &der)];
        chain.extend(
            issuer
                .ca_chain_der()
                .iter()
                .map(|der| public::stored_pem("CERTIFICATE", der)),
        );
        let certificate = if matches!(prepared.format, RootOutputFormat::PemBundle) {
            chain.join("\n")
        } else {
            prepared.format.certificate(&der)
        };
        let mut warnings = vec![
            "This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information.",
        ];
        if prepared.fields.max_path_length == Some(0) {
            warnings.push("Max path length of the signed certificate is zero. This certificate cannot be used to issue intermediate CA certificates.");
        }
        let mut response = ok(
            json!({"certificate":certificate,"issuing_ca":public::stored_pem("CERTIFICATE",&issuer.certificate_der),"ca_chain":chain,
            "serial_number":formatted_serial(&prepared.serial),"expiration":prepared.expires}),
            true,
        );
        response.body["warnings"] = json!(warnings);
        Ok(response)
    }
}
