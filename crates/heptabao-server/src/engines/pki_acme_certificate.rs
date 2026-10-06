//! Signed ACME certificates retain a public account/order owner. No account
//! proof is converted into a Vault token, Principal, or native lease owner.
use super::acme_orders::{IdentifierType, Order};
use super::acme_state::{Binding as MountBinding, Protocol};
use super::*;
use crate::auth::{AuthorityTime, RequestClock, Timestamp};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

const MAX_ACME_CERT_TTL: u64 = 90 * 86400;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub mount: MountBinding,
    pub account: String,
    pub thumbprint: String,
    pub order: String,
    pub directory: String,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Certificate {
    pub binding: Binding,
    pub created: Timestamp,
    pub issuer: String,
    pub serial: String,
    pub common_name: String,
    pub expires: u64,
    pub csr: Vec<u8>,
    pub der: Vec<u8>,
    pub(super) evidence: LeafProfilePublicEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) urls: Option<UrlEntries>,
}

// This process-local plan retains the accepted public order/CSR owner. It is
// never a Vault Principal, token lease, or a new source of request time.
struct PreparedCertificate {
    root: RootCa,
    prepared: LeafTemplate,
    binding: Binding,
    raw: Vec<u8>,
}
impl PreparedCertificate {
    fn into_certificate(self, der: Vec<u8>) -> Result<Certificate> {
        let public = self
            .prepared
            .csr_public_key
            .as_ref()
            .ok_or_else(|| error(503, "ACME original CSR public key unavailable"))?;
        let evidence = LeafProfilePublicEvidence::capture(&self.prepared, public)
            .ok_or_else(|| error(503, "ACME leaf public evidence unavailable"))?;
        let created = self
            .prepared
            .publication_time
            .exact()
            .ok_or_else(|| error(503, "ACME accepted precise issuance time missing"))?;
        Ok(Certificate {
            binding: self.binding,
            created,
            issuer: self.root.issuer_id.clone(),
            serial: self.prepared.serial,
            common_name: self.prepared.common_name,
            expires: self.prepared.expires,
            csr: self.raw,
            der,
            evidence,
            urls: self.prepared.url_entries,
        })
    }
}
pub(crate) struct ExternalCertificateTemplate {
    pub(crate) reference: String,
    public: external::ExternalPkiPublicKey,
    scheme: LeafSignature,
    tbs: Vec<u8>,
    plan: Box<PreparedCertificate>,
}
impl ExternalCertificateTemplate {
    pub(crate) fn validate_time(&self, at: Timestamp) -> Result<()> {
        self.plan
            .prepared
            .validate_publication_observed(AuthorityTime::Precise(at))
    }
    pub(crate) fn validate_provider_public(
        &self,
        public: &external::ExternalPkiPublicKey,
    ) -> Result<()> {
        if &self.public != public {
            return Err(error(503, "ACME external issuer public key changed"));
        }
        Ok(())
    }
    pub(in crate::engines) fn validate_issuer(&self, pki: &Pki) -> Result<()> {
        let key = pki.external_issuer_key(&self.plan.root.issuer_id)?;
        let root = pki.external_issuer_root(&self.plan.root.issuer_id)?;
        if key.reference != self.reference
            || key.public_key != self.public
            || key.key_id != self.plan.root.key_id
            || root.certificate_der != self.plan.root.certificate_der
        {
            return Err(error(503, "ACME original external signer owner changed"));
        }
        Ok(())
    }
    pub(crate) fn signing_input(&self) -> Result<Vec<u8>> {
        self.public.signing_input_leaf(&self.tbs, self.scheme)
    }
    pub(crate) fn hash_algorithm(&self) -> Option<&'static str> {
        self.scheme.hash_algorithm()
    }
    pub(crate) fn signature_algorithm(&self) -> &'static str {
        if self.scheme.pss() { "pss" } else { "pkcs1v15" }
    }
    pub(crate) fn signature_size_bound(&self) -> usize {
        self.public.signature_size_bound()
    }
    pub(in crate::engines) fn finish(
        self,
        signature: &[u8],
        pki: &Pki,
        at: Timestamp,
    ) -> Result<Certificate> {
        self.validate_time(at)?;
        self.validate_issuer(pki)?;
        self.public.verify_leaf(&self.tbs, signature, self.scheme)?;
        let der = external::signed_der_with_scheme(&self.tbs, signature, self.scheme);
        let certificate = self.plan.into_certificate(der)?;
        pki.validate_acme_certificate(&certificate)?;
        Ok(certificate)
    }
}

pub(crate) fn bad_csr(detail: &str) -> EngineError {
    bad(&format!("the CSR is unacceptable: {detail}"))
}
pub(crate) fn order_not_ready(status: &str, required: &str) -> EngineError {
    error(
        403,
        &format!(
            "the request attempted to finalize an order that is not ready to be finalized: order is status {status}, needs to be in {required} state"
        ),
    )
}
fn malformed(detail: &str) -> EngineError {
    bad(&format!("the request message was malformed: {detail}"))
}
pub(crate) fn parse_payload(payload: &Value) -> Result<Vec<u8>> {
    let value = payload
        .get("csr")
        .ok_or_else(|| malformed("missing csr in payload"))?;
    let text = value.as_str().ok_or_else(|| {
        malformed(&format!(
            "csr in payload not the expected type: {}",
            acme_orders::go_type(value)
        ))
    })?;
    if text.len() > 90 * 1024 {
        return Err(malformed("CSR exceeds bounds"));
    }
    let cleaned: String = text.chars().filter(|c| !matches!(c, '\r' | '\n')).collect();
    let decoder = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD.with_decode_allow_trailing_bits(true),
    );
    let raw = decoder.decode(&cleaned).map_err(|_| {
        let index = text
            .bytes()
            .position(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'\r' | b'\n'))
            .unwrap_or(text.len().saturating_sub(1));
        malformed(&format!(
            "failed base64 decoding csr: illegal base64 data at input byte {index}"
        ))
    })?;
    if let Some(detail) = outer_der_diagnostic(&raw) {
        return Err(malformed(&format!("failed to parse csr: {detail}")));
    }
    let (_, parsed) = x509_parser::certification_request::X509CertificationRequest::from_der(&raw)
        .map_err(|_| malformed("failed to parse csr: invalid CSR encoding"))?;
    let algorithm = &parsed.certification_request_info.subject_pki.algorithm;
    if algorithm.algorithm.to_id_string() == "1.2.840.113549.1.1.1"
        && algorithm
            .parameters
            .as_ref()
            .is_none_or(|value| value.as_null().is_err())
    {
        return Err(malformed(
            "failed to parse csr: x509: RSA key missing NULL parameters",
        ));
    }
    local_intermediate::parse_csr(&raw)
        .map_err(|e| malformed(&format!("failed to parse csr: {}", e.message)))?;
    Ok(raw)
}
// Match the native ASN.1 outer-SEQUENCE diagnostic structurally. The remaining
// complete CSR decoder and actual signature checks are the maintained parser.
fn outer_der_diagnostic(raw: &[u8]) -> Option<String> {
    if raw.len() < 2 {
        return None;
    }
    let tag = raw[0];
    if tag & 31 == 31 || raw[1] & 128 != 0 || tag == 0x30 {
        return None;
    }
    Some(format!(
        "asn1: structure error: tags don't match (16 vs {{class:{} tag:{} length:{} isCompound:{}}}) {{optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false}} certificateRequest @2",
        tag >> 6,
        tag & 31,
        raw[1],
        tag & 32 != 0
    ))
}

fn csr_identifiers(raw: &[u8]) -> Result<(BTreeSet<String>, BTreeSet<IpAddr>)> {
    let csr = local_intermediate::parse_csr(raw).map_err(|e| bad_csr(&e.message))?;
    let mut dns = BTreeSet::new();
    let mut ips = BTreeSet::new();
    if let Some(cn) = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .last()
    {
        let cn = cn
            .as_str()
            .map_err(|_| bad_csr("invalid CSR common name"))?;
        if !cn.is_empty() {
            if let Ok(ip) = cn.parse::<IpAddr>() {
                ips.insert(ip);
            } else {
                dns.insert(cn.to_ascii_lowercase());
            }
        }
    }
    if let Some(extensions) = csr.requested_extensions() {
        for extension in extensions {
            match extension {
                ParsedExtension::SubjectAlternativeName(names) => {
                    for name in &names.general_names {
                        match name {
                            GeneralName::DNSName(name) => {
                                dns.insert(name.to_ascii_lowercase());
                            }
                            GeneralName::IPAddress(raw) => {
                                let ip = match raw.len() {
                                    4 => IpAddr::from(
                                        <[u8; 4]>::try_from(*raw)
                                            .map_err(|_| bad_csr("invalid IP SAN"))?,
                                    ),
                                    16 => IpAddr::from(
                                        <[u8; 16]>::try_from(*raw)
                                            .map_err(|_| bad_csr("invalid IP SAN"))?,
                                    ),
                                    _ => return Err(bad_csr("invalid IP SAN")),
                                };
                                ips.insert(ip);
                            }
                            _ => return Err(bad_csr("CSR included unsupported SAN types")),
                        }
                    }
                }
                ParsedExtension::BasicConstraints(bc) if bc.ca => {
                    return Err(bad_csr(
                        "refusing to accept CSR with Basic Constraints extension with CA set to true",
                    ));
                }
                ParsedExtension::ParseError { .. } => {
                    return Err(bad_csr("failed to decode CSR extension"));
                }
                _ => {}
            }
        }
    }
    Ok((dns, ips))
}
pub(crate) fn validate_csr_order(raw: &[u8], order: &Order) -> Result<()> {
    let (dns, ips) = csr_identifiers(raw)?;
    let mut required_dns = BTreeSet::new();
    let mut required_ips = BTreeSet::new();
    for identifier in &order.identifiers {
        match identifier.kind {
            IdentifierType::Dns => {
                required_dns.insert(identifier.original.to_ascii_lowercase());
            }
            IdentifierType::Ip => {
                required_ips.insert(
                    identifier
                        .original
                        .parse::<IpAddr>()
                        .map_err(|_| bad_csr("invalid order IP identifier"))?,
                );
            }
        }
    }
    if required_dns.is_empty() && required_ips.is_empty() {
        return Err(error(
            500,
            "the server experienced an internal error: order did not include any identifiers",
        ));
    }
    if required_dns.len() != dns.len() {
        return Err(bad_csr(&format!(
            "Order ({}) and CSR ({}) mismatch on number of DNS identifiers",
            required_dns.len(),
            dns.len()
        )));
    }
    if required_ips.len() != ips.len() {
        return Err(bad_csr(&format!(
            "Order ({}) and CSR ({}) mismatch on number of IP identifiers",
            required_ips.len(),
            ips.len()
        )));
    }
    for identifier in required_dns {
        if !dns.contains(&identifier) {
            return Err(bad_csr(&format!(
                "CSR is missing order DNS identifier {identifier}"
            )));
        }
    }
    for identifier in required_ips {
        if !ips.contains(&identifier) {
            return Err(bad_csr(&format!(
                "CSR is missing order IP identifier {identifier}"
            )));
        }
    }
    Ok(())
}
impl Binding {
    fn from_order(order: &Order) -> Self {
        Self {
            mount: order.owner.clone(),
            account: order.account.clone(),
            thumbprint: order.account_thumbprint.clone(),
            order: order.id.clone(),
            directory: order.directory.clone(),
        }
    }
}
impl Protocol {
    pub(crate) fn validate_completed_order(&self, order: &Order) -> Result<()> {
        let Some(cert) = &order.certificate else {
            return Ok(());
        };
        if cert.binding != Binding::from_order(order)
            || cert.created < order.created
            || cert.created > self.clock
            || cert.created > order.expires
            || cert.expires <= cert.created.seconds()
            || cert.expires - cert.created.seconds() > MAX_ACME_CERT_TTL
            || cert.issuer.is_empty()
            || !valid_pki_id(&cert.issuer)
            || cert.der.is_empty()
            || cert.der.len() > 64 * 1024
            || cert.csr.len() > 64 * 1024
            || serial_bytes(&cert.serial).is_err()
            || order.authorizations.is_empty()
            || order.authorizations.iter().any(|id| {
                self.authorizations.get(id).is_none_or(|a| {
                    a.challenges
                        .iter()
                        .find_map(|c| c.validated.as_ref())
                        .is_none_or(|v| v.at > cert.created || cert.created > v.expires)
                })
            })
        {
            return Err(error(
                503,
                "ACME signed certificate account/order owner rejected",
            ));
        }
        validate_csr_order(&cert.csr, order)?;
        let account = self
            .accounts
            .get(&order.account)
            .ok_or_else(|| error(503, "ACME signed certificate account unavailable"))?;
        let request = local_intermediate::parse_csr(&cert.csr)?;
        let account_public = account.jwk.public_key()?;
        let csr_public = openssl::pkey::PKey::public_key_from_der(
            request.certification_request_info.subject_pki.raw,
        )
        .map_err(|_| error(503, "ACME captured CSR public key unavailable"))?;
        if csr_public.public_eq(&account_public) {
            return Err(error(503, "ACME signed certificate reused account key"));
        }
        Ok(())
    }
}
impl Pki {
    fn acme_prepare_certificate(
        &self,
        order: &Order,
        raw: &[u8],
        time: Timestamp,
        clock: Option<RequestClock>,
    ) -> Result<PreparedCertificate> {
        validate_csr_order(raw, order)?;
        let request = local_intermediate::parse_csr(raw)?;
        let account = self
            .acme_protocol
            .as_ref()
            .and_then(|protocol| protocol.accounts.get(&order.account))
            .ok_or_else(|| error(503, "ACME admitted account unavailable before signing"))?;
        let account_public = account.jwk.public_key()?;
        let csr_public = openssl::pkey::PKey::public_key_from_der(
            request.certification_request_info.subject_pki.raw,
        )
        .map_err(|_| bad_csr("invalid CSR public key"))?;
        if csr_public.public_eq(&account_public) {
            return Err(bad_csr("certificate public key must not match account key"));
        }
        let public = LocalPublicKey::from_spki(request.certification_request_info.subject_pki.raw)?;
        let prefix = order
            .directory
            .trim_end_matches("acme/")
            .trim_end_matches('/');
        let issuer = self.acme_directory_issuer(prefix)?;
        let issuer_id = issuer.issuer_id.clone();
        let explicit_role = match prefix.split('/').collect::<Vec<_>>().as_slice() {
            ["roles", role] | ["issuer", _, "roles", role] => Some((*role).to_owned()),
            _ => None,
        };
        let role_name = explicit_role.or_else(|| {
            self.acme
                .default_directory_policy
                .strip_prefix("role:")
                .map(str::to_owned)
        });
        let mut role = if let Some(name) = role_name {
            self.roles
                .get(&name)
                .ok_or_else(|| malformed("role does not exist"))?
                .clone()
        } else {
            Role::from_body(
                &json!({"allow_any_name":true,"allow_ip_sans":true,"allow_wildcard_certificates":true,"key_type":public.kind().key_type(),"key_bits":public.kind().bits()}),
            )?
        };
        // Native ACME never generates a Vault lease, and stores its signed leaf
        // regardless of generic no_store/generate_lease role response settings.
        role.generate_lease = false;
        if !self.acme.allow_role_ext_key_usage {
            let mut profile = role.effective_leaf_profile();
            profile.server_flag = true;
            profile.client_flag = false;
            profile.code_signing_flag = false;
            profile.email_protection_flag = false;
            profile.ext_key_usage = vec!["serverauth".into()];
            profile.ext_key_usage_oids.clear();
            role.role_leaf_profile = Some(profile);
        }
        role.max_ttl = if role.max_ttl == 0 {
            self.max_ttl
        } else {
            role.max_ttl
        }
        .min(MAX_ACME_CERT_TTL);
        let mut candidate = self.clone();
        if issuer.is_external() {
            candidate.select_external_default(&issuer_id)?;
        }
        let role_key = "__acme-finalize";
        candidate.roles.insert(role_key.into(), role.clone());
        // Override only this admitted certificate's expiry behavior. The live
        // issuer configuration remains byte-for-byte unchanged.
        let mut selected = issuer.clone();
        if selected.leaf_not_after_behavior.unwrap_or_default() == IssuerLeafNotAfterBehavior::Err {
            selected.leaf_not_after_behavior = Some(IssuerLeafNotAfterBehavior::Truncate);
        }
        // select_external_default already selected this exact retained typed
        // signer. Its historical RootCa deliberately has empty local IDs; the
        // temporary preparation view must not fall through to the local index.
        if issuer.is_external()
            || candidate
                .root
                .as_ref()
                .is_some_and(|r| r.issuer_id == issuer_id)
        {
            candidate.root = Some(selected);
        } else {
            candidate
                .local_issuers
                .as_mut()
                .ok_or_else(|| error(503, "ACME issuer index unavailable"))?
                .other
                .insert(issuer_id.clone(), selected);
        }
        let mut body = json!({"csr":public::stored_pem("CERTIFICATE REQUEST",raw)});
        if role.role_name_policy.as_ref().is_none_or(|p| p.require_cn)
            && request
                .certification_request_info
                .subject
                .iter_common_name()
                .next()
                .is_none()
        {
            let cn = order
                .identifiers
                .iter()
                .find(|i| i.wildcard)
                .or_else(|| {
                    order
                        .identifiers
                        .iter()
                        .find(|i| i.kind == IdentifierType::Dns)
                })
                .or_else(|| order.identifiers.first())
                .ok_or_else(|| bad_csr("missing CSR common name"))?;
            body["common_name"] = json!(cn.original);
        }
        let binding = Binding::from_order(order);
        let prepared = candidate
            .prepare_leaf_for_owner(
                IssuanceRoute {
                    mount: &order.owner.mount,
                    role: role_key,
                    explicit_issuer: Some(&issuer_id),
                    sign: true,
                },
                &body,
                LeafPreparationAuthority {
                    owner: LeafOwner::Acme(binding.clone()),
                    owner_expires: None,
                    precise_owner_expires: None,
                    time: AuthorityTime::Precise(time),
                    clock,
                    identity_templates: None,
                },
            )
            .map_err(|e| bad_csr(&format!("refusing to sign CSR: {}", e.message)))?;
        if !matches!(&prepared.owner,LeafOwner::Acme(owner)if owner==&binding) {
            return Err(error(503, "ACME prepared public account owner changed"));
        }
        let root = candidate.selected_issuer(&issuer_id)?.clone();
        Ok(PreparedCertificate {
            root,
            prepared,
            binding,
            raw: raw.to_vec(),
        })
    }
    pub(crate) fn acme_finalize_local(
        &self,
        order: &Order,
        raw: &[u8],
        time: Timestamp,
        clock: Option<RequestClock>,
    ) -> Result<Certificate> {
        let plan = self.acme_prepare_certificate(order, raw, time, clock)?;
        if plan.root.is_external() {
            return Err(error(
                501,
                "external ACME finalization requires a qualified provider signing lane",
            ));
        }
        let prepared = &plan.prepared;
        let leaf = prepared
            .csr_public_key
            .as_ref()
            .ok_or_else(|| error(503, "ACME signed leaf has no original CSR public key"))?;
        let root = &plan.root;
        let root_pair = root.local_key()?;
        let name = root_fields::certificate_subject(&root.certificate_der)?;
        let key_id = root_fields::certificate_key_identifier(&root.certificate_der)?;
        prepared.validate_publication(prepared.issued)?;
        let der = certificate_der_local_with_policy(
            &root_pair,
            leaf,
            CertificateSpec {
                url_entries: prepared.url_entries.as_ref(),
                serial: &prepared.serial,
                issuer_cn: &root.common_name,
                subject_cn: &prepared.common_name,
                issuer_name_der: Some(&name),
                subject_name_der: None,
                public_key: &[],
                authority_key_id: key_id.as_deref(),
                not_before: prepared.not_before,
                not_after: prepared.expires,
                is_ca: false,
                alt_names: &prepared.alt_names,
                email_sans: &prepared.email_sans,
                ip_sans: &prepared.ip_sans,
                uri_sans: &prepared.uri_sans,
                exclude_cn_from_sans: prepared.exclude_cn_from_sans,
                max_path_length: None,
                permitted_dns_domains: &[],
                role_leaf_profile: prepared.role_leaf_profile.as_ref(),
            },
            prepared.role_name_policy.as_ref(),
        )?;
        prepared.validate_publication(prepared.issued)?;
        let certificate = plan.into_certificate(der)?;
        self.validate_acme_certificate(&certificate)?;
        Ok(certificate)
    }
    pub(crate) fn acme_prepare_external_certificate(
        &self,
        order: &Order,
        raw: &[u8],
        time: Timestamp,
        clock: Option<RequestClock>,
    ) -> Result<Option<ExternalCertificateTemplate>> {
        let prefix = order
            .directory
            .trim_end_matches("acme/")
            .trim_end_matches('/');
        if !self.acme_directory_issuer(prefix)?.is_external() {
            return Ok(None);
        }
        let plan = self.acme_prepare_certificate(order, raw, time, clock)?;
        let key = self.external_issuer_key(&plan.root.issuer_id)?;
        let public = key.public_key.clone();
        let subject = plan
            .prepared
            .csr_public_key
            .as_ref()
            .ok_or_else(|| error(503, "ACME original CSR public key unavailable"))?;
        let scheme = public.leaf_signature(plan.prepared.role_name_policy.as_ref());
        let name = root_fields::certificate_subject(&plan.root.certificate_der)?;
        let key_id = root_fields::certificate_key_identifier(&plan.root.certificate_der)?;
        let prepared = &plan.prepared;
        let tbs = certificate_tbs_with(
            CertificateSpec {
                url_entries: prepared.url_entries.as_ref(),
                serial: &prepared.serial,
                issuer_cn: &plan.root.common_name,
                subject_cn: &prepared.common_name,
                issuer_name_der: Some(&name),
                subject_name_der: None,
                public_key: &[],
                authority_key_id: key_id.as_deref(),
                not_before: prepared.not_before,
                not_after: prepared.expires,
                is_ca: false,
                alt_names: &prepared.alt_names,
                email_sans: &prepared.email_sans,
                ip_sans: &prepared.ip_sans,
                uri_sans: &prepared.uri_sans,
                exclude_cn_from_sans: prepared.exclude_cn_from_sans,
                max_path_length: None,
                permitted_dns_domains: &[],
                role_leaf_profile: prepared.role_leaf_profile.as_ref(),
            },
            &subject.spki()?,
            &scheme.algorithm(),
        )?;
        Ok(Some(ExternalCertificateTemplate {
            reference: key.reference.clone(),
            public,
            scheme,
            tbs,
            plan: Box::new(plan),
        }))
    }
    fn validate_acme_certificate(&self, issued: &Certificate) -> Result<()> {
        let evidence = &issued.evidence;
        let (issuer_der, issuer_public) = self.profile_leaf_issuer_evidence(&issued.issuer)?;
        if let Some(urls) = &issued.urls {
            urls.validate()?;
        }
        evidence.profile.validate_role_oid_strings()?;
        evidence.public_key.validate()?;
        if let Some(policy) = &evidence.role_name_policy {
            policy.validate()?;
            policy.validate_sans(&evidence.ip_sans, &evidence.uri_sans)?;
            policy.validate_subject_capture(evidence.profile.leaf_subject_evidence.as_ref())?;
        }
        let (rest, request) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&issued.csr)
                .map_err(|_| bad("invalid ACME captured CSR"))?;
        if !rest.is_empty()
            || request.certification_request_info.subject_pki.raw != evidence.public_key.spki()?
        {
            return Err(bad("ACME signed certificate public key differs from CSR"));
        }
        let (_, issuer_certificate) =
            x509_parser::certificate::X509Certificate::from_der(issuer_der)
                .map_err(|_| bad("invalid ACME issuer DER"))?;
        if issued.expires
            > u64::try_from(issuer_certificate.validity().not_after.timestamp())
                .map_err(|_| bad("invalid ACME issuer expiry"))?
            && evidence.issuer_not_after_behavior != Some(IssuerLeafNotAfterBehavior::Permit)
        {
            return Err(bad(
                "ACME signed leaf exceeded its admitted issuer boundary",
            ));
        }
        let issuer_name = root_fields::certificate_subject(issuer_der)?;
        let authority_key_id = root_fields::certificate_key_identifier(issuer_der)?;
        let scheme =
            LeafSignature::for_key(issuer_public.kind(), evidence.role_name_policy.as_ref());
        let expected = certificate_tbs_with(
            CertificateSpec {
                url_entries: issued.urls.as_ref(),
                serial: &issued.serial,
                issuer_cn: "",
                subject_cn: &issued.common_name,
                issuer_name_der: Some(&issuer_name),
                subject_name_der: None,
                public_key: &[],
                authority_key_id: authority_key_id.as_deref(),
                not_before: evidence.not_before,
                not_after: issued.expires,
                is_ca: false,
                alt_names: &evidence.alt_names,
                email_sans: &evidence.email_sans,
                ip_sans: &evidence.ip_sans,
                uri_sans: &evidence.uri_sans,
                exclude_cn_from_sans: evidence.exclude_cn_from_sans,
                max_path_length: None,
                permitted_dns_domains: &[],
                role_leaf_profile: Some(&evidence.profile),
            },
            &evidence.public_key.spki()?,
            &scheme.algorithm(),
        )?;
        let (rest, certificate) = x509_parser::certificate::X509Certificate::from_der(&issued.der)
            .map_err(|_| bad("invalid ACME signed DER"))?;
        if !rest.is_empty()
            || certificate.signature_value.unused_bits != 0
            || certificate.signature_algorithm != certificate.tbs_certificate.signature
            || certificate.tbs_certificate.as_ref() != expected.as_slice()
            || !issuer_public.verify_leaf(&expected, &certificate.signature_value.data, scheme)?
        {
            return Err(bad(
                "ACME signed DER and account-owned public evidence differ",
            ));
        }
        Ok(())
    }
    pub(super) fn validate_acme_certificates(&self) -> Result<()> {
        let Some(protocol) = &self.acme_protocol else {
            return Ok(());
        };
        let mut serials = BTreeSet::new();
        for order in protocol.orders.values() {
            if let Some(cert) = &order.certificate {
                if !serials.insert(&cert.serial) || self.issued.contains_key(&cert.serial) {
                    return Err(bad("duplicate ACME signed certificate serial"));
                }
                self.validate_acme_certificate(cert)?;
            }
        }
        self.validate_acme_revocations()?;
        Ok(())
    }
    pub(crate) fn acme_certificate_chain(&self, certificate: &Certificate) -> Result<String> {
        self.validate_acme_certificate(certificate)?;
        let (issuer_der, _) = self.profile_leaf_issuer_evidence(&certificate.issuer)?;
        let mut body = pem("CERTIFICATE", &certificate.der);
        body.push_str(&pem("CERTIFICATE", issuer_der));
        // Historical issuer chain remains public after private-key retirement.
        if let Ok(root) = self.local_issuer(&certificate.issuer) {
            for text in root.local_ca_chain_pem() {
                if text != pem("CERTIFICATE", issuer_der) {
                    body.push_str(&text);
                    if !text.ends_with('\n') {
                        body.push('\n');
                    }
                }
            }
        }
        if body.len() > 512 * 1024 {
            return Err(error(503, "ACME public certificate chain exceeds bounds"));
        }
        Ok(body)
    }
}

impl Pki {
    pub(super) fn has_external_acme_issuer_reference(&self, id: &str, der: &[u8]) -> Result<bool> {
        let mut found = false;
        for certificate in self
            .acme_certificates()
            .filter(|certificate| certificate.issuer == id)
        {
            let (issuer, _) = self.profile_leaf_issuer_evidence(id)?;
            if issuer != der {
                return Err(bad("ACME public issuer archive changed"));
            }
            self.validate_acme_certificate(certificate)?;
            found = true;
        }
        Ok(found)
    }
    pub(super) fn acme_certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.acme_protocol
            .iter()
            .flat_map(|protocol| protocol.orders.values())
            .filter_map(|order| order.certificate.as_ref())
    }

    pub(super) fn acme_certificate_for_serial(&self, serial: &str) -> Result<Option<&Certificate>> {
        let mut matches = self
            .acme_certificates()
            .filter(|cert| cert.serial == serial);
        let found = matches.next();
        if matches.next().is_some() {
            return Err(bad("certificate serial is ambiguous"));
        }
        Ok(found)
    }
}
