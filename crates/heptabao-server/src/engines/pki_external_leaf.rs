//! External CA consumption contains public issuer state only. A leaf private
//! key exists in a zeroizing effect result until one successful publication.
use super::*;
use crate::auth::Timestamp;

#[derive(Clone)]
pub(super) enum ConsumptionTemplate {
    Leaf(Box<LeafTemplate>),
    Crl {
        revoked: Option<(String, u64)>,
        acme_revocation: Option<Box<OperatorRevocationPlan>>,
        ordinary_revocation: Option<Box<OrdinaryRevocationPlan>>,
        prepared: Box<CrlSet>,
    },
}

pub(super) struct ConsumptionMaterial {
    pub(super) template: ConsumptionTemplate,
    pub(super) leaf_pkcs8: Zeroizing<Vec<u8>>,
    pub(super) leaf_public: Option<LocalPublicKey>,
}

// Effect-only ownership: this is the original admitted operator, not an ACME
// account impersonating a Vault principal or a refreshed request clock.
#[derive(Clone)]
pub(super) struct OperatorRevocationPlan {
    revoked: super::acme_revoke::Revocation,
    clock: Option<crate::auth::RequestClock>,
}
impl OperatorRevocationPlan {
    fn validate(&self, pki: &Pki, now: u64) -> Result<()> {
        let floor = self
            .revoked
            .at
            .max(Timestamp::whole(now).map_err(|_| bad("invalid operator publication time"))?);
        let at = self
            .clock
            .map(|clock| clock.with_timestamp_floor(floor).observed_at())
            .transpose()
            .map_err(|_| error(503, "original operator clock unavailable"))?
            .unwrap_or(floor);
        let super::acme_revoke::Proof::Administrative {
            expires_at,
            precise_expires_at,
            ..
        } = &self.revoked.proof
        else {
            return Err(bad("actual administrative PKI owner required"));
        };
        if precise_expires_at.is_some_and(|end| at > end)
            || precise_expires_at.is_none() && expires_at.is_some_and(|end| at.seconds() >= end)
        {
            return Err(error(
                403,
                "administrative PKI original caller expired before signing",
            ));
        }
        pki.validate_live_acme_revocation(&self.revoked, at, false)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LeafPublic {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url_entries: Option<UrlEntries>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_name_policy: Option<RoleNamePolicy>,
    #[serde(default, skip_serializing_if = "role_false")]
    exclude_cn_from_sans: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    email_sans: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    uri_sans: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) issuer_not_after_behavior: Option<IssuerLeafNotAfterBehavior>,
    #[serde(default, skip_serializing_if = "role_false")]
    pub(super) signed_role_time_owned: bool,
    #[serde(default, skip_serializing_if = "role_false")]
    pub(super) role_time_owned: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) issuer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_leaf_profile: Option<RoleLeafProfile>,
    public_key: LocalPublicKey,
    not_before: i64,
    alt_names: Vec<String>,
    ip_sans: Vec<IpAddr>,
}

impl Pki {
    pub(in crate::engines::pki) fn has_external_url_state(&self) -> bool {
        let captured_crl =
            |crls: &CrlSet| crls.full.url_entries.is_some() || crls.delta.url_entries.is_some();
        self.external_signers()
            .any(|(_, root)| root.url_entries.is_some())
            || self
                .external
                .archived_issuers
                .values()
                .any(|issuer| issuer.url_entries.is_some())
            || self
                .external
                .issued_public
                .values()
                .any(|leaf| leaf.url_entries.is_some())
            || self.external.crls.as_ref().is_some_and(captured_crl)
            || self.external_history_has_url_crls()
    }
    pub(in crate::engines::pki) fn has_external_role_names_state(&self) -> bool {
        self.external.issued_public.values().any(|leaf| {
            leaf.role_name_policy.is_some()
                || leaf
                    .role_leaf_profile
                    .as_ref()
                    .is_some_and(|profile| profile.leaf_subject_evidence.is_some())
                || !leaf.email_sans.is_empty()
                || !leaf.uri_sans.is_empty()
        })
    }
    pub(in crate::engines::pki) fn has_external_signed_role_time_state(&self) -> bool {
        self.external
            .issued_public
            .values()
            .any(|leaf| leaf.signed_role_time_owned || leaf.not_before < 0)
    }
}

impl LeafPublic {
    pub(super) fn has_role_leaf_profile(&self) -> bool {
        self.role_leaf_profile.is_some() || !self.issuer_id.is_empty()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Crl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url_entries: Option<UrlEntries>,
    pub(super) number: u64,
    base: Option<u64>,
    issued: u64,
    pub(super) expires: u64,
    pub(super) revoked: BTreeMap<String, u64>,
    pub(super) der: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CrlSet {
    // Imported CA subjects can contain more than a CommonName. None keeps the
    // historical CN-only signing template. This effect-only capture is never
    // persisted; reopened CRLs recover their Name from the original signed DER.
    #[serde(skip)]
    issuer_name_der: Option<Vec<u8>>,
    pub(super) full: Crl,
    pub(super) delta: Crl,
}

impl CrlSet {
    pub(super) fn has_url_state(&self) -> bool {
        self.full.url_entries.is_some() || self.delta.url_entries.is_some()
    }
    pub(super) fn empty(now: u64, urls: Option<UrlEntries>) -> Self {
        Self::prepare(1, now, BTreeMap::new(), urls)
    }
    pub(super) fn prepare(
        number: u64,
        now: u64,
        revoked: BTreeMap<String, u64>,
        urls: Option<UrlEntries>,
    ) -> Self {
        let crl = |number, base: Option<u64>, revoked| Crl {
            url_entries: if base.is_none() { urls.clone() } else { None },
            number,
            base,
            issued: now,
            expires: now.saturating_add(72 * 3600),
            revoked,
            der: Vec::new(),
        };
        Self {
            issuer_name_der: None,
            full: crl(number, None, revoked),
            delta: crl(number + 1, Some(number), BTreeMap::new()),
        }
    }
    pub(super) fn with_certificate_issuer(
        mut self,
        certificate: &[u8],
        common_name: &str,
    ) -> Result<Self> {
        let subject = root_fields::certificate_subject(certificate)?;
        self.issuer_name_der = (subject != name(common_name)).then_some(subject);
        Ok(self)
    }
    fn signed_issuer_name(&self, issuer: &str) -> Result<Vec<u8>> {
        if let Some(captured) = &self.issuer_name_der {
            return Ok(captured.clone());
        }
        if self.full.der.is_empty() {
            return Ok(name(issuer));
        }
        if self.full.der.len() > 512 * 1024 {
            return Err(bad("external CRL exceeds bounds"));
        }
        use x509_parser::prelude::FromDer;
        let (trailing, parsed) =
            x509_parser::prelude::CertificateRevocationList::from_der(&self.full.der)
                .map_err(|_| bad("invalid external CRL DER"))?;
        if !trailing.is_empty()
            || parsed.signature_algorithm != parsed.tbs_cert_list.signature
            || parsed.signature_value.unused_bits != 0
        {
            return Err(bad("invalid complete external CRL signature envelope"));
        }
        Ok(parsed.issuer().as_raw().to_vec())
    }
    pub(super) fn has_full_dn(&self, issuer: &str) -> bool {
        self.signed_issuer_name(issuer)
            .is_ok_and(|actual| actual != name(issuer))
    }
    pub(super) fn matches_certificate_issuer(
        &self,
        certificate: &[u8],
        issuer: &str,
    ) -> Result<bool> {
        Ok(self.signed_issuer_name(issuer)? == root_fields::certificate_subject(certificate)?)
    }
    pub(super) fn tbs(&self, issuer: &str, public: &ExternalPkiPublicKey) -> Result<Vec<Vec<u8>>> {
        let actual = self.signed_issuer_name(issuer)?;
        Ok(vec![
            crl_tbs(issuer, Some(&actual), public, &self.full)?,
            crl_tbs(issuer, Some(&actual), public, &self.delta)?,
        ])
    }
    pub(super) fn sign(
        &mut self,
        issuer: &str,
        public: &ExternalPkiPublicKey,
        signatures: &[Zeroizing<Vec<u8>>],
    ) -> Result<()> {
        if signatures.len() != 2 {
            return Err(bad("external CRL signatures missing"));
        }
        let tbs = self.tbs(issuer, public)?;
        for ((crl, tbs), signature) in [&mut self.full, &mut self.delta]
            .into_iter()
            .zip(tbs)
            .zip(signatures)
        {
            crl.der = signed_der(&tbs, signature, public);
            validate_signed_der(public, &tbs, &crl.der)?;
        }
        Ok(())
    }
    pub(super) fn validate(&self, issuer: &ExternalPublicIssuer, clock: u64) -> Result<()> {
        issuer.validate()?;
        if let Some(captured) = &self.issuer_name_der {
            let actual = root_fields::certificate_subject(&issuer.certificate_der)?;
            if captured != &actual || actual == name(&issuer.common_name) {
                return Err(bad(
                    "external CRL issuer Name differs from its actual certificate",
                ));
            }
        }
        let effective = self.signed_issuer_name(&issuer.common_name)?;
        if effective != name(&issuer.common_name)
            && effective != root_fields::certificate_subject(&issuer.certificate_der)?
        {
            return Err(bad(
                "signed external CRL issuer Name is not owned by its actual certificate",
            ));
        }
        if self.full.base.is_some()
            || self.delta.base != Some(self.full.number)
            || self.full.number == 0
            || self.delta.number != self.full.number.checked_add(1).unwrap_or(0)
            || !self.delta.revoked.is_empty()
        {
            return Err(bad("invalid external CRL sequence"));
        }
        for crl in [&self.full, &self.delta] {
            if crl.issued > clock
                || crl.expires.checked_sub(crl.issued) != Some(72 * 3600)
                || crl.revoked.len() > MAX_ISSUED
                || crl.der.len() > 512 * 1024
                || crl
                    .revoked
                    .iter()
                    .any(|(serial, at)| serial_bytes(serial).is_err() || *at > crl.issued)
            {
                return Err(bad("invalid external CRL state"));
            }
            validate_signed_der(
                &issuer.public_key,
                &crl_tbs(
                    &issuer.common_name,
                    Some(&effective),
                    &issuer.public_key,
                    crl,
                )?,
                &crl.der,
            )?;
        }
        Ok(())
    }
    pub(super) fn selected(&self, delta: bool) -> &Crl {
        if delta { &self.delta } else { &self.full }
    }
}

fn positive_u64(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let offset = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    integer(&bytes[offset..])
}

fn key_identifier(public: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, public)
        .as_ref()
        .to_vec()
}

fn crl_tbs(
    issuer: &str,
    issuer_name_der: Option<&[u8]>,
    public: &ExternalPkiPublicKey,
    crl: &Crl,
) -> Result<Vec<u8>> {
    let mut parts = vec![
        integer(&[1]),
        public.signature_algorithm(),
        issuer_name_der.map_or_else(|| name(issuer), <[u8]>::to_vec),
        time(crl.issued),
        time(crl.expires),
    ];
    if !crl.revoked.is_empty() {
        let revoked = crl
            .revoked
            .iter()
            .map(|(serial, at)| Ok(seq(&[integer(&serial_bytes(serial)?), time(*at)])))
            .collect::<Result<Vec<_>>>()?;
        parts.push(seq(&revoked));
    }
    let mut extensions = vec![
        extension(
            &[0x55, 0x1d, 0x23],
            false,
            &seq(&[context_primitive(
                0,
                &key_identifier(&public.subject_key_bits()?),
            )]),
        ),
        extension(&[0x55, 0x1d, 0x14], false, &positive_u64(crl.number)),
    ];
    if let Some(base) = crl.base {
        extensions.push(extension(&[0x55, 0x1d, 0x1b], true, &positive_u64(base)));
    }
    if let Some(urls) = &crl.url_entries {
        urls.validate()?;
        if let Some(freshest) = urls.freshest_extension() {
            extensions.push(freshest);
        }
    }
    parts.push(context_explicit(0, &seq(&extensions)));
    Ok(seq(&parts))
}

fn leaf_tbs(
    root: &ExternalPublicIssuer,
    public: &ExternalPkiPublicKey,
    leaf_public: &LocalPublicKey,
    prepared: &LeafTemplate,
) -> Result<Vec<u8>> {
    if leaf_public.kind() != prepared.local_key_kind {
        return Err(bad("external leaf subject key type mismatch"));
    }
    leaf_public.validate()?;
    let leaf_bits = leaf_public.subject_key_bits()?;
    let subject_der = prepared.role_leaf_profile.as_ref().map_or_else(
        || Ok(name(&prepared.common_name)),
        |profile| profile.subject_der(&prepared.common_name),
    )?;
    let captured_subject = prepared
        .role_leaf_profile
        .as_ref()
        .and_then(|profile| profile.leaf_subject_evidence.as_ref());
    let other_names = captured_subject
        .map(|subject| subject.other_names_der())
        .transpose()?
        .unwrap_or_default();
    let policies = captured_subject
        .map(|subject| subject.policies_der())
        .transpose()?
        .flatten();
    let mut names = other_names.clone();
    // Keep the historical None encoding; new captured profiles use the same
    // admitted DNS CN projection as the local certificate producer.
    if !prepared.exclude_cn_from_sans
        && (prepared.role_leaf_profile.is_none()
            || (!prepared.common_name.is_empty()
                && (!prepared.common_name.contains('*')
                    || wildcard_dns_san(&prepared.common_name))))
    {
        names.push(context_primitive(2, prepared.common_name.as_bytes()));
    }
    names.extend(
        prepared
            .alt_names
            .iter()
            .map(|name| context_primitive(2, name.as_bytes())),
    );
    for email in &prepared.email_sans {
        names.push(context_primitive(1, email.as_bytes()));
    }
    for ip in &prepared.ip_sans {
        let bytes = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        names.push(context_primitive(7, &bytes));
    }
    for uri in &prepared.uri_sans {
        names.push(context_primitive(6, uri.as_bytes()));
    }
    let mut extensions = vec![
        extension(&[0x55, 0x1d, 0x0f], true, &bit_string(&[0xa8], 3)),
        extension(
            &[0x55, 0x1d, 0x25],
            false,
            &seq(&[
                oid(&[0x2b, 6, 1, 5, 5, 7, 3, 1]),
                oid(&[0x2b, 6, 1, 5, 5, 7, 3, 2]),
            ]),
        ),
        extension(
            &[0x55, 0x1d, 0x0e],
            false,
            &octet_string(&key_identifier(&leaf_bits)),
        ),
        extension(
            &[0x55, 0x1d, 0x23],
            false,
            &seq(&[context_primitive(
                0,
                &key_identifier(&public.subject_key_bits()?),
            )]),
        ),
    ];
    let qualified_policy =
        captured_subject.is_some_and(|subject| subject.policy_uses_extra_extension());
    if !other_names.is_empty()
        && !qualified_policy
        && let Some(policies) = &policies
    {
        extensions.push(policies.clone());
    }
    if prepared.role_leaf_profile.is_none() || !names.is_empty() {
        extensions.push(extension(
            &[0x55, 0x1d, 0x11],
            subject_der.as_slice() == [0x30, 0] && other_names.is_empty(),
            &seq(&names),
        ));
    }
    if (other_names.is_empty() || qualified_policy)
        && let Some(policies) = policies
    {
        extensions.push(policies);
    }
    if let Some(profile) = &prepared.role_leaf_profile {
        let mut controlled = profile.leaf_extensions()?;
        controlled.extend(extensions.into_iter().skip(2));
        extensions = controlled;
    }
    if let Some(urls) = &prepared.url_entries {
        extensions.extend(urls.certificate_extensions()?);
    }
    Ok(seq(&[
        context_explicit(0, &integer(&[2])),
        integer(&serial_bytes(&prepared.serial)?),
        public
            .leaf_signature(prepared.role_name_policy.as_ref())
            .algorithm(),
        if prepared.role_leaf_profile.is_some() || root.has_intermediate_chain() {
            root_fields::certificate_subject(&root.certificate_der)?
        } else {
            name(&root.common_name)
        },
        seq(&[time_signed(prepared.not_before), time(prepared.expires)]),
        subject_der,
        leaf_public.spki()?,
        context_explicit(3, &seq(&extensions)),
    ]))
}

impl Pki {
    pub(in crate::engines) fn has_full_dn_crl_state(&self) -> bool {
        self.external.crls.as_ref().is_some_and(|crls| {
            self.root
                .as_ref()
                .is_some_and(|root| crls.has_full_dn(&root.common_name))
        }) || self.external_history_has_full_dn_crls()
    }
    #[cfg(test)]
    pub(in crate::engines) fn alter_external_crl_issuer_for_test(
        &mut self,
        replacement: Option<Vec<u8>>,
    ) -> Result<()> {
        self.external
            .crls
            .as_mut()
            .ok_or_else(not_found)?
            .issuer_name_der = replacement;
        Ok(())
    }
    pub(in crate::engines::pki) fn has_external_role_leaf_profile_state(&self) -> bool {
        !self.external.archived_issuers.is_empty()
            || self
                .external
                .issued_public
                .values()
                .any(LeafPublic::has_role_leaf_profile)
    }

    pub(in crate::engines::pki) fn profile_leaf_is_external(&self, serial: &str) -> bool {
        self.external.issued_public.contains_key(serial)
    }

    pub(in crate::engines::pki) fn has_typed_leaf_subjects(&self) -> bool {
        self.external
            .issued_public
            .values()
            .any(|leaf| matches!(leaf.public_key, LocalPublicKey::Typed(_)))
    }

    pub(in crate::engines) fn prepare_external_consumption(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        mount: &str,
        context: crate::engines::PkiRequestContext<'_>,
    ) -> Result<Option<ExternalPkiTemplate>> {
        let owner = context.owner;
        let time = context.observed_time(context.time.seconds())?;
        let now = time.seconds();
        if (self.has_external_signer_history() || self.external.root.is_some())
            && let Some(selected) = self.external_route_issuer(path, body)?
            && self
                .external
                .root
                .as_ref()
                .is_none_or(|key| key.issuer_id != selected)
        {
            let mut candidate = self.clone();
            candidate.select_external_default(&selected)?;
            return candidate.prepare_external_consumption(method, path, body, mount, context);
        }
        let Some(key) = self.external.root.as_ref() else {
            return Ok(None);
        };
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| error(503, "external PKI root is missing"))?;
        let captured_issuer = self.captured_external_issuer()?;
        let issue = path
            .strip_prefix("issue/")
            .map(|role| (None, role, false))
            .or_else(|| path.strip_prefix("sign/").map(|role| (None, role, true)))
            .or_else(|| {
                Self::issuer_issue_route(path)
                    .map(|(reference, role)| (Some(reference), role, false))
            })
            .or_else(|| {
                Self::issuer_sign_route(path).map(|(reference, role)| (Some(reference), role, true))
            });
        let consumption = if let Some((reference, role, sign)) = issue {
            if !write_method(method) {
                return Err(unsupported());
            }
            if role.is_empty() || role.contains('/') {
                return Err(not_found());
            }
            if let Some(reference) = reference {
                self.require_public_issuer(reference)?;
            }
            let owner = owner.ok_or_else(|| error(403, "credential issuer is required"))?;
            let mut prepared = self.prepare_leaf_route(
                IssuanceRoute {
                    mount,
                    role,
                    explicit_issuer: reference,
                    sign,
                },
                body,
                LeafAuthority {
                    owner: &owner.owner,
                    owner_expires: owner.expires_at,
                    precise_owner_expires: owner.precise_expires_at,
                    time,
                    clock: context.clock,
                    identity_templates: context.identity_templates,
                },
            )?;
            prepared.path = format!("{mount}{path}");
            prepared.serial = external_serial()?;
            prepared.lease_id = format!("{}/{}", prepared.path, prepared.serial);
            // Role time policy already owns the actual signed validity.
            ConsumptionTemplate::Leaf(Box::new(prepared))
        } else if path == "revoke" || path == "crl/rotate" {
            if (path == "revoke" && !write_method(method))
                || (path == "crl/rotate" && method != "GET")
            {
                return Err(unsupported());
            }
            let acme_revocation = if path == "revoke" {
                let serial = self.resolve_certificate_serial(string(body, "serial_number")?)?;
                if self.acme_certificate_for_serial(&serial)?.is_some() {
                    let Some(revoked) = self.prepare_acme_operator_revocation(&serial, &context)?
                    else {
                        // Already revoked and expired records use the original no-effect route.
                        return Ok(None);
                    };
                    Some(Box::new(OperatorRevocationPlan {
                        revoked,
                        clock: context.clock,
                    }))
                } else {
                    None
                }
            } else {
                None
            };
            let ordinary_revocation = if path == "revoke" && acme_revocation.is_none() {
                let serial = self.resolve_certificate_serial(string(body, "serial_number")?)?;
                self.prepare_ordinary_revocation(&serial, &context)?
                    .map(Box::new)
            } else {
                None
            };
            let crl_now = acme_revocation
                .as_ref()
                .map_or(now, |plan| now.max(plan.revoked.at.seconds()));
            let revoked = if path == "revoke" {
                reject_unknown(body, &["serial_number"])?;
                let serial = self.resolve_certificate_serial(string(body, "serial_number")?)?;
                let at = if let Some(plan) = &acme_revocation {
                    if plan.revoked.issuer != key.issuer_id {
                        return Err(bad(
                            "ACME certificate requires its original external issuer",
                        ));
                    }
                    plan.revoked.at.seconds()
                } else if let Some(plan) = &ordinary_revocation {
                    plan.record.at.seconds()
                } else if let Some(issued) = self.issued.get(&serial) {
                    if !self.external_leaf_belongs_to_active(&serial) {
                        return Err(error(
                            501,
                            "retired issuer revocation requires its original signing authority",
                        ));
                    }
                    issued.revoked_at.unwrap_or(now.max(issued.issued))
                } else if let Some((issuer, issued, _, revoked)) = self.signed_ca_owner(&serial) {
                    if issuer != key.issuer_id {
                        return Err(bad("signed CA requires its original external parent"));
                    }
                    revoked.unwrap_or(now.max(issued))
                } else {
                    return Err(not_found());
                };
                Some((serial, at))
            } else {
                reject_unknown(body, &[])?;
                None
            };
            let mut entries = self
                .issued
                .iter()
                .filter_map(|(serial, issued)| {
                    issued
                        .revoked_at
                        .filter(|_| {
                            issued.expires > now
                                && (self.external_leaf_belongs_to_active(serial)
                                    || self.ordinary_orphan_candidate(serial))
                        })
                        .map(|at| (serial.clone(), at))
                })
                .collect::<BTreeMap<_, _>>();
            entries.extend(self.external_signed_ca_revocations(&key.issuer_id, now));
            entries.extend(self.acme_revoked_for_issuer(&key.issuer_id));
            if let Some((serial, at)) = &revoked {
                entries.insert(serial.clone(), *at);
            }
            let number = self.external.crls.as_ref().map_or(Ok(1), |crls| {
                crls.delta
                    .number
                    .checked_add(1)
                    .ok_or_else(|| error(507, "external CRL sequence exhausted"))
            })?;
            if number == u64::MAX {
                return Err(error(507, "external CRL sequence exhausted"));
            }
            ConsumptionTemplate::Crl {
                revoked,
                acme_revocation,
                ordinary_revocation,
                prepared: Box::new(
                    CrlSet::prepare(number, crl_now, entries, self.capture_urls(&key.issuer_id)?)
                        .with_certificate_issuer(
                        &captured_issuer.certificate_der,
                        &captured_issuer.common_name,
                    )?,
                ),
            }
        } else {
            return Ok(None);
        };
        Ok(Some(ExternalPkiTemplate {
            url_entries: None,
            url_warnings: Vec::new(),
            reference: key.reference.clone(),
            operation: "consume",
            output_format: RootOutputFormat::Pem,
            common_name: root.common_name.clone(),
            serial: String::new(),
            not_before: now,
            not_after: root.not_after,
            key_id: key.key_id.clone(),
            issuer_id: key.issuer_id.clone(),
            key_name: key.key_name.clone(),
            issuer_name: key.issuer_name.clone(),
            dns_san: key.dns_san,
            generated_at: now,
            consumption: Some(consumption),
            bound_public: Some(key.public_key.clone()),
            bound_issuer: Some(captured_issuer),
            imported: None,
            signed_ca: None,
            native_csr_body: None,
        }))
    }

    pub(super) fn publish_consumption(
        &mut self,
        material: ExternalPkiMaterial,
        signatures: &[Zeroizing<Vec<u8>>],
        now: u64,
    ) -> Result<EngineResponse> {
        if self
            .external
            .root
            .as_ref()
            .is_none_or(|key| key.issuer_id != material.template.issuer_id)
        {
            let original = self.external.root.as_ref().map(|key| key.issuer_id.clone());
            let mut candidate = self.clone();
            candidate
                .select_external_default(&material.template.issuer_id)
                .map_err(|_| error(503, "captured external issuer is unavailable"))?;
            let response = candidate.publish_consumption(material, signatures, now)?;
            candidate.restore_external_default(original.as_deref())?;
            *self = candidate;
            return Ok(response);
        }
        let captured_issuer = self.captured_external_issuer()?;
        let active_key = self
            .external
            .root
            .as_ref()
            .ok_or_else(|| bad("external PKI key missing"))?;
        if material.template.bound_issuer.as_ref() != Some(&captured_issuer)
            || material.public_key != captured_issuer.public_key
            || material.template.bound_public.as_ref() != Some(&captured_issuer.public_key)
            || material.template.reference != active_key.reference
            || material.template.issuer_id != active_key.issuer_id
            || material.template.key_id != active_key.key_id
            || material.template.key_name != active_key.key_name
            || material.template.issuer_name != active_key.issuer_name
            || material.template.dns_san != active_key.dns_san
        {
            return Err(error(
                503,
                "external PKI captured issuer changed before publication",
            ));
        }
        let consumption = material
            .consumption
            .ok_or_else(|| bad("external PKI consumption missing"))?;
        match consumption.template {
            ConsumptionTemplate::Leaf(prepared) => {
                prepared.validate_publication(now)?;
                if prepared.expires <= now
                    || prepared.owner_expires.is_some_and(|expires| expires <= now)
                {
                    return Err(error(403, "issuer no longer has a live PKI lease window"));
                }
                let public = consumption
                    .leaf_public
                    .ok_or_else(|| bad("external leaf public key missing"))?;
                self.admit_external_issuer_archive(&captured_issuer)?;
                let owner = captured_issuer.owner()?;
                if !prepared.local_issuer_id.is_empty()
                    || !prepared.role_time_owned
                        && i128::from(prepared.not_before) < i128::from(captured_issuer.not_before)
                    || prepared.expires > captured_issuer.not_after
                        && prepared.issuer_not_after_behavior
                            != Some(IssuerLeafNotAfterBehavior::Permit)
                {
                    return Err(bad("external PKI leaf owner or validity changed"));
                }
                let expected_tbs =
                    leaf_tbs(&captured_issuer, &material.public_key, &public, &prepared)?;
                if expected_tbs != material.tbs {
                    return Err(bad("external PKI captured leaf TBS changed"));
                }
                let serial = prepared.serial.clone();
                let no_store = prepared.no_store;
                let projection = LeafPublic {
                    url_entries: prepared.url_entries.clone(),
                    role_name_policy: prepared.role_name_policy.clone(),
                    exclude_cn_from_sans: prepared.exclude_cn_from_sans,
                    email_sans: prepared.email_sans.clone(),
                    uri_sans: prepared.uri_sans.clone(),
                    issuer_not_after_behavior: prepared.issuer_not_after_behavior,
                    signed_role_time_owned: prepared.signed_role_time_owned,
                    role_time_owned: prepared.role_time_owned,
                    issuer_id: captured_issuer.issuer_id.clone(),
                    role_leaf_profile: prepared.role_leaf_profile.clone(),
                    public_key: public,
                    not_before: prepared.not_before,
                    alt_names: prepared.alt_names.clone(),
                    ip_sans: prepared.ip_sans.clone(),
                };
                let scheme = material
                    .public_key
                    .leaf_signature(prepared.role_name_policy.as_ref());
                let response = self.publish_leaf(
                    *prepared,
                    signed_der_with_scheme(&material.tbs, &signatures[0], scheme),
                    &consumption.leaf_pkcs8,
                    &projection.public_key,
                    true,
                )?;
                if no_store {
                    return Ok(response);
                }
                // All fallible capture, owner and signature checks precede the
                // private leaf insertion; these closed values publish together.
                if let Some(issued) = self.issued.get_mut(&serial) {
                    issued.external_issuer_owner = Some(owner);
                }
                self.external
                    .archived_issuers
                    .insert(captured_issuer.issuer_id.clone(), captured_issuer);
                self.external.issued_public.insert(serial, projection);
                Ok(response)
            }
            ConsumptionTemplate::Crl {
                revoked,
                acme_revocation,
                ordinary_revocation,
                mut prepared,
            } => {
                if let Some(plan) = &acme_revocation {
                    plan.validate(self, now)?;
                }
                if let Some(plan) = &ordinary_revocation {
                    plan.validate(self, now)?;
                }
                prepared.sign(
                    &material.template.common_name,
                    &material.public_key,
                    signatures,
                )?;
                let response = if let Some(plan) = acme_revocation {
                    let response = plan.revoked.descriptor();
                    let protocol = self
                        .acme_protocol
                        .as_mut()
                        .ok_or_else(|| error(503, "ACME administrative protocol unavailable"))?;
                    protocol.observe_time(plan.revoked.at);
                    protocol
                        .revocations
                        .insert(plan.revoked.serial.clone(), plan.revoked);
                    response
                } else if let Some(plan) = ordinary_revocation {
                    self.admit_external_issuer_archive(&captured_issuer)?;
                    self.external
                        .archived_issuers
                        .insert(captured_issuer.issuer_id.clone(), captured_issuer.clone());
                    self.stage_ordinary_revocation(&plan)?
                } else if let Some((serial, at)) = revoked {
                    if let Some(issued) = self.issued.get_mut(&serial) {
                        issued.revoked_at = Some(at);
                    } else {
                        self.publish_external_signed_ca_revocation(
                            &serial,
                            &captured_issuer.issuer_id,
                            &captured_issuer.certificate_der,
                            at,
                        )?;
                    }
                    json!({"revocation_time":at,"revocation_time_rfc3339":timestamp(at),"state":"revoked"})
                } else {
                    json!({"success":true})
                };
                self.ordinary_crl_signed(&captured_issuer.issuer_id, &prepared.full.revoked);
                if self.ordinary_public_issuer_referenced(&captured_issuer.issuer_id) {
                    self.admit_external_issuer_archive(&captured_issuer)?;
                    self.external
                        .archived_issuers
                        .insert(captured_issuer.issuer_id.clone(), captured_issuer.clone());
                }
                self.external.crls = Some(*prepared);
                self.validate_acme_revocations()?;
                Ok(ok(response, true))
            }
        }
    }

    pub(in crate::engines::pki) fn external_crl_der(
        &self,
        delta: bool,
        now: u64,
    ) -> Result<Option<&[u8]>> {
        if self.external.root.is_none() {
            return Ok(None);
        }
        let crls = self
            .external
            .crls
            .as_ref()
            .ok_or_else(|| error(503, "external CRL rebuild is required"))?;
        // Existing token/lease revocation can retire a certificate without an
        // external effect dispatch. Never serve a signed cache that omits a
        // still-valid revoked certificate. An explicit grant-authorized rotate
        // must rebuild it; public reads cannot trigger or retry remote signing.
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| error(503, "external CRL issuer missing"))?;
        if !crls.matches_certificate_issuer(&root.certificate_der, &root.common_name)?
            || crls.full.expires <= now
            || crls.delta.expires <= now
            || self.issued.iter().any(|(serial, issued)| {
                issued.expires > now
                    && (self.external_leaf_belongs_to_active(serial)
                        || self.external.root.as_ref().is_some_and(|key| {
                            self.ordinary_orphan_for_crl(serial, &key.issuer_id)
                        }))
                    && issued
                        .revoked_at
                        .is_some_and(|at| crls.full.revoked.get(serial).copied() != Some(at))
            })
        {
            return Err(error(503, "external CRL rebuild is required"));
        }
        Ok(Some(&crls.selected(delta).der))
    }

    pub(in crate::engines::pki) fn external_crl_read(
        &self,
        path: &str,
        now: u64,
    ) -> Result<Option<EngineResponse>> {
        if self.external.root.is_none()
            || !matches!(
                path,
                "cert/crl" | "cert/delta-crl" | "crl" | "crl/pem" | "crl/delta" | "crl/delta/pem"
            )
        {
            return Ok(None);
        }
        let der = self
            .external_crl_der(path.contains("delta"), now)?
            .ok_or_else(not_found)?;
        if matches!(path, "cert/crl" | "cert/delta-crl") {
            return Ok(Some(ok(
                json!({"certificate":super::public::stored_pem("X509 CRL",der),"revocation_time":0,"revocation_time_rfc3339":""}),
                false,
            )));
        }
        let body = if path.ends_with("/pem") {
            super::public::stored_pem("X509 CRL", der).into_bytes()
        } else {
            der.to_vec()
        };
        Ok(Some(EngineResponse {
            status: 200,
            body: json!({"__heptabao_pki_crl":BASE64.encode(body),"pem":path.ends_with("/pem")}),
            mutated: false,
        }))
    }

    pub(in crate::engines::pki) fn external_leaf_issuer_reference(
        &self,
        serial: &str,
    ) -> Result<&str> {
        let leaf = self
            .external
            .issued_public
            .get(serial)
            .ok_or_else(not_found)?;
        if leaf.issuer_id.is_empty() {
            return self
                .external
                .root
                .as_ref()
                .map(|key| key.issuer_id.as_str())
                .ok_or_else(not_found);
        }
        let issuer = self
            .external
            .archived_issuers
            .get(&leaf.issuer_id)
            .ok_or_else(|| bad("external leaf issuer archive missing"))?;
        if self
            .issued
            .get(serial)
            .and_then(|issued| issued.external_issuer_owner.as_ref())
            != Some(&issuer.owner()?)
        {
            return Err(bad("external leaf issuer owner differs"));
        }
        Ok(&leaf.issuer_id)
    }

    fn external_leaf_belongs_to_active(&self, serial: &str) -> bool {
        let Some(key) = &self.external.root else {
            return false;
        };
        self.external.issued_public.get(serial).is_some_and(|leaf| {
            // Blank IDs are legacy projections, validated only with this active
            // actual root before they can be archived. Never use a retired key.
            leaf.issuer_id.is_empty() || leaf.issuer_id == key.issuer_id
        })
    }

    pub(in crate::engines::pki) fn reconcile_external_leaf_projections(&mut self) {
        self.external
            .issued_public
            .retain(|serial, _| self.issued.contains_key(serial));
        let mut referenced = self
            .external
            .issued_public
            .values()
            .map(|leaf| leaf.issuer_id.clone())
            .collect::<BTreeSet<_>>();
        referenced.extend(
            self.acme_certificates()
                .map(|certificate| certificate.issuer.clone()),
        );
        // Tidy has already removed the actual issued records. Root retirement
        // does not call this function and cannot discard signer history.
        self.external.archived_issuers.retain(|id, _| {
            referenced.contains(id)
                || self
                    .ordinary_revocations
                    .values()
                    .any(|r| r.references_issuer(id))
        });
    }

    pub(in crate::engines::pki) fn retire_external_leaf_issuer(
        &mut self,
        clock: u64,
    ) -> Result<()> {
        self.validate_external_consumption(clock)?;
        let issuer = self.captured_external_issuer()?;
        let unbound = self
            .external
            .issued_public
            .iter()
            .filter(|(_, leaf)| leaf.issuer_id.is_empty())
            .map(|(serial, _)| serial.clone())
            .collect::<Vec<_>>();
        if unbound.is_empty() {
            return Ok(());
        }
        self.admit_external_issuer_archive(&issuer)?;
        let owner = issuer.owner()?;
        // Validation above reconstructed each original TBS and verified its
        // signature against this actual root. No absent legacy projection is
        // guessed, and no leaf DER or historical None profile is rewritten.
        for serial in unbound {
            if let Some(leaf) = self.external.issued_public.get_mut(&serial) {
                leaf.issuer_id = issuer.issuer_id.clone();
            }
            if let Some(issued) = self.issued.get_mut(&serial) {
                issued.external_issuer_owner = Some(owner.clone());
            }
        }
        self.external
            .archived_issuers
            .insert(issuer.issuer_id.clone(), issuer);
        Ok(())
    }

    pub(in crate::engines::pki) fn validate_external_consumption(&self, clock: u64) -> Result<()> {
        self.validate_external_signer_history(clock)?;
        let active = self
            .external
            .root
            .as_ref()
            .map(|_| self.captured_external_issuer())
            .transpose()?;
        if let Some(crls) = &self.external.crls {
            let issuer = active
                .as_ref()
                .ok_or_else(|| bad("external CRL has no active issuer"))?;
            crls.validate(issuer, clock)?;
            if crls.full.revoked.iter().any(|(serial, at)| {
                self.issued.get(serial).is_some_and(|issued| {
                    (!self.external_leaf_belongs_to_active(serial)
                        && !self.ordinary_orphan_for_crl(serial, &issuer.issuer_id))
                        || issued.revoked_at != Some(*at)
                }) || self
                    .signed_ca_owner(serial)
                    .is_some_and(|(id, _, _, revoked)| {
                        id != issuer.issuer_id || revoked != Some(*at)
                    })
                    || self.acme_revocation(serial).is_some_and(|revoked| {
                        revoked.issuer != issuer.issuer_id || revoked.at.seconds() != *at
                    })
            }) {
                return Err(bad("external CRL certificate issuer ownership mismatch"));
            }
        }
        if self.external.issued_public.len() > MAX_ISSUED
            || self.external.archived_issuers.len() > MAX_ISSUED
            || self.issued.iter().any(|(serial, issued)| {
                issued.external_issuer_owner.is_some()
                    && !self.external.issued_public.contains_key(serial)
            })
        {
            return Err(bad("external PKI leaf projection ownership mismatch"));
        }
        let mut referenced = BTreeSet::new();
        for (id, issuer) in &self.external.archived_issuers {
            if id != &issuer.issuer_id {
                return Err(bad("external PKI archive identity mismatch"));
            }
            issuer.validate()?;
            if self.has_external_signed_ca_issuer_reference(id, &issuer.certificate_der)?
                || self.has_external_acme_issuer_reference(id, &issuer.certificate_der)?
                || self.ordinary_public_issuer_referenced(id)
            {
                referenced.insert(id.clone());
            }
            if self.local_pki_identifiers_in_use(&issuer.issuer_id, &issuer.key_id) {
                return Err(bad("external PKI archive conflicts with local ownership"));
            }
            if active
                .as_ref()
                .is_some_and(|root| root.issuer_id == *id && root != issuer)
            {
                return Err(bad(
                    "active external PKI issuer replaced its public archive",
                ));
            }
        }
        for (serial, projection) in &self.external.issued_public {
            let issued = self
                .issued
                .get(serial)
                .ok_or_else(|| bad("external PKI leaf record missing"))?;
            let issuer = if projection.issuer_id.is_empty() {
                if issued.external_issuer_owner.is_some() {
                    return Err(bad("external PKI legacy owner differs"));
                }
                active
                    .as_ref()
                    .ok_or_else(|| bad("unbound external PKI historical issuer is unavailable"))?
            } else {
                let issuer = self
                    .external
                    .archived_issuers
                    .get(&projection.issuer_id)
                    .ok_or_else(|| bad("external PKI archived issuer missing"))?;
                if issued.external_issuer_owner.as_ref() != Some(&issuer.owner()?) {
                    return Err(bad("external PKI private leaf issuer owner differs"));
                }
                referenced.insert(projection.issuer_id.clone());
                issuer
            };
            if issued.url_entries != projection.url_entries
                || !issued.local_issuer_id.is_empty()
                || projection.signed_role_time_owned != issued.signed_role_time_owned
                || projection.signed_role_time_owned != (projection.not_before < 0)
                || projection.not_before < 0 && !issued.role_time_owned
                || projection.issuer_not_after_behavior != issued.issuer_not_after_behavior
                || projection.role_time_owned != issued.role_time_owned
                || !issued.role_time_owned
                    && i128::from(projection.not_before) > i128::from(issued.issued)
                || issued.issued >= issued.expires
                || projection.alt_names.len() > 32
                || projection.ip_sans.len() > 32
                || projection
                    .alt_names
                    .iter()
                    .any(|name| !valid_common_name(name))
                || !issued.role_time_owned
                    && i128::from(projection.not_before) < i128::from(issuer.not_before)
                || issued.expires > issuer.not_after
                    && issued.issuer_not_after_behavior != Some(IssuerLeafNotAfterBehavior::Permit)
            {
                return Err(bad("invalid external PKI leaf projection"));
            }
            if let Some(policy) = &projection.role_name_policy {
                policy.validate()?;
                policy.validate_sans(&projection.ip_sans, &projection.uri_sans)?;
                policy.validate_subject_capture(
                    projection
                        .role_leaf_profile
                        .as_ref()
                        .and_then(|profile| profile.leaf_subject_evidence.as_ref()),
                )?;
            }
            if issued.role_names_owned != projection.role_name_policy.is_some()
                || projection.role_name_policy.is_none()
                    && (projection.exclude_cn_from_sans
                        || projection
                            .role_leaf_profile
                            .as_ref()
                            .is_some_and(|profile| profile.leaf_subject_evidence.is_some())
                        || !projection.email_sans.is_empty()
                        || !projection.uri_sans.is_empty())
                || projection.email_sans.len() > 33
                || projection.uri_sans.len() > 32
                || projection
                    .email_sans
                    .iter()
                    .chain(&projection.uri_sans)
                    .any(|value| !role_names::bounded_name(value))
            {
                return Err(bad("invalid external PKI captured role name evidence"));
            }
            match (&issued.role_leaf_profile, &projection.role_leaf_profile) {
                (None, None) => {}
                (Some(evidence), Some(profile))
                    if evidence.role_name_policy == projection.role_name_policy
                        && evidence.exclude_cn_from_sans == projection.exclude_cn_from_sans
                        && evidence.email_sans == projection.email_sans
                        && evidence.uri_sans == projection.uri_sans
                        && evidence.signed_role_time_owned == issued.signed_role_time_owned
                        && evidence.issuer_not_after_behavior
                            == issued.issuer_not_after_behavior
                        && evidence.role_time_owned == issued.role_time_owned
                        && evidence.profile == *profile
                        && evidence.public_key == projection.public_key
                        && evidence.not_before == projection.not_before
                        && evidence.alt_names == projection.alt_names
                        && evidence.ip_sans == projection.ip_sans => {}
                _ => return Err(bad("external PKI leaf profile projection differs")),
            }
            let prepared = LeafTemplate {
                url_entries: projection.url_entries.clone(),
                csr_public_key: None,
                role_name_policy: projection.role_name_policy.clone(),
                no_store: false,
                exclude_cn_from_sans: projection.exclude_cn_from_sans,
                email_sans: projection.email_sans.clone(),
                uri_sans: projection.uri_sans.clone(),
                issuer_not_after_behavior: issued.issuer_not_after_behavior,
                signed_role_time_owned: issued.signed_role_time_owned,
                role_time_owned: issued.role_time_owned,
                warnings: Vec::new(),
                role_leaf_profile: projection.role_leaf_profile.clone(),
                local_issuer_id: String::new(),
                serial: serial.clone(),
                path: issued.path.clone(),
                lease_id: issued.lease_id.clone(),
                owner: LeafOwner::Vault(issued.owner.clone()),
                owner_expires: None,
                precise_owner_expires: None,
                publication_time: crate::auth::AuthorityTime::Coarse(issued.issued),
                publication_clock: None,
                leased: issued.leased,
                common_name: issued.common_name.clone(),
                local_key_kind: projection.public_key.kind(),
                alt_names: projection.alt_names.clone(),
                ip_sans: projection.ip_sans.clone(),
                issued: issued.issued,
                not_before: projection.not_before,
                expires: issued.expires,
            };
            validate_signed_der_with_scheme(
                &issuer.public_key,
                &leaf_tbs(
                    issuer,
                    &issuer.public_key,
                    &projection.public_key,
                    &prepared,
                )?,
                &issued.certificate_der,
                issuer
                    .public_key
                    .leaf_signature(projection.role_name_policy.as_ref()),
            )?;
        }
        if self
            .external
            .archived_issuers
            .keys()
            .any(|id| !referenced.contains(id))
        {
            return Err(bad(
                "external PKI public issuer archive has no issued reference",
            ));
        }
        Ok(())
    }
}

impl ExternalPkiTemplate {
    pub(crate) fn validate_private_leaf_time(
        &self,
        time: crate::auth::AuthorityTime,
    ) -> Result<()> {
        match &self.consumption {
            Some(ConsumptionTemplate::Leaf(prepared)) => {
                prepared.validate_publication_observed(time)
            }
            Some(ConsumptionTemplate::Crl {
                ordinary_revocation: Some(plan),
                ..
            }) => plan.validate_actor(time),
            _ => Ok(()),
        }
    }
    pub(crate) fn leaf_lease_window(&self) -> Option<(u64, bool)> {
        match self.consumption.as_ref() {
            Some(ConsumptionTemplate::Leaf(prepared)) => Some((prepared.expires, prepared.leased)),
            _ => None,
        }
    }
    pub(crate) fn is_consumption(&self) -> bool {
        self.consumption.is_some()
    }
    pub(crate) fn leaf_owner(&self) -> Option<&LeaseOwner> {
        match self.consumption.as_ref() {
            Some(ConsumptionTemplate::Leaf(prepared)) => prepared.owner.vault_owner(),
            _ => None,
        }
    }
    pub(super) fn materialize_consumption(
        self,
        public: ExternalPkiPublicKey,
    ) -> Result<ExternalPkiMaterial> {
        if self.bound_public.as_ref() != Some(&public) {
            return Err(error(
                503,
                "external PKI provider public-key binding changed",
            ));
        }
        let consumption = self
            .consumption
            .clone()
            .ok_or_else(|| bad("external PKI consumption missing"))?;
        let (tbs, extra, leaf_pkcs8, leaf_public) = match &consumption {
            ConsumptionTemplate::Leaf(prepared) => {
                let (leaf_public, pkcs8) = if let Some(public) = &prepared.csr_public_key {
                    (public.clone(), Zeroizing::new(Vec::new()))
                } else {
                    let leaf = LocalPrivateMaterial::generate(prepared.local_key_kind)?;
                    (leaf.public()?, leaf.private_der()?)
                };
                let root = self
                    .bound_issuer
                    .as_ref()
                    .ok_or_else(|| bad("captured external PKI issuer missing"))?;
                root.validate()?;
                if root.public_key != public
                    || root.issuer_id != self.issuer_id
                    || root.key_id != self.key_id
                {
                    return Err(bad("captured external PKI issuer identity changed"));
                }
                (
                    leaf_tbs(root, &public, &leaf_public, prepared)?,
                    Vec::new(),
                    pkcs8,
                    Some(leaf_public),
                )
            }
            ConsumptionTemplate::Crl { prepared, .. } => {
                let mut tbs = prepared.tbs(&self.common_name, &public)?;
                let full = tbs.remove(0);
                (full, tbs, Zeroizing::new(Vec::new()), None)
            }
        };
        Ok(ExternalPkiMaterial {
            template: self,
            public_key: public,
            tbs,
            extra_tbs: extra,
            root_crls: None,
            native_csr: None,
            consumption: Some(ConsumptionMaterial {
                template: consumption,
                leaf_pkcs8,
                leaf_public,
            }),
        })
    }
}

// The effect owns a selected private signer and the exact prior signed CRLs.
// An ACME proof supplies only the public certificate revocation, never a token.
pub(crate) struct AcmeCrlTemplate {
    pub(crate) reference: String,
    issuer: ExternalPublicIssuer,
    prior_full: Vec<u8>,
    prior_delta: Vec<u8>,
    prepared: CrlSet,
    parts: Vec<Vec<u8>>,
}
impl AcmeCrlTemplate {
    pub(crate) fn validate_provider_public(&self, public: &ExternalPkiPublicKey) -> Result<()> {
        if public != &self.issuer.public_key {
            return Err(error(503, "ACME CRL provider public key changed"));
        }
        Ok(())
    }
    pub(in crate::engines) fn validate_issuer(&self, pki: &Pki) -> Result<()> {
        let mut selected = pki.clone();
        selected.select_external_default(&self.issuer.issuer_id)?;
        let actual = selected.captured_external_issuer()?;
        let key = selected.external.root.as_ref().ok_or_else(not_found)?;
        let crls = selected.external.crls.as_ref().ok_or_else(not_found)?;
        if actual != self.issuer
            || key.reference != self.reference
            || crls.full.der != self.prior_full
            || crls.delta.der != self.prior_delta
        {
            return Err(error(
                503,
                "ACME original CRL signer or signed frontier changed",
            ));
        }
        Ok(())
    }
    pub(crate) fn signing_inputs(&self) -> Result<Vec<Vec<u8>>> {
        self.parts
            .iter()
            .map(|part| {
                self.issuer
                    .public_key
                    .signing_input_leaf(part, self.issuer.public_key.leaf_signature(None))
            })
            .collect()
    }
    pub(crate) fn hash_algorithm(&self) -> Option<&'static str> {
        self.issuer.public_key.leaf_signature(None).hash_algorithm()
    }
    pub(crate) fn signature_algorithm(&self) -> &'static str {
        "pkcs1v15"
    }
    pub(crate) fn signature_size_bound(&self) -> usize {
        self.issuer.public_key.signature_size_bound()
    }
    pub(in crate::engines) fn publish(
        self,
        pki: &mut Pki,
        signatures: &[Zeroizing<Vec<u8>>],
        at: Timestamp,
    ) -> Result<()> {
        self.validate_issuer(pki)?;
        let original = pki.external.root.as_ref().map(|key| key.issuer_id.clone());
        let mut selected = pki.clone();
        selected.select_external_default(&self.issuer.issuer_id)?;
        let mut crls = self.prepared;
        crls.sign(
            &self.issuer.common_name,
            &self.issuer.public_key,
            signatures,
        )?;
        crls.validate(&self.issuer, at.seconds())?;
        selected.external.crls = Some(crls);
        selected.restore_external_default(original.as_deref())?;
        *pki = selected;
        Ok(())
    }
}
impl Pki {
    pub(in crate::engines) fn prepare_acme_external_crl(
        &self,
        revoked: &super::acme_revoke::Revocation,
        at: Timestamp,
    ) -> Result<AcmeCrlTemplate> {
        let mut selected = self.clone();
        selected.select_external_default(&revoked.issuer)?;
        let issuer = selected.captured_external_issuer()?;
        let key = selected.external.root.as_ref().ok_or_else(not_found)?;
        let previous = selected.external.crls.as_ref().ok_or_else(not_found)?;
        let number = previous
            .delta
            .number
            .checked_add(1)
            .filter(|number| *number != u64::MAX)
            .ok_or_else(|| error(507, "external CRL sequence exhausted"))?;
        let mut entries = selected
            .issued
            .iter()
            .filter_map(|(serial, cert)| {
                cert.revoked_at
                    .filter(|_| {
                        cert.expires > at.seconds()
                            && selected.external_leaf_belongs_to_active(serial)
                    })
                    .map(|time| (serial.clone(), time))
            })
            .collect::<BTreeMap<_, _>>();
        entries.extend(selected.external_signed_ca_revocations(&issuer.issuer_id, at.seconds()));
        entries.extend(selected.acme_revoked_for_issuer(&issuer.issuer_id));
        entries.insert(revoked.serial.clone(), revoked.at.seconds());
        let prepared = CrlSet::prepare(
            number,
            at.seconds(),
            entries,
            selected.capture_urls(&issuer.issuer_id)?,
        )
        .with_certificate_issuer(&issuer.certificate_der, &issuer.common_name)?;
        let parts = prepared.tbs(&issuer.common_name, &issuer.public_key)?;
        Ok(AcmeCrlTemplate {
            reference: key.reference.clone(),
            issuer,
            prior_full: previous.full.der.clone(),
            prior_delta: previous.delta.der.clone(),
            prepared,
            parts,
        })
    }
}
