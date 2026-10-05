//! External CA consumption contains public issuer state only. A leaf private
//! key exists in a zeroizing effect result until one successful publication.
use super::*;

#[derive(Clone)]
pub(super) enum ConsumptionTemplate {
    Leaf(LeafTemplate),
    Crl {
        revoked: Option<(String, u64)>,
        prepared: CrlSet,
    },
}

pub(super) struct ConsumptionMaterial {
    pub(super) template: ConsumptionTemplate,
    pub(super) leaf_pkcs8: Zeroizing<Vec<u8>>,
    pub(super) leaf_public: Option<LocalPublicKey>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LeafPublic {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    issuer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_leaf_profile: Option<RoleLeafProfile>,
    public_key: LocalPublicKey,
    not_before: u64,
    alt_names: Vec<String>,
    ip_sans: Vec<IpAddr>,
}

impl LeafPublic {
    pub(super) fn has_role_leaf_profile(&self) -> bool {
        self.role_leaf_profile.is_some() || !self.issuer_id.is_empty()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Crl {
    number: u64,
    base: Option<u64>,
    issued: u64,
    expires: u64,
    revoked: BTreeMap<String, u64>,
    der: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CrlSet {
    full: Crl,
    delta: Crl,
}

impl CrlSet {
    pub(super) fn empty(now: u64) -> Self {
        Self::prepare(1, now, BTreeMap::new())
    }
    fn prepare(number: u64, now: u64, revoked: BTreeMap<String, u64>) -> Self {
        let crl = |number, base, revoked| Crl {
            number,
            base,
            issued: now,
            expires: now.saturating_add(72 * 3600),
            revoked,
            der: Vec::new(),
        };
        Self {
            full: crl(number, None, revoked),
            delta: crl(number + 1, Some(number), BTreeMap::new()),
        }
    }
    pub(super) fn tbs(&self, issuer: &str, public: &ExternalPkiPublicKey) -> Result<Vec<Vec<u8>>> {
        Ok(vec![
            crl_tbs(issuer, public, &self.full)?,
            crl_tbs(issuer, public, &self.delta)?,
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
    pub(super) fn validate(
        &self,
        issuer: &str,
        public: &ExternalPkiPublicKey,
        clock: u64,
    ) -> Result<()> {
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
            validate_signed_der(public, &crl_tbs(issuer, public, crl)?, &crl.der)?;
        }
        Ok(())
    }
    fn selected(&self, delta: bool) -> &Crl {
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

fn crl_tbs(issuer: &str, public: &ExternalPkiPublicKey, crl: &Crl) -> Result<Vec<u8>> {
    let mut parts = vec![
        integer(&[1]),
        public.signature_algorithm(),
        name(issuer),
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
    let mut names = Vec::new();
    // Keep the historical None encoding; new captured profiles use the same
    // admitted DNS CN projection as the local certificate producer.
    if prepared.role_leaf_profile.is_none()
        || (!prepared.common_name.is_empty()
            && (!prepared.common_name.contains('*') || wildcard_dns_san(&prepared.common_name)))
    {
        names.push(context_primitive(2, prepared.common_name.as_bytes()));
    }
    names.extend(
        prepared
            .alt_names
            .iter()
            .map(|name| context_primitive(2, name.as_bytes())),
    );
    for ip in &prepared.ip_sans {
        let bytes = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        names.push(context_primitive(7, &bytes));
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
    if prepared.role_leaf_profile.is_none() || !names.is_empty() {
        extensions.push(extension(&[0x55, 0x1d, 0x11], false, &seq(&names)));
    }
    if let Some(profile) = &prepared.role_leaf_profile {
        let mut controlled = profile.leaf_extensions()?;
        controlled.extend(extensions.into_iter().skip(2));
        extensions = controlled;
    }
    Ok(seq(&[
        context_explicit(0, &integer(&[2])),
        integer(&serial_bytes(&prepared.serial)?),
        public.signature_algorithm(),
        if prepared.role_leaf_profile.is_some() {
            root_fields::certificate_subject(&root.certificate_der)?
        } else {
            name(&root.common_name)
        },
        seq(&[time(prepared.not_before), time(prepared.expires)]),
        prepared.role_leaf_profile.as_ref().map_or_else(
            || name(&prepared.common_name),
            |profile| profile.subject_der(&prepared.common_name),
        ),
        leaf_public.spki()?,
        context_explicit(3, &seq(&extensions)),
    ]))
}

impl Pki {
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
        owner: Option<&crate::auth::ResolvedLeaseOwner>,
        now: u64,
    ) -> Result<Option<ExternalPkiTemplate>> {
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
            .map(|role| (None, role))
            .or_else(|| {
                Self::issuer_issue_route(path).map(|(reference, role)| (Some(reference), role))
            });
        let consumption = if let Some((reference, role)) = issue {
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
            let mut prepared =
                self.prepare_leaf(mount, role, body, &owner.owner, owner.expires_at, now)?;
            if reference.is_some() {
                // Preserve the actual authorized issuer route in the lease graph.
                prepared.path = format!("{mount}{path}");
            }
            prepared.serial = external_serial()?;
            prepared.lease_id = format!("{}/{}", prepared.path, prepared.serial);
            prepared.not_before = now.saturating_sub(30).max(root.not_before);
            ConsumptionTemplate::Leaf(prepared)
        } else if path == "revoke" || path == "crl/rotate" {
            if (path == "revoke" && !write_method(method))
                || (path == "crl/rotate" && method != "GET")
            {
                return Err(unsupported());
            }
            let revoked = if path == "revoke" {
                reject_unknown(body, &["serial_number"])?;
                let serial = normalize_serial(string(body, "serial_number")?)?;
                let issued = self.issued.get(&serial).ok_or_else(not_found)?;
                if !self.external_leaf_belongs_to_active(&serial) {
                    return Err(error(
                        501,
                        "retired issuer revocation requires its original signing authority",
                    ));
                }
                Some((serial, issued.revoked_at.unwrap_or(now.max(issued.issued))))
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
                            issued.expires > now && self.external_leaf_belongs_to_active(serial)
                        })
                        .map(|at| (serial.clone(), at))
                })
                .collect::<BTreeMap<_, _>>();
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
                prepared: CrlSet::prepare(number, now, entries),
            }
        } else {
            return Ok(None);
        };
        Ok(Some(ExternalPkiTemplate {
            reference: key.reference.clone(),
            operation: "consume",
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
        }))
    }

    pub(super) fn publish_consumption(
        &mut self,
        material: ExternalPkiMaterial,
        signatures: &[Zeroizing<Vec<u8>>],
        now: u64,
    ) -> Result<EngineResponse> {
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
                    || prepared.not_before < captured_issuer.not_before
                    || prepared.expires > captured_issuer.not_after
                {
                    return Err(bad("external PKI leaf owner or validity changed"));
                }
                let expected_tbs =
                    leaf_tbs(&captured_issuer, &material.public_key, &public, &prepared)?;
                if expected_tbs != material.tbs {
                    return Err(bad("external PKI captured leaf TBS changed"));
                }
                let serial = prepared.serial.clone();
                let projection = LeafPublic {
                    issuer_id: captured_issuer.issuer_id.clone(),
                    role_leaf_profile: prepared.role_leaf_profile.clone(),
                    public_key: public,
                    not_before: prepared.not_before,
                    alt_names: prepared.alt_names.clone(),
                    ip_sans: prepared.ip_sans.clone(),
                };
                let response = self.publish_leaf(
                    prepared,
                    signed_der(&material.tbs, &signatures[0], &material.public_key),
                    &consumption.leaf_pkcs8,
                    &projection.public_key,
                    true,
                )?;
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
                mut prepared,
            } => {
                prepared.sign(
                    &material.template.common_name,
                    &material.public_key,
                    signatures,
                )?;
                let response = if let Some((serial, at)) = revoked {
                    self.issued
                        .get_mut(&serial)
                        .ok_or_else(not_found)?
                        .revoked_at = Some(at);
                    json!({"revocation_time":at,"revocation_time_rfc3339":timestamp(at),"state":"revoked"})
                } else {
                    json!({"success":true})
                };
                self.external.crls = Some(prepared);
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
        if crls.full.expires <= now
            || crls.delta.expires <= now
            || self.issued.iter().any(|(serial, issued)| {
                issued.expires > now
                    && self.external_leaf_belongs_to_active(serial)
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
        let referenced = self
            .external
            .issued_public
            .values()
            .map(|leaf| leaf.issuer_id.clone())
            .collect::<BTreeSet<_>>();
        // Tidy has already removed the actual issued records. Root retirement
        // does not call this function and cannot discard signer history.
        self.external
            .archived_issuers
            .retain(|id, _| referenced.contains(id));
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
            crls.validate(&issuer.common_name, &issuer.public_key, clock)?;
            if crls.full.revoked.iter().any(|(serial, at)| {
                self.issued.get(serial).is_some_and(|issued| {
                    !self.external_leaf_belongs_to_active(serial) || issued.revoked_at != Some(*at)
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
            if !issued.local_issuer_id.is_empty()
                || projection.not_before > issued.issued
                || issued.issued >= issued.expires
                || projection.alt_names.len() > 32
                || projection.ip_sans.len() > 32
                || projection
                    .alt_names
                    .iter()
                    .any(|name| !valid_common_name(name))
                || projection.not_before < issuer.not_before
                || issued.expires > issuer.not_after
            {
                return Err(bad("invalid external PKI leaf projection"));
            }
            match (&issued.role_leaf_profile, &projection.role_leaf_profile) {
                (None, None) => {}
                (Some(evidence), Some(profile))
                    if evidence.profile == *profile
                        && evidence.public_key == projection.public_key
                        && evidence.not_before == projection.not_before
                        && evidence.alt_names == projection.alt_names
                        && evidence.ip_sans == projection.ip_sans => {}
                _ => return Err(bad("external PKI leaf profile projection differs")),
            }
            let prepared = LeafTemplate {
                role_leaf_profile: projection.role_leaf_profile.clone(),
                local_issuer_id: String::new(),
                serial: serial.clone(),
                path: issued.path.clone(),
                lease_id: issued.lease_id.clone(),
                owner: issued.owner.clone(),
                owner_expires: None,
                leased: issued.leased,
                common_name: issued.common_name.clone(),
                local_key_kind: projection.public_key.kind(),
                alt_names: projection.alt_names.clone(),
                ip_sans: projection.ip_sans.clone(),
                issued: issued.issued,
                not_before: projection.not_before,
                expires: issued.expires,
            };
            validate_signed_der(
                &issuer.public_key,
                &leaf_tbs(
                    issuer,
                    &issuer.public_key,
                    &projection.public_key,
                    &prepared,
                )?,
                &issued.certificate_der,
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
            Some(ConsumptionTemplate::Leaf(prepared)) => Some(&prepared.owner),
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
                let leaf = LocalPrivateMaterial::generate(prepared.local_key_kind)?;
                let pkcs8 = leaf.private_der()?;
                let leaf_public = leaf.public()?;
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
            consumption: Some(ConsumptionMaterial {
                template: consumption,
                leaf_pkcs8,
                leaf_public,
            }),
        })
    }
}
