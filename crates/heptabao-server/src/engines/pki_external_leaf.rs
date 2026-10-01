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
    pub(super) leaf_public: Option<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LeafPublic {
    public_key: [u8; 32],
    not_before: u64,
    alt_names: Vec<String>,
    ip_sans: Vec<IpAddr>,
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
    pub(super) fn tbs(&self, issuer: &str, public: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        Ok(vec![
            crl_tbs(issuer, public, &self.full)?,
            crl_tbs(issuer, public, &self.delta)?,
        ])
    }
    pub(super) fn sign(
        &mut self,
        issuer: &str,
        public: &[u8; 32],
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
            crl.der = signed_der(&tbs, signature);
            validate_signed_der(public, &tbs, &crl.der)?;
        }
        Ok(())
    }
    pub(super) fn validate(&self, issuer: &str, public: &[u8; 32], clock: u64) -> Result<()> {
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

fn crl_tbs(issuer: &str, public: &[u8; 32], crl: &Crl) -> Result<Vec<u8>> {
    let mut parts = vec![
        integer(&[1]),
        algorithm_ed25519(),
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
            &seq(&[context_primitive(0, &key_identifier(public))]),
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
    root: &RootCa,
    public: &[u8; 32],
    leaf_public: &[u8; 32],
    prepared: &LeafTemplate,
) -> Result<Vec<u8>> {
    let mut names = vec![context_primitive(2, prepared.common_name.as_bytes())];
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
    let extensions = vec![
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
            &octet_string(&key_identifier(leaf_public)),
        ),
        extension(
            &[0x55, 0x1d, 0x23],
            false,
            &seq(&[context_primitive(0, &key_identifier(public))]),
        ),
        extension(&[0x55, 0x1d, 0x11], false, &seq(&names)),
    ];
    Ok(seq(&[
        context_explicit(0, &integer(&[2])),
        integer(&serial_bytes(&prepared.serial)?),
        algorithm_ed25519(),
        name(&root.common_name),
        seq(&[time(prepared.not_before), time(prepared.expires)]),
        name(&prepared.common_name),
        seq(&[algorithm_ed25519(), bit_string(leaf_public, 0)]),
        context_explicit(3, &seq(&extensions)),
    ]))
}

impl Pki {
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
        let consumption = if let Some(role) = path.strip_prefix("issue/") {
            if !write_method(method) {
                return Err(unsupported());
            }
            if role.is_empty() || role.contains('/') {
                return Err(not_found());
            }
            let owner = owner.ok_or_else(|| error(403, "credential issuer is required"))?;
            let mut prepared =
                self.prepare_leaf(mount, role, body, &owner.owner, owner.expires_at, now)?;
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
                        .filter(|_| issued.expires > now)
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
            bound_public: Some(key.public_key),
        }))
    }

    pub(super) fn publish_consumption(
        &mut self,
        material: ExternalPkiMaterial,
        signatures: &[Zeroizing<Vec<u8>>],
        now: u64,
    ) -> Result<EngineResponse> {
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
                let serial = prepared.serial.clone();
                let projection = LeafPublic {
                    public_key: public,
                    not_before: prepared.not_before,
                    alt_names: prepared.alt_names.clone(),
                    ip_sans: prepared.ip_sans.clone(),
                };
                let response = self.publish_leaf(
                    prepared,
                    signed_der(&material.tbs, &signatures[0]),
                    &consumption.leaf_pkcs8,
                    true,
                )?;
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
                    && issued
                        .revoked_at
                        .is_some_and(|at| crls.full.revoked.get(serial).copied() != Some(at))
            })
        {
            return Err(error(503, "external CRL rebuild is required"));
        }
        let crl = crls.selected(path.contains("delta"));
        if matches!(path, "cert/crl" | "cert/delta-crl") {
            return Ok(Some(ok(
                json!({"certificate":super::public::stored_pem("X509 CRL",&crl.der),"revocation_time":0,"revocation_time_rfc3339":""}),
                false,
            )));
        }
        let body = if path.ends_with("/pem") {
            super::public::stored_pem("X509 CRL", &crl.der).into_bytes()
        } else {
            crl.der.clone()
        };
        Ok(Some(EngineResponse {
            status: 200,
            body: json!({"__heptabao_pki_crl":BASE64.encode(body),"pem":path.ends_with("/pem")}),
            mutated: false,
        }))
    }

    pub(in crate::engines::pki) fn reconcile_external_leaf_projections(&mut self) {
        self.external
            .issued_public
            .retain(|serial, _| self.issued.contains_key(serial));
    }

    pub(in crate::engines::pki) fn validate_external_consumption(&self, clock: u64) -> Result<()> {
        let Some(key) = self.external.root.as_ref() else {
            if self.external.crls.is_some() || !self.external.issued_public.is_empty() {
                return Err(bad("external PKI issuer ownership mismatch"));
            }
            return Ok(());
        };
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| bad("external PKI issuer missing"))?;
        if let Some(crls) = &self.external.crls {
            crls.validate(&root.common_name, &key.public_key, clock)?;
        }
        if self.external.issued_public.len() != self.issued.len() {
            return Err(bad("external PKI leaf projection cardinality mismatch"));
        }
        for (serial, issued) in &self.issued {
            let projection = self
                .external
                .issued_public
                .get(serial)
                .ok_or_else(|| bad("external PKI leaf projection missing"))?;
            if projection.not_before > issued.issued
                || projection.alt_names.len() > 32
                || projection.ip_sans.len() > 32
                || projection
                    .alt_names
                    .iter()
                    .any(|name| !valid_common_name(name))
                || projection.not_before < root.not_before
            {
                return Err(bad("invalid external PKI leaf projection"));
            }
            let prepared = LeafTemplate {
                serial: serial.clone(),
                path: issued.path.clone(),
                lease_id: issued.lease_id.clone(),
                owner: issued.owner.clone(),
                owner_expires: None,
                leased: issued.leased,
                common_name: issued.common_name.clone(),
                alt_names: projection.alt_names.clone(),
                ip_sans: projection.ip_sans.clone(),
                issued: issued.issued,
                not_before: projection.not_before,
                expires: issued.expires,
            };
            validate_signed_der(
                &key.public_key,
                &leaf_tbs(root, &key.public_key, &projection.public_key, &prepared)?,
                &issued.certificate_der,
            )?;
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
    pub(super) fn materialize_consumption(self, public: [u8; 32]) -> Result<ExternalPkiMaterial> {
        if self.bound_public != Some(public) {
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
                let pkcs8 = Zeroizing::new(
                    Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                        .map_err(|_| error(503, "PKI leaf key generation failed"))?
                        .as_ref()
                        .to_vec(),
                );
                let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
                    .map_err(|_| error(503, "PKI leaf key generation failed"))?;
                let leaf_public: [u8; 32] = pair
                    .public_key()
                    .as_ref()
                    .try_into()
                    .map_err(|_| error(503, "PKI leaf public key generation failed"))?;
                let root = RootCa {
                    common_name: self.common_name.clone(),
                    pkcs8: Vec::new(),
                    certificate_der: Vec::new(),
                    serial: String::new(),
                    not_before: self.not_before,
                    not_after: self.not_after,
                };
                (
                    leaf_tbs(&root, &public, &leaf_public, prepared)?,
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
