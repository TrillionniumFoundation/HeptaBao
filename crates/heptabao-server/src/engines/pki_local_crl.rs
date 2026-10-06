//! Durable local CRLs. Public reads project signed bytes; only a persisted
//! engine transaction can allocate a number or consume pending revocations.
use super::*;
use x509_parser::prelude::{CertificateRevocationList, FromDer};

const MAX_CRL_DER: usize = 512 * 1024;
const MAX_CRL_NUMBER: u64 = i64::MAX as u64;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CrlConfig {
    expiry: String,
    disable: bool,
    ocsp_disable: bool,
    ocsp_expiry: String,
    auto_rebuild: bool,
    auto_rebuild_grace_period: String,
    enable_delta: bool,
    delta_rebuild_interval: String,
    allow_expired_cert_revocation: bool,
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            expiry: "72h".into(),
            disable: false,
            ocsp_disable: false,
            ocsp_expiry: "12h".into(),
            auto_rebuild: false,
            auto_rebuild_grace_period: "12h".into(),
            enable_delta: false,
            delta_rebuild_interval: "15m".into(),
            allow_expired_cert_revocation: false,
        }
    }
}

fn duration(value: &str) -> Result<u64> {
    if value.is_empty() || value.len() > 64 {
        return Err(bad("invalid local PKI CRL duration"));
    }
    let seconds = duration_seconds(&json!(value))?;
    if seconds > MAX_TTL {
        return Err(bad("local PKI CRL duration exceeds bounds"));
    }
    Ok(seconds)
}

impl CrlConfig {
    fn validate(&self) -> Result<()> {
        let expiry = duration(&self.expiry)?;
        let grace = duration(&self.auto_rebuild_grace_period)?;
        let delta = duration(&self.delta_rebuild_interval)?;
        duration(&self.ocsp_expiry)?;
        if expiry == 0
            || self.auto_rebuild && grace >= expiry
            || self.enable_delta && (!self.auto_rebuild || delta == 0 || delta >= expiry)
        {
            return Err(bad("invalid local PKI CRL rebuild policy"));
        }
        Ok(())
    }

    fn updated(&self, body: &Value) -> Result<Self> {
        reject_unknown(
            body,
            &[
                "expiry",
                "disable",
                "ocsp_disable",
                "ocsp_expiry",
                "auto_rebuild",
                "auto_rebuild_grace_period",
                "enable_delta",
                "delta_rebuild_interval",
                "allow_expired_cert_revocation",
            ],
        )?;
        let mut next = self.clone();
        for (name, target) in [
            ("expiry", &mut next.expiry),
            ("ocsp_expiry", &mut next.ocsp_expiry),
            (
                "auto_rebuild_grace_period",
                &mut next.auto_rebuild_grace_period,
            ),
            ("delta_rebuild_interval", &mut next.delta_rebuild_interval),
        ] {
            if let Some(value) = body.get(name) {
                *target = value
                    .as_str()
                    .ok_or_else(|| bad("CRL duration must be a string"))?
                    .into();
            }
        }
        for (name, target) in [
            ("disable", &mut next.disable),
            ("ocsp_disable", &mut next.ocsp_disable),
            ("auto_rebuild", &mut next.auto_rebuild),
            ("enable_delta", &mut next.enable_delta),
            (
                "allow_expired_cert_revocation",
                &mut next.allow_expired_cert_revocation,
            ),
        ] {
            if let Some(value) = optional_bool(body, name)? {
                *target = value;
            }
        }
        next.validate()?;
        Ok(next)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct CrlSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url_entries: Option<UrlEntries>,
    number: u64,
    base: Option<u64>,
    this_update: u64,
    next_update: u64,
    revoked: BTreeMap<String, u64>,
    der: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct IssuerCrl {
    last_number: u64,
    full: CrlSnapshot,
    delta: CrlSnapshot,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub(super) struct LocalCrlState {
    config: CrlConfig,
    issuers: BTreeMap<String, IssuerCrl>,
    rebuild_required: bool,
}

fn issuer_key(root: &RootCa) -> String {
    if root.issuer_id.is_empty() {
        format!("legacy:{}", root.serial)
    } else {
        root.issuer_id.clone()
    }
}

fn next_number(number: u64) -> Result<u64> {
    number
        .checked_add(1)
        .filter(|n| *n <= MAX_CRL_NUMBER)
        .ok_or_else(|| error(503, "local PKI CRL number exhausted"))
}

fn authority_key_id(root: &RootCa) -> Result<Vec<u8>> {
    if let Some(key) = root_fields::certificate_key_identifier(&root.certificate_der)? {
        return Ok(key);
    }
    // Old certificates may lack SKI. This digest only identifies the actual
    // owned public key; certificate/key and signature proofs remain required.
    Ok(root_fields::subject_key_identifier(&root.local_key()?.public()?.spki()?)?.to_vec())
}

fn crl_tbs(root: &RootCa, snapshot: &CrlSnapshot) -> Result<Vec<u8>> {
    let mut parts = vec![
        integer(&[1]),
        root.local_key()?.kind().signature_algorithm(),
        root_fields::certificate_subject(&root.certificate_der)?,
        time(snapshot.this_update),
        time(snapshot.next_update),
    ];
    if !snapshot.revoked.is_empty() {
        let mut entries = Vec::with_capacity(snapshot.revoked.len());
        for (serial, at) in &snapshot.revoked {
            entries.push(seq(&[integer(&serial_bytes(serial)?), time(*at)]));
        }
        parts.push(seq(&entries));
    }
    let mut extensions = vec![
        extension(
            &[0x55, 0x1d, 0x23],
            false,
            &seq(&[context_primitive(0, &authority_key_id(root)?)]),
        ),
        extension(
            &[0x55, 0x1d, 0x14],
            false,
            &integer(&snapshot.number.to_be_bytes()),
        ),
    ];
    if let Some(base) = snapshot.base {
        extensions.push(extension(
            &[0x55, 0x1d, 0x1b],
            true,
            &integer(&base.to_be_bytes()),
        ));
    }
    if let Some(urls) = &snapshot.url_entries {
        urls.validate()?;
        if let Some(freshest) = urls.freshest_extension() {
            extensions.push(freshest);
        }
    }
    parts.push(context_explicit(0, &seq(&extensions)));
    Ok(seq(&parts))
}

fn prepare_snapshot(
    revoked: BTreeMap<String, u64>,
    number: u64,
    base: Option<u64>,
    now: u64,
    expiry: u64,
    url_entries: Option<UrlEntries>,
) -> Result<CrlSnapshot> {
    let snapshot = CrlSnapshot {
        url_entries,
        number,
        base,
        this_update: now,
        next_update: now
            .checked_add(expiry)
            .ok_or_else(|| bad("CRL time overflow"))?,
        revoked,
        der: Vec::new(),
    };
    if snapshot.next_update > 253_402_300_799 {
        return Err(bad("CRL time exceeds X.509 bounds"));
    }
    Ok(snapshot)
}
fn sign_prepared_snapshot(
    root: &RootCa,
    mut snapshot: CrlSnapshot,
    before_sign: &mut impl FnMut() -> Result<()>,
) -> Result<CrlSnapshot> {
    let pair = root.local_key()?;
    let tbs = crl_tbs(root, &snapshot)?;
    // Metadata/TBS work cannot consume the accepted actor or request window
    // and still enter a signature with renewed authority.
    before_sign()?;
    let signature = pair.sign(&tbs)?;
    if !pair.public()?.verify(&tbs, &signature)? {
        return Err(error(503, "local PKI CRL signature failed validation"));
    }
    snapshot.der = seq(&[
        tbs,
        pair.kind().signature_algorithm(),
        bit_string(&signature, 0),
    ]);
    if snapshot.der.len() > MAX_CRL_DER {
        return Err(error(507, "local PKI CRL exceeds bounds"));
    }
    Ok(snapshot)
}

impl Pki {
    pub(super) fn has_local_crl_url_state(&self) -> bool {
        self.local_crl.as_ref().is_some_and(|state| {
            state
                .issuers
                .values()
                .any(|crls| crls.full.url_entries.is_some() || crls.delta.url_entries.is_some())
        })
    }
    pub(in crate::engines) fn has_local_crl_state(&self) -> bool {
        self.local_crl.is_some()
    }

    pub(super) fn local_ocsp_policy(&self) -> Result<(bool, u64)> {
        let config = self.local_crl_config();
        Ok((config.ocsp_disable, duration(&config.ocsp_expiry)?))
    }

    fn local_crl_config(&self) -> CrlConfig {
        self.local_crl
            .as_ref()
            .map_or_else(CrlConfig::default, |state| state.config.clone())
    }

    pub(super) fn mark_local_crl_dirty(&mut self) {
        if let Some(state) = &mut self.local_crl {
            state.rebuild_required = !state.config.auto_rebuild;
        }
    }

    fn revoked_for_issuer(&self, root: &RootCa) -> BTreeMap<String, u64> {
        let mut revoked: BTreeMap<String, u64> = self
            .issued
            .iter()
            .filter_map(|(serial, cert)| {
                let at = cert.revoked_at?;
                if self.profile_leaf_is_external(serial) || cert.external_issuer_owner.is_some() {
                    return None;
                }
                let owned = if cert.local_issuer_id.is_empty() {
                    if !Self::legacy_leaf_is_signed_by(root, cert) {
                        return None;
                    }
                    self.root
                        .as_ref()
                        .is_some_and(|default| issuer_key(default) == issuer_key(root))
                } else {
                    cert.local_issuer_id == root.issuer_id
                };
                owned.then(|| (serial.clone(), at))
            })
            .collect();
        revoked.extend(self.signed_ca_revocations(root));
        revoked.extend(self.acme_revoked_for_issuer(&root.issuer_id));
        revoked
    }

    pub(super) fn rebuild_local_crls(&mut self, now: u64, delta: bool) -> Result<bool> {
        self.rebuild_local_crls_guarded(now, delta, &mut || Ok(()))
    }
    fn rebuild_local_crls_guarded(
        &mut self,
        now: u64,
        delta: bool,
        before_sign: &mut impl FnMut() -> Result<()>,
    ) -> Result<bool> {
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Ok(false);
        }
        let mut next = self.local_crl.as_deref().cloned().unwrap_or_default();
        next.config.validate()?;
        let expiry = duration(&next.config.expiry)?;
        let roots = self.local_roots().collect::<Vec<_>>();
        let active = roots
            .iter()
            .map(|root| issuer_key(root))
            .collect::<BTreeSet<_>>();
        next.issuers.retain(|key, _| active.contains(key));
        for root in roots {
            let key = issuer_key(root);
            let revoked = if next.config.disable {
                BTreeMap::new()
            } else {
                self.revoked_for_issuer(root)
            };
            if delta && let Some(previous) = next.issuers.get_mut(&key) {
                let pending = revoked
                    .into_iter()
                    .filter(|(serial, at)| previous.full.revoked.get(serial) != Some(at))
                    .collect();
                let number = next_number(previous.last_number)?;
                previous.delta = sign_prepared_snapshot(
                    root,
                    prepare_snapshot(
                        pending,
                        number,
                        Some(previous.full.number),
                        now,
                        expiry,
                        None,
                    )?,
                    before_sign,
                )?;
                previous.last_number = number;
            } else {
                let full_number = next_number(
                    next.issuers
                        .get(&key)
                        .map_or(0, |previous| previous.last_number),
                )?;
                let delta_number = next_number(full_number)?;
                let full = sign_prepared_snapshot(
                    root,
                    prepare_snapshot(
                        revoked,
                        full_number,
                        None,
                        now,
                        expiry,
                        self.capture_urls(&root.issuer_id)?,
                    )?,
                    before_sign,
                )?;
                let delta = sign_prepared_snapshot(
                    root,
                    prepare_snapshot(
                        BTreeMap::new(),
                        delta_number,
                        Some(full_number),
                        now,
                        expiry,
                        None,
                    )?,
                    before_sign,
                )?;
                next.issuers.insert(
                    key,
                    IssuerCrl {
                        last_number: delta_number,
                        full,
                        delta,
                    },
                );
            }
        }
        next.rebuild_required = false;
        self.local_crl = Some(Box::new(next));
        Ok(true)
    }

    /// Must run inside the authenticated, deadline-bound engine transaction.
    /// Its caller persists a true return before exposing the resulting cache.
    pub(in crate::engines) fn maintain_local_crl(&mut self, now: u64) -> Result<bool> {
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Ok(false);
        }
        let Some(state) = &self.local_crl else {
            return if self.local_roots().next().is_some() {
                self.rebuild_local_crls(now, false)
            } else {
                Ok(false)
            };
        };
        let keys = self.local_roots().map(issuer_key).collect::<BTreeSet<_>>();
        if state.rebuild_required || keys != state.issuers.keys().cloned().collect() {
            return self.rebuild_local_crls(now, false);
        }
        if state.config.disable || !state.config.auto_rebuild {
            return Ok(false);
        }
        let grace = duration(&state.config.auto_rebuild_grace_period)?;
        if state
            .issuers
            .values()
            .any(|cached| now >= cached.full.next_update.saturating_sub(grace))
        {
            return self.rebuild_local_crls(now, false);
        }
        if state.config.enable_delta {
            let interval = duration(&state.config.delta_rebuild_interval)?;
            let mut due = false;
            for root in self.local_roots() {
                let cached = state
                    .issuers
                    .get(&issuer_key(root))
                    .ok_or_else(|| bad("missing issuer CRL cache"))?;
                let pending = self
                    .revoked_for_issuer(root)
                    .into_iter()
                    .filter(|(serial, at)| cached.full.revoked.get(serial) != Some(at))
                    .collect::<BTreeMap<_, _>>();
                if now >= cached.delta.this_update.saturating_add(interval)
                    && pending != cached.delta.revoked
                {
                    due = true;
                    break;
                }
            }
            if due {
                return self.rebuild_local_crls(now, true);
            }
        }
        Ok(false)
    }

    pub(super) fn cached_local_crl(&self, root: &RootCa, delta: bool) -> Result<&[u8]> {
        let cached = self
            .local_crl
            .as_ref()
            .and_then(|state| state.issuers.get(&issuer_key(root)))
            .ok_or_else(|| error(503, "local PKI CRL requires durable maintenance"))?;
        Ok(if delta {
            &cached.delta.der
        } else {
            &cached.full.der
        })
    }

    pub(super) fn handle_local_crl(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<EngineResponse>> {
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Ok(None);
        }
        if path == "config/crl" {
            let before = self.local_crl_config();
            if method == "GET" {
                reject_unknown(body, &[])?;
                return Ok(Some(ok(
                    serde_json::to_value(before)
                        .map_err(|_| bad("CRL config serialization failed"))?,
                    false,
                )));
            }
            if !write_method(method) {
                return Err(unsupported());
            }
            let config = before.updated(body)?;
            let mut next = self.clone();
            next.local_crl.get_or_insert_with(Box::default).config = config.clone();
            let maintained = if before.disable != config.disable
                || before.auto_rebuild && !config.auto_rebuild
                || before.enable_delta != config.enable_delta
            {
                next.rebuild_local_crls(now, false)?
            } else {
                next.maintain_local_crl(now)?
            };
            let changed = before != config || self.local_crl.is_none() || maintained;
            *self = next;
            return Ok(Some(ok(
                serde_json::to_value(config).map_err(|_| bad("CRL config serialization failed"))?,
                changed,
            )));
        }
        if matches!(path, "crl/rotate" | "crl/rotate-delta") {
            if method != "GET" {
                return Err(unsupported());
            }
            reject_unknown(body, &[])?;
            let delta = path == "crl/rotate-delta";
            if delta && !self.local_crl_config().enable_delta {
                return Ok(Some(ok(json!({"success":true}), false)));
            }
            self.rebuild_local_crls(now, delta)?;
            return Ok(Some(ok(json!({"success":true}), true)));
        }
        Ok(None)
    }

    pub(super) fn local_revocation_changed_guarded(
        &mut self,
        now: u64,
        before_sign: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.mark_local_crl_dirty();
        if !self.local_crl_config().auto_rebuild {
            self.rebuild_local_crls_guarded(now, false, before_sign)?;
        }
        Ok(())
    }

    pub(super) fn local_revocation_changed(&mut self, now: u64) -> Result<()> {
        self.mark_local_crl_dirty();
        if !self.local_crl_config().auto_rebuild {
            self.rebuild_local_crls(now, false)?;
        }
        Ok(())
    }

    pub(super) fn local_expired_revocation_allowed(&self) -> bool {
        self.local_crl_config().allow_expired_cert_revocation
    }

    pub(super) fn validate_local_crls(&self, clock: u64) -> Result<()> {
        let Some(state) = &self.local_crl else {
            return Ok(());
        };
        state.config.validate()?;
        if state.issuers.len() > 256 {
            return Err(bad("invalid local PKI CRL ownership"));
        }
        let roots = self.local_roots().collect::<Vec<_>>();
        let keys = roots
            .iter()
            .map(|root| issuer_key(root))
            .collect::<BTreeSet<_>>();
        if keys != state.issuers.keys().cloned().collect() {
            return Err(bad("invalid local PKI CRL issuer cache"));
        }
        for root in roots {
            let cached = state
                .issuers
                .get(&issuer_key(root))
                .ok_or_else(|| bad("missing issuer CRL cache"))?;
            if cached.last_number != cached.delta.number
                || cached.full.number >= cached.delta.number
                || cached.full.base.is_some()
                || cached.delta.base != Some(cached.full.number)
                || cached.full.this_update > cached.delta.this_update
            {
                return Err(bad("invalid local PKI CRL number sequence"));
            }
            let owned = self.revoked_for_issuer(root);
            for snapshot in [&cached.full, &cached.delta] {
                if snapshot.number == 0
                    || snapshot.number > MAX_CRL_NUMBER
                    || snapshot.this_update > clock
                    || snapshot.next_update > 253_402_300_799
                    || snapshot.next_update <= snapshot.this_update
                    || snapshot.next_update - snapshot.this_update > MAX_TTL
                    || snapshot.revoked.len() > MAX_ISSUED
                    || snapshot.der.is_empty()
                    || snapshot.der.len() > MAX_CRL_DER
                    || snapshot.revoked.iter().any(|(serial, at)| {
                        owned.get(serial) != Some(at) || *at > snapshot.this_update
                    })
                    || snapshot.base.is_some()
                        && snapshot
                            .revoked
                            .iter()
                            .any(|(serial, _)| cached.full.revoked.contains_key(serial))
                {
                    return Err(bad("invalid local PKI CRL snapshot"));
                }
                let (rest, parsed) = CertificateRevocationList::from_der(&snapshot.der)
                    .map_err(|_| bad("invalid local PKI CRL DER"))?;
                let tbs = crl_tbs(root, snapshot)?;
                let algorithm = root.local_key()?.kind().signature_algorithm();
                if !rest.is_empty()
                    || parsed.signature_value.unused_bits != 0
                    || parsed.tbs_cert_list.as_ref() != tbs.as_slice()
                    || seq(&[
                        tbs.clone(),
                        algorithm,
                        bit_string(parsed.signature_value.data.as_ref(), 0),
                    ]) != snapshot.der
                    || !root
                        .local_key()?
                        .public()?
                        .verify(&tbs, parsed.signature_value.data.as_ref())?
                {
                    return Err(bad("local PKI CRL signature or metadata mismatch"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::extensions::ParsedExtension;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    const NOW: u64 = 1_700_000_000;

    fn root(pki: &mut Pki, name: &str, now: u64) -> Result<()> {
        pki.handle_admin(
            "POST",
            "root/generate/internal",
            &json!({
            "common_name":format!("{name}.example.test"),"issuer_name":name,
            "key_name":format!("key-{name}"),"key_type":"ec","key_bits":256,
            "organization":"Actual issuer organization","ttl":"48h"}),
            now,
        )?;
        Ok(())
    }

    fn issue(pki: &mut Pki, issuer: &str, now: u64) -> Result<String> {
        pki.handle_admin(
            "POST",
            "roles/web",
            &json!({"allowed_domains":["example.test"],
            "allow_subdomains":true,"key_type":"ec","key_bits":256,"max_ttl":"2h",
            "issuer_ref":issuer}),
            now,
        )?;
        let owner = serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))
            .map_err(|_| bad("test owner"))?;
        let response = pki.issue_route(
            "pki/",
            "issue/web",
            &json!({"common_name":"leaf.example.test","ttl":"1h"}),
            LeafAuthority {
                owner: &owner,
                owner_expires: None,
                precise_owner_expires: None,
                time: crate::auth::AuthorityTime::Coarse(now),
                clock: None,
                identity_templates: None,
            },
        )?;
        normalize_serial(
            response.body["data"]["serial_number"]
                .as_str()
                .ok_or_else(|| bad("test serial"))?,
        )
    }

    fn cache<'a>(pki: &'a Pki, issuer: &str) -> Result<&'a IssuerCrl> {
        pki.local_crl
            .as_ref()
            .and_then(|state| {
                state
                    .issuers
                    .get(&issuer_key(pki.local_issuer(issuer).ok()?))
            })
            .ok_or_else(|| bad("test CRL cache"))
    }

    fn delta_config(pki: &mut Pki, now: u64) -> Result<()> {
        pki.handle_admin(
            "POST",
            "config/crl",
            &json!({"auto_rebuild":true,"enable_delta":true,
            "expiry":"2h","auto_rebuild_grace_period":"5m","delta_rebuild_interval":"1m"}),
            now,
        )?;
        Ok(())
    }

    fn check_der(pki: &Pki, issuer: &str, delta: bool, count: usize) -> TestResult {
        let root = pki.local_issuer(issuer)?;
        let bytes = pki.cached_local_crl(root, delta)?;
        let (rest, parsed) = CertificateRevocationList::from_der(bytes)?;
        assert!(rest.is_empty());
        assert_eq!(
            parsed.issuer().as_raw(),
            root_fields::certificate_subject(&root.certificate_der)?
        );
        assert_eq!(parsed.iter_revoked_certificates().count(), count);
        assert!(root.local_key()?.public()?.verify(
            parsed.tbs_cert_list.as_ref(),
            parsed.signature_value.data.as_ref()
        )?);
        let number = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid.to_id_string() == "2.5.29.20")
            .ok_or("number")?;
        assert!(!number.critical);
        let expected = if delta {
            cache(pki, issuer)?.delta.number
        } else {
            cache(pki, issuer)?.full.number
        };
        assert_eq!(number.value, integer(&expected.to_be_bytes()));
        let aki = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid.to_id_string() == "2.5.29.35")
            .ok_or("AKI")?;
        assert!(!aki.critical);
        match aki.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(key) => assert_eq!(
                key.key_identifier.as_ref().map(|v| v.0),
                Some(authority_key_id(root)?.as_slice())
            ),
            _ => return Err("invalid AKI type".into()),
        }
        let base = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid.to_id_string() == "2.5.29.27");
        if delta {
            let base = base.ok_or("delta indicator")?;
            assert!(base.critical);
            assert_eq!(
                base.value,
                integer(&cache(pki, issuer)?.full.number.to_be_bytes())
            );
        } else {
            assert!(base.is_none());
        }
        Ok(())
    }

    #[test]
    fn full_delta_numbers_real_signatures_ownership_cached_reads_and_durable_restart() -> TestResult
    {
        let mut pki = Pki::default();
        root(&mut pki, "alpha", NOW)?;
        root(&mut pki, "beta", NOW)?;
        let a = issue(&mut pki, "alpha", NOW)?;
        let b = issue(&mut pki, "beta", NOW)?;
        delta_config(&mut pki, NOW)?;
        assert_eq!(
            (
                cache(&pki, "alpha")?.full.number,
                cache(&pki, "alpha")?.delta.number
            ),
            (5, 6)
        );
        let before = pki
            .cached_local_crl(pki.local_issuer("alpha")?, false)?
            .to_vec();
        pki.handle_admin("POST", "revoke", &json!({"serial_number":a}), NOW + 1)?;
        assert_eq!(
            before,
            pki.cached_local_crl(pki.local_issuer("alpha")?, false)?
        );
        check_der(&pki, "alpha", true, 0)?;
        assert_eq!(
            pki.handle_admin("GET", "crl/rotate-delta", &json!({}), NOW + 2)?
                .body["data"]["success"],
            true
        );
        assert_eq!(
            (
                cache(&pki, "alpha")?.full.number,
                cache(&pki, "alpha")?.delta.number
            ),
            (5, 7)
        );
        check_der(&pki, "alpha", true, 1)?;
        check_der(&pki, "beta", true, 0)?;
        assert_eq!(
            before,
            pki.cached_local_crl(pki.local_issuer("alpha")?, false)?
        );
        pki.handle_admin("GET", "crl/rotate", &json!({}), NOW + 3)?;
        assert_eq!(
            (
                cache(&pki, "alpha")?.full.number,
                cache(&pki, "alpha")?.delta.number
            ),
            (8, 9)
        );
        check_der(&pki, "alpha", false, 1)?;
        check_der(&pki, "alpha", true, 0)?;
        pki.handle_admin("POST", "revoke", &json!({"serial_number":b}), NOW + 4)?;
        pki.handle_admin("GET", "crl/rotate-delta", &json!({}), NOW + 5)?;
        check_der(&pki, "beta", false, 0)?;
        check_der(&pki, "beta", true, 1)?;
        check_der(&pki, "alpha", false, 1)?;
        check_der(&pki, "alpha", true, 0)?;
        pki.validate("", "pki/", NOW + 5)?;
        let durable = serde_json::to_vec(&pki)?;
        let restored: Pki = serde_json::from_slice(&durable)?;
        restored.validate("", "pki/", NOW + 6)?;
        assert_eq!(durable, serde_json::to_vec(&restored)?);
        for (path, reference, delta) in [
            ("crl", "default", false),
            ("crl/delta/pem", "default", true),
            ("issuer/alpha/crl/der", "alpha", false),
            ("issuer/beta/crl/delta/pem", "beta", true),
        ] {
            let route = restored
                .public_read_route("GET", path)
                .ok_or("public CRL route")?;
            let response = restored.handle_public_read(route, &json!({}), NOW + 10000)?;
            assert!(!response.mutated);
            let bytes = BASE64.decode(
                response.body["__heptabao_pki_crl"]
                    .as_str()
                    .ok_or("raw CRL")?,
            )?;
            let expected = restored.cached_local_crl(restored.local_issuer(reference)?, delta)?;
            if path.ends_with("pem") {
                let canonical = pem("X509 CRL", expected);
                let native = if path.starts_with("issuer/") {
                    canonical.as_str()
                } else {
                    canonical
                        .strip_suffix('\n')
                        .ok_or("independent CRL PEM final LF")?
                };
                assert_eq!(
                    bytes.ends_with(b"\n"),
                    path.starts_with("issuer/"),
                    "actual native default and issuer raw CRL framing differs"
                );
                assert_eq!(bytes, native.as_bytes());
            } else {
                assert_eq!(bytes, expected);
            }
        }
        assert_eq!(durable, serde_json::to_vec(&restored)?);
        Ok(())
    }

    #[test]
    fn automatic_full_and_delta_maintenance_is_real_bounded_and_persistent() -> TestResult {
        let mut pki = Pki::default();
        root(&mut pki, "alpha", NOW)?;
        delta_config(&mut pki, NOW)?;
        let a = issue(&mut pki, "alpha", NOW)?;
        pki.handle_admin("POST", "revoke", &json!({"serial_number":a}), NOW + 1)?;
        assert!(!pki.maintain_local_crl(NOW + 59)?);
        check_der(&pki, "alpha", true, 0)?;
        assert!(pki.maintain_local_crl(NOW + 60)?);
        check_der(&pki, "alpha", true, 1)?;
        assert!(!pki.maintain_local_crl(NOW + 120)?);
        assert!(pki.maintain_local_crl(NOW + 6900)?);
        check_der(&pki, "alpha", false, 1)?;
        check_der(&pki, "alpha", true, 0)?;
        pki.validate("", "pki/", NOW + 6900)?;
        Ok(())
    }

    #[test]
    fn rejected_policy_rotation_and_counter_overflow_preserve_previous_state() -> TestResult {
        let mut pki = Pki::default();
        root(&mut pki, "alpha", NOW)?;
        for body in [
            json!({"enable_delta":true}),
            json!({"auto_rebuild":true,"expiry":"5m"}),
            json!({"expiry":[]}),
            json!({"expiry":"-1h"}),
            json!({"unexpected":true}),
        ] {
            let before = serde_json::to_vec(&pki)?;
            assert!(pki.handle_admin("POST", "config/crl", &body, NOW).is_err());
            assert_eq!(before, serde_json::to_vec(&pki)?);
        }
        for path in ["crl/rotate", "crl/rotate-delta"] {
            let before = serde_json::to_vec(&pki)?;
            assert!(pki.handle_admin("POST", path, &json!({}), NOW).is_err());
            assert_eq!(before, serde_json::to_vec(&pki)?);
        }
        let key = issuer_key(pki.local_issuer("alpha")?);
        pki.local_crl
            .as_mut()
            .ok_or("cache")?
            .issuers
            .get_mut(&key)
            .ok_or("issuer")?
            .last_number = MAX_CRL_NUMBER;
        let before = serde_json::to_vec(&pki)?;
        assert!(
            pki.handle_admin("GET", "crl/rotate", &json!({}), NOW + 1)
                .is_err()
        );
        assert_eq!(before, serde_json::to_vec(&pki)?);
        Ok(())
    }

    #[test]
    fn altered_signatures_numbers_dates_revocation_ownership_and_issuer_cache_are_rejected()
    -> TestResult {
        let mut pki = Pki::default();
        root(&mut pki, "alpha", NOW)?;
        root(&mut pki, "beta", NOW)?;
        let a = issue(&mut pki, "alpha", NOW)?;
        pki.handle_admin("POST", "revoke", &json!({"serial_number":a}), NOW + 1)?;
        let key = issuer_key(pki.local_issuer("alpha")?);
        for kind in 0..7 {
            let mut changed = pki.clone();
            let state = changed.local_crl.as_mut().ok_or("cache")?;
            let cached = state.issuers.get_mut(&key).ok_or("issuer")?;
            match kind {
                0 => {
                    let end = cached.full.der.len() - 1;
                    cached.full.der[end] ^= 1;
                }
                1 => cached.full.number += 1,
                2 => cached.delta.base = Some(900),
                3 => cached.full.this_update += 1,
                4 => cached.full.next_update += 1,
                5 => {
                    cached.full.revoked.insert("01".into(), NOW);
                }
                _ => {
                    state.issuers.remove(&key);
                }
            }
            assert!(
                changed.validate("", "pki/", NOW + 2).is_err(),
                "tamper {kind}"
            );
        }
        let mut changed = pki.clone();
        let alpha = changed.local_issuer("alpha")?.issuer_id.clone();
        let beta = changed.local_issuer("beta")?.issuer_id.clone();
        let entry = changed
            .issued
            .values_mut()
            .find(|cert| cert.local_issuer_id == alpha)
            .ok_or("owned issued")?;
        entry.local_issuer_id = beta;
        assert!(changed.validate("", "pki/", NOW + 2).is_err());
        Ok(())
    }
}
